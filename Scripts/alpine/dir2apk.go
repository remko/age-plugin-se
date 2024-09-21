// Script to convert a package directory into an .apk file.
//
// Implements the APK spec: https://wiki.alpinelinux.org/wiki/Apk_spec

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func NewPKGInfo() PKGInfo {
	return PKGInfo{
		"pkgname":    "age-plugin-se",
		"pkgver":     "0.1.4-r0",
		"pkgdesc":    "age plugin for Apple's Secure Enclave",
		"url":        "https://github.com/remko/age-plugin-se",
		"maintainer": "Remko Tronçon <r@mko.re>",
		"packager":   "Remko Tronçon <r@mko.re>",
		"origin":     "age-plugin-se",
		"commit":     "3bb554e284d9e685b3f3fb07ae5c294d5ec7c6dd",
		"license":    "MIT",
	}
}

func doMain() error {
	arch := flag.String("arch", "", "")
	keyfile := flag.String("key", "", "")
	outdir := flag.String("out", "", "")
	flag.Parse()
	rootdir := flag.Arg(0)

	if *arch == "" {
		return fmt.Errorf("missing arch")
	}
	if *keyfile == "" {
		return fmt.Errorf("missing key")
	}
	if *outdir == "" {
		return fmt.Errorf("missing out")
	}
	if rootdir == "" {
		return fmt.Errorf("missing dir")
	}

	builddate := time.Now()
	if os.Getenv("SOURCE_DATE_EPOCH") != "" {
		sourcedate, err := strconv.ParseInt(os.Getenv("SOURCE_DATE_EPOCH"), 10, 0)
		if err != nil {
			return err
		}
		builddate = time.Unix(sourcedate, 0)
	}

	////////////////////////////////////////////////////////////////////////////////
	// Base package
	////////////////////////////////////////////////////////////////////////////////

	pkginfo := NewPKGInfo()
	pkginfo["arch"] = *arch
	pkginfo["builddate"] = strconv.FormatInt(builddate.UnixMilli(), 10)
	if err := CreatePackage(pkginfo, rootdir, func(p string) bool { return !isDocPath(p) }, *outdir, *keyfile, builddate); err != nil {
		return err
	}

	////////////////////////////////////////////////////////////////////////////////
	// Doc package
	////////////////////////////////////////////////////////////////////////////////

	docpkginfo := NewPKGInfo()
	docpkginfo["arch"] = "noarch"
	docpkginfo["builddate"] = strconv.FormatInt(builddate.UnixMilli(), 10)
	docpkginfo["pkgdesc"] = docpkginfo["pkgdesc"] + " (documentation)"
	docpkginfo["install_if"] = fmt.Sprintf("docs %s=%s", docpkginfo["pkgname"], docpkginfo["pkgver"])
	docpkginfo["pkgname"] = docpkginfo["pkgname"] + "-doc"
	if err := CreatePackage(docpkginfo, rootdir, isDocPath, *outdir, *keyfile, builddate); err != nil {
		return err
	}
	return nil
}

func CreatePackage(pkginfo PKGInfo, rootdir string, pathfilter func(string) bool, outdir string, keyfile string, buildtime time.Time) error {
	datapath, size, err := CreateDataTarball(rootdir, pathfilter, buildtime)
	if err != nil {
		return err
	}
	defer os.Remove(datapath)
	pkginfo["size"] = strconv.FormatInt(size, 10)
	pkginfo["datahash"], err = sha256sum(datapath)
	if err != nil {
		return err
	}

	controlseg, err := CreateTarSegment(".PKGINFO", []byte(pkginfo.Marshal()), buildtime)
	if err != nil {
		return err
	}

	signature, err := signHash(controlseg, keyfile)
	if err != nil {
		return err
	}
	signatureseg, err := CreateTarSegment(fmt.Sprintf(".SIGN.RSA.%s.pub", path.Base(keyfile)), signature, buildtime)

	data, err := os.Open(datapath)
	if err != nil {
		return err
	}
	defer data.Close()
	pkg, err := os.Create(path.Join(outdir, fmt.Sprintf("%s-%s-%s.apk", pkginfo["pkgname"], pkginfo["pkgver"], pkginfo["arch"])))
	if err != nil {
		return err
	}
	defer pkg.Close()
	pkg.Write(signatureseg)
	pkg.Write(controlseg)
	if _, err := io.Copy(pkg, data); err != nil {
		return err
	}
	pkg.Close()

	return nil
}

func CreateDataTarball(rootdir string, pathfilter func(string) bool, buildtime time.Time) (string, int64, error) {
	datafile, err := os.CreateTemp("", "apk-data")
	if err != nil {
		return "", 0, err
	}
	defer datafile.Close()
	datagz := gzip.NewWriter(datafile)
	defer datagz.Close()
	datatar := tar.NewWriter(datagz)
	defer datatar.Close()
	var datasize int64 = 0

	tardirs := map[string]struct{}{}
	dirinfos := map[string]os.FileInfo{}

	err = filepath.Walk(rootdir, func(fpath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			dirinfos[fpath] = info
			return nil
		}
		if !pathfilter(fpath) {
			return nil
		}

		// Ensure parent dir entries are written
		createdirs := []string{}
		dir := path.Dir(fpath)
		for {
			if dir == rootdir {
				break
			}
			if _, ok := tardirs[dir]; ok {
				break
			}
			createdirs = append(createdirs, dir)
			dir = path.Dir(dir)
		}
		for i := len(createdirs) - 1; i >= 0; i-- {
			dir := createdirs[i]
			header, err := tar.FileInfoHeader(dirinfos[dir], dir)
			if err != nil {
				return err
			}
			header.AccessTime = buildtime
			header.ModTime = buildtime
			header.ChangeTime = buildtime
			relpath, err := filepath.Rel(rootdir, dir)
			if err != nil {
				return err
			}
			header.Name = relpath
			if err := datatar.WriteHeader(header); err != nil {
				return err
			}
		}

		header, err := tar.FileInfoHeader(info, fpath)
		if err != nil {
			return err
		}
		header.AccessTime = buildtime
		header.ModTime = buildtime
		header.ChangeTime = buildtime

		relpath, err := filepath.Rel(rootdir, fpath)
		if err != nil {
			return err
		}
		header.Name = relpath

		checksum, err := sha1sum(fpath)
		if err != nil {
			return nil
		}
		header.PAXRecords = map[string]string{
			"APK-TOOLS.checksum.SHA1": checksum,
		}

		if err := datatar.WriteHeader(header); err != nil {
			return err
		}

		f, err := os.Open(fpath)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(datatar, f)
		datasize += header.Size

		return err
	})
	if err != nil {
		os.Remove(datafile.Name())
		return "", 0, err
	}
	return datafile.Name(), datasize, nil
}

func CreateTarSegment(filename string, contents []byte, buildtime time.Time) ([]byte, error) {
	tbuf := bytes.NewBuffer(nil)
	tw := tar.NewWriter(tbuf)
	defer tw.Close()
	header := &tar.Header{
		Name:       filename,
		Size:       int64(len(contents)),
		Mode:       0644,
		AccessTime: buildtime,
		ModTime:    buildtime,
		ChangeTime: buildtime,
	}
	if err := tw.WriteHeader(header); err != nil {
		return nil, err
	}
	if _, err := tw.Write(contents); err != nil {
		return nil, err
	}
	tw.Close()
	tbuf.Truncate(tbuf.Len() - 1024)

	gzbuf := bytes.NewBuffer(nil)
	gzw := gzip.NewWriter(gzbuf)
	defer gzw.Close()
	if _, err := gzw.Write(tbuf.Bytes()); err != nil {
		return nil, err
	}
	gzw.Close()
	return gzbuf.Bytes(), nil
}

func isDocPath(path string) bool {
	return strings.Contains(path, "/man/") || strings.Contains("/licenses/", path)
}

////////////////////////////////////////////////////////////////////////////////

func sha1sum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sha256sum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func signHash(data []byte, keyfile string) ([]byte, error) {
	h := sha1.New()
	h.Write(data)
	hash := h.Sum(nil)

	keypem, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keypem)
	if block == nil {
		return nil, err
	}
	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key := parseResult.(*rsa.PrivateKey)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, hash)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

////////////////////////////////////////////////////////////////////////////////

type PKGInfo map[string]string

func (pi PKGInfo) Marshal() string {
	x := ""
	for _, k := range slices.Sorted(maps.Keys(pi)) {
		x += fmt.Sprintf("%s = %v\n", k, pi[k])
	}
	return x
}

////////////////////////////////////////////////////////////////////////////////

func main() {
	if err := doMain(); err != nil {
		panic(err)
	}
}
