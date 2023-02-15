> ⚠️ **This plugin is still under review. Feedback welcome!**

# Age plugin for Apple's Secure Enclave

[![Build](https://github.com/remko/age-plugin-se/actions/workflows/build.yml/badge.svg)](https://github.com/remko/age-plugin-se/actions/workflows/build.yml)

`age-plugin-se` is a plugin for [age](https://age-encryption.org), enabling encryption using [Apple's Secure Enclave](https://support.apple.com/en-gb/guide/security/sec59b0b31ff/web).

    $ age-plugin-se keygen --access-control=any-biometry -o key.txt
    Public key: age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp
    $ tar cvz ~/data | age -r age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp > data.tar.gz.age
    $ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz

<div align="center">
<img src="https://raw.githubusercontent.com/remko/age-plugin-se/main/Documentation/img/screenshot-biometry.png" alt="Biometry prompt" width=350/>
</div>


## Requirements

To generate identity files and decrypt encrypted files, you need a Mac running macOS 13 (Ventura) with a 
Secure Enclave processor.

For encrypting files, you need macOS 13 (Ventura), Linux, or Windows. A Secure Enclave processor is not necessary.


## Installation

### Homebrew

> Coming when v1.0 is released

### Pre-built binary

1. Download a binary from [the releases page](https://github.com/remko/age-plugin-se/releases)
2. Extract the package
3. (Windows only) Download and install [Swift](https://www.swift.org/download/)
4. (macOS only) Trust `age-plugin-se` once by Control-clicking the file in Finder, choosing *Open*, 
   and confirming trust
5. Move `age-plugin-se` to somewhere on your executable path (e.g. `/usr/local/bin`)

### Building from source

1. (non-macOS only) Download and install [Swift](https://www.swift.org/download/)

2. Clone [the source code repository](https://github.com/remko/age-plugin-se) or 
   get a source package from [the releases page](https://github.com/remko/age-plugin-se/releases)

3. Build the plugin
      
       make

4. Install the plugin

       sudo make install PREFIX=/usr/local


## Usage

    age-plugin-se keygen [-o OUTPUT] [--access-control ACCESS_CONTROL]

    Options:
      -o, --output OUTPUT               Write the result to the file at path OUTPUT
      
      --access-control ACCESS_CONTROL   Access control for using the generated key.
                                    
            Supported values: none, passcode, 
              any-biometry, any-biometry-and-passcode, any-biometry-or-passcode,
              current-biometry, current-biometry-and-passcode
            Default: any-biometry-or-passcode.             

            When using current biometry, adding or removing a fingerprint stops the
            key from working. Removing an added fingerprint enables the key again. 


## Development

Build the plugin

    make

Make sure `.build/debug/age-plugin-se` is in your execution path (or softlinked from a folder in your path), so `age` can find the plugin.

### Tests

To run the unit tests:

    make test

To get a coverage report of the unit test:

    make test COVERAGE=1

If you want an HTML version of the coverage report, make sure [llvm-coverage-viewer](https://www.npmjs.com/package/llvm-coverage-viewer) is installed.

To run a smoke test:

    make smoke-test
