> ⚠️ **This plugin is not production-ready yet. It is fully functional and tested, but the recipient and identity format are still subject to change. Feedback welcome!**

# Age plugin for Apple Secure Enclave

`age-plugin-se` is a plugin for [age](https://age-encryption.org), enabling encryption using [Apple's Secure Enclave](https://support.apple.com/en-gb/guide/security/sec59b0b31ff/web).

    $ age-plugin-se keygen --access-control=any-biometry -o key.txt
    Public key: age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258
    $ tar cvz ~/data | age -r age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258 > data.tar.gz.age
    $ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz

<div align="center">
<img src="https://raw.githubusercontent.com/remko/age-plugin-se/main/Documentation/img/screenshot-biometry.png" alt="Biometry prompt" width=350/>
</div>


## Requirements

This plugin requires macOS 13 (Ventura).
To generate identity files and decrypt encrypted files, you need a Mac with a Secure Enclave processor.
For encrypting files, a Secure Enclave processor is not necessary.

## Installation

### Homebrew

> TODO

### Pre-built binary

- Download a binary from [the releases page](https://github.com/remko/age-plugin-se/releases)
- Extract the package
- Trust `age-plugin-se` once by Control-clicking the file in Finder, choosing *Open*, 
  and confirming trust
- Move `age-plugin-se` to somewhere on your executable path (e.g. `/usr/local/bin`)

### Building from source

See [Building from source](#building-from-source).


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


## Building from source

Build the plugin

    make

If you get an error about missing tools, make sure Xcode is activated:

    sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer

Make sure `.build/debug/age-plugin-se` is in your execution path (or softlinked from a folder in your path), so `age` can find the plugin.

### Tests

To run the unit tests:

    make test

To run a smoke test:

    make smoke-test
