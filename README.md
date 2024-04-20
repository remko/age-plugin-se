# Age plugin for Apple's Secure Enclave

[![Build](https://github.com/remko/age-plugin-se/actions/workflows/build-main.yml/badge.svg)](https://github.com/remko/age-plugin-se/actions/workflows/build-main.yml)
[![Coverage](https://remko.github.io/age-plugin-se/ci/coverage.svg)](https://remko.github.io/age-plugin-se/ci/coverage.html)

`age-plugin-se` is a plugin for [age](https://age-encryption.org),
enabling encryption using [Apple's Secure
Enclave](https://support.apple.com/en-gb/guide/security/sec59b0b31ff/web).

    $ age-plugin-se keygen --access-control=any-biometry -o key.txt
    Public key: age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp
    $ tar cvz ~/data | age -r age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp > data.tar.gz.age
    $ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz

<div align="center">
<img src="https://raw.githubusercontent.com/remko/age-plugin-se/main/Documentation/img/screenshot-biometry.png" alt="Biometry prompt" width=350/>
</div>

## Requirements

To generate identity files and decrypt encrypted files, you need a Mac
running macOS 13 (Ventura) with a Secure Enclave processor.

For encrypting files, you need macOS 13 (Ventura), Linux, or Windows. A
Secure Enclave processor is not necessary.

## Installation

### Homebrew

1.  Register the Homebrew Tap

         brew tap remko/age-plugin-se https://github.com/remko/age-plugin-se

2.  Install the package

         brew install age-plugin-se

### Pre-built binary

1.  Download a binary from [the releases
    page](https://github.com/remko/age-plugin-se/releases)
2.  Extract the package
3.  (Windows only) Download and install
    [Swift](https://www.swift.org/download/)
4.  (macOS only) Trust `age-plugin-se` once by Control-clicking the file
    in Finder, choosing *Open*, and confirming trust
5.  Move `age-plugin-se` to somewhere on your executable path (e.g.
    `/usr/local/bin`)

### Building from source

1.  (non-macOS only) Download and install
    [Swift](https://www.swift.org/download/)

2.  Clone [the source code
    repository](https://github.com/remko/age-plugin-se) or get a source
    package from [the releases
    page](https://github.com/remko/age-plugin-se/releases)

3.  Build the plugin

        make

4.  Install the plugin

        sudo make install PREFIX=/usr/local

## Usage

    age-plugin-se keygen [-o OUTPUT] [--access-control ACCESS_CONTROL]
    age-plugin-se recipients [-o OUTPUT] [-i INPUT]

    The `keygen` subcommand generates a new private key bound to the current 
    Secure Enclave, with the given access controls, and outputs it to OUTPUT 
    or standard output.

    The `recipients` subcommand reads an identity file from INPUT or standard 
    input, and outputs the corresponding recipient(s) to OUTPUT or to standard 
    output.


    Options:
      --access-control ACCESS_CONTROL   Access control for using the generated key.
                                    
            Supported values: none, passcode, 
              any-biometry, any-biometry-and-passcode, any-biometry-or-passcode,
              current-biometry, current-biometry-and-passcode
            Default: any-biometry-or-passcode.             

            When using current biometry, adding or removing a fingerprint stops the
            key from working. Removing an added fingerprint enables the key again. 

      -o, --output OUTPUT               Write the result to the file at path OUTPUT

      -i, --input INPUT                 Read data from the file at path INPUT

## Development

Build the plugin

    make

Make sure `.build/debug/age-plugin-se` is in your execution path (or
softlinked from a folder in your path), so `age` can find the plugin.

### Tests

To run the unit tests:

    make test

To get a coverage report of the unit tests:

    make test COVERAGE=1

Annotated coverage source code can be found in `.build/coverage.html`.

To run a smoke test:

    make smoke-test
