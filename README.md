> ⚠️ **This plugin is not production-ready yet**

# age-plugin-applese

A plugin for [age](https://age-encryption.org/v1), enabling encryption using [Apple's Secure Enclave](https://support.apple.com/en-gb/guide/security/sec59b0b31ff/web).

## Installation

> TODO: Homebrew

To build from source, see the *Building from source* section.

## Usage

    $ age-plugin-applese keygen -o key.txt
    Public key: age1applese1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258
    $ tar cvz ~/data | age -r age1applese1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258 > data.tar.gz.age
    $ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz

## Building from source

Build the plugin (for development)

    swift build

For releases, run

    swift build -c release

If you get an error about missing tools, make sure Xcode is activated:

    sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer

Make sure `.build/debug/age-plugin-applese` is in your execution path (or softlinked from a folder in your path), so `age` can find the plugin.