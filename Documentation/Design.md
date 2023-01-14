# Design Notes

This document contains notes about design choices made in the plugin.


## SecureEnclave APIs: Security vs CryptoKit

Apple provides 2 APIs for communicating with the Secure Enclave: [through the Security Framework](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave), and [through CryptoKit](https://developer.apple.com/documentation/cryptokit/secureenclave).

The advantage of the Security framework is that it has been around for a long time, and is accessible from within Objective-C, which means you could write the entire plugin in e.g. Go, and use cgo out of the box for the few functions that need to talk to the Secure Enclave. However, using this API comes with disadvantages:

- The Security API requires your app to have special entitlements. This means you need to have an Apple Developer Certificate to build and run the app locally, and it could not be distributed through Homebrew core.
- Because the app needs entitlements, it cannot be distributed as a single binary, but has to be wrapped in a macOS App structure. You can still link from somewhere in the executable path to the binary inside the app structure, but the app would need to live somewhere else (possibly hidden, since the plugin is useless as a runnable standalone UI application)
- All keys are created through the Keychain. This means creating a key has a side effect of putting something in your keychain. You could probably export the private data from the keychain into an age identity file, and delete the key immediately after creating it, but something may go wrong, and you would be leaking data. Alternatively, you could choose to leave the keys in the Keychain, but then the plugin would need to manage looking up keys by tag, and push the complexity of keeping multiple keys via a plugin-specific CLI to the user. It's also not clear what happens during backup restore of the keychain, as there have been reports of confusing behavior there.
- Even for the few lines of Objective-C that are necessary, it would require a good understanding of how memory management works in the Objective-C API in order to not run memory corruption or leaks. I'm not that confident I can get this 100% right.

The CryptoKit framework does not have any of these disadvantages: it accesses the Secure Enclave directly, using a very simple API that does not require special entitlements. However, CryptoKit is only accessible through Swift, which means you can't directly write your plugin in a language such as Go and use cgo out of the box. You could probably still create a small library in Swift that does the necessary calls, and wrap that in an Objective-C or C API, and use Cgo on that, but that's a lot of moving parts and complexity for a simple plugin such as this one. Besides, the only potential part that could be reused in the plugin would be the Age stanza parsing, which not only just 50 lines of code, but isn't exposed by age anyway. CryptoKit comes with all the necessary cryptographic primitives that are necessary for the rest of the plugin.

For these reasons, I have chosen to keep the plugin as simple as possible for both me and the user, so it is implemented entirely in Swift using the CryptoKit API.
