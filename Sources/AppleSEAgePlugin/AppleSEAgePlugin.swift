import ArgumentParser
import CryptoKit
import Foundation

@main
struct AppleSEAgePlugin: ParsableCommand {
  static var configuration = CommandConfiguration(
    commandName: "age-plugin-applese",
    abstract: "Age plugin for Apple Secure Enclave keys.",
    version: "1.0.0",
    subcommands: [Keygen.self, Plugin.self],
    defaultSubcommand: Plugin.self)
}

extension AppleSEAgePlugin {
  struct Keygen: ParsableCommand {
    static var configuration = CommandConfiguration(abstract: "Generate a private key")

    @Option(name: .shortAndLong, help: "Output")
    var output: String? = nil

    mutating func run() {
      generateKey(outputFile: output)
    }
  }

  struct Plugin: ParsableCommand {
    static var configuration = CommandConfiguration(abstract: "Run plugin")

    @Option(name: .long, help: "Plugin state machine")
    var agePlugin: String? = nil

    mutating func run() {
      guard let agePlugin = agePlugin else {
        return
      }
      switch agePlugin {
      case "recipient-v1":
        runRecipientV1()
      case "identity-v1":
        runIdentityV1()
      default:
        assert(false)
      }
    }
  }
}
