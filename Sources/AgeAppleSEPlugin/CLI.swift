import CryptoKit
import Foundation

@main
struct CLI {
  static func main() {
    do {
      let options = try Options.parse()
      guard let command = options.command else {
        return
      }

      let plugin = Plugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
      switch command {
      case .keygen:
        try plugin.generateKey(
          outputFile: options.output, accessControl: options.accessControl.keyAccessControl)
      case .plugin(let sm):
        switch sm {
        case .recipientV1:
          plugin.runRecipientV1()
        case .identityV1:
          plugin.runIdentityV1()
        }
      }
    } catch {
      print("\(CommandLine.arguments[0]): error: \(error.localizedDescription)")
      exit(-1)
    }
  }
}

/// Command-line options parser
struct Options {
  enum Error: LocalizedError {
    case unknownOption(String)
    case missingValue(String)
    case invalidValue(String, String)

    public var errorDescription: String? {
      switch self {
      case .unknownOption(let option): return "unknown option: `\(option)`"
      case .missingValue(let option): return "missing value for option `\(option)`"
      case .invalidValue(let option, let value):
        return "invalid value for option `\(option)`: `\(value)`"
      }
    }
  }

  enum StateMachine: String {
    case recipientV1 = "recipient-v1"
    case identityV1 = "identity-v1"
  }

  enum Command {
    case keygen
    case plugin(StateMachine)
  }
  var command: Command?

  var output: String?

  enum AccessControl: String {
    case none = "none"
    case biometry = "biometry"
    case passcode = "passcode"
    case biometryOrPasscode = "biometry-or-passcode"
    case biometryAndPasscode = "biometry-and-passcode"

    var keyAccessControl: KeyAccessControl {
      switch self {
      case .none: return KeyAccessControl.none
      case .biometry: return KeyAccessControl.biometry
      case .passcode: return KeyAccessControl.passcode
      case .biometryOrPasscode: return KeyAccessControl.biometryOrPasscode
      case .biometryAndPasscode: return KeyAccessControl.biometryAndPasscode
      }
    }
  }
  var accessControl = AccessControl.biometryOrPasscode

  static func printHelp() {
    print(
      """
      Usage:
        age-plugin-applese keygen [-o OUTPUT] [--access-control ACCESS_CONTROL]

      Options:
        -o, --output OUTPUT                Write the result to the file at path OUTPUT
        --access-control ACCESS_CONTROL    Access control for using the generated key.
                                           Supported values: none, biometry, passcode, 
                                           biometry-and-passcode, biometry-or-passcode.     
                                           Default: biometry-or-passcode.                          

      Example:
        $ age-plugin-applese keygen -o key.txt
        Public key: age1applese1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258
        $ tar cvz ~/data | age -r age1applese1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258 > data.tar.gz.age
        $ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz
      """)
  }

  static func parse() throws -> Options {
    let args = CommandLine.arguments
    var opts = Options()
    var i = 1
    while i < args.count {
      let arg = args[i]
      if arg == "keygen" {
        opts.command = .keygen
      } else if ["--help", "-h"].contains(arg) {
        opts.command = nil
        printHelp()
        break
      } else if ["--version"].contains(arg) {
        opts.command = nil
        print(VERSION)
        break
      } else if [
        "--age-plugin", "-o", "--output", "--access-control",
      ].contains(where: {
        arg == $0 || arg.hasPrefix($0 + "=")
      }) {
        let argps = arg.split(separator: "=", maxSplits: 1)
        let value: String
        if argps.count == 1 {
          i += 1
          if i >= args.count {
            throw Error.missingValue(arg)
          }
          value = args[i]
        } else {
          value = String(argps[1])
        }
        let arg = String(argps[0])
        switch arg {
        case "--age-plugin":
          opts.command = try .plugin(
            StateMachine(rawValue: value) ?? { throw Error.invalidValue(arg, value) }())
        case "-o", "--output":
          opts.output = value
        case "--access-control":
          opts.accessControl =
            try AccessControl(rawValue: value) ?? { throw Error.invalidValue(arg, value) }()
        default:
          assert(false)
        }
      } else {
        throw Error.unknownOption(arg)
      }
      i += 1
    }
    return opts
  }

  private static func toBool(argument: String, value: String) throws -> Bool {
    switch value {
    case "yes", "true": return true
    case "no", "false":
      return false
    default:
      throw Error.invalidValue(argument, value)
    }
  }
}
