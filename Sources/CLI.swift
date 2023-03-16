import Foundation

let version = "v0.0.4"

@main
struct CLI {
  static func main() {
    do {
      let plugin = Plugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
      let options = try Options.parse(CommandLine.arguments)
      switch options.command {
      case .help:
        print(Options.help)
      case .version:
        print(version)
      case .keygen:
        let result = try plugin.generateKey(
          accessControl: options.accessControl.keyAccessControl, now: Date())
        if let outputFile = options.output {
          FileManager.default.createFile(
            atPath: outputFile,
            contents: result.0.data(using: .utf8),
            attributes: [.posixPermissions: 0o600]
          )
          print("Public key: \(result.1)")
        } else {
          print(result.0)
        }
      case .recipients:
        var input = ""
        if let inputFile = options.input {
          input = try String(
            contentsOfFile: inputFile)
        } else {
          input = try String(data: FileHandle.standardInput.readToEnd()!, encoding: .utf8)!
        }
        let result = try plugin.generateRecipients(input: input)
        if let outputFile = options.output {
          FileManager.default.createFile(
            atPath: outputFile,
            contents: result.data(using: .utf8),
            attributes: [.posixPermissions: 0o600]
          )
        } else if result != "" {
          print(result)
        }
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
  enum Error: LocalizedError, Equatable {
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

  enum Command: Equatable {
    case help
    case version
    case keygen
    case recipients
    case plugin(StateMachine)
  }
  var command: Command

  var output: String?
  var input: String?

  enum AccessControl: String {
    case none = "none"
    case passcode = "passcode"
    case anyBiometry = "any-biometry"
    case anyBiometryOrPasscode = "any-biometry-or-passcode"
    case anyBiometryAndPasscode = "any-biometry-and-passcode"
    case currentBiometry = "current-biometry"
    case currentBiometryAndPasscode = "current-biometry-and-passcode"

    var keyAccessControl: KeyAccessControl {
      switch self {
      case .none: return KeyAccessControl.none
      case .passcode: return KeyAccessControl.passcode
      case .anyBiometry: return KeyAccessControl.anyBiometry
      case .anyBiometryOrPasscode: return KeyAccessControl.anyBiometryOrPasscode
      case .anyBiometryAndPasscode: return KeyAccessControl.anyBiometryAndPasscode
      case .currentBiometry: return KeyAccessControl.currentBiometry
      case .currentBiometryAndPasscode: return KeyAccessControl.currentBiometryAndPasscode
      }
    }
  }
  var accessControl = AccessControl.anyBiometryOrPasscode

  static var help =
    """
    Usage:
      age-plugin-se keygen [-o OUTPUT] [--access-control ACCESS_CONTROL]
      age-plugin-se recipients [-o OUTPUT] [-i INPUT]

    Description:
      The `keygen` subcommand generates a new private key bound to the current 
      Secure Enclave, with the given access controls, and outputs it to OUTPUT 
      or standard output.

      The `recipients` subcommand reads an identity file from INPUT or standard 
      input, and outputs the corresponding recipient(s) to OUTPUT or to standard 
      output.

    Options:
      --access-control ACCESS_CONTROL   Access control for using the generated key.
                                        
                                        When using current biometry, adding or removing a 
                                        fingerprint stops the key from working. Removing an 
                                        added fingerprint enables the key again. 

                                        Supported values: none, passcode, 
                                          any-biometry, any-biometry-and-passcode, 
                                          any-biometry-or-passcode, current-biometry, 
                                          current-biometry-and-passcode
                                        Default: any-biometry-or-passcode.                          

      -i, --input INPUT                 Read data from the file at path INPUT

      -o, --output OUTPUT               Write the result to the file at path OUTPUT

    Example:
      $ age-plugin-se keygen -o key.txt
      Public key: age1se1qg8vwwqhztnh3vpt2nf2xwn7famktxlmp0nmkfltp8lkvzp8nafkqleh258
      $ tar cvz ~/data | age -r age1se1qgg72x2qfk9wg3wh0qg9u0v7l5dkq4jx69fv80p6wdus3ftg6flwg5dz2dp > data.tar.gz.age
      $ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz
    """

  static func parse(_ args: [String]) throws -> Options {
    var opts = Options(command: .help)
    var i = 1
    while i < args.count {
      let arg = args[i]
      if arg == "keygen" {
        opts.command = .keygen
      } else if arg == "recipients" {
        opts.command = .recipients
      } else if ["--help", "-h"].contains(arg) {
        opts.command = .help
        break
      } else if ["--version"].contains(arg) {
        opts.command = .version
        break
      } else if [
        "--age-plugin", "-i", "--input", "-o", "--output", "--access-control",
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
        case "-i", "--input":
          opts.input = value
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
}
