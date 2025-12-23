import Foundation

#if !os(Linux) && !os(Windows)
  import CryptoKit
#else
  import Crypto
#endif

class Plugin {
  var crypto: Crypto
  var stream: Stream

  init(crypto: Crypto, stream: Stream) {
    self.crypto = crypto
    self.stream = stream
  }

  func generateKey(accessControl: KeyAccessControl, recipientType: RecipientType, now: Date)
    throws
    -> (String, String)
  {
    if !crypto.isSecureEnclaveAvailable {
      throw Error.seUnsupported
    }
    #if !os(Linux) && !os(Windows)
      let createdAt = now.ISO8601Format()
      var accessControlFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
      if accessControl == .anyBiometry || accessControl == .anyBiometryAndPasscode {
        accessControlFlags.insert(.biometryAny)
      }
      if accessControl == .currentBiometry || accessControl == .currentBiometryAndPasscode {
        accessControlFlags.insert(.biometryCurrentSet)
      }
      if accessControl == .passcode || accessControl == .anyBiometryAndPasscode
        || accessControl == .currentBiometryAndPasscode
      {
        accessControlFlags.insert(.devicePasscode)
      }
      if accessControl == .anyBiometryOrPasscode {
        accessControlFlags.insert(.userPresence)
      }
      var error: Unmanaged<CFError>?
      guard
        let secAccessControl = SecAccessControlCreateWithFlags(
          kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
          accessControlFlags,
          &error)
      else {
        throw error!.takeRetainedValue() as Swift.Error
      }
    #else
      // FIXME: ISO8601Format currently not supported on Linux:
      //   https://github.com/apple/swift-corelibs-foundation/issues/4618
      // This code is only reached in unit tests on Linux anyway
      let createdAt = "1997-02-02T02:26:51Z"
      let secAccessControl = SecAccessControl()
    #endif

    let identity = try Identity(accessControl: secAccessControl, crypto: self.crypto)
    let ageRecipient = identity.recipient.ageRecipient(type: recipientType)
    let accessControlStr: String
    switch accessControl {
    case .none: accessControlStr = "none"
    case .passcode: accessControlStr = "passcode"
    case .anyBiometry: accessControlStr = "any biometry"
    case .anyBiometryOrPasscode: accessControlStr = "any biometry or passcode"
    case .anyBiometryAndPasscode: accessControlStr = "any biometry and passcode"
    case .currentBiometry: accessControlStr = "current biometry"
    case .currentBiometryAndPasscode: accessControlStr = "current biometry and passcode"
    }

    let recipientsStr = "# public key: \(ageRecipient)"

    let contents = """
      # created: \(createdAt)
      # access control: \(accessControlStr)
      \(recipientsStr)
      \(identity.ageIdentity)

      """

    return (contents, ageRecipient)
  }

  func generateRecipients(input: String, recipientType: RecipientType) throws -> String {
    var recipients: [String] = []
    for l in input.split(whereSeparator: \.isNewline) {
      if l.hasPrefix("#") {
        continue
      }
      let sl = String(l.trimmingCharacters(in: .whitespacesAndNewlines))
      let identity = try Identity(ageIdentity: sl, crypto: self.crypto)
      recipients.append(identity.recipient.ageRecipient(type: recipientType))
    }
    return recipients.joined(separator: "\n")
  }

  func runRecipientV1() {
    var recipients: [String] = []
    var identities: [String] = []
    var fileKeys: [Data] = []

    // Phase 1
    loop: while true {
      let stanza = try! Stanza.readFrom(stream: stream)
      switch stanza.type {
      case "add-recipient":
        recipients.append(stanza.args[0])
      case "add-identity":
        identities.append(stanza.args[0])
      case "wrap-file-key":
        fileKeys.append(stanza.body)
      case "done":
        break loop
      default:
        continue
      }
    }

    // Phase 2
    var stanzas: [Stanza] = []
    var errors: [Stanza] = []
    var recipientKeys: [(Recipient, RecipientStanzaType)] = []
    for (index, recipient) in recipients.enumerated() {
      do {
        recipientKeys.append(
          (
            try Recipient(ageRecipient: recipient),
            recipient.starts(with: "age1tag1") ? .p256tag : .pivp256
          ))
      } catch {
        errors.append(
          Stanza(
            error: "recipient", args: [String(index)],
            message: error.localizedDescription))
      }
    }
    for (index, identity) in identities.enumerated() {
      do {
        recipientKeys.append(
          (
            (try Identity(ageIdentity: identity, crypto: crypto)).recipient,
            .pivp256
          ))
      } catch {
        errors.append(
          Stanza(
            error: "identity", args: [String(index)],
            message: error.localizedDescription))
      }
    }
    for (index, fileKey) in fileKeys.enumerated() {
      for (recipientKey, recipientStanzaType) in recipientKeys {
        do {
          var tag: Data
          var nonce: ChaChaPoly.Nonce
          var wrapKey: SymmetricKey
          var pkEBytes: Data

          switch recipientStanzaType {
          case .pivp256:
            let skE = self.crypto.newEphemeralP256PrivateKey()
            pkEBytes = skE.publicKey.compressedRepresentation
            tag = recipientKey.sha256Tag
            nonce = try! ChaChaPoly.Nonce(data: Data(count: 12))

            // CryptoKit PublicKeys can be the identity point by construction (see CryptoTests), but
            // these keys can't be used in any operation. This is undocumented, but a documentation request
            // has been filed as FB11989432.
            // Swift Crypto PublicKeys cannot be the identity point by construction.
            // Compresed representation cannot be the identity point anyway (?)
            // Therefore, the shared secret cannot be all 0x00 bytes, so we don't need
            // to explicitly check this here.
            let sharedSecret = try skE.sharedSecretFromKeyAgreement(
              with: recipientKey.p256PublicKey)
            wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
              using: SHA256.self,
              salt: pkEBytes + recipientKey.compressedP256Representation,
              sharedInfo: Data("piv-p256".utf8),
              outputByteCount: 32
            )

          case .p256tag:
            let (sharedSecret, enc) = try HPKE.dhkemEncap(
              recipientKey: recipientKey.p256PublicKey, crypto: crypto)
            (wrapKey, nonce) = HPKE.context(
              kem: .dhkemP256,
              sharedSecret: sharedSecret,
              info: "age-encryption.org/p256tag".data(using: .utf8)!)
            tag = recipientKey.p256HKDFTag(using: enc)
            pkEBytes = enc
          }

          let sealedBox = try ChaChaPoly.seal(fileKey, using: wrapKey, nonce: nonce)
          stanzas.append(
            Stanza(
              type: "recipient-stanza",
              args: [
                String(index),
                recipientStanzaType.rawValue,
                tag.base64RawEncodedString(),
                pkEBytes.base64RawEncodedString(),
              ], body: sealedBox.ciphertext + sealedBox.tag
            )
          )
        } catch {
          errors.append(
            Stanza(error: "internal", args: [], message: error.localizedDescription))
        }
      }
    }
    for stanza in (errors.isEmpty ? stanzas : errors) {
      stanza.writeTo(stream: stream)
      let resp = try! Stanza.readFrom(stream: stream)
      assert(resp.type == "ok")
    }
    Stanza(type: "done").writeTo(stream: stream)
  }

  func runIdentityV1() {
    // Phase 1
    var identities: [String] = []
    var recipientStanzas: [Stanza] = []
    loop: while true {
      let stanza = try! Stanza.readFrom(stream: stream)
      switch stanza.type {
      case "add-identity":
        identities.append(stanza.args[0])
      case "recipient-stanza":
        recipientStanzas.append(stanza)
      case "done":
        break loop
      default:
        continue
      }
    }

    // Phase 2
    var identityKeys: [Identity] = []
    var errors: [Stanza] = []

    // Construct identities
    for (index, identity) in identities.enumerated() {
      do {
        identityKeys.append(
          (try Identity(ageIdentity: identity, crypto: crypto)))
      } catch {
        errors.append(
          Stanza(
            error: "identity", args: [String(index)],
            message: error.localizedDescription))
      }
    }

    var fileResponses: [Int: Stanza] = [:]
    if errors.isEmpty {
      // Check structural validity
      for recipientStanza in recipientStanzas {
        let fileIndex = Int(recipientStanza.args[0])!
        switch recipientStanza.args[1] {
        case "piv-p256", "p256tag":
          if recipientStanza.args.count != 4 {
            fileResponses[fileIndex] = Stanza(
              error: "stanza", args: [String(fileIndex)],
              message: "incorrect argument count")
            continue
          }
          let tag = Data(base64RawEncoded: recipientStanza.args[2])
          if tag == nil || tag!.count != 4 {
            fileResponses[fileIndex] = Stanza(
              error: "stanza", args: [String(fileIndex)], message: "invalid tag")
            continue
          }
          let share = Data(base64RawEncoded: recipientStanza.args[3])
          if share == nil || (recipientStanza.args[1] == "piv-p256" && share!.count != 33)
            || (recipientStanza.args[1] == "p256tag" && share!.count != 65)
          {
            fileResponses[fileIndex] = Stanza(
              error: "stanza", args: [String(fileIndex)], message: "invalid share")
            continue
          }
          if recipientStanza.body.count != 32 {
            fileResponses[fileIndex] = Stanza(
              error: "stanza", args: [String(fileIndex)],
              message: "invalid body")
            continue
          }

        default:
          continue
        }
      }

      // Unwrap keys
      for recipientStanza in recipientStanzas {
        let fileIndex = Int(recipientStanza.args[0])!
        if fileResponses[fileIndex] != nil {
          continue
        }
        guard let type = RecipientStanzaType(rawValue: recipientStanza.args[1]) else {
          continue
        }
        let tag = recipientStanza.args[2]
        let share = recipientStanza.args[3]
        for identity in identityKeys {
          do {
            let shareKeyData = Data(base64RawEncoded: share)!
            let identityTag =
              (type == .p256tag
              ? identity.recipient.p256HKDFTag(using: shareKeyData)
              : identity.recipient.sha256Tag)
              .base64RawEncodedString()
            if identityTag != tag {
              continue
            }

            var nonce: ChaChaPoly.Nonce
            var wrapKey: SymmetricKey

            switch type {
            case .pivp256:
              let shareKey = try P256.KeyAgreement.PublicKey(
                compressedRepresentation: shareKeyData)
              // CryptoKit PublicKeys can be the identity point by construction (see CryptoTests), but
              // these keys can't be used in any operation. This is undocumented, but a documentation request
              // has been filed as FB11989432.
              // Swift Crypto PublicKeys cannot be the identity point by construction.
              // Compresed representation cannot be the identity point anyway (?)
              // Therefore, the shared secret cannot be all 0x00 bytes, so we don't need
              // to explicitly check this here.
              let sharedSecret = try identity.p256PrivateKey
                .sharedSecretFromKeyAgreement(
                  with: shareKey)
              wrapKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: shareKeyData
                  + identity.recipient.compressedP256Representation,
                sharedInfo: Data("piv-p256".utf8),
                outputByteCount: 32
              )
              nonce = try! ChaChaPoly.Nonce(data: Data(count: 12))

            case .p256tag:
              let sharedSecret = try HPKE.dhkemDecap(
                enc: shareKeyData, recipientKey: identity.p256PrivateKey)
              (wrapKey, nonce) = HPKE.context(
                kem: .dhkemP256,
                sharedSecret: sharedSecret,
                info: "age-encryption.org/p256tag".data(using: .utf8)!)
            }

            let unwrappedKey = try ChaChaPoly.open(
              ChaChaPoly.SealedBox(combined: nonce + recipientStanza.body),
              using: wrapKey)
            fileResponses[fileIndex] = Stanza(
              type: "file-key",
              args: [String(fileIndex)],
              body: unwrappedKey
            )
          } catch {
            Stanza(type: "msg", body: Data(error.localizedDescription.utf8)).writeTo(
              stream: stream)
            let resp = try! Stanza.readFrom(stream: self.stream)
            assert(resp.type == "ok")
            // continue
          }
        }
      }
    }

    let responses = fileResponses.keys.sorted().map({ k in fileResponses[k]! })
    for stanza in (errors.isEmpty ? responses : errors) {
      stanza.writeTo(stream: stream)
      let resp = try! Stanza.readFrom(stream: stream)
      assert(resp.type == "ok")
    }
    Stanza(type: "done").writeTo(stream: stream)
  }

  enum Error: LocalizedError, Equatable {
    case seUnsupported
    case incompleteStanza
    case invalidStanza
    case unknownHRP(String)

    public var errorDescription: String? {
      switch self {
      case .seUnsupported: return "Secure Enclave not supported on this device"
      case .incompleteStanza: return "incomplete stanza"
      case .invalidStanza: return "invalid stanza"
      case .unknownHRP(let hrp): return "unknown HRP: \(hrp)"
      }
    }
  }
}

//////////////////////////////////////////////////////////////////////////////////////////

struct Stanza: Equatable {
  var type: String
  var args: [String] = []
  var body = Data()

  static func readFrom(stream: Stream) throws -> Stanza {
    guard let header = stream.readLine() else {
      throw Plugin.Error.incompleteStanza
    }
    let headerParts = header.components(separatedBy: " ")
    if headerParts.count < 2 {
      throw Plugin.Error.invalidStanza
    }
    if headerParts[0] != "->" {
      throw Plugin.Error.invalidStanza
    }
    var body = Data()
    while true {
      guard let line = stream.readLine() else {
        throw Plugin.Error.incompleteStanza
      }
      guard let lineData = Data(base64RawEncoded: line) else {
        throw Plugin.Error.invalidStanza
      }
      if lineData.count > 48 {
        throw Plugin.Error.invalidStanza
      }
      body.append(lineData)
      if lineData.count < 48 {
        break
      }
    }
    return Stanza(type: headerParts[1], args: Array(headerParts[2...]), body: body)
  }

  func writeTo(stream: Stream) {
    let parts = ([type] + args).joined(separator: " ")
    stream.writeLine("-> \(parts)\n\(body.base64RawEncodedString(wrap: true))")
  }
}

extension Stanza {
  init(error type: String, args: [String] = [], message: String) {
    self.type = "error"
    self.args = [type] + args
    self.body = Data(message.utf8)
  }
}

enum KeyAccessControl {
  case none
  case passcode
  case anyBiometry
  case anyBiometryOrPasscode
  case anyBiometryAndPasscode
  case currentBiometry
  case currentBiometryAndPasscode
}

enum RecipientType: String {
  case se = "se"
  case tag = "tag"
}

enum RecipientStanzaType: String {
  case p256tag = "p256tag"
  case pivp256 = "piv-p256"
}

////////////////////////////////////////////////////////////////////////////////

struct Recipient {
  let p256PublicKey: P256.KeyAgreement.PublicKey

  init(ageRecipient: String) throws {
    let id = try Bech32().decode(ageRecipient)
    if id.hrp != "age1se" && id.hrp != "age1tag" {
      throw Plugin.Error.unknownHRP(id.hrp)
    }
    self.p256PublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: id.data)
  }

  init(p256PublicKey: P256.KeyAgreement.PublicKey) {
    self.p256PublicKey = p256PublicKey
  }

  var uncompressedP256Representation: Data {
    return self.p256PublicKey.x963Representation
  }

  var compressedP256Representation: Data {
    return self.p256PublicKey.compressedRepresentation
  }

  var sha256Tag: Data {
    return Data(SHA256.hash(data: self.p256PublicKey.compressedRepresentation).prefix(4))
  }

  func p256HKDFTag(using: Data) -> Data {
    return Data(
      HKDF<SHA256>.extract(
        inputKeyMaterial: SymmetricKey(data: using + self.sha256Tag.prefix(4)),
        salt: "age-encryption.org/p256tag".data(using: .utf8)!)
    ).prefix(4)
  }

  func ageRecipient(type: RecipientType) -> String {
    return Bech32().encode(
      hrp: "age1\(type.rawValue)", data: self.p256PublicKey.compressedRepresentation)
  }
}

struct Identity {
  let p256PrivateKey: SecureEnclaveP256PrivateKey

  init(ageIdentity: String, crypto: Crypto) throws {
    let id = try Bech32().decode(ageIdentity)
    if id.hrp != "AGE-PLUGIN-SE-" {
      throw Plugin.Error.unknownHRP(id.hrp)
    }
    self.p256PrivateKey = try crypto.newSecureEnclaveP256PrivateKey(dataRepresentation: id.data)
  }

  init(accessControl: SecAccessControl, crypto: Crypto) throws {
    self.p256PrivateKey = try crypto.newSecureEnclaveP256PrivateKey(
      accessControl: accessControl)
  }

  var recipient: Recipient {
    return Recipient(p256PublicKey: self.p256PrivateKey.publicKey)
  }

  var ageIdentity: String {
    return Bech32().encode(
      hrp: "AGE-PLUGIN-SE-",
      data: self.p256PrivateKey.dataRepresentation)
  }
}
