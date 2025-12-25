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

  func generateKey(
    accessControl: KeyAccessControl, recipientType: RecipientType, now: Date, pq: Bool = false
  ) throws -> (String, String) {
    if !crypto.isSecureEnclaveAvailable {
      throw Error.seUnsupported
    }
    let createdAt = now.ISO8601Format()
    #if !os(Linux) && !os(Windows)
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
      let secAccessControl = SecAccessControl()
    #endif

    let identity = try Identity(accessControl: secAccessControl, pq: pq, crypto: self.crypto)
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

    let ageRecipient: String
    var recipientsStr = "# public key: \(identity.recipient.ageRecipient(type: recipientType))"
    if pq {
      ageRecipient = try! identity.recipient.ageTagPQRecipient
      recipientsStr += "\n# public key (post-quantum): \(ageRecipient)"
    } else {
      ageRecipient = identity.recipient.ageRecipient(type: recipientType)
    }

    let contents = """
      # created: \(createdAt)
      # access control: \(accessControlStr)
      \(recipientsStr)
      \(identity.ageIdentity)

      """

    return (contents, ageRecipient)
  }

  func generateRecipients(input: String, recipientType: RecipientType, pq: Bool = false) throws
    -> String
  {
    var recipients: [String] = []
    for l in input.split(whereSeparator: \.isNewline) {
      if l.hasPrefix("#") {
        continue
      }
      let sl = String(l.trimmingCharacters(in: .whitespacesAndNewlines))
      let identity = try Identity(ageIdentity: sl, crypto: self.crypto)
      if pq {
        recipients.append(try identity.recipient.ageTagPQRecipient)
      } else {
        recipients.append(identity.recipient.ageRecipient(type: recipientType))
      }
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
            recipient.starts(with: "age1tag1")
              ? .p256tag
              : recipient.starts(with: "age1tagpq") ? .mlkem768p256tag : .pivp256
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
              salt: pkEBytes + recipientKey.p256PublicKey.compressedRepresentation,
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

          case .mlkem768p256tag:
            let (sharedSecret, enc) = try HPKE.mlkemp256Encap(
              recipientP256Key: recipientKey.p256PublicKey,
              recipientMLKEM768Key: recipientKey.mlkem768PublicKey!,
              crypto: crypto)
            (wrapKey, nonce) = HPKE.context(
              kem: .mlkem768P256,
              sharedSecret: sharedSecret,
              info: "age-encryption.org/mlkem768p256tag".data(using: .utf8)!)
            tag = recipientKey.mlkem768p256HKDFTag(using: enc)
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
        case "piv-p256", "p256tag", "mlkem768p256tag":
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
            || (recipientStanza.args[1] == "mlkem768p256tag" && share!.count != 1153)
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
              : type == .mlkem768p256tag
                ? identity.recipient.mlkem768p256HKDFTag(using: shareKeyData)
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
                  + identity.recipient.p256PublicKey.compressedRepresentation,
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

            case .mlkem768p256tag:
              if identity.mlkemPrivateKey == nil {
                throw Error.missingPQ
              }
              let sharedSecret = try HPKE.mlkemp256Decap(
                enc: shareKeyData,
                recipientP256Key: identity.p256PrivateKey,
                recipientMLKEM768Key: identity.mlkemPrivateKey!)
              (wrapKey, nonce) = HPKE.context(
                kem: .mlkem768P256,
                sharedSecret: sharedSecret,
                info: "age-encryption.org/mlkem768p256tag".data(using: .utf8)!)
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
    case pqUnsupported
    case pqUnavailable
    case incompleteStanza
    case invalidStanza
    case invalidRecipient
    case unknownHRP(String)
    case missingPQ

    public var errorDescription: String? {
      switch self {
      case .seUnsupported: return "Secure Enclave not supported on this device"
      case .pqUnsupported: return "Post-quantum not supported in this build"
      case .pqUnavailable: return "This OS does not support post-quantum"
      case .incompleteStanza: return "incomplete stanza"
      case .invalidStanza: return "invalid stanza"
      case .invalidRecipient: return "invalid recipient"
      case .unknownHRP(let hrp): return "unknown HRP: \(hrp)"
      case .missingPQ: return "missing post-quantum key support"
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
  case mlkem768p256tag = "mlkem768p256tag"
  case pivp256 = "piv-p256"
}

////////////////////////////////////////////////////////////////////////////////

struct Recipient {
  let p256PublicKey: P256.KeyAgreement.PublicKey
  let mlkem768PublicKey: MLKEM768.PublicKey?

  init(ageRecipient: String) throws {
    let id = try Bech32().decode(ageRecipient)
    switch id.hrp {
    case "age1se", "age1tag":
      if id.data.count != 33 {
        throw Plugin.Error.invalidRecipient
      }
      self.p256PublicKey = try P256.KeyAgreement.PublicKey(compressedRepresentation: id.data)
      self.mlkem768PublicKey = nil
    case "age1tagpq":
      if id.data.count != 1184 + 65 {
        throw Plugin.Error.invalidRecipient
      }
      self.p256PublicKey = try P256.KeyAgreement.PublicKey(
        x963Representation: id.data[1184...])
      self.mlkem768PublicKey = try MLKEM768.PublicKey(
        rawRepresentation: id.data[..<1184])
      break
    default:
      throw Plugin.Error.unknownHRP(id.hrp)
    }
  }

  init(p256PublicKey: P256.KeyAgreement.PublicKey, mlkem768PublicKey: MLKEM768.PublicKey? = nil) {
    self.p256PublicKey = p256PublicKey
    self.mlkem768PublicKey = mlkem768PublicKey
  }

  var sha256Tag: Data {
    return Data(SHA256.hash(data: self.p256PublicKey.compressedRepresentation).prefix(4))
  }

  func p256HKDFTag(using: Data) -> Data {
    return Data(
      HKDF<SHA256>.extract(
        inputKeyMaterial: SymmetricKey(data: using + self.sha256Tag),
        salt: "age-encryption.org/p256tag".data(using: .utf8)!)
    ).prefix(4)
  }

  func mlkem768p256HKDFTag(using: Data) -> Data {
    let recipientHash = Data(SHA256.hash(data: self.p256PublicKey.x963Representation).prefix(4))
    return Data(
      HKDF<SHA256>.extract(
        inputKeyMaterial: SymmetricKey(data: using + recipientHash.prefix(4)),
        salt: "age-encryption.org/mlkem768p256tag".data(using: .utf8)!)
    ).prefix(4)
  }

  func ageRecipient(type: RecipientType) -> String {
    return Bech32().encode(
      hrp: "age1\(type.rawValue)", data: self.p256PublicKey.compressedRepresentation)
  }

  var ageTagPQRecipient: String {
    get throws {
      guard let mlkem768PublicKey = self.mlkem768PublicKey else {
        throw Plugin.Error.missingPQ
      }
      return Bech32().encode(
        hrp: "age1tagpq",
        data: mlkem768PublicKey.rawRepresentation + self.p256PublicKey.x963Representation)
    }
  }
}

struct Identity {
  let p256PrivateKey: SecureEnclaveP256PrivateKey
  let mlkemPrivateKey: SecureEnclaveMLKEM768PrivateKey?

  init(ageIdentity: String, crypto: Crypto) throws {
    let id = try Bech32().decode(ageIdentity)
    if id.hrp != "AGE-PLUGIN-SE-" {
      throw Plugin.Error.unknownHRP(id.hrp)
    }
    do {
      let (p256Data, mlkemData) = Identity.parseData(id.data)
      if mlkemData != nil {
        let p256PrivateKey = try crypto.newSecureEnclaveP256PrivateKey(
          dataRepresentation: p256Data)
        self.mlkemPrivateKey = try crypto.newSecureEnclaveMLKEM768PrivateKey(
          dataRepresentation: mlkemData!)
        self.p256PrivateKey = p256PrivateKey
        return
      }
    } catch {
      // Fall through to non-pq format
    }
    self.p256PrivateKey = try crypto.newSecureEnclaveP256PrivateKey(dataRepresentation: id.data)
    self.mlkemPrivateKey = nil
  }

  init(accessControl: SecAccessControl, pq: Bool, crypto: Crypto) throws {
    self.p256PrivateKey = try crypto.newSecureEnclaveP256PrivateKey(
      accessControl: accessControl)
    if pq {
      self.mlkemPrivateKey = try crypto.newSecureEnclaveMLKEM768PrivateKey(
        accessControl: accessControl)
    } else {
      self.mlkemPrivateKey = nil
    }
  }

  private static func parseData(_ data: Data) -> (p256Data: Data, mlkemData: Data?) {
    var offset = 0

    // P-256 key
    if data.count < offset + 2 {
      return (data, nil)
    }
    let p256Count = Int(data[offset]) << 8 | Int(data[offset + 1])
    offset += 2
    if data.count < offset + p256Count {
      return (data, nil)
    }
    let p256Data = data[offset..<(offset + p256Count)]
    offset += p256Count

    // MLKEM-768 key
    if data.count < offset + 2 {
      return (data, nil)
    }
    let mlkemCount = Int(data[offset]) << 8 | Int(data[offset + 1])
    offset += 2
    if data.count < offset + mlkemCount {
      return (data, nil)
    }
    let mlkemData = data[offset..<(offset + mlkemCount)]
    offset += mlkemCount

    // Remainder
    if data.count != offset {
      return (data, nil)
    }
    return (p256Data: p256Data, mlkemData: mlkemData)
  }

  var recipient: Recipient {
    return Recipient(
      p256PublicKey: self.p256PrivateKey.publicKey,
      mlkem768PublicKey: self.mlkemPrivateKey?.publicKey)
  }

  var ageIdentity: String {
    var data: Data
    if self.mlkemPrivateKey == nil {
      data = self.p256PrivateKey.dataRepresentation
    } else {
      let p256data = self.p256PrivateKey.dataRepresentation
      let mlkemdata = self.mlkemPrivateKey!.dataRepresentation
      data =
        Data([UInt8(p256data.count >> 8), UInt8(p256data.count & 0xFF)]) + p256data
        + Data([UInt8(mlkemdata.count >> 8), UInt8(mlkemdata.count & 0xFF)]) + mlkemdata
    }
    return Bech32().encode(hrp: "AGE-PLUGIN-SE-", data: data)
  }
}
