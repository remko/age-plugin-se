import Foundation

#if !os(Linux) && !os(Windows)
  import CryptoKit
  import LocalAuthentication
#else
  import Crypto
#endif

enum HPKE {
  enum KEM: UInt16 {
    case dhkemP256 = 0x0010
    // case mlkem768P256 = 0x0050

    var suiteID: Data {
      var data = Data("HPKE".utf8)
      data.append(contentsOf: [
        UInt8((rawValue >> 8) & 0xff),
        UInt8(rawValue & 0xff),
        0x00, 0x01,  // KDF: HKDF-SHA256
        0x00, 0x03,  // AEAD: ChaCha20Poly1305
      ])
      return data
    }
  }

  static func context(kem: KEM, sharedSecret: SymmetricKey, info: Data) -> (
    key: SymmetricKey, nonce: ChaChaPoly.Nonce
  ) {
    let suiteID = kem.suiteID
    let pskIDHash = labeledExtract(
      suiteID: suiteID, salt: nil, label: "psk_id_hash", ikm: Data())
    let infoHash = labeledExtract(suiteID: suiteID, salt: nil, label: "info_hash", ikm: info)

    var ksContext = Data([0x00])  // mode_base
    ksContext.append(pskIDHash)
    ksContext.append(infoHash)

    let secret = labeledExtract(
      suiteID: suiteID, salt: sharedSecret.withUnsafeBytes { Data($0) }, label: "secret",
      ikm: Data())
    return (
      key: labeledExpand(
        suiteID: suiteID, prk: secret, label: "key", info: ksContext, length: 32),
      nonce: try! ChaChaPoly.Nonce(
        data: labeledExpand(
          suiteID: suiteID, prk: secret, label: "base_nonce", info: ksContext, length: 12
        ).withUnsafeBytes { Data($0) })
    )
  }

  static func dhkemEncap(recipientKey: P256.KeyAgreement.PublicKey, crypto: Crypto) throws -> (
    sharedSecret: SymmetricKey, enc: Data
  ) {
    let skE = crypto.newEphemeralP256PrivateKey()
    let enc = skE.publicKey.x963Representation
    let sharedSecret = HPKE.extractAndExpand(
      suiteID: "KEM".data(using: .utf8)! + Data([0x00, 0x10]),
      dh: (try skE.sharedSecretFromKeyAgreement(with: recipientKey))
        .withUnsafeBytes {
          Data($0)
        },
      kemContext: enc + recipientKey.x963Representation,
      nSecret: 32)
    return (sharedSecret: sharedSecret, enc: enc)
  }

  static func dhkemDecap(enc: Data, recipientKey: SecureEnclaveP256PrivateKey) throws
    -> SymmetricKey
  {
    let shareKey = try P256.KeyAgreement.PublicKey(x963Representation: enc)
    let sharedSecret = HPKE.extractAndExpand(
      suiteID: "KEM".data(using: .utf8)! + Data([0x00, 0x10]),
      dh: (try recipientKey.sharedSecretFromKeyAgreement(with: shareKey))
        .withUnsafeBytes { Data($0) },
      kemContext: enc + recipientKey.publicKey.x963Representation,
      nSecret: 32)
    return sharedSecret
  }

  private static func labeledExtract(suiteID: Data, salt: Data?, label: String, ikm: Data) -> Data {
    var labeledIKM = Data("HPKE-v1".utf8)
    labeledIKM.append(suiteID)
    labeledIKM.append(Data(label.utf8))
    labeledIKM.append(ikm)
    return Data(
      HKDF<SHA256>.extract(
        inputKeyMaterial: SymmetricKey(data: labeledIKM), salt: salt ?? Data()))
  }

  private static func labeledExpand(
    suiteID: Data, prk: Data, label: String, info: Data, length: Int
  )
    -> SymmetricKey
  {
    var labeledInfo = Data()
    labeledInfo.append(UInt8((length >> 8) & 0xff))
    labeledInfo.append(UInt8(length & 0xff))
    labeledInfo.append(Data("HPKE-v1".utf8))
    labeledInfo.append(suiteID)
    labeledInfo.append(Data(label.utf8))
    labeledInfo.append(info)
    return HKDF<SHA256>.expand(
      pseudoRandomKey: SymmetricKey(data: prk), info: labeledInfo, outputByteCount: length
    )
  }

  private static func extractAndExpand(suiteID: Data, dh: Data, kemContext: Data, nSecret: Int)
    -> SymmetricKey
  {
    let eaePRK = labeledExtract(suiteID: suiteID, salt: nil, label: "eae_prk", ikm: dh)
    return labeledExpand(
      suiteID: suiteID,
      prk: eaePRK,
      label: "shared_secret",
      info: kemContext,
      length: nSecret
    )
  }
}
