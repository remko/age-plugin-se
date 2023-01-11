import CryptoKit
import Foundation

/// Abstraction for random/unpredictable/system-specific crypto operations
protocol Crypto {
  var isSecureEnclaveAvailable: Bool { get }

  func SecureEnclavePrivateKey(dataRepresentation: Data) throws -> SecureEnclavePrivateKey
  func SecureEnclavePrivateKey(accessControl: SecAccessControl) throws -> SecureEnclavePrivateKey
  func newEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey
  func seal(_: Data, using: SymmetricKey) throws -> Data
  func open(sealed ciphertext: Data, using key: SymmetricKey) throws -> Data
}

protocol SecureEnclavePrivateKey {
  var publicKey: P256.KeyAgreement.PublicKey { get }
  var dataRepresentation: Data { get }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> SharedSecret
}

class CryptoKitCrypto: Crypto {
  let nullNonce: ChaChaPoly.Nonce

  init() {
    nullNonce = try! ChaChaPoly.Nonce(data: Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))
  }

  var isSecureEnclaveAvailable: Bool {
    return SecureEnclave.isAvailable
  }

  func SecureEnclavePrivateKey(dataRepresentation: Data) throws -> SecureEnclavePrivateKey {
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation)
  }

  func SecureEnclavePrivateKey(accessControl: SecAccessControl) throws -> SecureEnclavePrivateKey {
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl)
  }

  func newEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey {
    return P256.KeyAgreement.PrivateKey()
  }

  func seal(_ plaintext: Data, using key: SymmetricKey) throws -> Data {
    let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nullNonce)
    return box.ciphertext + box.tag
  }

  func open(sealed box: Data, using key: SymmetricKey) throws -> Data {
    return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: nullNonce + box), using: key)
  }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecureEnclavePrivateKey {
}
