import CryptoKit
import Foundation
import LocalAuthentication

/// Abstraction for random/unpredictable/system-specific crypto operations
protocol Crypto {
  var isSecureEnclaveAvailable: Bool { get }

  func SecureEnclavePrivateKey(dataRepresentation: Data) throws -> SecureEnclavePrivateKey
  func SecureEnclavePrivateKey(accessControl: SecAccessControl) throws -> SecureEnclavePrivateKey
  func newEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey
}

protocol SecureEnclavePrivateKey {
  var publicKey: P256.KeyAgreement.PublicKey { get }
  var dataRepresentation: Data { get }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> SharedSecret
}

class CryptoKitCrypto: Crypto {
  let context = LAContext()

  var isSecureEnclaveAvailable: Bool {
    return SecureEnclave.isAvailable
  }

  func SecureEnclavePrivateKey(dataRepresentation: Data) throws -> SecureEnclavePrivateKey {
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: dataRepresentation, authenticationContext: context)
  }

  func SecureEnclavePrivateKey(accessControl: SecAccessControl) throws -> SecureEnclavePrivateKey {
    return try SecureEnclave.P256.KeyAgreement.PrivateKey(
      accessControl: accessControl, authenticationContext: context)
  }

  func newEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey {
    return P256.KeyAgreement.PrivateKey()
  }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecureEnclavePrivateKey {
}
