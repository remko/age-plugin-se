import Foundation

#if !os(Linux) && !os(Windows)
  import CryptoKit
  import LocalAuthentication
#else
  import Crypto
  struct SecAccessControl {}
#endif

/// Abstraction for random/unpredictable/system-specific crypto operations
protocol Crypto {
  var isSecureEnclaveAvailable: Bool { get }

  func newSecureEnclavePrivateKey(dataRepresentation: Data) throws -> SecureEnclavePrivateKey
  func newSecureEnclavePrivateKey(accessControl: SecAccessControl) throws -> SecureEnclavePrivateKey
  func newEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey
}

protocol SecureEnclavePrivateKey {
  var publicKey: P256.KeyAgreement.PublicKey { get }
  var dataRepresentation: Data { get }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> SharedSecret
}

#if !os(Linux) && !os(Windows)
  class CryptoKitCrypto: Crypto {
    let context = LAContext()

    var isSecureEnclaveAvailable: Bool {
      return SecureEnclave.isAvailable
    }

    func newSecureEnclavePrivateKey(dataRepresentation: Data) throws -> SecureEnclavePrivateKey {
      return try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: dataRepresentation, authenticationContext: context)
    }

    func newSecureEnclavePrivateKey(accessControl: SecAccessControl) throws
      -> SecureEnclavePrivateKey
    {
      return try SecureEnclave.P256.KeyAgreement.PrivateKey(
        accessControl: accessControl, authenticationContext: context)
    }

    func newEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey {
      return P256.KeyAgreement.PrivateKey()
    }
  }

  extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecureEnclavePrivateKey {
  }

#else

  class CryptoKitCrypto: Crypto {
    var isSecureEnclaveAvailable: Bool {
      return false
    }

    func newSecureEnclavePrivateKey(dataRepresentation: Data) throws -> SecureEnclavePrivateKey {
      throw Plugin.Error.seUnsupported
    }

    func newSecureEnclavePrivateKey(accessControl: SecAccessControl) throws
      -> SecureEnclavePrivateKey
    {
      throw Plugin.Error.seUnsupported
    }

    func newEphemeralPrivateKey() -> P256.KeyAgreement.PrivateKey {
      return P256.KeyAgreement.PrivateKey()
    }
  }

#endif
