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

  func newSecureEnclaveP256PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveP256PrivateKey
  func newSecureEnclaveP256PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveP256PrivateKey
  func newEphemeralP256PrivateKey() -> P256.KeyAgreement.PrivateKey
}

protocol SecureEnclaveP256PrivateKey {
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

    func newSecureEnclaveP256PrivateKey(dataRepresentation: Data) throws
      -> SecureEnclaveP256PrivateKey
    {
      return try SecureEnclave.P256.KeyAgreement.PrivateKey(
        dataRepresentation: dataRepresentation, authenticationContext: context)
    }

    func newSecureEnclaveP256PrivateKey(accessControl: SecAccessControl) throws
      -> SecureEnclaveP256PrivateKey
    {
      return try SecureEnclave.P256.KeyAgreement.PrivateKey(
        accessControl: accessControl, authenticationContext: context)
    }

    func newEphemeralP256PrivateKey() -> P256.KeyAgreement.PrivateKey {
      return P256.KeyAgreement.PrivateKey()
    }
  }

  extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecureEnclaveP256PrivateKey {
  }

#else

  class CryptoKitCrypto: Crypto {
    var isSecureEnclaveAvailable: Bool {
      return false
    }

    func newSecureEnclaveP256PrivateKey(dataRepresentation: Data) throws
      -> SecureEnclaveP256PrivateKey
    {
      throw Plugin.Error.seUnsupported
    }

    func newSecureEnclaveP256PrivateKey(accessControl: SecAccessControl) throws
      -> SecureEnclaveP256PrivateKey
    {
      throw Plugin.Error.seUnsupported
    }

    func newEphemeralP256PrivateKey() -> P256.KeyAgreement.PrivateKey {
      return P256.KeyAgreement.PrivateKey()
    }
  }

#endif
