import Foundation

#if !os(Linux) && !os(Windows)
  import CryptoKit
  import LocalAuthentication
#else
  import Crypto
  struct SecAccessControl {}
#endif

#if compiler(<6.2)
  enum MLKEM768 {
    struct PublicKey {
      init(rawRepresentation: Data) throws {
        throw Plugin.Error.pqUnsupported
      }

      func encapsulate() throws -> KEM.EncapsulationResult {
        throw Plugin.Error.pqUnsupported
      }

      var rawRepresentation: Data {
        fatalError(Plugin.Error.pqUnsupported.localizedDescription)
      }
    }

    struct PrivateKey {
      init(seedRepresentation: Data, publicKey: MLKEM768.PublicKey?) throws {
        throw Plugin.Error.pqUnsupported
      }

      var publicKey: MLKEM768.PublicKey {
        fatalError(Plugin.Error.pqUnsupported.localizedDescription)
      }

      var seedRepresentation: Data {
        fatalError(Plugin.Error.pqUnsupported.localizedDescription)
      }

      func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
        throw Plugin.Error.pqUnsupported
      }
    }
  }
#endif

/// Abstraction for random/unpredictable/system-specific crypto operations
protocol Crypto {
  var isSecureEnclaveAvailable: Bool { get }

  func newSecureEnclaveP256PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveP256PrivateKey
  func newSecureEnclaveP256PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveP256PrivateKey
  func newEphemeralP256PrivateKey() -> P256.KeyAgreement.PrivateKey

  func newSecureEnclaveMLKEM768PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveMLKEM768PrivateKey
  func newSecureEnclaveMLKEM768PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveMLKEM768PrivateKey
  func encapsulate(mlkem768Key: MLKEM768.PublicKey) throws -> KEM.EncapsulationResult
}

protocol SecureEnclaveP256PrivateKey {
  var publicKey: P256.KeyAgreement.PublicKey { get }
  var dataRepresentation: Data { get }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> SharedSecret
}

protocol SecureEnclaveMLKEM768PrivateKey {
  var publicKey: MLKEM768.PublicKey { get }
  var dataRepresentation: Data { get }

  func decapsulate(_ encapsulated: Data) throws -> SymmetricKey
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

    func newSecureEnclaveMLKEM768PrivateKey(dataRepresentation: Data) throws
      -> SecureEnclaveMLKEM768PrivateKey
    {
      #if compiler(>=6.2)
        if #unavailable(macOS 21.0) {
          throw Plugin.Error.pqUnavailable
        }
        return try SecureEnclave.MLKEM768.PrivateKey(
          dataRepresentation: dataRepresentation, authenticationContext: context)
      #else
        throw Plugin.Error.pqUnsupported
      #endif
    }
    func newSecureEnclaveMLKEM768PrivateKey(accessControl: SecAccessControl) throws
      -> SecureEnclaveMLKEM768PrivateKey
    {
      #if compiler(>=6.2)
        if #unavailable(macOS 21.0) {
          throw Plugin.Error.pqUnavailable
        }
        return try SecureEnclave.MLKEM768.PrivateKey(
          accessControl: accessControl, authenticationContext: context)
      #else
        throw Plugin.Error.pqUnsupported
      #endif
    }

    func encapsulate(mlkem768Key: MLKEM768.PublicKey) throws -> KEM.EncapsulationResult {
      return try mlkem768Key.encapsulate()
    }
  }

  extension SecureEnclave.P256.KeyAgreement.PrivateKey: SecureEnclaveP256PrivateKey {
  }

  #if compiler(>=6.2)
    extension SecureEnclave.MLKEM768.PrivateKey: SecureEnclaveMLKEM768PrivateKey {
    }
  #endif

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

    func newSecureEnclaveMLKEM768PrivateKey(accessControl: SecAccessControl) throws
      -> SecureEnclaveMLKEM768PrivateKey
    {
      throw Plugin.Error.seUnsupported
    }

    func newSecureEnclaveMLKEM768PrivateKey(dataRepresentation: Data) throws
      -> SecureEnclaveMLKEM768PrivateKey
    {
      throw Plugin.Error.seUnsupported
    }

    func encapsulate(mlkem768Key: MLKEM768.PublicKey) throws -> KEM.EncapsulationResult {
      return try mlkem768Key.encapsulate()
    }
  }

#endif
