import Foundation

@testable import age_plugin_se

#if !os(Linux) && !os(Windows)
  import CryptoKit
#else
  import Crypto
#endif

class DummyCrypto: Crypto {
  // If more keys are needed, add them to the front
  var dummyKeys = [
    "t8Y0uUHLtBvCtuUz0Hdw2lqbwZf6TgYzYKFWMEEFSs8",
    "HxEmObcQ6bcAUC8w6kPWrnlUIwBQoi66ZNpQZ0cAXww",
    "dCDteyAKpkwYd8jCunOz0mvWmy+24zvWV41YBD+Pkeg",
    "NkkLXSZ+yhx9imKKw9cOsbey4C1XZAPuSDMCgTLENrY",
    "bQrp04tXb+diJ6x28Kd8EDt9sCmI5diS36Zy3n49DHg",
    "m8/qMMkYDelvL+ihdUFYyKXBn+7We21fZ5zH/I61y3M",
    "lQq/Pq0GA2QFGTEiNMQIxZHzBnt+nPRXK5gL3X6nnJY",
    "VoUn+n/vzkuDzWgMV9n3e1L+tTSIl0Sg7lXSNDR5XqY",
    "3naom0zZxBZcSZCfoNzyjLVmG6hyRKX8bCU3wukusFI",
    "N2WRutxd1Ed0l4piqArI2gKYSTG7peE8BYBrLLV7YjQ",
  ].map { Data(base64RawEncoded: $0)! }

  var dummyMLKEM768Keys = [
    "09hlAvp48G4FE3FvE3DQ9yQLHgeamWAt/2ht726OOCb+zNi781ZaGhl4dS8vaZChGpBN8Umxj2GNISfLFFs5nQ",
    "Qm46OF6g3a+sBSL9Um1GcNJF9dqtbBLDYPwtkOJNbpgHu0SMf644xCrLnCyImP1Ri4UT4ny+/K3O8owg0dCSdw",
    "vQStBrrzKTynRHPEeAU2OlRmHekYGTdgRYxz0rsVKdaOIZOoaZcGwDf4AxKHYzZqk2UkboSC8nec3KzEWEABDA",
    "ZOihuKRH2jLwex1CHandug43unlX3lKPlOu70KSh6Xx045UWcHUpgzPVZ9PQGBw9WJdykypk7Oq77RyknLNpbQ",
    "dpu2yrxXvP+7J6UNidN3Yh1j74PaUXoVPlNN1WNivNA40OQHTSiBVjOuv2w/AkC1hKgukBHXmGq97AFoFbqD6g",
    "ftj+r9fmxeUjQ8N1TT2JVJDbdTLZZx3lNM8sJzavodnLruWGtpwmbwbsucej9qvS3wXS8oNP0LwmAm9NEnIdLQ",
    "rnfWf61wT3nLS9lNTF6DTzY4tTmgem6Hxd7XyrBRsLgYVMmSMsIqugrVllqzq2skQxRklH2pRizdIIHjZRMadg",
    "b17KmM0XDn3fO1GM0YV4gjXZYTsJS1RIkiYp3QAD6jdLb9i5Fn/Ni6HAW0crRzsQ9DQ8N2Q2mDyJDdnGAJ2zqw",
    "8numQKwcNRbEujlCwAzG9WF4cW3DSfIgz2XoAbtZH6AaTiMbD+tfJFqwItA+deK9XVF1r/lp01BH2Z5QKeZXow",
    "4zYIZbjwk1n9VxVkpiedwrrqQfk0OiP9VAfZYflKV9JTYFNd6BuYzuRjsk31nI0TSsQV+tSc5RaKVXcora4eWA",
  ].map { Data(base64RawEncoded: $0)! }

  // See print() statement below to generate these
  var dummyEncapsulations = [
    KEM.EncapsulationResult(
      sharedSecret: SymmetricKey(
        data: Data(base64RawEncoded: "ax1JNbXUsGHbs6DVjzcC6CrcJHOqLQKbvTjAygBf+E4")!),
      encapsulated: Data(
        base64RawEncoded:
          "2oNGI4Qzlu35omot6u2T870FUQLFH1qV2M5n4MHftYmVylCoFxTKjfKcGHfNdiqGPIEeHVPh+b1HpI6qw6bkZhoHQJpFqKFJu5Lf17fU9cFL+DOSfp1IwTjRXCz3RT0Y+l13WeUgY3lIJCtlu1TS/8rts5twGOLzYRfqeceLm7XT/Y7LUIeMBVQeEuFKYGR5IzBpdn+NZlPgTKfqQ5Qv987kWuZ+lIC9pOtfhXGGUPTF18/fG/OGK2arSd4jFzIrjqKEDPlqyDhWTKuBB3FGDByDXrBke0CbuKotvteWzdASiNFTBD8+SKDxqeDQt9RB2uVE3XwmwBNmBaM+0KqHVMuawgeQRrKBtPMk8fR4KXzFcIN46qugqh5eLNtSwVgJ6HUH2fDSQHp0hR2TVdN9+Y1Ry7D1/RahyWHgxFhcDZ8O9PWn1uPqMoHOhc67RdAjpXhaRxKsfjFKYf5vOvnAivbertz7vm8hU6Sp4ueB2NaAh9gG7lJ8AQSq+36Hrh0nZujARV74l6o9HkqkWJCzRNv1Jv69j3gq3AAjb663pTLrkIzVRPmUAqjLMCjR0nmWM304gyq/5glz6BPIoz4jZvDcQGPZVjEiEL6Ljgq473i3xZLyJZ6PMwDyDTlcA75Ipfx8xHYnyQrIrrMo5so7mgiXtI12edEi8DaVpfm111JKUd5POSzGrOtrU3yogaAFkVsS//2R4Jyk8EImiOpWofF1y960+0sY9rMQfzRUxdaH2F1vc+y1VHoazKZC5tuybDCL4Q1+3yiU9OkBAGea+iAZKBkuY8klbcJmTjNGuEwa2xjeqpcmYT5zPGp+2AdcCFa5IBz7AcrPzGMMWpa6BBas55blrzNWJZ+JQkfk72UcBJKl5v7hYznP1Wtgq52OvdMyCERiDiGRKnLwiq4fGarr7szg11tmrbzuB3++uWQUv9YO9COJwy3SQKLbwJ4bO+P31WpaayEFekhMgczhGXk9ibegdkol0jkroXsAz+mW/s6bKR6dlEOwxIJ4MNDXFjjMO7CjGL3XEdQBIV8EiWnx0d1RUlhjg/Okms4lokCdlJbnKAxqiEGmt6iIsJuk61EINmLlUnVAmiJ9jG4ewlLC7G+hZNkKS0Ek1W6rEmWY0oGJZWTD8I70bKKhmZDTxzaY+p5uC4UlIrBzuIu/C0D2mPd1Q4vlcSR2cqWsflXtBcdvImTkZj+xrPj6eT+5Q4rhBqg+edmKvYc0kp2QjOMXIwvrjVW9rwy/SETHAvih+DUo/nBbFfKnR+6lDdR+MXJrfUhX8BaL2eGt2M3GtvWx9eIATf3yGp9O/pUI96p5OGNIjXIqrLYjQ61uK8H0zdtwRRUDpH/Y4GwgNO+Ufw+mdaXl+e2kS0Hqxp6BFdXvoMM7OXttnM8bhMxcVyc3lwubqpAlOQ2lxepwjlkR5q/RYe93f+jbeRcrmeAfxgQ"
      )!)
  ]

  var isSecureEnclaveAvailable = true
  var failingOperations = false

  func newSecureEnclaveP256PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveP256PrivateKey
  {
    return DummySecureEnclaveP256PrivateKey(
      key: try P256.KeyAgreement.PrivateKey(rawRepresentation: dataRepresentation),
      crypto: self)
  }

  func newSecureEnclaveP256PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveP256PrivateKey
  {
    return DummySecureEnclaveP256PrivateKey(
      key: try P256.KeyAgreement.PrivateKey(rawRepresentation: dummyKeys.popLast()!),
      crypto: self)
  }

  func newEphemeralP256PrivateKey() -> P256.KeyAgreement.PrivateKey {
    return try! P256.KeyAgreement.PrivateKey(rawRepresentation: dummyKeys.popLast()!)
  }

  func newSecureEnclaveMLKEM768PrivateKey(dataRepresentation: Data) throws
    -> SecureEnclaveMLKEM768PrivateKey
  {
    return DummySecureEnclaveMLKEM768PrivateKey(
      key: try MLKEM768.PrivateKey(seedRepresentation: dataRepresentation, publicKey: nil),
      crypto: self)
  }

  func newSecureEnclaveMLKEM768PrivateKey(accessControl: SecAccessControl) throws
    -> SecureEnclaveMLKEM768PrivateKey
  {
    return DummySecureEnclaveMLKEM768PrivateKey(
      key: try MLKEM768.PrivateKey(
        seedRepresentation: dummyMLKEM768Keys.popLast()!, publicKey: nil),
      crypto: self)
  }

  func encapsulate(mlkem768Key: MLKEM768.PublicKey) throws -> KEM.EncapsulationResult {
    return dummyEncapsulations.popLast()!
    // let enc = try mlkem768Key.encapsulate()
    // print(
    //   "enc: \(enc.encapsulated.base64EncodedString()) ss: \(Data(enc.sharedSecret.withUnsafeBytes { Data($0) }).base64EncodedString())"
    // )
    // return enc
  }
}

struct DummySecureEnclaveP256PrivateKey: SecureEnclaveP256PrivateKey {
  var key: P256.KeyAgreement.PrivateKey
  var crypto: DummyCrypto

  var publicKey: P256.KeyAgreement.PublicKey {
    return key.publicKey
  }

  var dataRepresentation: Data {
    return key.rawRepresentation
  }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> SharedSecret
  {
    if crypto.failingOperations {
      throw DummyCryptoError.dummyError
    }
    return try key.sharedSecretFromKeyAgreement(with: publicKeyShare)
  }
}

struct DummySecureEnclaveMLKEM768PrivateKey: SecureEnclaveMLKEM768PrivateKey {
  var key: MLKEM768.PrivateKey
  var crypto: DummyCrypto

  var publicKey: MLKEM768.PublicKey {
    return key.publicKey
  }

  var dataRepresentation: Data {
    return key.seedRepresentation
  }

  func decapsulate(_ encapsulated: Data) throws -> SymmetricKey {
    return try self.key.decapsulate(encapsulated)
  }
}

enum DummyCryptoError: LocalizedError {
  case dummyError

  public var errorDescription: String? {
    switch self {
    case .dummyError: return "dummy error"
    }
  }
}
