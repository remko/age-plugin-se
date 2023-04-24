import XCTest

@testable import age_plugin_se

#if !os(Linux) && !os(Windows)
  import CryptoKit
#else
  import Crypto
#endif

final class CryptoKitCryptoTests: XCTestCase {
  var crypto = CryptoKitCrypto()

  func testNewEphemeralPrivateKey() throws {
    let k1 = crypto.newEphemeralPrivateKey()
    let k2 = crypto.newEphemeralPrivateKey()

    XCTAssertNotEqual(k1.rawRepresentation, k2.rawRepresentation)
    XCTAssertNotEqual(k1.publicKey.rawRepresentation, k2.publicKey.rawRepresentation)
  }

  func testNewEphemeralPrivateKey_DifferentCrypto() throws {
    let k1 = CryptoKitCrypto().newEphemeralPrivateKey()
    let k2 = CryptoKitCrypto().newEphemeralPrivateKey()

    XCTAssertNotEqual(k1.rawRepresentation, k2.rawRepresentation)
    XCTAssertNotEqual(k1.publicKey.rawRepresentation, k2.publicKey.rawRepresentation)
  }

  // A test to validate that CryptoKit / Swift Crypto cannot do any operations with points at infinity
  func testPointAtInfinity() throws {
    let sk = P256.KeyAgreement.PrivateKey()

    // base64.b64encode(ECC.generate(curve="p256").export_key(format="DER"))
    let pk = try P256.KeyAgreement.PublicKey(
      derRepresentation: Data(
        base64Encoded:
          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0Zl262mVCr+1pi9396tEdXC0HIQnENUkWal3nOzLWvX+TYja1xVE++6WzRvunrkBT91380BIJZvB7ZiiEN+Y1A=="
      )!)

    // Test that operations work from a regular DER constructed key
    let _ = try sk.sharedSecretFromKeyAgreement(with: pk)

    func run() throws {
      // base64.b64encode(ECC.EccKey(curve = "p256", point = ECC.generate(curve="p256").pointQ.point_at_infinity()).export_key(format="DER"))
      // Swift Crypto throws at construction time
      let identityPK = try P256.KeyAgreement.PublicKey(
        derRepresentation: Data(
          base64Encoded:
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        )!)

      // CryptoKit throws at operation time
      let _ = try sk.sharedSecretFromKeyAgreement(with: identityPK)
    }

    XCTAssertThrowsError(try run())
  }
}

final class DummyCryptoTests: XCTestCase {
  var crypto = DummyCrypto()

  func testNewEphemeralPrivateKey() throws {
    let k1 = crypto.newEphemeralPrivateKey()
    let k2 = crypto.newEphemeralPrivateKey()

    XCTAssertNotEqual(k1.rawRepresentation, k2.rawRepresentation)
    XCTAssertNotEqual(k1.publicKey.rawRepresentation, k2.publicKey.rawRepresentation)
  }

  func testNewEphemeralPrivateKey_DifferentCrypto() throws {
    let k1 = DummyCrypto().newEphemeralPrivateKey()
    let k2 = DummyCrypto().newEphemeralPrivateKey()

    XCTAssertEqual(k1.rawRepresentation, k2.rawRepresentation)
    XCTAssertEqual(k1.publicKey.rawRepresentation, k2.publicKey.rawRepresentation)
  }
}
