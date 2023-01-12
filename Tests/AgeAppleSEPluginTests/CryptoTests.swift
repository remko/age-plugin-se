import CryptoKit
import XCTest

@testable import age_plugin_applese

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
