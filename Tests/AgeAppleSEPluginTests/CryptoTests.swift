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

  func testSeal() throws {
    let k = SymmetricKey(size: .bits256)
    let body1 = try crypto.seal("0123456789abcdef".data(using: .utf8)!, using: k)
    let body2 = try crypto.seal("0123456789abcdef".data(using: .utf8)!, using: k)
    XCTAssertEqual(body1, body2)
    XCTAssertEqual(32, body1.count)
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

  func testSeal() throws {
    let k = SymmetricKey(size: .bits256)
    let body1 = try DummyCrypto().seal("0123456789abcdef".data(using: .utf8)!, using: k)
    let body2 = try DummyCrypto().seal("0123456789abcdef".data(using: .utf8)!, using: k)
    XCTAssertEqual(body1, body2)
    XCTAssertEqual(32, body1.count)
  }
}
