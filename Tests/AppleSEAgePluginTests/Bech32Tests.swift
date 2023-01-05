import XCTest

@testable import age_plugin_applese

final class Bech32Tests: XCTestCase {
  func testEncode() throws {
    XCTAssertEqual("Foo", Bech32.encode())
  }
}
