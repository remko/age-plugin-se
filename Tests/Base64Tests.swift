import XCTest

@testable import age_plugin_applese

final class Base64Tests: XCTestCase {
  func testDataInitBase64RawEncoded_NeedsNoPad() throws {
    XCTAssertEqual(
      Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
      Data(base64RawEncoded: "AQIDBAUG"))
  }

  func testDataInitBase64RawEncoded_Needs1Pad() throws {
    XCTAssertEqual(
      Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
      Data(base64RawEncoded: "AQIDBAUGBwg"))
  }

  func testDataInitBase64RawEncoded_Needs2Pads() throws {
    XCTAssertEqual(
      Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
      Data(base64RawEncoded: "AQIDBAUGBw"))
  }

  func testDataInitBase64RawEncoded_HasPad() throws {
    XCTAssertEqual(
      nil,
      Data(base64RawEncoded: "AQIDBAUGBwg="))
  }

  func testDataInit_InvalidBase64() throws {
    XCTAssertEqual(
      nil,
      Data(base64RawEncoded: "A_QIDBAUG"))
  }

  func testDataBase64RawEncodedData() throws {
    XCTAssertEqual(
      "AQIDBAUGBw".data(using: .utf8),
      Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]).base64RawEncodedData)
  }

  func testDataBase64RawEncodedData_Long() throws {
    XCTAssertEqual(
      """
      TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np
      bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFi
      b3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVu
      aWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBu
      aXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0
      ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxp
      dCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBF
      eGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBz
      dW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlk
      IGVzdCBsYWJvcnVtLg
      """.data(using: .utf8),
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        .data(using: .utf8)!
        .base64RawEncodedData)
  }

  func testDataBase64RawEncodedString_Long() throws {
    XCTAssertEqual(
      """
      TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np
      bmcgZWxpdCwgc2VkIGRvIGVpdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFi
      b3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0gdmVu
      aWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBu
      aXNpIHV0IGFsaXF1aXAgZXggZWEgY29tbW9kbyBjb25zZXF1YXQuIER1aXMgYXV0
      ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxp
      dCBlc3NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBF
      eGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQgbm9uIHByb2lkZW50LCBz
      dW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlk
      IGVzdCBsYWJvcnVtLg
      """,
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        .data(using: .utf8)!
        .base64RawEncodedString)
  }
}
