import XCTest

@testable import age_plugin_applese

final class StanzaTests: XCTestCase {
  var stream = MemoryStream()

  override func setUp() {
    stream = MemoryStream()
  }

  func testReadFrom() throws {
    stream.add(
      input:
        """
        -> mytype MyArgument1 MyArgument2
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
        """)
    XCTAssertEqual(
      Stanza(
        type: "mytype",
        args: ["MyArgument1", "MyArgument2"],
        body:
          "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
          .data(using: .utf8)!
      ), try Stanza.readFrom(stream: stream))
  }

  func testReadFrom_EmptyBody() throws {
    stream.add(
      input:
        """
        -> mytype

        """)
    XCTAssertEqual(
      Stanza(
        type: "mytype",
        args: [],
        body: Data()
      ), try Stanza.readFrom(stream: stream))
  }

  func testReadFrom_EmptyLastLine() throws {
    stream.add(
      input:
        """
        -> mystanza
        TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2Np

        """)
    XCTAssertEqual(
      Stanza(
        type: "mystanza",
        args: [],
        body:
          "Lorem ipsum dolor sit amet, consectetur adipisci"
          .data(using: .utf8)!
      ), try Stanza.readFrom(stream: stream))
  }

  func testReadFrom_MissingType() throws {
    stream.add(
      input:
        """
        ->
        IGVzdCBsYWJvcnVtLg
        """)
    XCTAssertThrowsError(try Stanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.invalidStanza)
    }
  }

  func testReadFrom_InvalidPrefix() throws {
    stream.add(
      input:
        """
        => mystanza
        IGVzdCBsYWJvcnVtLg
        """)
    XCTAssertThrowsError(try Stanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.invalidStanza)
    }
  }

  func testReadFrom_BodyTooLong() throws {
    stream.add(
      input:
        """
        -> mystanza
        dW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg
        """)
    XCTAssertThrowsError(try Stanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.invalidStanza)
    }
  }

  func testReadFrom_BodyInvalid() throws {
    stream.add(
      input:
        """
        -> mystanza
        _dW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVtLg
        """)
    XCTAssertThrowsError(try Stanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.invalidStanza)
    }
  }

  func testReadFrom_BodyIncomplete() throws {
    stream.add(
      input:
        """
        -> mystanza
        dW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlk
        """)
    XCTAssertThrowsError(try Stanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.incompleteStanza)
    }
  }

  func testReadFrom_BodyMissing() throws {
    stream.add(
      input:
        """
        -> mystanza
        """)
    XCTAssertThrowsError(try Stanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.incompleteStanza)
    }
  }

  func testReadFrom_BodyHasPadding() throws {
    stream.add(
      input:
        """
        => mystanza
        IGVzdCBsYWJvcnVtLg==
        """)
    XCTAssertThrowsError(try Stanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.invalidStanza)
    }
  }

  func testReadFrom_NoInput() throws {
    XCTAssertThrowsError(try Stanza.readFrom(stream: stream)) { error in
      XCTAssertEqual(error as! Plugin.Error, Plugin.Error.incompleteStanza)
    }
  }

  func testWriteTo() throws {
    Stanza(
      type: "mytype",
      args: ["MyArgument1", "MyArgument2"],
      body:
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        .data(using: .utf8)!
    ).writeTo(stream: stream)
    XCTAssertEqual(
      """
      -> mytype MyArgument1 MyArgument2
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
      """, stream.output)
  }

  func testWriteTo_NoArguments() throws {
    Stanza(
      type: "mytype",
      body: "Lorem ipsum".data(using: .utf8)!
    ).writeTo(stream: stream)
    XCTAssertEqual(
      """
      -> mytype
      TG9yZW0gaXBzdW0
      """, stream.output)
  }

  func testWriteTo_EmptyBody() throws {
    Stanza(
      type: "mytype",
      args: [],
      body: Data()
    ).writeTo(stream: stream)
    XCTAssertEqual(
      """
      -> mytype

      """, stream.output)
  }
}
