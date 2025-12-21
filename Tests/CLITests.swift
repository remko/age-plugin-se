import XCTest

@testable import age_plugin_se

final class OptionsTests: XCTestCase {
  func testParse_NoArguments() throws {
    let options = try Options.parse(["_"])
    XCTAssertEqual(.help, options.command)
  }

  func testParse_CommandWithHelp() throws {
    let options = try Options.parse(["_", "keygen", "--help"])
    XCTAssertEqual(.help, options.command)
  }

  func testParse_CommandWithVersion() throws {
    let options = try Options.parse(["_", "keygen", "--version"])
    XCTAssertEqual(.version, options.command)
  }

  func testParse_Keygen() throws {
    let options = try Options.parse(["_", "keygen", "--access-control=any-biometry"])
    XCTAssertEqual(.keygen, options.command)
    XCTAssertEqual(.anyBiometry, options.accessControl)
  }

  func testParse_KeyGen_InvalidAccessControl() throws {
    XCTAssertThrowsError(try Options.parse(["_", "keygen", "--access-control=unknown"])) { error in
      XCTAssertEqual(
        Options.Error.invalidValue("--access-control", "unknown"), error as! Options.Error)
    }
  }

  func testParse_Recipients() throws {
    let options = try Options.parse([
      "_", "recipients", "--output=recipients.txt", "--input=identity.txt",
    ])
    XCTAssertEqual(.recipients, options.command)
    XCTAssertEqual(.se, options.recipientType)
    XCTAssertEqual("identity.txt", options.input)
    XCTAssertEqual("recipients.txt", options.output)
  }

  func testParse_Recipients_P256TagRecipientType() throws {
    let options = try Options.parse([
      "_", "recipients", "--recipient-type=tag", "--output=recipients.txt",
      "--input=identity.txt",
    ])
    XCTAssertEqual(.recipients, options.command)
    XCTAssertEqual(.tag, options.recipientType)
    XCTAssertEqual("identity.txt", options.input)
    XCTAssertEqual("recipients.txt", options.output)
  }

  func testParse_Recipients_SERecipientType() throws {
    let options = try Options.parse([
      "_", "recipients", "--recipient-type=se", "--output=recipients.txt", "--input=identity.txt",
    ])
    XCTAssertEqual(.recipients, options.command)
    XCTAssertEqual(.se, options.recipientType)
    XCTAssertEqual("identity.txt", options.input)
    XCTAssertEqual("recipients.txt", options.output)
  }

  func testParse_Recipients_InvalidRecipientType() throws {
    XCTAssertThrowsError(
      try Options.parse([
        "_", "recipients", "--recipient-type=invalid", "--output=recipients.txt",
        "--input=identity.txt",
      ])
    ) { error in
      XCTAssertEqual(
        Options.Error.invalidValue("--recipient-type", "invalid"), error as! Options.Error)
    }
  }

  func testParse_Recipients_NoOptions() throws {
    let options = try Options.parse(["_", "recipients"])
    XCTAssertEqual(.recipients, options.command)
    XCTAssertEqual(nil, options.input)
    XCTAssertEqual(nil, options.output)
  }

  func testParse_AgePlugin() throws {
    let options = try Options.parse(["_", "--age-plugin=identity-v1"])
    XCTAssertEqual(.plugin(.identityV1), options.command)
  }

  func testParse_AgePlugin_InvalidPlugin() throws {
    XCTAssertThrowsError(try Options.parse(["_", "--age-plugin=unknown-v1"])) { error in
      XCTAssertEqual(
        Options.Error.invalidValue("--age-plugin", "unknown-v1"), error as! Options.Error)
    }
  }

  func testParse_LongOptionWithEqual() throws {
    let options = try Options.parse(["_", "keygen", "--output=foo.txt"])
    XCTAssertEqual(.keygen, options.command)
    XCTAssertEqual("foo.txt", options.output)
  }

  func testParse_LongOptionWithoutEqual() throws {
    let options = try Options.parse(["_", "keygen", "--output", "foo.txt"])
    XCTAssertEqual(.keygen, options.command)
    XCTAssertEqual("foo.txt", options.output)
  }

  func testParse_LongOptionWithoutValue() throws {
    XCTAssertThrowsError(try Options.parse(["_", "keygen", "--output"])) { error in
      XCTAssertEqual(Options.Error.missingValue("--output"), error as! Options.Error)
    }
  }
}
