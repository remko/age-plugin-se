import XCTest

@testable import age_plugin_applese

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

  func testParse_AgePlugin() throws {
    let options = try Options.parse(["_", "keygen", "--age-plugin=identity-v1"])
    XCTAssertEqual(.plugin(.identityV1), options.command)
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
