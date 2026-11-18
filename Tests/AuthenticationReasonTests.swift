import XCTest

@testable import age_plugin_se

#if !os(Linux) && !os(Windows)
  import CryptoKit
#else
  import Crypto
#endif

final class AuthenticationReasonTests: XCTestCase {
  var configHome: URL!
  var recipient: Recipient!

  override func setUpWithError() throws {
    configHome = FileManager.default.temporaryDirectory
      .appendingPathComponent("age-plugin-se-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(
      at: configHome.appendingPathComponent("age-plugin-se"), withIntermediateDirectories: true)
    recipient = Recipient(p256PublicKey: P256.KeyAgreement.PrivateKey().publicKey)
  }

  override func tearDownWithError() throws {
    try? FileManager.default.removeItem(at: configHome)
  }

  private var environment: [String: String] {
    return ["XDG_CONFIG_HOME": configHome.path]
  }

  private func writeNames(_ contents: String) throws {
    try contents.write(
      to: configHome.appendingPathComponent("age-plugin-se/names"), atomically: true,
      encoding: .utf8)
  }

  func testKeyName_SERecipient() throws {
    try writeNames("\(recipient.ageRecipient(type: .se)) Production key\n")
    XCTAssertEqual(
      AuthenticationReason.keyName(for: recipient, environment: environment), "Production key")
  }

  func testKeyName_TagRecipient() throws {
    try writeNames("\(recipient.ageRecipient(type: .tag)) Tag key\n")
    XCTAssertEqual(
      AuthenticationReason.keyName(for: recipient, environment: environment), "Tag key")
  }

  func testKeyName_SkipsCommentsBlankLinesAndOtherKeys() throws {
    let other = Recipient(p256PublicKey: P256.KeyAgreement.PrivateKey().publicKey)
    try writeNames(
      """
      # names for my keys

      \(other.ageRecipient(type: .se)) Other key
        \(recipient.ageRecipient(type: .se))   My key
      """)
    XCTAssertEqual(AuthenticationReason.keyName(for: recipient, environment: environment), "My key")
  }

  func testKeyName_NotListed() throws {
    try writeNames("# nothing here\n")
    XCTAssertNil(AuthenticationReason.keyName(for: recipient, environment: environment))
  }

  func testKeyName_NoFile() throws {
    XCTAssertNil(AuthenticationReason.keyName(for: recipient, environment: environment))
  }

  func testClean_RemovesLineBreaksAndControlCharacters() {
    XCTAssertEqual(
      AuthenticationReason.clean("deploy\nRequested by: zsh\u{7}"), "deployRequested by: zsh")
  }

  func testClean_RemovesBidiOverrides() {
    XCTAssertEqual(AuthenticationReason.clean("abc\u{202E}def"), "abcdef")
  }

  func testClean_Truncates() {
    let result = AuthenticationReason.clean(String(repeating: "a", count: 100))
    XCTAssertEqual(result, String(repeating: "a", count: 80) + "…")
  }

  func testDescribe_NamedKeyAndCallerNote() throws {
    try writeNames("\(recipient.ageRecipient(type: .se)) Production key\n")
    var env = environment
    env["AGE_SE_REASON"] = "deploy staging"
    let lines = AuthenticationReason.describe(recipient, environment: env)
      .components(separatedBy: "\n")
    XCTAssertEqual(lines.first, "unlock key “Production key”")
    XCTAssertEqual(lines.last, "Caller says: deploy staging")
  }

  func testDescribe_UnnamedKeyWithoutNote() throws {
    let id = recipient.ageRecipient(type: .se)
    let lines = AuthenticationReason.describe(recipient, environment: environment)
      .components(separatedBy: "\n")
    XCTAssertEqual(lines.first, "unlock unnamed key \(id.prefix(12))…\(id.suffix(6))")
    XCTAssertFalse(lines.contains { $0.hasPrefix("Caller says:") })
  }
}
