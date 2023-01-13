import CryptoKit
import XCTest

@testable import age_plugin_applese

final class PluginTests: XCTestCase {
  func testCertificateTag() throws {
    let key = try P256.KeyAgreement.PublicKey(compactRepresentation: Data(count: 32))
    XCTAssertEqual("Ujulpw", key.tag.base64RawEncodedString)
  }
}

final class GenerateTests: XCTestCase {
  var stream = MemoryStream()
  var crypto = DummyCrypto()

  override func setUp() {
    stream = MemoryStream()
    crypto = DummyCrypto()
  }

  func testGenerate() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateKey(accessControl: .anyBiometryOrPasscode, now: Date(timeIntervalSinceReferenceDate: -123456789.0))
    XCTAssertEqual(
      """
      # created: 1997-02-02T02:26:51Z
      # access control: any biometry or passcode
      # public key: age1applese1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k03fanu
      AGE-PLUGIN-APPLESE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6QN63NAW
      """, result.0)
    XCTAssertEqual("age1applese1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k03fanu", result.1)
  }

  func testGenerate_AnyBiometryAndPasscode() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateKey(accessControl: .anyBiometryAndPasscode, now: Date(timeIntervalSinceReferenceDate: -123456789.0))
    XCTAssertEqual(
      """
      # created: 1997-02-02T02:26:51Z
      # access control: any biometry and passcode
      # public key: age1applese1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k03fanu
      AGE-PLUGIN-APPLESE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6QN63NAW
      """, result.0)
    XCTAssertEqual("age1applese1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k03fanu", result.1)
  }

  func testGenerate_CurrentBiometry() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateKey(accessControl: .currentBiometry, now: Date(timeIntervalSinceReferenceDate: -123456789.0))
    XCTAssertEqual(
      """
      # created: 1997-02-02T02:26:51Z
      # access control: current biometry
      # public key: age1applese1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k03fanu
      AGE-PLUGIN-APPLESE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6QN63NAW
      """, result.0)
    XCTAssertEqual("age1applese1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k03fanu", result.1)
  }

  func testGenerate_NoSecureEnclaveSupport() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    crypto.isSecureEnclaveAvailable = false
    XCTAssertThrowsError(try plugin.generateKey(accessControl: .anyBiometryOrPasscode, now: Date(timeIntervalSinceReferenceDate: -123456789.0))) { error in
      XCTAssertEqual(Plugin.Error.seUnsupported, error as! Plugin.Error)
    }
  }
}

// Test keys:
//   crypto.SecureEnclavePrivateKey(dataRepresentation: Data(base64RawEncoded: "OSe+zDK18qF0UrjxYVkmwvxyEdxZHp9F69rElj8bKS8")!)
//   AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW
//   age1applese1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw8ajekk
//
//   crypto.SecureEnclavePrivateKey(dataRepresentation: Data(base64RawEncoded: "kBuQrPyfvCqBXJ5G4YBkqNER201niIeOmlXsRS2gxN0")!)
//   AGE-PLUGIN-APPLESE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWS232YLC
//   age1applese1q0mm28s88km3d8fvwve26xg4tt26cqamhxm79g9xvmw0f2erawj75hkckfk

final class RecipientV1Tests: XCTestCase {
  var stream = MemoryStream()
  var crypto = DummyCrypto()

  override func setUp() {
    stream = MemoryStream()
    crypto = DummyCrypto()
  }

  func testNothing() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(input: "-> done\n")
    plugin.runRecipientV1()
    XCTAssertEqual("-> done\n", stream.output)
  }

  func testRecipient() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-recipient age1applese1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw8ajekk

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> done

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
      SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
      -> done

      """, stream.output)
  }

  func testIdentity() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> done

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
      SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
      -> done

      """, stream.output)
  }

  func testMultipleRecipients() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-recipient age1applese1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw8ajekk

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> add-recipient age1applese1q0mm28s88km3d8fvwve26xg4tt26cqamhxm79g9xvmw0f2erawj75hkckfk

        -> done

        -> ok

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
      SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
      -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
      9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
      -> done

      """, stream.output)
  }

  func testMultipleRecipientsMultipleKeys() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-recipient age1applese1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw8ajekk

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAg
        -> add-recipient age1applese1q0mm28s88km3d8fvwve26xg4tt26cqamhxm79g9xvmw0f2erawj75hkckfk

        -> done

        -> ok

        -> ok

        -> ok

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
      SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
      -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
      9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
      -> recipient-stanza 1 piv-p256 14yi6A AvEp8Oz0cMnXhpXnWM6cwer4nEDHus/AvNp3kYnUH0Qs
      L3ig8s2AqjusH/0lW6ZueSEYhpeV2ofrQpaKP06WI9g
      -> recipient-stanza 1 piv-p256 1mgwOA AoIMpSYaKzGl5IBFaM9AFJXmrseGzTzcQjS9R4kRcjRi
      vm8flaP+4W08S6LwFENwnEKLlpzZ5YqZ3NdpKFo7Vg8
      -> done

      """, stream.output)
  }

  func testRecipientError() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-recipient age1applese1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw8ajekk

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> add-recipient age1invalid1q0mm28s88km3d8fvwve26xg4tt26cqamhxm79g9xvmw0f2erawj75hkckfk

        -> done

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> error recipient 1
      Q2hlY2tzdW0gZG9lc24ndCBtYXRjaA
      -> done

      """, stream.output)
  }

  func testIdentityError() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> add-identity AGE-PLUGIN-INVALID-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> done

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> error identity 1
      Q2hlY2tzdW0gZG9lc24ndCBtYXRjaA
      -> done

      """, stream.output)
  }

  func testInvalidRecipientHRP() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-recipient age1vld7p2khw44ds8t00vcfmjdf35zxqvn2trjccd35h4s22faj94vsjhn620

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> done

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> error recipient 0
      dW5rbm93biBIUlA6IGFnZQ
      -> done

      """, stream.output)
  }

  // func testFailingCryptoOperations() throws {
  //   let plugin = Plugin(crypto: crypto, stream: stream)

  //   stream.add(
  //     input:
  //       """
  //       -> add-recipient age1applese1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw8ajekk

  //       -> wrap-file-key
  //       AAAAAAAAAAAAAAAAAAAAAQ
  //       -> done

  //       -> ok

  //       """)
  //   crypto.failingOperations = true
  //   plugin.runRecipientV1()

  //   XCTAssertEqual(
  //     """
  //     -> error internal
  //     ZHVtbXkgZXJyb3I
  //     -> done

  //     """, stream.output)
  // }

  func testUnknownStanzaTypes() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-recipient age1applese1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw8ajekk

        -> unknown-stanza 1 2 3

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> anotherunknownstanza
        AAAAAAAAAAAAAAAAAAAAAQ
        -> done

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
      SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
      -> done

      """, stream.output)
  }
}

final class IdentityV1Tests: XCTestCase {
  var stream = MemoryStream()
  var crypto = DummyCrypto()

  override func setUp() {
    stream = MemoryStream()
    crypto = DummyCrypto()
  }

  func testNothing() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(input: "-> done\n")
    plugin.runIdentityV1()
    XCTAssertEqual("-> done\n", stream.output)
  }

  func testRecipientStanza() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> done

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> file-key 0
      AAAAAAAAAAAAAAAAAAAAAQ
      -> done

      """, stream.output)
  }

  func testRecipientStanzaMultipleFiles() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> recipient-stanza 1 piv-p256 14yi6A AvEp8Oz0cMnXhpXnWM6cwer4nEDHus/AvNp3kYnUH0Qs
        L3ig8s2AqjusH/0lW6ZueSEYhpeV2ofrQpaKP06WI9g
        -> done

        -> ok

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> file-key 0
      AAAAAAAAAAAAAAAAAAAAAQ
      -> file-key 1
      AAAAAAAAAAAAAAAAAAAAAg
      -> done

      """, stream.output)
  }

  func testRecipientStanzaMultipleFilesMultipleIdentities() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> add-identity AGE-PLUGIN-APPLESE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWS232YLC

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
        9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
        -> recipient-stanza 1 piv-p256 14yi6A AvEp8Oz0cMnXhpXnWM6cwer4nEDHus/AvNp3kYnUH0Qs
        L3ig8s2AqjusH/0lW6ZueSEYhpeV2ofrQpaKP06WI9g
        -> recipient-stanza 1 piv-p256 1mgwOA AoIMpSYaKzGl5IBFaM9AFJXmrseGzTzcQjS9R4kRcjRi
        vm8flaP+4W08S6LwFENwnEKLlpzZ5YqZ3NdpKFo7Vg8
        -> done

        -> ok

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> file-key 0
      AAAAAAAAAAAAAAAAAAAAAQ
      -> file-key 1
      AAAAAAAAAAAAAAAAAAAAAg
      -> done

      """, stream.output)
  }

  func testRecipientStanzaMultipleStanzasMissingIdentity() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWS232YLC

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
        9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
        -> done

        -> ok

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> file-key 0
      AAAAAAAAAAAAAAAAAAAAAQ
      -> done

      """, stream.output)
  }

  func testRecipientStanza_UnknownType() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 X25519 A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
        9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> done

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> file-key 0
      AAAAAAAAAAAAAAAAAAAAAQ
      -> done

      """, stream.output)
  }

  func testIdentityError() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> add-identity AGE-PLUGIN-INVALID-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> done

        -> ok

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> error identity 1
      Q2hlY2tzdW0gZG9lc24ndCBtYXRjaA
      -> done

      """, stream.output)
  }

  func testUnknownIdentityHRP() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> add-identity AGE-SECRET-KEY-1MCFVWZK6PK625PWMWVYPZDQM4N7AS3VA754JHCC60ZT7WJ79TQQSQDYVGF

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> done

        -> ok

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> error identity 1
      dW5rbm93biBIUlA6IEFHRS1TRUNSRVQtS0VZLQ
      -> done

      """, stream.output)
  }

  func testRecipientStanzaMultipleFilesStructurallyInvalidFile() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> add-identity AGE-PLUGIN-APPLESE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWS232YLC

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> recipient-stanza 0 piv-p256 1mgwOA
        9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
        -> recipient-stanza 1 piv-p256 14yi6A AvEp8Oz0cMnXhpXnWM6cwer4nEDHus/AvNp3kYnUH0Qs
        L3ig8s2AqjusH/0lW6ZueSEYhpeV2ofrQpaKP06WI9g
        -> recipient-stanza 1 piv-p256 1mgwOA AoIMpSYaKzGl5IBFaM9AFJXmrseGzTzcQjS9R4kRcjRi
        vm8flaP+4W08S6LwFENwnEKLlpzZ5YqZ3NdpKFo7Vg8
        -> done

        -> ok

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> error stanza 0
      aW5jb3JyZWN0IGFyZ3VtZW50IGNvdW50
      -> file-key 1
      AAAAAAAAAAAAAAAAAAAAAg
      -> done

      """, stream.output)
  }

  func testRecipientStanzaInvalidStructure_ArgumentCount() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 piv-p256 1mgwOA
        9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
        -> done

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> error stanza 0
      aW5jb3JyZWN0IGFyZ3VtZW50IGNvdW50
      -> done

      """, stream.output)
  }

  func testRecipientStanzaInvalidTag() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 piv-p256 14yi Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> done

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> error stanza 0
      aW52YWxpZCB0YWc
      -> done

      """, stream.output)
  }

  func testRecipientStanzaInvalidShare() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5Q
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> done

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> error stanza 0
      aW52YWxpZCBzaGFyZQ
      -> done

      """, stream.output)
  }

  func testRecipientStanzaInvalidBody() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdtw
        -> done

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> error stanza 0
      aW52YWxpZCBib2R5
      -> done

      """, stream.output)
  }

  func testFailingCryptoOperations() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> add-identity AGE-PLUGIN-APPLESE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWS232YLC

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
        9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
        -> done

        -> ok

        -> ok

        -> ok

        """)
    crypto.failingOperations = true
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> msg
      ZHVtbXkgZXJyb3I
      -> msg
      ZHVtbXkgZXJyb3I
      -> done

      """, stream.output)
  }

  func testUnknownStanzas() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> unknown-stanza-1 a bbb c

        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> unknown-stanza-2
        9NGkkBZykDMgw6dndbbjnn7DQBalVV4sVIurWku030Y
        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        SLgnrcnHLaJHCx+fwSEWWoflDgL91oDGCGNwb2YaT+4
        -> done

        -> ok

        """)
    plugin.runIdentityV1()

    XCTAssertEqual(
      """
      -> file-key 0
      AAAAAAAAAAAAAAAAAAAAAQ
      -> done

      """, stream.output)
  }

}
