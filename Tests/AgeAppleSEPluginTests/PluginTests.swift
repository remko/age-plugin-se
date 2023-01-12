import CryptoKit
import XCTest

@testable import age_plugin_applese

final class PluginTests: XCTestCase {
  func testCertificateTag() throws {
    let key = try P256.KeyAgreement.PublicKey(compactRepresentation: Data(count: 32))
    XCTAssertEqual("Ujulpw", key.tag.base64RawEncodedString)
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
      AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
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
      AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
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
      AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
      -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
      AAAAAAAAAAAAAAAAAAAAAc40tMOm028nNPk01X4fkLg
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
      AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
      -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
      AAAAAAAAAAAAAAAAAAAAAc40tMOm028nNPk01X4fkLg
      -> recipient-stanza 1 piv-p256 14yi6A AvEp8Oz0cMnXhpXnWM6cwer4nEDHus/AvNp3kYnUH0Qs
      AAAAAAAAAAAAAAAAAAAAAvsKEe4V9wXdyfRZ2ky82HI
      -> recipient-stanza 1 piv-p256 1mgwOA AoIMpSYaKzGl5IBFaM9AFJXmrseGzTzcQjS9R4kRcjRi
      AAAAAAAAAAAAAAAAAAAAAkfl7xTt8tiiD0rRMKEvjBM
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

  func testFailingCryptoOperations() throws {
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
    crypto.failingOperations = true
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> error internal
      ZHVtbXkgZXJyb3I
      -> done

      """, stream.output)
  }

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
      AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
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
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
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
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
        -> recipient-stanza 1 piv-p256 14yi6A AvEp8Oz0cMnXhpXnWM6cwer4nEDHus/AvNp3kYnUH0Qs
        AAAAAAAAAAAAAAAAAAAAAvsKEe4V9wXdyfRZ2ky82HI
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
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
        -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
        AAAAAAAAAAAAAAAAAAAAAc40tMOm028nNPk01X4fkLg
        -> recipient-stanza 1 piv-p256 14yi6A AvEp8Oz0cMnXhpXnWM6cwer4nEDHus/AvNp3kYnUH0Qs
        AAAAAAAAAAAAAAAAAAAAAvsKEe4V9wXdyfRZ2ky82HI
        -> recipient-stanza 1 piv-p256 1mgwOA AoIMpSYaKzGl5IBFaM9AFJXmrseGzTzcQjS9R4kRcjRi
        AAAAAAAAAAAAAAAAAAAAAkfl7xTt8tiiD0rRMKEvjBM
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
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
        -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
        AAAAAAAAAAAAAAAAAAAAAc40tMOm028nNPk01X4fkLg
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

  func testIdentityError() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> add-identity AGE-PLUGIN-INVALID-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
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

  func testRecipientStanzaMultipleFilesStructurallyInvalidFile() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-APPLESE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHS2FM3SW

        -> add-identity AGE-PLUGIN-APPLESE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWS232YLC

        -> recipient-stanza 0 piv-p256 14yi6A Az7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
        -> recipient-stanza 0 piv-p256 1mgwOA
        AAAAAAAAAAAAAAAAAAAAAc40tMOm028nNPk01X4fkLg
        -> recipient-stanza 1 piv-p256 14yi6A AvEp8Oz0cMnXhpXnWM6cwer4nEDHus/AvNp3kYnUH0Qs
        AAAAAAAAAAAAAAAAAAAAAvsKEe4V9wXdyfRZ2ky82HI
        -> recipient-stanza 1 piv-p256 1mgwOA AoIMpSYaKzGl5IBFaM9AFJXmrseGzTzcQjS9R4kRcjRi
        AAAAAAAAAAAAAAAAAAAAAkfl7xTt8tiiD0rRMKEvjBM
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
        AAAAAAAAAAAAAAAAAAAAAc40tMOm028nNPk01X4fkLg
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
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
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
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
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
        AAAAAAAAAAAAAAAAAAAAARIiJq2e9+1E+xK92Pvdt+Y
        -> recipient-stanza 0 piv-p256 1mgwOA A1x2nUpw2wo/7z0JR5puskK6NuvW5XkQBwkun/T3WC80
        AAAAAAAAAAAAAAAAAAAAAc40tMOm028nNPk01X4fkLg
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

}
