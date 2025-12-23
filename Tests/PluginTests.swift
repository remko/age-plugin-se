import XCTest

@testable import age_plugin_se

#if !os(Linux) && !os(Windows)
  import CryptoKit
#else
  import Crypto
#endif

final class PluginTests: XCTestCase {
  func testRecipientSHA256Tag() throws {
    let key = Recipient(
      p256PublicKey: try P256.KeyAgreement.PublicKey(compactRepresentation: Data(count: 32)))
    XCTAssertEqual("Ujulpw", key.sha256Tag.base64RawEncodedString())
  }

  // Test to ensure that age-plugin-yubikey has the same output tag
  // These values were extracted from a yubikey recipient
  func testRecipientSHA256Tag_YubiKeyPlugin() throws {
    let key = Recipient(
      p256PublicKey: try P256.KeyAgreement.PublicKey(
        compactRepresentation: Data([
          182, 32, 36, 98, 119, 204, 123, 231, 20, 203, 102, 119, 81, 232, 194, 196, 140,
          194, 55,
          12, 222, 162, 205, 252, 47, 114, 187, 157, 117, 151, 57, 158,
        ])))
    XCTAssertEqual(Data([128, 103, 102, 255]), key.sha256Tag)
    XCTAssertEqual("gGdm/w", key.sha256Tag.base64RawEncodedString())
  }

  func testRecipientP256HKDFTag() throws {
    let key = Recipient(
      p256PublicKey: try P256.KeyAgreement.PublicKey(compactRepresentation: Data(count: 32)))
    let ephemeralShare1 = Data([
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0,
      0, 0,
    ])
    let ephemeralShare2 = Data([
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0,
      0, 1,
    ])
    XCTAssertEqual("60GdBQ", key.p256HKDFTag(using: ephemeralShare1).base64RawEncodedString())
    XCTAssertEqual("7oE6Eg", key.p256HKDFTag(using: ephemeralShare2).base64RawEncodedString())
  }

  #if compiler(>=6.2)
    func testRecipientMLKEM768P256HKDFTag() throws {
      let key = Recipient(
        p256PublicKey: try P256.KeyAgreement.PublicKey(compactRepresentation: Data(count: 32)))
      let ephemeralShare1 = Data([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
        0, 0,
      ])
      let ephemeralShare2 = Data([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
        0, 1,
      ])
      XCTAssertEqual(
        "8CP0hA", key.mlkem768p256HKDFTag(using: ephemeralShare1).base64RawEncodedString())
      XCTAssertEqual(
        "LeMEAQ", key.mlkem768p256HKDFTag(using: ephemeralShare2).base64RawEncodedString())
    }
  #endif
}

final class GenerateKeyTests: XCTestCase {
  var stream = MemoryStream()
  var crypto = DummyCrypto()

  override func setUp() {
    stream = MemoryStream()
    crypto = DummyCrypto()
  }

  func testGenerate() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateKey(
      accessControl: .anyBiometryOrPasscode, recipientType: .se,
      now: Date(timeIntervalSinceReferenceDate: -123456789.0)
    )
    XCTAssertEqual(
      """
      # created: 1997-02-02T02:26:51Z
      # access control: any biometry or passcode
      # public key: age1se1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20kjmseq4
      AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG

      """, result.0)
    XCTAssertEqual(
      "age1se1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20kjmseq4", result.1)
  }

  func testGenerate_AnyBiometryAndPasscode() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateKey(
      accessControl: .anyBiometryAndPasscode,
      recipientType: .se,
      now: Date(timeIntervalSinceReferenceDate: -123456789.0))
    XCTAssertEqual(
      """
      # created: 1997-02-02T02:26:51Z
      # access control: any biometry and passcode
      # public key: age1se1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20kjmseq4
      AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG

      """, result.0)
    XCTAssertEqual(
      "age1se1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20kjmseq4", result.1)
  }

  func testGenerate_CurrentBiometry() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateKey(
      accessControl: .currentBiometry, recipientType: .se,
      now: Date(timeIntervalSinceReferenceDate: -123456789.0))
    XCTAssertEqual(
      """
      # created: 1997-02-02T02:26:51Z
      # access control: current biometry
      # public key: age1se1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20kjmseq4
      AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG

      """, result.0)
    XCTAssertEqual(
      "age1se1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20kjmseq4", result.1)
  }

  func testGenerate_NoSecureEnclaveSupport() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    crypto.isSecureEnclaveAvailable = false
    XCTAssertThrowsError(
      try plugin.generateKey(
        accessControl: .anyBiometryOrPasscode,
        recipientType: .se,
        now: Date(timeIntervalSinceReferenceDate: -123456789.0))
    ) { error in
      XCTAssertEqual(Plugin.Error.seUnsupported, error as! Plugin.Error)
    }
  }

  func testGenerate_TagRecipient() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateKey(
      accessControl: .anyBiometryOrPasscode, recipientType: .tag,
      now: Date(timeIntervalSinceReferenceDate: -123456789.0)
    )
    XCTAssertEqual(
      """
      # created: 1997-02-02T02:26:51Z
      # access control: any biometry or passcode
      # public key: age1tag1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k7ux6zq
      AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG

      """, result.0)
    XCTAssertEqual(
      "age1tag1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k7ux6zq", result.1)
  }

  #if compiler(>=6.2)
    func testGenerate_TagPQRecipient() throws {
      let plugin = Plugin(crypto: crypto, stream: stream)
      let result = try plugin.generateKey(
        accessControl: .anyBiometryOrPasscode, recipientType: .tag,
        now: Date(timeIntervalSinceReferenceDate: -123456789.0),
        pq: true
      )
      XCTAssertEqual(
        """
        # created: 1997-02-02T02:26:51Z
        # access control: any biometry or passcode
        # public key: age1tag1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k7ux6zq
        # public key (post-quantum): age1tagpq1xcpgv4y9vej72w8vuv64r3ap0refvqz6w6cdj8wt8q9s6cdkg7nvhegx9tq3kzc2zdv2g4y5vcmvgumtk0vgt0w8x5htj93tznjxdxj5y0nuw357wt8hhqw0x6tjs2nrgvagp2yzg3utp9rv6dzxfyf8pd0p53j8n2390qqxgugf9xycgpzxgk8z7xrapg5wzmur7qy4gmtmwlrf67cdhaecde64qlwjcc73sr97g4zq3cezwarsjr55relhck8756nm84jkl4zq6fj6chxwdy84cacnfztjqnwx3h2up085xd7vp3nw8aduhn790haxphm42dtlwjnlxpyca9n9fvz8trdspgwgvqq9ujc2aj5zkvp5sdfghx2ujw4axrqvsw9ntzrrveexrnttntqctdq5snrv2zhq0703yzud2n9excf9qjcumsymk5jcny428jcqj2m0ecmk36jxz5fksdkxpw8dh4f4u3u8f8h3cjqgtxk8k649x23etexrmgm5n9k4xacynznsedtr524t7c3zy33wvrlj25pesvshcvanvg4jqpk7kxd0tdzsxemna7unek8kwwhksud0w9heugyfdzk82ngc0sp5vxlupswupde7n0tvy7uqs3zedps48yyvusykah4hxzm4pqlx3td63ys5edvah42ewyw3va06q0zzdd2md32jrspjtv6cqdtz2ymjdwp5hzg6jng4zwf5ywuek44knvezzj6ul0cpwpw8ypms9qtk6rya4s5y2pyhtdps2tscg8lct2p974g3ufc69fug2v92czf5d9qhyqn0ypsfkqjkp22nn08cdyc575x2x7uu63nf345lzver77kpdx78veuzr9xs2dlnh24srwuth77ynz53wjs2ngjpkdq8ty8y0yq8hlr67c7fphx8t0fq3rxxkmp7wu7r75skgzl4xaxw2xkawqpznmrx5atnysxsslukg8q9waj822dr6avk9rju5wltp9dl5fjmrr394mzjcqn0fd5ay6756q32w5jhl8uh2z25287nt37lkuqpunv5gmv2ftsmkhukw0qf75uwmzcjnwp4pgf5w93ng7k0ukxx9lzzqyh2d6738tfjj9j6e7c46l9ceg2regvjyp3pmpdamy2m6dzc69wvdw90kkykryvduzyzhlwy7qqu48nvj7rc74ceafc0vyskka4js64hcryjgk7nzsnefydpj6p52aqvgkyq8smpdf5u0utvay62vcj9zxwt5dhsa2qa4zpzszeg56cag4znrz0m2ekq5hdhhecf0uf85uqmg503sd5u9v6pv93t0dnw8x3r6c9wx55txh56k9eyj3343gzu7c8266wr865gkg04wz8zwdeygepwhu9wuvumkxsu3afgdfjnejwe2gtmpsa502vvyc0352evxqjcw2jal8fjuzansezsvf44ckgueqd8zr3kcqgx9kfpghpgp9gvqxgex0gmjffmhxhkh22fsqlx3pf2eh3r20fx0tn63zqylyszhkqdt5kqytgm0309c06hv5vqm5yvgksrlxq640yv294x2y9gtk5z5wujrh3czg8jzpvutfschc95tens366mgwg9q96ztdw4lyd2aw4uygcu4vnxqhehtderaefcsf4qf92sqjvk8p4kuffykkth80rhufw5nw5z592pqw7hgxkw22uhaa4m47tcgd7www48j3tgt2p5nqgc8wzd9r0fpyemp96thxcuwh2h00qt5pp20yqhzdjhzrncd2sgwqtk22sx8vseveggfy2e0wgx46zmv026pxu7e9n6gg9tqvanyrnjy554yc6s74mplurdzyq7fyfv8hnnvxfjwjue6lzkk377jz5mqu80qcq74jgy8my83jjpu2zlgzrm0uzu7uwwf6caftd6mvehrg2ttupzjxttjnakj39ygt467wqrt0tglqf26ll78ut7lwyunqg5xslqyvs5n27ghncwl5lzs
        AGE-PLUGIN-SE-1QQSRWEV3HTW9M4Z8WJTC5C4GPTYD5Q5CFYCMHF0P8SZCQ6EVK4AKYDQQGR3NVZR9HRCFXK0A2U2KFF38NHPT46JPLY6R5GLA2SRAJC0EFFTAY5MQ2DW7SXUCEMJX8VJD7KWG6Y62CS2L44YUU5TG54TH9ZK6U8JCGYJD4J

        """, result.0)
      XCTAssertEqual(
        "age1tagpq1xcpgv4y9vej72w8vuv64r3ap0refvqz6w6cdj8wt8q9s6cdkg7nvhegx9tq3kzc2zdv2g4y5vcmvgumtk0vgt0w8x5htj93tznjxdxj5y0nuw357wt8hhqw0x6tjs2nrgvagp2yzg3utp9rv6dzxfyf8pd0p53j8n2390qqxgugf9xycgpzxgk8z7xrapg5wzmur7qy4gmtmwlrf67cdhaecde64qlwjcc73sr97g4zq3cezwarsjr55relhck8756nm84jkl4zq6fj6chxwdy84cacnfztjqnwx3h2up085xd7vp3nw8aduhn790haxphm42dtlwjnlxpyca9n9fvz8trdspgwgvqq9ujc2aj5zkvp5sdfghx2ujw4axrqvsw9ntzrrveexrnttntqctdq5snrv2zhq0703yzud2n9excf9qjcumsymk5jcny428jcqj2m0ecmk36jxz5fksdkxpw8dh4f4u3u8f8h3cjqgtxk8k649x23etexrmgm5n9k4xacynznsedtr524t7c3zy33wvrlj25pesvshcvanvg4jqpk7kxd0tdzsxemna7unek8kwwhksud0w9heugyfdzk82ngc0sp5vxlupswupde7n0tvy7uqs3zedps48yyvusykah4hxzm4pqlx3td63ys5edvah42ewyw3va06q0zzdd2md32jrspjtv6cqdtz2ymjdwp5hzg6jng4zwf5ywuek44knvezzj6ul0cpwpw8ypms9qtk6rya4s5y2pyhtdps2tscg8lct2p974g3ufc69fug2v92czf5d9qhyqn0ypsfkqjkp22nn08cdyc575x2x7uu63nf345lzver77kpdx78veuzr9xs2dlnh24srwuth77ynz53wjs2ngjpkdq8ty8y0yq8hlr67c7fphx8t0fq3rxxkmp7wu7r75skgzl4xaxw2xkawqpznmrx5atnysxsslukg8q9waj822dr6avk9rju5wltp9dl5fjmrr394mzjcqn0fd5ay6756q32w5jhl8uh2z25287nt37lkuqpunv5gmv2ftsmkhukw0qf75uwmzcjnwp4pgf5w93ng7k0ukxx9lzzqyh2d6738tfjj9j6e7c46l9ceg2regvjyp3pmpdamy2m6dzc69wvdw90kkykryvduzyzhlwy7qqu48nvj7rc74ceafc0vyskka4js64hcryjgk7nzsnefydpj6p52aqvgkyq8smpdf5u0utvay62vcj9zxwt5dhsa2qa4zpzszeg56cag4znrz0m2ekq5hdhhecf0uf85uqmg503sd5u9v6pv93t0dnw8x3r6c9wx55txh56k9eyj3343gzu7c8266wr865gkg04wz8zwdeygepwhu9wuvumkxsu3afgdfjnejwe2gtmpsa502vvyc0352evxqjcw2jal8fjuzansezsvf44ckgueqd8zr3kcqgx9kfpghpgp9gvqxgex0gmjffmhxhkh22fsqlx3pf2eh3r20fx0tn63zqylyszhkqdt5kqytgm0309c06hv5vqm5yvgksrlxq640yv294x2y9gtk5z5wujrh3czg8jzpvutfschc95tens366mgwg9q96ztdw4lyd2aw4uygcu4vnxqhehtderaefcsf4qf92sqjvk8p4kuffykkth80rhufw5nw5z592pqw7hgxkw22uhaa4m47tcgd7www48j3tgt2p5nqgc8wzd9r0fpyemp96thxcuwh2h00qt5pp20yqhzdjhzrncd2sgwqtk22sx8vseveggfy2e0wgx46zmv026pxu7e9n6gg9tqvanyrnjy554yc6s74mplurdzyq7fyfv8hnnvxfjwjue6lzkk377jz5mqu80qcq74jgy8my83jjpu2zlgzrm0uzu7uwwf6caftd6mvehrg2ttupzjxttjnakj39ygt467wqrt0tglqf26ll78ut7lwyunqg5xslqyvs5n27ghncwl5lzs",
        result.1)
    }
  #endif
}

final class GenerateRecipientsTests: XCTestCase {
  var stream = MemoryStream()
  var crypto = DummyCrypto()

  override func setUp() {
    stream = MemoryStream()
    crypto = DummyCrypto()
  }

  func testGenerate() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateRecipients(
      input: """
        # Comment 1
        AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG
        """,
      recipientType: .se
    )
    XCTAssertEqual(
      """
      age1se1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20kjmseq4
      """, result)
  }

  func testGenerate_P256Tag() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateRecipients(
      input: """
        # Comment 1
        AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG
        """,
      recipientType: .tag
    )
    XCTAssertEqual(
      """
      age1tag1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k7ux6zq
      """, result)
  }

  #if compiler(>=6.2)
    func testGenerate_P256TagPQ() throws {
      let plugin = Plugin(crypto: crypto, stream: stream)
      let result = try plugin.generateRecipients(
        input: """
          # Comment 1
          AGE-PLUGIN-SE-1QQSRWEV3HTW9M4Z8WJTC5C4GPTYD5Q5CFYCMHF0P8SZCQ6EVK4AKYDQQGR3NVZR9HRCFXK0A2U2KFF38NHPT46JPLY6R5GLA2SRAJC0EFFTAY5MQ2DW7SXUCEMJX8VJD7KWG6Y62CS2L44YUU5TG54TH9ZK6U8JCGYJD4J
          """,
        recipientType: .tag,
        pq: true
      )
      XCTAssertEqual(
        """
        age1tagpq1xcpgv4y9vej72w8vuv64r3ap0refvqz6w6cdj8wt8q9s6cdkg7nvhegx9tq3kzc2zdv2g4y5vcmvgumtk0vgt0w8x5htj93tznjxdxj5y0nuw357wt8hhqw0x6tjs2nrgvagp2yzg3utp9rv6dzxfyf8pd0p53j8n2390qqxgugf9xycgpzxgk8z7xrapg5wzmur7qy4gmtmwlrf67cdhaecde64qlwjcc73sr97g4zq3cezwarsjr55relhck8756nm84jkl4zq6fj6chxwdy84cacnfztjqnwx3h2up085xd7vp3nw8aduhn790haxphm42dtlwjnlxpyca9n9fvz8trdspgwgvqq9ujc2aj5zkvp5sdfghx2ujw4axrqvsw9ntzrrveexrnttntqctdq5snrv2zhq0703yzud2n9excf9qjcumsymk5jcny428jcqj2m0ecmk36jxz5fksdkxpw8dh4f4u3u8f8h3cjqgtxk8k649x23etexrmgm5n9k4xacynznsedtr524t7c3zy33wvrlj25pesvshcvanvg4jqpk7kxd0tdzsxemna7unek8kwwhksud0w9heugyfdzk82ngc0sp5vxlupswupde7n0tvy7uqs3zedps48yyvusykah4hxzm4pqlx3td63ys5edvah42ewyw3va06q0zzdd2md32jrspjtv6cqdtz2ymjdwp5hzg6jng4zwf5ywuek44knvezzj6ul0cpwpw8ypms9qtk6rya4s5y2pyhtdps2tscg8lct2p974g3ufc69fug2v92czf5d9qhyqn0ypsfkqjkp22nn08cdyc575x2x7uu63nf345lzver77kpdx78veuzr9xs2dlnh24srwuth77ynz53wjs2ngjpkdq8ty8y0yq8hlr67c7fphx8t0fq3rxxkmp7wu7r75skgzl4xaxw2xkawqpznmrx5atnysxsslukg8q9waj822dr6avk9rju5wltp9dl5fjmrr394mzjcqn0fd5ay6756q32w5jhl8uh2z25287nt37lkuqpunv5gmv2ftsmkhukw0qf75uwmzcjnwp4pgf5w93ng7k0ukxx9lzzqyh2d6738tfjj9j6e7c46l9ceg2regvjyp3pmpdamy2m6dzc69wvdw90kkykryvduzyzhlwy7qqu48nvj7rc74ceafc0vyskka4js64hcryjgk7nzsnefydpj6p52aqvgkyq8smpdf5u0utvay62vcj9zxwt5dhsa2qa4zpzszeg56cag4znrz0m2ekq5hdhhecf0uf85uqmg503sd5u9v6pv93t0dnw8x3r6c9wx55txh56k9eyj3343gzu7c8266wr865gkg04wz8zwdeygepwhu9wuvumkxsu3afgdfjnejwe2gtmpsa502vvyc0352evxqjcw2jal8fjuzansezsvf44ckgueqd8zr3kcqgx9kfpghpgp9gvqxgex0gmjffmhxhkh22fsqlx3pf2eh3r20fx0tn63zqylyszhkqdt5kqytgm0309c06hv5vqm5yvgksrlxq640yv294x2y9gtk5z5wujrh3czg8jzpvutfschc95tens366mgwg9q96ztdw4lyd2aw4uygcu4vnxqhehtderaefcsf4qf92sqjvk8p4kuffykkth80rhufw5nw5z592pqw7hgxkw22uhaa4m47tcgd7www48j3tgt2p5nqgc8wzd9r0fpyemp96thxcuwh2h00qt5pp20yqhzdjhzrncd2sgwqtk22sx8vseveggfy2e0wgx46zmv026pxu7e9n6gg9tqvanyrnjy554yc6s74mplurdzyq7fyfv8hnnvxfjwjue6lzkk377jz5mqu80qcq74jgy8my83jjpu2zlgzrm0uzu7uwwf6caftd6mvehrg2ttupzjxttjnakj39ygt467wqrt0tglqf26ll78ut7lwyunqg5xslqyvs5n27ghncwl5lzs
        """, result)
    }
  #endif

  func testGenerate_P256TagPQ_MissingPQ() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    XCTAssertThrowsError(
      try plugin.generateRecipients(
        input: """
          # Comment 1
          AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG
          """,
        recipientType: .tag,
        pq: true
      ))
  }

  func testGenerate_MultipleLines() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    let result = try plugin.generateRecipients(
      input: """
        # Comment 1

        AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG

        # Comment 2

        AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG
        """,
      recipientType: .se
    )
    XCTAssertEqual(
      """
      age1se1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20kjmseq4
      age1se1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw6hta9l
      """, result)
  }

  func testGenerate_InvalidCharacter() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    XCTAssertThrowsError(
      try plugin.generateRecipients(
        input: """
          - Comment 1
          AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG
          """,
        recipientType: .se
      ))
  }

  func testGenerate_InvalidPrivateKey() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    XCTAssertThrowsError(
      try plugin.generateRecipients(
        input: """
          AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VH
          """,
        recipientType: .se
      ))
  }

  func testGenerate_UnknownPrivateKeyType() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    XCTAssertThrowsError(
      try plugin.generateRecipients(
        input: """
          AGE-SECRET-KEY-18GRJ0APHQRYQ3FX60Y3P3TSUMSCQ0NE6HCA23PKNXTPA6RQSND2SPSLF4W
          """,
        recipientType: .se
      )
    ) { error in
      XCTAssertEqual(Plugin.Error.unknownHRP("AGE-SECRET-KEY-"), error as! Plugin.Error)
    }
  }
}

final class RecipientV1Tests: XCTestCase {
  var stream = MemoryStream()
  var crypto = DummyCrypto()

  override func setUp() {
    stream = MemoryStream()
    crypto = DummyCrypto()
  }

  // Just a test to get the identities of the test keys used in this test
  func testKeys() throws {
    let key1 = try! Identity(
      ageIdentity:
        "AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG",
      crypto: crypto)

    XCTAssertEqual(
      "OSe+zDK18qF0UrjxYVkmwvxyEdxZHp9F69rElj8bKS8",
      key1.p256PrivateKey.dataRepresentation.base64RawEncodedString())
    XCTAssertEqual(
      "age1se1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw6hta9l",
      key1.recipient.ageRecipient(type: .se))
    XCTAssertEqual(
      "age1tag1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lwksa782",
      key1.recipient.ageRecipient(type: .tag))

    let key2 = try! Identity(
      ageIdentity:
        "AGE-PLUGIN-SE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWSREKAW7",
      crypto: crypto)
    XCTAssertEqual(
      "kBuQrPyfvCqBXJ5G4YBkqNER201niIeOmlXsRS2gxN0",
      key2.p256PrivateKey.dataRepresentation.base64RawEncodedString())
    XCTAssertEqual(
      "age1se1q0mm28s88km3d8fvwve26xg4tt26cqamhxm79g9xvmw0f2erawj752upj6l",
      key2.recipient.ageRecipient(type: .se))
    XCTAssertEqual(
      "age1tag1q0mm28s88km3d8fvwve26xg4tt26cqamhxm79g9xvmw0f2erawj75xmh3c2",
      key2.recipient.ageRecipient(type: .tag))

    #if compiler(>=6.2)
      let pqkey1 = try! Identity(
        ageIdentity:
          "AGE-PLUGIN-SE-1QQSRWEV3HTW9M4Z8WJTC5C4GPTYD5Q5CFYCMHF0P8SZCQ6EVK4AKYDQQGQTXY09DTD6G9NF4GDLPJK5RKC4KHE6GJW5ZK3QT5M026WN6LKLNULCPFD57EE5WZWWKMGPUZJG2Q6Z235TZMSPLG50WQUC875N87PJ6685E57",
        crypto: crypto)
      XCTAssertEqual(
        "N2WRutxd1Ed0l4piqArI2gKYSTG7peE8BYBrLLV7YjQ",
        pqkey1.p256PrivateKey.dataRepresentation.base64RawEncodedString())
      XCTAssertEqual(
        "FmI8rVt0gs01Q34ZWoO2K2vnSJOoK0QLpt6tOnr9vz5/AUtp7OaOE51toDwUkKBoSo0WLcA/RR7gcwf1Jn8GWg",
        pqkey1.mlkemPrivateKey!.dataRepresentation.base64RawEncodedString())
      XCTAssertEqual(
        "age1tag1qvlvs7x2g83gtaqg0dlstnm3ee8tr49dhtdnxudpfd0sy2gedw20k7ux6zq",
        pqkey1.recipient.ageRecipient(type: .tag))
      XCTAssertEqual(
        "age1tagpq192gcyxhj9t7jfrspm3qgvurfuafxvfgqjcy2xdr6zmqedjaxux3y7ndr9y5desly4z5agxr34p92lqgu2jkh0gga6k35jky7c4wqjp7sp3e9tzq8kply6qrg3fj60vhpcm38f3f6pyf66c38ft65t5rnehnhwj0gnfx7lqcnhs3sgfech48403jv7d4ugsjn5npsru0rdhtyx63gk6r6j0yplenq8reen5lkxzy77cmw273cpgrsd34326qydr52xate6erazhs47vus4efqjeams4vpc39x5t92aepzrcg75eu47apysrxy2lumen5mgmuqktdefxenr7zslrkyuth8cq4ggn7z29kzdfgr9jfnxt9gfp523v93r9cydu9wk6zenemy4wmrkx95kj774km7agy8jpvnf27kv464xuf767n0evt6yzsgq0sxcpl592fenvxyr8cvsyhfsyt048lweqza2quz66aksvhjctm2gv7xzj543ucyfyrf0r4y0uwqhyyqeytddkuy4tut00vsjhrqnpawvdy6mswrav52e5f69wfz8sgrzwh47utkf4ms744c2nfr0pxx0y9x9qa8jxs2ma3jwfug5zdmq6f9ssc2d6vtvjmjg0gynfn6jeyz4gnxljxyu7tzh3zss9yrj6acaxf8a0spw2r63c5eyguu8dtn2afzps9qkdxc20y5zuncmyg0v9s7w2tjla26h6fzvh7egkmfx6aas75pp6uyvv9h8wn0n327r44pdtps7mzrkp0f54assm9ez0qcr6jflel235z8zg4gywc4n6afp2ns5xvk5almfg9t2qxgmwf5r0q2flwgpc4j5cnczq5z7a40rcrs48mpqp95pypjet9xl9kvx9xtyzdn4tl458k4c5yhexzagfp2sh2s8lvmjzwlvuayq7g9pvm3tfhs3zjn3tvahrxphw40lcdgfkantrlje3ghqx5d6zchlq3tf0a9dua5w62j2cgy9xs3ewg6zjteh9pjerre7wvu5zwqmxqckvamqej0whuy4tqwwdytzms67ca8s0gwtzwykyyy8xguwgju9dqu8u9wnd3nzlyggwrygtq6ycce32q4gn68fy93rpk9qm2vm2pc0l9dwdnggerz0xfd52nzh0uqzjplqn2qzgp0k5ql9y9culhmt8gfxmkzdvt0wf50a7rjs2m682kakn3yvdxspzgpujyg3388r4t50s0nyzgkkpdg43wx8fek295e5sl28jmszgy332vugqw3373qt3f4562r23pnucef3fy90tqtv05mzu3y0jxz0cxyd793ya2k2qfmc3seu4avvptvcuq3p9wt82cwjds59w2pspx2dzdmwyuary99wyyxv6pan3s30pufs8c52kq8guslfauc2qppyzjf50wvqzyrj6frl3gkxrgqdw9u2lmnhjsyjzmmwxme3kr4mqnzqtqecwzfpjp3hsp0khfrerfu4u3ytdv9u7rhadey3adhxsx48mm30pekt28k836lkpm9du98ykka2ng2gyg3m6fg27mg4cf9tzwwkfw24xk0crp7wrqfkwz6gjhzkq2u0d5e5qsx9ygpws3jshy0ssw9xtrnrxgtmwv6g5prwk809s3d664m2uvur0rc0nyqek6ug77ext9lkfjpqv5gfqcfv2ckzt8qdduc25pg334s3efgqz8ec7vj39nfevrpk4d9f0w4y722tfjwuqhz7cpaz7ezaylqhs2swhs6vsa6a92fuwzpavryz9fpcn992cd34yng32fsjj8zh397k3qhzg9vfpcc4qr56gnnyz95g4ynzc6f8878m5yqa8d9uqguzcr74lmraamz4jhy06vt4s32axkeqdhtensy8my83jjpu2zlgzrm0uzu7uwwf6caftd6mvehrg2ttupzjxttjnakj39ygt467wqrt0tglqf26ll78ut7lwyunqg5xslqyvs5n27ghncsg3u8h",
        try pqkey1.recipient.ageTagPQRecipient)
    #endif
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
        -> add-recipient age1se1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw6hta9l

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

  func testRecipient_P256Tag() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-recipient age1tag1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lwksa782

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> done

        -> ok

        """)
    plugin.runRecipientV1()

    XCTAssertEqual(
      """
      -> recipient-stanza 0 p256tag NDTf9g BD7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7aUSkQuuvOANb1o+BKtf/4/F++4nJgRQ0PgIyFJq8i88
      14bmQarAgrOM0M27KRHYp9RzNYlcv3pJgRm9sTCB08c
      -> done

      """, stream.output)
  }

  #if compiler(>=6.2)
    func testRecipient_MLKEM768P256Tag() throws {
      let plugin = Plugin(crypto: crypto, stream: stream)

      stream.add(
        input:
          """
          -> add-recipient age1tagpq192gcyxhj9t7jfrspm3qgvurfuafxvfgqjcy2xdr6zmqedjaxux3y7ndr9y5desly4z5agxr34p92lqgu2jkh0gga6k35jky7c4wqjp7sp3e9tzq8kply6qrg3fj60vhpcm38f3f6pyf66c38ft65t5rnehnhwj0gnfx7lqcnhs3sgfech48403jv7d4ugsjn5npsru0rdhtyx63gk6r6j0yplenq8reen5lkxzy77cmw273cpgrsd34326qydr52xate6erazhs47vus4efqjeams4vpc39x5t92aepzrcg75eu47apysrxy2lumen5mgmuqktdefxenr7zslrkyuth8cq4ggn7z29kzdfgr9jfnxt9gfp523v93r9cydu9wk6zenemy4wmrkx95kj774km7agy8jpvnf27kv464xuf767n0evt6yzsgq0sxcpl592fenvxyr8cvsyhfsyt048lweqza2quz66aksvhjctm2gv7xzj543ucyfyrf0r4y0uwqhyyqeytddkuy4tut00vsjhrqnpawvdy6mswrav52e5f69wfz8sgrzwh47utkf4ms744c2nfr0pxx0y9x9qa8jxs2ma3jwfug5zdmq6f9ssc2d6vtvjmjg0gynfn6jeyz4gnxljxyu7tzh3zss9yrj6acaxf8a0spw2r63c5eyguu8dtn2afzps9qkdxc20y5zuncmyg0v9s7w2tjla26h6fzvh7egkmfx6aas75pp6uyvv9h8wn0n327r44pdtps7mzrkp0f54assm9ez0qcr6jflel235z8zg4gywc4n6afp2ns5xvk5almfg9t2qxgmwf5r0q2flwgpc4j5cnczq5z7a40rcrs48mpqp95pypjet9xl9kvx9xtyzdn4tl458k4c5yhexzagfp2sh2s8lvmjzwlvuayq7g9pvm3tfhs3zjn3tvahrxphw40lcdgfkantrlje3ghqx5d6zchlq3tf0a9dua5w62j2cgy9xs3ewg6zjteh9pjerre7wvu5zwqmxqckvamqej0whuy4tqwwdytzms67ca8s0gwtzwykyyy8xguwgju9dqu8u9wnd3nzlyggwrygtq6ycce32q4gn68fy93rpk9qm2vm2pc0l9dwdnggerz0xfd52nzh0uqzjplqn2qzgp0k5ql9y9culhmt8gfxmkzdvt0wf50a7rjs2m682kakn3yvdxspzgpujyg3388r4t50s0nyzgkkpdg43wx8fek295e5sl28jmszgy332vugqw3373qt3f4562r23pnucef3fy90tqtv05mzu3y0jxz0cxyd793ya2k2qfmc3seu4avvptvcuq3p9wt82cwjds59w2pspx2dzdmwyuary99wyyxv6pan3s30pufs8c52kq8guslfauc2qppyzjf50wvqzyrj6frl3gkxrgqdw9u2lmnhjsyjzmmwxme3kr4mqnzqtqecwzfpjp3hsp0khfrerfu4u3ytdv9u7rhadey3adhxsx48mm30pekt28k836lkpm9du98ykka2ng2gyg3m6fg27mg4cf9tzwwkfw24xk0crp7wrqfkwz6gjhzkq2u0d5e5qsx9ygpws3jshy0ssw9xtrnrxgtmwv6g5prwk809s3d664m2uvur0rc0nyqek6ug77ext9lkfjpqv5gfqcfv2ckzt8qdduc25pg334s3efgqz8ec7vj39nfevrpk4d9f0w4y722tfjwuqhz7cpaz7ezaylqhs2swhs6vsa6a92fuwzpavryz9fpcn992cd34yng32fsjj8zh397k3qhzg9vfpcc4qr56gnnyz95g4ynzc6f8878m5yqa8d9uqguzcr74lmraamz4jhy06vt4s32axkeqdhtensy8my83jjpu2zlgzrm0uzu7uwwf6caftd6mvehrg2ttupzjxttjnakj39ygt467wqrt0tglqf26ll78ut7lwyunqg5xslqyvs5n27ghncsg3u8h

          -> wrap-file-key
          AAAAAAAAAAAAAAAAAAAAAQ
          -> done

          -> ok

          """)
      plugin.runRecipientV1()

      XCTAssertEqual(
        """
        -> recipient-stanza 0 mlkem768p256tag nhdJ8g 2oNGI4Qzlu35omot6u2T870FUQLFH1qV2M5n4MHftYmVylCoFxTKjfKcGHfNdiqGPIEeHVPh+b1HpI6qw6bkZhoHQJpFqKFJu5Lf17fU9cFL+DOSfp1IwTjRXCz3RT0Y+l13WeUgY3lIJCtlu1TS/8rts5twGOLzYRfqeceLm7XT/Y7LUIeMBVQeEuFKYGR5IzBpdn+NZlPgTKfqQ5Qv987kWuZ+lIC9pOtfhXGGUPTF18/fG/OGK2arSd4jFzIrjqKEDPlqyDhWTKuBB3FGDByDXrBke0CbuKotvteWzdASiNFTBD8+SKDxqeDQt9RB2uVE3XwmwBNmBaM+0KqHVMuawgeQRrKBtPMk8fR4KXzFcIN46qugqh5eLNtSwVgJ6HUH2fDSQHp0hR2TVdN9+Y1Ry7D1/RahyWHgxFhcDZ8O9PWn1uPqMoHOhc67RdAjpXhaRxKsfjFKYf5vOvnAivbertz7vm8hU6Sp4ueB2NaAh9gG7lJ8AQSq+36Hrh0nZujARV74l6o9HkqkWJCzRNv1Jv69j3gq3AAjb663pTLrkIzVRPmUAqjLMCjR0nmWM304gyq/5glz6BPIoz4jZvDcQGPZVjEiEL6Ljgq473i3xZLyJZ6PMwDyDTlcA75Ipfx8xHYnyQrIrrMo5so7mgiXtI12edEi8DaVpfm111JKUd5POSzGrOtrU3yogaAFkVsS//2R4Jyk8EImiOpWofF1y960+0sY9rMQfzRUxdaH2F1vc+y1VHoazKZC5tuybDCL4Q1+3yiU9OkBAGea+iAZKBkuY8klbcJmTjNGuEwa2xjeqpcmYT5zPGp+2AdcCFa5IBz7AcrPzGMMWpa6BBas55blrzNWJZ+JQkfk72UcBJKl5v7hYznP1Wtgq52OvdMyCERiDiGRKnLwiq4fGarr7szg11tmrbzuB3++uWQUv9YO9COJwy3SQKLbwJ4bO+P31WpaayEFekhMgczhGXk9ibegdkol0jkroXsAz+mW/s6bKR6dlEOwxIJ4MNDXFjjMO7CjGL3XEdQBIV8EiWnx0d1RUlhjg/Okms4lokCdlJbnKAxqiEGmt6iIsJuk61EINmLlUnVAmiJ9jG4ewlLC7G+hZNkKS0Ek1W6rEmWY0oGJZWTD8I70bKKhmZDTxzaY+p5uC4UlIrBzuIu/C0D2mPd1Q4vlcSR2cqWsflXtBcdvImTkZj+xrPj6eT+5Q4rhBqg+edmKvYc0kp2QjOMXIwvrjVW9rwy/SETHAvih+DUo/nBbFfKnR+6lDdR+MXJrfUhX8BaL2eGt2M3GtvWx9eIATf3yGp9O/pUI96p5OGNIjXIqrLYjQ61uK8H0zdtwRRUDpH/Y4GwgNO+Ufw+mdaXl+e2kS0Hqxp6BFdXvoMM7OXttnM8bhMxcVyc3lwubqpAlOQ2lxepwjlkR5q/RYe93f+jbeRcrmeAfxgQEPsh4ykHihfQIe38Fz3HOTrHUrbrbM3GhS18CKRlrlPtpRKRC6684A1vWj4Eq1//j8X77icmBFDQ+AjIUmryLzw
        PqGDmcnQr3tUHkSfD++b8gvuXZIA4li8UZtbu0UOwNo
        -> done

        """, stream.output)
    }
  #endif

  func testIdentity() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)

    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-recipient age1se1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw6hta9l

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> add-recipient age1se1q0mm28s88km3d8fvwve26xg4tt26cqamhxm79g9xvmw0f2erawj752upj6l

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
        -> add-recipient age1se1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw6hta9l

        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAQ
        -> wrap-file-key
        AAAAAAAAAAAAAAAAAAAAAg
        -> add-recipient age1se1q0mm28s88km3d8fvwve26xg4tt26cqamhxm79g9xvmw0f2erawj752upj6l

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
        -> add-recipient age1se1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw6hta9l

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
  //       -> add-recipient age1se1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw6hta9l

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
        -> add-recipient age1se1qf0l9gks6x65ha077wq3w3u8fy02tpg3cd9w5j0jlgpfgqkcut2lw6hta9l

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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

  func testRecipientStanza_P256Tag() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

        -> recipient-stanza 0 p256tag NDTf9g BD7IeMpB4oX0CHt/Bc9xzk6x1K262zNxoUtfAikZa5T7aUSkQuuvOANb1o+BKtf/4/F++4nJgRQ0PgIyFJq8i88
        14bmQarAgrOM0M27KRHYp9RzNYlcv3pJgRm9sTCB08c
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

  #if compiler(>=6.2)
    func testRecipientStanza_MLKEM768P256Tag() throws {
      let plugin = Plugin(crypto: crypto, stream: stream)
      stream.add(
        input:
          """
          -> add-identity AGE-PLUGIN-SE-1QQSRWEV3HTW9M4Z8WJTC5C4GPTYD5Q5CFYCMHF0P8SZCQ6EVK4AKYDQQGQTXY09DTD6G9NF4GDLPJK5RKC4KHE6GJW5ZK3QT5M026WN6LKLNULCPFD57EE5WZWWKMGPUZJG2Q6Z235TZMSPLG50WQUC875N87PJ6685E57

          -> recipient-stanza 0 mlkem768p256tag KyeQyw B9jOe+qOs9lFS/PG+u5sjGh8aLrUw4YnXhTgB0Z4QyAbRxeP87+0Ceq7dvVlB11lXu6/GgobbKOuMMydWtjAW0/IhKoGXK+iFMOYCt4jneDe11Jn3FYETp873tk4YVgA0sn7+iw5T2EFOvGXydZuW4qsOVIC/Q14r5DaxzrH7K+4jrM5ylD+IEPDZxXNBLmzOq33dZYVpDAoCU0/cuXXs2Mm4qOWGeFIGEeaDNpfS4Ux+w16hrfMVn6ko33S9wQ6mZCkkZ8ibk8qXLC29acUFKv78DNWzPOOwnKcSJMOrTXLjETKRclcLixZKfYlNxEjfmtiYH6BVlhMIba15Sw1/EB6ZlOAaUeYXQ+N/IoscLTxywqyUv1p8P1ZVRLq8+6ZEWe0unGqeLa1JHAuX4sPo3SPNhP7PZXa0CCW8d6YBJ6NTML6syHqS9yTcsJiL+SgnuPHBVj4ZaDwynuuelVFE8UkM1sSNteL6kCx+iAz9e3uFTtpgly824vJz6Gjsekc7RydU0jjMQGKcHiGA/2DhU4eDC+iXM/yMT80ovheRviP7i49Vco5Z7v7eTbyK0kjJEeCW+TUUQpPZrMpVwJLhDhENdFxYQLz0QnBn0L2F+QQ2Il6Nyo9qizj7q+V8jNGs2j+/3HCgOPBbcIu99hRKHrhuIBnuoby5t+FmgiRUUJ1boEIA2DlvtRqsZtZxRuvhEfz+H9+WNrFXYvf1JkzyNJwwnkwLQU6aYII7Z3BXbkoMfJo84X0FMpNFjTzHk7ObwMpnXEB6Jz+pr+MUWKDIrgvaa3cdz8g38QVROMsK1MguIpyF2nzH9opWrOvbzS+XYNQU8o2Pl1GyJAPTVKR/D8nH+dVQXTMD+CgpSl278W3aLQFUeiKB4HT5BVCvFmw1JtLzwlWTRRInyCDTRdEui1e00e6Kwc4QJN38eBAgvYp4Nisib3UChSjUGKgS4HA8CgkiHO/mYerPOnK8YWgl158daU4mM3nXgTwEhrVKK78tP/P7zFehwMv3nOZvixuz3P4yG1lzlVIsM3Ti9gHnfVi0XqewqSuTacb8cKTEHdX/Xw4yxIoTTn3mt4qX90gJCVyyPqU18QFZ+LF7WBggLP2bFqOmuOpNFhb/5sNAuslHT9HmJxZpOvcyOdO1SMize7ZdanTj0cvLK+jczqg9uLSgb95eULkliA55Lr6RVxmtjZ/aqNcpmXygxxfaKOQXTA3u6OkwBnKbXzFcoaXFkCR+Jvke/z8c5mN2dp7OaFgZNG8gRXAdIbZeBDcMdQ+knwi+dcMNVMn3zBqecXoS69n6Y5in+/C7Pkck9g8UqAJXFAv3hMAlz+YuIOdBJtiUajgsZeV2mkTzhkqbRWhesXL1JgNJcFYQQocAE0l3A3vQAEdeyuRtt7OF2gCBV44viB1MB+NivexducLiT9eFzbypYASFh1yuCicxItPymgEPsh4ykHihfQIe38Fz3HOTrHUrbrbM3GhS18CKRlrlPtpRKRC6684A1vWj4Eq1//j8X77icmBFDQ+AjIUmryLzw
          cEMMgOZ8EWj7cnVQLFSh7lb4crWG75kTmC7ts70W9mY
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

    func testRecipientStanza_MLKEM768P256Tag_MissingPQ() throws {
      let plugin = Plugin(crypto: crypto, stream: stream)
      stream.add(
        input:
          """
          -> add-identity AGE-PLUGIN-SE-1XAJERWKUTH2YWAYH3F32SZKGMGPFSJF3HWJ7Z0Q9SP4JEDTMVG6Q6JD2VG

          -> recipient-stanza 0 mlkem768p256tag KyeQyw B9jOe+qOs9lFS/PG+u5sjGh8aLrUw4YnXhTgB0Z4QyAbRxeP87+0Ceq7dvVlB11lXu6/GgobbKOuMMydWtjAW0/IhKoGXK+iFMOYCt4jneDe11Jn3FYETp873tk4YVgA0sn7+iw5T2EFOvGXydZuW4qsOVIC/Q14r5DaxzrH7K+4jrM5ylD+IEPDZxXNBLmzOq33dZYVpDAoCU0/cuXXs2Mm4qOWGeFIGEeaDNpfS4Ux+w16hrfMVn6ko33S9wQ6mZCkkZ8ibk8qXLC29acUFKv78DNWzPOOwnKcSJMOrTXLjETKRclcLixZKfYlNxEjfmtiYH6BVlhMIba15Sw1/EB6ZlOAaUeYXQ+N/IoscLTxywqyUv1p8P1ZVRLq8+6ZEWe0unGqeLa1JHAuX4sPo3SPNhP7PZXa0CCW8d6YBJ6NTML6syHqS9yTcsJiL+SgnuPHBVj4ZaDwynuuelVFE8UkM1sSNteL6kCx+iAz9e3uFTtpgly824vJz6Gjsekc7RydU0jjMQGKcHiGA/2DhU4eDC+iXM/yMT80ovheRviP7i49Vco5Z7v7eTbyK0kjJEeCW+TUUQpPZrMpVwJLhDhENdFxYQLz0QnBn0L2F+QQ2Il6Nyo9qizj7q+V8jNGs2j+/3HCgOPBbcIu99hRKHrhuIBnuoby5t+FmgiRUUJ1boEIA2DlvtRqsZtZxRuvhEfz+H9+WNrFXYvf1JkzyNJwwnkwLQU6aYII7Z3BXbkoMfJo84X0FMpNFjTzHk7ObwMpnXEB6Jz+pr+MUWKDIrgvaa3cdz8g38QVROMsK1MguIpyF2nzH9opWrOvbzS+XYNQU8o2Pl1GyJAPTVKR/D8nH+dVQXTMD+CgpSl278W3aLQFUeiKB4HT5BVCvFmw1JtLzwlWTRRInyCDTRdEui1e00e6Kwc4QJN38eBAgvYp4Nisib3UChSjUGKgS4HA8CgkiHO/mYerPOnK8YWgl158daU4mM3nXgTwEhrVKK78tP/P7zFehwMv3nOZvixuz3P4yG1lzlVIsM3Ti9gHnfVi0XqewqSuTacb8cKTEHdX/Xw4yxIoTTn3mt4qX90gJCVyyPqU18QFZ+LF7WBggLP2bFqOmuOpNFhb/5sNAuslHT9HmJxZpOvcyOdO1SMize7ZdanTj0cvLK+jczqg9uLSgb95eULkliA55Lr6RVxmtjZ/aqNcpmXygxxfaKOQXTA3u6OkwBnKbXzFcoaXFkCR+Jvke/z8c5mN2dp7OaFgZNG8gRXAdIbZeBDcMdQ+knwi+dcMNVMn3zBqecXoS69n6Y5in+/C7Pkck9g8UqAJXFAv3hMAlz+YuIOdBJtiUajgsZeV2mkTzhkqbRWhesXL1JgNJcFYQQocAE0l3A3vQAEdeyuRtt7OF2gCBV44viB1MB+NivexducLiT9eFzbypYASFh1yuCicxItPymgEPsh4ykHihfQIe38Fz3HOTrHUrbrbM3GhS18CKRlrlPtpRKRC6684A1vWj4Eq1//j8X77icmBFDQ+AjIUmryLzw
          cEMMgOZ8EWj7cnVQLFSh7lb4crWG75kTmC7ts70W9mY
          -> done

          -> ok

          """)
      plugin.runIdentityV1()

      XCTAssertEqual(
        """
        -> msg
        bWlzc2luZyBwb3N0LXF1YW50dW0ga2V5IHN1cHBvcnQ
        -> done

        """, stream.output)
    }
  #endif

  func testRecipientStanzaMultipleFiles() throws {
    let plugin = Plugin(crypto: crypto, stream: stream)
    stream.add(
      input:
        """
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

        -> add-identity AGE-PLUGIN-SE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWSREKAW7

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
        -> add-identity AGE-PLUGIN-SE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWSREKAW7

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

        -> add-identity AGE-PLUGIN-SE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWSREKAW7

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

        -> add-identity AGE-PLUGIN-SE-1JQDEPT8UN77Z4Q2UNERWRQRY4RG3RK6DV7YG0R562HKY2TDQCNWSREKAW7

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

        -> add-identity AGE-PLUGIN-SE-18YNMANPJKHE2ZAZJHRCKZKFXCT78YYWUTY0F730TMTZFV0CM9YHSRP8GPG

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
