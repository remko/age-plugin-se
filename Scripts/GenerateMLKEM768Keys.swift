#!/usr/bin/swift 

import CryptoKit
import Foundation

extension Data {
  func base64RawEncodedData() -> Data {
    var s = base64EncodedData(options: [])
    if let pi = s.firstIndex(of: Character("=").asciiValue!) {
      s = Data(s[s.startIndex..<pi])
    }
    return s
  }
}

if #available(macOS 21.0, *) {
  for _ in 1...10 {
    let privateKey = try! CryptoKit.MLKEM768.PrivateKey()
    print(String(data: privateKey.seedRepresentation.base64RawEncodedData(), encoding: .utf8)!)
  }
} else {
  print("ML-KEM is not supported on this operating system version.")
}
