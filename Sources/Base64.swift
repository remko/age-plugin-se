import Foundation

extension Data {
  init?(base64RawEncoded: String) {
    if base64RawEncoded.hasSuffix("=") {
      return nil
    }
    var str = base64RawEncoded
    switch base64RawEncoded.count % 4 {
    case 2:
      str += "=="
    case 3:
      str += "="
    default:
      ()
    }
    guard let data = Data(base64Encoded: str) else {
      return nil
    }
    self = data
  }

  func base64RawEncodedData(wrap: Bool = false) -> Data {
    var options: Data.Base64EncodingOptions = []
    if wrap {
      options = [.lineLength64Characters, .endLineWithLineFeed]
    }
    var s = base64EncodedData(options: options)
    if let pi = s.firstIndex(of: Character("=").asciiValue!) {
      s = Data(s[s.startIndex..<pi])
    }
    return s
  }

  func base64RawEncodedString(wrap: Bool = false) -> String {
    return String(decoding: base64RawEncodedData(wrap: wrap), as: UTF8.self)
  }
}
