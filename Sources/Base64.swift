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

  var base64RawEncodedData: Data {
    var s = base64EncodedData(options: [
      Base64EncodingOptions.lineLength64Characters, Base64EncodingOptions.endLineWithLineFeed,
    ])
    if let pi = s.firstIndex(of: Character("=").asciiValue!) {
      s = Data(s[s.startIndex..<pi])
    }
    return s
  }

  var base64RawEncodedString: String {
    return String(data: base64RawEncodedData, encoding: .utf8)!
  }
}
