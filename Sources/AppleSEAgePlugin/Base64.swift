import Foundation

extension Data {
  init?(base64RawEncoded: String) {
    var data: Data?
    switch base64RawEncoded.count % 4 {
    case 2:
      data = Data(base64Encoded: base64RawEncoded + "==")
    case 3:
      data = Data(base64Encoded: base64RawEncoded + "=")
    default:
      data = Data(base64Encoded: base64RawEncoded)
    }
    if data == nil {
      return nil
    }
    self = data!
  }

  var base64RawEncodedData: Data {
    var s = base64EncodedString(options: [
      Base64EncodingOptions.lineLength64Characters, Base64EncodingOptions.endLineWithLineFeed,
    ])
    if let pi = s.firstIndex(of: "=") {
      s = String(s[s.startIndex..<pi])
    }
    return s.data(using: String.Encoding.utf8)!
  }

  var base64RawEncodedString: String {
    var s = base64EncodedString(options: [
      Base64EncodingOptions.lineLength64Characters, Base64EncodingOptions.endLineWithLineFeed,
    ])
    if let pi = s.firstIndex(of: "=") {
      s = String(s[s.startIndex..<pi])
    }
    return s
  }
}
