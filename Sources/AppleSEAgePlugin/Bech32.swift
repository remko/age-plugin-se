// Spec: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
// Modified version of https://github.com/0xDEADP00L/Bech32/blob/master/LICENSE

// Copyright 2018 Evolution Group Limited

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Foundation

/// Bech32 checksum implementation
public class Bech32 {
  private let gen: [UInt32] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3]
  /// Bech32 checksum delimiter
  private let checksumMarker: String = "1"
  /// Bech32 character set for encoding
  private let encCharset: Data = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".data(using: .utf8)!
  /// Bech32 character set for decoding
  private let decCharset: [Int8] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
    1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1,
    1, 0, 3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1,
  ]

  private func convertBits(from: Int, to: Int, pad: Bool, idata: Data) throws -> Data {
    var acc: Int = 0
    var bits: Int = 0
    let maxv: Int = (1 << to) - 1
    let maxAcc: Int = (1 << (from + to - 1)) - 1
    var odata = Data()
    for ibyte in idata {
      acc = ((acc << from) | Int(ibyte)) & maxAcc
      bits += from
      while bits >= to {
        bits -= to
        odata.append(UInt8((acc >> bits) & maxv))
      }
    }
    if pad {
      if bits != 0 {
        odata.append(UInt8((acc << (to - bits)) & maxv))
      }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
      throw DecodingError.bitsConversionFailed
    }
    return odata
  }

  /// Find the polynomial with value coefficients mod the generator as 30-bit.
  private func polymod(_ values: Data) -> UInt32 {
    var chk: UInt32 = 1
    for v in values {
      let top = (chk >> 25)
      chk = (chk & 0x1ffffff) << 5 ^ UInt32(v)
      for i: UInt8 in 0..<5 {
        chk ^= ((top >> i) & 1) == 0 ? 0 : gen[Int(i)]
      }
    }
    return chk
  }

  /// Expand a HRP for use in checksum computation.
  private func expandHrp(_ hrp: String) -> Data {
    guard let hrpBytes = hrp.data(using: .utf8) else { return Data() }
    var result = Data(repeating: 0x00, count: hrpBytes.count * 2 + 1)
    for (i, c) in hrpBytes.enumerated() {
      result[i] = c >> 5
      result[i + hrpBytes.count + 1] = c & 0x1f
    }
    result[hrp.count] = 0
    return result
  }

  /// Verify checksum
  private func verifyChecksum(hrp: String, checksum: Data) -> Bool {
    var data = expandHrp(hrp)
    data.append(checksum)
    return polymod(data) == 1
  }

  /// Create checksum
  private func createChecksum(hrp: String, values: Data) -> Data {
    var enc = expandHrp(hrp)
    enc.append(values)
    enc.append(Data(repeating: 0x00, count: 6))
    let mod: UInt32 = polymod(enc) ^ 1
    var ret: Data = Data(repeating: 0x00, count: 6)
    for i in 0..<6 {
      ret[i] = UInt8((mod >> (5 * (5 - i))) & 31)
    }
    return ret
  }

  /// Encode Bech32 string
  private func encodeBech32(_ hrp: String, values: Data) -> String {
    let checksum = createChecksum(hrp: hrp, values: values)
    var combined = values
    combined.append(checksum)

    guard let hrpBytes = hrp.data(using: .utf8) else { return "" }
    var ret = hrpBytes
    ret.append("1".data(using: .utf8)!)
    for i in combined {
      ret.append(encCharset[Int(i)])
    }
    return String(data: ret, encoding: .utf8) ?? ""
  }

  /// Decode Bech32 string
  public func decodeBech32(_ str: String) throws -> (hrp: String, checksum: Data) {
    guard let strBytes = str.data(using: .utf8) else {
      throw DecodingError.nonUTF8String
    }
    var lower: Bool = false
    var upper: Bool = false
    for c in strBytes {
      // printable range
      if c < 33 || c > 126 {
        throw DecodingError.nonPrintableCharacter
      }
      // 'a' to 'z'
      if c >= 97 && c <= 122 {
        lower = true
      }
      // 'A' to 'Z'
      if c >= 65 && c <= 90 {
        upper = true
      }
    }
    if lower && upper {
      throw DecodingError.invalidCase
    }
    guard let pos = str.range(of: checksumMarker, options: .backwards)?.lowerBound else {
      throw DecodingError.noChecksumMarker
    }
    let intPos: Int = str.distance(from: str.startIndex, to: pos)
    guard intPos >= 1 else {
      throw DecodingError.incorrectHrpSize
    }
    guard intPos + 7 <= str.count else {
      throw DecodingError.incorrectChecksumSize
    }
    let vSize: Int = str.count - 1 - intPos
    var values: Data = Data(repeating: 0x00, count: vSize)
    for i in 0..<vSize {
      let c = strBytes[i + intPos + 1]
      let decInt = decCharset[Int(c)]
      if decInt == -1 {
        throw DecodingError.invalidCharacter
      }
      values[i] = UInt8(decInt)
    }
    let hrp = String(str[..<pos]).lowercased()
    guard verifyChecksum(hrp: hrp, checksum: values) else {
      throw DecodingError.checksumMismatch
    }
    return (hrp, Data(values[..<(vSize - 6)]))
  }

  public func encode(hrp: String, data: Data) -> String {
    let isUpper = hrp[hrp.startIndex].isUppercase
    let result = encodeBech32(
      isUpper ? hrp.lowercased() : hrp,
      values: try! self.convertBits(from: 8, to: 5, pad: true, idata: data))
    return isUpper ? result.uppercased() : result
  }

  public func decode(_ str: String) throws -> (hrp: String, data: Data) {
    let isUpper = str[str.startIndex].isUppercase
    let result = try decodeBech32(isUpper ? str.lowercased() : str)
    return (
      isUpper ? result.hrp.uppercased() : result.hrp,
      try convertBits(from: 5, to: 8, pad: false, idata: result.checksum)
    )
  }
}

extension Bech32 {
  public enum DecodingError: LocalizedError {
    case nonUTF8String
    case nonPrintableCharacter
    case invalidCase
    case noChecksumMarker
    case incorrectHrpSize
    case incorrectChecksumSize

    case invalidCharacter
    case checksumMismatch

    case bitsConversionFailed

    public var errorDescription: String? {
      switch self {
      case .bitsConversionFailed:
        return "Failed to perform bits conversion"
      case .checksumMismatch:
        return "Checksum doesn't match"
      case .incorrectChecksumSize:
        return "Checksum size too low"
      case .incorrectHrpSize:
        return "Human-readable-part is too small or empty"
      case .invalidCase:
        return "String contains mixed case characters"
      case .invalidCharacter:
        return "Invalid character met on decoding"
      case .noChecksumMarker:
        return "Checksum delimiter not found"
      case .nonPrintableCharacter:
        return "Non printable character in input string"
      case .nonUTF8String:
        return "String cannot be decoded by utf8 decoder"
      }
    }
  }
}
