#if os(Linux)
  @preconcurrency import Foundation
#else
  import Foundation
#endif

/// Abstraction of a line-based communication stream
protocol Stream {
  func readLine() -> String?
  func writeLine(_: String)
}

class StandardIOStream: Stream {
  func readLine() -> String? {
    return Swift.readLine(strippingNewline: true)
  }

  func writeLine(_ line: String) {
    FileHandle.standardOutput.write(Data(line.utf8))
    FileHandle.standardOutput.write(Data([0xa]))
    fflush(stdout)
  }
}
