@testable import age_plugin_se

class MemoryStream: Stream {
  var inputLines: [String] = []
  var outputLines: [String] = []

  var output: String {
    return outputLines.joined(separator: "\n")
  }

  func add(input: String) {
    inputLines.append(contentsOf: input.components(separatedBy: "\n"))
  }

  func readLine() -> String? {
    if inputLines.isEmpty {
      return nil
    }
    let result = inputLines[0]
    inputLines.removeFirst()
    return result
  }

  func writeLine(_ line: String) {
    outputLines.append(contentsOf: line.components(separatedBy: "\n"))
  }
}
