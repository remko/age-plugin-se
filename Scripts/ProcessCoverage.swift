#!/usr/bin/swift 

//
// Postprocesses an LLVM coverage report, as output by `swift test --enable-coverage`.
//
// - Filters files out of the report that are not interesting (tests, package
//   dependencies)
// - Generates an HTML report of the coverage, with annotated source code
// - Prints a summary report to standard output
// - Generates an SVG of a coverage badge that can be used in the README
//

import Foundation

let inputPath = CommandLine.arguments[1]
let outputPath = CommandLine.arguments[2]
let htmlOutputPath = CommandLine.arguments[3]
let badgeOutputPath = CommandLine.arguments[4]

var report = try JSONDecoder().decode(
  CoverageReport.self,
  from: try Data(contentsOf: URL(fileURLWithPath: inputPath))
)

// Filter out data we don't need
// Ideally, this wouldn't be necessary, and we could specify not to record coverage for
// these files
for di in report.data.indices {
  report.data[di].files.removeAll(where: { f in
    f.filename.contains("Tests/") || f.filename.contains(".build/")
  })
  // Update (some) totals
  (report.data[di].totals.lines.covered, report.data[di].totals.lines.count) =
    report.data[di].files.reduce(
      (0, 0),
      { acc, next in
        (
          acc.0 + next.summary.lines.covered,
          acc.1 + next.summary.lines.count
        )
      })
  report.data[di].totals.lines.percent =
    100 * Float(report.data[di].totals.lines.covered) / Float(report.data[di].totals.lines.count)
}

// Write out filtered report
FileManager.default.createFile(
  atPath: outputPath,
  contents: try JSONEncoder().encode(report)
)

////////////////////////////////////////////////////////////////////////////////
// Summary report
////////////////////////////////////////////////////////////////////////////////

var totalCovered = 0
var totalCount = 0
print("Code coverage (lines):")
for d in report.data {
  for f in d.files {
    let filename = f.filename.stripPrefix(FileManager.default.currentDirectoryPath + "/")
    let lines = String(format: "%d/%d", f.summary.lines.covered, f.summary.lines.count)
    let percent = String(
      format: "(%.01f%%)", Float(f.summary.lines.covered * 100) / Float(f.summary.lines.count))
    print(
      "  \(filename.rightPadded(toLength: 24)) \(lines.leftPadded(toLength: 10)) \(percent.leftPadded(toLength: 8))"
    )
  }
  totalCovered += d.totals.lines.covered
  totalCount += d.totals.lines.count
}
let lines = String(format: "%d/%d", totalCovered, totalCount)
let percent = String(
  format: "(%.01f%%)", Float(totalCovered * 100) / Float(totalCount))
print("  ---")
print(
  "  \("TOTAL".rightPadded(toLength: 24)) \(lines.leftPadded(toLength: 10)) \(percent.leftPadded(toLength: 8))"
)

////////////////////////////////////////////////////////////////////////////////
// Coverage badge
////////////////////////////////////////////////////////////////////////////////

let percentRounded = Int((Float(totalCovered * 100) / Float(totalCount)).rounded())
FileManager.default.createFile(
  atPath: badgeOutputPath,
  contents: Data(
    """
    <svg xmlns="http://www.w3.org/2000/svg" width="105" height="20">
      <title>Coverage - \(percent)%</title>
      <defs>
        <linearGradient id="workflow-fill" x1="50%" y1="0%" x2="50%" y2="100%">
          <stop stop-color="#444D56" offset="0%"></stop>
          <stop stop-color="#24292E" offset="100%"></stop>
        </linearGradient>
        <linearGradient id="state-fill" x1="50%" y1="0%" x2="50%" y2="100%">
          <stop stop-color="#34D058" offset="0%"></stop>
          <stop stop-color="#28A745" offset="100%"></stop>
        </linearGradient>
      </defs>
      <g fill="none" fill-rule="evenodd">
        <g font-family="&#39;DejaVu Sans&#39;,Verdana,Geneva,sans-serif" font-size="11">
          <path id="workflow-bg" d="M0,3 C0,1.3431 1.3552,0 3.02702703,0 L65,0 L65,20 L3.02702703,20 C1.3552,20 0,18.6569 0,17 L0,3 Z" fill="url(#workflow-fill)" fill-rule="nonzero"></path>
          <text fill="#010101" fill-opacity=".3">
            <tspan x="6" y="15" aria-hidden="true">Coverage</tspan>
          </text>
          <text fill="#FFFFFF">
            <tspan x="6" y="14">Coverage</tspan>
          </text>
        </g>
        <g transform="translate(65)" font-family="&#39;DejaVu Sans&#39;,Verdana,Geneva,sans-serif" font-size="11">
          <path d="M0 0h46.939C48.629 0 40 1.343 40 3v14c0 1.657-1.37 3-3.061 3H0V0z" id="state-bg" fill="url(#state-fill)" fill-rule="nonzero"></path>
          <text fill="#010101" fill-opacity=".3" aria-hidden="true">
            <tspan x="7" y="15">\(percentRounded)%</tspan>
          </text>
          <text fill="#FFFFFF">
            <tspan x="7" y="14">\(percentRounded)%</tspan>
          </text>
        </g>
      </g>
    </svg>
    """.utf8
  ))

////////////////////////////////////////////////////////////////////////////////
// HTML Report
////////////////////////////////////////////////////////////////////////////////

var out = ""
var files = ""
var fileID = 0
for d in report.data {
  for f in d.files {
    let filename = f.filename.stripPrefix(FileManager.default.currentDirectoryPath + "/")
    let percent = String(
      format: "%.01f", Float(f.summary.lines.covered * 100) / Float(f.summary.lines.count))
    files += "<option value=\"f\(fileID)\">\(filename.htmlEscaped) (\(percent)%)</option>"
    out += "<pre id=\"f\(fileID)\" style=\"display: none\"><span>"
    var segments = f.segments
    for (index, line) in try
      (String(contentsOfFile: f.filename).split(omittingEmptySubsequences: false) { $0.isNewline })
      .enumerated()
    {
      var l = line
      var columnOffset = 0
      while let segment = segments.first {
        if segment.line != index + 1 {
          break
        }
        var endIndex = l.utf8.index(l.startIndex, offsetBy: segment.column - 1 - columnOffset)
        if endIndex > l.endIndex {
          endIndex = l.endIndex
        }
        columnOffset = segment.column - 1
        let spanClass = !segment.hasCount ? "" : segment.count > 0 ? "c" : "nc"
        out +=
          String(l[l.startIndex..<endIndex]).htmlEscaped
          + "</span><span class=\"\(spanClass)\">"
        l = l[endIndex..<l.endIndex]
        segments.removeFirst(1)
      }
      out += String(l).htmlEscaped + "\n"
    }
    out += "</span></pre>"
    fileID += 1
  }
}

out =
  """
  <!DOCTYPE html>
  <html>
    <head>
      <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
      <title>Coverage</title>
      <style>
        body {
          background: #111;
          color: #888;
          font-family: monospace;
          font-size: 15px;
        }
        nav { position: fixed; top: 0; }
        pre { margin-top: 25px; }
        .c { color: green; }
        .nc { color: red; }
      </style>
    </head>
    <body>
      <nav>
        <select id="files">
          \(files)
        </select>
      </nav>
  """ + out + """
    <script>
      (function() {
        var filesEl = document.getElementById('files');
        var selectedEl;
        function select(fileID) {
          if (selectedEl != null) {
            selectedEl.style.display = 'none';
          }
          selectedEl = document.getElementById(fileID);
          if (selectedEl == null) {
            return;
          }
          filesEl.value = fileID;
          selectedEl.style.display = 'block';
          location.hash = fileID;
        }

        if (location.hash !== "") {
          select(location.hash.substr(1));
        }
        if (selectedEl == null) {
          select("f0");
        }

        filesEl.addEventListener('change', function() { 
          select(filesEl.value);
          window.scrollTo(0, 0);
        } , false);
      })();
    </script>
    </body></html>
    """
FileManager.default.createFile(
  atPath: htmlOutputPath,
  contents: Data(out.utf8)
)

////////////////////////////////////////////////////////////////////////////////
// LLVM Coverage Export JSON Format
// See https://github.com/llvm/llvm-project/blob/main/llvm/tools/llvm-cov/CoverageExporterJson.cpp
////////////////////////////////////////////////////////////////////////////////

struct CoverageReport: Codable {
  var type: String
  var version: String
  var data: [CoverageExport]
}

struct CoverageExport: Codable {
  var totals: CoverageSummary
  var files: [CoverageFile]
  var functions: [CoverageFunction]
}

struct CoverageFile: Codable {
  var filename: String
  var summary: CoverageSummary
  var segments: [CoverageSegment]
  var branches: [CoverageBranch]
  var expansions: [CoverageExpansion]
}

struct CoverageFunction: Codable {
  var count: Int
  var filenames: [String]
  var name: String
  var regions: [CoverageRegion]
  var branches: [CoverageBranch]
}

struct CoverageSummary: Codable {
  var lines: CoverageSummaryEntry
  var branches: CoverageSummaryEntry
  var functions: CoverageSummaryEntry
  var instantiations: CoverageSummaryEntry
  var regions: CoverageSummaryEntry
}

struct CoverageSummaryEntry: Codable {
  var count: Int
  var covered: Int
  var percent: Float
  var notcovered: Int?
}

struct CoverageSegment {
  var line: Int
  var column: Int
  var count: Int
  var hasCount: Bool
  var isRegionEntry: Bool
  var isGapRegion: Bool
}

extension CoverageSegment: Decodable {
  init(from decoder: Decoder) throws {
    var c = try decoder.unkeyedContainer()
    line = try c.decode(Int.self)
    column = try c.decode(Int.self)
    count = try c.decode(Int.self)
    hasCount = try c.decode(Bool.self)
    isRegionEntry = try c.decode(Bool.self)
    isGapRegion = try c.decode(Bool.self)
  }
}

extension CoverageSegment: Encodable {
  func encode(to encoder: Encoder) throws {
    var c = encoder.unkeyedContainer()
    try c.encode(line)
    try c.encode(column)
    try c.encode(count)
    try c.encode(hasCount)
    try c.encode(isRegionEntry)
    try c.encode(isGapRegion)
  }
}

struct CoverageRegion {
  var lineStart: Int
  var columnStart: Int
  var lineEnd: Int
  var columnEnd: Int
  var executionCount: Int
  var fileID: Int
  var expandedFileID: Int
  var regionKind: Int
}

extension CoverageRegion: Decodable {
  init(from decoder: Decoder) throws {
    var c = try decoder.unkeyedContainer()
    lineStart = try c.decode(Int.self)
    columnStart = try c.decode(Int.self)
    lineEnd = try c.decode(Int.self)
    columnEnd = try c.decode(Int.self)
    executionCount = try c.decode(Int.self)
    fileID = try c.decode(Int.self)
    expandedFileID = try c.decode(Int.self)
    regionKind = try c.decode(Int.self)
  }
}

extension CoverageRegion: Encodable {
  func encode(to encoder: Encoder) throws {
    var c = encoder.unkeyedContainer()
    try c.encode(lineStart)
    try c.encode(columnStart)
    try c.encode(lineEnd)
    try c.encode(columnEnd)
    try c.encode(executionCount)
    try c.encode(fileID)
    try c.encode(expandedFileID)
    try c.encode(regionKind)
  }
}

struct CoverageBranch: Codable {}

struct CoverageExpansion: Codable {}

////////////////////////////////////////////////////////////////////////////////
// Misc utility
////////////////////////////////////////////////////////////////////////////////

extension String {
  func leftPadded(toLength: Int) -> String {
    if count < toLength {
      return String(repeating: " ", count: toLength - count) + self
    } else {
      return self
    }
  }

  func rightPadded(toLength: Int) -> String {
    if count < toLength {
      return self + String(repeating: " ", count: toLength - count)
    } else {
      return self
    }
  }

  func stripPrefix(_ prefix: String) -> String {
    return self.hasPrefix(prefix) ? String(self.dropFirst(prefix.count)) : self
  }

  var htmlEscaped: String {
    return self.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(
      of: "<", with: "&lt;"
    ).replacingOccurrences(
      of: ">", with: "&gt;")
  }
}
