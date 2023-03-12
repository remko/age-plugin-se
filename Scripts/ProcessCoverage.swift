#!/usr/bin/swift 

import Foundation

let data = try JSONDecoder().decode(
  CoverageData.self,
  from:
    try String(contentsOfFile: CommandLine.arguments[1]).data(using: .utf8)!
)

var covered = 0
var total = 0
print("Code coverage (lines):")
for d in data.data {
  for f in d.files {
    if f.filename.contains("Tests/") || f.filename.contains(".build/") {
      continue
    }
    let filename = String(f.filename.split(separator: "/").last!)
    let percent = String(
      format: "%.01f", Float(f.summary.lines.covered * 100) / Float(f.summary.lines.count))
    print("  \(filename): \(f.summary.lines.covered)/\(f.summary.lines.count) (\(percent)%)")
    covered += f.summary.lines.covered
    total += f.summary.lines.count
  }
}
let percent = String(
  format: "%.01f", Float(covered * 100) / Float(total))
print("  ---")
print("  TOTAL: \(covered)/\(total) (\(percent)%)")

let percentr = Int((Float(covered * 100) / Float(total)).rounded())
let coverageSVG = """
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
          <tspan x="7" y="15">\(percentr)%</tspan>
        </text>
        <text fill="#FFFFFF">
          <tspan x="7" y="14">\(percentr)%</tspan>
        </text>
      </g>
    </g>
  </svg>
  """
FileManager.default.createFile(
  atPath: CommandLine.arguments[2],
  contents: coverageSVG.data(using: .utf8)
)

////////////////////////////////////////////////////////////////////////////////

struct CoverageData: Codable {
  var data: [CoverageDataEntry]
}

struct CoverageDataEntry: Codable {
  var files: [CoverageFileEntry]
}

struct CoverageFileEntry: Codable {
  var filename: String
  var summary: CoverageFileSummary
}

struct CoverageFileSummary: Codable {
  var lines: CoverageFileSummaryLines
}

struct CoverageFileSummaryLines: Codable {
  var count: Int
  var covered: Int
}

////////////////////////////////////////////////////////////////////////////////
