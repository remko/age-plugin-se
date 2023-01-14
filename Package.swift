// swift-tools-version: 5.7

import PackageDescription

let package = Package(
  name: "AgeAppleSEPlugin",
  platforms: [.macOS(.v13)],
  targets: [
    .executableTarget(name: "age-plugin-applese", path: "Sources"),
    .testTarget(
      name: "Tests",
      dependencies: ["age-plugin-applese"],
      path: "Tests"
    ),
  ]
)
