// swift-tools-version: 5.7

import PackageDescription

let package = Package(
  name: "AgeAppleSEPlugin",
  platforms: [
    .macOS(.v13)
  ],
  dependencies: [],
  targets: [
    .executableTarget(
      name: "age-plugin-applese",
      dependencies: [],
      path: "Sources/AgeAppleSEPlugin"
    ),
    .testTarget(
      name: "AgeAppleSEPluginTests",
      dependencies: ["age-plugin-applese"]),
  ]
)
