// swift-tools-version: 5.7

import PackageDescription

let package = Package(
  name: "AgeAppleSEPlugin",
  platforms: [
    .macOS(.v13)
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-argument-parser", from: "1.2.0")
  ],
  targets: [
    .executableTarget(
      name: "age-plugin-applese",
      dependencies: [
        .product(name: "ArgumentParser", package: "swift-argument-parser")
      ],
      path: "Sources/AgeAppleSEPlugin"
    ),
    .testTarget(
      name: "AgeAppleSEPluginTests",
      dependencies: ["age-plugin-applese"]),
  ]
)
