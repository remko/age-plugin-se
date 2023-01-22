// swift-tools-version: 5.7

import PackageDescription

let package = Package(
  name: "AgeSecureEnclavePlugin",
  platforms: [.macOS(.v13)],
  targets: [
    .executableTarget(name: "age-plugin-se", path: "Sources"),
    .testTarget(
      name: "Tests",
      dependencies: ["age-plugin-se"],
      path: "Tests"
    ),
  ]
)
