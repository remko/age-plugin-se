// swift-tools-version: 5.7

import PackageDescription

// Technically, the dependencies don't need the platform conditional.
// However, I like to keep the dependencies out of the build entirely on macOS.
// Unfortunately, this also means Package.resolved isn't stable.

var packageDependencies: [Package.Dependency] {
  #if os(Linux) || os(Windows)
    return [.package(url: "https://github.com/apple/swift-crypto.git", "2.0.0"..<"3.0.0")]
  #else
    return []
  #endif
}

var targetDependencies: [Target.Dependency] {
  #if os(Linux) || os(Windows)
    return [
      .product(
        name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux, .windows]))
    ]
  #else
    return []
  #endif
}

let package = Package(
  name: "AgeSecureEnclavePlugin",
  platforms: [.macOS(.v13)],
  dependencies: packageDependencies,
  targets: [
    .executableTarget(name: "age-plugin-se", dependencies: targetDependencies, path: "Sources"),
    .testTarget(name: "Tests", dependencies: ["age-plugin-se"], path: "Tests"),
  ]
)
