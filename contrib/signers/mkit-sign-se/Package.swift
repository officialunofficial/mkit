// swift-tools-version: 5.9
//
// mkit-sign-se — Apple Secure Enclave external signer for mkit.
//
// Speaks the v1 external-signer protocol defined in
// `docs/SPEC-EXTERNAL-SIGNER.md`. P-256 only (that is the only algorithm
// the Secure Enclave supports). The private scalar is non-extractable by
// construction; the Keychain stores a SecKey reference under
// `kSecAttrApplicationTag = <tag>`.

import PackageDescription

let package = Package(
    name: "mkit-sign-se",
    platforms: [
        // CryptoKit's SecureEnclave API requires macOS 10.15+; we pin
        // 12.0 because that is the oldest version we actually test
        // against and documents a stable `SecureEnclave.isAvailable`.
        .macOS(.v12)
    ],
    products: [
        .executable(name: "mkit-sign-se", targets: ["mkit-sign-se"])
    ],
    targets: [
        .executableTarget(
            name: "mkit-sign-se",
            path: "Sources/mkit-sign-se"
        ),
        .testTarget(
            name: "mkitSignSeTests",
            dependencies: ["mkit-sign-se"],
            path: "Tests/mkitSignSeTests"
        ),
    ]
)
