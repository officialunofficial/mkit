// swift-tools-version: 5.9
//
// mkit-sign-se — Apple Secure Enclave external signer for mkit.
//
// Speaks the v1 external-signer protocol defined in
// `docs/SPEC-EXTERNAL-SIGNER.md`: length-prefixed protobuf `SignerFrame`
// messages on stdin/stdout. The schema is shared with the Rust
// reference signers (`rust/crates/mkit-rpc/proto/signer.proto`); the
// Swift package consumes pre-generated `.pb.swift` sources from
// `Sources/mkit-sign-se/Generated/` (see `scripts/regenerate-proto.sh`).
//
// P-256 only (the only algorithm the Secure Enclave supports). The
// private scalar is non-extractable by construction; the Keychain
// stores an opaque `dataRepresentation` blob under
// `kSecAttrAccount = <tag>`.

import PackageDescription

let package = Package(
    name: "mkit-sign-se",
    platforms: [
        // CryptoKit's SecureEnclave API requires macOS 10.15+; we pin
        // 12.0 because that is the oldest version we actually test
        // against and documents a stable `SecureEnclave.isAvailable`.
        // SwiftProtobuf 1.30+ also supports macOS 12.
        .macOS(.v12)
    ],
    products: [
        .executable(name: "mkit-sign-se", targets: ["mkit-sign-se"])
    ],
    dependencies: [
        // Canonical Apple-platform protobuf runtime. Matches the wire
        // format produced by the `buffa` runtime the Rust reference
        // signers use — both speak length-prefixed protobuf 3 / edition
        // 2023. Generated sources are checked into
        // `Sources/mkit-sign-se/Generated/` to avoid build-time codegen
        // (SwiftPM has no clean `build.rs` equivalent).
        .package(url: "https://github.com/apple/swift-protobuf", from: "1.30.0")
    ],
    targets: [
        .executableTarget(
            name: "mkit-sign-se",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf")
            ],
            path: "Sources/mkit-sign-se"
        ),
        .testTarget(
            name: "mkitSignSeTests",
            dependencies: [
                "mkit-sign-se",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            path: "Tests/mkitSignSeTests"
        ),
    ]
)
