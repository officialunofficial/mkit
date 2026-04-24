// ProtocolTests.swift — round-trip + encoding tests for mkit-sign-se.
//
// The SEP-backed parts are gated with `XCTSkip` when
// `SecureEnclave.isAvailable` is false, so CI on Intel Macs without T2
// does not fail.

import CryptoKit
import XCTest

@testable import mkit_sign_se

final class ProtocolTests: XCTestCase {

    // MARK: - JSON round-trip

    func testRequestDecodesCanonicalShape() throws {
        let json = """
            {"pae_base64":"RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ==","algorithm":"p256"}
            """
        let data = Data(json.utf8)
        let req = try decodeRequest(data)
        XCTAssertEqual(req.algorithm, "p256")
        XCTAssertEqual(
            req.paeBase64,
            "RFNTRXYxIDI4IGFwcGxpY2F0aW9uL3ZuZC5pbi10b3RvK2pzb24gMiB7fQ==")
    }

    func testRequestTolerateTrailingNewline() throws {
        // mkit writes `request + '\n'` before closing stdin. Ensure we
        // trim trailing \n / \r\n before decoding.
        let base = "{\"pae_base64\":\"AAA=\",\"algorithm\":\"p256\"}"
        for suffix in ["\n", "\r\n", ""] {
            let data = Data((base + suffix).utf8)
            let req = try decodeRequest(data)
            XCTAssertEqual(req.paeBase64, "AAA=")
            XCTAssertEqual(req.algorithm, "p256")
        }
    }

    func testResponseEncodesWireShape() throws {
        let r = SignResponse(
            keyid:
                "p256:02515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f",
            sigBase64: "AAAA"
        )
        let line = try encodeResponseLine(r)
        // Must be a single line, `keyid` first, `sig_base64` second.
        XCTAssertEqual(
            line,
            "{\"keyid\":\"p256:02515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f\",\"sig_base64\":\"AAAA\"}"
        )
    }

    // MARK: - DER -> compact signature conversion

    func testDERToCompactKnownVector() throws {
        // Hand-assembled DER signature: r = 0x01, s = 0x02, both
        // trivial. Expected compact output: 32 zero bytes + 0x01 then
        // 32 zero bytes + 0x02 — i.e. left-padded r || s.
        let der = Data([
            0x30, 0x06,  // SEQUENCE, 6 bytes
            0x02, 0x01, 0x01,  // INTEGER 1
            0x02, 0x01, 0x02,  // INTEGER 2
        ])
        let compact = try compactECDSASignatureFromDER(der)
        XCTAssertEqual(compact.count, 64)
        var expected = Data(repeating: 0, count: 64)
        expected[31] = 0x01
        expected[63] = 0x02
        XCTAssertEqual(compact, expected)
    }

    func testDERToCompactStripsPaddingByte() throws {
        // r has high bit set so DER adds a leading 0x00. The compact
        // form must strip that and land in the low 32 bytes cleanly.
        // r = 0x0080..00 (33 bytes w/ padding), s = 0x03.
        var der = Data([0x30, 0x26])
        // INTEGER r: length 33, 0x00 0x80 then 31 zero bytes.
        der.append(contentsOf: [0x02, 0x21, 0x00, 0x80])
        der.append(Data(repeating: 0, count: 31))
        // INTEGER s: length 1, value 3.
        der.append(contentsOf: [0x02, 0x01, 0x03])
        let compact = try compactECDSASignatureFromDER(der)
        XCTAssertEqual(compact.count, 64)
        XCTAssertEqual(compact[0], 0x80)
        for i in 1..<32 { XCTAssertEqual(compact[i], 0) }
        for i in 32..<63 { XCTAssertEqual(compact[i], 0) }
        XCTAssertEqual(compact[63], 0x03)
    }

    // MARK: - SEC1 compression

    func testCompressSEC1EvenY() throws {
        // Fabricate a 64-byte uncompressed pubkey with y-last-byte
        // even. Compressed prefix should be 0x02.
        var raw = Data(repeating: 0xAB, count: 64)
        raw[63] = 0x02  // y ends in 0x02 -> even
        let compressed = try compressSEC1FromRaw(raw)
        XCTAssertEqual(compressed.count, 33)
        XCTAssertEqual(compressed[0], 0x02)
        // x is the first 32 bytes of `raw`.
        XCTAssertEqual(compressed.dropFirst(), raw.prefix(32))
    }

    func testCompressSEC1OddY() throws {
        var raw = Data(repeating: 0xCD, count: 64)
        raw[63] = 0x07  // odd
        let compressed = try compressSEC1FromRaw(raw)
        XCTAssertEqual(compressed.count, 33)
        XCTAssertEqual(compressed[0], 0x03)
    }

    func testCompressSEC1RealKey() throws {
        // Round-trip via CryptoKit: generate a software P-256 key,
        // extract its rawRepresentation (64 bytes, uncompressed no
        // prefix), compress, and ask P256 to re-parse it from
        // compressed SEC1. If our compression math is correct the
        // re-parsed key matches.
        let sk = P256.Signing.PrivateKey()
        let raw = sk.publicKey.rawRepresentation  // 64 bytes
        let compressed = try compressSEC1FromRaw(raw)
        XCTAssertEqual(compressed.count, 33)
        // `x963Representation` has a 0x04 prefix; `compressedRepresentation`
        // (on PublicKey) is what we want to compare against — available
        // on P256 since macOS 14. Use a manual check instead: build a
        // VerifyingKey from our compressed bytes and confirm its raw
        // form matches.
        let reparsed = try P256.Signing.PublicKey(compressedRepresentation: compressed)
        XCTAssertEqual(reparsed.rawRepresentation, raw)
    }

    // MARK: - Hex

    func testHexLower() {
        XCTAssertEqual(hexLower(Data([0x00, 0xFF, 0x10, 0xAB])), "00ff10ab")
    }

    // MARK: - Sign + verify roundtrip (SEP-gated)

    func testKeygenSignVerifyRoundtrip() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this host")
        }
        // Use a unique tag per test run to avoid collisions.
        let tag = "mkit-sign-se-test-" + UUID().uuidString
        defer {
            try? SecureEnclaveKey.delete(tag: tag)
        }
        let key = try SecureEnclaveKey.create(tag: tag, requireBiometric: false)
        let pae = Data("DSSEv1 4 test 2 hi".utf8)
        let digest = SHA256.hash(data: pae)
        let sig = try key.signature(for: digest)
        let compact = sig.rawRepresentation
        XCTAssertEqual(compact.count, 64)

        // Verify via pure P256.Signing — doesn't touch the SEP, so we
        // prove the bytes we emit are the ones a software-side
        // verifier will accept.
        let pub = key.publicKey  // P256.Signing.PublicKey (non-SEP)
        let softSig = try P256.Signing.ECDSASignature(rawRepresentation: compact)
        XCTAssertTrue(pub.isValidSignature(softSig, for: digest))
    }
}
