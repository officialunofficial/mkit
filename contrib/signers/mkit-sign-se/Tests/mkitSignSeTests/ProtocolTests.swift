// ProtocolTests.swift — wire-format round-trip + encoding tests for
// mkit-sign-se.
//
// The SEP-backed test (`testKeygenSignVerifyRoundtrip`) is gated with
// `XCTSkip` when `SecureEnclave.isAvailable` is false, so CI on Intel
// Macs without T2 does not fail. Everything else is wire-format only
// and runs everywhere.

import CryptoKit
import SwiftProtobuf
import XCTest

@testable import mkit_sign_se

final class ProtocolTests: XCTestCase {

    // MARK: - Frame round-trip via in-memory buffers

    /// In-memory `FrameReader` / `FrameWriter` so we exercise the
    /// framing layer without touching real file descriptors.
    final class BufferStream: FrameReader, FrameWriter {
        var input: Data
        var output = Data()
        init(input: Data) { self.input = input }

        func readExact(_ count: Int) throws -> Data? {
            if input.isEmpty { return nil }
            guard input.count >= count else {
                throw FrameError.bodyTruncated(expected: UInt32(count), actual: input.count)
            }
            let chunk = input.prefix(count)
            input.removeFirst(count)
            return Data(chunk)
        }

        func writeAll(_ data: Data) throws {
            output.append(data)
        }

        func flush() throws {}
    }

    /// Encode a `SignerFrame` to the on-wire byte stream (length prefix
    /// + protobuf body) without going through `writeFrame`, so the test
    /// can assert `readFrame` recovers the same bytes.
    private func encodeFrame(_ frame: SignerFrame) throws -> Data {
        let body = try frame.serializedData()
        var out = Data(capacity: 4 + body.count)
        let n = UInt32(body.count)
        out.append(UInt8(n & 0xFF))
        out.append(UInt8((n >> 8) & 0xFF))
        out.append(UInt8((n >> 16) & 0xFF))
        out.append(UInt8((n >> 24) & 0xFF))
        out.append(body)
        return out
    }

    func testRoundTripHelloFrame() throws {
        var hello = Hello()
        hello.`protocol` = .protocolVersion1
        hello.callerID = "test/0.1"
        hello.wantCapabilities = true
        var frame = SignerFrame()
        frame.body = .hello(hello)

        let buf = BufferStream(input: try encodeFrame(frame))
        let read = try readFrame(buf)
        XCTAssertNotNil(read)
        guard case .some(.hello(let parsed)) = read?.body else {
            XCTFail("expected Hello, got \(String(describing: read?.body))")
            return
        }
        XCTAssertEqual(parsed.`protocol`, .protocolVersion1)
        XCTAssertEqual(parsed.callerID, "test/0.1")
        XCTAssertTrue(parsed.wantCapabilities)
    }

    func testWriteFrameProducesLittleEndianLengthPrefix() throws {
        let frame = errorFrame(.invalidRequest, "hello")
        let buf = BufferStream(input: Data())
        try writeFrame(frame, to: buf)
        let body = try frame.serializedData()
        XCTAssertEqual(buf.output.count, 4 + body.count)
        let advertised =
            UInt32(buf.output[0])
            | (UInt32(buf.output[1]) << 8)
            | (UInt32(buf.output[2]) << 16)
            | (UInt32(buf.output[3]) << 24)
        XCTAssertEqual(Int(advertised), body.count)
        XCTAssertEqual(buf.output.dropFirst(4), body)
    }

    func testReadFrameRejectsOversize() {
        // 4-byte LE length advertising MAX + 1 bytes.
        let n: UInt32 = maxFrameBytes + 1
        var buf = Data()
        buf.append(UInt8(n & 0xFF))
        buf.append(UInt8((n >> 8) & 0xFF))
        buf.append(UInt8((n >> 16) & 0xFF))
        buf.append(UInt8((n >> 24) & 0xFF))
        let stream = BufferStream(input: buf)
        XCTAssertThrowsError(try readFrame(stream)) { err in
            guard case FrameError.lengthTooLarge(let got) = err else {
                XCTFail("expected lengthTooLarge, got \(err)")
                return
            }
            XCTAssertEqual(got, n)
        }
    }

    func testReadFrameReturnsNilOnCleanEof() throws {
        let stream = BufferStream(input: Data())
        XCTAssertNil(try readFrame(stream))
    }

    // MARK: - Hello / capabilities

    func testHelloResponseAdvertisesP256OnlyAndOpaqueHandle() {
        let frame = helloResponseFrame(signerVersion: "0.0-test", requiresUserPresence: false)
        guard case .some(.helloResponse(let resp)) = frame.body else {
            XCTFail("expected HelloResponse body")
            return
        }
        XCTAssertEqual(resp.`protocol`, .protocolVersion1)
        XCTAssertEqual(resp.signerID, "mkit-sign-se/0.0-test")
        let caps = resp.capabilities
        XCTAssertEqual(caps.algorithms, [.p256])
        XCTAssertEqual(caps.keyForms, [.opaqueHandle])
        XCTAssertFalse(caps.supportsPin)
        XCTAssertFalse(caps.supportsCertificateChain)
        XCTAssertEqual(caps.maxPayloadBytes, 0)
    }

    // MARK: - handleSign error paths

    func testHandleSignRejectsNonP256Algorithm() {
        var req = SignRequest()
        req.algorithm = .ed25519
        req.keyForm = .opaqueHandle
        req.keyRef = Data("nonesuch".utf8)
        let frame = handleSign(req, defaultTag: nil)
        guard case .some(.error(let err)) = frame.body else {
            XCTFail("expected Error frame, got \(String(describing: frame.body))")
            return
        }
        XCTAssertEqual(err.code, .unsupportedAlgorithm)
    }

    func testHandleSignRejectsRawBytesKeyForm() {
        var req = SignRequest()
        req.algorithm = .p256
        req.keyForm = .rawBytes
        let frame = handleSign(req, defaultTag: "tag")
        guard case .some(.error(let err)) = frame.body else {
            XCTFail("expected Error frame")
            return
        }
        XCTAssertEqual(err.code, .unsupportedKeyForm)
    }

    func testHandleSignRequiresATag() {
        var req = SignRequest()
        req.algorithm = .p256
        req.keyForm = .opaqueHandle
        // No keyRef, no defaultTag.
        let frame = handleSign(req, defaultTag: nil)
        guard case .some(.error(let err)) = frame.body else {
            XCTFail("expected Error frame")
            return
        }
        XCTAssertEqual(err.code, .invalidRequest)
        XCTAssertTrue(err.message.contains("tag"))
    }

    // MARK: - DER -> compact signature conversion

    func testDERToCompactKnownVector() throws {
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
        var der = Data([0x30, 0x26])
        der.append(contentsOf: [0x02, 0x21, 0x00, 0x80])
        der.append(Data(repeating: 0, count: 31))
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
        var raw = Data(repeating: 0xAB, count: 64)
        raw[63] = 0x02  // y ends in even byte
        let compressed = try compressSEC1FromRaw(raw)
        XCTAssertEqual(compressed.count, 33)
        XCTAssertEqual(compressed[0], 0x02)
        XCTAssertEqual(compressed.dropFirst(), raw.prefix(32))
    }

    func testCompressSEC1OddY() throws {
        var raw = Data(repeating: 0xCD, count: 64)
        raw[63] = 0x07
        let compressed = try compressSEC1FromRaw(raw)
        XCTAssertEqual(compressed.count, 33)
        XCTAssertEqual(compressed[0], 0x03)
    }

    func testCompressSEC1RealKey() throws {
        let sk = P256.Signing.PrivateKey()
        let raw = sk.publicKey.rawRepresentation
        let compressed = try compressSEC1FromRaw(raw)
        XCTAssertEqual(compressed.count, 33)
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
        let pub = key.publicKey
        let softSig = try P256.Signing.ECDSASignature(rawRepresentation: compact)
        XCTAssertTrue(pub.isValidSignature(softSig, for: digest))
    }

    // MARK: - handleSign full success path (SEP-gated)

    func testHandleSignProducesVerifiableResponse() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this host")
        }
        let tag = "mkit-sign-se-test-" + UUID().uuidString
        defer { try? SecureEnclaveKey.delete(tag: tag) }
        let key = try SecureEnclaveKey.create(tag: tag, requireBiometric: false)

        let pae = Data("DSSEv1 4 test 2 hi".utf8)
        var req = SignRequest()
        req.algorithm = .p256
        req.keyForm = .opaqueHandle
        req.keyRef = Data(tag.utf8)
        req.payload = pae

        let frame = handleSign(req, defaultTag: nil)
        guard case .some(.signResponse(let resp)) = frame.body else {
            XCTFail("expected SignResponse, got \(String(describing: frame.body))")
            return
        }
        XCTAssertEqual(resp.signature.count, 64)
        XCTAssertEqual(resp.publicKey.count, 33)
        XCTAssertEqual(resp.algorithm, .p256)
        XCTAssertTrue(resp.keyID.hasPrefix("p256:"))

        // The keyid hex is the compressed pubkey we returned.
        let pub = key.publicKey
        let softSig = try P256.Signing.ECDSASignature(rawRepresentation: resp.signature)
        let digest = SHA256.hash(data: pae)
        XCTAssertTrue(pub.isValidSignature(softSig, for: digest))
    }
}
