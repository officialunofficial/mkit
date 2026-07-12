// Protocol.swift — v1 external-signer wire framing for mkit-sign-se.
//
// The wire is length-prefixed protobuf 3 / edition 2023 `SignerFrame`
// messages over stdin/stdout, as defined in
// `rust/crates/mkit-rpc/proto/mkit/rpc/v1/signer/signer.proto` and documented in
// `docs/specs/SPEC-EXTERNAL-SIGNER.md`. Each frame is:
//
//     [u32 LE length][N bytes protobuf-encoded SignerFrame]
//
// Frames larger than `maxFrameBytes` (1 MiB, matching the Rust
// `MAX_FRAME_BYTES` constant in `rust/crates/mkit-rpc/src/framing.rs`)
// are rejected and the connection MUST be closed — receivers MUST NOT
// continue reading after a length-too-large.
//
// Pre-generated Swift sources live in `Generated/`; see README.md for
// the `protoc` command that regenerates them.

import Foundation
import SwiftProtobuf

// MARK: - Type aliases (drop the protoc-generated `Mkit_Rpc_V1_…` prefix)

typealias SignerFrame = Mkit_Rpc_V1_Signer_SignerFrame
typealias Hello = Mkit_Rpc_V1_Signer_Hello
typealias HelloResponse = Mkit_Rpc_V1_Signer_HelloResponse
typealias Capabilities = Mkit_Rpc_V1_Signer_Capabilities
typealias SignRequest = Mkit_Rpc_V1_Signer_SignRequest
typealias SignResponse = Mkit_Rpc_V1_Signer_SignResponse
typealias PinPrompt = Mkit_Rpc_V1_Signer_PinPrompt
typealias PinResponse = Mkit_Rpc_V1_Signer_PinResponse
typealias RpcError = Mkit_Rpc_V1_Error
typealias RpcAlgorithm = Mkit_Rpc_V1_Algorithm
typealias RpcKeyForm = Mkit_Rpc_V1_KeyForm
typealias RpcErrorCode = Mkit_Rpc_V1_ErrorCode
typealias RpcProtocolVersion = Mkit_Rpc_V1_ProtocolVersion

// MARK: - Framing

/// Cap mirrors `MAX_FRAME_BYTES` in `rust/crates/mkit-rpc/src/framing.rs`.
let maxFrameBytes: UInt32 = 1024 * 1024

/// Errors surfaced by the framing layer. Mirrors the variant set of
/// `mkit_rpc::FrameError` so the response logic in `Main.swift` can
/// map each one onto an `Error` frame with the right `ErrorCode`.
enum FrameError: Error, CustomStringConvertible {
    /// Stream ended mid length-prefix (1–3 bytes read). A clean EOF
    /// before any length-prefix byte is not an error — `readFrame`
    /// returns `nil` and `serve` exits successfully.
    case lengthPrefixTruncated
    /// Length prefix advertised > `maxFrameBytes`.
    case lengthTooLarge(UInt32)
    /// Stream ended before all `len` body bytes were read.
    case bodyTruncated(expected: UInt32, actual: Int)
    /// Protobuf decode failure.
    case decodeFailed(String)
    /// Underlying I/O error.
    case io(String)

    var description: String {
        switch self {
        case .lengthPrefixTruncated: return "length prefix truncated"
        case .lengthTooLarge(let n): return "frame length \(n) exceeds 1 MiB cap"
        case .bodyTruncated(let expected, let actual):
            return "frame body truncated: expected \(expected) bytes, got \(actual)"
        case .decodeFailed(let s): return "frame decode failed: \(s)"
        case .io(let s): return "io: \(s)"
        }
    }
}

/// Reader / writer protocol so the framing helpers can be exercised
/// against in-memory buffers in unit tests as well as the real
/// stdin/stdout pair. We intentionally avoid `FileHandle` here so the
/// tests don't need to touch the process's actual streams.
protocol FrameReader {
    /// Read exactly `count` bytes; return `nil` on EOF (no bytes
    /// available) and throw on partial read.
    func readExact(_ count: Int) throws -> Data?
}

protocol FrameWriter {
    func writeAll(_ data: Data) throws
    func flush() throws
}

// MARK: - FileHandle adapters

/// Stdin wrapped as a `FrameReader`. EOF is signalled by `availableData`
/// returning an empty `Data`; we accumulate until we either have
/// `count` bytes or we hit EOF with `actual == 0`.
struct FileHandleReader: FrameReader {
    let handle: FileHandle

    func readExact(_ count: Int) throws -> Data? {
        var out = Data()
        out.reserveCapacity(count)
        while out.count < count {
            let need = count - out.count
            // `read(upToCount:)` is the documented Foundation API for
            // a single read syscall; `availableData` works too but
            // returns `data` of arbitrary size including the empty
            // EOF marker.
            let chunk: Data?
            if #available(macOS 10.15.4, *) {
                chunk = try handle.read(upToCount: need)
            } else {
                let d = handle.availableData
                chunk = d.isEmpty ? nil : d
            }
            guard let c = chunk, !c.isEmpty else {
                if out.isEmpty {
                    // No bytes read at all → caller saw a clean EOF.
                    return nil
                }
                // Partial read followed by EOF → throw so caller can
                // surface a "truncated" diagnostic.
                throw FrameError.bodyTruncated(expected: UInt32(count), actual: out.count)
            }
            out.append(c)
        }
        return out
    }
}

struct FileHandleWriter: FrameWriter {
    let handle: FileHandle

    func writeAll(_ data: Data) throws {
        if #available(macOS 10.15.4, *) {
            try handle.write(contentsOf: data)
        } else {
            handle.write(data)
        }
    }

    func flush() throws {
        // FileHandle doesn't expose an explicit flush for pipes; the
        // OS pipe buffer is line/block-buffered by default and the
        // write syscalls above push bytes directly. This is a no-op
        // for symmetry with the Rust `write_frame`.
    }
}

// MARK: - read / write

/// Read a single `SignerFrame` from `reader`. Throws on any framing or
/// decode error; returns `nil` on clean EOF before any length byte is
/// read (caller closed the pipe between requests).
func readFrame(_ reader: FrameReader) throws -> SignerFrame? {
    // 4-byte u32 LE length prefix.
    let lenBytes: Data
    do {
        guard let read = try reader.readExact(4) else {
            return nil
        }
        lenBytes = read
    } catch FrameError.bodyTruncated(_, let actual) {
        // We started reading the length prefix but ran out before 4
        // bytes arrived. Distinct error variant for diagnostics.
        _ = actual
        throw FrameError.lengthPrefixTruncated
    }

    // The 4 bytes are little-endian per the spec. Build the u32 in
    // discrete steps — the single-expression form trips Swift's
    // type-checker timeout in release mode.
    let b0 = UInt32(lenBytes[lenBytes.startIndex])
    let b1 = UInt32(lenBytes[lenBytes.startIndex + 1])
    let b2 = UInt32(lenBytes[lenBytes.startIndex + 2])
    let b3 = UInt32(lenBytes[lenBytes.startIndex + 3])
    let len: UInt32 = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    if len > maxFrameBytes {
        throw FrameError.lengthTooLarge(len)
    }

    // Read exactly `len` body bytes. Zero-length frames are legal
    // (a `SignerFrame` with no oneof set encodes to 0 bytes) and
    // produce an "empty frame body" error downstream.
    let body: Data
    if len == 0 {
        body = Data()
    } else {
        do {
            guard let read = try reader.readExact(Int(len)) else {
                throw FrameError.bodyTruncated(expected: len, actual: 0)
            }
            body = read
        } catch FrameError.bodyTruncated(_, let actual) {
            throw FrameError.bodyTruncated(expected: len, actual: actual)
        }
    }

    do {
        return try SignerFrame(serializedBytes: body)
    } catch {
        throw FrameError.decodeFailed("\(error)")
    }
}

/// Write a single `SignerFrame` to `writer`, prefixed by its
/// little-endian u32 length. Refuses to emit a frame whose serialised
/// body exceeds `maxFrameBytes`.
func writeFrame(_ frame: SignerFrame, to writer: FrameWriter) throws {
    let body: Data
    do {
        body = try frame.serializedData()
    } catch {
        throw FrameError.io("serialize SignerFrame: \(error)")
    }
    guard body.count <= Int(maxFrameBytes) else {
        throw FrameError.lengthTooLarge(UInt32(clamping: body.count))
    }
    let len = UInt32(body.count)
    var prefix = Data(count: 4)
    prefix[0] = UInt8(len & 0xFF)
    prefix[1] = UInt8((len >> 8) & 0xFF)
    prefix[2] = UInt8((len >> 16) & 0xFF)
    prefix[3] = UInt8((len >> 24) & 0xFF)
    try writer.writeAll(prefix)
    try writer.writeAll(body)
    try writer.flush()
}

// MARK: - Frame builders

/// Build a `SignerFrame` containing a `HelloResponse` advertising this
/// signer's capabilities. P-256 only, OPAQUE_HANDLE only, requires
/// user presence when biometric gating is in effect (we conservatively
/// set it true regardless — the SE always involves the user implicitly
/// via the keychain unlock state, and the field is advisory).
func helloResponseFrame(signerVersion: String, requiresUserPresence: Bool) -> SignerFrame {
    var caps = Capabilities()
    caps.algorithms = [.p256]
    caps.keyForms = [.opaqueHandle]
    caps.supportsPin = false
    caps.supportsCertificateChain = false
    caps.maxPayloadBytes = 0  // 0 = use the framing default (1 MiB)
    caps.requiresUserPresence = requiresUserPresence

    var resp = HelloResponse()
    resp.`protocol` = .protocolVersion1
    resp.signerID = "mkit-sign-se/\(signerVersion)"
    resp.capabilities = caps

    var frame = SignerFrame()
    frame.body = .helloResponse(resp)
    return frame
}

/// Build a `SignerFrame` containing an `Error`.
func errorFrame(_ code: RpcErrorCode, _ message: String, details: Data = Data()) -> SignerFrame {
    var err = RpcError()
    err.code = code
    err.message = message
    err.details = details
    var frame = SignerFrame()
    frame.body = .error(err)
    return frame
}

/// Build a `SignerFrame` containing a `SignResponse`.
func signResponseFrame(
    signature: Data,
    publicKey: Data,
    keyID: String
) -> SignerFrame {
    var resp = SignResponse()
    resp.signature = signature
    resp.publicKey = publicKey
    resp.algorithm = .p256
    resp.keyID = keyID
    // certificate_chain stays empty; webauthn stays unset.

    var frame = SignerFrame()
    frame.body = .signResponse(resp)
    return frame
}

// MARK: - Signature / pubkey format helpers
//
// These are independent of the protobuf surface and used by both the
// runtime sign path and the unit tests. Kept here so `Protocol.swift`
// remains the one stop for "wire-format bits" — the SEP-specific code
// lives in `SecureEnclaveKey.swift`.

/// Convert an ASN.1 DER-encoded ECDSA signature to the 64-byte compact
/// form `r || s` big-endian.
///
/// Layout of the input (RFC 3279):
/// ```
/// SEQUENCE {
///   INTEGER r
///   INTEGER s
/// }
/// ```
///
/// Both integers may have a leading 0x00 padding byte when the high bit
/// of the magnitude would otherwise mark them as negative. The output
/// strips that, and left-pads each half with zeros to exactly 32 bytes.
///
/// The primary Secure Enclave path uses
/// `P256.Signing.ECDSASignature.rawRepresentation`, which is already
/// compact. This helper exists for the unit tests (where we feed a
/// known DER vector) and as a defensive fallback if a future CryptoKit
/// change ever returns DER.
func compactECDSASignatureFromDER(_ der: Data) throws -> Data {
    var idx = der.startIndex
    func take(_ n: Int) throws -> Data {
        guard idx + n <= der.endIndex else { throw SignerError.malformedDERSignature }
        let slice = der[idx..<(idx + n)]
        idx += n
        return Data(slice)
    }
    func takeByte() throws -> UInt8 {
        let b = try take(1)
        return b[b.startIndex]
    }
    // DER length can be short-form (< 128) or long-form (0x80 | n, then
    // n length bytes big-endian). ECDSA signatures we care about are
    // always well under 256 bytes so both forms stay within a single
    // length byte when short-form, or a one-byte-length long-form.
    func readLength() throws -> Int {
        let first = try takeByte()
        if first & 0x80 == 0 {
            return Int(first)
        }
        let n = Int(first & 0x7F)
        guard n == 1 else { throw SignerError.malformedDERSignature }
        return Int(try takeByte())
    }
    // SEQUENCE
    guard try takeByte() == 0x30 else { throw SignerError.malformedDERSignature }
    let seqLen = try readLength()
    guard idx + seqLen == der.endIndex else { throw SignerError.malformedDERSignature }

    func readInteger() throws -> Data {
        guard try takeByte() == 0x02 else { throw SignerError.malformedDERSignature }
        let n = try readLength()
        var bytes = try take(n)
        // Strip a single leading 0x00 that is present purely to keep
        // the DER INTEGER non-negative. Keep true zeros as-is.
        if bytes.count > 1 && bytes.first == 0 {
            bytes = bytes.dropFirst()
        }
        // Left-pad to 32.
        guard bytes.count <= 32 else { throw SignerError.malformedDERSignature }
        if bytes.count < 32 {
            var padded = Data(repeating: 0, count: 32 - bytes.count)
            padded.append(contentsOf: bytes)
            return padded
        }
        return bytes
    }
    let r = try readInteger()
    let s = try readInteger()
    var out = Data(capacity: 64)
    out.append(r)
    out.append(s)
    return out
}

/// Convert a 64-byte SEC1 uncompressed P-256 public key (x || y, no
/// 0x04 prefix — as CryptoKit's `publicKey.rawRepresentation` returns)
/// to the 33-byte compressed form (`0x02 || x` if y-even, `0x03 || x`
/// if y-odd).
///
/// Input MUST be exactly 64 bytes. Throws otherwise.
func compressSEC1FromRaw(_ raw: Data) throws -> Data {
    guard raw.count == 64 else { throw SignerError.malformedPublicKey }
    let x = raw.prefix(32)
    let y = raw.suffix(32)
    let lastY = y[y.index(before: y.endIndex)]
    let prefix: UInt8 = (lastY & 0x01) == 0 ? 0x02 : 0x03
    var out = Data(capacity: 33)
    out.append(prefix)
    out.append(contentsOf: x)
    return out
}

/// Lowercase hex encoding.
func hexLower(_ data: Data) -> String {
    let table: [UInt8] = Array("0123456789abcdef".utf8)
    var out = [UInt8]()
    out.reserveCapacity(data.count * 2)
    for b in data {
        out.append(table[Int(b >> 4)])
        out.append(table[Int(b & 0x0F)])
    }
    return String(decoding: out, as: UTF8.self)
}
