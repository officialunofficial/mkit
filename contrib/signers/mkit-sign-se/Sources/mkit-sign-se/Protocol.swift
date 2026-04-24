// Protocol.swift — JSON request/response shapes for the mkit external
// signer v1 wire protocol. See docs/SPEC-EXTERNAL-SIGNER.md §3, §4.
//
// The request is one line of UTF-8 JSON on stdin; the response is one
// line of UTF-8 JSON on stdout. We intentionally keep these types
// separate from any Secure Enclave specifics so the same shapes can be
// reused by the Swift unit tests without importing CryptoKit.

import Foundation

/// Request shape — exactly the fields mkit writes to stdin.
///
/// Per SPEC-EXTERNAL-SIGNER §9, unknown top-level fields MUST be
/// tolerated for forward compatibility; `Codable` drops them silently
/// when `JSONDecoder.allowsJSON5 == false`, which is the default.
struct SignRequest: Codable, Equatable {
    /// RFC 4648 §4 standard base64 (padded) of the DSSE PAE bytes.
    let paeBase64: String
    /// `"p256"`, `"ed25519"`, or `"secp256k1"`. This signer only
    /// supports `p256`; anything else is rejected at signing time.
    let algorithm: String

    enum CodingKeys: String, CodingKey {
        case paeBase64 = "pae_base64"
        case algorithm
    }
}

/// Response shape — what we write to stdout on success.
struct SignResponse: Codable, Equatable {
    /// `p256:<66-hex-chars>` — 33-byte SEC1-compressed pubkey in
    /// lowercase hex, with the `p256:` prefix.
    let keyid: String
    /// Base64 of the 64-byte compact `r || s` big-endian signature.
    let sigBase64: String

    enum CodingKeys: String, CodingKey {
        case keyid
        case sigBase64 = "sig_base64"
    }
}

/// Encode a `SignResponse` as a single line of compact JSON (no
/// trailing newline — the caller adds one). Keys are emitted in
/// declaration order, which matches every example in the spec.
func encodeResponseLine(_ r: SignResponse) throws -> String {
    // Hand-assemble to guarantee field order and avoid the
    // `JSONEncoder` `.sortedKeys` option re-ordering to alphabetical
    // (`keyid` before `sig_base64` happens to be alphabetical anyway,
    // but we want the shape invariant regardless of sort order).
    let escapedKeyid = escapeJSONString(r.keyid)
    let escapedSig = escapeJSONString(r.sigBase64)
    return "{\"keyid\":\(escapedKeyid),\"sig_base64\":\(escapedSig)}"
}

/// Parse a single line of JSON as a `SignRequest`. Whitespace and a
/// single trailing `\n` or `\r\n` are tolerated because mkit writes
/// `request + '\n'` before closing stdin.
func decodeRequest(_ bytes: Data) throws -> SignRequest {
    let trimmed = trimTrailingNewlines(bytes)
    let decoder = JSONDecoder()
    return try decoder.decode(SignRequest.self, from: trimmed)
}

private func trimTrailingNewlines(_ bytes: Data) -> Data {
    var end = bytes.count
    while end > 0 {
        let b = bytes[bytes.index(bytes.startIndex, offsetBy: end - 1)]
        if b == 0x0A || b == 0x0D {
            end -= 1
        } else {
            break
        }
    }
    return bytes.prefix(end)
}

/// Minimal JSON string escaping — we use this instead of
/// `JSONEncoder` for the response so field order is deterministic
/// regardless of `JSONEncoder` option changes.
private func escapeJSONString(_ s: String) -> String {
    var out = "\""
    for scalar in s.unicodeScalars {
        switch scalar {
        case "\"": out.append("\\\"")
        case "\\": out.append("\\\\")
        case "\n": out.append("\\n")
        case "\r": out.append("\\r")
        case "\t": out.append("\\t")
        default:
            if scalar.value < 0x20 {
                out.append(String(format: "\\u%04x", scalar.value))
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    out.append("\"")
    return out
}

// MARK: - Signature / pubkey format helpers

/// Convert an ASN.1 DER-encoded ECDSA signature to the 64-byte compact
/// form `r || s` big-endian required by SPEC-EXTERNAL-SIGNER §4.2.
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
/// Note: the primary Secure Enclave path uses
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
/// if y-odd) required for the `p256:` keyid.
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

/// Lowercase hex encoding. No dependency on Foundation's
/// `String(format:)` for hot paths; the Swift stdlib lacks a built-in.
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
