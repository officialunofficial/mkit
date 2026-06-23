// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Signed-write envelope (DEMO MODE — open write, verify-only, no allow-list).
//
// A faithful Rust port of reference-ts/lib/envelope.ts. The wire protocol is
// ConnectRPC; the envelope rides in request metadata (headers), so one guard
// covers every procedure uniformly. The client signs a canonical request
// string; the server recomputes it, BLAKE3-hashes it, and STRICT-verifies the
// Ed25519 signature. A valid signature proves request integrity + same-author,
// but grants NO authority — any valid key may write any ref.
//
// THE CANONICAL STRING (client and server build it byte-for-byte):
//
//   [ "mkit-write:v1",
//     procedure,        // "/mkit.repo.v1.RepoService/UpdateRef"
//     bodyDigest,       // lowercase-hex BLAKE3 of the RAW request body bytes
//     createdAt,        // decimal epoch-ms as a string
//     idempotencyKey ]  // the Idempotency-Key value, or "" if absent
//   .join("\n")
//
// signing_digest = BLAKE3(utf8(canonical))   (the signed message, 32 bytes)
// valid          = ed25519_verify_strict(pubkey, signing_digest, signature)
//
// This is a PLAIN envelope digest — NOT an mkit commit signature — so the
// SPEC-SIGNING commit/remix/tag domain prefixes do NOT apply. We strict-verify
// with the same `ed25519_dalek::VerifyingKey::verify_strict` mkit-core uses
// (RFC 8032 / ZIP-215-off): non-canonical R, high-s, and non-canonical pubkey
// encodings are rejected.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::hashing::blake3;

/// Constant first line of the canonical string.
pub const ENVELOPE_PREFIX: &str = "mkit-write:v1";

/// Freshness window: ±5 minutes, in milliseconds.
pub const FRESHNESS_WINDOW_MS: i64 = 5 * 60_000;

/// Build the canonical string. Order and field set are part of the contract.
/// `body_digest` is the lowercase-hex BLAKE3 of the raw request body.
#[must_use]
pub fn canonical_envelope(
    procedure: &str,
    body_digest: &str,
    created_at: i64,
    idempotency_key: &str,
) -> String {
    format!("{ENVELOPE_PREFIX}\n{procedure}\n{body_digest}\n{created_at}\n{idempotency_key}")
}

/// BLAKE3 digest (32 raw bytes) of the canonical string — the signed message.
#[must_use]
pub fn envelope_signing_digest(
    procedure: &str,
    body_digest: &str,
    created_at: i64,
    idempotency_key: &str,
) -> [u8; 32] {
    blake3(canonical_envelope(procedure, body_digest, created_at, idempotency_key).as_bytes())
}

/// The headers carrying the write envelope. Hex headers should already be
/// normalized (0x-stripped, lowercased) by the caller.
#[derive(Debug, Default, Clone)]
pub struct EnvelopeHeaders {
    pub public_key: Option<String>,    // X-Public-Key (64-hex)
    pub signature: Option<String>,     // X-Signature (128-hex)
    pub digest: Option<String>,        // X-Digest (client-claimed raw-body digest, 64-hex)
    pub created_at: Option<String>,    // X-Created-At (decimal epoch-ms)
    pub idempotency_key: Option<String>, // Idempotency-Key
}

/// Verification outcome. The status mirrors the TS contract: 400 = malformed
/// request, 401 = auth failure / staleness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyEnvelope {
    Ok {
        public_key: String,
        body_digest: String,
        idempotency_key: String,
    },
    Err { status: u16, error: &'static str },
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Verify a write envelope. Pure given `now` (epoch-ms) and the
/// server-computed `actual_body_digest` (lowercase-hex BLAKE3 of the raw
/// request body). Mirrors `verifyEnvelope` in reference-ts/lib/envelope.ts.
#[must_use]
pub fn verify_envelope(
    procedure: &str,
    actual_body_digest: &str,
    now: i64,
    headers: &EnvelopeHeaders,
) -> VerifyEnvelope {
    let (Some(public_key), Some(signature), Some(digest), Some(created_at)) = (
        headers.public_key.as_deref(),
        headers.signature.as_deref(),
        headers.digest.as_deref(),
        headers.created_at.as_deref(),
    ) else {
        return VerifyEnvelope::Err { status: 401, error: "missing signature headers" };
    };

    if !is_hex(public_key, 64) || !is_hex(digest, 64) || !is_hex(signature, 128) {
        return VerifyEnvelope::Err { status: 400, error: "malformed signature headers" };
    }

    if digest != actual_body_digest {
        return VerifyEnvelope::Err { status: 400, error: "body digest mismatch" };
    }

    let Ok(created_at_ms) = created_at.parse::<i64>() else {
        return VerifyEnvelope::Err { status: 401, error: "stale or future signature" };
    };
    if (now - created_at_ms).abs() > FRESHNESS_WINDOW_MS {
        return VerifyEnvelope::Err { status: 401, error: "stale or future signature" };
    }

    let idempotency_key = headers.idempotency_key.clone().unwrap_or_default();
    let signing_digest =
        envelope_signing_digest(procedure, digest, created_at_ms, &idempotency_key);

    if !ed25519_verify_strict(public_key, signature, &signing_digest) {
        return VerifyEnvelope::Err { status: 401, error: "invalid signature" };
    }

    VerifyEnvelope::Ok {
        public_key: public_key.to_owned(),
        body_digest: digest.to_owned(),
        idempotency_key,
    }
}

/// Strict Ed25519 verify of `signature_hex` (128-hex) over `message` (the
/// 32-byte signing digest) under `public_key_hex` (64-hex). Returns false
/// (never panics) on any malformed input. ZIP-215-off / RFC-8032 strict —
/// the same line mkit-core::sign::verify holds.
#[must_use]
pub fn ed25519_verify_strict(public_key_hex: &str, signature_hex: &str, message: &[u8]) -> bool {
    let Ok(pk_bytes) = hex_to_32(public_key_hex) else { return false };
    let Ok(sig_bytes) = hex_to_64(signature_hex) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else { return false };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify_strict(message, &sig).is_ok()
}

fn hex_to_32(s: &str) -> Result<[u8; 32], ()> {
    if !is_hex(s, 64) {
        return Err(());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| ())?;
    Ok(out)
}

fn hex_to_64(s: &str) -> Result<[u8; 64], ()> {
    if !is_hex(s, 128) {
        return Err(());
    }
    let mut out = [0u8; 64];
    hex::decode_to_slice(s, &mut out).map_err(|_| ())?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Deterministic test signer matching reference-ts/test/envelope.test.ts:
    // SEED = 32 bytes of 0x07.
    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn pubkey_hex(sk: &SigningKey) -> String {
        hex::encode(sk.verifying_key().to_bytes())
    }

    const NOW: i64 = 1_700_000_000_000;
    const PROCEDURE: &str = "/mkit.repo.v1.RepoService/UpdateRef";

    fn body_digest() -> String {
        crate::hashing::blake3_hex(b"serialized-protobuf-request")
    }

    // Sign the canonical envelope: signature over BLAKE3(canonical).
    fn sign(sk: &SigningKey, procedure: &str, bd: &str, created: i64, idem: &str) -> String {
        let digest = envelope_signing_digest(procedure, bd, created, idem);
        hex::encode(sk.sign(&digest).to_bytes())
    }

    fn headers_for(
        sk: &SigningKey,
        procedure: &str,
        bd: &str,
        created: i64,
        idem: &str,
    ) -> EnvelopeHeaders {
        EnvelopeHeaders {
            public_key: Some(pubkey_hex(sk)),
            signature: Some(sign(sk, procedure, bd, created, idem)),
            digest: Some(bd.to_owned()),
            created_at: Some(created.to_string()),
            idempotency_key: if idem.is_empty() { None } else { Some(idem.to_owned()) },
        }
    }

    #[test]
    fn canonical_is_five_fields() {
        let s = canonical_envelope(PROCEDURE, &body_digest(), NOW, "abc-123");
        let lines: Vec<&str> = s.split('\n').collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], ENVELOPE_PREFIX);
        assert_eq!(lines[1], PROCEDURE);
        assert_eq!(lines[2], body_digest());
        assert_eq!(lines[3], NOW.to_string());
        assert_eq!(lines[4], "abc-123");
    }

    #[test]
    fn absent_idempotency_is_empty_field() {
        let s = canonical_envelope(PROCEDURE, &body_digest(), NOW, "");
        assert_eq!(s.split('\n').nth(4), Some(""));
    }

    #[test]
    fn no_field_collisions() {
        let a = envelope_signing_digest(PROCEDURE, &body_digest(), NOW, "abc-123");
        assert_ne!(
            a,
            envelope_signing_digest("/mkit.repo.v1.RepoService/PutObject", &body_digest(), NOW, "abc-123")
        );
        assert_ne!(
            a,
            envelope_signing_digest(PROCEDURE, &crate::hashing::blake3_hex(b"x"), NOW, "abc-123")
        );
        assert_ne!(a, envelope_signing_digest(PROCEDURE, &body_digest(), NOW + 1, "abc-123"));
        assert_ne!(a, envelope_signing_digest(PROCEDURE, &body_digest(), NOW, "different"));
    }

    #[test]
    fn accepts_fresh_signed_envelope() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        match verify_envelope(PROCEDURE, &bd, NOW, &h) {
            VerifyEnvelope::Ok { public_key, body_digest, idempotency_key } => {
                assert_eq!(public_key, pubkey_hex(&sk));
                assert_eq!(body_digest, bd);
                assert_eq!(idempotency_key, "abc-123");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn rejects_tampered_body() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        let actual = crate::hashing::blake3_hex(b"tampered");
        assert_eq!(
            verify_envelope(PROCEDURE, &actual, NOW, &h),
            VerifyEnvelope::Err { status: 400, error: "body digest mismatch" }
        );
    }

    #[test]
    fn rejects_different_procedure() {
        let sk = signer();
        let bd = body_digest();
        // signed for UpdateRef, server sees PutObject
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        assert_eq!(
            verify_envelope("/mkit.repo.v1.RepoService/PutObject", &bd, NOW, &h),
            VerifyEnvelope::Err { status: 401, error: "invalid signature" }
        );
    }

    #[test]
    fn freshness_window() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        // stale (> 5 min old)
        assert_eq!(
            verify_envelope(PROCEDURE, &bd, NOW + FRESHNESS_WINDOW_MS + 1, &h),
            VerifyEnvelope::Err { status: 401, error: "stale or future signature" }
        );
        // future (> 5 min ahead)
        assert_eq!(
            verify_envelope(PROCEDURE, &bd, NOW - FRESHNESS_WINDOW_MS - 1, &h),
            VerifyEnvelope::Err { status: 401, error: "stale or future signature" }
        );
        // exactly at boundary -> accepted
        assert!(matches!(
            verify_envelope(PROCEDURE, &bd, NOW + FRESHNESS_WINDOW_MS, &h),
            VerifyEnvelope::Ok { .. }
        ));
    }

    #[test]
    fn rejects_missing_headers() {
        let sk = signer();
        let bd = body_digest();
        let mut h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        h.signature = None;
        assert_eq!(
            verify_envelope(PROCEDURE, &bd, NOW, &h),
            VerifyEnvelope::Err { status: 401, error: "missing signature headers" }
        );
    }

    #[test]
    fn rejects_malformed_hex() {
        let sk = signer();
        let bd = body_digest();
        let mut h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        h.public_key = Some("nothex".to_owned());
        assert_eq!(
            verify_envelope(PROCEDURE, &bd, NOW, &h),
            VerifyEnvelope::Err { status: 400, error: "malformed signature headers" }
        );
    }

    #[test]
    fn open_write_wrong_key_for_sig_rejected() {
        let sk = signer();
        let bd = body_digest();
        let mut h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        // swap pubkey to a different valid key without re-signing
        let other = SigningKey::from_bytes(&[9u8; 32]);
        h.public_key = Some(pubkey_hex(&other));
        assert_eq!(
            verify_envelope(PROCEDURE, &bd, NOW, &h),
            VerifyEnvelope::Err { status: 401, error: "invalid signature" }
        );
    }

    #[test]
    fn open_write_any_valid_key_accepted() {
        // A DIFFERENT valid key signing its own envelope is accepted (demo mode).
        let sk2 = SigningKey::from_bytes(&[3u8; 32]);
        let bd = body_digest();
        let h = headers_for(&sk2, PROCEDURE, &bd, NOW, "abc-123");
        assert!(matches!(
            verify_envelope(PROCEDURE, &bd, NOW, &h),
            VerifyEnvelope::Ok { .. }
        ));
    }
}
