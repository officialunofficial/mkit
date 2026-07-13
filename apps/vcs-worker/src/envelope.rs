// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Signed-write envelope (DEMO MODE — open write, verify-only, no allow-list),
// ported from apps/repo-worker/src/envelope.rs. Two shapes:
//
// 1. UNARY envelope (UpdateRef, AdvanceRefs) — binds the signature to the
//    exact serialized request body, byte-for-byte, exactly as repo-worker's
//    envelope does:
//
//      canonical = [ "mkit-write:v1", procedure, bodyDigest, createdAt,
//                    idempotencyKey ].join("\n")
//      signing_digest = BLAKE3(utf8(canonical))
//      valid = ed25519_verify_strict(pubkey, signing_digest, signature)
//
// 2. STREAMING envelope (UploadPack) — a client-streaming call's
//    `Interceptor::intercept_streaming` runs ONCE at stream establishment,
//    before any message (header or chunk) has arrived, so there is no single
//    "request body" to BLAKE3 yet — the pack bytes arrive incrementally over
//    the rest of the call. The streaming envelope therefore binds ONLY to
//    (procedure, createdAt, idempotencyKey) — it proves "a holder of this key
//    authorized an UploadPack call at this time," not "…over these specific
//    bytes." Content integrity for the uploaded pack is independently and
//    unconditionally enforced inside the handler itself (SPEC-TRANSPORT-CONNECT
//    §6.1: the server MUST verify BLAKE3(received bytes) == header.pack_id
//    regardless of auth), so the missing body-binding is not a content-
//    integrity gap — it is a narrower authentication claim than the unary
//    envelope makes, documented so it is never mistaken for the stronger one.
//
//      stream_canonical = [ "mkit-stream-write:v1", procedure, createdAt,
//                            idempotencyKey ].join("\n")
//      signing_digest = BLAKE3(utf8(stream_canonical))
//      valid = ed25519_verify_strict(pubkey, signing_digest, signature)
//
// Both are PLAIN envelope digests — NOT mkit commit signatures — so the
// SPEC-SIGNING commit/remix/tag domain prefixes do NOT apply. Verification
// uses `ed25519_dalek::VerifyingKey::verify_strict` (RFC 8032 / ZIP-215-off),
// the same strict line mkit-core::sign holds.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::hashing::blake3;

/// Constant first line of the unary canonical string.
pub const ENVELOPE_PREFIX: &str = "mkit-write:v1";
/// Constant first line of the streaming (establishment-only) canonical string.
pub const STREAM_ENVELOPE_PREFIX: &str = "mkit-stream-write:v1";

/// Freshness window: ±5 minutes, in milliseconds.
pub const FRESHNESS_WINDOW_MS: i64 = 5 * 60_000;

/// Build the unary canonical string. Order and field set are part of the
/// contract. `body_digest` is the lowercase-hex BLAKE3 of the raw request
/// body.
#[must_use]
pub fn canonical_envelope(
    procedure: &str,
    body_digest: &str,
    created_at: i64,
    idempotency_key: &str,
) -> String {
    format!("{ENVELOPE_PREFIX}\n{procedure}\n{body_digest}\n{created_at}\n{idempotency_key}")
}

/// BLAKE3 digest (32 raw bytes) of the unary canonical string — the signed
/// message.
#[must_use]
pub fn envelope_signing_digest(
    procedure: &str,
    body_digest: &str,
    created_at: i64,
    idempotency_key: &str,
) -> [u8; 32] {
    blake3(canonical_envelope(procedure, body_digest, created_at, idempotency_key).as_bytes())
}

/// Build the streaming canonical string (no body digest — see module docs).
#[must_use]
pub fn canonical_stream_envelope(
    procedure: &str,
    created_at: i64,
    idempotency_key: &str,
) -> String {
    format!("{STREAM_ENVELOPE_PREFIX}\n{procedure}\n{created_at}\n{idempotency_key}")
}

/// BLAKE3 digest (32 raw bytes) of the streaming canonical string.
#[must_use]
pub fn stream_envelope_signing_digest(
    procedure: &str,
    created_at: i64,
    idempotency_key: &str,
) -> [u8; 32] {
    blake3(canonical_stream_envelope(procedure, created_at, idempotency_key).as_bytes())
}

/// The headers carrying a unary write envelope. Hex headers should already be
/// normalized (0x-stripped, lowercased) by the caller.
#[derive(Debug, Default, Clone)]
pub struct EnvelopeHeaders {
    pub public_key: Option<String>,      // X-Public-Key (64-hex)
    pub signature: Option<String>,       // X-Signature (128-hex)
    pub digest: Option<String>,          // X-Digest (client-claimed raw-body digest, 64-hex)
    pub created_at: Option<String>,      // X-Created-At (decimal epoch-ms)
    pub idempotency_key: Option<String>, // Idempotency-Key
}

/// The headers carrying a streaming write envelope — same as
/// [`EnvelopeHeaders`] minus `digest` (no body to bind at establishment).
#[derive(Debug, Default, Clone)]
pub struct StreamEnvelopeHeaders {
    pub public_key: Option<String>,
    pub signature: Option<String>,
    pub created_at: Option<String>,
    pub idempotency_key: Option<String>,
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
    Err {
        status: u16,
        error: &'static str,
    },
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Verify a unary write envelope. Pure given `now` (epoch-ms) and the
/// server-computed `actual_body_digest` (lowercase-hex BLAKE3 of the raw
/// request body).
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
        return VerifyEnvelope::Err {
            status: 401,
            error: "missing signature headers",
        };
    };

    if !is_hex(public_key, 64) || !is_hex(digest, 64) || !is_hex(signature, 128) {
        return VerifyEnvelope::Err {
            status: 400,
            error: "malformed signature headers",
        };
    }

    if digest != actual_body_digest {
        return VerifyEnvelope::Err {
            status: 400,
            error: "body digest mismatch",
        };
    }

    let Ok(created_at_ms) = created_at.parse::<i64>() else {
        return VerifyEnvelope::Err {
            status: 401,
            error: "stale or future signature",
        };
    };
    if (now - created_at_ms).abs() > FRESHNESS_WINDOW_MS {
        return VerifyEnvelope::Err {
            status: 401,
            error: "stale or future signature",
        };
    }

    let idempotency_key = headers.idempotency_key.clone().unwrap_or_default();
    let signing_digest =
        envelope_signing_digest(procedure, digest, created_at_ms, &idempotency_key);

    if !ed25519_verify_strict(public_key, signature, &signing_digest) {
        return VerifyEnvelope::Err {
            status: 401,
            error: "invalid signature",
        };
    }

    VerifyEnvelope::Ok {
        public_key: public_key.to_owned(),
        body_digest: digest.to_owned(),
        idempotency_key,
    }
}

/// Verify a streaming (establishment-only) write envelope. See module docs
/// for what this claim does and does not prove.
#[must_use]
pub fn verify_stream_envelope(
    procedure: &str,
    now: i64,
    headers: &StreamEnvelopeHeaders,
) -> VerifyEnvelope {
    let (Some(public_key), Some(signature), Some(created_at)) = (
        headers.public_key.as_deref(),
        headers.signature.as_deref(),
        headers.created_at.as_deref(),
    ) else {
        return VerifyEnvelope::Err {
            status: 401,
            error: "missing signature headers",
        };
    };

    if !is_hex(public_key, 64) || !is_hex(signature, 128) {
        return VerifyEnvelope::Err {
            status: 400,
            error: "malformed signature headers",
        };
    }

    let Ok(created_at_ms) = created_at.parse::<i64>() else {
        return VerifyEnvelope::Err {
            status: 401,
            error: "stale or future signature",
        };
    };
    if (now - created_at_ms).abs() > FRESHNESS_WINDOW_MS {
        return VerifyEnvelope::Err {
            status: 401,
            error: "stale or future signature",
        };
    }

    let idempotency_key = headers.idempotency_key.clone().unwrap_or_default();
    let signing_digest = stream_envelope_signing_digest(procedure, created_at_ms, &idempotency_key);

    if !ed25519_verify_strict(public_key, signature, &signing_digest) {
        return VerifyEnvelope::Err {
            status: 401,
            error: "invalid signature",
        };
    }

    VerifyEnvelope::Ok {
        public_key: public_key.to_owned(),
        body_digest: String::new(),
        idempotency_key,
    }
}

/// Strict Ed25519 verify of `signature_hex` (128-hex) over `message` (the
/// 32-byte signing digest) under `public_key_hex` (64-hex). Returns false
/// (never panics) on any malformed input. ZIP-215-off / RFC-8032 strict —
/// the same line mkit-core::sign::verify holds.
#[must_use]
pub fn ed25519_verify_strict(public_key_hex: &str, signature_hex: &str, message: &[u8]) -> bool {
    let Ok(pk_bytes) = hex_to_32(public_key_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex_to_64(signature_hex) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
        return false;
    };
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

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn pubkey_hex(sk: &SigningKey) -> String {
        hex::encode(sk.verifying_key().to_bytes())
    }

    const NOW: i64 = 1_700_000_000_000;
    const PROCEDURE: &str = "/mkit.transport.v1.TransportService/UpdateRef";
    const STREAM_PROCEDURE: &str = "/mkit.transport.v1.TransportService/UploadPack";

    fn body_digest() -> String {
        crate::hashing::blake3_hex(b"serialized-protobuf-request")
    }

    fn sign(sk: &SigningKey, procedure: &str, bd: &str, created: i64, idem: &str) -> String {
        let digest = envelope_signing_digest(procedure, bd, created, idem);
        hex::encode(sk.sign(&digest).to_bytes())
    }

    fn stream_sign(sk: &SigningKey, procedure: &str, created: i64, idem: &str) -> String {
        let digest = stream_envelope_signing_digest(procedure, created, idem);
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
            idempotency_key: if idem.is_empty() {
                None
            } else {
                Some(idem.to_owned())
            },
        }
    }

    #[test]
    fn accepts_fresh_signed_envelope() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        match verify_envelope(PROCEDURE, &bd, NOW, &h) {
            VerifyEnvelope::Ok {
                public_key,
                body_digest,
                idempotency_key,
            } => {
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
            VerifyEnvelope::Err {
                status: 400,
                error: "body digest mismatch"
            }
        );
    }

    #[test]
    fn rejects_different_procedure() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        assert_eq!(
            verify_envelope(
                "/mkit.transport.v1.TransportService/AdvanceRefs",
                &bd,
                NOW,
                &h
            ),
            VerifyEnvelope::Err {
                status: 401,
                error: "invalid signature"
            }
        );
    }

    #[test]
    fn freshness_window() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        assert_eq!(
            verify_envelope(PROCEDURE, &bd, NOW + FRESHNESS_WINDOW_MS + 1, &h),
            VerifyEnvelope::Err {
                status: 401,
                error: "stale or future signature"
            }
        );
        assert_eq!(
            verify_envelope(PROCEDURE, &bd, NOW - FRESHNESS_WINDOW_MS - 1, &h),
            VerifyEnvelope::Err {
                status: 401,
                error: "stale or future signature"
            }
        );
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
            VerifyEnvelope::Err {
                status: 401,
                error: "missing signature headers"
            }
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
            VerifyEnvelope::Err {
                status: 400,
                error: "malformed signature headers"
            }
        );
    }

    #[test]
    fn open_write_any_valid_key_accepted() {
        let sk2 = SigningKey::from_bytes(&[3u8; 32]);
        let bd = body_digest();
        let h = headers_for(&sk2, PROCEDURE, &bd, NOW, "abc-123");
        assert!(matches!(
            verify_envelope(PROCEDURE, &bd, NOW, &h),
            VerifyEnvelope::Ok { .. }
        ));
    }

    // --- streaming envelope --------------------------------------------

    #[test]
    fn stream_accepts_fresh_signed_envelope() {
        let sk = signer();
        let h = StreamEnvelopeHeaders {
            public_key: Some(pubkey_hex(&sk)),
            signature: Some(stream_sign(&sk, STREAM_PROCEDURE, NOW, "up-1")),
            created_at: Some(NOW.to_string()),
            idempotency_key: Some("up-1".to_owned()),
        };
        assert!(matches!(
            verify_stream_envelope(STREAM_PROCEDURE, NOW, &h),
            VerifyEnvelope::Ok { .. }
        ));
    }

    #[test]
    fn stream_rejects_wrong_procedure() {
        let sk = signer();
        let h = StreamEnvelopeHeaders {
            public_key: Some(pubkey_hex(&sk)),
            signature: Some(stream_sign(&sk, STREAM_PROCEDURE, NOW, "up-1")),
            created_at: Some(NOW.to_string()),
            idempotency_key: Some("up-1".to_owned()),
        };
        assert_eq!(
            verify_stream_envelope("/mkit.transport.v1.TransportService/AdvanceRefs", NOW, &h),
            VerifyEnvelope::Err {
                status: 401,
                error: "invalid signature"
            }
        );
    }

    #[test]
    fn stream_and_unary_digests_never_collide() {
        // Same procedure/created_at/idem: the two envelope kinds must never
        // produce the same signing digest (distinct prefixes + field counts).
        let bd = body_digest();
        let unary = envelope_signing_digest(PROCEDURE, &bd, NOW, "k");
        let stream = stream_envelope_signing_digest(PROCEDURE, NOW, "k");
        assert_ne!(unary, stream);
    }
}
