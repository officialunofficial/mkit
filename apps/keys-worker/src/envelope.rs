// Signed-write envelope verification — a self-contained copy of the scheme in
// apps/repo-worker/src/envelope.rs, so keys-worker accepts the SAME envelope the
// web app already builds in apps/web/src/lib/repo/envelope.ts.
//
// Canonical string (newline-joined), BLAKE3-of-canonical is the signed message:
//
//   mkit-write:v1
//   <procedure>
//   <body_digest>          // lowercase-hex BLAKE3 of the raw request body
//   <created_at>           // decimal epoch-millis
//   <idempotency_key>
//
// The signature is raw Ed25519 over BLAKE3(canonical), verify_strict'd against
// X-Public-Key. Reads are open; only writes carry an envelope.

use ed25519_dalek::{Signature, VerifyingKey};

/// Literal first line of the canonical string.
pub const ENVELOPE_PREFIX: &str = "mkit-write:v1";

/// Accept signatures within ±5 minutes of now (replay/skew window).
pub const FRESHNESS_WINDOW_MS: i64 = 5 * 60_000;

/// Lowercase-hex BLAKE3 of `bytes` — matches the web client's `api.blake3_hex`.
pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Reconstruct the canonical string the client signed.
pub fn canonical_envelope(
    procedure: &str,
    body_digest: &str,
    created_at: i64,
    idempotency_key: &str,
) -> String {
    format!("{ENVELOPE_PREFIX}\n{procedure}\n{body_digest}\n{created_at}\n{idempotency_key}")
}

/// BLAKE3(canonical) — the 32 bytes that are Ed25519-signed.
pub fn envelope_signing_digest(
    procedure: &str,
    body_digest: &str,
    created_at: i64,
    idempotency_key: &str,
) -> [u8; 32] {
    *blake3::hash(
        canonical_envelope(procedure, body_digest, created_at, idempotency_key).as_bytes(),
    )
    .as_bytes()
}

/// The signed-write headers carried on a write request.
#[derive(Default)]
pub struct EnvelopeHeaders {
    pub public_key: Option<String>,      // X-Public-Key   (64-hex)
    pub signature: Option<String>,       // X-Signature    (128-hex)
    pub digest: Option<String>,          // X-Digest       (client-claimed body digest, 64-hex)
    pub created_at: Option<String>,      // X-Created-At   (decimal epoch-ms)
    pub idempotency_key: Option<String>, // Idempotency-Key
}

/// Outcome of `verify_envelope`. On `Ok`, `public_key` is the verified signer.
pub enum VerifyEnvelope {
    Ok { public_key: String },
    Err { status: u16, error: &'static str },
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Verify a signed-write envelope. `actual_body_digest` is the server-computed
/// BLAKE3 of the raw body; `now` is epoch-millis. Mirrors repo-worker's checks:
/// header presence, hex shape, body-digest match, freshness window, strict sig.
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

    // The client-claimed body digest must match what we hashed off the wire.
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

    let idempotency_key = headers.idempotency_key.as_deref().unwrap_or_default();
    let signing_digest = envelope_signing_digest(procedure, digest, created_at_ms, idempotency_key);

    if !ed25519_verify_strict(public_key, signature, &signing_digest) {
        return VerifyEnvelope::Err {
            status: 401,
            error: "invalid signature",
        };
    }

    VerifyEnvelope::Ok {
        public_key: public_key.to_owned(),
    }
}

/// Strict Ed25519 verify (`verify_strict`) — the exact check mkit-core uses.
pub fn ed25519_verify_strict(public_key_hex: &str, signature_hex: &str, message: &[u8]) -> bool {
    let Ok(pk) = hex::decode(public_key_hex) else {
        return false;
    };
    let Ok(sig) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else {
        return false;
    };
    let Ok(sig): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify_strict(message, &Signature::from_bytes(&sig))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Deterministic test signer matching apps/repo-worker/src/envelope.rs's
    // test module (and reference-ts/test/envelope.test.ts): SEED = 32 bytes
    // of 0x07.
    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn pubkey_hex(sk: &SigningKey) -> String {
        hex::encode(sk.verifying_key().to_bytes())
    }

    const NOW: i64 = 1_700_000_000_000;
    const PROCEDURE: &str = "/mkit.keys.v1.Keys/SetName";

    fn body_digest() -> String {
        blake3_hex(b"serialized-name-body")
    }

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
            idempotency_key: if idem.is_empty() {
                None
            } else {
                Some(idem.to_owned())
            },
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
    fn accepts_fresh_signed_envelope() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        match verify_envelope(PROCEDURE, &bd, NOW, &h) {
            VerifyEnvelope::Ok { public_key } => assert_eq!(public_key, pubkey_hex(&sk)),
            VerifyEnvelope::Err { status, error } => {
                panic!("expected Ok, got Err {{ status: {status}, error: {error} }}")
            }
        }
    }

    #[test]
    fn rejects_tampered_body() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        let actual = blake3_hex(b"tampered");
        match verify_envelope(PROCEDURE, &actual, NOW, &h) {
            VerifyEnvelope::Err { status, error } => {
                assert_eq!(status, 400);
                assert_eq!(error, "body digest mismatch");
            }
            VerifyEnvelope::Ok { .. } => panic!("expected Err"),
        }
    }

    #[test]
    fn rejects_different_procedure() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        match verify_envelope("/mkit.keys.v1.Keys/DeleteName", &bd, NOW, &h) {
            VerifyEnvelope::Err { status, error } => {
                assert_eq!(status, 401);
                assert_eq!(error, "invalid signature");
            }
            VerifyEnvelope::Ok { .. } => panic!("expected Err"),
        }
    }

    #[test]
    fn freshness_window() {
        let sk = signer();
        let bd = body_digest();
        let h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        // stale (> 5 min old)
        match verify_envelope(PROCEDURE, &bd, NOW + FRESHNESS_WINDOW_MS + 1, &h) {
            VerifyEnvelope::Err { status, error } => {
                assert_eq!(status, 401);
                assert_eq!(error, "stale or future signature");
            }
            VerifyEnvelope::Ok { .. } => panic!("expected Err"),
        }
        // future (> 5 min ahead)
        match verify_envelope(PROCEDURE, &bd, NOW - FRESHNESS_WINDOW_MS - 1, &h) {
            VerifyEnvelope::Err { status, error } => {
                assert_eq!(status, 401);
                assert_eq!(error, "stale or future signature");
            }
            VerifyEnvelope::Ok { .. } => panic!("expected Err"),
        }
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
        match verify_envelope(PROCEDURE, &bd, NOW, &h) {
            VerifyEnvelope::Err { status, error } => {
                assert_eq!(status, 401);
                assert_eq!(error, "missing signature headers");
            }
            VerifyEnvelope::Ok { .. } => panic!("expected Err"),
        }
    }

    #[test]
    fn rejects_malformed_hex() {
        let sk = signer();
        let bd = body_digest();
        let mut h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        h.public_key = Some("nothex".to_owned());
        match verify_envelope(PROCEDURE, &bd, NOW, &h) {
            VerifyEnvelope::Err { status, error } => {
                assert_eq!(status, 400);
                assert_eq!(error, "malformed signature headers");
            }
            VerifyEnvelope::Ok { .. } => panic!("expected Err"),
        }
    }

    #[test]
    fn wrong_key_for_sig_rejected() {
        let sk = signer();
        let bd = body_digest();
        let mut h = headers_for(&sk, PROCEDURE, &bd, NOW, "abc-123");
        // swap pubkey to a different valid key without re-signing
        let other = SigningKey::from_bytes(&[9u8; 32]);
        h.public_key = Some(pubkey_hex(&other));
        match verify_envelope(PROCEDURE, &bd, NOW, &h) {
            VerifyEnvelope::Err { status, error } => {
                assert_eq!(status, 401);
                assert_eq!(error, "invalid signature");
            }
            VerifyEnvelope::Ok { .. } => panic!("expected Err"),
        }
    }

    #[test]
    fn ed25519_verify_strict_rejects_malformed_hex() {
        assert!(!ed25519_verify_strict("nothex", "alsonothex", b"msg"));
    }
}
