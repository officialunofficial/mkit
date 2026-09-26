//! The auth v2 envelope (SPEC-TRANSPORT-CONNECT §7.1), built over
//! [`mkit_core::write_auth::Operation`] and signed with `ed25519-dalek`.
//! Every field is public so a case can build a deliberately wrong envelope,
//! and a [`SignedOp`] carries the exact headers so a case can replay them.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::hash::{Hash, hash, to_hex, to_hex_bytes};
use mkit_core::write_auth::{Context, MAX_VALIDITY_MS, Operation};

use super::profile::random_hex;

/// Milliseconds since the Unix epoch on this machine. Envelopes are dated
/// with it, so the machine running the suite needs a clock within
/// `MAX_CLOCK_LEAD_MS` (30 s) of the server's.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// An auth v2 identity: a key plus the deployment it signs for.
#[derive(Clone)]
pub struct Signer {
    key: SigningKey,
    audience: String,
    repository: String,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("public_key", &self.public_key_hex())
            .finish_non_exhaustive()
    }
}

/// One envelope's fields, before signing. [`Signer::sign`] turns it into
/// headers; a case edits fields first to build an invalid request.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// `X-Envelope-Version` (`None`: header omitted).
    pub version: Option<String>,
    /// The audience signed over and sent.
    pub audience: String,
    /// The repository signed over and sent.
    pub repository: String,
    /// The full procedure, e.g. `/mkit.transport.v1.TransportService/UpdateRef`.
    pub procedure: String,
    /// `body:<hex>` or `pack:<hex>:<len>`.
    pub commitment: String,
    /// `X-Digest` (unary requests only).
    pub digest: Option<String>,
    /// Validity start, epoch ms.
    pub created_at: i64,
    /// Validity end, epoch ms.
    pub expires_at: i64,
    /// 64 lowercase hex characters, fresh per logical operation.
    pub nonce: String,
}

/// A signed operation: the exact headers to send, and its nonce.
#[derive(Debug, Clone)]
pub struct SignedOp {
    /// Lowercase header names and values.
    pub headers: Vec<(String, String)>,
    /// The `Idempotency-Key`.
    pub nonce: String,
}

impl SignedOp {
    /// Replace (or add) header `name`, keeping the signature: a tampered
    /// copy.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.retain(|(n, _)| n != name);
        self.headers.push((name.to_owned(), value.into()));
        self
    }
}

/// `body:<hex BLAKE3 of body>`.
#[must_use]
pub fn body_commitment(body: &[u8]) -> String {
    format!("body:{}", to_hex(&hash(body)))
}

/// `pack:<hex id>:<len>`.
#[must_use]
pub fn pack_commitment(id: &[u8], len: u64) -> String {
    format!("pack:{}:{len}", to_hex_bytes(id))
}

impl Signer {
    /// A signer with `seed`.
    #[must_use]
    pub fn new(seed: [u8; 32], audience: &str, repository: &str) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
            audience: audience.to_owned(),
            repository: repository.to_owned(),
        }
    }

    /// A signer whose seed is derived from `seed`, the run id and `label`,
    /// so each case (and each run) signs with its own key and per-signer
    /// quotas never couple cases or runs.
    #[must_use]
    pub fn derive(
        seed: &[u8; 32],
        run_id: &str,
        label: &str,
        audience: &str,
        repository: &str,
    ) -> Self {
        let mut input = Vec::with_capacity(64 + run_id.len() + label.len());
        input.extend_from_slice(b"mkit-server-conformance signer\n");
        input.extend_from_slice(seed);
        input.extend_from_slice(run_id.as_bytes());
        input.push(b'\n');
        input.extend_from_slice(label.as_bytes());
        let derived: Hash = hash(&input);
        Self::new(derived, audience, repository)
    }

    /// The public key, lowercase hex.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        to_hex(self.key.verifying_key().as_bytes())
    }

    /// A fresh, valid envelope for `procedure` over `commitment`: created
    /// now, valid for the full window minus a margin, with a random nonce.
    #[must_use]
    pub fn envelope(&self, procedure: &str, commitment: String) -> Envelope {
        let created_at = now_ms();
        Envelope {
            version: Some("2".to_owned()),
            audience: self.audience.clone(),
            repository: self.repository.clone(),
            procedure: procedure.to_owned(),
            commitment,
            digest: None,
            created_at,
            expires_at: created_at + MAX_VALIDITY_MS - 60_000,
            nonce: random_hex::<32>(),
        }
    }

    /// Sign a unary request with exactly `body`.
    #[must_use]
    pub fn sign_body(&self, procedure: &str, body: &[u8]) -> SignedOp {
        let mut env = self.envelope(procedure, body_commitment(body));
        env.digest = Some(to_hex(&hash(body)));
        self.sign(&env)
    }

    /// Sign an `UploadPack` of `len` bytes with id `id`.
    #[must_use]
    pub fn sign_pack(&self, procedure: &str, id: &[u8], len: u64) -> SignedOp {
        self.sign(&self.envelope(procedure, pack_commitment(id, len)))
    }

    /// Sign `env` as it stands. A field the canonical form rejects (e.g.
    /// a non-canonical audience) is signed over a zero digest, which no
    /// server accepts: the case still gets its invalid request.
    #[must_use]
    pub fn sign(&self, env: &Envelope) -> SignedOp {
        let op = Operation {
            context: Context {
                audience: &env.audience,
                repository: &env.repository,
            },
            procedure: &env.procedure,
            commitment: &env.commitment,
            created_at: env.created_at,
            expires_at: env.expires_at,
            nonce: &env.nonce,
        };
        let digest = op.digest().unwrap_or([0; 32]);
        let signature = self.key.sign(&digest);
        let mut headers = vec![
            ("x-audience".to_owned(), env.audience.clone()),
            ("x-repository".to_owned(), env.repository.clone()),
            ("x-public-key".to_owned(), self.public_key_hex()),
            (
                "x-signature".to_owned(),
                to_hex_bytes(&signature.to_bytes()),
            ),
            ("x-content-commitment".to_owned(), env.commitment.clone()),
            ("x-created-at".to_owned(), env.created_at.to_string()),
            ("x-expires-at".to_owned(), env.expires_at.to_string()),
            ("idempotency-key".to_owned(), env.nonce.clone()),
        ];
        if let Some(version) = &env.version {
            headers.push(("x-envelope-version".to_owned(), version.clone()));
        }
        if let Some(digest) = &env.digest {
            headers.push(("x-digest".to_owned(), digest.clone()));
        }
        SignedOp {
            headers,
            nonce: env.nonce.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use mkit_core::write_auth::{Headers, verify_headers};

    use super::*;

    fn headers(op: &SignedOp) -> Headers {
        let get = |name: &str| {
            op.headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        Headers {
            version: get("x-envelope-version"),
            audience: get("x-audience"),
            repository: get("x-repository"),
            public_key: get("x-public-key"),
            signature: get("x-signature"),
            digest: get("x-digest"),
            commitment: get("x-content-commitment"),
            created_at: get("x-created-at"),
            expires_at: get("x-expires-at"),
            idempotency_key: get("idempotency-key"),
        }
    }

    const PROC: &str = "/mkit.transport.v1.TransportService/UpdateRef";

    #[test]
    fn signed_body_verifies_with_mkit_core() {
        let signer = Signer::derive(&[7; 32], "run", "case", "https://a.test", "room");
        let op = signer.sign_body(PROC, b"body");
        let ctx = Context {
            audience: "https://a.test",
            repository: "room",
        };
        let commitment = body_commitment(b"body");
        verify_headers(ctx, PROC, Some(&commitment), now_ms(), &headers(&op)).unwrap();
        // A different body fails its commitment.
        let other = body_commitment(b"other");
        assert!(verify_headers(ctx, PROC, Some(&other), now_ms(), &headers(&op)).is_err());
    }

    #[test]
    fn derived_signers_differ_per_label_and_run() {
        let key = |run: &str, label: &str| {
            Signer::derive(&[1; 32], run, label, "https://a.test", "r").public_key_hex()
        };
        assert_ne!(key("r1", "a"), key("r1", "b"));
        assert_ne!(key("r1", "a"), key("r2", "a"));
        assert_eq!(key("r1", "a"), key("r1", "a"));
    }
}
