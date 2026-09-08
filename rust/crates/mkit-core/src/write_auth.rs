//! Destination-bound signed request contract (SPEC-TRANSPORT-CONNECT, auth v2).
//!
//! This module is pure: it neither reads configuration nor reserves nonces.
//! Callers supply trusted destination context and persist the verified operation
//! alongside its effects. A valid signature alone does not prevent replay.

use crate::hash::{Hash, hash};
use ed25519_dalek::{Signature, VerifyingKey};

/// Domain/version. v1 requests are never interpreted as v2 requests.
pub const DOMAIN: &str = "mkit-write:v2";
/// Maximum validity interval; replay records must survive at least until expiry.
pub const MAX_VALIDITY_MS: i64 = 300_000;
/// Maximum permitted clock lead of the sender.
pub const MAX_CLOCK_LEAD_MS: i64 = 30_000;

/// Trusted server identity. Values come from deployment configuration and the
/// decoded request target, never from unverified forwarded headers.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// Canonical HTTP(S) origin, without a trailing slash or default port.
    pub audience: &'a str,
    /// Repository/room identity within that service.
    pub repository: &'a str,
}

/// Fields authenticated by a v2 request signature. All string fields are
/// bounded and newline-free, making the newline-separated encoding unambiguous.
#[derive(Clone, Copy, Debug)]
pub struct Operation<'a> {
    /// Intended service and repository.
    pub context: Context<'a>,
    /// Full Connect procedure, or the documented full procedure for REST.
    pub procedure: &'a str,
    /// `body:<64 lowercase hex>` or `pack:<64 lowercase hex>:<decimal length>`.
    pub commitment: &'a str,
    /// Inclusive start time in epoch milliseconds.
    pub created_at: i64,
    /// Inclusive expiry time in epoch milliseconds.
    pub expires_at: i64,
    /// 32 random bytes, encoded as 64 lowercase hexadecimal characters.
    pub nonce: &'a str,
}

/// A malformed envelope, wrong destination, expired request or bad signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AuthError(pub &'static str);

fn component(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Whether a value is the fixed-length canonical lowercase hexadecimal form.
#[must_use]
pub fn is_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validate the canonical deployment origin. DNS names are ASCII lowercase;
/// international names must be their ASCII URL form. No userinfo, path, query,
/// fragment, trailing dot or default port is accepted.
///
/// # Errors
/// Returns an error for an ambiguous or noncanonical origin.
pub fn validate_audience(value: &str) -> Result<(), AuthError> {
    let (authority, default_port) = if let Some(v) = value.strip_prefix("https://") {
        (v, "443")
    } else if let Some(v) = value.strip_prefix("http://") {
        (v, "80")
    } else {
        return Err(AuthError("audience must be a canonical HTTP(S) origin"));
    };
    if !component(value, 512)
        || authority.is_empty()
        || authority
            .bytes()
            .any(|b| b.is_ascii_uppercase() || b"/@?#\\".contains(&b))
    {
        return Err(AuthError("noncanonical audience"));
    }
    let (host, port) = if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or(AuthError("invalid audience IPv6 host"))?;
        let host = &authority[..=end];
        host[1..host.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| AuthError("invalid audience IPv6 host"))?;
        let suffix = &authority[end + 1..];
        (
            host,
            if suffix.is_empty() {
                None
            } else {
                Some(
                    suffix
                        .strip_prefix(':')
                        .ok_or(AuthError("invalid audience port"))?,
                )
            },
        )
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if host.is_empty()
            || host.ends_with('.')
            || !host
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        {
            return Err(AuthError("invalid audience host"));
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(AuthError("invalid audience host"));
    }
    if let Some(port) = port {
        let parsed = port
            .parse::<u16>()
            .map_err(|_| AuthError("invalid audience port"))?;
        if parsed == 0 || port == default_port || parsed.to_string() != port {
            return Err(AuthError("noncanonical audience port"));
        }
    }
    Ok(())
}

impl Operation<'_> {
    /// Encode all authenticated fields in the v2 canonical order.
    ///
    /// # Errors
    /// Rejects malformed fields, invalid validity intervals and unknown content
    /// commitment forms before signing or verification.
    pub fn canonical(&self) -> Result<String, AuthError> {
        validate_audience(self.context.audience)?;
        if !component(self.context.repository, 255)
            || !component(self.procedure, 512)
            || !self.procedure.starts_with('/')
            || !is_hex(self.nonce, 32)
        {
            return Err(AuthError("invalid repository, procedure or nonce"));
        }
        if self.created_at < 0
            || self.expires_at <= self.created_at
            || self
                .expires_at
                .checked_sub(self.created_at)
                .is_none_or(|n| n > MAX_VALIDITY_MS)
        {
            return Err(AuthError("invalid validity interval"));
        }
        if let Some(digest) = self.commitment.strip_prefix("body:") {
            if !is_hex(digest, 32) {
                return Err(AuthError("invalid body commitment"));
            }
        } else if let Some(pack) = self.commitment.strip_prefix("pack:") {
            let (digest, length) = pack
                .split_once(':')
                .ok_or(AuthError("invalid pack commitment"))?;
            if !is_hex(digest, 32)
                || length.parse::<u64>().is_err()
                || length.parse::<u64>().is_ok_and(|n| n.to_string() != length)
            {
                return Err(AuthError("invalid pack commitment"));
            }
        } else {
            return Err(AuthError("unknown content commitment"));
        }
        Ok(format!(
            "{DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.context.audience,
            self.context.repository,
            self.procedure,
            self.commitment,
            self.created_at,
            self.expires_at,
            self.nonce
        ))
    }

    /// Digest signed with plain Ed25519 (without commit-signing domains).
    ///
    /// # Errors
    /// Same validation errors as [`Self::canonical`].
    pub fn digest(&self) -> Result<Hash, AuthError> {
        Ok(hash(self.canonical()?.as_bytes()))
    }

    /// Validate destination, time and Ed25519 signature. Persistence/effect
    /// adapters must reserve the nonce after this returns, before any effects.
    ///
    /// # Errors
    /// Rejects destination mismatch, stale/future requests and invalid signatures.
    pub fn verify(
        &self,
        expected: Context<'_>,
        now: i64,
        public_key: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), AuthError> {
        let digest = self.digest()?;
        if self.context.audience != expected.audience
            || self.context.repository != expected.repository
        {
            return Err(AuthError("request audience or repository mismatch"));
        }
        if now < 0
            || self.created_at > now.saturating_add(MAX_CLOCK_LEAD_MS)
            || now > self.expires_at
        {
            return Err(AuthError("expired or future authorization"));
        }
        let key =
            VerifyingKey::from_bytes(public_key).map_err(|_| AuthError("invalid public key"))?;
        key.verify_strict(&digest, &Signature::from_bytes(signature))
            .map_err(|_| AuthError("invalid signature"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn shared_auth_v2_golden_matches_canonical_digest_and_signature() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/golden/auth-v2/unary.json")).unwrap();
        let field = |name: &str| fixture[name].as_str().unwrap();
        let operation = Operation {
            context: Context {
                audience: field("audience"),
                repository: field("repository"),
            },
            procedure: field("procedure"),
            commitment: field("commitment"),
            created_at: fixture["created_at"].as_i64().unwrap(),
            expires_at: fixture["expires_at"].as_i64().unwrap(),
            nonce: field("nonce"),
        };
        assert_eq!(operation.canonical().unwrap(), field("canonical"));
        assert_eq!(
            crate::hash::to_hex(&operation.digest().unwrap()),
            field("signing_digest")
        );
        assert_eq!(
            crate::hash::to_hex(&hash(field("body").as_bytes())),
            field("body_digest")
        );
        let headers = Headers {
            version: Some("2".into()),
            audience: Some(field("audience").into()),
            repository: Some(field("repository").into()),
            public_key: Some(field("public_key").into()),
            signature: Some(field("signature").into()),
            commitment: Some(field("commitment").into()),
            digest: Some(field("body_digest").into()),
            created_at: Some(operation.created_at.to_string()),
            expires_at: Some(operation.expires_at.to_string()),
            idempotency_key: Some(field("nonce").into()),
        };
        let authorized = verify_headers(
            operation.context,
            operation.procedure,
            Some(operation.commitment),
            operation.created_at + 1,
            &headers,
        )
        .unwrap();
        assert_eq!(authorized.fingerprint, field("signing_digest"));
        assert!(
            verify_headers(
                operation.context,
                operation.procedure,
                Some(operation.commitment),
                operation.expires_at + 1,
                &headers
            )
            .is_err()
        );
    }

    #[test]
    fn destination_repository_and_pack_are_bound() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let nonce = "ab".repeat(32);
        let commitment = format!("pack:{}:12", "cd".repeat(32));
        let mut operation = Operation {
            context: Context {
                audience: "https://a.example",
                repository: "main",
            },
            procedure: "/mkit.transport.v1.TransportService/UploadPack",
            commitment: &commitment,
            created_at: 1000,
            expires_at: 2000,
            nonce: &nonce,
        };
        let signature = key.sign(&operation.digest().unwrap()).to_bytes();
        let pk = key.verifying_key().to_bytes();
        operation
            .verify(operation.context, 1500, &pk, &signature)
            .unwrap();
        assert!(
            operation
                .verify(
                    Context {
                        audience: "https://b.example",
                        ..operation.context
                    },
                    1500,
                    &pk,
                    &signature
                )
                .is_err()
        );
        assert!(
            operation
                .verify(
                    Context {
                        repository: "other",
                        ..operation.context
                    },
                    1500,
                    &pk,
                    &signature
                )
                .is_err()
        );
        let changed = format!("pack:{}:13", "cd".repeat(32));
        operation.commitment = &changed;
        assert!(
            operation
                .verify(operation.context, 1500, &pk, &signature)
                .is_err()
        );
    }

    #[test]
    fn ambiguous_origins_are_rejected() {
        for origin in [
            "https://HOST",
            "https://host/",
            "https://host:443",
            "https://u@host",
            "https://host?x",
            "https://host\nother",
            "https://host:00444",
        ] {
            assert!(validate_audience(origin).is_err(), "{origin}");
        }
        for origin in ["https://host", "http://localhost:8080", "https://[::1]:444"] {
            validate_audience(origin).unwrap();
        }
    }
}

/// Transport-independent v2 header values. Adapters must not normalize signed
/// fields on read; noncanonical representations are rejected.
#[derive(Clone, Debug, Default)]
pub struct Headers {
    /// Must be exactly `2`.
    pub version: Option<String>,
    /// Canonical intended origin.
    pub audience: Option<String>,
    /// Intended repository.
    pub repository: Option<String>,
    /// Raw Ed25519 public key, canonical hexadecimal.
    pub public_key: Option<String>,
    /// Raw Ed25519 signature, canonical hexadecimal.
    pub signature: Option<String>,
    /// Unary body digest (retained as an independently checked header).
    pub digest: Option<String>,
    /// Full typed content commitment.
    pub commitment: Option<String>,
    /// Canonical decimal start milliseconds.
    pub created_at: Option<String>,
    /// Canonical decimal expiry milliseconds.
    pub expires_at: Option<String>,
    /// Stable operation nonce; retained across transport retries.
    pub idempotency_key: Option<String>,
}

/// Validated identity and operation binding for a transactional effect adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized {
    /// Destination/repository/signer/nonce replay namespace.
    pub scope: String,
    /// Author authenticated by Ed25519.
    pub public_key: String,
    /// Stable nonce within the destination/repository/signer scope.
    pub nonce: String,
    /// Digest of all authenticated operation fields, including times/nonce.
    pub fingerprint: String,
    /// Typed body or pack commitment.
    pub commitment: String,
    /// Replay records cannot be removed before this timestamp has passed.
    pub expires_at: i64,
}

fn decimal(value: Option<&str>) -> Result<i64, AuthError> {
    let value = value.ok_or(AuthError("missing validity header"))?;
    let number = value
        .parse::<i64>()
        .map_err(|_| AuthError("invalid validity header"))?;
    if number.to_string() != value {
        return Err(AuthError("noncanonical validity header"));
    }
    Ok(number)
}

fn decode_hex<const N: usize>(value: Option<&str>) -> Result<[u8; N], AuthError> {
    let value = value.ok_or(AuthError("missing signature header"))?;
    if !is_hex(value, N) {
        return Err(AuthError("noncanonical signature header"));
    }
    let mut output = [0; N];
    for (byte, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let nibble = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        *byte = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(output)
}

/// Verify adapter headers against deployment-owned context and actual content.
/// `expected_commitment` is required for unary operations; streaming handlers
/// may defer that comparison until the first header, before attributed effects.
///
/// # Errors
/// Rejects legacy/missing versions, malformed fields, context/content mismatch,
/// validity-window failures and invalid signatures.
pub fn verify_headers(
    expected: Context<'_>,
    procedure: &str,
    expected_commitment: Option<&str>,
    now: i64,
    headers: &Headers,
) -> Result<Authorized, AuthError> {
    fn required(value: Option<&str>) -> Result<&str, AuthError> {
        value.ok_or(AuthError("missing auth v2 header"))
    }
    if headers.version.as_deref() != Some("2") {
        return Err(AuthError("auth v2 required"));
    }
    let operation = Operation {
        context: Context {
            audience: required(headers.audience.as_deref())?,
            repository: required(headers.repository.as_deref())?,
        },
        procedure,
        commitment: required(headers.commitment.as_deref())?,
        created_at: decimal(headers.created_at.as_deref())?,
        expires_at: decimal(headers.expires_at.as_deref())?,
        nonce: required(headers.idempotency_key.as_deref())?,
    };
    if let Some(expected) = expected_commitment {
        if operation.commitment != expected {
            return Err(AuthError("content commitment mismatch"));
        }
        if let Some(digest) = expected.strip_prefix("body:")
            && headers.digest.as_deref() != Some(digest)
        {
            return Err(AuthError("body digest mismatch"));
        }
    } else if !operation.commitment.starts_with("pack:") {
        return Err(AuthError("stream requires a pack commitment"));
    }
    operation.verify(
        expected,
        now,
        &decode_hex::<32>(headers.public_key.as_deref())?,
        &decode_hex::<64>(headers.signature.as_deref())?,
    )?;
    Ok(Authorized {
        scope: crate::hash::to_hex(&hash(
            format!(
                "{}\n{}\n{}\n{}",
                expected.audience,
                expected.repository,
                required(headers.public_key.as_deref())?,
                operation.nonce
            )
            .as_bytes(),
        )),
        public_key: required(headers.public_key.as_deref())?.to_owned(),
        nonce: operation.nonce.to_owned(),
        fingerprint: crate::hash::to_hex(&operation.digest()?),
        commitment: operation.commitment.to_owned(),
        expires_at: operation.expires_at,
    })
}
