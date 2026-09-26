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
    /// Canonical content commitment text: `body:<64 lowercase hex>`,
    /// `pack:<64 lowercase hex>:<decimal length>` or
    /// `part:<64 hex ticket>:<decimal index>:<64 hex subtree>:<decimal length>`
    /// (see [`ContentCommitment`]).
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

/// Canonical 64-hex digest: lowercase fixed-length hex only.
fn hex32(value: &str) -> Option<[u8; 32]> {
    if is_hex(value, 32) {
        crate::hash::from_hex(value).ok()
    } else {
        None
    }
}

/// Canonical unsigned decimal: no sign, no leading zero (`0` itself allowed).
fn canonical_decimal<T: core::str::FromStr + ToString>(value: &str) -> Option<T> {
    let number = value.parse::<T>().ok()?;
    (number.to_string() == value).then_some(number)
}

/// A parsed auth v2 content commitment (SPEC-TRANSPORT-CONNECT §7.1, §7.6).
///
/// [`ContentCommitment::parse`] accepts only the canonical text form, and
/// [`Display`](core::fmt::Display) writes it back, so
/// `parse(&c.to_string()) == Ok(c)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentCommitment {
    /// `body:<64 hex>`: BLAKE3 of the exact unary request bytes.
    Body(Hash),
    /// `pack:<64 hex>:<decimal len>`: an `UploadPack` stream.
    Pack {
        /// Pack id (BLAKE3 of the whole pack).
        id: Hash,
        /// Pack byte count.
        len: u64,
    },
    /// `part:<64 hex ticket>:<decimal index>:<64 hex subtree>:<decimal len>`:
    /// one `UploadPart` stream (SPEC-TRANSPORT-CONNECT §7.6).
    Part(PartCommitment),
}

/// The fields of a `part:` commitment (SPEC-TRANSPORT-CONNECT §7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartCommitment {
    /// Upload ticket id.
    pub ticket: [u8; 32],
    /// Zero-based part index.
    pub index: u32,
    /// The part's BLAKE3 chaining value as a non-root subtree at offset
    /// `index × part_size` (see [`crate::upload_parts`]).
    pub subtree: [u8; 32],
    /// Part byte count; never zero.
    pub len: u64,
}

/// The kind of a [`ContentCommitment`], without its fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentKind {
    /// `body:`
    Body,
    /// `pack:`
    Pack,
    /// `part:`
    Part,
}

impl ContentCommitment {
    /// Strict canonical parse: lowercase fixed-length hex; canonical decimals
    /// (no sign, no leading zero, `0` allowed for a `part:` index); a `part:`
    /// length of at least 1; an index that fits `u32`; exactly four fields
    /// after `part:`.
    ///
    /// # Errors
    /// `invalid body commitment`, `invalid pack commitment`,
    /// `invalid part commitment` or `unknown content commitment`.
    pub fn parse(text: &str) -> Result<Self, AuthError> {
        if let Some(digest) = text.strip_prefix("body:") {
            hex32(digest)
                .map(Self::Body)
                .ok_or(AuthError("invalid body commitment"))
        } else if let Some(pack) = text.strip_prefix("pack:") {
            let invalid = AuthError("invalid pack commitment");
            let (digest, len) = pack.split_once(':').ok_or(invalid)?;
            Ok(Self::Pack {
                id: hex32(digest).ok_or(invalid)?,
                len: canonical_decimal(len).ok_or(invalid)?,
            })
        } else if let Some(part) = text.strip_prefix("part:") {
            Self::parse_part(part)
                .map(Self::Part)
                .ok_or(AuthError("invalid part commitment"))
        } else {
            Err(AuthError("unknown content commitment"))
        }
    }

    fn parse_part(fields: &str) -> Option<PartCommitment> {
        let mut fields = fields.split(':');
        let ticket = hex32(fields.next()?)?;
        let index = canonical_decimal(fields.next()?)?;
        let subtree = hex32(fields.next()?)?;
        let len = canonical_decimal(fields.next()?).filter(|&len| len != 0)?;
        if fields.next().is_some() {
            return None;
        }
        Some(PartCommitment {
            ticket,
            index,
            subtree,
            len,
        })
    }

    /// The commitment's kind.
    #[must_use]
    pub fn kind(&self) -> CommitmentKind {
        match self {
            Self::Body(_) => CommitmentKind::Body,
            Self::Pack { .. } => CommitmentKind::Pack,
            Self::Part(_) => CommitmentKind::Part,
        }
    }
}

impl core::fmt::Display for ContentCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use crate::hash::to_hex;
        match self {
            Self::Body(digest) => write!(f, "body:{}", to_hex(digest)),
            Self::Pack { id, len } => write!(f, "pack:{}:{len}", to_hex(id)),
            Self::Part(part) => write!(
                f,
                "part:{}:{}:{}:{}",
                to_hex(&part.ticket),
                part.index,
                to_hex(&part.subtree),
                part.len
            ),
        }
    }
}

/// What a verifier expects the signed content commitment to be.
#[derive(Clone, Copy, Debug)]
pub enum ExpectedCommitment<'a> {
    /// Unary: exactly this text, plus the `X-Digest` check for `body:`.
    Exact(&'a str),
    /// `UploadPack` stream: any well-formed `pack:`. The handler compares it
    /// with the first stream message itself.
    PackStream,
    /// `UploadPart` stream: any well-formed `part:`. The handler compares the
    /// ticket id and index with the first stream message itself
    /// (SPEC-TRANSPORT-CONNECT §7.6).
    PartStream,
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
        ContentCommitment::parse(self.commitment)?;
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

    const UPLOAD_PART: &str = "/mkit.transport.v1.TransportService/UploadPart";

    fn part_text(ticket: &str, index: &str, subtree: &str, len: &str) -> String {
        format!("part:{ticket}:{index}:{subtree}:{len}")
    }

    /// Headers for `operation`, signed by `key`.
    fn signed_headers(operation: &Operation<'_>, key: &SigningKey) -> Headers {
        let digest = operation
            .commitment
            .strip_prefix("body:")
            .map(ToOwned::to_owned);
        Headers {
            version: Some("2".into()),
            audience: Some(operation.context.audience.into()),
            repository: Some(operation.context.repository.into()),
            public_key: Some(crate::hash::to_hex(&key.verifying_key().to_bytes())),
            signature: Some(crate::hash::to_hex_bytes(
                &key.sign(&operation.digest().unwrap()).to_bytes(),
            )),
            commitment: Some(operation.commitment.into()),
            digest,
            created_at: Some(operation.created_at.to_string()),
            expires_at: Some(operation.expires_at.to_string()),
            idempotency_key: Some(operation.nonce.into()),
        }
    }

    fn operation_with<'a>(commitment: &'a str, nonce: &'a str) -> Operation<'a> {
        Operation {
            context: Context {
                audience: "https://a.example",
                repository: "main",
            },
            procedure: UPLOAD_PART,
            commitment,
            created_at: 1000,
            expires_at: 2000,
            nonce,
        }
    }

    #[test]
    fn part_commitment_roundtrip() {
        for index in [0, 1, u32::MAX] {
            for len in [1, u64::MAX] {
                let commitment = ContentCommitment::Part(PartCommitment {
                    ticket: [0x5a; 32],
                    index,
                    subtree: [0xcd; 32],
                    len,
                });
                let text = commitment.to_string();
                assert_eq!(
                    text,
                    part_text(
                        &"5a".repeat(32),
                        &index.to_string(),
                        &"cd".repeat(32),
                        &len.to_string()
                    )
                );
                assert_eq!(ContentCommitment::parse(&text), Ok(commitment));
                assert_eq!(commitment.kind(), CommitmentKind::Part);
            }
        }
        for commitment in [
            ContentCommitment::Body([1; 32]),
            ContentCommitment::Pack {
                id: [2; 32],
                len: 0,
            },
            ContentCommitment::Pack {
                id: [2; 32],
                len: u64::MAX,
            },
        ] {
            assert_eq!(
                ContentCommitment::parse(&commitment.to_string()),
                Ok(commitment)
            );
        }
        assert_eq!(
            ContentCommitment::Body([1; 32]).kind(),
            CommitmentKind::Body
        );
        assert_eq!(
            ContentCommitment::Pack {
                id: [2; 32],
                len: 3
            }
            .kind(),
            CommitmentKind::Pack
        );
    }

    /// The reject cases of `mkit-server`'s `verified_auth_rejects_noncanonical_fields`
    /// keep their `Operation::canonical` messages.
    #[test]
    fn body_and_pack_parse_unchanged() {
        let digest = "cd".repeat(32);
        let nonce = "ab".repeat(32);
        for (commitment, message) in [
            (
                format!("body:{}", digest.to_uppercase()),
                "invalid body commitment",
            ),
            (format!("body:{}", &digest[..62]), "invalid body commitment"),
            (format!("pack:{digest}:012"), "invalid pack commitment"),
            (format!("pack:{digest}:+12"), "invalid pack commitment"),
            (format!("pack:{digest}:"), "invalid pack commitment"),
            (format!("pack:{digest}"), "invalid pack commitment"),
            (
                format!("pack:{digest}:18446744073709551616"),
                "invalid pack commitment",
            ),
            (
                format!("pack:{}:12", digest.to_uppercase()),
                "invalid pack commitment",
            ),
            (format!("pack:{digest}:1:2"), "invalid pack commitment"),
            // Formerly an unknown kind; now a malformed `part:`.
            (format!("part:{digest}:1"), "invalid part commitment"),
            (String::new(), "unknown content commitment"),
            (format!("blob:{digest}"), "unknown content commitment"),
            (format!("BODY:{digest}"), "unknown content commitment"),
        ] {
            assert_eq!(
                operation_with(&commitment, &nonce).canonical(),
                Err(AuthError(message)),
                "{commitment}"
            );
        }
        for commitment in [
            format!("body:{digest}"),
            format!("pack:{digest}:0"),
            format!("pack:{digest}:18446744073709551615"),
        ] {
            operation_with(&commitment, &nonce).canonical().unwrap();
        }
    }

    #[test]
    fn part_commitment_rejects() {
        let hex = "cd".repeat(32);
        let upper = hex.to_uppercase();
        let short = &hex[..63];
        let nonce = "ab".repeat(32);
        for commitment in [
            part_text(&upper, "1", &hex, "8"),
            part_text(short, "1", &hex, "8"),
            part_text(&format!("{hex}0"), "1", &hex, "8"),
            part_text(&hex, "1", &upper, "8"),
            part_text(&hex, "1", short, "8"),
            part_text(&hex, "01", &hex, "8"),
            part_text(&hex, "+1", &hex, "8"),
            part_text(&hex, "-1", &hex, "8"),
            part_text(&hex, "4294967296", &hex, "8"),
            part_text(&hex, "1", &hex, "0"),
            part_text(&hex, "1", &hex, "007"),
            part_text(&hex, "1", &hex, "+7"),
            part_text(&hex, "1", &hex, "18446744073709551616"),
            part_text(&hex, "", &hex, "8"),
            part_text(&hex, "1", &hex, ""),
            part_text("", "1", &hex, "8"),
            part_text(&hex, "1", "", "8"),
            format!("part:{hex}:1:{hex}"),
            format!("part:{hex}:1"),
            format!("part:{hex}:1:{hex}:8:9"),
            format!("{}:", part_text(&hex, "1", &hex, "8")),
            format!("part::{}", part_text(&hex, "1", &hex, "8")),
            "part:".to_owned(),
        ] {
            assert_eq!(
                ContentCommitment::parse(&commitment),
                Err(AuthError("invalid part commitment")),
                "{commitment}"
            );
            assert_eq!(
                operation_with(&commitment, &nonce).canonical(),
                Err(AuthError("invalid part commitment")),
                "{commitment}"
            );
        }
        for (index, len) in [("0", "1"), ("4294967295", "18446744073709551615")] {
            let commitment = part_text(&hex, index, &hex, len);
            operation_with(&commitment, &nonce).canonical().unwrap();
        }
    }

    /// The committed `part.json` golden (see `tests/golden_uploads.rs`).
    fn part_golden() -> (serde_json::Value, Headers) {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/golden/auth-v2/part.json")).unwrap();
        let field = |name: &str| Some(fixture[name].as_str().unwrap().to_owned());
        let headers = Headers {
            version: Some("2".into()),
            audience: field("audience"),
            repository: field("repository"),
            public_key: field("public_key"),
            signature: field("signature"),
            commitment: field("commitment"),
            digest: None,
            created_at: Some(fixture["created_at"].as_i64().unwrap().to_string()),
            expires_at: Some(fixture["expires_at"].as_i64().unwrap().to_string()),
            idempotency_key: field("nonce"),
        };
        (fixture, headers)
    }

    #[test]
    fn verify_headers_with_part_stream_accepts_part_golden() {
        let (fixture, headers) = part_golden();
        let context = Context {
            audience: fixture["audience"].as_str().unwrap(),
            repository: fixture["repository"].as_str().unwrap(),
        };
        let procedure = fixture["procedure"].as_str().unwrap();
        let now = fixture["created_at"].as_i64().unwrap() + 1;
        let authorized = verify_headers_with(
            context,
            procedure,
            ExpectedCommitment::PartStream,
            now,
            &headers,
        )
        .unwrap();
        assert_eq!(authorized.fingerprint, fixture["signing_digest"]);
        assert_eq!(authorized.commitment, fixture["commitment"]);
        let ContentCommitment::Part(part) = authorized.content_commitment().unwrap() else {
            panic!("expected a part commitment");
        };
        assert_eq!(part.ticket, [0x5a; 32]);
        assert_eq!(part.index, 1);
        // The exact expectation accepts it too, with no body digest.
        let exact = fixture["commitment"].as_str().unwrap();
        verify_headers_with(
            context,
            procedure,
            ExpectedCommitment::Exact(exact),
            now,
            &headers,
        )
        .unwrap();
        assert_eq!(
            verify_headers(context, procedure, Some(exact), now, &headers),
            Ok(authorized)
        );
    }

    #[test]
    fn verify_headers_none_still_rejects_part() {
        let (fixture, headers) = part_golden();
        let context = Context {
            audience: fixture["audience"].as_str().unwrap(),
            repository: fixture["repository"].as_str().unwrap(),
        };
        let now = fixture["created_at"].as_i64().unwrap() + 1;
        for procedure in [fixture["procedure"].as_str().unwrap(), UPLOAD_PART] {
            assert_eq!(
                verify_headers(context, procedure, None, now, &headers),
                Err(AuthError("stream requires a pack commitment"))
            );
            assert_eq!(
                verify_headers_with(
                    context,
                    procedure,
                    ExpectedCommitment::PackStream,
                    now,
                    &headers
                ),
                Err(AuthError("stream requires a pack commitment"))
            );
        }
    }

    #[test]
    fn part_stream_rejects_pack_and_body() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let nonce = "ab".repeat(32);
        let pack = format!("pack:{}:12", "cd".repeat(32));
        let body = format!("body:{}", "cd".repeat(32));
        for commitment in [&pack, &body] {
            let operation = operation_with(commitment, &nonce);
            let headers = signed_headers(&operation, &key);
            assert_eq!(
                verify_headers_with(
                    operation.context,
                    UPLOAD_PART,
                    ExpectedCommitment::PartStream,
                    1500,
                    &headers
                ),
                Err(AuthError("stream requires a part commitment")),
                "{commitment}"
            );
        }
        // The pack stream still accepts a pack commitment, both ways.
        let operation = operation_with(&pack, &nonce);
        let headers = signed_headers(&operation, &key);
        let with = verify_headers_with(
            operation.context,
            UPLOAD_PART,
            ExpectedCommitment::PackStream,
            1500,
            &headers,
        )
        .unwrap();
        assert_eq!(
            verify_headers(operation.context, UPLOAD_PART, None, 1500, &headers),
            Ok(with)
        );
        // A malformed part commitment fails canonical validation.
        let bad = format!("part:{}:01:{}:8", "5a".repeat(32), "cd".repeat(32));
        let mut headers = signed_headers(&operation, &key);
        headers.commitment = Some(bad);
        assert_eq!(
            verify_headers_with(
                operation.context,
                UPLOAD_PART,
                ExpectedCommitment::PartStream,
                1500,
                &headers
            ),
            Err(AuthError("invalid part commitment"))
        );
    }

    #[test]
    fn authorized_content_commitment_roundtrip() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let nonce = "ab".repeat(32);
        let part = part_text(&"5a".repeat(32), "7", &"cd".repeat(32), "9");
        for (commitment, expected) in [
            (
                format!("body:{}", "cd".repeat(32)),
                ExpectedCommitment::Exact(
                    "body:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
                ),
            ),
            (
                format!("pack:{}:12", "cd".repeat(32)),
                ExpectedCommitment::PackStream,
            ),
            (part, ExpectedCommitment::PartStream),
        ] {
            let operation = operation_with(&commitment, &nonce);
            let headers = signed_headers(&operation, &key);
            let authorized =
                verify_headers_with(operation.context, UPLOAD_PART, expected, 1500, &headers)
                    .unwrap();
            let typed = authorized.content_commitment().unwrap();
            assert_eq!(typed.to_string(), authorized.commitment);
            assert_eq!(typed, ContentCommitment::parse(&commitment).unwrap());
        }
        let hand_built = Authorized {
            scope: String::new(),
            public_key: String::new(),
            nonce: String::new(),
            fingerprint: String::new(),
            commitment: "part:".into(),
            expires_at: 0,
        };
        assert_eq!(
            hand_built.content_commitment(),
            Err(AuthError("invalid part commitment"))
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
    /// Canonical content commitment text; see [`Self::content_commitment`].
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

impl Authorized {
    /// Typed view of [`Self::commitment`], which is canonical whenever the
    /// verifier produced this value.
    ///
    /// # Errors
    /// The [`ContentCommitment::parse`] errors, for a hand-built value only.
    pub fn content_commitment(&self) -> Result<ContentCommitment, AuthError> {
        ContentCommitment::parse(&self.commitment)
    }
}

/// Verify adapter headers against deployment-owned context and actual content.
/// `expected_commitment` is required for unary operations; with `None`, an
/// `UploadPack` handler may defer that comparison until the first header,
/// before attributed effects. Same as [`verify_headers_with`] with
/// [`ExpectedCommitment::Exact`], or [`ExpectedCommitment::PackStream`] for
/// `None`.
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
    verify_headers_with(
        expected,
        procedure,
        expected_commitment.map_or(ExpectedCommitment::PackStream, ExpectedCommitment::Exact),
        now,
        headers,
    )
}

/// Verify adapter headers against deployment-owned context and actual
/// content, with the commitment expectation of a unary call, an
/// `UploadPack` stream or an `UploadPart` stream.
///
/// # Errors
/// Rejects legacy/missing versions, malformed fields, context/content mismatch,
/// a commitment of the wrong kind for the stream, validity-window failures
/// and invalid signatures.
pub fn verify_headers_with(
    expected: Context<'_>,
    procedure: &str,
    commitment: ExpectedCommitment<'_>,
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
    match commitment {
        ExpectedCommitment::Exact(expected) => {
            if operation.commitment != expected {
                return Err(AuthError("content commitment mismatch"));
            }
            if let Some(digest) = expected.strip_prefix("body:")
                && headers.digest.as_deref() != Some(digest)
            {
                return Err(AuthError("body digest mismatch"));
            }
        }
        ExpectedCommitment::PackStream => {
            if !operation.commitment.starts_with("pack:") {
                return Err(AuthError("stream requires a pack commitment"));
            }
        }
        ExpectedCommitment::PartStream => {
            if !operation.commitment.starts_with("part:") {
                return Err(AuthError("stream requires a part commitment"));
            }
        }
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
