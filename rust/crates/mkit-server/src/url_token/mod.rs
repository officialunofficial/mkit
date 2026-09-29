//! Signed URL tokens (SPEC-WRITE-GRANTS §9.4): the `mkit-url-token:v1`
//! statement, its `<statement>.<signature>` encoding, the deployment's
//! Ed25519 key set and `IssueObjectUrl`'s mint.
//!
//! The token key is dedicated: it MUST NOT equal the receipt key, the
//! hook key, the admin key, or any key that signs auth v2
//! (SPEC-WRITE-GRANTS §9.4). [`crate::pipeline::Pipeline::new`] refuses a
//! URL-token seed equal to an upload-ticket secret; the receipt-key check
//! lands with WP-5.8. The token string and the seeds never appear in
//! `Debug` output or tracing.

#[cfg(test)]
mod golden;
mod statement;
#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::future::Future;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mkit_attest::grant::GrantError;
use mkit_core::hash::{hash, to_hex_bytes};
use zeroize::Zeroizing;

use crate::error::{Redacted, ServerError};

pub(crate) use statement::key_id;
pub use statement::{TargetError, UrlTarget, UrlTokenStatement};

/// The statement domain separator (SPEC-WRITE-GRANTS §9.4).
pub const DOMAIN: &str = "mkit-url-token:v1";
/// The longest target path, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// The default token lifetime (§1.1 `url_token_ttl`).
pub const DEFAULT_TTL_MS: u64 = 15 * 60 * 1000;
/// The longest lifetime a statement may encode and a configuration may
/// set (executor bound; §9.4 bounds by `url_token_ttl` at issue).
pub const MAX_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Why a statement, token or key configuration is rejected. Every variant
/// maps to one stable [`UrlTokenError::reason`] for the golden vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlTokenError {
    /// The token is longer than any valid token can be.
    #[error("token too long")]
    Length,
    /// Not exactly two nonempty base64url segments joined by `.`.
    #[error("token format")]
    Format,
    /// A segment is not strict unpadded base64url.
    #[error("token encoding")]
    Encoding,
    /// The signature segment is not 64 bytes.
    #[error("signature length")]
    SignatureLength,
    /// A §3.1 statement rule failed.
    #[error("statement: {0}")]
    Statement(#[from] GrantError),
    /// The `target` field fails its grammar.
    #[error("invalid target")]
    Target,
    /// The key id is not in the verification set, or its key is retired.
    #[error("unknown or retired key id")]
    KeyId,
    /// The Ed25519 signature does not verify strictly.
    #[error("bad signature")]
    Signature,
    /// The audience, repository or target does not match the request.
    #[error("binding mismatch")]
    Binding,
    /// The token's `now` is at or past `expiry`.
    #[error("token expired")]
    Expired,
    /// `expiry - issued` exceeds the configured lifetime.
    #[error("lifetime too long")]
    Lifetime,
    /// The token's epoch differs from the stored epoch.
    #[error("epoch mismatch")]
    Epoch,
}

impl UrlTokenError {
    /// The stable rejection reason, for tests and golden vectors.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Length => "token too long",
            Self::Format => "token format",
            Self::Encoding => "token encoding",
            Self::SignatureLength => "signature length",
            Self::Statement(e) => e.reason(),
            Self::Target => "invalid target",
            Self::KeyId => "unknown or retired key id",
            Self::Signature => "bad signature",
            Self::Binding => "binding mismatch",
            Self::Expired => "token expired",
            Self::Lifetime => "lifetime too long",
            Self::Epoch => "epoch mismatch",
        }
    }
}

/// A retired verification key: it verifies until `retired_at_ms + ttl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredKey {
    /// The 32-byte Ed25519 public key.
    pub public: [u8; 32],
    /// Retirement time, Unix epoch milliseconds.
    pub retired_at_ms: u64,
}

/// Invalid key-set or lifetime configuration. Never contains secret input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UrlTokenConfigError {
    /// Malformed seed or public key, a weak or duplicated public key, a
    /// retired key equal to the active key, a missing or repeated `active`
    /// line, or an unknown key-file directive.
    #[error("invalid URL token key configuration")]
    Keys,
    /// A token lifetime outside `1..=MAX_TTL_MS`.
    #[error("invalid URL token lifetime")]
    Ttl,
}

/// The deployment's URL-token signing key and its retired verification
/// keys (§9.4). Only key ids appear in `Debug`; seeds never do.
pub struct UrlTokenKeys {
    active: SigningKey,
    retired: Vec<RetiredKey>,
}

impl UrlTokenKeys {
    /// Signing `active` seed plus the retired verification set.
    ///
    /// # Errors
    /// [`UrlTokenConfigError::Keys`] for a malformed or weak retired public
    /// key, a retired key equal to the active key, or a duplicate key id.
    #[allow(clippy::needless_pass_by_value)] // The zeroizing seed moves with the key.
    pub fn new(
        active_seed: Zeroizing<[u8; 32]>,
        retired: Vec<RetiredKey>,
    ) -> Result<Self, UrlTokenConfigError> {
        let active = SigningKey::from_bytes(&active_seed);
        let active_public = active.verifying_key().to_bytes();
        let mut ids = BTreeSet::from([key_id(&active_public)]);
        for key in &retired {
            let verifying =
                VerifyingKey::from_bytes(&key.public).map_err(|_| UrlTokenConfigError::Keys)?;
            if verifying.is_weak()
                || key.public == active_public
                || !ids.insert(key_id(&key.public))
            {
                return Err(UrlTokenConfigError::Keys);
            }
        }
        Ok(Self { active, retired })
    }

    /// Parse a key file: blank lines and `#` comments are ignored; exactly
    /// one `active <64 hex seed>` line and zero or more
    /// `retired <64 hex public key> <retired_at_ms>` lines follow the §3.1
    /// decimal and hex rules. Errors never echo input.
    ///
    /// # Errors
    /// As [`UrlTokenKeys::new`], plus malformed lines.
    pub fn parse_key_file(text: &str) -> Result<Self, UrlTokenConfigError> {
        let invalid = || UrlTokenConfigError::Keys;
        let mut seed = None;
        let mut retired = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("active") => {
                    let hex = fields.next().ok_or_else(invalid)?;
                    if seed.is_some() || fields.next().is_some() {
                        return Err(invalid());
                    }
                    seed = Some(Zeroizing::new(
                        mkit_attest::grant::text::hex32(hex).map_err(|_| invalid())?,
                    ));
                }
                Some("retired") => {
                    let public = fields.next().ok_or_else(invalid)?;
                    let at = fields.next().ok_or_else(invalid)?;
                    let retired_at_ms = at
                        .parse::<u64>()
                        .ok()
                        .filter(|n| n.to_string() == at)
                        .ok_or_else(invalid)?;
                    if fields.next().is_some() {
                        return Err(invalid());
                    }
                    retired.push(RetiredKey {
                        public: mkit_attest::grant::text::hex32(public).map_err(|_| invalid())?,
                        retired_at_ms,
                    });
                }
                _ => return Err(invalid()),
            }
        }
        Self::new(seed.ok_or_else(invalid)?, retired)
    }

    /// [`Self::parse_key_file`] over an owned secret, wiping the source text.
    ///
    /// # Errors
    /// As [`UrlTokenKeys::parse_key_file`].
    pub fn parse_key_file_secret(text: String) -> Result<Self, UrlTokenConfigError> {
        let text = Zeroizing::new(text);
        Self::parse_key_file(&text)
    }

    /// The active key's id: `hex(blake3(public)[..16])`.
    #[must_use]
    pub fn active_key_id(&self) -> String {
        to_hex_bytes(&self.active_id())
    }

    /// The active key's 16-byte id.
    fn active_id(&self) -> [u8; 16] {
        key_id(&self.active.verifying_key().to_bytes())
    }

    /// The active seed, for the `Pipeline::new` distinctness check against
    /// the upload-ticket secrets. Callers must not log it.
    pub(crate) fn active_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.active.to_bytes())
    }

    /// The verification key for a statement's key id: the active key, or a
    /// retired key before `retired_at_ms + ttl_ms`.
    pub(crate) fn verifying_key(
        &self,
        id: &[u8; 16],
        now_ms: i64,
        ttl_ms: u64,
    ) -> Option<VerifyingKey> {
        let active = self.active.verifying_key();
        if key_id(active.as_bytes()) == *id {
            return Some(active);
        }
        let key = self.retired.iter().find(|key| key_id(&key.public) == *id)?;
        let after = key.retired_at_ms.saturating_add(ttl_ms);
        if now_ms >= 0 && u64::try_from(now_ms).ok() < Some(after) {
            VerifyingKey::from_bytes(&key.public).ok()
        } else {
            None
        }
    }

    /// The published key list (SPEC-SERVER §7.2): `version` 1, the active
    /// key unbounded, each retired key bounded by `notAfterMs`
    /// (`retired_at_ms + ttl_ms`). Mounting it at
    /// `/.well-known/mkit-url-token-keys.json` is WP-4.16.
    #[must_use]
    pub fn key_set_json(&self, ttl_ms: u64) -> String {
        let entry = |id: [u8; 16], public: &[u8; 32]| {
            format!(
                "\"keyId\":\"{}\",\"alg\":\"ed25519\",\"publicKey\":\"{}\"",
                to_hex_bytes(&id),
                to_hex_bytes(public)
            )
        };
        let active = self.active.verifying_key().to_bytes();
        let mut json = format!(
            "{{\"version\":1,\"keys\":[{{{}",
            entry(self.active_id(), &active)
        );
        for key in &self.retired {
            let not_after = key.retired_at_ms.saturating_add(ttl_ms);
            let _ = write!(
                json,
                "}},{{{},\"notAfterMs\":\"{not_after}\"",
                entry(key_id(&key.public), &key.public)
            );
        }
        json.push_str("}]}");
        json
    }
}

impl fmt::Debug for UrlTokenKeys {
    /// Key ids only; never a seed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlTokenKeys")
            .field(
                "active_key_id",
                &to_hex_bytes(&key_id(&self.active.verifying_key().to_bytes())),
            )
            .field(
                "retired_key_ids",
                &self
                    .retired
                    .iter()
                    .map(|key| to_hex_bytes(&key_id(&key.public)))
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// The deployment's URL-token configuration: keys and the longest
/// lifetime it issues (`url_token_ttl`, §1.1).
#[derive(Clone)]
pub struct UrlTokenConfig {
    keys: Arc<UrlTokenKeys>,
    ttl_ms: u64,
}

impl UrlTokenConfig {
    /// `keys` with the default lifetime cap, [`DEFAULT_TTL_MS`] (15
    /// minutes).
    #[must_use]
    pub fn new(keys: UrlTokenKeys) -> Self {
        Self {
            keys: Arc::new(keys),
            ttl_ms: DEFAULT_TTL_MS,
        }
    }

    /// `keys` with an explicit issued-token lifetime cap.
    ///
    /// # Errors
    /// [`UrlTokenConfigError::Ttl`] for `ttl_ms` outside `1..=MAX_TTL_MS`.
    pub fn with_ttl_ms(keys: UrlTokenKeys, ttl_ms: u64) -> Result<Self, UrlTokenConfigError> {
        if ttl_ms == 0 || ttl_ms > MAX_TTL_MS {
            return Err(UrlTokenConfigError::Ttl);
        }
        Ok(Self {
            keys: Arc::new(keys),
            ttl_ms,
        })
    }

    /// The issued-token lifetime cap, in milliseconds.
    #[must_use]
    pub fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    /// The signing and verification key set.
    #[must_use]
    pub fn keys(&self) -> &UrlTokenKeys {
        &self.keys
    }

    /// Mint a token binding `audience`, `repository` and `target` at
    /// `epoch`, issued at `now_ms`. A `requested_ttl_s` of 0 asks for the
    /// configured lifetime; any request is clamped to it, never refused.
    ///
    /// # Errors
    /// `internal` when the statement cannot encode (a caller's clock far
    /// outside its range).
    pub fn mint(
        &self,
        audience: &str,
        repository: &str,
        target: &UrlTarget,
        epoch: u64,
        now_ms: i64,
        requested_ttl_s: u32,
    ) -> Result<MintedToken, ServerError> {
        let ttl_ms = if requested_ttl_s == 0 {
            self.ttl_ms
        } else {
            u64::from(requested_ttl_s)
                .saturating_mul(1000)
                .min(self.ttl_ms)
        };
        let expires_at_ms = now_ms.saturating_add(i64::try_from(ttl_ms).unwrap_or(i64::MAX));
        let statement = UrlTokenStatement::new(
            audience,
            repository,
            target.clone(),
            epoch,
            now_ms,
            expires_at_ms,
            self.keys.active_id(),
        );
        let bytes = statement.encode().map_err(|e| {
            ServerError::internal(
                "request failed",
                format_args!("url token statement did not encode: {}", e.reason()),
            )
        })?;
        let signature = self.keys.active.sign(&hash(&bytes));
        Ok(MintedToken {
            token: Redacted::new(statement::encode_token(&bytes, &signature.to_bytes())),
            expires_at_ms,
        })
    }

    /// Verification phase 1, before any repository lookup
    /// (SPEC-HTTP-OBJECTS §6): strict token decode, the statement rules, a
    /// key id in the verification set (the active key, or a retired key
    /// before `retired_at_ms + ttl_ms`) and the strict Ed25519 signature
    /// over `blake3(statement)`.
    ///
    /// # Errors
    /// [`TokenRejected`] for any failure; the reason never escapes.
    pub fn precheck(&self, token: &str, now_ms: i64) -> Result<Prechecked, TokenRejected> {
        let (bytes, signature) = statement::decode_token(token).map_err(|_| TokenRejected)?;
        let statement = UrlTokenStatement::parse(&bytes).map_err(|_| TokenRejected)?;
        let key = self
            .keys
            .verifying_key(&statement.key_id(), now_ms, self.ttl_ms)
            .ok_or(TokenRejected)?;
        key.verify_strict(&hash(&bytes), &Signature::from_bytes(&signature))
            .map_err(|_| TokenRejected)?;
        Ok(Prechecked { statement })
    }
}

impl fmt::Debug for UrlTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UrlTokenConfig")
            .field("keys", &self.keys)
            .field("ttl_ms", &self.ttl_ms)
            .finish()
    }
}

/// A freshly minted token and its expiry. The token string is a
/// credential: [`MintedToken::expose`] reads it for the response; `Debug`
/// never shows it.
#[derive(Clone)]
pub struct MintedToken {
    token: Redacted,
    /// Expiry on the business clock, Unix epoch milliseconds.
    pub expires_at_ms: i64,
}

impl MintedToken {
    /// The token string, for the `IssueObjectUrl` response.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.token.expose()
    }
}

impl fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedToken")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// The one rejection every URL-token verification failure maps to: the
/// reason never survives to the client, so a private repository's
/// uniform `not_found` cannot identify which check failed
/// (SPEC-HTTP-OBJECTS §3 step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid URL token")]
pub struct TokenRejected;

/// A statement that passed [`UrlTokenConfig::precheck`]: syntax, key id
/// and signature verified, still unbound to the request. `Debug` shows
/// neither the token nor its claims.
pub struct Prechecked {
    statement: UrlTokenStatement,
}

impl fmt::Debug for Prechecked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prechecked").finish_non_exhaustive()
    }
}

/// What verification phase 2 binds a token to: the request's audience,
/// repository and target, each compared byte for byte.
#[derive(Debug)]
pub struct Binding<'a> {
    /// The deployment's auth v2 audience.
    pub audience: &'a str,
    /// The request's repository identity (STC §7.4).
    pub repository: &'a str,
    /// The target the request asks for.
    pub target: &'a UrlTarget,
}

/// A token bound to the request; the epoch comparison is all that is
/// left (§9.4).
#[derive(Debug, Clone, Copy)]
pub struct BoundToken {
    epoch: u64,
}

impl BoundToken {
    /// The epoch the token was minted at.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The last check: the token serves only while the stored epoch
    /// still equals the epoch it was minted at.
    ///
    /// # Errors
    /// [`TokenRejected`] on a mismatch.
    pub fn check_epoch(&self, stored: u64) -> Result<(), TokenRejected> {
        if self.epoch == stored {
            Ok(())
        } else {
            Err(TokenRejected)
        }
    }
}

impl Prechecked {
    /// Verification phase 2, before any stored-epoch read
    /// (SPEC-HTTP-OBJECTS §6): `audience`, `repository` and `target`
    /// equal the request's byte for byte, `now < expiry`, and
    /// `expiry - issued <= ttl_ms` — the configured lifetime, which may
    /// be shorter than the statement grammar's `MAX_TTL_MS` bound.
    ///
    /// # Errors
    /// [`TokenRejected`] for any failure.
    pub fn check_binding(
        self,
        binding: &Binding<'_>,
        now_ms: i64,
        ttl_ms: u64,
    ) -> Result<BoundToken, TokenRejected> {
        let statement = &self.statement;
        if statement.audience() != binding.audience
            || statement.repository() != binding.repository
            || statement.target() != binding.target
        {
            return Err(TokenRejected);
        }
        if now_ms >= statement.expiry_ms() {
            return Err(TokenRejected);
        }
        let lifetime = statement.expiry_ms().saturating_sub(statement.issued_ms());
        if lifetime > i64::try_from(ttl_ms).unwrap_or(i64::MAX) {
            return Err(TokenRejected);
        }
        Ok(BoundToken {
            epoch: statement.epoch(),
        })
    }
}

/// §9.4 verification for a serving path: [`UrlTokenConfig::precheck`],
/// then [`Prechecked::check_binding`], then exactly one `read_epoch`
/// call and the epoch comparison. `read_epoch` never runs when an
/// earlier phase fails — the stored-epoch read is the last step
/// (SPEC-HTTP-OBJECTS §6). A public repository ignores the result; that
/// choice belongs to the serving caller (SPEC-HTTP-OBJECTS §3 step 5).
///
/// # Errors
/// The outer `Err` is `read_epoch`'s own error — an infrastructure
/// failure, never confused with a rejection (SPEC-HTTP-OBJECTS §3: a
/// store failure is a 503, not a fabricated `not_found`). The inner
/// `Err` is the uniform [`TokenRejected`].
pub async fn verify<F, Fut, E>(
    cfg: &UrlTokenConfig,
    token: &str,
    binding: &Binding<'_>,
    now_ms: i64,
    read_epoch: F,
) -> Result<Result<(), TokenRejected>, E>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<u64, E>>,
{
    let bound = match cfg
        .precheck(token, now_ms)
        .and_then(|p| p.check_binding(binding, now_ms, cfg.ttl_ms()))
    {
        Ok(bound) => bound,
        Err(rejected) => return Ok(Err(rejected)),
    };
    Ok(bound.check_epoch(read_epoch().await?))
}
