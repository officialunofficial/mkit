//! Verifying a signed hook request: the hook service's side of SPEC-SERVER
//! §7.1, for a service that receives what [`HookSigner`](super::HookSigner)
//! sends.
//!
//! [`HookVerifier`] depends only on the hash, the signature scheme and `std`:
//! no server runtime, so a Rust hook implementer can use it (WP-3.7b, MKIT-67,
//! relocates it beside the signer and the `hooks.v1` messages). It performs
//! every check §7.1 lists: the eight headers and their canonical forms, the
//! key id against the key list (§7.2) with its validity bounds, the audience,
//! the validity window, the digest of the exact body bytes, the strict
//! Ed25519 signature over the BLAKE3 of the canonical string, and, when asked
//! to, replay of a nonce inside its window.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use ed25519_dalek::{Signature, VerifyingKey};
use mkit_core::hash::{hash, to_hex};
use serde::Deserialize;

use super::sign::{DOMAIN, MAX_VALIDITY};

/// How far the sender's clock may lead the receiver's (SPEC-SERVER §7.1).
pub const MAX_CLOCK_LEAD_MS: i64 = 30_000;

/// One key of a §7.2 key list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierKey {
    /// The key id (`[A-Za-z0-9._-]`, 1-64 bytes).
    pub key_id: String,
    /// The Ed25519 public key.
    pub public_key: [u8; 32],
    /// The key is not valid for requests created before this epoch
    /// millisecond, if set.
    pub not_before_ms: Option<i64>,
    /// The key is not valid for requests created after this epoch
    /// millisecond, if set.
    pub not_after_ms: Option<i64>,
}

impl VerifierKey {
    /// A key with no validity bounds.
    #[must_use]
    pub fn new(key_id: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            key_id: key_id.into(),
            public_key,
            not_before_ms: None,
            not_after_ms: None,
        }
    }

    /// The keys of a §7.2 key-list JSON document.
    ///
    /// # Errors
    /// [`KeyListError`] for anything the format refuses: another `version` or
    /// `alg`, a public key that is not 64 lowercase hex digits, a bound that
    /// is not a decimal `int64` string, a key id outside the §7.1 grammar, or
    /// a repeated key id.
    pub fn parse_list(json: &str) -> Result<Vec<Self>, KeyListError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Entry {
            key_id: String,
            alg: String,
            public_key: String,
            not_before_ms: Option<String>,
            not_after_ms: Option<String>,
        }
        #[derive(Deserialize)]
        struct List {
            version: u32,
            keys: Vec<Entry>,
        }
        let list: List = serde_json::from_str(json).map_err(|_| KeyListError("malformed JSON"))?;
        if list.version != 1 {
            return Err(KeyListError("unsupported key-list version"));
        }
        let bound = |value: Option<String>| -> Result<Option<i64>, KeyListError> {
            value
                .map(|text| {
                    text.parse::<i64>()
                        .ok()
                        .filter(|n| n.to_string() == text)
                        .ok_or(KeyListError(
                            "a validity bound is not a decimal int64 string",
                        ))
                })
                .transpose()
        };
        let mut keys: Vec<Self> = Vec::with_capacity(list.keys.len());
        for entry in list.keys {
            if entry.alg != "ed25519" {
                return Err(KeyListError("unsupported key algorithm"));
            }
            if !valid_key_id(&entry.key_id) {
                return Err(KeyListError("key id outside [A-Za-z0-9._-], 1-64 bytes"));
            }
            if keys.iter().any(|known| known.key_id == entry.key_id) {
                return Err(KeyListError("repeated key id"));
            }
            let public_key = lower_hex_32(&entry.public_key)
                .ok_or(KeyListError("public key is not 64 lowercase hex digits"))?;
            keys.push(Self {
                key_id: entry.key_id,
                public_key,
                not_before_ms: bound(entry.not_before_ms)?,
                not_after_ms: bound(entry.not_after_ms)?,
            });
        }
        Ok(keys)
    }
}

/// A refused key list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid hook key list: {0}")]
pub struct KeyListError(&'static str);

/// Why a request failed verification. The text is fixed and never quotes the
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// A required `X-Mkit-Hook-*` header is absent or sent twice.
    #[error("missing or repeated hook header {0}")]
    Header(&'static str),
    /// `X-Mkit-Hook-Version` is not `1`.
    #[error("unsupported hook signature version")]
    Version,
    /// A header value is not in its canonical form.
    #[error("hook header {0} is not canonical")]
    Malformed(&'static str),
    /// The key id is not in the key list.
    #[error("unknown hook key id")]
    UnknownKey,
    /// The request was created outside the key's validity bounds.
    #[error("hook key not valid at the request's creation time")]
    KeyBounds,
    /// The audience is not this hook service's origin.
    #[error("audience is not this hook service's origin")]
    Audience,
    /// The validity interval is not positive, or exceeds 300,000 ms.
    #[error("hook validity interval out of range")]
    Interval,
    /// The request was created more than 30 s ahead of this clock.
    #[error("hook request created in the future")]
    ClockLead,
    /// The request has expired.
    #[error("hook request expired")]
    Expired,
    /// The digest does not match the body.
    #[error("hook digest does not match the body")]
    Digest,
    /// The signature does not verify.
    #[error("hook signature does not verify")]
    Signature,
    /// The nonce was already used inside its window.
    #[error("hook nonce replayed")]
    Replay,
}

/// A request that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verified {
    /// The key that signed it.
    pub key_id: String,
    /// Its nonce, 64 lowercase hex digits.
    pub nonce: String,
    /// Epoch milliseconds it was created.
    pub created_ms: i64,
    /// Epoch milliseconds it expires.
    pub expires_ms: i64,
}

/// Verifies signed hook requests for one hook service.
pub struct HookVerifier {
    audience: String,
    keys: Vec<VerifierKey>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// Nonces seen, each until its request's expiry; `None`: no replay check.
    replay: Option<Mutex<HashMap<String, i64>>>,
}

impl core::fmt::Debug for HookVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HookVerifier")
            .field("audience", &self.audience)
            .field("keys", &self.keys.len())
            .field("replay", &self.replay.is_some())
            .finish_non_exhaustive()
    }
}

fn valid_key_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if !is_lower_hex(value, 64) {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(value.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Base-10 ASCII digits, no sign, no leading zero (a lone `0` is allowed).
fn decimal(value: &str) -> Option<i64> {
    let canonical = !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'));
    if canonical { value.parse().ok() } else { None }
}

impl HookVerifier {
    /// A verifier for the hook service whose canonical origin is `audience`,
    /// trusting `keys`, reading time from `clock` (epoch milliseconds).
    #[must_use]
    pub fn new(
        audience: impl Into<String>,
        keys: Vec<VerifierKey>,
        clock: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> Self {
        Self {
            audience: audience.into(),
            keys,
            clock: Arc::new(clock),
            replay: None,
        }
    }

    /// Also reject a nonce seen before, until its request's window closes
    /// (SPEC-SERVER §7.1 step 5). The set is in memory: a hook that restarts
    /// forgets it, and one that runs several instances must share one.
    #[must_use]
    pub fn with_replay_protection(mut self) -> Self {
        self.replay = Some(Mutex::new(HashMap::new()));
        self
    }

    /// Verify one request: `procedure` is the Connect path it arrived on,
    /// `headers` every header it carried (names compare case-insensitively),
    /// and `body` the exact bytes received.
    ///
    /// # Errors
    /// The first [`VerifyError`] found. A request that fails is never
    /// remembered for replay.
    pub fn verify(
        &self,
        procedure: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Verified, VerifyError> {
        let get = |name: &'static str| -> Result<&str, VerifyError> {
            let mut found = headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| *v);
            match (found.next(), found.next()) {
                (Some(value), None) => Ok(value),
                _ => Err(VerifyError::Header(name)),
            }
        };
        // Every header first, before the body is looked at (§7.1).
        let version = get("X-Mkit-Hook-Version")?;
        let key_id = get("X-Mkit-Hook-Key-Id")?;
        let audience = get("X-Mkit-Hook-Audience")?;
        let created = get("X-Mkit-Hook-Created-At")?;
        let expires = get("X-Mkit-Hook-Expires-At")?;
        let nonce = get("X-Mkit-Hook-Nonce")?;
        let digest = get("X-Mkit-Hook-Digest")?;
        let signature = get("X-Mkit-Hook-Signature")?;
        if version != "1" {
            return Err(VerifyError::Version);
        }
        let created_ms =
            decimal(created).ok_or(VerifyError::Malformed("X-Mkit-Hook-Created-At"))?;
        let expires_ms =
            decimal(expires).ok_or(VerifyError::Malformed("X-Mkit-Hook-Expires-At"))?;
        if !is_lower_hex(nonce, 64) {
            return Err(VerifyError::Malformed("X-Mkit-Hook-Nonce"));
        }
        if !valid_key_id(key_id) {
            return Err(VerifyError::Malformed("X-Mkit-Hook-Key-Id"));
        }
        let signature_bytes = if is_lower_hex(signature, 128) {
            let mut out = [0u8; 64];
            for (byte, pair) in out.iter_mut().zip(signature.as_bytes().chunks(2)) {
                *byte = u8::from_str_radix(core::str::from_utf8(pair).unwrap_or("zz"), 16)
                    .map_err(|_| VerifyError::Malformed("X-Mkit-Hook-Signature"))?;
            }
            out
        } else {
            return Err(VerifyError::Malformed("X-Mkit-Hook-Signature"));
        };
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id == key_id)
            .ok_or(VerifyError::UnknownKey)?;
        if key.not_before_ms.is_some_and(|bound| created_ms < bound)
            || key.not_after_ms.is_some_and(|bound| created_ms > bound)
        {
            return Err(VerifyError::KeyBounds);
        }
        if audience != self.audience {
            return Err(VerifyError::Audience);
        }
        let now = (self.clock)();
        let max_ms = i64::try_from(MAX_VALIDITY.as_millis()).unwrap_or(i64::MAX);
        if expires_ms <= created_ms || expires_ms - created_ms > max_ms {
            return Err(VerifyError::Interval);
        }
        if created_ms > now.saturating_add(MAX_CLOCK_LEAD_MS) {
            return Err(VerifyError::ClockLead);
        }
        if expires_ms <= now {
            return Err(VerifyError::Expired);
        }
        if digest != format!("body:{}", to_hex(&hash(body))) {
            return Err(VerifyError::Digest);
        }
        let canonical = [
            DOMAIN, key_id, audience, procedure, digest, created, expires, nonce,
        ]
        .join("\n");
        VerifyingKey::from_bytes(&key.public_key)
            .and_then(|public| {
                public.verify_strict(
                    &hash(canonical.as_bytes()),
                    &Signature::from_bytes(&signature_bytes),
                )
            })
            .map_err(|_| VerifyError::Signature)?;
        if let Some(seen) = &self.replay {
            let mut seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
            seen.retain(|_, until| *until > now);
            match seen.entry(nonce.to_owned()) {
                std::collections::hash_map::Entry::Occupied(_) => return Err(VerifyError::Replay),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(expires_ms);
                }
            }
        }
        Ok(Verified {
            key_id: key_id.to_owned(),
            nonce: nonce.to_owned(),
            created_ms,
            expires_ms,
        })
    }
}
