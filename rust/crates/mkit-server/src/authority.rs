//! Deployment-authority generation statements (SPEC-SERVER §6.2.1).
//! The outer RPC is unsigned; this bounded statement is its authorization.

use crate::{
    ServerError,
    store::{Key, keys},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use mkit_core::{hash::hash, repo_identity::Namespace, write_auth::validate_audience};
use std::collections::BTreeSet;

/// Dedicated statement domain, independent of grants and hook requests.
pub const DOMAIN: &str = "mkit-authority-generation:v1";
/// Maximum signed statement wire size, before decoding or signature work.
pub const MAX_STATEMENT_BYTES: usize = 2048;
/// Maximum generation increase, computed without overflow.
pub const MAX_STEP: u64 = 1024;

/// A deployment-authority verification key with explicit namespace permission.
#[derive(Debug, Clone)]
pub struct AuthorityKey {
    /// Hook-style key identifier, 1–64 ASCII token bytes.
    pub key_id: String,
    /// Strict Ed25519 public key; never a namespace-owner trust fallback.
    pub public_key: [u8; 32],
    /// Exact self-certifying namespaces this key may fence.
    pub namespaces: BTreeSet<Namespace>,
}

/// Optional deployment fencing configuration. Construction validates all keys.
#[derive(Debug, Clone)]
pub struct AuthorityFence {
    keys: Vec<AuthorityKey>,
}

fn rejected() -> ServerError {
    ServerError::permission_denied("authority generation statement rejected")
}
fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn decimal(text: &str) -> Result<u64, ServerError> {
    text.parse::<u64>()
        .ok()
        .filter(|n| n.to_string() == text)
        .ok_or_else(rejected)
}

impl AuthorityFence {
    /// Validate a bounded set of dedicated keys, each with namespace permissions.
    ///
    /// # Errors
    /// Empty/oversized lists, malformed, weak or duplicate keys, and owner keys.
    pub fn new(keys: Vec<AuthorityKey>) -> Result<Self, ServerError> {
        if keys.is_empty() || keys.len() > 16 {
            return Err(rejected());
        }
        let mut ids = BTreeSet::new();
        let mut publics = BTreeSet::new();
        for key in &keys {
            let public = VerifyingKey::from_bytes(&key.public_key).map_err(|_| rejected())?;
            if !valid_id(&key.key_id)
                || !ids.insert(&key.key_id)
                || !publics.insert(key.public_key)
                || public.is_weak()
                || key.namespaces.is_empty()
                || key.namespaces.len() > 1024
                || key
                    .namespaces
                    .iter()
                    .any(|ns| matches!(ns,Namespace::Ed25519(owner) if owner == &key.public_key))
            {
                return Err(rejected());
            }
        }
        Ok(Self { keys })
    }

    /// All configured role keys, for adapter key separation.
    pub fn public_keys(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.keys.iter().map(|k| k.public_key)
    }

    /// Verify `<unpadded-base64url statement>.<unpadded-base64url signature>`.
    /// Fields: domain, key id, namespace, generation, audience, created, expiry,
    /// nonce; UTF-8, LF separated, no final LF. Signature covers BLAKE3(bytes).
    ///
    /// # Errors
    /// Every malformed, wrongly bound, expired or unauthorized statement.
    pub fn verify(
        &self,
        wire: &str,
        audience: &str,
        now_ms: i64,
    ) -> Result<AuthorityStatement, ServerError> {
        if wire.len() > MAX_STATEMENT_BYTES {
            return Err(rejected());
        }
        let (text, sig) = wire.split_once('.').ok_or_else(rejected)?;
        let decode = |s: &str| {
            let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| rejected())?;
            if URL_SAFE_NO_PAD.encode(&bytes) != s {
                return Err(rejected());
            }
            Ok(bytes)
        };
        let bytes = decode(text)?;
        let sig = decode(sig)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| rejected())?;
        let fields = text.split('\n').collect::<Vec<_>>();
        let [
            domain,
            id,
            namespace,
            generation,
            origin,
            created,
            expiry,
            nonce,
        ] = fields.as_slice()
        else {
            return Err(rejected());
        };
        let namespace = Namespace::parse(namespace).map_err(|_| rejected())?;
        let key = self
            .keys
            .iter()
            .find(|key| key.key_id == *id && key.namespaces.contains(&namespace))
            .ok_or_else(rejected)?;
        let created = decimal(created)?;
        let expiry = decimal(expiry)?;
        let now = u64::try_from(now_ms).map_err(|_| rejected())?;
        if *domain != DOMAIN
            || *origin != audience
            || validate_audience(origin).is_err()
            || expiry <= created
            || expiry - created > 300_000
            || now >= expiry
            || created > now.saturating_add(30_000)
            || nonce.len() != 64
            || !nonce.bytes().all(|b| matches!(b,b'0'..=b'9'|b'a'..=b'f'))
        {
            return Err(rejected());
        }
        let signature = Signature::from_slice(&sig).map_err(|_| rejected())?;
        VerifyingKey::from_bytes(&key.public_key)
            .map_err(|_| rejected())?
            .verify_strict(&hash(&bytes), &signature)
            .map_err(|_| rejected())?;
        Ok(AuthorityStatement {
            namespace,
            generation: decimal(generation)?,
        })
    }
}

/// Verified target of one idempotent generation transition.
#[derive(Debug, Clone)]
pub struct AuthorityStatement {
    /// Namespace authorized by the configured deployment key.
    pub namespace: Namespace,
    /// Target generation, bounded relative to stored state at the CAS.
    pub generation: u64,
}

/// Which independent integer a shared lease completion scan fences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FenceKind {
    Grant,
    Authority,
}
impl FenceKind {
    pub(crate) fn key(self) -> Key {
        match self {
            Self::Grant => keys::grant_epoch(),
            Self::Authority => keys::authority_generation(),
        }
    }
}

pub(crate) fn moved() -> ServerError {
    ServerError::permission_denied("namespace authority generation changed")
        .with_abort_cause(crate::error::AbortCause::EpochMismatch)
}
