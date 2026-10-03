//! Required receipt-and-notice role key publication for takedown deployments.
use crate::{Code, ServerError};
use mkit_core::hash::{hash, to_hex};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptEntry {
    key_id: String,
    alg: String,
    public_key: String,
    not_before_ms: Option<String>,
    not_after_ms: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    version: u32,
    keys: Vec<ReceiptEntry>,
}

/// Validated public configuration; private key bytes never enter diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PublicationConfig {
    /// Current raw Ed25519 public key.
    pub public_key: [u8; 32],
    /// BLAKE3 digest of the public key, without a prefix.
    pub key_id: String,
    /// Exact public key-list JSON returned at the well-known endpoint.
    pub key_list: String,
    keys: Vec<[u8; 32]>,
}
impl PublicationConfig {
    /// Validate the private seed and published list required by §14.7.
    /// # Errors
    /// Invalid keys, duplicate identities, bounds or a missing signing key.
    pub fn parse(seed_hex: &str, list: &str) -> Result<Self, ServerError> {
        let invalid = || {
            ServerError::new(
                Code::InvalidArgument,
                "invalid receipt-and-notice key configuration",
            )
        };
        let seed =
            zeroize::Zeroizing::new(crate::admin::auth::hex::<32>(seed_hex).ok_or_else(invalid)?);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = to_hex(&hash(&public_key));
        if list.len() > 65_536 {
            return Err(invalid());
        }
        let parsed: List = serde_json::from_str(list).map_err(|_| invalid())?;
        if parsed.version != 1 || parsed.keys.is_empty() || parsed.keys.len() > 128 {
            return Err(invalid());
        }
        let mut key_ids = std::collections::BTreeSet::new();
        let mut present = false;
        let mut keys = Vec::new();
        for entry in parsed.keys {
            let public = crate::admin::auth::hex::<32>(&entry.public_key).ok_or_else(invalid)?;
            ed25519_dalek::VerifyingKey::from_bytes(&public).map_err(|_| invalid())?;
            if entry.alg != "ed25519"
                || entry.key_id != to_hex(&hash(&public))
                || !key_ids.insert(entry.key_id.clone())
            {
                return Err(invalid());
            }
            let bound = |value: Option<String>| -> Result<Option<i64>, ServerError> {
                value
                    .map(|s| {
                        s.parse::<i64>()
                            .ok()
                            .filter(|v| v.to_string() == s)
                            .ok_or_else(invalid)
                    })
                    .transpose()
            };
            let before = bound(entry.not_before_ms)?;
            let after = bound(entry.not_after_ms)?;
            if before.zip(after).is_some_and(|(b, a)| b >= a) {
                return Err(invalid());
            }
            present |= entry.key_id == key_id;
            keys.push(public);
        }
        if !present {
            return Err(invalid());
        }
        Ok(Self {
            public_key,
            key_id,
            key_list: list.into(),
            keys,
        })
    }
    /// Every published role key, including retired keys forbidden for writers.
    #[must_use]
    pub fn public_keys(&self) -> &[[u8; 32]] {
        &self.keys
    }
}
