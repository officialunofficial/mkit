use core::fmt;
use ed25519_dalek::{SigningKey, VerifyingKey};
use mkit_core::hash::{Hash, from_hex};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Invalid configuration. Never contains supplied keys or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid or conflicting scanner retrieval configuration")]
pub struct ConfigError;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct Key {
    pub id: String,
    pub secret: Zeroizing<Hash>,
    pub retired_at_ms: Option<u64>,
}

/// Dedicated active/retained MAC keys and the incoming scanner allowlist.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetrievalConfig {
    pub(super) keys: Vec<Key>,
    scanners: Vec<Hash>,
}

impl fmt::Debug for RetrievalConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetrievalConfig")
            .field(
                "key_ids",
                &self.keys.iter().map(|k| &k.id).collect::<Vec<_>>(),
            )
            .field("scanner_count", &self.scanners.len())
            .finish_non_exhaustive()
    }
}

fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
}

impl RetrievalConfig {
    /// Parse exactly one `active <id> <64 hex>` line, followed by up to 15
    /// `retained <id> <64 hex> <retired_at_ms>` lines. Scanner keys are
    /// 1–32 distinct, non-weak Ed25519 public keys, one per line.
    /// Blank lines and whole-line comments are ignored.
    ///
    /// # Errors
    /// Invalid grammar, duplicate/weak keys or cross-role reuse.
    pub fn parse(keys: &str, scanners: &str) -> Result<Self, ConfigError> {
        let mut parsed: Vec<Key> = Vec::new();
        let mut ids = BTreeSet::new();
        for line in lines(keys) {
            let fields: Vec<_> = line.split_whitespace().collect();
            let (id, secret, retired_at_ms) = match fields.as_slice() {
                ["active", id, secret] if parsed.is_empty() => (*id, *secret, None),
                ["retained", id, secret, at] if !parsed.is_empty() => {
                    let at_ms = at.parse::<u64>().map_err(|_| ConfigError)?;
                    if at_ms.to_string() != *at {
                        return Err(ConfigError);
                    }
                    (*id, *secret, Some(at_ms))
                }
                _ => return Err(ConfigError),
            };
            if id.is_empty()
                || id.len() > 32
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                || !ids.insert(id.to_owned())
                || parsed.len() >= 16
            {
                return Err(ConfigError);
            }
            let secret = Zeroizing::new(from_hex(secret).map_err(|_| ConfigError)?);
            if parsed.iter().any(|k| bool::from(k.secret.ct_eq(&*secret))) {
                return Err(ConfigError);
            }
            parsed.push(Key {
                id: id.to_owned(),
                secret,
                retired_at_ms,
            });
        }
        let mut public = Vec::new();
        for line in lines(scanners) {
            let key = from_hex(line).map_err(|_| ConfigError)?;
            let verifying = VerifyingKey::from_bytes(&key).map_err(|_| ConfigError)?;
            if public.len() >= 32 || verifying.is_weak() || public.contains(&key) {
                return Err(ConfigError);
            }
            public.push(key);
        }
        if parsed.is_empty() || public.is_empty() {
            return Err(ConfigError);
        }
        let config = Self {
            keys: parsed,
            scanners: public,
        };
        config.check_role_keys(&[], &[])?;
        Ok(config)
    }

    /// Incoming scanner keys, for authentication and deployment separation.
    pub fn scanner_keys(&self) -> impl Iterator<Item = Hash> + '_ {
        self.scanners.iter().copied()
    }

    /// Refuse reuse of any raw secret in another deployment role.
    ///
    /// # Errors
    /// Any active/retained MAC secret or scanner key equals the supplied key.
    pub fn check_secret(&self, secret: &Hash) -> Result<(), ConfigError> {
        self.check_role_keys(&[], &[*secret])
    }

    /// Compare all active/retained retrieval and scanner keys with role keys.
    /// Public comparisons include Ed25519 public keys derived from MAC secrets,
    /// so a signing seed reused as a MAC secret cannot evade startup checks.
    ///
    /// # Errors
    /// A cross-role collision, including between scanners and retrieval keys.
    pub fn check_role_keys(&self, public: &[Hash], seeds: &[Hash]) -> Result<(), ConfigError> {
        let derived: Vec<_> = self
            .keys
            .iter()
            .map(|k| SigningKey::from_bytes(&k.secret).verifying_key().to_bytes())
            .collect();
        for key in &self.keys {
            if seeds.iter().any(|s| bool::from(key.secret.ct_eq(s)))
                || public.contains(&*key.secret)
                || self.scanners.contains(&*key.secret)
            {
                return Err(ConfigError);
            }
        }
        if derived
            .iter()
            .any(|k| public.contains(k) || seeds.contains(k) || self.scanners.contains(k))
            || self.scanners.iter().any(|k| {
                public.contains(k)
                    || seeds.contains(k)
                    || seeds
                        .iter()
                        .any(|s| SigningKey::from_bytes(s).verifying_key().as_bytes() == k)
            })
        {
            return Err(ConfigError);
        }
        Ok(())
    }

    #[cfg(feature = "remote-hooks")]
    pub(crate) fn accepts(&self, public: &Hash) -> bool {
        self.scanners.contains(public)
    }
}
