//! Dedicated, versioned MACs for selected-ref structural continuation evidence.
#[cfg(feature = "http-objects")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mkit_core::hash::{Hash, from_hex};
#[cfg(feature = "http-objects")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

/// Domain-separated structural evidence; never a bearer authorization grant.
pub const DOMAIN: &str = "mkit-history-continuation:v1";
/// Bound stop-sensitive ancestry and parsing allocation across a paging chain.
pub const MAX_ANCESTORS: usize = 1024;
#[cfg(feature = "http-objects")]
const MAX_PAYLOAD: usize = 256 * 1024;
#[cfg(feature = "http-objects")]
const MAX_TOKEN: usize = MAX_PAYLOAD * 4 / 3 + 48;

/// Invalid configuration; secret inputs never appear in diagnostics.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid history continuation configuration")]
pub struct ConfigError;

/// Deployment realm, dedicated active secret and fixed maximum lifetime.
/// Replacing the active key immediately invalidates outstanding continuations.
#[derive(Clone)]
pub struct HistoryTokenConfig {
    secret: std::sync::Arc<Zeroizing<Hash>>,
    realm: String,
    ttl_ms: u64,
}
impl core::fmt::Debug for HistoryTokenConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HistoryTokenConfig")
            .field("realm", &self.realm)
            .field("ttl_ms", &self.ttl_ms)
            .finish_non_exhaustive()
    }
}
impl HistoryTokenConfig {
    /// Derived public role key, reserved against client/owner authentication.
    #[must_use]
    pub fn public_key(&self) -> Hash {
        ed25519_dalek::SigningKey::from_bytes(&self.secret)
            .verifying_key()
            .to_bytes()
    }
    /// Reject published role material that exposes or reuses the MAC secret.
    /// # Errors
    /// A raw or derived cross-role collision.
    pub fn check_public_roles(&self, public: &[Hash]) -> Result<(), ConfigError> {
        if public
            .iter()
            .any(|p| *p == self.public_key() || bool::from(p.ct_eq(&**self.secret)))
        {
            return Err(ConfigError);
        }
        Ok(())
    }
    /// Constant-time role-separation check without exposing secret material.
    #[must_use]
    pub fn contains_secret(&self, candidate: &Hash) -> bool {
        bool::from(candidate.ct_eq(&**self.secret))
    }
    /// Configure one dedicated secret. Realm must uniquely identify the backend.
    /// # Errors
    /// Empty/oversized realm, zero secret, or lifetime outside 1–900000 ms.
    pub fn new(secret: Zeroizing<Hash>, realm: String, ttl_ms: u64) -> Result<Self, ConfigError> {
        if realm.is_empty()
            || realm.len() > 2048
            || *secret == [0; 32]
            || !(1..=900_000).contains(&ttl_ms)
        {
            return Err(ConfigError);
        }
        Ok(Self {
            secret: std::sync::Arc::new(secret),
            realm,
            ttl_ms,
        })
    }
    /// Parse the deployment key-file pattern: one `active <64 hex>` line.
    /// Blank lines/comments are allowed. No retired key remains redeemable.
    /// The owned source text is wiped after parsing.
    /// # Errors
    /// Invalid key-file grammar or configuration.
    pub fn parse_key_file_secret(
        text: String,
        realm: String,
        ttl_ms: u64,
    ) -> Result<Self, ConfigError> {
        let text = Zeroizing::new(text);
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        let fields: Vec<_> = lines
            .next()
            .ok_or(ConfigError)?
            .split_whitespace()
            .collect();
        let ["active", hex] = fields.as_slice() else {
            return Err(ConfigError);
        };
        let secret = Zeroizing::new(from_hex(hex).map_err(|_| ConfigError)?);
        if lines.next().is_some() {
            return Err(ConfigError);
        }
        Self::new(secret, realm, ttl_ms)
    }
    #[cfg(feature = "http-objects")]
    pub(crate) fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }
    #[cfg(feature = "http-objects")]
    pub(crate) fn realm(&self) -> &str {
        &self.realm
    }
    pub(crate) fn check_roles(
        &self,
        cfg: &crate::pipeline::PipelineConfig,
    ) -> Result<(), ConfigError> {
        use crate::policy::NamespacePolicy;
        use mkit_core::repo_identity::Namespace;
        match &cfg.addressing {
            crate::Addressing::Single { repo } => {
                if let Ok(Namespace::Ed25519(key)) = Namespace::parse(repo.namespace.as_str()) {
                    self.check_public_roles(&[key])?;
                }
            }
            crate::Addressing::Multi(multi) => {
                if let NamespacePolicy::Allowlist(namespaces) = &multi.namespace_policy {
                    for namespace in namespaces {
                        if let Namespace::Ed25519(key) = namespace {
                            self.check_public_roles(&[*key])?;
                        }
                    }
                }
            }
        }
        let secret: &Hash = &self.secret;
        let public = self.public_key();
        if cfg
            .ticket_keys
            .as_ref()
            .is_some_and(|keys| keys.contains_ed25519_public(&public))
            || cfg.url_tokens.as_ref().is_some_and(|t| {
                t.keys().contains_secret(secret)
                    || t.keys().public_keys().any(|p| p == public || p == *secret)
            })
            || cfg
                .scanner_retrieval
                .as_ref()
                .is_some_and(|s| s.check_role_keys(&[public], &[*secret]).is_err())
            || cfg
                .admin_keys
                .iter()
                .any(|p| *p == public || bool::from(p.ct_eq(secret)))
            || cfg
                .authority_fence
                .as_ref()
                .is_some_and(|f| f.public_keys().any(|p| p == public || p == *secret))
            || cfg.receipt_publication.as_ref().is_some_and(|r| {
                r.public_keys()
                    .iter()
                    .any(|p| *p == public || *p == *secret)
            })
        {
            return Err(ConfigError);
        }
        Ok(())
    }
    #[cfg(feature = "http-objects")]
    fn mac(&self, payload: &[u8]) -> Hash {
        let key = Zeroizing::new(blake3::derive_key(DOMAIN, &**self.secret));
        *blake3::keyed_hash(&key, payload).as_bytes()
    }
    #[cfg(feature = "http-objects")]
    pub(crate) fn mint(&self, claims: &Claims) -> Result<String, ()> {
        let payload = serde_json::to_vec(claims).map_err(|_| ())?;
        if payload.len() > MAX_PAYLOAD {
            return Err(());
        }
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(self.mac(&payload))
        ))
    }
    #[cfg(feature = "http-objects")]
    pub(crate) fn verify(&self, token: &str) -> Result<Claims, ()> {
        if token.len() > MAX_TOKEN {
            return Err(());
        }
        let (payload, mac) = token.split_once('.').ok_or(())?;
        if mac.len() != 43 {
            return Err(());
        }
        let mac = URL_SAFE_NO_PAD.decode(mac).map_err(|_| ())?;
        let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| ())?;
        if payload.len() > MAX_PAYLOAD || !bool::from(self.mac(&payload).as_slice().ct_eq(&mac)) {
            return Err(());
        }
        // Authenticate before allocating the bounded graph/strings.
        let claims: Claims = serde_json::from_slice(&payload).map_err(|_| ())?;
        if claims.version != 1
            || claims.purpose != DOMAIN
            || claims.realm != self.realm
            || claims.ancestry.is_empty()
            || claims.ancestry.len() > MAX_ANCESTORS
            || claims.ancestry.last() != Some(&claims.cursor)
            || claims.issued >= claims.expires
            || claims.expires - claims.issued > self.ttl_ms
        {
            return Err(());
        }
        Ok(claims)
    }
}

#[cfg(feature = "http-objects")]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claims {
    pub version: u8,
    pub purpose: String,
    pub realm: String,
    pub namespace: String,
    pub repository: String,
    pub reference: String,
    pub writer: bool,
    pub credential: Hash,
    pub anchor: Hash,
    pub publication: crate::store::publication::Publication,
    pub security: Hash,
    pub issued: u64,
    pub expires: u64,
    pub cursor: Hash,
    pub chain: Hash,
    pub ancestry: Vec<Hash>,
}

#[cfg(all(test, feature = "http-objects"))]
mod tests {
    use super::*;
    fn config(seed: u8) -> HistoryTokenConfig {
        HistoryTokenConfig::new(Zeroizing::new([seed; 32]), "realm".into(), 1000)
            .expect("valid dedicated key fixture")
    }
    fn claims() -> Claims {
        Claims {
            version: 1,
            purpose: DOMAIN.into(),
            realm: "realm".into(),
            namespace: "namespace".into(),
            repository: "repo".into(),
            reference: "refs/heads/main".into(),
            writer: false,
            credential: [0; 32],
            anchor: [1; 32],
            publication: crate::store::publication::Publication::default(),
            security: [2; 32],
            issued: 1,
            expires: 1001,
            cursor: [1; 32],
            chain: [3; 32],
            ancestry: vec![[1; 32]],
        }
    }
    #[test]
    fn dedicated_history_mac_rejects_rotation_other_purposes_and_noncanonical_encodings() {
        let cfg = config(91);
        let token = cfg.mint(&claims()).unwrap();
        assert!(cfg.verify(&token).is_ok());
        assert!(config(92).verify(&token).is_err());
        for bad in [
            format!("{token}="),
            format!("{token}."),
            "=".repeat(MAX_TOKEN + 1),
        ] {
            assert!(cfg.verify(&bad).is_err());
        }
        let mut foreign = claims();
        foreign.purpose = crate::url_token::DOMAIN.into();
        assert!(cfg.verify(&cfg.mint(&foreign).unwrap()).is_err());
        let (payload, _) = token.split_once('.').unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        let raw_mac = blake3::keyed_hash(&[91; 32], &bytes);
        assert!(
            cfg.verify(&format!(
                "{payload}.{}",
                URL_SAFE_NO_PAD.encode(raw_mac.as_bytes())
            ))
            .is_err()
        );
        let mut oversized = claims();
        oversized.ancestry = vec![[1; 32]; MAX_ANCESTORS + 1];
        assert!(cfg.verify(&cfg.mint(&oversized).unwrap()).is_err());
        assert!(!format!("{cfg:?}").contains(&mkit_core::hash::to_hex(&[91; 32])));
    }
    #[test]
    fn history_key_files_and_cross_role_reuse_fail_closed() {
        let cfg = config(91);
        assert!(cfg.check_public_roles(&[cfg.public_key()]).is_err());
        assert!(cfg.check_public_roles(&[[91; 32]]).is_err());
        assert!(cfg.check_public_roles(&[[90; 32]]).is_ok());
        assert!(HistoryTokenConfig::new(Zeroizing::new([0; 32]), "realm".into(), 1000).is_err());
        assert!(
            HistoryTokenConfig::parse_key_file_secret(
                format!("active {}", mkit_core::hash::to_hex(&[91; 32])),
                "realm".into(),
                1000
            )
            .is_ok()
        );
        assert!(
            HistoryTokenConfig::parse_key_file_secret(
                format!(
                    "active {}\nretired {} 1",
                    mkit_core::hash::to_hex(&[91; 32]),
                    mkit_core::hash::to_hex(&[92; 32])
                ),
                "realm".into(),
                1000
            )
            .is_err()
        );
        let mut pipeline = crate::pipeline::PipelineConfig::new(
            crate::Addressing::Multi(crate::MultiAddressing::new()),
            crate::pipeline::AuthMode::Open,
            crate::upload::UploadLimits::new(1024, 1),
        );
        pipeline.ticket_keys =
            Some(crate::upload::token::TicketKeys::new(vec![("ticket".into(), [91; 32])]).unwrap());
        assert!(cfg.check_roles(&pipeline).is_err());
    }
}
