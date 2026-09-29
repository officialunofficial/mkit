//! Request signing (SPEC-SERVER §7.1).

use core::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use zeroize::Zeroizing;

use crate::rt::{MaybeSend, MaybeSync};

/// The literal domain separator of the hook key use.
pub const DOMAIN: &str = "mkit-hook:v1";
/// The longest permitted validity interval.
pub const MAX_VALIDITY: Duration = Duration::from_mins(5);
/// The validity interval used unless configured otherwise.
pub const DEFAULT_VALIDITY: Duration = Duration::from_millis(DEFAULT_VALIDITY_MS);
const DEFAULT_VALIDITY_MS: u64 = 60_000;

/// A signer setting the spec refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// A key id must be 1-64 bytes of `[A-Za-z0-9._-]`.
    #[error("hook key id must be 1-64 bytes of [A-Za-z0-9._-]")]
    KeyId,
    /// The validity interval must be positive and at most 300,000 ms.
    #[error("hook signature validity must be 1 ms to 300 s")]
    Validity,
    /// The clock reads before the epoch, which no header can express.
    #[error("hook clock is before the Unix epoch")]
    Clock,
}

/// The dedicated hook signing key. It must not be a key used for `mkit-write:v2`,
/// grants, receipts or administration.
pub struct HookSigner {
    key_id: String,
    seed: Zeroizing<[u8; 32]>,
    validity_ms: i64,
}

impl core::fmt::Debug for HookSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HookSigner")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl HookSigner {
    /// A signer for `key_id` over the Ed25519 `seed`, valid for
    /// [`DEFAULT_VALIDITY`].
    ///
    /// # Errors
    /// [`SignerError::KeyId`] for a key id outside the spec's grammar.
    pub fn new(key_id: impl Into<String>, seed: Zeroizing<[u8; 32]>) -> Result<Self, SignerError> {
        let key_id = key_id.into();
        let valid = (1..=64).contains(&key_id.len())
            && key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !valid {
            return Err(SignerError::KeyId);
        }
        Ok(Self {
            key_id,
            seed,
            validity_ms: i64::try_from(DEFAULT_VALIDITY_MS).unwrap_or(60_000),
        })
    }

    /// Set the validity interval each signature carries.
    ///
    /// # Errors
    /// [`SignerError::Validity`] outside 1 ms to [`MAX_VALIDITY`].
    pub fn with_validity(mut self, validity: Duration) -> Result<Self, SignerError> {
        if validity.is_zero() || validity > MAX_VALIDITY {
            return Err(SignerError::Validity);
        }
        self.validity_ms =
            i64::try_from(validity.as_millis()).map_err(|_| SignerError::Validity)?;
        Ok(self)
    }

    /// The eight §7.1 headers for one attempt: `created_ms` and the fresh
    /// `nonce` are supplied so a test can reproduce a vector.
    ///
    /// # Errors
    /// [`SignerError::Clock`] for a negative `created_ms`.
    pub fn headers(
        &self,
        audience: &str,
        procedure: &str,
        body: &[u8],
        created_ms: i64,
        nonce: &[u8; 32],
    ) -> Result<Vec<(&'static str, String)>, SignerError> {
        if created_ms < 0 {
            return Err(SignerError::Clock);
        }
        let expires_ms = created_ms.saturating_add(self.validity_ms);
        let digest = format!("body:{}", to_hex(&hash(body)));
        let nonce = to_hex_bytes(nonce);
        let canonical = [
            DOMAIN,
            &self.key_id,
            audience,
            procedure,
            &digest,
            &created_ms.to_string(),
            &expires_ms.to_string(),
            &nonce,
        ]
        .join("\n");
        let key = SigningKey::from_bytes(&self.seed);
        let signature = key.sign(&hash(canonical.as_bytes()));
        Ok(vec![
            ("X-Mkit-Hook-Version", "1".to_owned()),
            ("X-Mkit-Hook-Key-Id", self.key_id.clone()),
            ("X-Mkit-Hook-Audience", audience.to_owned()),
            ("X-Mkit-Hook-Created-At", created_ms.to_string()),
            ("X-Mkit-Hook-Expires-At", expires_ms.to_string()),
            ("X-Mkit-Hook-Nonce", nonce),
            ("X-Mkit-Hook-Digest", digest),
            ("X-Mkit-Hook-Signature", to_hex_bytes(&signature.to_bytes())),
        ])
    }
}

/// The source of the fresh 32-byte nonce every attempt carries.
pub trait NonceSource: MaybeSend + MaybeSync {
    /// Fill `nonce` with 32 fresh random bytes; `false` on failure.
    fn fill(&self, nonce: &mut [u8; 32]) -> bool;
}

/// The operating system's CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsNonces;

impl NonceSource for OsNonces {
    fn fill(&self, nonce: &mut [u8; 32]) -> bool {
        getrandom::fill(nonce).is_ok()
    }
}
