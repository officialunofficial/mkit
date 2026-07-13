//! `mkit_transport_connect::EnvelopeSigner` adapters over the SAME signer
//! resolution `mkit commit` uses (`cfg.signer` == `""`/`"legacy"` -> the
//! repo key file; `"keystore"` -> a keystore backend), so `mkit push`'s
//! write-envelope auth authenticates with the user's existing commit
//! identity rather than a parallel key path. See
//! `remote_dispatch::envelope_signer_from_config`, the sole caller.
//!
//! Both signers sign the raw 32-byte envelope digest directly — no
//! SPEC-SIGNING domain prefix — matching
//! `apps/vcs-worker`/`apps/repo-worker`'s envelope contract exactly (see
//! `mkit-transport-connect::envelope`'s module docs).

use std::sync::Mutex;

use mkit_attest::{RepoKeySigner, Signer as AttestSigner};
use mkit_core::hash::to_hex_bytes;
use mkit_core::sign::KeyPair;
use mkit_keystore::{KeyRef, KeySelector, KeySigner, open_backend};
use mkit_transport_connect::EnvelopeSigner;

use crate::config::Config;

/// `cfg.signer = ""` / `"legacy"`: the same repo-key-file `KeyPair`
/// `mkit commit` loads via `crate::commands::commit::load_signing_key`,
/// signed through the EXISTING `mkit_attest::RepoKeySigner` — its `sign`
/// already signs the given bytes directly with no extra domain prefix
/// ("the PAE's own `\"DSSEv1 \"` prefix is the domain separator" per its
/// own doc comment), which is exactly the plain-Ed25519-over-digest
/// contract the write envelope needs. Reusing it means this module adds
/// no new raw-`ed25519-dalek` call site to mkit-cli.
pub(crate) struct RepoKeyEnvelopeSigner {
    public_key_hex: String,
    // `Signer::sign` takes `&mut self`; `EnvelopeSigner::sign_hex` (called
    // through `Arc<dyn EnvelopeSigner>` from an async transport) only
    // gets `&self` — the `Mutex` bridges the two. `RepoKeySigner` itself
    // has no real mutable state (each `sign` call constructs a fresh
    // `SigningKey` from the held seed), so contention here is never
    // meaningful.
    inner: Mutex<RepoKeySigner>,
}

impl RepoKeyEnvelopeSigner {
    pub(crate) fn new(kp: KeyPair) -> Self {
        let public_key_hex = to_hex_bytes(&kp.public.0);
        Self {
            public_key_hex,
            inner: Mutex::new(RepoKeySigner::new(kp)),
        }
    }
}

impl EnvelopeSigner for RepoKeyEnvelopeSigner {
    fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "repo-key signer mutex poisoned".to_owned())?;
        let sig = guard.sign(message).map_err(|e| e.to_string())?;
        Ok(to_hex_bytes(&sig))
    }
}

/// `cfg.signer = "keystore"`: `cfg.key.ed25519_ref_or_fallback()` opened
/// via `mkit-keystore`, mirroring
/// `crate::commands::commit::load_keystore_commit_signer` exactly.
///
/// `KeySigner::sign` takes `&mut self`, but `EnvelopeSigner::sign_hex`
/// (called through `Arc<dyn EnvelopeSigner>` from an async transport) only
/// gets `&self` — a `Mutex` bridges the two, matching the interior
/// mutability every other `Arc`-shared, `&mut self`-signing wrapper in
/// this codebase needs (e.g. `mkit-attest`'s `ExternalSigner` conversation
/// state).
pub(crate) struct KeystoreEnvelopeSigner {
    public_key_hex: String,
    signer: Mutex<Box<dyn KeySigner>>,
}

impl KeystoreEnvelopeSigner {
    pub(crate) fn open(cfg: &Config) -> Result<Self, String> {
        let key_ref = cfg
            .key
            .ed25519_ref_or_fallback()
            .parse::<KeyRef>()
            .map_err(|e| format!("key.ed25519_ref: {e}"))?;
        let store =
            open_backend(key_ref.backend()).map_err(|e| format!("keystore backend: {e}"))?;
        let selector = KeySelector::new(
            key_ref.label().to_owned(),
            Some(mkit_keystore::Algorithm::Ed25519),
        )
        .map_err(|e| format!("key.ed25519_ref: {e}"))?;
        let opener = store.opener().ok_or_else(|| {
            format!(
                "keystore backend `{}` does not support opening keys",
                key_ref.backend()
            )
        })?;
        let signer = opener.open(&selector).map_err(|e| match e {
            mkit_keystore::Error::KeyNotFound(_) => format!(
                "missing keystore signing key for algorithm ed25519 — run `mkit key generate --backend {} --algorithm ed25519 --label <label>` first: {e}",
                key_ref.backend()
            ),
            other => format!("keystore signing key for algorithm ed25519: {other}"),
        })?;
        let public = signer
            .public_key()
            .map_err(|e| format!("keystore public key: {e}"))?;
        if public.as_bytes().len() != 32 {
            return Err(format!(
                "keystore Ed25519 public key must be 32 bytes, got {}",
                public.as_bytes().len()
            ));
        }
        Ok(Self {
            public_key_hex: to_hex_bytes(public.as_bytes()),
            signer: Mutex::new(signer),
        })
    }
}

impl EnvelopeSigner for KeystoreEnvelopeSigner {
    fn public_key_hex(&self) -> String {
        self.public_key_hex.clone()
    }

    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        let mut guard = self
            .signer
            .lock()
            .map_err(|_| "keystore signer mutex poisoned".to_owned())?;
        // `KeySigner::sign`'s own contract: "Ed25519 signers return the
        // 64-byte RFC 8032 signature over `msg`" — raw sign, no domain
        // digest applied, exactly what the envelope needs.
        let sig = guard.sign(message).map_err(|e| e.to_string())?;
        if sig.len() != 64 {
            return Err(format!(
                "keystore Ed25519 signature must be 64 bytes, got {}",
                sig.len()
            ));
        }
        Ok(to_hex_bytes(&sig))
    }
}
