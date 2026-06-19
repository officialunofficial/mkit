//! Factory helpers for building a [`Signer`] from CLI / config inputs.
//!
//! The attest / verify-attest commands each need to turn a
//! `(algorithm, signer_kind, Config)` quartet into a concrete
//! `Box<dyn Signer>`. Centralising the dispatch keeps the commands
//! thin and makes the algorithm -> signer-impl mapping a single place
//! to audit.
//!
//! Key material layout on disk (per `docs/SPEC-ATTESTATIONS.md` §6.1):
//!
//! * Ed25519 — path resolved from `cfg.signing_key`
//! (default `.mkit/keys/default.key`). Shared with the commit signer.
//! **Not** auto-generated — the caller must run
//! `mkit keygen` first, matching `mkit commit`'s contract. This is
//! the same property that closes the C1 attack surface (see
//! `docs/THREAT-MODEL.md`): no command silently creates a key file
//! from a path the config could control.
//! * secp256k1 / p256 — path resolved from
//! `attest.{secp256k1,p256}_key_path` (user-scoped only; default
//! `.mkit/keys/<algo>.key`). Raw 32-byte secret, mode 0600. Same
//! no-auto-generate contract; absent file → clear error.
//!
//! The `external` signer kind handles all three algorithms via a single
//! subprocess binary; the algorithm is recorded so verification can
//! dispatch the right crypto path without reparsing the keyid.

use std::path::Path;

use mkit_attest::{Algorithm, ExternalSigner, Signer};
use mkit_keystore::{KeyRef, KeySelector, open_backend};
use zeroize::Zeroizing;

use crate::config::Config;

/// Errors the factory surfaces. Mapped to CLI exit codes by the caller.
#[derive(Debug)]
pub enum FactoryError {
    /// Algorithm name (e.g. `"rsa"`) is not one of `ed25519`, `secp256k1`, `p256`.
    UnknownAlgorithm(String),
    /// `--signer` value is not one of `repo-key`, `external`, `keystore`.
    UnknownSignerKind(String),
    /// The per-algorithm keyfile is missing. Error message points the
    /// user at `mkit keygen --algorithm <algo>`.
    MissingKeyFile { algorithm: Algorithm, path: String },
    /// The selected keystore key is missing. Error message points the user at
    /// `mkit key generate --algorithm <algo> --label <label>`.
    MissingKeystoreKey {
        algorithm: Algorithm,
        backend: String,
        reason: String,
    },
    /// Keyfile exists but is not a 32-byte raw secret.
    InvalidKeyFile { path: String, reason: String },
    /// `attest.external_signer_path` is empty / relative / unusable.
    ExternalSignerPath(String),
    /// Failure surfaced from the mkit-attest signer itself (wraps its
    /// `Error` as a string; the CLI doesn't need to pattern-match these).
    Signer(String),
    /// Failure surfaced from mkit-keystore.
    Keystore(String),
}

impl std::fmt::Display for FactoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAlgorithm(s) => write!(
                f,
                "unknown algorithm '{s}' — expected one of: ed25519, secp256k1, p256"
            ),
            Self::UnknownSignerKind(s) => write!(
                f,
                "unknown signer '{s}' — expected one of: repo-key, external, keystore"
            ),
            Self::MissingKeyFile { algorithm, path } => write!(
                f,
                "{algorithm} key file not found at '{path}' — run `mkit keygen --algorithm {algorithm}` first"
            ),
            Self::MissingKeystoreKey {
                algorithm,
                backend,
                reason,
            } => write!(
                f,
                "missing keystore signing key for algorithm {algorithm} — run `mkit key generate --backend {backend} --algorithm {algorithm} --label <label>` first: {reason}"
            ),
            Self::InvalidKeyFile { path, reason } => {
                write!(f, "invalid key file '{path}': {reason}")
            }
            Self::ExternalSignerPath(s) => {
                write!(f, "attest.external_signer_path: {s}")
            }
            Self::Signer(s) => write!(f, "signer: {s}"),
            Self::Keystore(s) => write!(f, "keystore: {s}"),
        }
    }
}

impl std::error::Error for FactoryError {}

/// Parse `"ed25519" | "secp256k1" | "p256"` into an [`Algorithm`].
pub fn parse_algorithm(s: &str) -> Result<Algorithm, FactoryError> {
    s.parse::<Algorithm>()
        .map_err(|_| FactoryError::UnknownAlgorithm(s.to_owned()))
}

/// Build a signer.
///
/// * `root` — the repo root (the `.mkit/` directory lives directly under it).
/// * `algorithm` — resolved [`Algorithm`].
/// * `signer_kind` — `"repo-key"`, `"external"`, or `"keystore"`.
/// * `cfg` — the merged config (defaults + user-scoped + repo-scoped).
///
/// The returned signer is ready to be called with PAE bytes.
pub fn build_signer(
    root: &Path,
    algorithm: Algorithm,
    signer_kind: &str,
    cfg: &Config,
) -> Result<Box<dyn Signer>, FactoryError> {
    match signer_kind {
        "repo-key" => build_repo_key_signer(root, algorithm, cfg),
        "external" => build_external_signer(algorithm, &cfg.attest),
        "keystore" => build_keystore_signer(algorithm, cfg),
        other => Err(FactoryError::UnknownSignerKind(other.to_owned())),
    }
}

fn build_keystore_signer(
    algorithm: Algorithm,
    cfg: &Config,
) -> Result<Box<dyn Signer>, FactoryError> {
    let key_ref = configured_key_ref(cfg, algorithm)
        .parse::<KeyRef>()
        .map_err(|error| FactoryError::Keystore(format!("key ref: {error}")))?;
    let store = open_backend(key_ref.backend())
        .map_err(|error| FactoryError::Keystore(error.to_string()))?;
    let keystore_algorithm = to_keystore_algorithm(algorithm)?;
    let backend = key_ref.backend().to_string();
    let label = key_ref.label().to_owned();
    let selector = KeySelector::new(label.clone(), Some(keystore_algorithm))
        .map_err(|error| FactoryError::Keystore(error.to_string()))?;
    let opener = store
        .opener()
        .ok_or_else(|| FactoryError::Keystore(format!("backend {backend} cannot open keys")))?;
    let signer = opener.open(&selector).map_err(|error| match error {
        mkit_keystore::Error::KeyNotFound(_) => FactoryError::MissingKeystoreKey {
            algorithm,
            backend,
            reason: error.to_string(),
        },
        other => FactoryError::Keystore(other.to_string()),
    })?;
    Ok(Box::new(KeystoreAttestSigner { algorithm, signer }))
}

fn configured_key_ref(cfg: &Config, algorithm: Algorithm) -> &str {
    match algorithm {
        Algorithm::Ed25519 => cfg.key.ed25519_ref_or_fallback(),
        Algorithm::Secp256k1 => cfg.key.secp256k1_ref_or_fallback(),
        Algorithm::P256 => cfg.key.p256_ref_or_fallback(),
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => "",
    }
}

// `Result` is necessary on the `bls-threshold` arm; without that
// feature, clippy sees only infallible arms and flags the wrap.
#[allow(clippy::unnecessary_wraps)]
fn to_keystore_algorithm(algorithm: Algorithm) -> Result<mkit_keystore::Algorithm, FactoryError> {
    match algorithm {
        Algorithm::Ed25519 => Ok(mkit_keystore::Algorithm::Ed25519),
        Algorithm::Secp256k1 => Ok(mkit_keystore::Algorithm::Secp256k1),
        Algorithm::P256 => Ok(mkit_keystore::Algorithm::P256),
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(FactoryError::UnknownAlgorithm(
            "bls12381-thr keystore backend is Phase 2 of issue #160".to_owned(),
        )),
    }
}

struct KeystoreAttestSigner {
    algorithm: Algorithm,
    signer: Box<dyn mkit_keystore::KeySigner>,
}

impl std::fmt::Debug for KeystoreAttestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeystoreAttestSigner")
            .field("algorithm", &self.algorithm)
            .field("signer", &"<keystore>")
            .finish()
    }
}

impl Signer for KeystoreAttestSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn keyid(&self) -> Result<String, mkit_attest::Error> {
        self.signer
            .keyid()
            .map(mkit_keystore::KeyId::into_string)
            .map_err(|error| mkit_attest::Error::ExternalSignerBadResponse(error.to_string()))
    }

    fn sign(&mut self, pae: &[u8]) -> Result<Vec<u8>, mkit_attest::Error> {
        self.signer
            .sign(pae)
            .map_err(|error| mkit_attest::Error::ExternalSignerBadResponse(error.to_string()))
    }
}

fn build_repo_key_signer(
    root: &Path,
    algorithm: Algorithm,
    cfg: &Config,
) -> Result<Box<dyn Signer>, FactoryError> {
    match algorithm {
        Algorithm::Ed25519 => {
            // Reuse the commit signer's key path. As of we no
            // longer auto-generate the key here — `mkit commit`
            // doesn't either, and silently creating identities was
            // half of the C1 confused-deputy class. If the user runs
            // `mkit attest` against a brand-new repo with no key,
            // they get the same `MissingKeyFile` error as
            // `mkit keygen` would point them to.
            let rel = cfg.signing_key.as_str();
            let path = crate::config::resolve_key_path(root, rel).map_err(|e| {
                FactoryError::InvalidKeyFile {
                    path: rel.to_owned(),
                    reason: e.to_string(),
                }
            })?;
            if !path.exists() {
                return Err(FactoryError::MissingKeyFile {
                    algorithm,
                    path: path.display().to_string(),
                });
            }
            let kp =
                mkit_core::sign::load_key(&path).map_err(|e| FactoryError::InvalidKeyFile {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })?;
            Ok(Box::new(mkit_attest::RepoKeySigner::new(kp)))
        }
        Algorithm::Secp256k1 => {
            let rel = cfg.attest.secp256k1_key_path_or_default();
            let secret = load_raw_secret(root, rel, algorithm)?;
            // Borrow through `from_seed_zeroizing` so no plain
            // `[u8; 32]` is materialised on this frame.
            let signer = mkit_attest::signer_k256::Secp256k1Signer::from_seed_zeroizing(&secret)
                .map_err(|e| FactoryError::Signer(e.to_string()))?;
            Ok(Box::new(signer))
        }
        Algorithm::P256 => {
            let rel = cfg.attest.p256_key_path_or_default();
            let secret = load_raw_secret(root, rel, algorithm)?;
            // Borrow through `from_seed_zeroizing`; see secp256k1 arm.
            let signer = mkit_attest::signer_p256::P256Signer::from_seed_zeroizing(&secret)
                .map_err(|e| FactoryError::Signer(e.to_string()))?;
            Ok(Box::new(signer))
        }
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(FactoryError::UnknownAlgorithm(
            "bls12381-thr repo-key signer is Phase 3 of issue #160 (release-party CLI)".to_owned(),
        )),
    }
}

fn build_external_signer(
    algorithm: Algorithm,
    config: &crate::config::AttestConfig,
) -> Result<Box<dyn Signer>, FactoryError> {
    if config.external_signer_path.is_empty() {
        return Err(FactoryError::ExternalSignerPath(
            "empty — set `attest.external_signer_path` in user-scoped \
             config ($XDG_CONFIG_HOME/mkit/config). Per-repo .mkit/config \
             cannot set this key (security)."
                .into(),
        ));
    }
    let mut ext = ExternalSigner::with_algorithm(&config.external_signer_path, algorithm)
        .map_err(|e| FactoryError::ExternalSignerPath(e.to_string()))?
        .with_args(config.external_signer_args.clone());
    // Apply the user-scoped timeout override if set; otherwise the
    // crate default (DEFAULT_EXTERNAL_SIGNER_TIMEOUT, 120s) stays in
    // effect. A 0 value means "fail fast" (deadline already passed).
    if let Some(secs) = config.external_signer_timeout_secs {
        ext = ext.with_timeout(std::time::Duration::from_secs(secs));
    }
    Ok(Box::new(ext))
}

fn load_raw_secret(
    root: &Path,
    rel_path: &str,
    algorithm: Algorithm,
) -> Result<Zeroizing<[u8; 32]>, FactoryError> {
    let path = crate::config::resolve_key_path(root, rel_path).map_err(|e| {
        FactoryError::InvalidKeyFile {
            path: rel_path.to_owned(),
            reason: e.to_string(),
        }
    })?;
    if !path.exists() {
        // Report the resolved absolute path, matching the ed25519 arm so
        // the missing-key error is uniform across algorithms.
        return Err(FactoryError::MissingKeyFile {
            algorithm,
            path: path.display().to_string(),
        });
    }
    mkit_core::sign::load_raw_32(&path).map_err(|e| FactoryError::InvalidKeyFile {
        path: rel_path.to_owned(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// Helper: write a 32-byte raw key file with mode 0600 and parent
    /// dir 0700 so `mkit_core::sign::load_key` accepts it.
    fn write_ed25519_key(path: &Path, bytes: &[u8; 32]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
            let mut p = fs::metadata(parent).unwrap().permissions();
            p.set_mode(0o700);
            fs::set_permissions(parent, p).unwrap();
        }
        fs::write(path, bytes).unwrap();
        let mut perm = fs::metadata(path).unwrap().permissions();
        perm.set_mode(0o600);
        fs::set_permissions(path, perm).unwrap();
    }

    #[test]
    fn parse_algorithm_round_trip() {
        assert_eq!(parse_algorithm("ed25519").unwrap(), Algorithm::Ed25519);
        assert_eq!(parse_algorithm("secp256k1").unwrap(), Algorithm::Secp256k1);
        assert_eq!(parse_algorithm("p256").unwrap(), Algorithm::P256);
    }

    #[test]
    fn parse_algorithm_rejects_unknown() {
        match parse_algorithm("rsa") {
            Err(FactoryError::UnknownAlgorithm(s)) => assert_eq!(s, "rsa"),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("unexpected success"),
        }
    }

    #[test]
    fn unknown_signer_kind_errors() {
        let td = tempfile::tempdir().unwrap();
        let cfg = Config::with_defaults();
        match build_signer(td.path(), Algorithm::Ed25519, "sigstore", &cfg) {
            Err(FactoryError::UnknownSignerKind(s)) => assert_eq!(s, "sigstore"),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("unexpected success"),
        }
    }

    /// `mkit attest --signer repo-key` no longer auto-generates
    /// the Ed25519 key. Same contract as `mkit commit` — silent
    /// identity creation was half of the C1 confused-deputy class.
    #[test]
    fn repo_key_ed25519_missing_key_errors_with_keygen_hint() {
        let td = tempfile::tempdir().unwrap();
        let cfg = Config::with_defaults();
        match build_signer(td.path(), Algorithm::Ed25519, "repo-key", &cfg) {
            Err(FactoryError::MissingKeyFile { algorithm, path }) => {
                assert_eq!(algorithm, Algorithm::Ed25519);
                assert!(path.contains("default.key"), "{path}");
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("unexpected success"),
        }
        assert!(
            !td.path().join(".mkit/keys/default.key").exists(),
            "factory must not silently create the key file"
        );
    }

    #[test]
    fn repo_key_ed25519_loads_existing_key() {
        let td = tempfile::tempdir().unwrap();
        let key_path = td.path().join(".mkit/keys/default.key");
        write_ed25519_key(&key_path, &[0xCDu8; 32]);
        let cfg = Config::with_defaults();
        let signer = build_signer(td.path(), Algorithm::Ed25519, "repo-key", &cfg)
            .expect("ed25519 repo-key should load existing key");
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
    }

    /// User points `signing_key` at a non-default location via
    /// user-scoped config; the factory honours it.
    #[test]
    fn repo_key_ed25519_honours_signing_key_config() {
        let td = tempfile::tempdir().unwrap();
        let key_path = td.path().join(".mkit/keys/custom-global.key");
        write_ed25519_key(&key_path, &[0xEFu8; 32]);
        let mut cfg = Config::with_defaults();
        cfg.signing_key = ".mkit/keys/custom-global.key".into();
        let signer = build_signer(td.path(), Algorithm::Ed25519, "repo-key", &cfg)
            .expect("custom signing_key path should load");
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn repo_key_secp256k1_missing_key_errors_with_keygen_hint() {
        let td = tempfile::tempdir().unwrap();
        let cfg = Config::with_defaults();
        match build_signer(td.path(), Algorithm::Secp256k1, "repo-key", &cfg) {
            Err(FactoryError::MissingKeyFile { algorithm, path }) => {
                assert_eq!(algorithm, Algorithm::Secp256k1);
                assert!(path.contains("secp256k1"));
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("unexpected success"),
        }
    }

    #[test]
    fn repo_key_p256_loads_existing_raw_secret() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(td.path().join(".mkit/keys")).unwrap();
        let mut secret = [0u8; 32];
        secret[31] = 3;
        fs::write(td.path().join(".mkit/keys/p256.key"), secret).unwrap();
        let mut perm = fs::metadata(td.path().join(".mkit/keys/p256.key"))
            .unwrap()
            .permissions();
        perm.set_mode(0o600);
        fs::set_permissions(td.path().join(".mkit/keys/p256.key"), perm).unwrap();
        let mut dperm = fs::metadata(td.path().join(".mkit/keys"))
            .unwrap()
            .permissions();
        dperm.set_mode(0o700);
        fs::set_permissions(td.path().join(".mkit/keys"), dperm).unwrap();

        let cfg = Config::with_defaults();
        let signer = build_signer(td.path(), Algorithm::P256, "repo-key", &cfg)
            .expect("p256 repo-key should load raw secret");
        assert_eq!(signer.algorithm(), Algorithm::P256);
    }

    #[test]
    fn repo_key_wrong_length_key_errors() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(td.path().join(".mkit/keys")).unwrap();
        fs::write(td.path().join(".mkit/keys/secp256k1.key"), b"short").unwrap();
        let mut perm = fs::metadata(td.path().join(".mkit/keys/secp256k1.key"))
            .unwrap()
            .permissions();
        perm.set_mode(0o600);
        fs::set_permissions(td.path().join(".mkit/keys/secp256k1.key"), perm).unwrap();
        let mut dperm = fs::metadata(td.path().join(".mkit/keys"))
            .unwrap()
            .permissions();
        dperm.set_mode(0o700);
        fs::set_permissions(td.path().join(".mkit/keys"), dperm).unwrap();

        let cfg = Config::with_defaults();
        match build_signer(td.path(), Algorithm::Secp256k1, "repo-key", &cfg) {
            Err(FactoryError::InvalidKeyFile { reason, .. }) => {
                assert!(reason.contains("32 bytes"), "{reason}");
            }
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("unexpected success"),
        }
    }

    #[test]
    fn external_signer_requires_path() {
        let td = tempfile::tempdir().unwrap();
        let cfg = Config::with_defaults();
        match build_signer(td.path(), Algorithm::Ed25519, "external", &cfg) {
            Err(FactoryError::ExternalSignerPath(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("unexpected success"),
        }
    }
}
