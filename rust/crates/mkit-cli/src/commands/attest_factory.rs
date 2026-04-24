//! Factory helpers for building a [`Signer`] from CLI / config inputs.
//!
//! The attest / verify-attest commands each need to turn a
//! `(algorithm, signer_kind, AttestConfig)` triple into a concrete
//! `Box<dyn Signer>`. Centralising the dispatch keeps the commands
//! thin and makes the algorithm -> signer-impl mapping a single place
//! to audit.
//!
//! Key material layout on disk (per `docs/SPEC-ATTESTATIONS.md` §6.1):
//!
//! * Ed25519 — `.mkit/keys/default.key` (shared with the commit signer;
//!   generated on first use by `mkit commit`).
//! * secp256k1 / p256 — `.mkit/keys/<algo>.key`, a raw 32-byte secret
//!   with mode 0600. **Not** auto-generated; the caller must run
//!   `mkit keygen --algorithm <algo>` first. Absent file → clear error.
//!
//! The `external` signer kind handles all three algorithms via a single
//! subprocess binary; the algorithm is recorded so verification can
//! dispatch the right crypto path without reparsing the keyid.

use std::fs;
use std::path::Path;

use mkit_attest::{Algorithm, ExternalSigner, Signer};
use mkit_core::sign::KeyPair;

use crate::config::AttestConfig;

/// Errors the factory surfaces. Mapped to CLI exit codes by the caller.
#[derive(Debug)]
pub enum FactoryError {
    /// Algorithm name (e.g. `"rsa"`) is not one of `ed25519`, `secp256k1`, `p256`.
    UnknownAlgorithm(String),
    /// `--signer` value is not one of `repo-key`, `external`.
    UnknownSignerKind(String),
    /// The per-algorithm keyfile is missing. Error message points the
    /// user at `mkit keygen --algorithm <algo>`.
    MissingKeyFile { algorithm: Algorithm, path: String },
    /// Keyfile exists but is not a 32-byte raw secret.
    InvalidKeyFile { path: String, reason: String },
    /// `attest.external_signer_path` is empty / relative / unusable.
    ExternalSignerPath(String),
    /// Failure surfaced from the mkit-attest signer itself (wraps its
    /// `Error` as a string; the CLI doesn't need to pattern-match these).
    Signer(String),
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
                "unknown signer '{s}' — expected one of: repo-key, external"
            ),
            Self::MissingKeyFile { algorithm, path } => write!(
                f,
                "{algorithm} key file not found at '{path}' — run `mkit keygen --algorithm {algorithm}` first"
            ),
            Self::InvalidKeyFile { path, reason } => {
                write!(f, "invalid key file '{path}': {reason}")
            }
            Self::ExternalSignerPath(s) => {
                write!(f, "attest.external_signer_path: {s}")
            }
            Self::Signer(s) => write!(f, "signer: {s}"),
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
/// * `signer_kind` — `"repo-key"` or `"external"`.
/// * `config` — the `[attest]` section from `.mkit/config`.
///
/// The returned signer is ready to be called with PAE bytes.
pub fn build_signer(
    root: &Path,
    algorithm: Algorithm,
    signer_kind: &str,
    config: &AttestConfig,
) -> Result<Box<dyn Signer>, FactoryError> {
    match signer_kind {
        "repo-key" => build_repo_key_signer(root, algorithm, config),
        "external" => build_external_signer(algorithm, config),
        other => Err(FactoryError::UnknownSignerKind(other.to_owned())),
    }
}

fn build_repo_key_signer(
    root: &Path,
    algorithm: Algorithm,
    config: &AttestConfig,
) -> Result<Box<dyn Signer>, FactoryError> {
    match algorithm {
        Algorithm::Ed25519 => {
            // Reuse the commit signer's key; auto-generate if absent,
            // matching `mkit commit` UX. That keeps `mkit attest` usable
            // in a freshly-initialised repo without an extra `keygen`
            // step.
            let key_path = root.join(".mkit/keys/default.key");
            let kp = load_or_generate_ed25519(&key_path)?;
            Ok(Box::new(mkit_attest::RepoKeySigner::new(kp)))
        }
        Algorithm::Secp256k1 => {
            let rel = config.secp256k1_key_path_or_default();
            let secret = load_raw_secret(root, rel, algorithm)?;
            let signer = mkit_attest::signer_k256::Secp256k1Signer::new(secret)
                .map_err(|e| FactoryError::Signer(e.to_string()))?;
            Ok(Box::new(signer))
        }
        Algorithm::P256 => {
            let rel = config.p256_key_path_or_default();
            let secret = load_raw_secret(root, rel, algorithm)?;
            let signer = mkit_attest::signer_p256::P256Signer::new(secret)
                .map_err(|e| FactoryError::Signer(e.to_string()))?;
            Ok(Box::new(signer))
        }
    }
}

fn build_external_signer(
    algorithm: Algorithm,
    config: &AttestConfig,
) -> Result<Box<dyn Signer>, FactoryError> {
    if config.external_signer_path.is_empty() {
        return Err(FactoryError::ExternalSignerPath(
            "empty — set `attest.external_signer_path` in .mkit/config".into(),
        ));
    }
    let ext = ExternalSigner::with_algorithm(&config.external_signer_path, algorithm)
        .map_err(|e| FactoryError::ExternalSignerPath(e.to_string()))?;
    Ok(Box::new(ext))
}

fn load_or_generate_ed25519(path: &Path) -> Result<KeyPair, FactoryError> {
    use mkit_core::sign;
    if path.exists() {
        return sign::load_key(path).map_err(|e| FactoryError::InvalidKeyFile {
            path: path.display().to_string(),
            reason: e.to_string(),
        });
    }
    let kp = KeyPair::generate().map_err(|e| FactoryError::Signer(e.to_string()))?;
    sign::save_key(path, &kp).map_err(|e| FactoryError::InvalidKeyFile {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    Ok(kp)
}

fn load_raw_secret(
    root: &Path,
    rel_path: &str,
    algorithm: Algorithm,
) -> Result<[u8; 32], FactoryError> {
    let path = root.join(rel_path);
    if !path.exists() {
        return Err(FactoryError::MissingKeyFile {
            algorithm,
            path: rel_path.to_owned(),
        });
    }
    let bytes = fs::read(&path).map_err(|e| FactoryError::InvalidKeyFile {
        path: rel_path.to_owned(),
        reason: e.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(FactoryError::InvalidKeyFile {
            path: rel_path.to_owned(),
            reason: format!("expected 32 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        let cfg = AttestConfig::default();
        match build_signer(td.path(), Algorithm::Ed25519, "sigstore", &cfg) {
            Err(FactoryError::UnknownSignerKind(s)) => assert_eq!(s, "sigstore"),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("unexpected success"),
        }
    }

    #[test]
    fn repo_key_ed25519_generates_key_when_missing() {
        let td = tempfile::tempdir().unwrap();
        let cfg = AttestConfig::default();
        let signer = build_signer(td.path(), Algorithm::Ed25519, "repo-key", &cfg)
            .expect("ed25519 repo-key should auto-generate");
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
        assert!(td.path().join(".mkit/keys/default.key").exists());
    }

    #[test]
    fn repo_key_secp256k1_missing_key_errors_with_keygen_hint() {
        let td = tempfile::tempdir().unwrap();
        let cfg = AttestConfig::default();
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

        let cfg = AttestConfig::default();
        let signer = build_signer(td.path(), Algorithm::P256, "repo-key", &cfg)
            .expect("p256 repo-key should load raw secret");
        assert_eq!(signer.algorithm(), Algorithm::P256);
    }

    #[test]
    fn repo_key_wrong_length_key_errors() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(td.path().join(".mkit/keys")).unwrap();
        fs::write(td.path().join(".mkit/keys/secp256k1.key"), b"short").unwrap();

        let cfg = AttestConfig::default();
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
        let cfg = AttestConfig::default();
        match build_signer(td.path(), Algorithm::Ed25519, "external", &cfg) {
            Err(FactoryError::ExternalSignerPath(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("unexpected success"),
        }
    }
}
