//! User-scoped software compatibility backend.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use k256::ecdsa::{Signature as K256Signature, SigningKey as K256SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    Algorithm, BackendKind, Capabilities, Error, GenerateOptions, ImportOptions, KeyAttrs,
    KeyMetadata, KeySelector, KeySigner, Keystore, Result, SecretKey, validate_label,
};

/// Persistent Foundation V1 software keystore.
#[derive(Clone, Debug)]
pub struct SoftwareKeystore {
    root: PathBuf,
}

impl SoftwareKeystore {
    /// Create a software keystore using the default user-scoped root.
    pub fn new() -> Result<Self> {
        Ok(Self {
            root: default_storage_root()?,
        })
    }

    /// Create a software keystore at an explicit root, useful for tests.
    #[must_use]
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Storage root for this backend.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, label: &str, algorithm: Algorithm) -> Result<PathBuf> {
        validate_label(label)?;
        Ok(self
            .root
            .join(algorithm.as_str())
            .join(format!("{}.key", hex_lower(label.as_bytes()))))
    }

    fn metadata_for(
        label: String,
        algorithm: Algorithm,
        secret: &SecretKey,
    ) -> Result<KeyMetadata> {
        let signer =
            SoftwareSigner::new(label.clone(), secret.algorithm(), *secret.expose_secret())?;
        Ok(KeyMetadata {
            label,
            backend: BackendKind::Software,
            algorithm,
            public_key: signer.public_key()?,
            keyid: signer.keyid()?,
            extractable: true,
            require_user_presence: false,
            device_bound: false,
        })
    }

    fn load_secret(&self, label: &str, algorithm: Algorithm) -> Result<SecretKey> {
        let path = self.path_for(label, algorithm)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: label.into(),
                algorithm: Some(algorithm),
            }));
        }
        let bytes = mkit_core::sign::load_raw_32(&path).map_err(core_error)?;
        Ok(SecretKey::new(algorithm, *bytes))
    }
}

impl Default for SoftwareKeystore {
    fn default() -> Self {
        Self::new().expect("default software keystore root should be discoverable")
    }
}

impl Keystore for SoftwareKeystore {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: BackendKind::Software,
            algorithms: vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256],
            can_generate: true,
            can_import: true,
            can_export: true,
            can_delete: true,
            supports_listing: true,
            supports_user_presence: false,
            supports_device_bound: false,
            supports_non_extractable: false,
        }
    }

    fn generate(
        &self,
        label: &str,
        algorithm: Algorithm,
        attrs: KeyAttrs,
        options: GenerateOptions,
    ) -> Result<Box<dyn KeySigner>> {
        validate_attrs(&attrs)?;
        let mut secret = random_valid_secret(algorithm)?;
        let wrapped = SecretKey::new(algorithm, secret);
        secret.zeroize();
        self.import(
            label,
            wrapped,
            attrs,
            ImportOptions {
                overwrite: options.overwrite,
            },
        )
    }

    fn import(
        &self,
        label: &str,
        secret: SecretKey,
        attrs: KeyAttrs,
        options: ImportOptions,
    ) -> Result<Box<dyn KeySigner>> {
        validate_attrs(&attrs)?;
        validate_label(label)?;
        validate_secret(secret.algorithm(), secret.expose_secret())?;
        let path = self.path_for(label, secret.algorithm())?;
        if options.overwrite {
            mkit_core::sign::save_raw_32(&path, secret.expose_secret()).map_err(core_error)?;
        } else {
            let created = mkit_core::sign::save_raw_32_create_new(&path, secret.expose_secret())
                .map_err(core_error)?;
            if !created {
                return Err(Error::KeyAlreadyExists {
                    label: label.into(),
                    algorithm: secret.algorithm(),
                });
            }
        }
        Ok(Box::new(SoftwareSigner::new(
            label.into(),
            secret.algorithm(),
            *secret.expose_secret(),
        )?))
    }

    fn open(&self, selector: &KeySelector) -> Result<Box<dyn KeySigner>> {
        validate_label(&selector.label)?;
        let algorithm = self.resolve_selector_algorithm(selector)?;
        let secret = self.load_secret(&selector.label, algorithm)?;
        Ok(Box::new(SoftwareSigner::new(
            selector.label.clone(),
            algorithm,
            *secret.expose_secret(),
        )?))
    }

    fn list(&self) -> Result<Vec<KeyMetadata>> {
        let mut out = Vec::new();
        for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256] {
            let dir = self.root.join(algorithm.as_str());
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(Error::Io(format!("read_dir {}: {error}", dir.display())));
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| Error::Io(format!("read_dir entry: {error}")))?;
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("key") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                let label = String::from_utf8(hex_decode(stem)?).map_err(|error| {
                    Error::Encoding(format!(
                        "stored label is not UTF-8 in {}: {error}",
                        path.display()
                    ))
                })?;
                validate_label(&label)?;
                let secret = self.load_secret(&label, algorithm)?;
                out.push(Self::metadata_for(label, algorithm, &secret)?);
            }
        }
        out.sort_by(|left, right| {
            (&left.backend, &left.label, left.algorithm).cmp(&(
                &right.backend,
                &right.label,
                right.algorithm,
            ))
        });
        Ok(out)
    }

    fn export(&self, selector: &KeySelector) -> Result<SecretKey> {
        let signer = self.open(selector)?;
        self.load_secret(signer.label(), signer.algorithm())
    }

    fn delete(&self, selector: &KeySelector) -> Result<()> {
        validate_label(&selector.label)?;
        let algorithm = self.resolve_selector_algorithm(selector)?;
        let path = self.path_for(&selector.label, algorithm)?;
        if !path.exists() {
            return Err(Error::KeyNotFound(KeySelector {
                label: selector.label.clone(),
                algorithm: Some(algorithm),
            }));
        }
        std::fs::remove_file(&path)
            .map_err(|error| Error::Io(format!("delete {}: {error}", path.display())))
    }
}

impl SoftwareKeystore {
    fn resolve_selector_algorithm(&self, selector: &KeySelector) -> Result<Algorithm> {
        if let Some(algorithm) = selector.algorithm {
            return Ok(algorithm);
        }
        let matches: Vec<_> = self
            .list()?
            .into_iter()
            .filter(|metadata| metadata.label == selector.label)
            .collect();
        match matches.as_slice() {
            [] => Err(Error::KeyNotFound(selector.clone())),
            [metadata] => Ok(metadata.algorithm),
            _ => Err(Error::AmbiguousKeySelector(selector.clone())),
        }
    }
}

/// Software signer backed by in-memory secret material loaded from the software backend.
pub struct SoftwareSigner {
    label: String,
    secret: SecretKey,
}

impl SoftwareSigner {
    fn new(label: String, algorithm: Algorithm, mut secret: [u8; 32]) -> Result<Self> {
        validate_secret(algorithm, &secret)?;
        let wrapped = SecretKey::new(algorithm, secret);
        secret.zeroize();
        Ok(Self {
            label,
            secret: wrapped,
        })
    }
}

impl std::fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareSigner")
            .field("label", &self.label)
            .field("algorithm", &self.secret.algorithm())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl KeySigner for SoftwareSigner {
    fn algorithm(&self) -> Algorithm {
        self.secret.algorithm()
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn metadata(&self) -> Result<KeyMetadata> {
        Ok(KeyMetadata {
            label: self.label.clone(),
            backend: BackendKind::Software,
            algorithm: self.algorithm(),
            public_key: self.public_key()?,
            keyid: self.keyid()?,
            extractable: true,
            require_user_presence: false,
            device_bound: false,
        })
    }

    fn public_key(&self) -> Result<Vec<u8>> {
        public_key(self.algorithm(), self.secret.expose_secret())
    }

    fn keyid(&self) -> Result<String> {
        let public_key = self.public_key()?;
        Ok(format!("{}:{}", self.algorithm(), hex_lower(&public_key)))
    }

    fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        sign_message(self.algorithm(), self.secret.expose_secret(), msg)
    }
}

fn validate_attrs(attrs: &KeyAttrs) -> Result<()> {
    if !attrs.extractable {
        return Err(Error::UnsupportedAttributes(
            "software backend does not support non-extractable keys in Foundation V1".into(),
        ));
    }
    if attrs.require_user_presence {
        return Err(Error::UnsupportedAttributes(
            "software backend does not support user presence".into(),
        ));
    }
    if attrs.device_bound {
        return Err(Error::UnsupportedAttributes(
            "software backend does not support device-bound keys".into(),
        ));
    }
    Ok(())
}

fn validate_secret(algorithm: Algorithm, secret: &[u8; 32]) -> Result<()> {
    match algorithm {
        Algorithm::Ed25519 => {
            let _ = Ed25519SigningKey::from_bytes(secret);
            Ok(())
        }
        Algorithm::Secp256k1 => K256SigningKey::from_bytes(secret.into())
            .map(|_| ())
            .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar")),
        Algorithm::P256 => P256SigningKey::from_bytes(secret.into())
            .map(|_| ())
            .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar")),
    }
}

fn public_key(algorithm: Algorithm, secret: &[u8; 32]) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => Ok(Ed25519SigningKey::from_bytes(secret)
            .verifying_key()
            .to_bytes()
            .to_vec()),
        Algorithm::Secp256k1 => Ok(K256SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar"))?
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()),
        Algorithm::P256 => Ok(P256SigningKey::from_bytes(secret.into())
            .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar"))?
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()),
    }
}

fn sign_message(algorithm: Algorithm, secret: &[u8; 32], msg: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => Ok(Ed25519SigningKey::from_bytes(secret)
            .sign(msg)
            .to_bytes()
            .to_vec()),
        Algorithm::Secp256k1 => {
            use k256::ecdsa::signature::DigestSigner as _;
            let key = K256SigningKey::from_bytes(secret.into())
                .map_err(|_| invalid_key_material(algorithm, "invalid secp256k1 scalar"))?;
            let mut hash = Sha256::new();
            hash.update(msg);
            let sig: K256Signature = key
                .try_sign_digest(hash)
                .map_err(|_| Error::Internal("secp256k1 signing failed".into()))?;
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        }
        Algorithm::P256 => {
            use p256::ecdsa::signature::Signer as _;
            let key = P256SigningKey::from_bytes(secret.into())
                .map_err(|_| invalid_key_material(algorithm, "invalid P-256 scalar"))?;
            let sig: P256Signature = key.sign(msg);
            let sig = sig.normalize_s().unwrap_or(sig);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

fn random_valid_secret(algorithm: Algorithm) -> Result<[u8; 32]> {
    let mut secret = [0u8; 32];
    loop {
        getrandom::fill(&mut secret).map_err(|_| Error::Internal("rng failed".into()))?;
        if validate_secret(algorithm, &secret).is_ok() {
            return Ok(secret);
        }
    }
}

fn default_storage_root() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        if let Some(data_home) = std::env::var_os("XDG_DATA_HOME") {
            return Ok(PathBuf::from(data_home).join("mkit").join("keys"));
        }
        let Some(home) = std::env::var_os("HOME") else {
            return Err(Error::BackendUnavailable(
                "HOME is unset and XDG_DATA_HOME is unset".into(),
            ));
        };
        Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("mkit")
            .join("keys"))
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Ok(PathBuf::from(appdata).join("mkit").join("keys"));
        }
        let Some(profile) = std::env::var_os("USERPROFILE") else {
            return Err(Error::BackendUnavailable(
                "APPDATA is unset and USERPROFILE is unset".into(),
            ));
        };
        Ok(PathBuf::from(profile)
            .join("AppData")
            .join("Roaming")
            .join("mkit")
            .join("keys"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let Some(home) = std::env::var_os("HOME") else {
            return Err(Error::BackendUnavailable("HOME is unset".into()));
        };
        Ok(PathBuf::from(home).join(".mkit").join("keys"))
    }
}

#[allow(clippy::needless_pass_by_value)]
fn core_error(error: mkit_core::MkitError) -> Error {
    Error::Io(error.to_string())
}

fn invalid_key_material(algorithm: Algorithm, reason: &str) -> Error {
    Error::InvalidKeyMaterial {
        algorithm,
        reason: reason.into(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return Err(Error::Encoding("hex string has odd length".into()));
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        let hi = hex_value(chunk[0])?;
        let lo = hex_value(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::Encoding("invalid lowercase hex".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_backend_import_open_list_export_delete_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SoftwareKeystore::with_root(dir.path().join("keys"));
        let secret = SecretKey::new(Algorithm::Ed25519, [3; 32]);
        let mut signer = store
            .import(
                "default",
                secret,
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import");
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
        assert_eq!(signer.public_key().expect("public key").len(), 32);

        let listed = store.list().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].label, "default");
        assert_eq!(listed[0].algorithm, Algorithm::Ed25519);

        let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");
        let exported = store.export(&selector).expect("export");
        assert_eq!(exported.expose_secret(), &[3; 32]);

        let sig = signer.sign(b"message").expect("sign");
        assert_eq!(sig.len(), 64);

        store.delete(&selector).expect("delete");
        assert!(matches!(store.open(&selector), Err(Error::KeyNotFound(_))));
    }

    #[test]
    fn software_backend_refuses_overwrite_without_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SoftwareKeystore::with_root(dir.path().join("keys"));
        let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");
        store
            .import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [3; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("initial import");
        assert!(matches!(
            store.import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [4; 32]),
                KeyAttrs::default(),
                ImportOptions::default(),
            ),
            Err(Error::KeyAlreadyExists { .. })
        ));
        store
            .import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [4; 32]),
                KeyAttrs::default(),
                ImportOptions { overwrite: true },
            )
            .expect("overwrite import");
        assert_eq!(
            store.export(&selector).expect("export").expose_secret(),
            &[4; 32]
        );
    }

    #[test]
    fn software_backend_concurrent_import_without_force_allows_one_writer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SoftwareKeystore::with_root(dir.path().join("keys"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for seed in [[3; 32], [4; 32]] {
            let store = store.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.import(
                    "default",
                    SecretKey::new(Algorithm::Ed25519, seed),
                    KeyAttrs::default(),
                    ImportOptions::default(),
                )
            }));
        }
        barrier.wait();

        let mut successes = 0;
        let mut already_exists = 0;
        for handle in handles {
            match handle.join().expect("thread should not panic") {
                Ok(_) => successes += 1,
                Err(Error::KeyAlreadyExists { .. }) => already_exists += 1,
                Err(error) => panic!("unexpected import error: {error}"),
            }
        }
        assert_eq!(successes, 1);
        assert_eq!(already_exists, 1);

        let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");
        let exported = store.export(&selector).expect("export");
        assert!(matches!(exported.expose_secret(), [3 | 4, ..]));
    }

    #[test]
    fn software_backend_rejects_unsupported_attrs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SoftwareKeystore::with_root(dir.path().join("keys"));
        let attrs = KeyAttrs {
            extractable: false,
            require_user_presence: false,
            device_bound: false,
        };
        assert!(matches!(
            store.import(
                "default",
                SecretKey::new(Algorithm::Ed25519, [3; 32]),
                attrs,
                ImportOptions::default(),
            ),
            Err(Error::UnsupportedAttributes(_))
        ));
    }

    #[test]
    fn software_backend_generates_all_supported_algorithms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SoftwareKeystore::with_root(dir.path().join("keys"));
        for (algorithm, public_key_len, signature_len) in [
            (Algorithm::Ed25519, 32, 64),
            (Algorithm::Secp256k1, 33, 64),
            (Algorithm::P256, 33, 64),
        ] {
            let label = format!("generated-{algorithm}");
            let mut signer = store
                .generate(
                    &label,
                    algorithm,
                    KeyAttrs::default(),
                    GenerateOptions::default(),
                )
                .expect("generate");
            assert_eq!(
                signer.public_key().expect("public key").len(),
                public_key_len
            );
            assert_eq!(
                signer.sign(b"message").expect("signature").len(),
                signature_len
            );
            let selector = KeySelector::new(label, Some(algorithm)).expect("selector");
            assert_eq!(
                store.export(&selector).expect("export").algorithm(),
                algorithm
            );
        }
    }
}

#[cfg(all(test, feature = "attest"))]
mod compatibility_tests {
    use super::*;
    use mkit_attest::Signer as _;

    const PAE: &[u8] = b"DSSEv1 28 application/vnd.in-toto+json 2 {}";

    #[test]
    fn ed25519_signatures_match_existing_repo_key_signer() {
        let seed = [0x42; 32];
        let mut expected =
            mkit_attest::RepoKeySigner::new(mkit_core::sign::KeyPair::from_seed(seed));
        let mut actual = SoftwareSigner::new("default".into(), Algorithm::Ed25519, seed).unwrap();

        assert_eq!(
            actual.public_key().unwrap(),
            mkit_core::sign::KeyPair::from_seed(seed).public.0
        );
        assert_eq!(actual.sign(PAE).unwrap(), expected.sign(PAE).unwrap());
    }

    #[test]
    fn secp256k1_signatures_match_existing_software_signer() {
        let mut seed = [0u8; 32];
        seed[31] = 1;
        let expected = mkit_attest::signer_k256::Secp256k1Signer::new(seed).unwrap();
        let mut actual = SoftwareSigner::new("default".into(), Algorithm::Secp256k1, seed).unwrap();

        assert_eq!(actual.public_key().unwrap(), expected.public_key_sec1());
        assert_eq!(actual.keyid().unwrap(), expected.keyid_string());
        assert_eq!(actual.sign(PAE).unwrap(), expected.sign_dsse(PAE).unwrap());
    }

    #[test]
    fn p256_signatures_match_existing_software_signer() {
        let seed = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let expected = mkit_attest::signer_p256::P256Signer::new(seed).unwrap();
        let mut actual = SoftwareSigner::new("default".into(), Algorithm::P256, seed).unwrap();

        assert_eq!(actual.public_key().unwrap(), expected.public_key_sec1());
        assert_eq!(actual.keyid().unwrap(), expected.keyid());
        assert_eq!(actual.sign(PAE).unwrap(), expected.sign_dsse(PAE).unwrap());
    }
}
