use crate::{
    Algorithm, BackendKind, Error, KeyLabel, KeyMetadata, KeySigner as _, Result, SecretKey,
    SoftwareSigner,
};

pub(crate) fn metadata_from_account_secret(
    account: &str,
    backend: BackendKind,
    secret: Vec<u8>,
) -> Result<Option<KeyMetadata>> {
    let Some((algorithm, label)) = parse_account(account) else {
        return Ok(None);
    };
    let secret = zeroize::Zeroizing::new(secret);
    if secret.len() != 32 {
        return Err(Error::InvalidKeyMaterial {
            algorithm,
            reason: format!("expected 32 bytes, got {}", secret.len()),
        });
    }
    let mut secret_bytes = zeroize::Zeroizing::new([0u8; 32]);
    secret_bytes.copy_from_slice(secret.as_slice());
    let secret = SecretKey::from_zeroizing(algorithm, secret_bytes);
    let label = KeyLabel::new(label)?;
    let signer = SoftwareSigner::new(label.clone(), backend, algorithm, *secret.expose_secret())?;
    Ok(Some(KeyMetadata {
        label,
        backend,
        algorithm,
        public_key: signer.public_key()?,
        keyid: signer.keyid()?,
        extractable: true,
        require_user_presence: false,
        device_bound: false,
    }))
}

pub(crate) fn list_metadata_from_account_secret(
    account: &str,
    backend: BackendKind,
    secret: Vec<u8>,
) -> Result<Option<KeyMetadata>> {
    match metadata_from_account_secret(account, backend, secret) {
        Ok(metadata) => Ok(metadata),
        Err(error) if is_malformed_list_entry_error(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn sort_metadata(metadata: &mut [KeyMetadata]) {
    metadata.sort_by(|left, right| {
        (&left.backend, &left.label, left.algorithm).cmp(&(
            &right.backend,
            &right.label,
            right.algorithm,
        ))
    });
}

pub(crate) fn parse_account(account: &str) -> Option<(Algorithm, String)> {
    let (algorithm, label) = account.split_once(':')?;
    let algorithm = algorithm.parse().ok()?;
    crate::validate_label(label).ok()?;
    Some((algorithm, label.to_owned()))
}

pub(crate) fn resolve_selector_algorithm<F>(
    selector: &crate::KeySelector,
    mut load_secret: F,
) -> Result<Algorithm>
where
    F: FnMut(&KeyLabel, Algorithm) -> Result<SecretKey>,
{
    if let Some(algorithm) = selector.algorithm {
        return Ok(algorithm);
    }
    let mut matches = Vec::new();
    for algorithm in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256] {
        match load_secret(selector.label_id(), algorithm) {
            Ok(_) => matches.push(algorithm),
            Err(Error::KeyNotFound(_)) => {}
            Err(error) => return Err(error),
        }
    }
    match matches.as_slice() {
        [] => Err(Error::KeyNotFound(selector.clone())),
        [algorithm] => Ok(*algorithm),
        _ => Err(Error::AmbiguousKeySelector(selector.clone())),
    }
}

pub(crate) fn is_malformed_list_entry_error(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidKeyMaterial { .. } | Error::InvalidLabel { .. } | Error::Encoding(_)
    )
}

#[cfg(test)]
pub(crate) fn exercise_native_backend_roundtrip(store: &dyn crate::Keystore) -> Result<()> {
    let label = unique_test_label();
    let selector = crate::KeySelector::new(label.clone(), Some(Algorithm::Ed25519))?;
    let importer = store
        .importer()
        .ok_or(Error::UnsupportedOperation("backend import"))?;
    let opener = store
        .opener()
        .ok_or(Error::UnsupportedOperation("backend open"))?;
    let lister = store
        .lister()
        .ok_or(Error::UnsupportedOperation("backend list"))?;
    let exporter = store
        .exporter()
        .ok_or(Error::UnsupportedOperation("backend export"))?;
    let deleter = store
        .deleter()
        .ok_or(Error::UnsupportedOperation("backend delete"))?;
    let _ = deleter.delete(&selector);
    let _cleanup_guard = NativeTestCleanup {
        deleter,
        selector: &selector,
    };

    let result = (|| -> Result<()> {
        let seed = [0x36; 32];
        let mut signer = importer.import(
            selector.label_id(),
            SecretKey::new(Algorithm::Ed25519, seed),
            crate::KeyAttrs::default(),
            crate::ImportOptions { overwrite: false },
        )?;
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
        assert_eq!(signer.label().as_str(), label);
        assert_eq!(signer.sign(b"native backend roundtrip")?.len(), 64);

        let reopened_signer = opener.open(&selector)?;
        assert_eq!(reopened_signer.metadata()?.label(), label);

        let listed_metadata = lister.list()?;
        assert!(
            listed_metadata
                .iter()
                .any(|metadata| metadata.label() == label
                    && metadata.algorithm == Algorithm::Ed25519),
            "created key must appear in native backend listing"
        );

        let exported_seed = exporter.export(&selector)?;
        assert_eq!(exported_seed.expose_secret(), &seed);

        deleter.delete(&selector)?;
        assert!(matches!(opener.open(&selector), Err(Error::KeyNotFound(_))));
        Ok(())
    })();

    let cleanup = deleter.delete(&selector);
    if result.is_ok()
        && !matches!(cleanup, Ok(()) | Err(Error::KeyNotFound(_)))
        && let Err(error) = cleanup
    {
        return Err(error);
    }
    result?;

    let invalid_label = unique_test_label();
    let invalid_selector = crate::KeySelector::new(invalid_label.clone(), Some(Algorithm::P256))?;
    let _invalid_cleanup_guard = NativeTestCleanup {
        deleter,
        selector: &invalid_selector,
    };
    let invalid_result = importer.import(
        invalid_selector.label_id(),
        SecretKey::new(Algorithm::P256, [0; 32]),
        crate::KeyAttrs::default(),
        crate::ImportOptions { overwrite: false },
    );
    assert!(
        matches!(invalid_result, Err(Error::InvalidKeyMaterial { .. })),
        "invalid P-256 import must fail before persistence"
    );
    assert!(
        matches!(opener.open(&invalid_selector), Err(Error::KeyNotFound(_))),
        "invalid P-256 import must not leave an openable key"
    );
    let _ = deleter.delete(&invalid_selector);

    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_native_backend_roundtrip_test(store: &dyn crate::Keystore) {
    run_native_backend_roundtrip_test_with_availability(store, false, |_| None);
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_required_native_backend_roundtrip_test(store: &dyn crate::Keystore) {
    run_native_backend_roundtrip_test_with_availability(store, true, |_| None);
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_required_native_backend_roundtrip_test_with_gate(
    store: &dyn crate::Keystore,
    gate: impl FnOnce(crate::BackendKind) -> Option<String>,
) {
    run_native_backend_roundtrip_test_with_availability(store, true, gate);
}

#[cfg(test)]
fn run_native_backend_roundtrip_test_with_availability<F>(
    store: &dyn crate::Keystore,
    require_backend: bool,
    extra_gate: F,
) where
    F: FnOnce(crate::BackendKind) -> Option<String>,
{
    let backend = store.capabilities().backend;
    if std::env::var_os("MKIT_RUN_NATIVE_KEYSTORE_TESTS").as_deref() != Some("1".as_ref()) {
        let message = format!(
            "native backend roundtrip for {backend} requires MKIT_RUN_NATIVE_KEYSTORE_TESTS=1"
        );
        assert!(!require_backend, "{message}");
        eprintln!("skipping {message}");
        return;
    }
    if let Some(message) = extra_gate(backend) {
        assert!(!require_backend, "{message}");
        eprintln!("skipping {message}");
        return;
    }

    match exercise_native_backend_roundtrip(store)
        .and_then(|()| exercise_native_backend_ecdsa_verification(store))
    {
        Ok(()) => {}
        Err(Error::BackendUnavailable(message)) if !require_backend => {
            eprintln!("skipping native backend roundtrip for {backend}: {message}");
        }
        Err(error) => panic!("native backend roundtrip for {backend} failed: {error:?}"),
    }
}

#[cfg(test)]
fn exercise_native_backend_ecdsa_verification(store: &dyn crate::Keystore) -> Result<()> {
    let importer = store
        .importer()
        .ok_or(Error::UnsupportedOperation("backend import"))?;
    let opener = store
        .opener()
        .ok_or(Error::UnsupportedOperation("backend open"))?;
    let lister = store
        .lister()
        .ok_or(Error::UnsupportedOperation("backend list"))?;
    let exporter = store
        .exporter()
        .ok_or(Error::UnsupportedOperation("backend export"))?;
    let deleter = store
        .deleter()
        .ok_or(Error::UnsupportedOperation("backend delete"))?;
    for algorithm in [Algorithm::Secp256k1, Algorithm::P256] {
        let label = unique_test_label();
        let selector = crate::KeySelector::new(label.clone(), Some(algorithm))?;
        let _ = deleter.delete(&selector);
        let _cleanup_guard = NativeTestCleanup {
            deleter,
            selector: &selector,
        };

        let result = (|| -> Result<()> {
            let mut seed = [0u8; 32];
            seed[31] = 1;
            let mut signer = importer.import(
                selector.label_id(),
                SecretKey::new(algorithm, seed),
                crate::KeyAttrs::default(),
                crate::ImportOptions { overwrite: false },
            )?;
            let message = b"native backend ecdsa verification equivalence";
            let signature = signer.sign(message)?;
            verify_ecdsa_signature(
                algorithm,
                signer.public_key()?.as_bytes(),
                message,
                &signature,
            )?;

            let mut reopened_signer = opener.open(&selector)?;
            let reopened_signature = reopened_signer.sign(message)?;
            verify_ecdsa_signature(
                algorithm,
                reopened_signer.public_key()?.as_bytes(),
                message,
                &reopened_signature,
            )?;

            let listed_metadata = lister.list()?;
            assert!(
                listed_metadata
                    .iter()
                    .any(|metadata| metadata.label() == label && metadata.algorithm == algorithm),
                "created ECDSA key must appear in native backend listing"
            );
            assert_eq!(exporter.export(&selector)?.expose_secret(), &seed);
            deleter.delete(&selector)
        })();

        let cleanup = deleter.delete(&selector);
        if result.is_ok()
            && !matches!(cleanup, Ok(()) | Err(Error::KeyNotFound(_)))
            && let Err(error) = cleanup
        {
            return Err(error);
        }
        result?;
    }
    Ok(())
}

#[cfg(test)]
struct NativeTestCleanup<'a> {
    deleter: &'a dyn crate::KeyDeleter,
    selector: &'a crate::KeySelector,
}

#[cfg(test)]
impl Drop for NativeTestCleanup<'_> {
    fn drop(&mut self) {
        let _ = self.deleter.delete(self.selector);
    }
}

#[cfg(test)]
fn verify_ecdsa_signature(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    match algorithm {
        Algorithm::Secp256k1 => {
            use k256::ecdsa::signature::DigestVerifier as _;
            use sha2::Digest as _;

            let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|error| Error::Encoding(format!("secp256k1 public key: {error}")))?;
            let signature = k256::ecdsa::Signature::from_slice(signature)
                .map_err(|error| Error::Encoding(format!("secp256k1 signature: {error}")))?;
            let mut digest = sha2::Sha256::new();
            digest.update(message);
            verifying_key
                .verify_digest(digest, &signature)
                .map_err(|error| Error::Internal(format!("secp256k1 signature verify: {error}")))
        }
        Algorithm::P256 => {
            use p256::ecdsa::signature::Verifier as _;

            let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|error| Error::Encoding(format!("P-256 public key: {error}")))?;
            let signature = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|error| Error::Encoding(format!("P-256 signature: {error}")))?;
            verifying_key
                .verify(message, &signature)
                .map_err(|error| Error::Internal(format!("P-256 signature verify: {error}")))
        }
        Algorithm::Ed25519 => Err(Error::UnsupportedAlgorithm(Algorithm::Ed25519)),
        // ECDSA-only helper; BLS verification flows through
        // `mkit_attest::signer_bls_threshold::verify`, not this
        // module's test-only helper.
        #[cfg(feature = "bls-threshold")]
        Algorithm::Bls12381Threshold => Err(Error::UnsupportedAlgorithm(algorithm)),
    }
}

#[cfg(test)]
fn unique_test_label() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("t36-{}-{nanos}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyId, PublicKeyBytes};

    #[test]
    fn label_only_selector_resolution_matches_contract() {
        let load_secret = |label: &KeyLabel, algorithm: Algorithm| match (label.as_str(), algorithm)
        {
            ("unique", Algorithm::Ed25519)
            | ("ambiguous", Algorithm::Ed25519 | Algorithm::P256) => {
                Ok(SecretKey::new(algorithm, [1; 32]))
            }
            _ => Err(Error::KeyNotFound(crate::KeySelector {
                label: label.clone(),
                algorithm: Some(algorithm),
            })),
        };

        assert_eq!(
            resolve_selector_algorithm(
                &crate::KeySelector::new("unique", None).unwrap(),
                load_secret
            )
            .unwrap(),
            Algorithm::Ed25519
        );
        assert!(matches!(
            resolve_selector_algorithm(
                &crate::KeySelector::new("missing", None).unwrap(),
                load_secret
            ),
            Err(Error::KeyNotFound(_))
        ));
        assert!(matches!(
            resolve_selector_algorithm(
                &crate::KeySelector::new("ambiguous", None).unwrap(),
                load_secret
            ),
            Err(Error::AmbiguousKeySelector(_))
        ));
        assert_eq!(
            resolve_selector_algorithm(
                &crate::KeySelector::new("ambiguous", Some(Algorithm::P256)).unwrap(),
                load_secret
            )
            .unwrap(),
            Algorithm::P256
        );
    }

    #[test]
    fn label_only_selector_resolution_fails_closed_for_matching_malformed_key() {
        let load_secret = |label: &KeyLabel, algorithm: Algorithm| match (label.as_str(), algorithm)
        {
            ("corrupt", Algorithm::Ed25519) => Err(Error::InvalidKeyMaterial {
                algorithm,
                reason: "expected 32 bytes, got 3".into(),
            }),
            _ => Err(Error::KeyNotFound(crate::KeySelector {
                label: label.clone(),
                algorithm: Some(algorithm),
            })),
        };

        assert!(matches!(
            resolve_selector_algorithm(
                &crate::KeySelector::new("corrupt", None).unwrap(),
                load_secret
            ),
            Err(Error::InvalidKeyMaterial { .. })
        ));
    }

    #[test]
    fn listing_metadata_skips_malformed_native_entries() {
        assert!(
            list_metadata_from_account_secret(
                "ed25519:bad",
                BackendKind::MacosKeychain,
                vec![1, 2, 3]
            )
            .unwrap()
            .is_none()
        );

        let metadata = list_metadata_from_account_secret(
            "ed25519:good",
            BackendKind::MacosKeychain,
            vec![1; 32],
        )
        .unwrap()
        .expect("valid entry should list");
        assert_eq!(metadata.label, "good");
        assert_eq!(metadata.algorithm, Algorithm::Ed25519);
    }

    #[test]
    fn parses_backend_account_names() {
        assert_eq!(
            parse_account("ed25519:release.key"),
            Some((Algorithm::Ed25519, "release.key".into()))
        );
        assert_eq!(parse_account("ed25519:"), None);
        assert_eq!(parse_account("unknown:release"), None);
        assert_eq!(parse_account("ed25519:../release"), None);
    }

    #[test]
    fn metadata_sorting_is_deterministic() {
        let mut metadata = vec![
            KeyMetadata {
                label: KeyLabel::new("z").unwrap(),
                backend: BackendKind::MacosKeychain,
                algorithm: Algorithm::P256,
                public_key: PublicKeyBytes::new(Vec::new()),
                keyid: KeyId::new("z").unwrap(),
                extractable: true,
                require_user_presence: false,
                device_bound: false,
            },
            KeyMetadata {
                label: KeyLabel::new("a").unwrap(),
                backend: BackendKind::MacosKeychain,
                algorithm: Algorithm::Ed25519,
                public_key: PublicKeyBytes::new(Vec::new()),
                keyid: KeyId::new("a-ed25519").unwrap(),
                extractable: true,
                require_user_presence: false,
                device_bound: false,
            },
            KeyMetadata {
                label: KeyLabel::new("a").unwrap(),
                backend: BackendKind::MacosKeychain,
                algorithm: Algorithm::P256,
                public_key: PublicKeyBytes::new(Vec::new()),
                keyid: KeyId::new("a-p256").unwrap(),
                extractable: true,
                require_user_presence: false,
                device_bound: false,
            },
        ];

        sort_metadata(&mut metadata);

        assert_eq!(metadata[0].label, "a");
        assert_eq!(metadata[0].algorithm, Algorithm::Ed25519);
        assert_eq!(metadata[1].label, "a");
        assert_eq!(metadata[1].algorithm, Algorithm::P256);
        assert_eq!(metadata[2].label, "z");
    }

    #[test]
    fn ecdsa_verification_accepts_valid_signatures() {
        for algorithm in [Algorithm::Secp256k1, Algorithm::P256] {
            let mut seed = [0u8; 32];
            seed[31] = 1;
            let mut signer = SoftwareSigner::new(
                KeyLabel::new("ecdsa").unwrap(),
                BackendKind::Software,
                algorithm,
                seed,
            )
            .unwrap();
            let message = b"verify ecdsa instead of comparing bytes";
            let signature = signer.sign(message).unwrap();
            verify_ecdsa_signature(
                algorithm,
                signer.public_key().unwrap().as_bytes(),
                message,
                &signature,
            )
            .unwrap();
        }
    }
}
