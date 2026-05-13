use crate::{
    Algorithm, BackendKind, Error, KeyMetadata, KeySigner as _, Result, SecretKey, SoftwareSigner,
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
    let secret: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidKeyMaterial {
            algorithm,
            reason: format!("expected 32 bytes, got {}", secret.len()),
        })?;
    let secret = SecretKey::new(algorithm, secret);
    let signer = SoftwareSigner::new(
        label.clone(),
        backend.clone(),
        algorithm,
        *secret.expose_secret(),
    )?;
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

pub(crate) fn resolve_selector_algorithm(
    store: &dyn crate::Keystore,
    selector: &crate::KeySelector,
) -> Result<Algorithm> {
    if let Some(algorithm) = selector.algorithm {
        return Ok(algorithm);
    }
    let matches: Vec<_> = store
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

#[cfg(test)]
pub(crate) fn exercise_native_backend_roundtrip(store: &dyn crate::Keystore) -> Result<()> {
    let label = unique_test_label();
    let selector = crate::KeySelector::new(label.clone(), Some(Algorithm::Ed25519))?;
    let _ = store.delete(&selector);

    let result = (|| -> Result<()> {
        let seed = [0x36; 32];
        let mut signer = store.import(
            &label,
            SecretKey::new(Algorithm::Ed25519, seed),
            crate::KeyAttrs::default(),
            crate::ImportOptions { overwrite: false },
        )?;
        assert_eq!(signer.algorithm(), Algorithm::Ed25519);
        assert_eq!(signer.label(), label);
        assert_eq!(signer.sign(b"native backend roundtrip")?.len(), 64);

        let opened = store.open(&selector)?;
        assert_eq!(opened.metadata()?.label, label);

        let listed = store.list()?;
        assert!(
            listed
                .iter()
                .any(|metadata| metadata.label == label && metadata.algorithm == Algorithm::Ed25519),
            "created key must appear in native backend listing"
        );

        let exported = store.export(&selector)?;
        assert_eq!(exported.expose_secret(), &seed);

        store.delete(&selector)?;
        assert!(matches!(store.open(&selector), Err(Error::KeyNotFound(_))));
        Ok(())
    })();

    let cleanup = store.delete(&selector);
    if result.is_ok()
        && !matches!(cleanup, Ok(()) | Err(Error::KeyNotFound(_)))
        && let Err(error) = cleanup
    {
        return Err(error);
    }
    result?;

    let invalid_label = unique_test_label();
    let invalid_selector = crate::KeySelector::new(invalid_label.clone(), Some(Algorithm::P256))?;
    let invalid_result = store.import(
        &invalid_label,
        SecretKey::new(Algorithm::P256, [0; 32]),
        crate::KeyAttrs::default(),
        crate::ImportOptions { overwrite: false },
    );
    assert!(
        matches!(invalid_result, Err(Error::InvalidKeyMaterial { .. })),
        "invalid P-256 import must fail before persistence"
    );
    assert!(
        matches!(store.open(&invalid_selector), Err(Error::KeyNotFound(_))),
        "invalid P-256 import must not leave an openable key"
    );
    let _ = store.delete(&invalid_selector);

    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_native_backend_roundtrip_test(store: &dyn crate::Keystore) {
    run_native_backend_roundtrip_test_with_availability(store, false);
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn run_required_native_backend_roundtrip_test(store: &dyn crate::Keystore) {
    run_native_backend_roundtrip_test_with_availability(store, true);
}

#[cfg(test)]
fn run_native_backend_roundtrip_test_with_availability(
    store: &dyn crate::Keystore,
    require_backend: bool,
) {
    if std::env::var_os("MKIT_RUN_NATIVE_KEYSTORE_TESTS").as_deref() != Some("1".as_ref()) {
        eprintln!("skipping native backend roundtrip; set MKIT_RUN_NATIVE_KEYSTORE_TESTS=1 to run");
        return;
    }

    match exercise_native_backend_roundtrip(store)
        .and_then(|()| exercise_native_backend_ecdsa_verification(store))
    {
        Ok(()) => {}
        Err(Error::BackendUnavailable(message)) if !require_backend => {
            eprintln!("skipping native backend roundtrip: {message}");
        }
        Err(error) => panic!("native backend roundtrip failed: {error:?}"),
    }
}

#[cfg(test)]
fn exercise_native_backend_ecdsa_verification(store: &dyn crate::Keystore) -> Result<()> {
    for algorithm in [Algorithm::Secp256k1, Algorithm::P256] {
        let label = unique_test_label();
        let selector = crate::KeySelector::new(label.clone(), Some(algorithm))?;
        let _ = store.delete(&selector);

        let result = (|| -> Result<()> {
            let mut seed = [0u8; 32];
            seed[31] = 1;
            let mut signer = store.import(
                &label,
                SecretKey::new(algorithm, seed),
                crate::KeyAttrs::default(),
                crate::ImportOptions { overwrite: false },
            )?;
            let message = b"native backend ecdsa verification equivalence";
            let signature = signer.sign(message)?;
            verify_ecdsa_signature(algorithm, &signer.public_key()?, message, &signature)?;

            let mut opened = store.open(&selector)?;
            let reopened_signature = opened.sign(message)?;
            verify_ecdsa_signature(
                algorithm,
                &opened.public_key()?,
                message,
                &reopened_signature,
            )?;

            let listed = store.list()?;
            assert!(
                listed
                    .iter()
                    .any(|metadata| metadata.label == label && metadata.algorithm == algorithm),
                "created ECDSA key must appear in native backend listing"
            );
            assert_eq!(store.export(&selector)?.expose_secret(), &seed);
            store.delete(&selector)
        })();

        let cleanup = store.delete(&selector);
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

    #[derive(Clone)]
    struct FakeKeystore {
        metadata: Vec<KeyMetadata>,
    }

    impl crate::Keystore for FakeKeystore {
        fn capabilities(&self) -> crate::Capabilities {
            crate::Capabilities {
                backend: BackendKind::Software,
                algorithms: Vec::new(),
                can_generate: false,
                can_import: false,
                can_export: false,
                can_delete: false,
                supports_listing: true,
                supports_user_presence: false,
                supports_device_bound: false,
                supports_non_extractable: false,
            }
        }

        fn generate(
            &self,
            _label: &str,
            _algorithm: Algorithm,
            _attrs: crate::KeyAttrs,
            _options: crate::GenerateOptions,
        ) -> Result<Box<dyn crate::KeySigner>> {
            unimplemented!()
        }

        fn import(
            &self,
            _label: &str,
            _secret: crate::SecretKey,
            _attrs: crate::KeyAttrs,
            _options: crate::ImportOptions,
        ) -> Result<Box<dyn crate::KeySigner>> {
            unimplemented!()
        }

        fn open(&self, _selector: &crate::KeySelector) -> Result<Box<dyn crate::KeySigner>> {
            unimplemented!()
        }

        fn list(&self) -> Result<Vec<KeyMetadata>> {
            Ok(self.metadata.clone())
        }

        fn export(&self, _selector: &crate::KeySelector) -> Result<crate::SecretKey> {
            unimplemented!()
        }

        fn delete(&self, _selector: &crate::KeySelector) -> Result<()> {
            unimplemented!()
        }
    }

    fn metadata(label: &str, algorithm: Algorithm) -> KeyMetadata {
        KeyMetadata {
            label: label.into(),
            backend: BackendKind::Software,
            algorithm,
            public_key: Vec::new(),
            keyid: String::new(),
            extractable: true,
            require_user_presence: false,
            device_bound: false,
        }
    }

    #[test]
    fn label_only_selector_resolution_matches_contract() {
        let store = FakeKeystore {
            metadata: vec![
                metadata("unique", Algorithm::Ed25519),
                metadata("ambiguous", Algorithm::Ed25519),
                metadata("ambiguous", Algorithm::P256),
            ],
        };

        assert_eq!(
            resolve_selector_algorithm(&store, &crate::KeySelector::new("unique", None).unwrap())
                .unwrap(),
            Algorithm::Ed25519
        );
        assert!(matches!(
            resolve_selector_algorithm(&store, &crate::KeySelector::new("missing", None).unwrap()),
            Err(Error::KeyNotFound(_))
        ));
        assert!(matches!(
            resolve_selector_algorithm(
                &store,
                &crate::KeySelector::new("ambiguous", None).unwrap()
            ),
            Err(Error::AmbiguousKeySelector(_))
        ));
        assert_eq!(
            resolve_selector_algorithm(
                &store,
                &crate::KeySelector::new("ambiguous", Some(Algorithm::P256)).unwrap()
            )
            .unwrap(),
            Algorithm::P256
        );
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
                label: "z".into(),
                backend: BackendKind::MacosKeychain,
                algorithm: Algorithm::P256,
                public_key: Vec::new(),
                keyid: String::new(),
                extractable: true,
                require_user_presence: false,
                device_bound: false,
            },
            KeyMetadata {
                label: "a".into(),
                backend: BackendKind::MacosKeychain,
                algorithm: Algorithm::Ed25519,
                public_key: Vec::new(),
                keyid: String::new(),
                extractable: true,
                require_user_presence: false,
                device_bound: false,
            },
            KeyMetadata {
                label: "a".into(),
                backend: BackendKind::MacosKeychain,
                algorithm: Algorithm::P256,
                public_key: Vec::new(),
                keyid: String::new(),
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
            let mut signer =
                SoftwareSigner::new("ecdsa".into(), BackendKind::Software, algorithm, seed)
                    .unwrap();
            let message = b"verify ecdsa instead of comparing bytes";
            let signature = signer.sign(message).unwrap();
            verify_ecdsa_signature(
                algorithm,
                &signer.public_key().unwrap(),
                message,
                &signature,
            )
            .unwrap();
        }
    }
}
