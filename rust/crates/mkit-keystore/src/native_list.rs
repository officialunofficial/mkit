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
    let secret: [u8; 32] =
        secret
            .try_into()
            .map_err(|secret: Vec<u8>| Error::InvalidKeyMaterial {
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
    result
}

#[cfg(test)]
pub(crate) fn run_native_backend_roundtrip_test(store: &dyn crate::Keystore) {
    if std::env::var_os("MKIT_RUN_NATIVE_KEYSTORE_TESTS").as_deref() != Some("1".as_ref()) {
        eprintln!("skipping native backend roundtrip; set MKIT_RUN_NATIVE_KEYSTORE_TESTS=1 to run");
        return;
    }

    match exercise_native_backend_roundtrip(store) {
        Ok(()) => {}
        Err(Error::BackendUnavailable(message)) => {
            eprintln!("skipping native backend roundtrip: {message}");
        }
        Err(error) => panic!("native backend roundtrip failed: {error:?}"),
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
}
