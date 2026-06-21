//! Tests for the software keystore backend.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

mod golden_vectors {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/common/vectors.rs"
    ));
}

#[derive(Debug)]
struct TestProtector;

impl KeyProtector for TestProtector {
    fn id(&self) -> &'static str {
        "test-protector"
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        Ok(dek.to_vec())
    }

    fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let dek: [u8; 32] = wrapped
            .try_into()
            .map_err(|_| Error::Encoding(format!("test DEK length: {}", wrapped.len())))?;
        Ok(Zeroizing::new(dek))
    }
}

#[derive(Debug)]
struct CountingProtector {
    deletes: Arc<AtomicUsize>,
}

impl KeyProtector for CountingProtector {
    fn id(&self) -> &'static str {
        "counting-protector"
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        Ok(dek.to_vec())
    }

    fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let dek: [u8; 32] = wrapped
            .try_into()
            .map_err(|_| Error::Encoding(format!("test DEK length: {}", wrapped.len())))?;
        Ok(Zeroizing::new(dek))
    }

    fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Debug)]
struct FailingDeleteProtector;

impl KeyProtector for FailingDeleteProtector {
    fn id(&self) -> &'static str {
        "failing-delete-protector"
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        Ok(dek.to_vec())
    }

    fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let dek: [u8; 32] = wrapped
            .try_into()
            .map_err(|_| Error::Encoding(format!("test DEK length: {}", wrapped.len())))?;
        Ok(Zeroizing::new(dek))
    }

    fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
        Err(Error::Io("test DEK cleanup failure".into()))
    }
}

#[derive(Debug)]
struct FailingUnwrapProtector {
    deletes: Arc<AtomicUsize>,
}

impl KeyProtector for FailingUnwrapProtector {
    fn id(&self) -> &'static str {
        "failing-unwrap-protector"
    }

    fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
        Ok(dek.to_vec())
    }

    fn unwrap_dek(&self, _wrapped: &[u8], _aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        Err(Error::BackendUnavailable("test unwrap failure".into()))
    }

    fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn software_store(root: impl Into<PathBuf>) -> SoftwareKeystore {
    SoftwareKeystore::with_root_and_protector(root, Arc::new(TestProtector))
}

#[test]
fn software_backend_import_open_list_export_delete_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));
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
    let store = software_store(dir.path().join("keys"));
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
    let store = software_store(dir.path().join("keys"));
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
    let store = software_store(dir.path().join("keys"));
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

#[cfg(unix)]
#[test]
fn software_backend_rejects_symlinked_storage_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real_root = dir.path().join("real-keys");
    let symlink_root = dir.path().join("keys");
    std::fs::create_dir_all(&real_root).expect("real root");
    std::os::unix::fs::symlink(&real_root, &symlink_root).expect("symlink root");
    let store = software_store(&symlink_root);

    let result = store.import(
        "default",
        SecretKey::new(Algorithm::Ed25519, [3; 32]),
        KeyAttrs::default(),
        ImportOptions::default(),
    );
    assert!(matches!(result, Err(Error::Io(message)) if message.contains("symlink")));
}

#[cfg(unix)]
#[test]
fn software_backend_rejects_symlinked_algorithm_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("keys");
    let real_algorithm_dir = dir.path().join("real-ed25519");
    std::fs::create_dir_all(&root).expect("root");
    std::fs::create_dir_all(&real_algorithm_dir).expect("real algorithm dir");
    std::os::unix::fs::symlink(&real_algorithm_dir, root.join("ed25519"))
        .expect("symlink algorithm dir");
    let store = software_store(root);

    let result = store.import(
        "default",
        SecretKey::new(Algorithm::Ed25519, [3; 32]),
        KeyAttrs::default(),
        ImportOptions::default(),
    );
    assert!(matches!(result, Err(Error::Io(message)) if message.contains("symlink")));
}

#[cfg(unix)]
#[test]
fn software_backend_rejects_symlinked_final_key_path_for_open_and_delete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));
    let path = store
        .path_for("default", Algorithm::Ed25519)
        .expect("key path");
    std::fs::create_dir_all(path.parent().expect("key parent")).expect("key parent");
    let target = dir.path().join("target.key");
    std::fs::write(&target, [3; 32]).expect("target key");
    std::os::unix::fs::symlink(&target, &path).expect("symlink key path");
    let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");

    assert!(
        matches!(store.open(&selector), Err(Error::Io(message)) if message.contains("symlink"))
    );
    assert!(
        matches!(store.delete(&selector), Err(Error::Io(message)) if message.contains("symlink"))
    );
    assert!(
        path.is_symlink(),
        "delete must not remove a symlinked key path"
    );
}

#[test]
fn software_backend_generates_all_supported_algorithms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));
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

#[test]
fn software_backend_writes_encrypted_record_not_raw_seed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));
    let seed = [0x4a; 32];
    store
        .import(
            "encrypted",
            SecretKey::new(Algorithm::Ed25519, seed),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("import");

    let path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
    let encoded = std::fs::read(path).expect("record bytes");
    assert!(encoded.starts_with(b"MKITKSV1"));
    assert_ne!(encoded, seed);
    assert_eq!(store.list().unwrap()[0].label, "encrypted");
}

#[test]
fn software_list_reports_attrs_stored_in_record_not_constants() {
    // Regression: `list()` must derive the reported attributes from the
    // decrypted record's authenticated `KeyAttrs`, not from hardcoded
    // constants. `validate_attrs` keeps the public API from writing
    // anything but the defaults today, so we hand-craft a record with
    // non-default attrs to prove the listing path honors stored state.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));

    let secret = SecretKey::new(Algorithm::Ed25519, [0x5c; 32]);
    let public_key = public_key(secret.algorithm(), secret.expose_secret()).expect("public key");
    let keyid = format!("{}:{}", secret.algorithm(), hex_lower(&public_key));
    let attrs = KeyAttrs {
        extractable: true,
        require_user_presence: true,
        device_bound: true,
    };
    let record =
        EncryptedKeyRecord::encrypt("crafted", &secret, attrs, public_key, keyid, &TestProtector)
            .expect("encrypt record");

    let path = store.path_for("crafted", Algorithm::Ed25519).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).expect("algorithm dir");
    std::fs::write(&path, record.encode().expect("encode")).expect("write record");

    let listed = store.list().expect("list");
    let entry = listed
        .iter()
        .find(|metadata| metadata.label == "crafted")
        .expect("crafted key listed");
    assert!(entry.extractable, "stored extractable must be reported");
    assert!(
        entry.require_user_presence,
        "stored require_user_presence must be reported, not the constant false"
    );
    assert!(
        entry.device_bound,
        "stored device_bound must be reported, not the constant false"
    );
}

#[test]
fn software_import_proves_protector_roundtrip_before_record_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deletes = Arc::new(AtomicUsize::new(0));
    let store = SoftwareKeystore::with_root_and_protector(
        dir.path().join("keys"),
        Arc::new(FailingUnwrapProtector {
            deletes: Arc::clone(&deletes),
        }),
    );

    let result = store.import(
        "encrypted",
        SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
        KeyAttrs::default(),
        ImportOptions::default(),
    );

    assert!(
        matches!(result, Err(Error::BackendUnavailable(message)) if message.contains("unwrap failure"))
    );
    assert_eq!(deletes.load(Ordering::SeqCst), 1);
    assert!(
        !store
            .path_for("encrypted", Algorithm::Ed25519)
            .unwrap()
            .exists(),
        "record must not be committed when protector cannot unwrap"
    );
}

#[test]
fn software_pre_install_write_failure_cleans_new_dek() {
    let deletes = Arc::new(AtomicUsize::new(0));
    let protector = CountingProtector {
        deletes: Arc::clone(&deletes),
    };

    let error = cleanup_new_dek_after_write_failure(
        &protector,
        b"wrapped-dek",
        KeyFileWriteError::before_record_install(Error::Io("pre-install write failure".into())),
    );

    assert!(matches!(error, Error::Io(message) if message.contains("pre-install")));
    assert_eq!(deletes.load(Ordering::SeqCst), 1);
}

#[test]
fn software_post_install_write_failure_preserves_new_dek() {
    let deletes = Arc::new(AtomicUsize::new(0));
    let protector = CountingProtector {
        deletes: Arc::clone(&deletes),
    };

    let error = cleanup_new_dek_after_write_failure(
        &protector,
        b"wrapped-dek",
        KeyFileWriteError::after_record_install(Error::Io("post-install fsync failure".into())),
    );

    assert!(matches!(error, Error::Io(message) if message.contains("post-install")));
    assert_eq!(deletes.load(Ordering::SeqCst), 0);
}

#[test]
fn software_list_authenticates_record_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));
    store
        .import(
            "encrypted",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("import");
    let path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
    let mut record = EncryptedKeyRecord::decode(&std::fs::read(&path).expect("record bytes"))
        .expect("record decode");
    record.keyid = "ed25519:forged".into();
    std::fs::write(&path, record.encode().expect("record encode")).expect("record write");

    assert!(
        matches!(store.list(), Err(Error::Encoding(message)) if message.contains("authentication"))
    );
}

#[test]
fn software_label_only_resolution_ignores_unrelated_corrupt_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));
    store
        .import(
            "valid",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("valid import");
    store
        .import(
            "corrupt",
            SecretKey::new(Algorithm::P256, [1; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("corrupt import");
    let corrupt_path = store.path_for("corrupt", Algorithm::P256).unwrap();
    let mut record =
        EncryptedKeyRecord::decode(&std::fs::read(&corrupt_path).expect("record bytes"))
            .expect("record decode");
    record.keyid = "p256:forged".into();
    std::fs::write(&corrupt_path, record.encode().expect("record encode")).expect("record write");

    assert!(
        store.list().is_err(),
        "strict list still authenticates all records"
    );
    let selector = KeySelector::new("valid", None).unwrap();
    assert_eq!(
        store.open(&selector).unwrap().algorithm(),
        Algorithm::Ed25519
    );
    assert_eq!(
        store.export(&selector).unwrap().expose_secret(),
        &[0x4a; 32]
    );
    store.delete(&selector).unwrap();
}

#[test]
fn software_label_only_resolution_fails_closed_for_matching_corrupt_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));
    store
        .import(
            "corrupt",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("import");
    let path = store.path_for("corrupt", Algorithm::Ed25519).unwrap();
    let mut record = EncryptedKeyRecord::decode(&std::fs::read(&path).expect("record bytes"))
        .expect("record decode");
    record.keyid = "ed25519:forged".into();
    std::fs::write(&path, record.encode().expect("record encode")).expect("record write");
    let selector = KeySelector::new("corrupt", None).unwrap();

    assert!(
        matches!(store.open(&selector), Err(Error::Encoding(message)) if message.contains("authentication"))
    );
}

#[test]
fn software_delete_authenticates_before_dek_cleanup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deletes = Arc::new(AtomicUsize::new(0));
    let store = SoftwareKeystore::with_root_and_protector(
        dir.path().join("keys"),
        Arc::new(CountingProtector {
            deletes: Arc::clone(&deletes),
        }),
    );
    store
        .import(
            "encrypted",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("import");
    let path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
    let mut record = EncryptedKeyRecord::decode(&std::fs::read(&path).expect("record bytes"))
        .expect("record decode");
    record.public_key = vec![0xff; 32];
    std::fs::write(&path, record.encode().expect("record encode")).expect("record write");
    let selector = KeySelector::new("encrypted", Some(Algorithm::Ed25519)).unwrap();

    assert!(
        matches!(store.delete(&selector), Err(Error::Encoding(message)) if message.contains("authentication"))
    );
    assert_eq!(deletes.load(Ordering::SeqCst), 0);
    assert!(
        path.exists(),
        "unauthenticated record must remain for inspection"
    );
}

#[test]
fn software_delete_removes_record_before_best_effort_dek_cleanup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SoftwareKeystore::with_root_and_protector(
        dir.path().join("keys"),
        Arc::new(FailingDeleteProtector),
    );
    store
        .import(
            "encrypted",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("import");
    let path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
    let selector = KeySelector::new("encrypted", Some(Algorithm::Ed25519)).unwrap();

    store.delete(&selector).expect("delete");
    assert!(!path.exists(), "selected key record must be removed");
}

#[test]
fn software_overwrite_cleans_up_old_dek_after_success() {
    let dir = tempfile::tempdir().expect("tempdir");
    let deletes = Arc::new(AtomicUsize::new(0));
    let store = SoftwareKeystore::with_root_and_protector(
        dir.path().join("keys"),
        Arc::new(CountingProtector {
            deletes: Arc::clone(&deletes),
        }),
    );
    store
        .import(
            "shared",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("initial import");
    store
        .import(
            "shared",
            SecretKey::new(Algorithm::P256, [1; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("other algorithm import");
    store
        .import(
            "shared",
            SecretKey::new(Algorithm::Ed25519, [0x5b; 32]),
            KeyAttrs::default(),
            ImportOptions { overwrite: true },
        )
        .expect("overwrite import");

    let ed25519 = KeySelector::new("shared", Some(Algorithm::Ed25519)).unwrap();
    let p256 = KeySelector::new("shared", Some(Algorithm::P256)).unwrap();
    assert_eq!(store.export(&ed25519).unwrap().expose_secret(), &[0x5b; 32]);
    assert_eq!(store.export(&p256).unwrap().expose_secret(), &[1; 32]);
    assert_eq!(deletes.load(Ordering::SeqCst), 1);
}

#[test]
fn software_failed_overwrite_does_not_cleanup_old_dek() {
    #[derive(Debug)]
    struct FailSecondWrapProtector {
        wraps: Arc<AtomicUsize>,
        deletes: Arc<AtomicUsize>,
    }

    impl KeyProtector for FailSecondWrapProtector {
        fn id(&self) -> &'static str {
            "fail-second-wrap-protector"
        }

        fn wrap_dek(&self, dek: &[u8; 32], _aad: &[u8]) -> Result<Vec<u8>> {
            if self.wraps.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(dek.to_vec())
            } else {
                Err(Error::Io("test wrap failure".into()))
            }
        }

        fn unwrap_dek(&self, wrapped: &[u8], _aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            let dek: [u8; 32] = wrapped
                .try_into()
                .map_err(|_| Error::Encoding(format!("test DEK length: {}", wrapped.len())))?;
            Ok(Zeroizing::new(dek))
        }

        fn delete_wrapped_dek(&self, _wrapped: &[u8]) -> Result<()> {
            self.deletes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let wraps = Arc::new(AtomicUsize::new(0));
    let deletes = Arc::new(AtomicUsize::new(0));
    let store = SoftwareKeystore::with_root_and_protector(
        dir.path().join("keys"),
        Arc::new(FailSecondWrapProtector {
            wraps: Arc::clone(&wraps),
            deletes: Arc::clone(&deletes),
        }),
    );
    store
        .import(
            "encrypted",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("import");

    assert!(matches!(
        store.import(
            "encrypted",
            SecretKey::new(Algorithm::Ed25519, [0x5b; 32]),
            KeyAttrs::default(),
            ImportOptions { overwrite: true },
        ),
        Err(Error::Io(message)) if message.contains("wrap failure")
    ));
    assert_eq!(deletes.load(Ordering::SeqCst), 0);
    let selector = KeySelector::new("encrypted", Some(Algorithm::Ed25519)).unwrap();
    assert_eq!(
        store.export(&selector).unwrap().expose_secret(),
        &[0x4a; 32]
    );
}

#[test]
fn encrypted_software_backend_matches_golden_vectors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = software_store(dir.path().join("keys"));
    for vector in golden_vectors::VECTORS {
        let algorithm: Algorithm = vector.algorithm.parse().expect("algorithm parses");
        let seed: [u8; 32] = hex_decode(vector.seed_hex)
            .expect("seed hex")
            .try_into()
            .expect("seed length");
        let mut signer = store
            .import(
                vector.label,
                SecretKey::new(algorithm, seed),
                KeyAttrs::default(),
                ImportOptions::default(),
            )
            .expect("import vector");
        assert_eq!(
            hex_lower(signer.public_key().expect("public key").as_bytes()),
            vector.public_hex
        );
        assert_eq!(
            signer.keyid().expect("keyid"),
            format!("{}:{}", vector.algorithm, vector.public_hex)
        );
        let message = match algorithm {
            Algorithm::Ed25519 => b"".as_slice(),
            Algorithm::Secp256k1 | Algorithm::P256 => golden_vectors::PAE,
            // Golden vectors cover ed25519/secp/p256 only; BLS
            // golden vectors live in mkit-attest. Skip via
            // `continue` would change the loop shape, so panic
            // here — the calling loop never produces this arm.
            #[cfg(feature = "bls-threshold")]
            Algorithm::Bls12381Threshold => {
                unreachable!("golden-vector test does not enumerate BLS12-381 threshold algorithms")
            }
        };
        assert_eq!(
            hex_lower(&signer.sign(message).expect("sign")),
            vector.signature_hex
        );
    }
}

#[cfg(unix)]
#[test]
fn software_backend_writes_private_storage_permissions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("keys");
    let store = software_store(&root);
    store
        .import(
            "encrypted",
            SecretKey::new(Algorithm::Ed25519, [0x4a; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("import");

    let algorithm_dir = root.join("ed25519");
    let key_path = store.path_for("encrypted", Algorithm::Ed25519).unwrap();
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&algorithm_dir), 0o700);
    assert_eq!(mode(&key_path), 0o600);
}

#[test]
fn software_raw_backend_reports_raw_backend_kind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = SoftwareRawKeystore::with_root(dir.path().join("keys"));
    let signer = store
        .import(
            "default",
            SecretKey::new(Algorithm::Ed25519, [9; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("import");

    assert_eq!(store.capabilities().backend, BackendKind::SoftwareRaw);
    assert_eq!(
        signer.metadata().expect("metadata").backend,
        BackendKind::SoftwareRaw
    );
    let selector = KeySelector::new("default", Some(Algorithm::Ed25519)).expect("selector");
    assert_eq!(
        store.list().expect("list")[0].backend,
        BackendKind::SoftwareRaw
    );
    assert_eq!(
        store.export(&selector).expect("export").expose_secret(),
        &[9; 32]
    );
}

#[test]
fn software_and_raw_backends_do_not_alias_storage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("keys");
    let software = software_store(&root);
    let raw = SoftwareRawKeystore::with_root(&root);

    software
        .import(
            "shared",
            SecretKey::new(Algorithm::Ed25519, [7; 32]),
            KeyAttrs::default(),
            ImportOptions::default(),
        )
        .expect("software import");
    raw.import(
        "shared",
        SecretKey::new(Algorithm::Ed25519, [8; 32]),
        KeyAttrs::default(),
        ImportOptions::default(),
    )
    .expect("raw import");

    let software_path = software.path_for("shared", Algorithm::Ed25519).unwrap();
    let raw_path = raw.inner.path_for("shared", Algorithm::Ed25519).unwrap();
    assert_ne!(software_path, raw_path);
    assert_eq!(std::fs::read(&raw_path).expect("raw bytes"), [8; 32]);
    assert_ne!(
        std::fs::read(&software_path).expect("record bytes"),
        [8; 32]
    );

    let selector = KeySelector::new("shared", Some(Algorithm::Ed25519)).unwrap();
    assert_eq!(
        software.export(&selector).unwrap().expose_secret(),
        &[7; 32]
    );
    assert_eq!(raw.export(&selector).unwrap().expose_secret(), &[8; 32]);
}

#[test]
fn software_capabilities_are_backend_accurate() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (store, backend) in [
        (
            Box::new(software_store(dir.path().join("software"))) as Box<dyn Keystore>,
            BackendKind::Software,
        ),
        (
            Box::new(SoftwareRawKeystore::with_root(dir.path().join("raw"))) as Box<dyn Keystore>,
            BackendKind::SoftwareRaw,
        ),
    ] {
        let capabilities = store.capabilities();
        assert_eq!(capabilities.backend, backend);
        // The encrypted software backend additionally advertises
        // Bls12381Threshold when `bls-threshold` is enabled (raw
        // does not, because BLS storage requires AEAD-bound AAD).
        #[allow(unused_mut)]
        let mut expected_algorithms =
            vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256];
        #[cfg(feature = "bls-threshold")]
        if backend == BackendKind::Software {
            expected_algorithms.push(Algorithm::Bls12381Threshold);
        }
        assert_eq!(capabilities.algorithms, expected_algorithms);
        assert!(capabilities.can_generate);
        assert!(capabilities.can_import);
        assert!(capabilities.can_export);
        assert!(capabilities.can_delete);
        assert!(capabilities.supports_listing);
        assert!(!capabilities.supports_user_presence);
        assert!(!capabilities.supports_device_bound);
        assert!(!capabilities.supports_non_extractable);
        assert_eq!(capabilities.can_generate, store.generator().is_some());
        assert_eq!(capabilities.can_import, store.importer().is_some());
        assert_eq!(capabilities.can_export, store.exporter().is_some());
        assert_eq!(capabilities.can_delete, store.deleter().is_some());
        assert_eq!(capabilities.supports_listing, store.lister().is_some());
    }
}

#[cfg(not(any(
    feature = "linux-secret-service",
    feature = "macos-keychain",
    feature = "systemd-creds",
    feature = "windows-credential"
)))]
#[test]
fn software_capabilities_report_structural_support_without_protector() {
    let dir = tempfile::tempdir().expect("tempdir");
    let capabilities = SoftwareKeystore::with_root(dir.path().join("software")).capabilities();

    assert_eq!(capabilities.backend, BackendKind::Software);
    // The encrypted software backend additionally advertises
    // Bls12381Threshold when `bls-threshold` is enabled (see
    // `capabilities()`); gate the expectation the same way so this
    // holds under both feature settings.
    #[allow(unused_mut)]
    let mut expected_algorithms = vec![Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256];
    #[cfg(feature = "bls-threshold")]
    expected_algorithms.push(Algorithm::Bls12381Threshold);
    assert_eq!(capabilities.algorithms, expected_algorithms);
    assert!(capabilities.can_generate);
    assert!(capabilities.can_import);
    assert!(capabilities.can_export);
    assert!(capabilities.can_delete);
    assert!(capabilities.supports_listing);
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
#[test]
fn systemd_protector_requires_available_runtime() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(matches!(
        systemd_creds_protector_for_availability(dir.path(), false),
        Err(Error::BackendUnavailable(_))
    ));
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
#[test]
fn systemd_protector_rejects_symlinked_storage_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let real_root = dir.path().join("real-keys");
    let symlink_root = dir.path().join("keys");
    std::fs::create_dir_all(&real_root).expect("real root");
    std::os::unix::fs::symlink(&real_root, &symlink_root).expect("symlink root");
    let protector = SystemdCredsProtector {
        storage_root: symlink_root.clone(),
        dek_root: symlink_root.join("deks"),
    };
    let path = protector.path_for("0123456789abcdef");

    assert!(
        matches!(protector.prepare_write_path(&path), Err(Error::Io(message)) if message.contains("symlink"))
    );
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
#[test]
fn systemd_protector_rejects_symlinked_dek_dir() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("keys");
    let real_deks = dir.path().join("real-deks");
    std::fs::create_dir_all(&root).expect("root");
    std::fs::create_dir_all(&real_deks).expect("real deks");
    std::os::unix::fs::symlink(&real_deks, root.join("deks")).expect("symlink deks");
    let protector = SystemdCredsProtector {
        storage_root: root.clone(),
        dek_root: root.join("deks"),
    };
    let path = protector.path_for("0123456789abcdef");

    assert!(
        matches!(protector.prepare_write_path(&path), Err(Error::Io(message)) if message.contains("symlink"))
    );
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
#[test]
fn systemd_protector_delete_rejects_symlinked_dek_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("keys");
    let protector = SystemdCredsProtector {
        storage_root: root.clone(),
        dek_root: root.join("deks"),
    };
    let path = protector.path_for("0123456789abcdef");
    std::fs::create_dir_all(path.parent().expect("dek parent")).expect("dek parent");
    let target = dir.path().join("target.cred");
    std::fs::write(&target, b"credential").expect("target credential");
    std::os::unix::fs::symlink(&target, &path).expect("symlink dek");

    assert!(
        matches!(protector.delete_wrapped_dek(b"0123456789abcdef"), Err(Error::Io(message)) if message.contains("symlink"))
    );
    assert!(
        path.is_symlink(),
        "delete must not remove symlinked DEK path"
    );
}

#[cfg(all(target_os = "linux", feature = "systemd-creds"))]
#[test]
fn systemd_protector_write_path_creates_private_dirs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("keys");
    let protector = SystemdCredsProtector {
        storage_root: root.clone(),
        dek_root: root.join("deks"),
    };
    let path = protector.path_for("0123456789abcdef");

    protector.prepare_write_path(&path).expect("prepare path");

    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&root.join("deks")), 0o700);
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}

// -- BLS12-381 threshold share storage --------------------------
//
// End-to-end test against the test protector: dealer → store one
// share per holder → load each share → sign with three holders →
// aggregate → verify. The test exercises every line on the BLS
// path including delete and the per-share AAD binding (a share
// record stored under one cohort cannot be passed off as a share
// for another cohort, because the cohort public key + holder
// index are in the AAD).
#[cfg(feature = "bls-threshold")]
#[test]
fn bls_share_storage_round_trip_and_verify() {
    use commonware_codec::{DecodeExt, Encode as _};
    use commonware_cryptography::bls12381::primitives::group::Share;
    use commonware_utils::{NZU32, test_rng_seeded};
    use mkit_attest::Signer as _;
    use tempfile::TempDir;

    let dir = TempDir::new().expect("tempdir");
    let store = SoftwareKeystore::with_root_and_protector(
        dir.path(),
        Arc::new(TestProtector) as Arc<dyn KeyProtector>,
    );

    // 3-of-4 cohort via the in-tree trusted dealer.
    let mut rng = test_rng_seeded(0xF00D);
    let (sharing, shares) = mkit_attest::bls_threshold_trusted_dealer(&mut rng, NZU32!(4));
    let agg_pubkey = sharing.public().encode().to_vec();
    let keyid = format!(
        "{}{}",
        mkit_attest::BLS_THRESHOLD_KEYID_PREFIX,
        hex_lower(&agg_pubkey)
    );

    // Store each share as `release-{index}`.
    for (offset, share) in shares.iter().enumerate() {
        let index = u32::try_from(offset).expect("offset fits in u32");
        let label = KeyLabel::new(format!("release-{index}")).unwrap();
        let share_bytes = share.encode().to_vec();
        store
            .store_bls_share(
                &label,
                &share_bytes,
                agg_pubkey.clone(),
                index,
                3,
                4,
                keyid.clone(),
                false,
            )
            .expect("store share");
    }

    // List shows all four.
    let listed = store.list_bls_shares().expect("list");
    assert_eq!(listed.len(), 4);

    // Reload three shares, build a ThresholdSigner per share, sign,
    // aggregate, verify.
    let pae = b"DSSEv1 28 application/vnd.in-toto+json 12 release v0.2.0";
    let mut partials: Vec<Vec<u8>> = Vec::with_capacity(3);
    for index in 0u32..3 {
        let label = KeyLabel::new(format!("release-{index}")).unwrap();
        let loaded = store.load_bls_share(&label).expect("load share");
        assert_eq!(loaded.metadata.share_index, index);
        assert_eq!(loaded.metadata.threshold, 3);
        assert_eq!(loaded.metadata.total, 4);
        assert_eq!(loaded.metadata.cohort_public_key, agg_pubkey);
        assert_eq!(loaded.metadata.keyid, keyid);
        let share = Share::decode(loaded.share_bytes.as_slice()).expect("decode share");
        let mut signer = mkit_attest::ThresholdSigner::new(share, sharing.clone());
        partials.push(signer.sign(pae).expect("sign"));
    }

    let agg_sig = mkit_attest::bls_threshold_aggregate(&sharing, &partials).expect("aggregate");
    mkit_attest::bls_threshold_verify(&agg_pubkey, pae, &agg_sig)
        .expect("aggregated signature verifies");

    // Tamper test: delete one share and re-load — gone.
    let label = KeyLabel::new("release-2").unwrap();
    store.delete_bls_share(&label).expect("delete");
    assert!(matches!(
        store.load_bls_share(&label),
        Err(Error::KeyNotFound(_))
    ));
}

/// A BLS share record's AAD binds the cohort public key + holder
/// index + threshold + total. Flipping any of those in the
/// on-disk record breaks the AEAD authentication and the load
/// fails closed.
#[cfg(feature = "bls-threshold")]
#[test]
fn bls_share_aad_binds_cohort_metadata() {
    use commonware_codec::Encode as _;
    use commonware_utils::{NZU32, test_rng_seeded};
    use tempfile::TempDir;

    let dir = TempDir::new().expect("tempdir");
    let store = SoftwareKeystore::with_root_and_protector(
        dir.path(),
        Arc::new(TestProtector) as Arc<dyn KeyProtector>,
    );

    let mut rng = test_rng_seeded(0xC0DE);
    let (sharing, shares) = mkit_attest::bls_threshold_trusted_dealer(&mut rng, NZU32!(4));
    let agg_pubkey = sharing.public().encode().to_vec();
    let label = KeyLabel::new("aad-bind").unwrap();
    let share_bytes = shares[0].encode().to_vec();
    store
        .store_bls_share(
            &label,
            &share_bytes,
            agg_pubkey.clone(),
            0,
            3,
            4,
            format!("bls12381-thr:{}", hex_lower(&agg_pubkey)),
            false,
        )
        .expect("store");

    // Read raw record bytes, flip the encoded threshold value, and
    // write back. The decrypt must fail because the AAD no longer
    // matches the ciphertext.
    let path = store.bls_path_for(label.as_str()).unwrap();
    let mut raw = std::fs::read(&path).expect("read");
    // The threshold u32 sits a known number of bytes in after the
    // magic/version/protector/cohort_pubkey prefix. Rather than
    // hand-compute the offset, decode + re-encode through the
    // record type with a mutated threshold; that's the same
    // tamper a hostile editor would produce by re-running our
    // encoder.
    let mut record = encrypted_record::BlsShareRecord::decode(&raw).unwrap();
    record.threshold = 1; // attacker drops the quorum to 1-of-N
    raw = record.encode().expect("re-encode tampered");
    std::fs::write(&path, &raw).expect("write");

    let result = store.load_bls_share(&label);
    assert!(
        result.is_err(),
        "BLS share with tampered threshold must not decrypt"
    );
}
