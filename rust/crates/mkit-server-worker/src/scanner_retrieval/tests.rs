use super::*;

fn config() -> RetrievalConfig {
    let scanner =
        mkit_server::hooks::HookSigner::new("scanner", zeroize::Zeroizing::new([12; 32])).unwrap();
    RetrievalConfig::parse(
        &format!("active scan {}", "18".repeat(32)),
        &mkit_core::hash::to_hex(&scanner.public_key()),
    )
    .unwrap()
}

#[test]
fn activation_requires_all_inputs_and_the_release_launch_profile() {
    assert!(parse(&|_| None, false, false).unwrap().is_none());
    for key in [KEYS_SECRET, "SCANNER_KEYS"] {
        assert!(parse(&|name| (name == key).then(|| "key".into()), false, false).is_err());
    }
    for enable in ["", "1", "TRUE"] {
        assert!(
            parse(
                &|name| (name == "SCANNER_RETRIEVAL").then(|| enable.into()),
                true,
                true
            )
            .is_err()
        );
    }
    let valid = |name: &str| match name {
        "SCANNER_RETRIEVAL" => Some("true".into()),
        "WORKERS_PLAN" => Some("paid".into()),
        "LAUNCH_PROFILE" => Some("uno".into()),
        KEYS_SECRET => Some(format!("active scan {}", "18".repeat(32))),
        "SCANNER_KEYS" => Some(mkit_core::hash::to_hex(
            &mkit_server::hooks::HookSigner::new("scanner", zeroize::Zeroizing::new([12; 32]))
                .unwrap()
                .public_key(),
        )),
        _ => None,
    };
    assert!(parse(&valid, false, true).is_err());
    assert!(parse(&valid, true, false).is_err());
    assert!(
        parse(
            &|name| if name == "WORKERS_PLAN" {
                Some("free".into())
            } else {
                valid(name)
            },
            true,
            true
        )
        .is_err()
    );
    assert!(parse(&valid, true, true).is_ok());
    assert_eq!(
        parse(
            &|name| if name == "LAUNCH_PROFILE" {
                None
            } else {
                valid(name)
            },
            true,
            true
        )
        .is_ok(),
        cfg!(feature = "test-faults")
    );
}

#[test]
fn mount_defaults_off_and_is_exact() {
    let mut cfg = WorkerConfig::from_vars(|name| match name {
        "AUTH_AUDIENCE" => Some("https://server.example".into()),
        "AUTH_REPOSITORY" => Some("repo".into()),
        _ => None,
    })
    .unwrap();
    assert!(!mounted(PATH, &cfg));
    cfg.scanner_retrieval = Some(Arc::new(config()));
    assert!(mounted(PATH, &cfg));
    for path in [
        "/_mkit/scanner/pack/",
        "/_mkit/scanner",
        "/mkit.transport.v1.TransportService/DownloadPack",
    ] {
        assert!(!mounted(path, &cfg));
    }
}

#[test]
fn hook_seed_cannot_reuse_retrieval_role() {
    assert!(check_hook_seed(&config(), Some(&format!("hook {}", "18".repeat(32)))).is_err());
    assert!(check_hook_seed(&config(), Some(&format!("hook {}", "19".repeat(32)))).is_ok());
    assert!(
        check_hook_seed(
            &config(),
            Some(&format!("# comment\n\n hook {}", "19".repeat(32)))
        )
        .is_ok()
    );
}

#[test]
fn response_has_precise_range_and_no_cache_headers() {
    let mut reply = RetrievalResponse {
        bytes: bytes::Bytes::from_static(b"xyz"),
        start: 2,
        total: 8,
        partial: true,
    };
    assert_eq!(
        reply_headers(&reply),
        vec![
            ("content-type", "application/octet-stream".into()),
            ("content-length", "3".into()),
            ("content-range", "bytes 2-4/8".into())
        ]
    );
    reply.partial = false;
    assert_eq!(reply_headers(&reply).len(), 2);
}

#[test]
fn request_capture_never_retains_more_than_its_fixed_bound() {
    use mkit_server::scanner_retrieval::{MAX_CALLS, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
    let mut bytes = Vec::with_capacity(MAX_REQUEST_BYTES);
    assert!(append_body(&mut bytes, &vec![0; MAX_REQUEST_BYTES]));
    assert!(!append_body(&mut bytes, &[1]));
    assert_eq!(
        (bytes.len(), bytes.capacity()),
        (MAX_REQUEST_BYTES, MAX_REQUEST_BYTES)
    );
    const {
        assert!(
            MAX_CALLS < 9000,
            "retrieval retains invocation adapter headroom"
        );
    }
    assert_eq!(MAX_RESPONSE_BYTES, 1 << 20);
}

#[cfg(feature = "test-faults")]
#[test]
fn deployment_constructor_rejects_role_reuse_before_any_route() {
    let owner =
        mkit_server::hooks::HookSigner::new("owner", zeroize::Zeroizing::new([9; 32])).unwrap();
    let scanner =
        mkit_server::hooks::HookSigner::new("scanner", zeroize::Zeroizing::new([12; 32])).unwrap();
    let scanner_public = mkit_core::hash::to_hex(&scanner.public_key());
    let base = |name: &str| match name {
        "AUTH_AUDIENCE" => Some("https://server.example".into()),
        "ADDRESSING" => Some("multi".into()),
        "NAMESPACE_ALLOWLIST" => Some(format!(
            "ed25519-{}",
            mkit_core::hash::to_hex(&owner.public_key())
        )),
        "INDEXED_MODE" | "SCANNER_RETRIEVAL" => Some("true".into()),
        "WORKERS_PLAN" => Some("paid".into()),
        "HOOK_ROLES" => Some("inspect".into()),
        "TICKET_KEYS" => Some(format!("ticket {}", "07".repeat(32))),
        KEYS_SECRET => Some(format!("active scanner {}", "18".repeat(32))),
        "SCANNER_KEYS" => Some(scanner_public.clone()),
        _ => None,
    };
    assert!(WorkerConfig::from_vars(base).is_ok());
    let admin = serde_json::json!({"version":1,"keys":[{"keyId":"operator","alg":"ed25519","publicKey":scanner_public,"roles":["audit"]}]}).to_string();
    for (name, value) in [
        (KEYS_SECRET, format!("active scanner {}", "07".repeat(32))),
        ("ADMIN_KEYS", admin),
    ] {
        assert!(
            WorkerConfig::from_vars(|key| if key == name {
                Some(value.clone())
            } else {
                base(key)
            })
            .is_err(),
            "{name}"
        );
    }
}
