use super::*;
use std::collections::BTreeMap;

fn vars() -> BTreeMap<String, String> {
    [
        ("AUTH_AUDIENCE", "https://vcs.example"),
        ("LAUNCH_PROFILE", "paid-workers"),
        ("INDEXED_MODE", "true"),
        ("WORKERS_PLAN", "paid"),
        ("ADDRESSING", "multi"),
        ("NAMESPACE_POLICY", "any"),
        ("UNSAFE_OPEN_NAMESPACES", "true"),
        (
            "TICKET_KEYS",
            "ticket 1111111111111111111111111111111111111111111111111111111111111111",
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}
fn parse(v: &BTreeMap<String, String>) -> Result<WorkerConfig, ConfigError> {
    WorkerConfig::parse_vars(&|k| v.get(k).cloned())
}
fn check(v: &BTreeMap<String, String>) -> Result<WorkerConfig, ConfigError> {
    WorkerConfig::from_vars(|k| v.get(k).cloned())
}

#[test]
fn runtime_receipt_seed_cannot_reuse_the_ticket_seed() {
    let cfg = check(&vars()).unwrap();
    let error = validate_runtime_key_material(&cfg, &|name| {
        (name == crate::admin::RECEIPT_SECRET).then(|| "11".repeat(32))
    })
    .unwrap_err();
    assert!(error.0.contains("receipt signing seed"));
}

#[test]
fn programmatic_launch_changes_cannot_disable_the_extraction_driver() {
    let mut cfg = check(&vars()).unwrap();
    assert!(cfg.validate().is_ok());
    cfg.indexed.as_mut().unwrap().verification = mkit_server::indexed::VerificationMode::Inline;
    assert!(cfg.validate().unwrap_err().0.contains("scheduled indexed"));
    cfg.indexed = None;
    assert!(cfg.validate().unwrap_err().0.contains("scheduled indexed"));
}

#[cfg(not(feature = "test-faults"))]
#[test]
fn programmatic_indexed_activation_requires_the_launch_profile() {
    let mut cfg = check(&vars()).unwrap();
    cfg.launch = None;
    assert!(
        cfg.validate()
            .unwrap_err()
            .0
            .contains("LAUNCH_PROFILE=paid-workers")
    );
    #[cfg(feature = "http-objects")]
    {
        cfg.http_mount = Some(crate::http_mount::WorkerHttpMountConfig {
            indexed: cfg.indexed.take().unwrap(),
            http_objects: mkit_server::http_objects::HttpObjectsConfig::default(),
            options: mkit_server::http_objects::mount::HttpMountOptions::default(),
            read_runtime: None,
        });
        assert!(
            cfg.validate()
                .unwrap_err()
                .0
                .contains("LAUNCH_PROFILE=paid-workers")
        );
    }
    cfg.indexed = None;
    #[cfg(feature = "http-objects")]
    {
        cfg.http_mount = None;
    }
    assert!(cfg.validate().is_ok());
}

#[test]
fn programmatic_launch_audience_requires_https() {
    let mut cfg = check(&vars()).unwrap();
    cfg.audience = "http://vcs.example".into();
    assert!(
        cfg.validate().is_err(),
        "an embedded launch must retain the HTTPS audience required at startup"
    );
}

#[test]
fn programmatic_admin_audience_must_match_the_serving_origin() {
    let mut v = vars();
    v.insert(
        "ADMIN_KEYS".into(),
        serde_json::json!({"version":1,"keys":[{
            "keyId":"operator", "alg":"ed25519", "publicKey":"22".repeat(32),
            "roles":["audit"]
        }]})
        .to_string(),
    );
    let mut cfg = check(&v).unwrap();
    assert!(cfg.validate().is_ok());
    cfg.audience = "https://another.example".into();
    assert!(
        cfg.validate().is_err(),
        "admin authentication and purge intents must use the serving origin"
    );
}

#[cfg(feature = "http-objects")]
#[test]
fn programmatic_admin_keys_cannot_repeat_url_token_keys() {
    let mut v = vars();
    v.insert("HTTP_OBJECTS".into(), "true".into());
    v.insert(
        "URL_TOKEN_KEYS".into(),
        format!("active {}", "22".repeat(32)),
    );
    let mut cfg = check(&v).unwrap();
    let public = cfg
        .url_tokens
        .as_ref()
        .unwrap()
        .keys()
        .public_keys()
        .next()
        .unwrap();
    cfg.admin = Some(
        mkit_server::admin::Config::parse(
            &cfg.audience,
            &serde_json::json!({"version":1,"keys":[{
                "keyId":"operator", "alg":"ed25519",
                "publicKey":mkit_core::hash::to_hex(&public), "roles":["all"]
            }]})
            .to_string(),
        )
        .unwrap(),
    );
    assert!(
        cfg.validate().is_err(),
        "programmatic admin configuration must retain dedicated URL-token keys"
    );
}

#[test]
fn programmatic_remote_inspection_requires_scanner_retrieval() {
    let mut cfg = check(&vars()).unwrap();
    cfg.hooks = crate::hooks::config::HookVars::parse(&|name| {
        (name == "HOOK_ROLES").then(|| "inspect".into())
    })
    .unwrap();
    assert!(cfg.scanner_retrieval.is_none());
    assert!(
        cfg.validate().is_err(),
        "a remote launch inspector must receive its private scanner retrieval configuration"
    );
}

#[cfg(feature = "http-objects")]
#[test]
fn programmatic_http_mount_validates_before_early_responses() {
    let mut cfg = check(&vars()).unwrap();
    cfg.http_mount = Some(crate::http_mount::WorkerHttpMountConfig {
        indexed: cfg.indexed.unwrap(),
        http_objects: mkit_server::http_objects::HttpObjectsConfig::default(),
        options: mkit_server::http_objects::mount::HttpMountOptions::default(),
        read_runtime: None,
    });
    assert!(cfg.validate().unwrap_err().0.contains("URL_TOKEN_KEYS"));
    cfg.http_mount.as_mut().unwrap().http_objects.read_deadline = std::time::Duration::ZERO;
    assert!(cfg.validate().is_err());
}

#[test]
fn launch_profile_is_paid_indexed_permanent_and_optional_features_are_off() {
    let cfg = parse(&vars()).unwrap();
    assert_eq!(cfg.launch, Some(LaunchConfig { takedown: false }));
    assert!(cfg.indexed.is_some());
    assert!(cfg.admin.is_none());
    assert!(cfg.hooks.is_none());
    #[cfg(feature = "http-objects")]
    assert!(cfg.http_mount.is_none());
    assert!(check(&vars()).is_ok());
    for (name, value, diagnostic) in [
        ("LAUNCH_PROFILE", "full", "LAUNCH_PROFILE"),
        ("INDEXED_MODE", "false", "INDEXED_MODE=true"),
        ("WORKERS_PLAN", "free", "WORKERS_PLAN=paid"),
        ("STORAGE_LEASES", "true", "leases and GC"),
        ("GC_ENABLED", "true", "leases and GC"),
        ("RETENTION", "30d", "RETENTION"),
        ("HTTP_OBJECTS", "1", "HTTP_OBJECTS"),
        ("TAKEDOWN_ENABLED", "yes", "TAKEDOWN_ENABLED"),
        ("SHARDING", "single", "SHARDING=d34"),
        ("UNSAFE_OPEN_NAMESPACES", "false", "UNSAFE_OPEN_NAMESPACES"),
    ] {
        let mut v = vars();
        v.insert(name.into(), value.into());
        assert!(check(&v).unwrap_err().0.contains(diagnostic), "{name}");
    }
}
#[test]
fn launch_partial_inspection_and_preservation_refuse_before_activation() {
    let mut v = vars();
    v.insert("HOOK_ROLES".into(), "inspect".into());
    assert!(check(&v).unwrap_err().0.contains("SCANNER_RETRIEVAL=true"));
    v.insert("SCANNER_RETRIEVAL".into(), "true".into());
    assert!(check(&v).unwrap_err().0.contains("SCANNER_RETRIEVAL_KEYS"));
    v.insert("SCANNER_KEYS".into(), "invalid scanner".into());
    assert!(check(&v).unwrap_err().0.contains("SCANNER_RETRIEVAL_KEYS"));
    v.insert(
        "SCANNER_RETRIEVAL_KEYS".into(),
        "invalid retrieval key".into(),
    );
    assert!(check(&v).unwrap_err().0.contains("keys are invalid"));
    for (k, value) in [
        ("INSPECT_MODE", "async"),
        ("INSPECT_ON_UNAVAILABLE", "publish"),
    ] {
        let mut bad = v.clone();
        bad.insert(k.into(), value.into());
        assert!(check(&bad).unwrap_err().0.contains("sync and fail_closed"));
    }
    let mut v = vars();
    v.insert("TAKEDOWN_ENABLED".into(), "true".into());
    assert!(check(&v).unwrap_err().0.contains("ADMIN_KEYS"));
    let mut v = vars();
    v.insert("PRESERVATION_RETENTION_MS".into(), "60000".into());
    assert!(check(&v).unwrap_err().0.contains("TAKEDOWN_ENABLED=true"));
}

#[test]
fn clear_deadlines_are_refused_even_without_an_inspector() {
    for name in [
        "INSPECT_CLEAR_DEADLINE_MS",
        "INSPECT_CLEAR_DEADLINE",
        "INSPECT_DEADLINE_MS",
    ] {
        let mut v = vars();
        v.insert(name.into(), "1".into());
        assert!(check(&v).unwrap_err().0.contains("clear deadlines"));
    }
}

#[cfg(feature = "http-objects")]
#[test]
fn launch_http_requires_tokens_and_preserves_role_separation() {
    let mut v = vars();
    v.insert("HTTP_OBJECTS".into(), "true".into());
    assert!(check(&v).unwrap_err().0.contains("URL_TOKEN_KEYS"));
    v.insert(
        "URL_TOKEN_KEYS".into(),
        format!("active {}", "22".repeat(32)),
    );
    let cfg = parse(&v).unwrap();
    assert!(cfg.http_mount.is_some());
    assert!(cfg.url_tokens.is_some());
    assert!(!cfg.http_mount.unwrap().http_objects.admit_reads);
    v.insert("HTTP_ADMIT_READS".into(), "true".into());
    assert!(check(&v).unwrap_err().0.contains("admit hook role"));
    v.remove("HTTP_ADMIT_READS");
    v.insert(
        "URL_TOKEN_KEYS".into(),
        format!("active {}", "11".repeat(32)),
    );
    assert!(
        check(&v)
            .unwrap_err()
            .0
            .contains("must differ from TICKET_KEYS")
    );
}

#[cfg(feature = "http-objects")]
#[test]
fn launch_refuses_ticket_secrets_exposed_as_active_or_retired_token_public_keys() {
    let mut v = vars();
    v.insert("HTTP_OBJECTS".into(), "true".into());
    v.insert(
        "URL_TOKEN_KEYS".into(),
        format!("active {}", "22".repeat(32)),
    );
    let cfg = check(&v).unwrap();
    let public = cfg.url_tokens.unwrap().keys().public_keys().next().unwrap();
    v.insert(
        "TICKET_KEYS".into(),
        format!("ticket {}", mkit_core::hash::to_hex(&public)),
    );
    assert!(
        check(&v).is_err(),
        "published active public bytes must never be accepted ticket MAC material"
    );
    v.insert(
        "URL_TOKEN_KEYS".into(),
        format!(
            "active {}\nretired {} 0",
            "33".repeat(32),
            mkit_core::hash::to_hex(&public)
        ),
    );
    assert!(
        check(&v).is_err(),
        "retained public bytes must never be accepted ticket MAC material"
    );
}

#[test]
fn programmatic_admin_public_bytes_cannot_be_ticket_secret_material() {
    let mut cfg = check(&vars()).unwrap();
    let public = mkit_server::hooks::HookSigner::new("operator", zeroize::Zeroizing::new([34; 32]))
        .unwrap()
        .public_key();
    cfg.ticket_keys =
        Some(mkit_server::upload::token::TicketKeys::new(vec![("ticket".into(), public)]).unwrap());
    cfg.admin = Some(mkit_server::admin::Config::parse(&cfg.audience, &serde_json::json!({"version":1,"keys":[{
        "keyId":"operator", "alg":"ed25519", "publicKey":mkit_core::hash::to_hex(&public), "roles":["audit"]
    }]}).to_string()).unwrap());
    assert!(
        cfg.validate().is_err(),
        "programmatic role guards must refuse public ticket secrets"
    );
}

#[cfg(feature = "http-objects")]
#[test]
fn programmatic_token_seed_cannot_be_a_published_admin_key() {
    let mut v = vars();
    v.insert("HTTP_OBJECTS".into(), "true".into());
    v.insert(
        "URL_TOKEN_KEYS".into(),
        format!("active {}", "22".repeat(32)),
    );
    let mut cfg = check(&v).unwrap();
    cfg.admin = Some(
        mkit_server::admin::Config::parse(
            &cfg.audience,
            &serde_json::json!({"version":1,"keys":[{
                "keyId":"operator", "alg":"ed25519", "publicKey":"22".repeat(32), "roles":["audit"]
            }]})
            .to_string(),
        )
        .unwrap(),
    );
    assert!(
        cfg.validate().is_err(),
        "public admin material must never disclose the active URL signing seed"
    );
}

#[cfg(feature = "signed-http-hooks")]
#[test]
fn launch_hook_public_bytes_cannot_be_ticket_secret_material() {
    let mut v = vars();
    v.insert("HOOK_ROLES".into(), "admit".into());
    v.insert("HOOK_URL".into(), "https://hooks.example".into());
    v.insert("MKIT_HOOK_KEY".into(), format!("hook {}", "55".repeat(32)));
    let public = mkit_server::hooks::HookSigner::new("hook", zeroize::Zeroizing::new([0x55; 32]))
        .unwrap()
        .public_key();
    v.insert(
        "TICKET_KEYS".into(),
        format!("ticket {}", mkit_core::hash::to_hex(&public)),
    );
    assert!(check(&v).unwrap_err().0.contains("hook public key"));
}

#[cfg(all(feature = "http-objects", feature = "signed-http-hooks"))]
#[test]
fn mutated_programmatic_token_seed_is_checked_against_environment_hook_public() {
    let mut v = vars();
    v.insert("HOOK_ROLES".into(), "admit".into());
    v.insert("HOOK_URL".into(), "https://hooks.example".into());
    v.insert("MKIT_HOOK_KEY".into(), format!("hook {}", "55".repeat(32)));
    v.insert("HTTP_OBJECTS".into(), "true".into());
    v.insert(
        "URL_TOKEN_KEYS".into(),
        format!("active {}", "22".repeat(32)),
    );
    let mut cfg = check(&v).unwrap();
    assert!(validate_runtime_key_material(&cfg, &|name| v.get(name).cloned()).is_ok());
    let public = mkit_server::hooks::HookSigner::new("hook", zeroize::Zeroizing::new([0x55; 32]))
        .unwrap()
        .public_key();
    cfg.url_tokens = Some(mkit_server::url_token::UrlTokenConfig::new(
        mkit_server::url_token::UrlTokenKeys::new(zeroize::Zeroizing::new(public), vec![]).unwrap(),
    ));
    assert!(
        cfg.validate().is_ok(),
        "environment hook key is only available at runtime"
    );
    assert!(
        validate_runtime_key_material(&cfg, &|name| v.get(name).cloned())
            .unwrap_err()
            .0
            .contains("signing seed")
    );
}

#[cfg(feature = "http-objects")]
#[test]
fn mutated_programmatic_token_public_rechecks_environment_receipt_seed() {
    let mut v = vars();
    v.insert("HTTP_OBJECTS".into(), "true".into());
    v.insert(
        "URL_TOKEN_KEYS".into(),
        format!("active {}", "22".repeat(32)),
    );
    let mut cfg = check(&v).unwrap();
    let future =
        mkit_server::url_token::UrlTokenKeys::new(zeroize::Zeroizing::new([0x33; 32]), vec![])
            .unwrap();
    let public = future.public_keys().next().unwrap();
    let receipt = mkit_server::hooks::HookSigner::new("receipt", zeroize::Zeroizing::new(public))
        .unwrap()
        .public_key();
    let seed = mkit_core::hash::to_hex(&public);
    cfg.takedown = Some(crate::admin::TakedownSettings {
        retention_ms: 60000,
        publication: mkit_server::takedown::PublicationConfig::parse(&seed,
            &serde_json::json!({"version":1,"keys":[{"keyId":mkit_core::hash::to_hex(&mkit_core::hash::hash(&receipt)),
            "alg":"ed25519","publicKey":mkit_core::hash::to_hex(&receipt)}]}).to_string()).unwrap(),
    });
    v.insert("RECEIPT_NOTICE_KEY".into(), seed);
    assert!(validate_runtime_key_material(&cfg, &|name| v.get(name).cloned()).is_ok());
    cfg.url_tokens = Some(mkit_server::url_token::UrlTokenConfig::new(future));
    assert!(
        validate_runtime_key_material(&cfg, &|name| v.get(name).cloned())
            .unwrap_err()
            .0
            .contains("receipt signing seed")
    );
}

#[cfg(feature = "signed-http-hooks")]
#[test]
fn launch_signed_hooks_are_validated_at_startup_and_redact_keys() {
    let mut v = vars();
    v.insert("HOOK_ROLES".into(), "admit".into());
    v.insert("HOOK_URL".into(), "https://hooks.example".into());
    assert!(check(&v).unwrap_err().0.contains("MKIT_HOOK_KEY"));
    v.insert(
        "MKIT_HOOK_KEY".into(),
        "secret value must not escape".into(),
    );
    let err = check(&v).unwrap_err().0;
    assert!(!err.contains("value must not escape"));
    v.insert("MKIT_HOOK_KEY".into(), format!("hook {}", "11".repeat(32)));
    assert!(check(&v).unwrap_err().0.contains("must differ"));
    v.insert("MKIT_HOOK_KEY".into(), format!("hook {}", "33".repeat(32)));
    assert!(check(&v).is_ok());
}

#[test]
fn launch_inspection_uses_the_merged_retrieval_codec_and_separate_keys() {
    let mut v = vars();
    v.insert("HOOK_ROLES".into(), "inspect".into());
    v.insert("SCANNER_RETRIEVAL".into(), "true".into());
    let scanner =
        mkit_server::hooks::HookSigner::new("scanner", zeroize::Zeroizing::new([0x55; 32]))
            .unwrap();
    v.insert(
        "SCANNER_KEYS".into(),
        mkit_core::hash::to_hex(&scanner.public_key()),
    );
    v.insert(
        "SCANNER_RETRIEVAL_KEYS".into(),
        format!("active scanner {}", "44".repeat(32)),
    );
    let config = check(&v).unwrap();
    assert!(config.scanner_retrieval.is_some());
    assert!(
        config
            .pipeline_config()
            .unwrap()
            .scanner_retrieval
            .is_some()
    );
    v.insert(
        "SCANNER_RETRIEVAL_KEYS".into(),
        format!("active scanner {}", "11".repeat(32)),
    );
    assert!(check(&v).unwrap_err().0.contains("distinct"));
}

#[test]
fn configured_launch_cannot_run_with_a_free_runtime_plan() {
    let cfg = check(&vars()).unwrap();
    for plan in [None, Some("free"), Some("unknown")] {
        assert!(cfg.validate_for_plan(plan).is_err(), "{plan:?}");
    }
    assert!(cfg.validate_for_plan(Some(" PaId ")).is_ok());
    let baseline = WorkerConfig::from_vars(|name| match name {
        "AUTH_AUDIENCE" => Some("https://vcs.example".into()),
        "AUTH_REPOSITORY" => Some("repo".into()),
        _ => None,
    })
    .unwrap();
    assert!(baseline.validate_for_plan(Some("free")).is_ok());
}

#[test]
fn only_the_paid_workers_profile_name_starts_and_the_retired_alias_is_refused() {
    let mut v = vars();
    v.insert("LAUNCH_PROFILE".into(), "paid-workers".into());
    let cfg = check(&v).unwrap();
    cfg.validate().unwrap();
    assert_eq!(cfg.launch, Some(LaunchConfig { takedown: false }));
    assert!(cfg.pipeline_config().is_ok());
    for name in ["STORAGE_LEASES", "GC_ENABLED"] {
        let mut bad = v.clone();
        bad.insert(name.into(), "true".into());
        assert!(check(&bad).is_err());
    }
    v.insert("LAUNCH_PROFILE".into(), "uno".into());
    assert!(
        check(&v)
            .unwrap_err()
            .0
            .contains("LAUNCH_PROFILE must be paid-workers")
    );
}
