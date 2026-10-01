use super::*;
use std::collections::BTreeMap;

fn vars() -> BTreeMap<String, String> {
    [
        ("AUTH_AUDIENCE", "https://vcs.example"),
        ("LAUNCH_PROFILE", "uno"),
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
fn programmatic_launch_changes_cannot_disable_the_extraction_driver() {
    let mut cfg = check(&vars()).unwrap();
    assert!(cfg.validate().is_ok());
    cfg.indexed.as_mut().unwrap().verification = mkit_server::indexed::VerificationMode::Inline;
    assert!(cfg.validate().unwrap_err().0.contains("scheduled indexed"));
    cfg.indexed = None;
    assert!(cfg.validate().unwrap_err().0.contains("scheduled indexed"));
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
