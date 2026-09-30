//! Release startup selection is explicit and optional features fail closed.
#![cfg(feature = "http")]
#![allow(clippy::unwrap_used)]

mod common;

fn flags(root: &std::path::Path) -> Vec<String> {
    let tickets = root.join("ticket.keys");
    common::secret_file(
        &tickets,
        format!("tickets {}\n", "11".repeat(32)).as_bytes(),
    );
    [
        "--listen".into(),
        "127.0.0.1:0".into(),
        "--repo-root".into(),
        common::s(root).into(),
        "--meta".into(),
        format!("sqlite:{}", common::s(&root.join("metadata.sqlite"))),
        "--auth".into(),
        "auth-v2".into(),
        "--audience".into(),
        "https://server.example".into(),
        "--addressing".into(),
        "multi".into(),
        "--namespace-policy".into(),
        "any".into(),
        "--unsafe-open-namespaces".into(),
        "--ticket-key-file".into(),
        common::s(&tickets).into(),
        "--launch-profile".into(),
        "uno".into(),
    ]
    .into()
}

fn resolve(
    flags: &[String],
) -> Result<mkit_server_native::config::ServeConfig, mkit_server_native::config::ConfigError> {
    common::resolve_with(&flags.iter().map(String::as_str).collect::<Vec<_>>(), &[])
}

#[test]
fn launch_implies_indexed_and_keeps_http_opt_in() {
    let root = common::repo_root();
    let config = resolve(&flags(root.path())).unwrap();
    let indexed = config.pipeline.indexed.unwrap();
    assert_eq!(
        indexed.verification,
        mkit_server::indexed::VerificationMode::Inline
    );
    assert_eq!(
        indexed.max_pack_bytes,
        config.pipeline.upload_limits.max_total_bytes
    );
    assert_eq!(config.pipeline.begin_upload_threshold_bytes, 0);
    #[cfg(feature = "http-objects")]
    assert!(config.pipeline.http_objects.is_none() && config.router.http_objects.is_none());
}

#[test]
fn launch_refuses_wrong_sharding_and_partial_indexed_limits() {
    let root = common::repo_root();
    let mut launch = flags(root.path());
    launch.extend(["--sharding".into(), "single".into()]);
    assert!(
        resolve(&launch)
            .unwrap_err()
            .message
            .contains("--sharding d34")
    );
    let mut launch = flags(root.path());
    launch.extend(["--indexed-decode-budget".into(), "1".into()]);
    assert!(
        resolve(&launch)
            .unwrap_err()
            .message
            .contains("invalid indexed")
    );
    let mut core = flags(root.path());
    core.truncate(core.len() - 2);
    core.extend(["--indexed-decode-budget".into(), "1".into()]);
    assert!(
        resolve(&core)
            .unwrap_err()
            .message
            .contains("indexed limits require")
    );
}

#[cfg(not(feature = "test-faults"))]
#[test]
fn release_indexed_requires_explicit_launch_profile() {
    let root = common::repo_root();
    let mut core = flags(root.path());
    core.truncate(core.len() - 2);
    core.push("--indexed".into());
    assert!(
        resolve(&core)
            .unwrap_err()
            .message
            .contains("--launch-profile uno")
    );
}

#[test]
fn http_cannot_activate_outside_launch_or_without_compiled_support() {
    let root = common::repo_root();
    let mut core = flags(root.path());
    core.truncate(core.len() - 2);
    core.push("--http-objects".into());
    assert!(
        resolve(&core)
            .unwrap_err()
            .message
            .contains("--launch-profile uno")
    );
    #[cfg(not(feature = "http-objects"))]
    {
        let mut launch = flags(root.path());
        launch.push("--http-objects".into());
        assert!(
            resolve(&launch)
                .unwrap_err()
                .message
                .contains("cargo feature")
        );
    }
}

#[cfg(feature = "http-objects")]
#[test]
fn http_launch_requires_dedicated_tokens_and_mounts_native_proofs() {
    let root = common::repo_root();
    let mut launch = flags(root.path());
    launch.push("--http-objects".into());
    assert!(
        resolve(&launch)
            .unwrap_err()
            .message
            .contains("--url-token-key-file")
    );
    let tokens = root.path().join("url.keys");
    common::secret_file(&tokens, format!("active {}\n", "22".repeat(32)).as_bytes());
    launch.extend(["--url-token-key-file".into(), common::s(&tokens).into()]);
    let config = resolve(&launch).unwrap();
    assert!(config.pipeline.http_objects.is_some());
    assert!(config.pipeline.url_tokens.is_some());
    assert!(config.router.http_objects.is_some());
    common::secret_file(&tokens, format!("active {}\n", "11".repeat(32)).as_bytes());
    assert!(
        resolve(&launch)
            .unwrap_err()
            .message
            .contains("key separation")
    );
}

#[cfg(feature = "hooks")]
#[test]
fn launch_inspection_validates_then_refuses_missing_retrieval() {
    let root = common::repo_root();
    let hook_key = root.path().join("hook.key");
    common::secret_file(&hook_key, format!("hook {}\n", "33".repeat(32)).as_bytes());
    let mut launch = flags(root.path());
    launch.extend([
        "--hook-inspect-url".into(),
        "https://scanner.example".into(),
        "--hook-key-file".into(),
        common::s(&hook_key).into(),
    ]);
    let error = resolve(&launch).unwrap_err();
    assert_eq!(error.code, mkit_server_native::exit::UNAVAILABLE);
    assert!(error.message.contains("R-193 scanner retrieval"));
    launch.extend(["--inspect-mode".into(), "async".into()]);
    assert!(
        resolve(&launch)
            .unwrap_err()
            .message
            .contains("sync and fail_closed")
    );
}
