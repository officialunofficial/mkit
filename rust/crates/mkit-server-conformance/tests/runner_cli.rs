//! Exercise the installed command boundary, JSON output, and exit codes.
#![cfg(feature = "test-host")]

use mkit_server_conformance::test_host::ControlledHost;
use mkit_server_conformance::wire::{Profile, WireAuth};

fn profile_text(audience: &str) -> String {
    format!(
        "version = 1\n[wire]\nauth = 'auth-v2'\naudience = '{audience}'\nrepository = 'default'\natomic_advance = true\nfeatures = ['tickets']\nsigner_seed_hex = '{}'\nmilestone = 'M1'\n[control]\ncontrols = ['observe']\n",
        "62".repeat(32)
    )
}

async fn invoke(args: Vec<String>) -> std::process::Output {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_mkit-server-conformance"))
            .args(args)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn run_emits_only_json_and_honors_separate_control_binding() {
    let host = ControlledHost::start(Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x62; 32],
    }))
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.toml");
    std::fs::write(&path, profile_text(host.base_url())).unwrap();
    let args = |base: &str, tier: &str, filter: &str| {
        vec![
            "run".into(),
            "--base-url".into(),
            base.into(),
            "--control-url".into(),
            host.base_url().into(),
            "--profile".into(),
            path.display().to_string(),
            "--tier".into(),
            tier.into(),
            "--filter".into(),
            filter.into(),
        ]
    };
    let pass = invoke(args(
        host.base_url(),
        "controlled",
        "authority.setter_disabled",
    ))
    .await;
    assert_eq!(
        pass.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&pass.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&pass.stdout).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["passed"], true);
    assert_eq!(json["cases"][0]["status"], "pass");
    assert!(!String::from_utf8_lossy(&pass.stdout).contains(&"62".repeat(32)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_url = format!("http://{}", listener.local_addr().unwrap());
    let bad_server = tokio::spawn(async move {
        axum::serve(
            listener,
            axum::Router::new().fallback(|| async { http::StatusCode::INTERNAL_SERVER_ERROR }),
        )
        .await
        .unwrap();
    });
    let fail = invoke(args(&bad_url, "wire", "info.shape_and_policy")).await;
    assert_eq!(
        fail.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&fail.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&fail.stdout).unwrap();
    assert_eq!(json["passed"], false);
    assert_eq!(json["cases"][0]["status"], "fail");
    let empty = invoke(args(host.base_url(), "wire", "no-such-case")).await;
    assert_eq!(empty.status.code(), Some(2));
    assert!(empty.stdout.is_empty());
    bad_server.abort();
    host.shutdown().await;
}

#[tokio::test]
async fn invalid_profile_and_unavailable_binding_are_setup_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.toml");
    let args = || {
        vec![
            "run".into(),
            "--base-url".into(),
            "http://127.0.0.1:1".into(),
            "--profile".into(),
            path.display().to_string(),
        ]
    };
    std::fs::write(&path, "version=1\nsecret='private-value'\n[wire]").unwrap();
    let invalid = invoke(args()).await;
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("private-value"));
    std::fs::write(&path, profile_text("http://127.0.0.1:1")).unwrap();
    let unavailable = invoke(args()).await;
    assert_eq!(unavailable.status.code(), Some(2));
    assert!(unavailable.stdout.is_empty());
}

#[cfg(feature = "reference-runner")]
#[tokio::test]
async fn diff_embeds_reference_and_emits_json() {
    let host = ControlledHost::start(Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x62; 32],
    }))
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.toml");
    std::fs::write(&path, profile_text(host.base_url())).unwrap();
    let output = invoke(vec![
        "diff".into(),
        "--base-url".into(),
        host.base_url().into(),
        "--profile".into(),
        path.display().to_string(),
    ])
    .await;
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["version"], 1);
    assert!(
        json["cases"]
            .as_array()
            .unwrap()
            .iter()
            .all(|case| case["status"] == "matched")
    );
    host.shutdown().await;
}
