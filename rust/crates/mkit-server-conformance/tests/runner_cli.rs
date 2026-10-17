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
            .expect("execute conformance runner")
    })
    .await
    .expect("join conformance runner")
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

#[cfg(feature = "reference-runner")]
#[tokio::test]
async fn diff_reports_excessive_pending_hint_as_runner_error_without_polling_early() {
    use axum::body::{Body, to_bytes};
    use base64::Engine as _;
    use buffa::Message as _;
    use http::{Request, Response};
    use mkit_transport_connect::generated::PendingVerification;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let host = ControlledHost::start(Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x62; 32],
    }))
    .await
    .unwrap();
    let upstream = host.base_url().to_owned();
    let advances = Arc::new(AtomicUsize::new(0));
    let observed = advances.clone();
    let router = axum::Router::new().fallback(move |request: Request<Body>| {
        let upstream = upstream.clone();
        let observed = observed.clone();
        async move {
            let (parts, body) = request.into_parts();
            if parts.uri.path().ends_with("/AdvanceRefs") {
                observed.fetch_add(1, Ordering::SeqCst);
                let detail = PendingVerification { retry_after_ms: Some(60_000), ..Default::default() }.encode_to_vec();
                let error = serde_json::json!({"code":"unavailable", "message":"pending verification", "details":[{"type":"mkit.transport.v1.PendingVerification", "value":base64::engine::general_purpose::STANDARD.encode(detail)}]});
                return Response::builder().status(503)
                    .header("content-type", "application/json").header("retry-after", "60")
                    .body(Body::from(error.to_string())).unwrap();
            }
            let bytes = to_bytes(body, 1024 * 1024).await.unwrap();
            let mut forwarded = reqwest::Client::new().request(parts.method, format!("{upstream}{}", parts.uri));
            for (name, value) in &parts.headers {
                if name != "host" && name != "content-length" { forwarded = forwarded.header(name, value); }
            }
            let reply = forwarded.body(bytes).send().await.unwrap();
            let status = reply.status();
            let content_type = reply.headers().get("content-type").cloned();
            let bytes = reply.bytes().await.unwrap();
            let mut response = Response::builder().status(status);
            if let Some(content_type) = content_type { response = response.header("content-type", content_type); }
            response.body(Body::from(bytes)).unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", listener.local_addr().unwrap());
    let proxy = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.toml");
    std::fs::write(&path, profile_text(host.base_url())).unwrap();
    let started = std::time::Instant::now();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(50),
        invoke(vec![
            "diff".into(),
            "--base-url".into(),
            proxy_url.clone(),
            "--control-url".into(),
            proxy_url,
            "--profile".into(),
            path.display().to_string(),
        ]),
    )
    .await
    .expect("oversized poll hint must fail promptly");
    assert_eq!(
        output.status.code(),
        Some(2),
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
            .any(|case| case["status"] == "runner_error")
    );
    assert_eq!(
        advances.load(Ordering::SeqCst),
        1,
        "no poll may occur before the mandatory delay"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    proxy.abort();
    host.shutdown().await;
}
