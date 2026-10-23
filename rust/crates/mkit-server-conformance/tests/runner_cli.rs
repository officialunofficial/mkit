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
    assert_eq!(empty.stdout, [] as [u8; 0]);
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
    assert_eq!(unavailable.stdout, [] as [u8; 0]);
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
async fn diff_preserves_indexed_multi_profile_and_matches_native_decisions() {
    use mkit_server_conformance::wire::Feature;

    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x62; 32],
    });
    profile.atomic_advance = true;
    profile
        .features
        .extend([Feature::MultiRepo, Feature::Tickets, Feature::IndexedMode]);
    profile.derive_features();
    let host = ControlledHost::start(profile).await.unwrap();
    assert!(host.profile().has(Feature::MultiRepo));
    assert!(host.profile().has(Feature::IndexedMode));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("indexed-profile.toml");
    std::fs::write(
        &path,
        profile_text(host.base_url()).replace(
            "features = ['tickets']",
            "features = ['tickets', 'multi-repo', 'indexed-mode']",
        ),
    )
    .unwrap();
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
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let cases = report["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    assert!(cases.iter().all(|case| case["status"] == "matched"));
    host.shutdown().await;
}

#[cfg(feature = "reference-runner")]
#[tokio::test]
async fn diff_reports_excessive_pending_hint_as_runner_error_without_polling_early() {
    pending_hint_cli(false).await;
}

#[cfg(feature = "reference-runner")]
#[tokio::test]
async fn diff_preserves_observed_acceptance_failure_before_later_pending_budget() {
    pending_hint_cli(true).await;
}

#[cfg(feature = "reference-runner")]
async fn pending_hint_proxy(
    upstream: &str,
    corrupt_accepted_observation: bool,
) -> (
    String,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use axum::body::{Body, to_bytes};
    use base64::Engine as _;
    use buffa::Message as _;
    use http::{Request, Response};
    use mkit_transport_connect::generated::PendingVerification;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let upstream = upstream.to_owned();
    let advances = Arc::new(AtomicUsize::new(0));
    let observed = advances.clone();
    let router = axum::Router::new().fallback(move |request: Request<Body>| {
        let upstream = upstream.clone();
        let observed = observed.clone();
        async move {
            let (parts, body) = request.into_parts();
            let pending = parts.uri.path().ends_with("/AdvanceRefs")
                && (observed.fetch_add(1, Ordering::SeqCst) > 0 || !corrupt_accepted_observation);
            if pending {
                let detail = PendingVerification { retry_after_ms: Some(60_000), ..Default::default() }.encode_to_vec();
                let error = serde_json::json!({"code":"unavailable", "message":"pending verification", "details":[{"type":"mkit.transport.v1.PendingVerification", "value":base64::engine::general_purpose::STANDARD.encode(detail)}]});
                return Response::builder().status(503)
                    .header("content-type", "application/json").header("retry-after", "60")
                    .body(Body::from(error.to_string())).expect("construct typed pending response");
            }
            let bytes = to_bytes(body, 1024 * 1024).await.expect("read bounded proxy request");
            let mut forwarded = reqwest::Client::new().request(parts.method, format!("{upstream}{}", parts.uri));
            for (name, value) in &parts.headers {
                if name != "host" && name != "content-length" { forwarded = forwarded.header(name, value); }
            }
            let reply = forwarded.body(bytes).send().await.expect("forward request to reference host");
            let status = reply.status();
            let content_type = reply.headers().get("content-type").cloned();
            let mut bytes = reply.bytes().await.expect("read reference response").to_vec();
            if corrupt_accepted_observation
                && parts.uri.path() == mkit_server_conformance::control::CONTROL_PATH
            {
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("decode control response");
                if let Some(reservations) = value.get_mut("observation")
                    .and_then(|snapshot| snapshot.get_mut("reservations"))
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for reservation in reservations {
                        if reservation["state"] == "committed" {
                            reservation["terminal_count"] = 2.into();
                        }
                    }
                }
                bytes = serde_json::to_vec(&value).expect("encode mutated control response");
            }
            let mut response = Response::builder().status(status);
            if let Some(content_type) = content_type { response = response.header("content-type", content_type); }
            response.body(Body::from(bytes)).expect("construct forwarded response")
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind pending-response proxy");
    let proxy_url = format!(
        "http://{}",
        listener.local_addr().expect("read proxy listener address")
    );
    let proxy = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("serve pending-response proxy");
    });
    (proxy_url, advances, proxy)
}

#[cfg(feature = "reference-runner")]
async fn pending_hint_cli(corrupt_accepted_observation: bool) {
    use std::sync::atomic::Ordering;

    let host = ControlledHost::start(Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x62; 32],
    }))
    .await
    .expect("start native reference host");
    let (proxy_url, advances, proxy) =
        pending_hint_proxy(host.base_url(), corrupt_accepted_observation).await;
    let dir = tempfile::tempdir().expect("create runner profile directory");
    let path = dir.path().join("profile.toml");
    std::fs::write(&path, profile_text(host.base_url())).expect("write runner profile");
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
        Some(if corrupt_accepted_observation { 1 } else { 2 }),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("decode runner JSON report");
    assert_eq!(json["version"], 1);
    let cases = json["cases"]
        .as_array()
        .expect("runner report has case array");
    if corrupt_accepted_observation {
        assert!(cases.iter().any(|case| case["status"] == "failed"));
        assert!(!cases.iter().any(|case| case["status"] == "runner_error"));
    } else {
        assert!(cases.iter().any(|case| case["status"] == "runner_error"));
    }
    assert_eq!(
        advances.load(Ordering::SeqCst),
        if corrupt_accepted_observation { 2 } else { 1 },
        "no poll may occur before the mandatory delay"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    proxy.abort();
    host.shutdown().await;
}
