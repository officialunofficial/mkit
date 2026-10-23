#![cfg(feature = "test-host")]

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use mkit_server_conformance::test_host::ControlledHost;
use mkit_server_conformance::wire::{Feature, Profile, WireAuth, WireTarget};
use mkit_server_conformance::{control, controlled};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn profile() -> Profile {
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x64; 32],
    });
    profile.atomic_advance = true;
    profile.quota = Some(mkit_server_conformance::wire::QuotaLimits {
        max_ops: 64,
        max_bytes: 4 * 1024 * 1024,
        window_ms: 3_600_000,
    });
    profile
        .features
        .extend([Feature::MultiRepo, Feature::Tickets, Feature::IndexedMode]);
    profile.derive_features();
    profile
}

#[tokio::test]
async fn real_wire_publication_covers_recovery_prefix_deletion_and_combined_race() {
    let host = ControlledHost::start(profile())
        .await
        .expect("isolated indexed host");
    let target = WireTarget {
        base_url: host.base_url().parse().unwrap(),
        profile: host.profile().clone(),
    };
    let report = controlled::run(&target, &BTreeMap::new(), Some("publication.")).await;
    assert_eq!(report.cases.len(), 5, "{}", report.tap());
    assert!(!report.failed(), "{}", report.tap());
    assert_eq!(report.passes().len(), 5, "{}", report.tap());
    host.shutdown().await;
}

#[tokio::test]
async fn optional_removal_features_and_combined_publication_are_truthful() {
    use mkit_server_conformance::wire::Verdict;
    let host = ControlledHost::start(profile()).await.unwrap();
    let mut declared = host.profile().clone();
    declared.features.remove(&Feature::CombinedPublication);
    let target = WireTarget {
        base_url: host.base_url().parse().unwrap(),
        profile: declared,
    };
    for filter in ["publication.combined_", "reliance."] {
        let report = controlled::run(&target, &BTreeMap::new(), Some(filter)).await;
        assert_ne!(
            report.cases,
            [] as [mkit_server_conformance::wire::CaseReport; 0]
        );
        assert!(
            report
                .cases
                .iter()
                .all(|case| matches!(case.verdict, Verdict::NotApplicable(_))),
            "{}",
            report.tap()
        );
    }
    let client = mkit_server_conformance::controlled::ControlClient::new(&target.base_url).unwrap();
    let capabilities = client.capabilities().await.unwrap();
    for capability in [
        "reliance.fixture",
        "reliance.observe",
        "gc.prepare_drop",
        "gc.commit_drop",
        "inspection.hide_member",
    ] {
        assert!(capabilities.unsupported.contains_key(capability));
        assert!(!capabilities.controls.iter().any(|name| name == capability));
    }
    assert!(
        client
            .command(&control::Request::CommitGcDrop {
                repository: "not-a-repository".into(),
                pack: "not-a-pack".into(),
            })
            .await
            .unwrap_err()
            .contains("HTTP 501")
    );
    host.shutdown().await;
}

#[derive(Clone, Copy)]
enum Fault {
    TornPair,
    DuplicateTerminal,
}

struct ProxyState {
    upstream: String,
    client: reqwest::Client,
    fault: Fault,
    mutations: AtomicUsize,
}
struct Proxy {
    base: String,
    state: Arc<ProxyState>,
    task: tokio::task::JoinHandle<()>,
}

impl Proxy {
    async fn start(upstream: &str, fault: Fault) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("valid isolated publication fault-proxy fixture");
        let base = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("valid isolated publication fault-proxy fixture")
        );
        let state = Arc::new(ProxyState {
            upstream: upstream.into(),
            client: reqwest::Client::new(),
            fault,
            mutations: AtomicUsize::new(0),
        });
        let app = axum::Router::new()
            .fallback(forward)
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("valid isolated publication fault-proxy fixture");
        });
        Self { base, state, task }
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward(State(state): State<Arc<ProxyState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 16 * 1024 * 1024)
        .await
        .expect("valid isolated publication fault-proxy fixture");
    let observing = parts.uri.path() == control::CONTROL_PATH
        && serde_json::from_slice::<Value>(&body)
            .expect("valid isolated publication fault-proxy fixture")["operation"]
            == "observe_publication";
    let mut headers = parts.headers;
    headers.remove(http::header::HOST);
    headers.remove(http::header::TRANSFER_ENCODING);
    let reply = state
        .client
        .request(parts.method, format!("{}{}", state.upstream, parts.uri))
        .headers(headers)
        .body(body)
        .send()
        .await
        .expect("valid isolated publication fault-proxy fixture");
    let status = reply.status();
    let mut headers = reply.headers().clone();
    let mut body = reply
        .bytes()
        .await
        .expect("valid isolated publication fault-proxy fixture")
        .to_vec();
    if observing && status.is_success() {
        let mut value: Value =
            serde_json::from_slice(&body).expect("valid isolated publication fault-proxy fixture");
        let snapshot = &mut value["publication_observation"];
        if snapshot["published_head"].is_string() {
            match state.fault {
                Fault::TornPair => snapshot["published_packmap"] = Value::Null,
                Fault::DuplicateTerminal => {
                    snapshot["acceptance"]["reservations"][0]["terminal_count"] = 2.into();
                }
            }
            state.mutations.fetch_add(1, Ordering::Relaxed);
            body =
                serde_json::to_vec(&value).expect("valid isolated publication fault-proxy fixture");
        }
    }
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[tokio::test]
async fn publication_oracle_rejects_torn_pair_and_second_settlement() {
    for fault in [Fault::TornPair, Fault::DuplicateTerminal] {
        let host = ControlledHost::start(profile()).await.unwrap();
        let proxy = Proxy::start(host.base_url(), fault).await;
        let target = WireTarget {
            base_url: proxy.base.parse().unwrap(),
            profile: host.profile().clone(),
        };
        let report = controlled::run(
            &target,
            &BTreeMap::new(),
            Some("publication.deferred_restart_no_resettlement"),
        )
        .await;
        assert!(
            proxy.state.mutations.load(Ordering::Relaxed) > 0,
            "fault not reached: {}",
            report.tap()
        );
        assert!(
            report.failed(),
            "publication fault escaped: {}",
            report.tap()
        );
        let expected = match fault {
            Fault::TornPair => "torn published pair",
            Fault::DuplicateTerminal => "clearance repeated or changed acceptance effects",
        };
        assert!(
            report.tap().contains(expected),
            "wrong failure: {}",
            report.tap()
        );
        host.shutdown().await;
    }
}
