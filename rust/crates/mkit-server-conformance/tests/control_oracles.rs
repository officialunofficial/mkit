#![cfg(feature = "test-host")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use mkit_server_conformance::control;
use mkit_server_conformance::test_host::ControlledHost;
use mkit_server_conformance::wire::{Feature, Profile, QuotaLimits, WireAuth, WireTarget};
use serde_json::Value;

#[derive(Clone, Copy)]
enum Fault {
    RollbackOnRestart,
    ChargeOnRefusal,
    CommitOnRefusal,
}

#[derive(Default)]
struct Model {
    initial: Option<Value>,
    rolled_back: bool,
    authority_changed: bool,
    replay_repairs: usize,
    mutations: usize,
}

struct ProxyState {
    upstream: String,
    client: reqwest::Client,
    fault: Fault,
    model: Mutex<Model>,
}

struct FaultProxy {
    base_url: String,
    state: Arc<ProxyState>,
    task: tokio::task::JoinHandle<()>,
}

impl FaultProxy {
    async fn start(upstream: &str, fault: Fault) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("valid isolated fault-proxy fixture");
        let base_url = format!(
            "http://{}",
            listener
                .local_addr()
                .expect("valid isolated fault-proxy fixture")
        );
        let state = Arc::new(ProxyState {
            upstream: upstream.into(),
            client: reqwest::Client::new(),
            fault,
            model: Mutex::new(Model::default()),
        });
        let app = axum::Router::new()
            .fallback(forward)
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("valid isolated fault-proxy fixture");
        });
        Self {
            base_url,
            state,
            task,
        }
    }
}

impl Drop for FaultProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward(State(state): State<Arc<ProxyState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 16 * 1024 * 1024)
        .await
        .expect("valid isolated fault-proxy fixture");
    let operation = (parts.uri.path() == control::CONTROL_PATH).then(|| {
        serde_json::from_slice::<Value>(&body).expect("valid isolated fault-proxy fixture")
    });
    let operation = operation
        .as_ref()
        .and_then(|value| value["operation"].as_str());
    if parts.uri.path().ends_with("/AdvanceRefs") {
        let mut model = state
            .model
            .lock()
            .expect("valid isolated fault-proxy fixture");
        if model.rolled_back {
            // Model the exact false positive: a retry repairs a lost accepted
            // transaction. Recovery must be observed before this can happen.
            model.rolled_back = false;
            model.replay_repairs += 1;
        }
    }
    let url = format!("{}{}", state.upstream, parts.uri);
    let mut headers = parts.headers;
    headers.remove(http::header::HOST);
    headers.remove(http::header::TRANSFER_ENCODING);
    let response = state
        .client
        .request(parts.method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .expect("valid isolated fault-proxy fixture");
    let status = response.status();
    let mut headers = response.headers().clone();
    let mut body = response
        .bytes()
        .await
        .expect("valid isolated fault-proxy fixture")
        .to_vec();
    if status.is_success() {
        mutate_observation(&state, operation, &mut body);
    }
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

fn mutate_observation(state: &ProxyState, operation: Option<&str>, body: &mut Vec<u8>) {
    let mut model = state
        .model
        .lock()
        .expect("valid isolated fault-proxy fixture");
    match operation {
        Some("restart") if matches!(state.fault, Fault::RollbackOnRestart) => {
            model.rolled_back = true;
        }
        Some("bump_authority") => model.authority_changed = true,
        Some("observe") => {
            let mut response: Value =
                serde_json::from_slice(body).expect("valid isolated fault-proxy fixture");
            let observation = &mut response["observation"];
            if model.initial.is_none() {
                model.initial = Some(observation.clone());
            }
            match state.fault {
                Fault::RollbackOnRestart if model.rolled_back => {
                    *observation = model
                        .initial
                        .clone()
                        .expect("valid isolated fault-proxy fixture");
                    model.mutations += 1;
                }
                Fault::ChargeOnRefusal if model.authority_changed => {
                    let ops = observation["quota"]["ops"].as_u64().unwrap_or(0);
                    let bytes = observation["quota"]["bytes"].as_u64().unwrap_or(0);
                    observation["quota"] = serde_json::json!({"ops": ops + 1, "bytes": bytes});
                    model.mutations += 1;
                }
                Fault::CommitOnRefusal if model.authority_changed => {
                    let reservation = observation["reservations"]
                        .as_array_mut()
                        .expect("valid isolated fault-proxy fixture")
                        .last_mut()
                        .expect("valid isolated fault-proxy fixture");
                    *reservation = serde_json::json!({"state":"committed", "terminal_count":1});
                    model.mutations += 1;
                }
                _ => {}
            }
            *body = serde_json::to_vec(&response).expect("valid isolated fault-proxy fixture");
        }
        _ => {}
    }
}

fn profile() -> Profile {
    let owner = ed25519_dalek::SigningKey::from_bytes(&[0x32; 32]);
    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: format!(
            "ed25519-{}/oracle",
            mkit_core::hash::to_hex(owner.verifying_key().as_bytes())
        ),
        seed: [0x62; 32],
    });
    profile.atomic_advance = true;
    profile.quota = Some(QuotaLimits {
        max_ops: 32,
        max_bytes: 1024 * 1024,
        window_ms: 3_600_000,
    });
    profile
        .features
        .extend([Feature::MultiRepo, Feature::Tickets]);
    profile.derive_features();
    profile
}

async fn run_mutant(fault: Fault, filter: &str) -> usize {
    let host = ControlledHost::start(profile())
        .await
        .expect("valid isolated fault-proxy fixture");
    let proxy = FaultProxy::start(host.base_url(), fault).await;
    let target = WireTarget {
        base_url: proxy
            .base_url
            .parse()
            .expect("valid isolated fault-proxy fixture"),
        profile: host.profile().clone(),
    };
    let report =
        mkit_server_conformance::controlled::run(&target, &BTreeMap::new(), Some(filter)).await;
    assert!(
        report.failed(),
        "mutant escaped the runner: {}",
        report.tap()
    );
    assert_eq!(report.cases.len(), 1);
    let expected = match fault {
        Fault::RollbackOnRestart => "recovery lost or changed accepted state",
        Fault::ChargeOnRefusal => "guard failure changed quota charge",
        Fault::CommitOnRefusal => "exactly one aborted ref reservation",
    };
    assert!(
        matches!(&report.cases[0].verdict, mkit_server_conformance::wire::Verdict::Fail(reason) if reason.contains(expected)),
        "wrong oracle failed: {}",
        report.tap()
    );
    let repairs = {
        let model = proxy
            .state
            .model
            .lock()
            .expect("valid isolated fault-proxy fixture");
        assert!(
            model.mutations > 0,
            "fault was never exercised: {}",
            report.tap()
        );
        model.replay_repairs
    };
    host.shutdown().await;
    repairs
}

#[tokio::test]
async fn acknowledged_rollback_is_detected_before_replay_can_repair_it() {
    assert_eq!(
        run_mutant(
            Fault::RollbackOnRestart,
            "acceptance.after_response_restart"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn final_guard_rejects_a_charge_or_committed_reservation_on_refusal() {
    for fault in [Fault::ChargeOnRefusal, Fault::CommitOnRefusal] {
        run_mutant(fault, "guard.authority_final_boundary").await;
    }
}
