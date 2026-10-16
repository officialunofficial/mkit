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
    SetterPending,
    SetterDenied,
    SetterMissingDelay,
}

#[derive(Default)]
struct Model {
    initial: Option<Value>,
    rolled_back: bool,
    authority_changed: bool,
    replay_repairs: usize,
    mutations: usize,
    setter_requests: Vec<Vec<u8>>,
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

fn setter_refusal(state: &ProxyState, body: &[u8]) -> Option<Response> {
    if !matches!(
        state.fault,
        Fault::SetterPending | Fault::SetterDenied | Fault::SetterMissingDelay
    ) {
        return None;
    }
    let mut model = state.model.lock().expect("isolated setter oracle");
    model.setter_requests.push(body.to_vec());
    if model.setter_requests.len() > 1 {
        return None;
    }
    let denied = matches!(state.fault, Fault::SetterDenied);
    let mut response = Response::new(Body::from(if denied {
        r#"{"code":"permission_denied","message":"fixture refusal"}"#
    } else {
        r#"{"code":"unavailable","message":"authority barrier pending"}"#
    }));
    *response.status_mut() = if denied {
        http::StatusCode::FORBIDDEN
    } else {
        http::StatusCode::SERVICE_UNAVAILABLE
    };
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    if !matches!(state.fault, Fault::SetterMissingDelay) {
        response.headers_mut().insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("0"),
        );
    }
    Some(response)
}

async fn forward(State(state): State<Arc<ProxyState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 16 * 1024 * 1024)
        .await
        .expect("valid isolated fault-proxy fixture");
    if parts.uri.path().ends_with("/SetAuthorityGeneration")
        && let Some(response) = setter_refusal(&state, &body)
    {
        return response;
    }
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
        Fault::RollbackOnRestart if filter == "acceptance.before_acceptance_restart" => {
            "recovery exposed a partial acceptance before replay"
        }
        Fault::RollbackOnRestart => "recovery lost or changed accepted state",
        Fault::ChargeOnRefusal => "guard failure changed quota charge",
        Fault::CommitOnRefusal => "exactly one aborted ref reservation",
        Fault::SetterPending | Fault::SetterDenied | Fault::SetterMissingDelay => {
            unreachable!("separate setter oracle")
        }
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

#[tokio::test]
async fn pending_reservation_loss_is_detected_before_replay_can_replace_it() {
    assert_eq!(
        run_mutant(
            Fault::RollbackOnRestart,
            "acceptance.before_acceptance_restart"
        )
        .await,
        0
    );
}

#[tokio::test]
async fn authority_setter_retries_only_a_valid_pending_response() {
    for (fault, passes, requests) in [
        (Fault::SetterPending, true, 2),
        (Fault::SetterDenied, false, 1),
        (Fault::SetterMissingDelay, false, 1),
    ] {
        let host = ControlledHost::start(profile())
            .await
            .expect("isolated setter host");
        let proxy = FaultProxy::start(host.base_url(), fault).await;
        let target = WireTarget {
            base_url: proxy.base_url.parse().expect("isolated setter URL"),
            profile: host.profile().clone(),
        };
        let report = mkit_server_conformance::controlled::run(
            &target,
            &BTreeMap::new(),
            Some("authority.setter_enabled"),
        )
        .await;
        assert_eq!(!report.failed(), passes, "{}", report.tap());
        {
            let model = proxy.state.model.lock().expect("isolated setter oracle");
            assert_eq!(model.setter_requests.len(), requests, "{}", report.tap());
            assert!(
                model
                    .setter_requests
                    .windows(2)
                    .all(|pair| pair[0] == pair[1]),
                "setter retry changed its signed statement"
            );
        }
        host.shutdown().await;
    }
}
