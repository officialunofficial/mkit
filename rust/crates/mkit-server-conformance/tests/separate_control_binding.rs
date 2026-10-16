#![cfg(feature = "test-host")]

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::response::IntoResponse as _;
use mkit_server_conformance::test_host::ControlledHost;
use mkit_server_conformance::wire::{Profile, WireAuth, WireTarget};
use mkit_server_conformance::{control, controlled};

#[tokio::test]
async fn controlled_cases_keep_transport_requests_on_the_transport_origin() {
    let host = ControlledHost::start(Profile::new(WireAuth::AuthV2 {
        audience: "http://placeholder.invalid".into(),
        repository: "default".into(),
        seed: [0x52; 32],
    }))
    .await
    .unwrap();
    let origin = Arc::new(host.base_url().to_owned());
    let proxy = axum::Router::new()
        .route(control::CAPABILITIES_PATH, axum::routing::any(forward))
        .route(control::CONTROL_PATH, axum::routing::any(forward))
        .with_state(origin);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_url = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let proxy = tokio::spawn(async move { axum::serve(listener, proxy).await.unwrap() });
    let target = WireTarget {
        base_url: host.base_url().parse().unwrap(),
        profile: host.profile().clone(),
    };
    for filter in [
        "authority.setter_disabled",
        "acceptance.after_response_restart",
    ] {
        let report =
            controlled::run_with_control(&target, &control_url, &BTreeMap::new(), Some(filter))
                .await;
        assert!(!report.failed(), "{}", report.tap());
        assert_eq!(report.passes().len(), 1, "{}", report.tap());
    }
    proxy.abort();
    host.shutdown().await;
}

async fn forward(
    axum::extract::State(origin): axum::extract::State<Arc<String>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    let reply = reqwest::Client::new()
        .request(parts.method, format!("{origin}{}", parts.uri))
        .headers(parts.headers)
        .body(body)
        .send()
        .await
        .unwrap();
    (reply.status(), reply.bytes().await.unwrap()).into_response()
}
