// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Host-side integration test for mkit#796: drives `grpc.health.v1.Health`'s
// `Check` RPC through the REAL `connectrpc` `Router` + `ConnectRpcService`
// dispatch — the exact machinery `apps/vcs-worker/src/worker_impl.rs`'s
// `serve_connect` uses in production — over a genuine Connect unary HTTP
// request/response. Mirrors `apps/repo-worker/tests/purge_room_dispatch.rs`'s
// pattern and rationale for why this is host-only and needs neither the
// wasm32 target nor a live R2/Durable-Object runtime.
//
// What this test proves: the vendored `grpc.health.v1.health.proto` codegen
// registers `Check` at the documented `grpc.health.v1.Health/Check` path and
// round-trips `HealthCheckRequest.service` / `HealthCheckResponse.status`
// through proto3-JSON at their documented wire names. It does NOT (and, on
// this host target, cannot) prove that the real `worker_impl::health::
// HealthServer` correctly probes R2/the RefStore DO — that handler is
// `#[cfg(target_arch = "wasm32")]` only (see `src/lib.rs`'s module doc) and
// needs a live Workers runtime to execute, not just compile. That gap is
// closed by the wasm32 build (compiles the real R2/DO probe) plus a manual
// `wrangler dev --local` pass, exactly like every other RPC in this crate.

use bytes::Bytes;
use connectrpc::{
    ConnectError, ConnectRpcService, RequestContext, Response, Router, ServiceRequest,
    ServiceResult, ServiceStream,
};
use http_body_util::{BodyExt, Full};
use mkit_vcs_worker::proto::grpc::health::v1::{
    Health, HealthCheckRequest, HealthCheckResponse, HealthExt,
    health_check_response::ServingStatus,
};
use std::sync::Arc;
use tower::ServiceExt;

/// A minimal `Health` test double, standing in for the real
/// `worker_impl::health::HealthServer` (whose `probe()` touches R2/the
/// RefStore DO through `worker::Env` and so cannot run on this host target).
/// Reports `status` for `""` and `known_service`; anything else is
/// `NotFound` — the exact contract `HealthServer::check` implements.
struct FakeHealthService {
    known_service: &'static str,
    status: ServingStatus,
}

#[allow(refining_impl_trait)]
impl Health for FakeHealthService {
    async fn check(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, HealthCheckRequest>,
    ) -> ServiceResult<HealthCheckResponse> {
        let service = request.service;
        if !(service.is_empty() || service == self.known_service) {
            return Err(ConnectError::not_found(format!(
                "unknown service {service}"
            )));
        }
        Response::ok(HealthCheckResponse {
            status: self.status.into(),
            ..Default::default()
        })
    }

    async fn watch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, HealthCheckRequest>,
    ) -> ServiceResult<ServiceStream<HealthCheckResponse>> {
        Err(ConnectError::unimplemented("not exercised by this test"))
    }
}

async fn check_over_wire(service: &FakeHealthService, requested: &str) -> serde_json::Value {
    let router: Router = Arc::new(FakeHealthService {
        known_service: service.known_service,
        status: service.status,
    })
    .register(Router::new());
    let svc = ConnectRpcService::new(router);

    let body = serde_json::to_vec(&serde_json::json!({ "service": requested })).unwrap();
    let http_req = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://localhost/grpc.health.v1.Health/Check")
        .header("content-type", "application/json")
        .header("connect-protocol-version", "1")
        .body(Full::new(Bytes::from(body)))
        .unwrap();

    let http_resp = svc
        .oneshot(http_req)
        .await
        .expect("ConnectRpcService error is Infallible");
    assert_eq!(http_resp.status(), http::StatusCode::OK);

    let body_bytes = http_resp
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    serde_json::from_slice(&body_bytes).expect("HealthCheckResponse is valid JSON")
}

#[tokio::test]
async fn health_check_reports_serving_under_normal_conditions() {
    let service = FakeHealthService {
        known_service: "mkit.transport.v1.TransportService",
        status: ServingStatus::SERVING,
    };

    // Whole-process entry (empty service name) — proto3-JSON omits a
    // default-valued `status` (SERVING == 1, not the zero value), so
    // decode via the SDK-shaped enum below is what asserts this rather
    // than raw JSON field presence.
    let resp = check_over_wire(&service, "").await;
    assert_eq!(resp["status"], "SERVING");

    // The registered TransportService by name.
    let resp = check_over_wire(&service, "mkit.transport.v1.TransportService").await;
    assert_eq!(resp["status"], "SERVING");
}

#[tokio::test]
async fn health_check_reports_not_serving_when_the_backing_store_check_fails() {
    let service = FakeHealthService {
        known_service: "mkit.transport.v1.TransportService",
        status: ServingStatus::NOT_SERVING,
    };
    let resp = check_over_wire(&service, "").await;
    assert_eq!(resp["status"], "NOT_SERVING");
}

#[tokio::test]
async fn health_check_unknown_service_is_not_found_not_a_status() {
    let service = FakeHealthService {
        known_service: "mkit.transport.v1.TransportService",
        status: ServingStatus::SERVING,
    };
    let router: Router = Arc::new(FakeHealthService {
        known_service: service.known_service,
        status: service.status,
    })
    .register(Router::new());
    let svc = ConnectRpcService::new(router);

    let body = serde_json::to_vec(&serde_json::json!({ "service": "acme.NoSuchService" })).unwrap();
    let http_req = http::Request::builder()
        .method(http::Method::POST)
        .uri("http://localhost/grpc.health.v1.Health/Check")
        .header("content-type", "application/json")
        .header("connect-protocol-version", "1")
        .body(Full::new(Bytes::from(body)))
        .unwrap();

    let http_resp = svc
        .oneshot(http_req)
        .await
        .expect("ConnectRpcService error is Infallible");
    assert_eq!(http_resp.status(), http::StatusCode::NOT_FOUND);
}
