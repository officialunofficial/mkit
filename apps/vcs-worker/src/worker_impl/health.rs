// SPDX-License-Identifier: MIT OR Apache-2.0
//
// grpc.health.v1.Health service (mkit#796): reports SERVING once a cheap R2
// HEAD + RefStore DO round trip both succeed. This hand-writes the `Health`
// trait impl generated from the vendored proto/grpc/health/v1/health.proto
// (see build.rs's module docs) rather than depending on the
// `connectrpc-health` crate: that crate's Cargo.toml unconditionally depends
// on `connectrpc` with `features = ["server"]`, which pulls in `tokio/net` +
// `hyper-util/server` + `dep:libc` — none of which build for
// wasm32-unknown-unknown.

use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use worker::Env;
use worker::send::SendFuture;

use crate::proto::grpc::health::v1::{
    Health, HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus,
};
use crate::proto::mkit::transport::v1::TRANSPORT_SERVICE_SERVICE_NAME;

use super::service::{STORAGE_BUCKET, do_call};
use super::wire::{ListReq, ListResp};

/// R2 key this checker HEADs. Never written by any real handler — a `None`
/// result IS the successful case (the bucket answered; nothing needs to
/// exist there). Namespaced away from `packs/…` so it can never collide
/// with a real pack digest.
const HEALTH_PROBE_KEY: &str = "__mkit-health-check__";

pub struct HealthServer {
    env: Env,
}

impl HealthServer {
    pub fn new(env: Env) -> Self {
        Self { env }
    }
}

/// Cheap reachability probe, not a deep validation (issue #796's testing
/// decision): an R2 HEAD on a key that never exists, plus a RefStore DO
/// `/list` round trip with an empty prefix (no ref needs to exist either).
/// Both are the same store operations `TransportServer` already performs
/// for `PackExists` / `ListRefs` — this just doesn't require anything to be
/// found.
async fn probe(env: &Env) -> ServingStatus {
    let env_r2 = env.clone();
    let r2_ok = SendFuture::new(async move {
        let Ok(bucket) = env_r2.bucket(STORAGE_BUCKET) else {
            return false;
        };
        bucket.head(HEALTH_PROBE_KEY).await.is_ok()
    })
    .await;

    let env_do = env.clone();
    let do_ok = SendFuture::new(async move {
        do_call::<ListReq, ListResp>(
            &env_do,
            "/list",
            &ListReq {
                prefix: String::new(),
            },
        )
        .await
        .is_ok()
    })
    .await;

    if r2_ok && do_ok {
        ServingStatus::SERVING
    } else {
        ServingStatus::NOT_SERVING
    }
}

#[allow(refining_impl_trait)]
impl Health for HealthServer {
    async fn check(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, HealthCheckRequest>,
    ) -> ServiceResult<HealthCheckResponse> {
        let service = request.service;
        if !(service.is_empty() || service == TRANSPORT_SERVICE_SERVICE_NAME) {
            return Err(ConnectError::not_found(format!(
                "unknown service {service}"
            )));
        }

        let status = probe(&self.env).await;
        Response::ok(HealthCheckResponse {
            status: status.into(),
            ..Default::default()
        })
    }

    async fn watch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, HealthCheckRequest>,
    ) -> ServiceResult<ServiceStream<HealthCheckResponse>> {
        // kubelet's `grpc:` probe and `grpc_health_probe` only call Check;
        // this reference server has no push channel to drive a real Watch
        // stream, so it reports Unimplemented — the documented signal
        // (grpc.health.v1's own doc comment on `Watch`) telling a
        // Watch-capable client (service meshes) not to retry.
        Err(ConnectError::unimplemented(
            "Watch is not supported by this server; use Check",
        ))
    }
}
