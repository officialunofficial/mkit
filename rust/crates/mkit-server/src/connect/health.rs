//! `grpc.health.v1.Health` over [`Pipeline::health`]: the generated trait,
//! hand-implemented. The `connectrpc-health` crate would force
//! `connectrpc/server`, which is not wasm-clean (see `build.rs`).

use core::fmt;
use std::sync::Arc;

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream};

use super::Shared;
use super::proto::grpc::health::v1::health_check_response::ServingStatus;
use super::proto::grpc::health::v1::{Health, HealthCheckRequest, HealthCheckResponse};
use super::proto::mkit::transport::v1::TRANSPORT_SERVICE_SERVICE_NAME;
use crate::error::ServerError;
use crate::pipeline::{HookSet, Pipeline};
use crate::rt::send_wrap;
use crate::store::{BlobStore, NamespaceStore};

/// `Check` answers for the whole server (`""`) and for
/// `mkit.transport.v1.TransportService`: `SERVING` when both stores answer
/// their probe, else `NOT_SERVING`. Any other name is `not_found`. `Watch`
/// is `unimplemented`, which tells a Watch-capable client not to retry.
pub struct ConnectHealth<B, N, H> {
    pipe: Shared<Pipeline<B, N, H>>,
}

impl<B, N, H> fmt::Debug for ConnectHealth<B, N, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectHealth").finish_non_exhaustive()
    }
}

impl<B, N, H> ConnectHealth<B, N, H> {
    /// Health over `pipeline`'s stores.
    #[must_use]
    pub fn new(pipeline: Arc<Pipeline<B, N, H>>) -> Self {
        Self {
            pipe: Shared::new(pipeline),
        }
    }
}

#[allow(refining_impl_trait)]
impl<B, N, H> Health for ConnectHealth<B, N, H>
where
    B: BlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    async fn check(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, HealthCheckRequest>,
    ) -> ServiceResult<HealthCheckResponse> {
        let service = request.service;
        if !(service.is_empty() || service == TRANSPORT_SERVICE_SERVICE_NAME) {
            return Err(ServerError::not_found("unknown service").into());
        }
        let pipe = self.pipe.arc();
        let healthy = send_wrap(async move { pipe.health().await.is_healthy() }).await;
        let status = if healthy {
            ServingStatus::SERVING
        } else {
            ServingStatus::NOT_SERVING
        };
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
        Err(ServerError::unimplemented("Watch is not supported by this server; use Check").into())
    }
}
