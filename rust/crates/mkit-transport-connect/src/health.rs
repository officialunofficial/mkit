//! `grpc.health.v1.Health` wiring for `mkit serve --http` (mkit#796).
//!
//! Delegates the wire protocol entirely to the upstream
//! [`connectrpc_health`] crate (already wire-compatible with
//! `grpc_health_probe` / kubelet gRPC probes / service meshes) — this
//! module supplies only the [`Checker`] that decides what SERVING means
//! for a [`Transport`]-backed `mkit serve --http`.

use std::sync::Arc;

use connectrpc::ConnectError;
use connectrpc_health::{Checker, Status};
use mkit_core::protocol::Transport;

use crate::proto::mkit::transport::v1::TRANSPORT_SERVICE_SERVICE_NAME;
use crate::service::blocking;

/// Reports SERVING for the whole-process entry (`""`) and for
/// `mkit.transport.v1.TransportService` once a cheap read against the
/// wrapped [`Transport`] succeeds; any other service name is unknown to
/// this checker.
pub(crate) struct TransportChecker<T> {
    transport: Arc<T>,
}

impl<T> TransportChecker<T> {
    pub(crate) fn new(transport: Arc<T>) -> Self {
        Self { transport }
    }
}

impl<T: Transport + Send + Sync + 'static> Checker for TransportChecker<T> {
    async fn check(&self, service: &str) -> Result<Status, ConnectError> {
        if !(service.is_empty() || service == TRANSPORT_SERVICE_SERVICE_NAME) {
            return Err(ConnectError::not_found(format!(
                "unknown service {service}"
            )));
        }

        // Cheap store read, not a deep validation (issue #796's testing
        // decision): `list_refs("")` is a valid call against every
        // `Transport` backend (an empty prefix always matches, per
        // SPEC-TRANSPORT-CONNECT §4) and requires no ref to actually
        // exist — it just needs the store to answer. A transport error
        // here (e.g. the backing directory/bucket became unreachable)
        // reports `NotServing` rather than propagating as a Check RPC
        // error, matching the gRPC Health contract: Check itself always
        // succeeds for a known service, carrying the degraded status in
        // the response body instead of the transport-level error.
        let probe = blocking(Arc::clone(&self.transport), |t| t.list_refs("")).await;
        Ok(match probe {
            Ok(_) => Status::Serving,
            Err(_) => Status::NotServing,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use connectrpc_health::Checker as _;
    use mkit_transport_memory::MemoryTransport;

    use super::*;

    #[tokio::test]
    async fn empty_service_name_is_serving_when_store_is_reachable() {
        let checker = TransportChecker::new(Arc::new(MemoryTransport::new()));
        assert_eq!(checker.check("").await.unwrap(), Status::Serving);
    }

    #[tokio::test]
    async fn transport_service_name_is_serving_when_store_is_reachable() {
        let checker = TransportChecker::new(Arc::new(MemoryTransport::new()));
        assert_eq!(
            checker.check(TRANSPORT_SERVICE_SERVICE_NAME).await.unwrap(),
            Status::Serving
        );
    }

    #[tokio::test]
    async fn unknown_service_name_is_not_found() {
        let checker = TransportChecker::new(Arc::new(MemoryTransport::new()));
        let err = checker.check("acme.NoSuchService").await.unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::NotFound);
    }
}
