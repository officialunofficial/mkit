//! Integration test for mkit#798: per-verb-class client timeouts.
//!
//! `ConnectTransport` applies a short `UNARY_TIMEOUT` to cheap unary RPCs
//! (`ListRefs`/`ReadRef`/`UpdateRef`/`AdvanceRefs`/`PackExists`) and a much
//! longer `PACK_TRANSFER_TIMEOUT` to the pack-transfer RPCs
//! (`UploadPack`/`DownloadPack`) — independently configurable via
//! `with_unary_timeout`/`with_pack_transfer_timeout`.
//!
//! This drives a real (in-process) Connect server, per
//! SPEC-TRANSPORT-CONNECT's testing-decisions bar (mirrors
//! `tests/roundtrip.rs`'s "a real server, not a mock standing in for one").
//! Both the `ListRefs` and `DownloadPack` handlers are deliberately slow by
//! the same fixed delay; the test asserts a short `unary_timeout` fails the
//! `ListRefs` call fast (nowhere near the legacy 300s budget) while a
//! *longer* `pack_transfer_timeout` on the very same client instance lets
//! the equally-slow `DownloadPack` call succeed — proving the two timeout
//! classes are wired independently rather than sharing one client-wide
//! deadline.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use connectrpc::server::Server;
use connectrpc::{RequestContext, Response, Router, ServiceRequest, ServiceResult, ServiceStream};
use mkit_core::protocol::{PackKey, Transport, TransportError};
use mkit_transport_connect::{ConnectTransport, generated};

/// Deliberately slow `TransportService`: `list_refs` and `download_pack`
/// each sleep for `delay` before responding. No other verb is exercised by
/// this test; their bodies are trivial stand-ins that satisfy the trait.
struct SlowService {
    delay: Duration,
}

#[allow(refining_impl_trait)]
impl generated::TransportService for SlowService {
    async fn list_refs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
        tokio::time::sleep(self.delay).await;
        Ok(Response::new(generated::ListRefsResponse::default()))
    }

    async fn read_ref(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::ReadRefRequest>,
    ) -> ServiceResult<generated::ReadRefResponse> {
        Ok(Response::new(generated::ReadRefResponse::default()))
    }

    async fn update_ref(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::UpdateRefRequest>,
    ) -> ServiceResult<generated::UpdateRefResponse> {
        Ok(Response::new(generated::UpdateRefResponse::default()))
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        Ok(Response::new(generated::AdvanceRefsResponse::default()))
    }

    async fn pack_exists(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
        Ok(Response::new(generated::PackExistsResponse::default()))
    }

    async fn upload_pack(
        &self,
        _ctx: RequestContext,
        _requests: connectrpc::InboundStream<generated::UploadPackRequest>,
    ) -> ServiceResult<generated::UploadPackResponse> {
        Ok(Response::new(generated::UploadPackResponse::default()))
    }

    async fn download_pack(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<generated::DownloadPackResponse>> {
        tokio::time::sleep(self.delay).await;
        let msg = request.to_owned_message();
        let pack_id = msg.pack_id.unwrap_or_default();
        let data = b"slow-pack-payload".to_vec();
        #[allow(clippy::cast_possible_truncation)]
        let total_bytes = data.len() as u64;
        let header = generated::DownloadPackResponse {
            body: Some(
                generated::DownloadPackHeader {
                    total_bytes: Some(total_bytes),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        let chunk = generated::DownloadPackResponse {
            body: Some(
                generated::PackChunk {
                    pack_id: Some(pack_id),
                    offset: Some(0),
                    data: Some(data),
                    last: Some(true),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        Response::stream_ok(futures::stream::iter([Ok(header), Ok(chunk)]))
    }
}

/// Bind a real Connect server on an ephemeral loopback port, whose
/// `ListRefs`/`DownloadPack` handlers each sleep `delay` before responding.
/// Returns the port, a shutdown trigger, and the server thread's join
/// handle — mirrors `tests/roundtrip.rs::spawn_server`.
fn spawn_slow_server(
    delay: Duration,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("build server tokio runtime");
        rt.block_on(async move {
            let bound = Server::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral loopback port");
            let port = bound
                .local_addr()
                .expect("bound server has a local addr")
                .port();
            addr_tx.send(port).expect("send bound port to test thread");

            let service = Arc::new(SlowService { delay });
            let router = Router::new().add_service(service);

            bound
                .serve_with_graceful_shutdown(router, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve TransportService");
        });
    });

    let port = addr_rx.recv().expect("recv bound port");
    (port, shutdown_tx, handle)
}

#[test]
fn unary_timeout_fires_fast_while_pack_transfer_timeout_covers_the_same_delay() {
    // Both handlers sleep 300ms. A 50ms `unary_timeout` cannot cover that;
    // a 5s `pack_transfer_timeout` comfortably can — on the very same
    // client instance, proving the two classes don't share one deadline.
    let handler_delay = Duration::from_millis(300);
    let short_unary_timeout = Duration::from_millis(50);
    let ample_pack_transfer_timeout = Duration::from_secs(5);

    let (port, shutdown, handle) = spawn_slow_server(handler_delay);
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("valid loopback URI");
    let client = ConnectTransport::connect_for_test(uri)
        .with_unary_timeout(short_unary_timeout)
        .with_pack_transfer_timeout(ample_pack_transfer_timeout);

    // -- cheap unary call: must fail, and fail fast ----------------------
    let start = Instant::now();
    let err = client
        .list_refs("")
        .expect_err("a ListRefs call slower than unary_timeout must fail");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "unary_timeout must fire well before the 300s legacy default \
         (and before the handler's own 300ms delay would have finished \
         naturally is irrelevant — 50ms must win): took {elapsed:?}"
    );
    assert!(
        !matches!(err, TransportError::PackNotFound),
        "expected a timeout-shaped error, got {err:?}"
    );

    // -- pack-transfer call: same slow handler, must still succeed ------
    let key = PackKey::new([0x77u8; 32]);
    let start = Instant::now();
    let bytes = client
        .download_pack(&key)
        .expect("a DownloadPack call within pack_transfer_timeout must succeed");
    let elapsed = start.elapsed();
    assert_eq!(bytes, b"slow-pack-payload".to_vec());
    assert!(
        elapsed >= handler_delay,
        "sanity check: the handler's delay must actually have been waited out, took {elapsed:?}"
    );
    assert!(
        elapsed < ample_pack_transfer_timeout,
        "must succeed comfortably inside the pack-transfer budget, took {elapsed:?}"
    );

    let _ = shutdown.send(());
    handle.join().expect("server thread joins cleanly");
}
