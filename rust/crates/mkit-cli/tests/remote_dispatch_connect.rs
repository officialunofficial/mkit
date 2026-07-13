//! Integration coverage for the `mkit+https` / `mkit+http` dispatch
//! branch in [`mkit_cli::remote_dispatch::open`] — now backed by
//! [`mkit_transport_connect::ConnectTransport`] (mkit#701), the native
//! `mkit.transport.v1` `ConnectRPC` client.
//!
//! Replaces the retired `remote_dispatch_http.rs`, whose `mockito`-based
//! fixture mocked the now-inactive `mkit-transport-http` JSON dialect —
//! per this issue's testing decision, the replacement drives a full
//! push/pull roundtrip against a REAL in-process
//! `mkit.transport.v1.TransportService` server (a `connectrpc` hyper
//! server, memory-backed) instead of a mock standing in for one.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc;

use connectrpc::server::Server;
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, Router, ServiceRequest, ServiceResult,
    ServiceStream,
};
use futures::StreamExt;
use mkit_cli::remote_dispatch;
use mkit_core::protocol::{AdvanceOutcome, PackKey, RefWriteCondition, Transport, TransportError};
use mkit_transport_connect::generated;
use mkit_transport_memory::MemoryTransport;

use generated::__buffa::oneof::upload_pack_request::Body as UploadBody;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

// ---------------------------------------------------------------------------
// In-process TransportService server (memory-backed) — see
// mkit-transport-connect/tests/roundtrip.rs for the crate-local sibling of
// this fixture; duplicated here (not shared) so this crate's tests don't
// need a `test-support` feature on `mkit-transport-connect`.
// ---------------------------------------------------------------------------

fn to_connect_error(err: TransportError) -> ConnectError {
    match err {
        TransportError::PackNotFound => ConnectError::not_found("pack not found"),
        TransportError::AccessDenied => ConnectError::permission_denied("access denied"),
        TransportError::RefConflict => ConnectError::failed_precondition("ref CAS conflict"),
        TransportError::InvalidRef(msg) => ConnectError::invalid_argument(msg),
        TransportError::PayloadTooLarge(n) => {
            ConnectError::resource_exhausted(format!("payload too large: {n} bytes"))
        }
        TransportError::ProtocolError => ConnectError::invalid_argument("protocol error"),
        TransportError::ServerError { status } if status >= 500 || status == 429 => {
            ConnectError::unavailable(format!("server error {status}"))
        }
        TransportError::ServerError { status } => {
            ConnectError::unknown(format!("server error {status}"))
        }
        TransportError::RemoteError(msg) => ConnectError::unknown(msg),
        TransportError::ConnectionFailed
        | TransportError::InvalidResponse
        | TransportError::InsecureScheme => ConnectError::new(
            ErrorCode::Internal,
            "unexpected client-only error surfaced server-side",
        ),
    }
}

fn to_hash(bytes: Option<Vec<u8>>) -> Result<mkit_core::hash::Hash, ConnectError> {
    let bytes = bytes.ok_or_else(|| ConnectError::invalid_argument("missing 32-byte digest"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| ConnectError::invalid_argument("digest must be exactly 32 bytes"))
}

fn wire_to_condition(
    expectation: Option<buffa::EnumValue<generated::RefExpectation>>,
    expected_id: Option<Vec<u8>>,
) -> Result<RefWriteCondition, ConnectError> {
    match expectation.and_then(|e| e.as_known()) {
        Some(generated::RefExpectation::Any) => Ok(RefWriteCondition::Any),
        Some(generated::RefExpectation::Missing) => Ok(RefWriteCondition::Missing),
        Some(generated::RefExpectation::Match) => {
            Ok(RefWriteCondition::Match(to_hash(expected_id)?))
        }
        _ => Err(ConnectError::invalid_argument(
            "REF_EXPECTATION_UNSPECIFIED",
        )),
    }
}

struct TestService {
    inner: Arc<MemoryTransport>,
}

#[allow(refining_impl_trait)]
impl generated::TransportService for TestService {
    async fn list_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
        let msg = request.to_owned_message();
        let prefix = msg.prefix.unwrap_or_default();
        let refs = self.inner.list_refs(&prefix).map_err(to_connect_error)?;
        Ok(Response::new(generated::ListRefsResponse {
            refs: refs
                .into_iter()
                .map(|r| generated::RefEntry {
                    name: Some(r.name),
                    object_id: Some(r.hash.unwrap_or_default().to_vec()),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }))
    }

    async fn read_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::ReadRefRequest>,
    ) -> ServiceResult<generated::ReadRefResponse> {
        let msg = request.to_owned_message();
        let name = msg.name.unwrap_or_default();
        let current = self.inner.read_ref(&name).map_err(to_connect_error)?;
        Ok(Response::new(generated::ReadRefResponse {
            exists: Some(current.is_some()),
            object_id: current.map(|h| h.to_vec()),
            ..Default::default()
        }))
    }

    async fn update_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::UpdateRefRequest>,
    ) -> ServiceResult<generated::UpdateRefResponse> {
        let msg = request.to_owned_message();
        let name = msg.name.unwrap_or_default();
        let condition = wire_to_condition(msg.expectation, msg.expected_id)?;
        let new_id = to_hash(msg.new_id)?;
        self.inner
            .update_ref(&name, condition, &new_id)
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::UpdateRefResponse::default()))
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        let msg = request.to_owned_message();
        let head_ref = msg.head_ref.unwrap_or_default();
        let head_condition = wire_to_condition(msg.head_expectation, msg.head_expected_id)?;
        let head_new = to_hash(msg.head_new_id)?;
        let packmap_ref = msg.packmap_ref.unwrap_or_default();
        let packmap_condition =
            wire_to_condition(msg.packmap_expectation, msg.packmap_expected_id)?;
        let packmap_new = to_hash(msg.packmap_new_id)?;

        let outcome = self
            .inner
            .advance_refs(
                &head_ref,
                head_condition,
                &head_new,
                &packmap_ref,
                packmap_condition,
                &packmap_new,
            )
            .map_err(to_connect_error)?;
        let proto_outcome = match outcome {
            AdvanceOutcome::Committed => generated::AdvanceOutcome::Committed,
            AdvanceOutcome::HeadConflict => generated::AdvanceOutcome::HeadConflict,
            AdvanceOutcome::PackmapConflict => generated::AdvanceOutcome::PackmapConflict,
        };
        Ok(Response::new(generated::AdvanceRefsResponse {
            outcome: Some(proto_outcome.into()),
            ..Default::default()
        }))
    }

    async fn pack_exists(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
        let msg = request.to_owned_message();
        let key = PackKey::new(to_hash(msg.pack_id)?);
        let exists = self.inner.pack_exists(&key).map_err(to_connect_error)?;
        Ok(Response::new(generated::PackExistsResponse {
            exists: Some(exists),
            ..Default::default()
        }))
    }

    async fn upload_pack(
        &self,
        _ctx: RequestContext,
        mut requests: connectrpc::InboundStream<generated::UploadPackRequest>,
    ) -> ServiceResult<generated::UploadPackResponse> {
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("empty UploadPack stream"))??;
        let header = match first.to_owned_message().body {
            Some(UploadBody::Header(h)) => *h,
            _ => {
                return Err(ConnectError::invalid_argument(
                    "first message must be header",
                ));
            }
        };
        let pack_id = header.pack_id.unwrap_or_default();
        let total_bytes = header.total_bytes.unwrap_or(0);

        let mut buf = Vec::new();
        loop {
            let item = requests.next().await.ok_or_else(|| {
                ConnectError::invalid_argument("stream ended before a `last` chunk")
            })??;
            match item.to_owned_message().body {
                Some(UploadBody::Chunk(c)) => {
                    if c.pack_id.as_deref() != Some(pack_id.as_slice()) {
                        return Err(ConnectError::invalid_argument("chunk pack_id mismatch"));
                    }
                    let offset = c.offset.unwrap_or(0);
                    if offset != buf.len() as u64 {
                        return Err(ConnectError::invalid_argument("chunk offset out of order"));
                    }
                    buf.extend_from_slice(&c.data.unwrap_or_default());
                    if c.last.unwrap_or(false) {
                        break;
                    }
                }
                _ => return Err(ConnectError::invalid_argument("expected a chunk message")),
            }
        }
        if buf.len() as u64 != total_bytes {
            return Err(ConnectError::invalid_argument(
                "received byte count does not match header.total_bytes",
            ));
        }
        let key = PackKey::new(to_hash(Some(pack_id))?);
        self.inner
            .upload_pack(&buf, &key)
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::UploadPackResponse::default()))
    }

    async fn download_pack(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<generated::DownloadPackResponse>> {
        let msg = request.to_owned_message();
        let key = PackKey::new(to_hash(msg.pack_id)?);
        let bytes = self.inner.download_pack(&key).map_err(to_connect_error)?;

        #[allow(clippy::cast_possible_truncation)]
        let total_bytes = bytes.len() as u64;
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
                    pack_id: Some(key.as_bytes().to_vec()),
                    offset: Some(0),
                    data: Some(bytes),
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

/// Bind a real Connect server on an ephemeral loopback port, backed by
/// `backend`. Returns the port, a shutdown trigger, and the server
/// thread's join handle.
fn spawn_server(
    backend: Arc<MemoryTransport>,
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

            let service = Arc::new(TestService { inner: backend });
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

// ---------------------------------------------------------------------------
// Smoke tests: URL scheme dispatch
// ---------------------------------------------------------------------------

#[test]
fn open_accepts_mkit_http_url_and_returns_transport() {
    // Construction does NOT make a network call — nothing needs to be
    // listening on port 1 for this to succeed.
    let tx = remote_dispatch::open("mkit+http://127.0.0.1:1/proj")
        .expect("mkit+http:// must dispatch to ConnectTransport");
    drop(tx);
}

#[test]
fn open_accepts_mkit_https_url() {
    let tx = remote_dispatch::open("mkit+https://example.invalid/p")
        .expect("mkit+https:// must dispatch to ConnectTransport");
    drop(tx);
}

#[test]
fn open_rejects_malformed_mkit_http_url() {
    let Err(err) = remote_dispatch::open("mkit+http://") else {
        panic!("expected error for empty mkit+http URL");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("transport") || msg.contains("malformed"),
        "unexpected error for empty mkit+http URL: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Full push / pull roundtrip through the real Connect server
// ---------------------------------------------------------------------------

fn source_repo_with_one_commit() -> (tempfile::TempDir, String) {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    std::fs::write(td.path().join("hello.txt"), b"hello\n").unwrap();
    assert!(run_in(td.path(), &["add", "hello.txt"]).status.success());
    let out = run_in(td.path(), &["commit", "-m", "init"]);
    assert!(out.status.success(), "commit failed: {out:?}");
    let tip_hex = std::fs::read_to_string(td.path().join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_owned();
    (td, tip_hex)
}

#[test]
fn push_then_pull_roundtrip_through_real_connect_server() {
    let (src, tip_hex) = source_repo_with_one_commit();

    let backend = Arc::new(MemoryTransport::new());
    let (port, shutdown, handle) = spawn_server(backend);
    let url = format!("mkit+http://127.0.0.1:{port}/myproj");

    // -- push --------------------------------------------------------
    let tx = remote_dispatch::open(&url).expect("open mkit+http (push)");
    let n = remote_dispatch::push_all(src.path(), tx.as_ref()).expect("push must succeed");
    assert_eq!(n, 1, "exactly one branch (main) must be pushed");
    drop(tx);

    // -- pull into a fresh repo ---------------------------------------
    let dst = tempfile::tempdir().unwrap();
    assert!(run_in(dst.path(), &["init"]).status.success());
    let tx = remote_dispatch::open(&url).expect("open mkit+http (pull)");
    let n = remote_dispatch::pull_all(dst.path(), tx.as_ref(), "default", None).expect("pull");
    assert_eq!(n, 1, "one remote branch must be fetched");
    drop(tx);

    let local_tip = std::fs::read_to_string(dst.path().join(".mkit/refs/heads/main")).unwrap();
    assert_eq!(
        local_tip.trim(),
        tip_hex,
        "pulled branch must land on the remote tip"
    );
    assert_eq!(
        std::fs::read(dst.path().join("hello.txt")).unwrap(),
        b"hello\n",
        "pull must materialise the committed file"
    );

    let _ = shutdown.send(());
    handle.join().expect("server thread joins cleanly");
}
