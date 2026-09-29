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

use std::collections::{BTreeMap, HashMap};
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};

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
use generated::__buffa::oneof::upload_part_request::Msg as PartBody;

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
        _ => ConnectError::new(ErrorCode::Internal, "unexpected transport error"),
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

#[derive(Debug)]
struct CapturedCall {
    procedure: &'static str,
    repository: Option<String>,
    ref_hint: Option<String>,
    part_index: Option<u32>,
}

type CapturedCalls = Arc<Mutex<Vec<CapturedCall>>>;

#[derive(Default)]
struct PartGate {
    reached: std::sync::atomic::AtomicBool,
    released: Mutex<bool>,
    ready: Condvar,
}

struct TestService {
    inner: Arc<MemoryTransport>,
    calls: CapturedCalls,
    not_found: Vec<&'static str>,
    pending_advance: bool,
    admission_required: bool,
    ticketed: bool,
    part_buffers: Mutex<HashMap<Vec<u8>, BTreeMap<u32, Vec<u8>>>>,
    part_gate: Option<Arc<PartGate>>,
}

impl TestService {
    fn capture(&self, ctx: &RequestContext, procedure: &'static str) -> Result<(), ConnectError> {
        let header = |name| {
            ctx.headers()
                .get(name)
                .map(|value| value.to_str().unwrap().to_owned())
        };
        self.calls.lock().unwrap().push(CapturedCall {
            procedure,
            repository: header("x-repository"),
            ref_hint: header("x-mkit-ref"),
            part_index: None,
        });
        if self.admission_required
            && procedure == "AdvanceRefs"
            && ctx.headers().get("payment-authorization").is_none()
        {
            return Err(
                ConnectError::permission_denied("admission required").with_detail(
                    connectrpc::ErrorDetail::from_message(
                        "mkit.transport.v1.AdmissionChallenge",
                        &generated::AdmissionChallenge {
                            challenges: vec![generated::Challenge {
                                scheme: Some("test".into()),
                                value: Some("secret-challenge-value".into()),
                                ..Default::default()
                            }],
                            description: Some("pay to write".into()),
                            ..Default::default()
                        },
                    ),
                ),
            );
        }
        if self.not_found.contains(&procedure) {
            return Err(ConnectError::not_found("repository not found"));
        }
        Ok(())
    }
}

#[allow(refining_impl_trait)]
impl generated::TransportService for TestService {
    async fn get_receipt(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetReceiptRequest>,
    ) -> ServiceResult<generated::GetReceiptResponse> {
        Err(ConnectError::unimplemented("not implemented yet"))
    }

    // WP-1.2: compile-only stubs for the additive M1 trait methods.
    async fn get_server_info(
        &self,
        ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetServerInfoRequest>,
    ) -> ServiceResult<generated::GetServerInfoResponse> {
        self.capture(&ctx, "GetServerInfo")?;
        if self.ticketed {
            Ok(Response::new(generated::GetServerInfoResponse {
                protocol: Some("mkit.transport.v1".into()),
                spec_version: Some(2),
                part_size: Some(8 << 20),
                max_parts: Some(512),
                max_list_refs_page_size: Some(1000),
                atomic_advance: Some(true),
                begin_upload_threshold_bytes: Some(0),
                ..Default::default()
            }))
        } else {
            Err(connectrpc::ConnectError::unimplemented(
                "not implemented yet",
            ))
        }
    }

    async fn begin_upload(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::BeginUploadRequest>,
    ) -> ServiceResult<generated::BeginUploadResponse> {
        if !self.ticketed {
            return Err(connectrpc::ConnectError::unimplemented(
                "not implemented yet",
            ));
        }
        self.capture(&ctx, "BeginUpload")?;
        let pack_id = request.to_owned_message().pack_id.unwrap_or_default();
        if pack_id.len() != 32 {
            return Err(ConnectError::invalid_argument("pack id"));
        }
        Ok(Response::new(generated::BeginUploadResponse {
            result: Some(
                generated::__buffa::oneof::begin_upload_response::Result::Ticket(Box::new(
                    generated::UploadTicket {
                        id: Some(pack_id.clone()),
                        token: Some(pack_id),
                        part_size: Some(8 << 20),
                        expires_unix_ms: Some(i64::MAX),
                        ..Default::default()
                    },
                )),
            ),
            ..Default::default()
        }))
    }

    async fn upload_part(
        &self,
        ctx: RequestContext,
        mut requests: connectrpc::InboundStream<generated::UploadPartRequest>,
    ) -> ServiceResult<generated::UploadPartResponse> {
        if !self.ticketed {
            return Err(connectrpc::ConnectError::unimplemented(
                "not implemented yet",
            ));
        }
        self.capture(&ctx, "UploadPart")?;
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("missing header"))??;
        let Some(PartBody::Header(header)) = first.to_owned_message().msg else {
            return Err(ConnectError::invalid_argument("missing header"));
        };
        let index = header.index.unwrap_or(0);
        let token = header.ticket_token.unwrap_or_default();
        let mut bytes = Vec::new();
        while let Some(message) = requests.next().await {
            if let Some(PartBody::Chunk(chunk)) = message?.to_owned_message().msg {
                bytes.extend_from_slice(&chunk);
            }
        }
        self.calls.lock().unwrap().last_mut().unwrap().part_index = Some(index);
        self.part_buffers
            .lock()
            .unwrap()
            .entry(token)
            .or_default()
            .insert(index, bytes);
        if index == 1
            && let Some(gate) = &self.part_gate
        {
            gate.reached
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let mut released = gate.released.lock().unwrap();
            while !*released {
                released = gate.ready.wait(released).unwrap();
            }
        }
        Ok(Response::new(generated::UploadPartResponse {
            receipt: Some(vec![index as u8, 1]),
            ..Default::default()
        }))
    }

    async fn complete_upload(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::CompleteUploadRequest>,
    ) -> ServiceResult<generated::CompleteUploadResponse> {
        if !self.ticketed {
            return Err(connectrpc::ConnectError::unimplemented(
                "not implemented yet",
            ));
        }
        self.capture(&ctx, "CompleteUpload")?;
        let message = request.to_owned_message();
        let token = message.ticket_token.unwrap_or_default();
        let mut buffers = self.part_buffers.lock().unwrap();
        let parts = buffers
            .remove(&token)
            .ok_or_else(|| ConnectError::invalid_argument("missing parts"))?;
        if message.receipts.len() != parts.len() {
            return Err(ConnectError::invalid_argument("missing receipts"));
        }
        let bytes: Vec<u8> = parts.into_values().flatten().collect();
        let key = PackKey::new(mkit_core::hash::hash(&bytes));
        self.inner
            .upload_pack(&bytes, &key)
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::CompleteUploadResponse::default()))
    }

    async fn list_refs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
        self.capture(&ctx, "ListRefs")?;
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
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::ReadRefRequest>,
    ) -> ServiceResult<generated::ReadRefResponse> {
        self.capture(&ctx, "ReadRef")?;
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
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::UpdateRefRequest>,
    ) -> ServiceResult<generated::UpdateRefResponse> {
        self.capture(&ctx, "UpdateRef")?;
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
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        self.capture(&ctx, "AdvanceRefs")?;
        if self.pending_advance {
            return Err(
                ConnectError::unavailable("verification pending").with_detail(
                    connectrpc::ErrorDetail::from_message(
                        "mkit.transport.v1.PendingVerification",
                        &generated::PendingVerification::default().with_retry_after_ms(5_000),
                    ),
                ),
            );
        }
        let msg = request.to_owned_message();
        if self.ticketed && msg.ticket_ids.is_empty() {
            return Err(ConnectError::failed_precondition("tickets missing"));
        }
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
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
        self.capture(&ctx, "PackExists")?;
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
        ctx: RequestContext,
        mut requests: connectrpc::InboundStream<generated::UploadPackRequest>,
    ) -> ServiceResult<generated::UploadPackResponse> {
        self.capture(&ctx, "UploadPack")?;
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
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<generated::DownloadPackResponse>> {
        self.capture(&ctx, "DownloadPack")?;
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

    async fn get_grant_epoch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetGrantEpochRequest>,
    ) -> ServiceResult<generated::GetGrantEpochResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn set_grant_epoch(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetGrantEpochRequest>,
    ) -> ServiceResult<generated::SetGrantEpochResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn set_repo_visibility(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetRepoVisibilityRequest>,
    ) -> ServiceResult<generated::SetRepoVisibilityResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn issue_object_url(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::IssueObjectUrlRequest>,
    ) -> ServiceResult<generated::IssueObjectUrlResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
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
    CapturedCalls,
) {
    spawn_server_with_errors(backend, Vec::new())
}

fn spawn_server_with_errors(
    backend: Arc<MemoryTransport>,
    not_found: Vec<&'static str>,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
    CapturedCalls,
) {
    spawn_server_with_behavior(backend, not_found, false)
}

fn spawn_server_with_behavior(
    backend: Arc<MemoryTransport>,
    not_found: Vec<&'static str>,
    pending_advance: bool,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
    CapturedCalls,
) {
    spawn_server_admission(backend, not_found, pending_advance, false)
}

fn spawn_server_admission(
    backend: Arc<MemoryTransport>,
    not_found: Vec<&'static str>,
    pending_advance: bool,
    admission_required: bool,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
    CapturedCalls,
) {
    spawn_server_options(
        backend,
        not_found,
        pending_advance,
        admission_required,
        false,
        None,
    )
}

fn spawn_server_options(
    backend: Arc<MemoryTransport>,
    not_found: Vec<&'static str>,
    pending_advance: bool,
    admission_required: bool,
    ticketed: bool,
    part_gate: Option<Arc<PartGate>>,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
    CapturedCalls,
) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server_calls = Arc::clone(&calls);
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

            let service = Arc::new(TestService {
                inner: backend,
                calls: server_calls,
                not_found,
                pending_advance,
                admission_required,
                ticketed,
                part_buffers: Mutex::new(HashMap::new()),
                part_gate,
            });
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
    (port, shutdown_tx, handle, calls)
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
fn cli_push_uses_begin_upload_and_ticketed_advance() {
    let (src, tip_hex) = source_repo_with_one_commit();
    let backend = Arc::new(MemoryTransport::new());
    let (port, shutdown, handle, calls) =
        spawn_server_options(Arc::clone(&backend), Vec::new(), false, false, true, None);
    let url = format!("mkit+http://127.0.0.1:{port}/myproj");
    let config_path = src.path().join(".mkit/config");
    let mut config = std::fs::read_to_string(&config_path).unwrap_or_default();
    config.push_str(&format!(
        "\nremote.origin.url = {url}\nremote.origin.type = http\n"
    ));
    std::fs::write(config_path, config).unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(xdg.path().join("mkit")).unwrap();
    std::fs::write(
        xdg.path().join("mkit/config"),
        format!("transport_auth = envelope\ntrusted_remote_endpoint = {url}\n"),
    )
    .unwrap();
    let output = Command::new(mkit_bin())
        .args(["push", "origin"])
        .current_dir(src.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let calls = calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .filter(|call| call.procedure == "BeginUpload")
            .count()
            >= 2
    );
    assert!(calls.iter().any(|call| call.procedure == "AdvanceRefs"));
    assert_eq!(
        backend
            .read_ref("refs/heads/main")
            .unwrap()
            .map(|h| mkit_core::hash::to_hex(&h)),
        Some(tip_hex)
    );
    drop(calls);
    let _ = shutdown.send(());
    handle.join().unwrap();
}

#[test]
fn push_then_pull_roundtrip_through_real_connect_server() {
    let (src, tip_hex) = source_repo_with_one_commit();

    let backend = Arc::new(MemoryTransport::new());
    let (port, shutdown, handle, calls) = spawn_server(backend);
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

    {
        let calls = calls.lock().unwrap();
        assert!(!calls.is_empty());
        assert!(
            calls
                .iter()
                .all(|call| call.repository.as_deref() == Some("myproj")),
            "{calls:?}"
        );
        let downloads: Vec<_> = calls
            .iter()
            .filter(|call| call.procedure == "DownloadPack")
            .collect();
        assert!(
            downloads.len() >= 2,
            "packlist and pack downloads must both be observed: {calls:?}"
        );
        assert!(
            downloads
                .iter()
                .all(|call| call.ref_hint.as_deref() == Some("refs/heads/main")),
            "{downloads:?}"
        );
        assert!(
            calls
                .iter()
                .filter(|call| call.procedure != "DownloadPack")
                .all(|call| call.ref_hint.is_none())
        );
    }
    let _ = shutdown.send(());
    handle.join().expect("server thread joins cleanly");
}

#[cfg(unix)]
#[test]
fn cli_pending_interrupt_uses_configured_observer_and_exits_75() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    // Kills the push if the test panics before it exits, so no child outlives it.
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    let (src, _) = source_repo_with_one_commit();
    let (port, shutdown, handle, calls) =
        spawn_server_with_behavior(Arc::new(MemoryTransport::new()), Vec::new(), true);
    let url = format!("mkit+http://127.0.0.1:{port}/myproj");
    // `remote add` intentionally restricts saved URLs to public schemes;
    // this loopback-only fixture writes the same repo-scoped config shape.
    let config_path = src.path().join(".mkit/config");
    let mut config = std::fs::read_to_string(&config_path).unwrap_or_default();
    config.push_str("\nremote.origin.url = ");
    config.push_str(&url);
    config.push_str("\nremote.origin.type = http\n");
    std::fs::write(config_path, config).unwrap();

    let xdg = tempfile::tempdir().unwrap();
    let child = Command::new(mkit_bin())
        .args(["push", "origin"])
        .current_dir(src.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("MKIT_PROGRESS", "always")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = KillOnDrop(child);

    let started = Instant::now();
    while !calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call.procedure == "AdvanceRefs")
    {
        // Generous budgets: a debug `mkit push` on a loaded test runner.
        assert!(
            started.elapsed() <= Duration::from_secs(30),
            "push did not reach AdvanceRefs"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    let signalled = Command::new("kill")
        .args(["-INT", &child.0.id().to_string()])
        .status()
        .unwrap();
    assert!(signalled.success(), "could not signal push process");
    let interrupted_at = Instant::now();
    while child.0.try_wait().unwrap().is_none() {
        assert!(
            interrupted_at.elapsed() <= Duration::from_secs(10),
            "push did not stop within the polling slice"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.0.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    let status = child.0.wait().unwrap();
    assert_eq!(status.code(), Some(75), "{stderr}");
    assert!(
        stderr.contains("Waiting for server verification"),
        "{stderr}"
    );
    assert!(
        stderr.contains("push: interrupted; re-run push to retry"),
        "{stderr}"
    );
    assert!(!stderr.contains("BeginUpload"), "{stderr}");

    let _ = shutdown.send(());
    handle.join().unwrap();
}

#[test]
fn open_rejects_invalid_repository_path_before_connecting() {
    for path in [
        "Uppercase",
        "namespace//repo",
        "some/project/path",
        "repo%20name",
    ] {
        let url = format!("mkit+http://127.0.0.1:1/{path}");
        let Err(err) = remote_dispatch::open(&url) else {
            panic!("invalid repository path accepted: {path}");
        };
        assert!(
            matches!(err, remote_dispatch::DispatchError::MalformedUrl(_)),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(message.contains(path), "{message}");
        assert!(message.contains(&url), "{message}");
    }
}

#[test]
fn list_refs_not_found_names_the_repository_and_origin() {
    let repo = tempfile::tempdir().unwrap();
    assert!(run_in(repo.path(), &["init"]).status.success());
    let (port, shutdown, handle, _) =
        spawn_server_with_errors(Arc::new(MemoryTransport::new()), vec!["ListRefs"]);
    let origin = format!("http://127.0.0.1:{port}");
    let tx = remote_dispatch::open(&format!("mkit+{origin}/myproj")).unwrap();
    let error = remote_dispatch::fetch_all(repo.path(), tx.as_ref(), "default").unwrap_err();
    let remote_dispatch::DispatchError::RepositoryNotFound {
        identity,
        origin: observed,
    } = &error
    else {
        panic!("expected repository-not-found error, got {error:?}");
    };
    assert_eq!(identity, "myproj");
    assert_eq!(observed, &origin);
    assert!(error.to_string().contains("empty path selects `default`"));
    drop(tx);
    let _ = shutdown.send(());
    handle.join().unwrap();
}

#[test]
fn read_ref_not_found_is_an_absent_ref() {
    let (port, shutdown, handle, calls) =
        spawn_server_with_errors(Arc::new(MemoryTransport::new()), vec!["ReadRef"]);
    let tx = remote_dispatch::open(&format!("mkit+http://127.0.0.1:{port}/myproj")).unwrap();
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), None);
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "ReadRef must not trigger discovery"
    );
    drop(tx);
    let _ = shutdown.send(());
    handle.join().unwrap();
}

#[test]
fn push_not_found_names_the_repository_for_each_write() {
    let (src, _) = source_repo_with_one_commit();
    for procedure in ["UploadPack", "AdvanceRefs", "UpdateRef"] {
        let (port, shutdown, handle, calls) =
            spawn_server_with_errors(Arc::new(MemoryTransport::new()), vec![procedure]);
        let origin = format!("http://127.0.0.1:{port}");
        let tx = remote_dispatch::open(&format!("mkit+{origin}/myproj")).unwrap();
        if procedure == "UpdateRef" {
            // The first push publishes its refs through AdvanceRefs. An unchanged
            // second push reaches the head-only UpdateRef path.
            remote_dispatch::push_all(src.path(), tx.as_ref()).unwrap();
        }
        let error = remote_dispatch::push_all(src.path(), tx.as_ref()).unwrap_err();
        let remote_dispatch::DispatchError::RepositoryNotFound {
            identity,
            origin: observed,
        } = &error
        else {
            panic!("{procedure}: expected repository-not-found error, got {error:?}");
        };
        assert_eq!(identity, "myproj", "{procedure}");
        assert_eq!(observed, &origin, "{procedure}");
        assert!(
            calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call.procedure == procedure)
        );
        drop(tx);
        let _ = shutdown.send(());
        handle.join().unwrap();
    }
}

#[cfg(unix)]
#[test]
#[allow(clippy::too_many_lines)]
fn cli_admission_helper_trust_filter_json_and_exit_codes() {
    use std::fmt::Write as _;
    use std::os::unix::fs::PermissionsExt;
    for case in [
        "happy",
        "reserved",
        "no-helper",
        "untrusted",
        "missing-helper",
    ] {
        let (src, _) = source_repo_with_one_commit();
        let (port, shutdown, handle, calls) =
            spawn_server_admission(Arc::new(MemoryTransport::new()), Vec::new(), false, true);
        let url = format!("mkit+http://127.0.0.1:{port}/myproj");
        let config_path = src.path().join(".mkit/config");
        let mut config = std::fs::read_to_string(&config_path).unwrap_or_default();
        write!(
            config,
            "\nremote.origin.url = {url}\nremote.origin.type = http\n"
        )
        .unwrap();
        std::fs::write(config_path, config).unwrap();
        let xdg = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(xdg.path().join("mkit")).unwrap();
        let helper = xdg.path().join("helper.sh");
        let marker = xdg.path().join("ran");
        let header = if case == "reserved" {
            "X-Mkit-Ref"
        } else {
            "Payment-Authorization"
        };
        if case != "missing-helper" {
            std::fs::write(&helper, format!("#!/bin/sh\ncat >/dev/null\ntouch '{}'\nprintf '%s' '{{\"{header}\":\"secret-helper-value\"}}'\n", marker.display())).unwrap();
            let mut perms = std::fs::metadata(&helper).unwrap().permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&helper, perms).unwrap();
        }
        let trusted = if case == "untrusted" {
            "mkit+http://127.0.0.1:1/other"
        } else {
            &url
        };
        let user = if case == "no-helper" {
            format!("trusted_remote_endpoint = {trusted}\n")
        } else {
            format!(
                "trusted_remote_endpoint = {trusted}\nadmission_helper = {}\n",
                helper.display()
            )
        };
        std::fs::write(xdg.path().join("mkit/config"), user).unwrap();
        let output = Command::new(mkit_bin())
            .args(["push", "origin", "--format", "json"])
            .current_dir(src.path())
            .env("XDG_CONFIG_HOME", xdg.path())
            .output()
            .unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            !stderr.contains("secret-helper-value") && !stdout.contains("secret-helper-value"),
            "{case}"
        );
        assert!(
            !stderr.contains("secret-challenge-value")
                && !stdout.contains("secret-challenge-value"),
            "{case}"
        );
        match case {
            "happy" => {
                assert!(output.status.success(), "{stderr}");
                assert!(marker.exists());
                assert_eq!(
                    calls
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|c| c.procedure == "AdvanceRefs")
                        .count(),
                    2
                );
            }
            "reserved" => {
                assert_eq!(output.status.code(), Some(78), "{stderr}");
                assert!(stderr.contains("X-Mkit-Ref"));
                assert!(marker.exists());
            }
            "no-helper" => {
                assert_eq!(output.status.code(), Some(77), "{stderr}");
                assert!(stdout.contains("\"admission_required\":true"));
                assert!(stderr.contains("hint:"));
            }
            "untrusted" => {
                assert_eq!(output.status.code(), Some(77), "{stderr}");
                assert!(!marker.exists());
                assert!(stderr.contains("hint:"));
            }
            "missing-helper" => {
                assert_eq!(output.status.code(), Some(78), "{stderr}");
                assert!(!marker.exists());
            }
            _ => unreachable!(),
        }
        let _ = shutdown.send(());
        handle.join().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn cli_part_upload_interrupts_with_exit_75_and_resumes_from_file_receipts() {
    use std::process::Stdio;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    let (src, _) = source_repo_with_one_commit();
    let mut big = vec![0_u8; (8 << 20) * 2 + (1 << 20)];
    let mut random = 0x8c17_a9e5_u32;
    for byte in &mut big {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        *byte = random as u8;
    }
    std::fs::write(src.path().join("large.bin"), &big).unwrap();
    assert!(run_in(src.path(), &["add", "large.bin"]).status.success());
    let committed = run_in(src.path(), &["commit", "-m", "large"]);
    assert!(committed.status.success(), "{committed:?}");
    let gate = Arc::new(PartGate::default());
    let (port, shutdown, handle, calls) = spawn_server_options(
        Arc::new(MemoryTransport::new()),
        Vec::new(),
        false,
        false,
        true,
        Some(Arc::clone(&gate)),
    );
    let url = format!("mkit+http://127.0.0.1:{port}/myproj");
    let config_path = src.path().join(".mkit/config");
    let mut config = std::fs::read_to_string(&config_path).unwrap_or_default();
    config.push_str(&format!(
        "\nremote.origin.url = {url}\nremote.origin.type = http\n"
    ));
    std::fs::write(config_path, config).unwrap();
    let xdg = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(xdg.path().join("mkit")).unwrap();
    std::fs::write(
        xdg.path().join("mkit/config"),
        format!("transport_auth = envelope\ntrusted_remote_endpoint = {url}\n"),
    )
    .unwrap();
    let child = Command::new(mkit_bin())
        .args(["push", "origin"])
        .current_dir(src.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .env("MKIT_PROGRESS", "always")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = KillOnDrop(child);
    let started = Instant::now();
    while !gate.reached.load(Ordering::SeqCst) {
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "push never reached second part"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        Command::new("kill")
            .args(["-INT", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    *gate.released.lock().unwrap() = true;
    gate.ready.notify_all();
    let stopped = Instant::now();
    while child.0.try_wait().unwrap().is_none() {
        assert!(
            stopped.elapsed() < Duration::from_secs(30),
            "interrupted push did not stop"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.0.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    let status = child.0.wait().unwrap();
    assert_eq!(status.code(), Some(75), "{stderr}");
    assert!(
        stderr.contains("upload interrupted; 2 of 3 parts saved"),
        "{stderr}"
    );
    assert!(
        stderr.contains("run `mkit push` again to resume"),
        "{stderr}"
    );
    let first_parts: Vec<_> = calls
        .lock()
        .unwrap()
        .iter()
        .filter_map(|call| call.part_index)
        .collect();
    assert_eq!(first_parts, [0, 1]);

    let resumed = Command::new(mkit_bin())
        .args(["push", "origin"])
        .current_dir(src.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    let all_parts: Vec<_> = calls
        .lock()
        .unwrap()
        .iter()
        .filter_map(|call| call.part_index)
        .collect();
    assert_eq!(all_parts, [0, 1, 2]);
    let _ = shutdown.send(());
    handle.join().unwrap();
}
