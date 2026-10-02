//! Deterministic retry regression: an in-process `TransportService` that
//! fails the first N calls to a given RPC with a retryable Connect error
//! class (`unavailable`), then succeeds — mirroring
//! `mkit-transport-http`'s `retry_503_then_200_succeeds` /
//! `retry_uses_injected_backoff_and_sleeper` pattern (mkit#790).
//!
//! Before mkit#790, `ConnectTransport` made every RPC as a single attempt
//! with no retry/backoff, unlike `mkit-transport-http`/`-ssh`/`-enc`. This
//! file asserts every `Transport` method now goes through the shared
//! `mkit_core::protocol::retrying`/`BackoffIterator` ladder: a transient
//! `unavailable` is absorbed and the call still returns `Ok`, a
//! non-retryable error is NOT retried (surfaces on the first attempt), and
//! the injected sleep hook is actually invoked between attempts with the
//! expected delay.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use connectrpc::server::Server;
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, Router, ServiceRequest, ServiceResult,
    ServiceStream,
};
use ed25519_dalek::{Signer as _, SigningKey};
use futures::StreamExt;
use mkit_core::hash::hash as blake3_hash;
use mkit_core::protocol::{
    AdvanceOutcome, BackoffIterator, PackKey, RefWriteCondition, Transport, TransportError,
};
use mkit_transport_connect::admission::{
    AdmissionContext, AdmissionPolicy, AdmissionResponder, AdmissionResponderError,
};
use mkit_transport_connect::{ConnectTransport, EnvelopeSigner, PendingEvent, generated};
use mkit_transport_memory::MemoryTransport;

use generated::__buffa::oneof::upload_pack_request::Body as UploadBody;

// ---------------------------------------------------------------------------
// Server-side TransportError -> ConnectError (identical to roundtrip.rs).
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
            let hash = to_hash(expected_id)?;
            Ok(RefWriteCondition::Match(hash))
        }
        _ => Err(ConnectError::invalid_argument(
            "REF_EXPECTATION_UNSPECIFIED",
        )),
    }
}

// ---------------------------------------------------------------------------
// FlakyService — a `TransportService` backed by an in-memory `Transport`
// that fails the first `fail_times` calls of ONE targeted RPC (identified
// by `target`) with `unavailable`, then delegates normally. Every other RPC
// always delegates normally. A shared `AtomicUsize` counts total calls made
// to the targeted RPC, so tests can assert exactly how many attempts the
// client made.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rpc {
    ListRefs,
    ReadRef,
    UpdateRef,
    AdvanceRefs,
    PackExists,
    UploadPack,
    DownloadPack,
}

/// Which Connect error class `FlakyService` raises while it's still
/// "failing". `Unavailable` maps to `TransportError::ServerError{503}` —
/// retryable per `is_retryable`. `NotFound` maps to
/// `TransportError::PackNotFound` — NOT retryable, so a test using it
/// asserts the client gives up after exactly one attempt regardless of
/// `fail_times`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailKind {
    Unavailable,
    NotFound,
    Pending(u32),
    PendingMalformed,
    Mixed,
    PendingThenUnauthenticated,
    PendingThenTwoUnauthenticated,
    PendingUnauthenticatedTwice,
    Admission,
    Raw402,
    AdmissionThenUnavailable,
}

impl FailKind {
    fn to_connect_error(self, n: usize, fail_times: usize) -> ConnectError {
        match self {
            FailKind::Unavailable => {
                ConnectError::unavailable(format!("flaky failure #{} of {}", n + 1, fail_times))
            }
            FailKind::NotFound => ConnectError::not_found("flaky not-found failure"),
            FailKind::Pending(delay) => ConnectError::unavailable("verification pending")
                .with_detail(connectrpc::ErrorDetail::from_message(
                    "mkit.transport.v1.PendingVerification",
                    &generated::PendingVerification::default().with_retry_after_ms(delay),
                )),
            FailKind::PendingMalformed => ConnectError::unavailable("verification pending")
                .with_detail(connectrpc::ErrorDetail {
                    type_url: "mkit.transport.v1.PendingVerification".to_owned(),
                    value: Some("%%%".to_owned()),
                    debug: None,
                }),
            FailKind::Mixed if n == 1 => ConnectError::new(ErrorCode::Aborted, "in flight"),
            FailKind::Mixed => FailKind::Pending(1_000).to_connect_error(n, fail_times),
            FailKind::PendingThenUnauthenticated if n == 1 => {
                ConnectError::unauthenticated("clock ahead")
            }
            FailKind::PendingThenUnauthenticated => {
                FailKind::Pending(1_000).to_connect_error(n, fail_times)
            }
            FailKind::PendingThenTwoUnauthenticated if n > 0 => {
                ConnectError::unauthenticated("clock ahead")
            }
            FailKind::PendingThenTwoUnauthenticated => {
                FailKind::Pending(1_000).to_connect_error(n, fail_times)
            }
            FailKind::PendingUnauthenticatedTwice if n == 1 || n == 3 => {
                ConnectError::unauthenticated("clock ahead")
            }
            FailKind::PendingUnauthenticatedTwice => {
                FailKind::Pending(1_000).to_connect_error(n, fail_times)
            }
            FailKind::Admission => ConnectError::permission_denied("admission required")
                .with_detail(connectrpc::ErrorDetail::from_message(
                    "mkit.transport.v1.AdmissionChallenge",
                    &generated::AdmissionChallenge {
                        challenges: vec![generated::Challenge {
                            scheme: Some("test".into()),
                            value: Some("opaque-secret".into()),
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                )),
            FailKind::Raw402 => ConnectError::unknown("raw body opaque-secret")
                .with_http_status(http::StatusCode::PAYMENT_REQUIRED),
            FailKind::AdmissionThenUnavailable if n == 0 => {
                FailKind::Admission.to_connect_error(n, fail_times)
            }
            FailKind::AdmissionThenUnavailable => ConnectError::unavailable("retry this response"),
        }
    }
}

struct FlakyService {
    inner: Arc<MemoryTransport>,
    target: Rpc,
    fail_times: usize,
    fail_kind: FailKind,
    calls: Arc<AtomicUsize>,
    read_nonces: Option<Arc<Mutex<Vec<String>>>>,
    advance_headers: Option<Arc<Mutex<Vec<http::HeaderMap>>>>,
}

impl FlakyService {
    fn capture_read_auth(&self, ctx: &RequestContext, method: &str) -> Result<(), ConnectError> {
        let Some(nonces) = &self.read_nonces else {
            return Ok(());
        };
        let get = |name| {
            ctx.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        };
        let headers = mkit_core::write_auth::Headers {
            version: Some(get("x-envelope-version")),
            audience: Some(get("x-audience")),
            repository: Some(get("x-repository")),
            public_key: Some(get("x-public-key")),
            signature: Some(get("x-signature")),
            digest: Some(get("x-digest")),
            commitment: Some(get("x-content-commitment")),
            created_at: Some(get("x-created-at")),
            expires_at: Some(get("x-expires-at")),
            idempotency_key: Some(get("idempotency-key")),
        };
        let audience = headers.audience.as_deref().unwrap();
        let commitment = headers.commitment.as_deref().unwrap();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        mkit_core::write_auth::verify_headers(
            mkit_core::write_auth::Context {
                audience,
                repository: "default",
            },
            &format!("/mkit.transport.v1.TransportService/{method}"),
            Some(commitment),
            now,
            &headers,
        )
        .map_err(|e| ConnectError::unauthenticated(e.to_string()))?;
        nonces
            .lock()
            .unwrap()
            .push(headers.idempotency_key.unwrap());
        Ok(())
    }
    /// Returns `Some(err)` if `rpc` is the targeted RPC and it should still
    /// fail on this call (bumping `calls` regardless of the RPC). Returns
    /// `None` when the call should proceed to the real backend.
    fn maybe_fail(&self, rpc: Rpc) -> Option<ConnectError> {
        if rpc != self.target {
            return None;
        }
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.fail_times {
            Some(self.fail_kind.to_connect_error(n, self.fail_times))
        } else {
            None
        }
    }
}

#[allow(refining_impl_trait)]
impl generated::TransportService for FlakyService {
    async fn list_repos(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::ListReposRequest>,
    ) -> ServiceResult<generated::ListReposResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "unused test method",
        ))
    }

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
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetServerInfoRequest>,
    ) -> ServiceResult<generated::GetServerInfoResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn begin_upload(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::BeginUploadRequest>,
    ) -> ServiceResult<generated::BeginUploadResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn upload_part(
        &self,
        _ctx: RequestContext,
        _requests: connectrpc::InboundStream<generated::UploadPartRequest>,
    ) -> ServiceResult<generated::UploadPartResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn complete_upload(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::CompleteUploadRequest>,
    ) -> ServiceResult<generated::CompleteUploadResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }

    async fn list_refs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
        self.capture_read_auth(&ctx, "ListRefs")?;
        if let Some(e) = self.maybe_fail(Rpc::ListRefs) {
            return Err(e);
        }
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
        self.capture_read_auth(&ctx, "ReadRef")?;
        if let Some(e) = self.maybe_fail(Rpc::ReadRef) {
            return Err(e);
        }
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
        if let Some(headers) = &self.advance_headers {
            let mut captured = ctx.headers().clone();
            captured.insert(
                "x-test-body",
                hex::encode(buffa::Message::encode_to_vec(&request.to_owned_message()))
                    .parse()
                    .unwrap(),
            );
            headers.lock().unwrap().push(captured);
        }
        if let Some(e) = self.maybe_fail(Rpc::UpdateRef) {
            return Err(e);
        }
        let msg = request.to_owned_message();
        let name = msg.name.unwrap_or_default();
        let condition = wire_to_condition(msg.expectation, msg.expected_id)?;
        let new_id = to_hash(msg.new_id)?;
        self.inner
            .update_ref(&name, condition, &new_id)
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::UpdateRefResponse::default())
            .with_header("payment-receipt", "receipt-secret")
            .with_header("payment-receipt", "v".repeat(8_193))
            .with_header("payment-response", "reply-secret"))
    }

    async fn advance_refs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        if let Some(headers) = &self.advance_headers {
            let mut captured = ctx.headers().clone();
            captured.insert(
                "x-test-body",
                hex::encode(buffa::Message::encode_to_vec(&request.to_owned_message()))
                    .parse()
                    .unwrap(),
            );
            headers.lock().unwrap().push(captured);
        }
        if let Some(e) = self.maybe_fail(Rpc::AdvanceRefs) {
            return Err(e);
        }
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
        ctx: RequestContext,
        request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
        self.capture_read_auth(&ctx, "PackExists")?;
        if let Some(e) = self.maybe_fail(Rpc::PackExists) {
            return Err(e);
        }
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
        // Drain the client's stream before possibly failing, matching a
        // real server (which must consume the request body either way) and
        // so the client-side retry sees a normal RPC-level error rather
        // than a mid-stream disconnect.
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

        if let Some(e) = self.maybe_fail(Rpc::UploadPack) {
            return Err(e);
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
        self.capture_read_auth(&ctx, "DownloadPack")?;
        if let Some(e) = self.maybe_fail(Rpc::DownloadPack) {
            return Err(e);
        }
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

    async fn get_authority_generation(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::GetAuthorityGenerationRequest>,
    ) -> ServiceResult<generated::GetAuthorityGenerationResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
    }
    async fn set_authority_generation(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, generated::SetAuthorityGenerationRequest>,
    ) -> ServiceResult<generated::SetAuthorityGenerationResponse> {
        Err(connectrpc::ConnectError::unimplemented(
            "not implemented yet",
        ))
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

// ---------------------------------------------------------------------------
// Server bootstrap
// ---------------------------------------------------------------------------

/// Bind a real Connect server on an ephemeral loopback port, backed by a
/// fresh in-memory `MemoryTransport`, whose `target` RPC fails the first
/// `fail_times` calls with `unavailable`. Returns the port, a shutdown
/// trigger, the server thread's join handle, and the shared call counter.
fn spawn_flaky_server(
    target: Rpc,
    fail_times: usize,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    spawn_flaky_server_with_kind(target, fail_times, FailKind::Unavailable)
}

/// Like [`spawn_flaky_server`], with an explicit [`FailKind`] — used by the
/// non-retryable-error test to fail with `not_found` instead of
/// `unavailable`.
fn spawn_flaky_server_with_kind(
    target: Rpc,
    fail_times: usize,
    fail_kind: FailKind,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    spawn_flaky_server_internal(target, fail_times, fail_kind, None, None)
}

fn spawn_flaky_server_with_capture(
    target: Rpc,
    fail_times: usize,
    fail_kind: FailKind,
    read_nonces: Option<Arc<Mutex<Vec<String>>>>,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    spawn_flaky_server_internal(target, fail_times, fail_kind, read_nonces, None)
}

fn spawn_flaky_server_internal(
    target: Rpc,
    fail_times: usize,
    fail_kind: FailKind,
    read_nonces: Option<Arc<Mutex<Vec<String>>>>,
    advance_headers: Option<Arc<Mutex<Vec<http::HeaderMap>>>>,
) -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_server = Arc::clone(&calls);

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

            let service = Arc::new(FlakyService {
                inner: Arc::new(MemoryTransport::new()),
                target,
                fail_times,
                fail_kind,
                calls: calls_for_server,
                read_nonces,
                advance_headers,
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

fn connect_to(port: u16) -> ConnectTransport {
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("valid loopback URI");
    // `connect_for_test` defaults to a fast, no-sleep ladder with 5 retries
    // on top of the initial attempt (6 total calls at most — see
    // `ConnectTransport::connect_for_test_with_signer`'s doc comment) —
    // plenty of headroom for these tests' 1-2 induced failures.
    ConnectTransport::connect_for_test(uri)
}

struct StaticResponder {
    calls: Arc<AtomicUsize>,
    fail: bool,
}
impl AdmissionResponder for StaticResponder {
    fn respond(
        &self,
        ctx: &AdmissionContext<'_>,
    ) -> Result<Vec<(String, String)>, AdmissionResponderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(matches!(
            ctx.procedure.rsplit('/').next(),
            Some("UpdateRef" | "AdvanceRefs")
        ));
        if self.fail {
            return Err(AdmissionResponderError::Failed("responder failed".into()));
        }
        Ok(vec![(
            "Payment-Authorization".into(),
            "Payment secret".into(),
        )])
    }
}

#[test]
fn admission_retries_once_and_keeps_headers_and_identity() {
    for target in [Rpc::UpdateRef, Rpc::AdvanceRefs] {
        let captures = Arc::new(Mutex::new(Vec::new()));
        let (port, stop, handle, calls) = spawn_flaky_server_internal(
            target,
            1,
            FailKind::Admission,
            None,
            Some(captures.clone()),
        );
        let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
        let responder_calls = Arc::new(AtomicUsize::new(0));
        let client = ConnectTransport::connect_for_test_with_signer(
            uri,
            Some(Arc::new(TestSigner(SigningKey::from_bytes(&[7; 32])))),
        )
        .with_admission(AdmissionPolicy::new(Arc::new(StaticResponder {
            calls: responder_calls.clone(),
            fail: false,
        })));
        let h = blake3_hash(b"head");
        let p = blake3_hash(b"packmap");
        match target {
            Rpc::UpdateRef => client
                .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
                .unwrap(),
            Rpc::AdvanceRefs => {
                client
                    .advance_refs(
                        "refs/heads/main",
                        RefWriteCondition::Missing,
                        &h,
                        "refs/packmaps/main",
                        RefWriteCondition::Missing,
                        &p,
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(responder_calls.load(Ordering::SeqCst), 1);
        let headers = captures.lock().unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].get("payment-authorization"), None);
        assert_eq!(
            headers[1].get("payment-authorization").unwrap(),
            "Payment secret"
        );
        assert_eq!(
            headers[0].get("idempotency-key"),
            headers[1].get("idempotency-key")
        );
        assert_eq!(headers[0].get("x-test-body"), headers[1].get("x-test-body"));
        shutdown(stop, handle);
    }
}

#[test]
fn admission_without_policy_or_on_second_challenge_is_terminal() {
    let h = blake3_hash(b"head");
    let (port, stop, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::UpdateRef, 3, FailKind::Raw402);
    let error = connect_to(port)
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
        .unwrap_err();
    assert!(matches!(error, TransportError::AdmissionRequired(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    shutdown(stop, handle);

    let (port, stop, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::UpdateRef, 3, FailKind::Admission);
    let responder_calls = Arc::new(AtomicUsize::new(0));
    let client = connect_to(port).with_admission(AdmissionPolicy::new(Arc::new(StaticResponder {
        calls: responder_calls.clone(),
        fail: false,
    })));
    let error = client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
        .unwrap_err();
    assert!(error.to_string().contains("remote challenged again"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(responder_calls.load(Ordering::SeqCst), 1);
    shutdown(stop, handle);
}

#[test]
fn raw_http_402_stops_after_one_attempt() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut bytes = [0; 4096];
        let _ = stream.read(&mut bytes).unwrap();
        stream.write_all(b"HTTP/1.1 402 Payment Required\r\nContent-Length: 0\r\nWWW-Authenticate: Payment opaque\r\nConnection: close\r\n\r\n").unwrap();
    });
    let hash = blake3_hash(b"head");
    let error = connect_to(port)
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &hash)
        .unwrap_err();
    match error {
        TransportError::AdmissionRequired(required) => {
            assert!(required.challenges.is_empty());
            assert_eq!(required.www_authenticate, ["Payment opaque"]);
        }
        other => panic!("expected admission challenge, got {other}"),
    }
    server.join().unwrap();
}

#[test]
fn helper_headers_remain_on_every_transport_retry() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (port, stop, handle, calls) = spawn_flaky_server_internal(
        Rpc::UpdateRef,
        3,
        FailKind::AdmissionThenUnavailable,
        None,
        Some(captured.clone()),
    );
    let responder_calls = Arc::new(AtomicUsize::new(0));
    let client = connect_to(port).with_admission(AdmissionPolicy::new(Arc::new(StaticResponder {
        calls: responder_calls.clone(),
        fail: false,
    })));
    client
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &blake3_hash(b"head"),
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(responder_calls.load(Ordering::SeqCst), 1);
    let headers = captured.lock().unwrap();
    assert!(
        headers[1..]
            .iter()
            .all(|h| h.get("payment-authorization").unwrap() == "Payment secret")
    );
    drop(headers);
    shutdown(stop, handle);
}

#[test]
fn raw_402_passes_empty_challenges_to_responder() {
    struct RawResponder;
    impl AdmissionResponder for RawResponder {
        fn respond(
            &self,
            ctx: &AdmissionContext<'_>,
        ) -> Result<Vec<(String, String)>, AdmissionResponderError> {
            assert!(ctx.required.challenges.is_empty());
            assert!(ctx.required.description.is_empty());
            Ok(vec![(
                "Payment-Authorization".into(),
                "Payment token".into(),
            )])
        }
    }
    let (port, stop, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::UpdateRef, 1, FailKind::Raw402);
    let client = connect_to(port).with_admission(AdmissionPolicy::new(Arc::new(RawResponder)));
    client
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &blake3_hash(b"head"),
        )
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    shutdown(stop, handle);
}

static ADMISSION_CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000_000);
fn admission_now() -> i64 {
    ADMISSION_CLOCK.load(Ordering::SeqCst)
}

#[test]
fn helper_past_identity_margin_gets_new_nonce() {
    struct SlowResponder;
    impl AdmissionResponder for SlowResponder {
        fn respond(
            &self,
            _: &AdmissionContext<'_>,
        ) -> Result<Vec<(String, String)>, AdmissionResponderError> {
            ADMISSION_CLOCK.fetch_add(280_000, Ordering::SeqCst);
            Ok(vec![(
                "Payment-Authorization".into(),
                "Payment token".into(),
            )])
        }
    }
    ADMISSION_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (port, stop, handle, _) = spawn_flaky_server_internal(
        Rpc::UpdateRef,
        1,
        FailKind::Admission,
        None,
        Some(captured.clone()),
    );
    let client = connect_to(port)
        .with_clock_for_test(admission_now)
        .with_admission(AdmissionPolicy::new(Arc::new(SlowResponder)));
    client
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &blake3_hash(b"head"),
        )
        .unwrap();
    let headers = captured.lock().unwrap();
    assert_ne!(
        headers[0].get("idempotency-key"),
        headers[1].get("idempotency-key")
    );
    drop(headers);
    shutdown(stop, handle);
}

#[test]
fn receipts_are_observed_only_on_success_and_hide_values() {
    let (port, stop, handle, _calls) =
        spawn_flaky_server_with_kind(Rpc::UpdateRef, 0, FailKind::Unavailable);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let out = observed.clone();
    let client = connect_to(port).with_admission_receipt_observer(move |receipt| {
        out.lock()
            .unwrap()
            .push((receipt.header.to_owned(), format!("{:?}", receipt.value)))
    });
    client
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &blake3_hash(b"head"),
        )
        .unwrap();
    let receipts = observed.lock().unwrap();
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().any(|(name, _)| name == "payment-receipt"));
    assert!(receipts.iter().any(|(name, _)| name == "payment-response"));
    assert!(receipts.iter().all(|(_, debug)| !debug.contains("secret")));
    shutdown(stop, handle);

    let (port, stop, handle, _) =
        spawn_flaky_server_with_kind(Rpc::UpdateRef, 1, FailKind::Admission);
    let seen = Arc::new(AtomicUsize::new(0));
    let observer = seen.clone();
    let client = connect_to(port).with_admission_receipt_observer(move |_| {
        observer.fetch_add(1, Ordering::SeqCst);
    });
    assert!(
        client
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &blake3_hash(b"head")
            )
            .is_err()
    );
    assert_eq!(seen.load(Ordering::SeqCst), 0);
    shutdown(stop, handle);
}

struct TestSigner(SigningKey);
impl EnvelopeSigner for TestSigner {
    fn public_key_hex(&self) -> String {
        mkit_core::hash::to_hex_bytes(&self.0.verifying_key().to_bytes())
    }
    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        Ok(mkit_core::hash::to_hex_bytes(
            &self.0.sign(message).to_bytes(),
        ))
    }
}

#[test]
fn signed_read_retries_use_fresh_valid_nonces() {
    for target in [
        Rpc::ListRefs,
        Rpc::ReadRef,
        Rpc::PackExists,
        Rpc::DownloadPack,
    ] {
        let nonces = Arc::new(Mutex::new(Vec::new()));
        let (port, shutdown_tx, handle, calls) =
            spawn_flaky_server_with_capture(target, 2, FailKind::Unavailable, Some(nonces.clone()));
        let uri: http::Uri = format!("http://127.0.0.1:{port}").parse().unwrap();
        let client = ConnectTransport::connect_for_test_with_signer(
            uri,
            Some(Arc::new(TestSigner(SigningKey::from_bytes(&[7; 32])))),
        );
        let key = PackKey::new(blake3_hash(b"missing-pack"));
        match target {
            Rpc::ListRefs => assert!(client.list_refs("").unwrap().is_empty()),
            Rpc::ReadRef => assert_eq!(client.read_ref("refs/heads/main").unwrap(), None),
            Rpc::PackExists => assert!(!client.pack_exists(&key).unwrap()),
            Rpc::DownloadPack => assert!(matches!(
                client.download_pack(&key),
                Err(TransportError::PackNotFound)
            )),
            _ => unreachable!(),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3, "{target:?}");
        let nonces = nonces.lock().unwrap();
        assert_eq!(nonces.len(), 3, "{target:?}");
        assert!(
            nonces
                .iter()
                .all(|nonce| mkit_core::write_auth::is_hex(nonce, 32))
        );
        assert_eq!(
            nonces
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
        drop(nonces);
        shutdown(shutdown_tx, handle);
    }
}

fn shutdown(shutdown_tx: tokio::sync::oneshot::Sender<()>, handle: std::thread::JoinHandle<()>) {
    let _ = shutdown_tx.send(());
    handle.join().expect("server thread joins cleanly");
}

// ---------------------------------------------------------------------------
// Per-verb: two transient `unavailable` failures, then success.
// ---------------------------------------------------------------------------

#[test]
fn read_ref_retries_on_unavailable_then_succeeds() {
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::ReadRef, 2);
    let client = connect_to(port);

    let h = blake3_hash(b"commit-1");
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
        .expect("seed ref (untargeted RPC, not flaky)");

    let got = client
        .read_ref("refs/heads/main")
        .expect("read_ref eventually succeeds after 2 retries");
    assert_eq!(got, Some(h));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "2 failing attempts + 1 succeeding attempt"
    );

    shutdown(shutdown_tx, handle);
}

#[test]
fn list_refs_retries_on_unavailable_then_succeeds() {
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::ListRefs, 2);
    let client = connect_to(port);

    let h = blake3_hash(b"commit-1");
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
        .expect("seed ref (untargeted RPC, not flaky)");

    let refs = client
        .list_refs("refs/heads/")
        .expect("list_refs eventually succeeds after 2 retries");
    assert_eq!(refs.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    shutdown(shutdown_tx, handle);
}

#[test]
fn update_ref_retries_on_unavailable_then_succeeds() {
    // Mutating CAS op: SPEC-TRANSPORT §7 / mkit#790 both call out that this
    // is safe by construction because `is_retryable` excludes `RefConflict`
    // — a transient `unavailable` retries, a CAS conflict never does.
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::UpdateRef, 2);
    let client = connect_to(port);

    let h = blake3_hash(b"commit-1");
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &h)
        .expect("update_ref eventually succeeds after 2 retries");
    assert_eq!(client.read_ref("refs/heads/main").unwrap(), Some(h));
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    shutdown(shutdown_tx, handle);
}

#[test]
fn advance_refs_retries_on_unavailable_then_succeeds() {
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::AdvanceRefs, 2);
    let client = connect_to(port);

    let head_h = blake3_hash(b"commit-1");
    let packmap_h = blake3_hash(b"packmap-1");
    let outcome = client
        .advance_refs(
            "refs/heads/feature",
            RefWriteCondition::Missing,
            &head_h,
            "refs/packmaps/feature",
            RefWriteCondition::Missing,
            &packmap_h,
        )
        .expect("advance_refs eventually succeeds after 2 retries");
    assert_eq!(outcome, AdvanceOutcome::Committed);
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    shutdown(shutdown_tx, handle);
}

#[test]
fn pack_exists_retries_on_unavailable_then_succeeds() {
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::PackExists, 2);
    let client = connect_to(port);

    let key = PackKey::from(blake3_hash(b"some pack bytes"));
    let exists = client
        .pack_exists(&key)
        .expect("pack_exists eventually succeeds after 2 retries");
    assert!(!exists);
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    shutdown(shutdown_tx, handle);
}

#[test]
fn upload_pack_retries_on_unavailable_then_succeeds() {
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::UploadPack, 2);
    let client = connect_to(port);

    let data = b"pack bytes for the flaky upload_pack test";
    let key = PackKey::from(blake3_hash(data));
    client
        .upload_pack(data, &key)
        .expect("upload_pack eventually succeeds after 2 retries");
    assert!(client.pack_exists(&key).unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    shutdown(shutdown_tx, handle);
}

#[test]
fn download_pack_retries_on_unavailable_then_succeeds() {
    // Exercises the "re-issue the whole stream from scratch on every
    // attempt" contract `ConnectTransport::retrying`'s doc comment
    // describes: a partially-read stream from a failed prior attempt is
    // never resumed.
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::DownloadPack, 2);
    let client = connect_to(port);

    let data = b"pack bytes for the flaky download_pack test";
    let key = PackKey::from(blake3_hash(data));
    client
        .upload_pack(data, &key)
        .expect("seed pack (untargeted RPC, not flaky)");

    let got = client
        .download_pack(&key)
        .expect("download_pack eventually succeeds after 2 retries");
    assert_eq!(got, data.to_vec());
    assert_eq!(calls.load(Ordering::SeqCst), 3);

    shutdown(shutdown_tx, handle);
}

// ---------------------------------------------------------------------------
// Non-retryable classes and ladder exhaustion
// ---------------------------------------------------------------------------

#[test]
fn does_not_retry_a_non_retryable_error() {
    // `not_found` maps to `TransportError::PackNotFound`, which
    // `is_retryable` explicitly excludes — the call must finish on the
    // very first attempt even though the server is configured to "fail"
    // (from its own counter's perspective) 5 times.
    let (port, shutdown_tx, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::PackExists, 5, FailKind::NotFound);
    let client = connect_to(port);

    let key = PackKey::new([0xEE; 32]);
    assert!(
        !client
            .pack_exists(&key)
            .expect("not_found means the pack is absent")
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a non-retryable error must not be retried"
    );

    shutdown(shutdown_tx, handle);
}

#[test]
fn retry_gives_up_after_the_ladder_is_exhausted() {
    // `connect_for_test`'s ladder is 5 retries on top of the initial
    // attempt (`mkit_core::protocol::retrying`: the first call is always
    // made, then up to `BackoffIterator`'s 5 yielded delays are consumed
    // one retry at a time) — 6 attempts total. Configuring the server to
    // fail 10 times means every attempt fails, so the call must return the
    // last error and the server must see exactly 6 calls (no attempt
    // beyond the ladder's bound).
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::ReadRef, 10);
    let client = connect_to(port);

    let err = client
        .read_ref("refs/heads/main")
        .expect_err("every attempt fails, so the call must return Err");
    assert!(
        matches!(err, TransportError::ServerError { status: 503 }),
        "{err:?}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        6,
        "1 initial attempt + 5 retries from the ladder"
    );

    shutdown(shutdown_tx, handle);
}

// ---------------------------------------------------------------------------
// Sleep hook: the injected backoff/sleep functions are actually invoked
// between attempts with the expected delay, mirroring
// `HttpTransport`'s `retry_uses_injected_backoff_and_sleeper`.
// ---------------------------------------------------------------------------

static RECORDED_SLEEP_COUNT: AtomicUsize = AtomicUsize::new(0);
static RECORDED_SLEEP_MILLIS: AtomicU64 = AtomicU64::new(0);

fn one_retry_backoff() -> BackoffIterator {
    BackoffIterator::with(Duration::from_millis(9), Duration::from_millis(9), 1)
}

fn record_sleep(delay: Duration) {
    RECORDED_SLEEP_COUNT.fetch_add(1, Ordering::SeqCst);
    RECORDED_SLEEP_MILLIS.store(
        u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
        Ordering::SeqCst,
    );
}

#[test]
fn retry_uses_injected_backoff_and_sleep_hook() {
    RECORDED_SLEEP_COUNT.store(0, Ordering::SeqCst);
    RECORDED_SLEEP_MILLIS.store(0, Ordering::SeqCst);

    let (port, shutdown_tx, handle, calls) = spawn_flaky_server(Rpc::ReadRef, 1);
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("valid loopback URI");
    let client =
        ConnectTransport::connect_for_test_with_retry(uri, one_retry_backoff, record_sleep);

    let got = client
        .read_ref("refs/heads/main")
        .expect("read_ref eventually succeeds after 1 retry");
    assert_eq!(got, None);
    assert_eq!(calls.load(Ordering::SeqCst), 2, "1 failure + 1 success");
    assert_eq!(RECORDED_SLEEP_COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(RECORDED_SLEEP_MILLIS.load(Ordering::SeqCst), 9);

    shutdown(shutdown_tx, handle);
}

static PENDING_SLEEPS: Mutex<Vec<Duration>> = Mutex::new(Vec::new());
static MIXED_SLEEPS: Mutex<Vec<Duration>> = Mutex::new(Vec::new());

fn record_pending_sleep(delay: Duration) {
    PENDING_SLEEPS.lock().unwrap().push(delay);
}

fn record_mixed_sleep(delay: Duration) {
    MIXED_SLEEPS.lock().unwrap().push(delay);
}

fn advance_for_pending_test(client: &ConnectTransport) -> Result<AdvanceOutcome, TransportError> {
    client.advance_refs(
        "refs/heads/feature",
        RefWriteCondition::Missing,
        &blake3_hash(b"pending head"),
        "refs/packmaps/feature",
        RefWriteCondition::Missing,
        &blake3_hash(b"pending packmap"),
    )
}

#[test]
fn pending_polls_past_the_ladder_with_clamped_sliced_waits() {
    PENDING_SLEEPS.lock().unwrap().clear();
    let (port, shutdown_tx, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::AdvanceRefs, 2, FailKind::Pending(1_500));
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client =
        ConnectTransport::connect_for_test_with_retry(uri, one_retry_backoff, record_pending_sleep);
    assert_eq!(
        advance_for_pending_test(&client).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "pending must not consume the one-retry ladder"
    );
    assert_eq!(
        PENDING_SLEEPS.lock().unwrap().as_slice(),
        [
            Duration::from_secs(1),
            Duration::from_millis(500),
            Duration::from_secs(1),
            Duration::from_millis(500)
        ]
    );
    shutdown(shutdown_tx, handle);
}

#[test]
fn undecodable_pending_detail_uses_the_ladder() {
    let (port, shutdown_tx, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::AdvanceRefs, 2, FailKind::PendingMalformed);
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client = ConnectTransport::connect_for_test_with_retry(
        uri,
        one_retry_backoff,
        no_sleep_for_pending_test,
    );
    assert!(matches!(
        advance_for_pending_test(&client),
        Err(TransportError::ServerError { status: 503 })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    shutdown(shutdown_tx, handle);
}

fn no_sleep_for_pending_test(_: Duration) {}

#[test]
fn pending_detail_on_another_rpc_is_ordinary_unavailable() {
    let (port, shutdown_tx, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::ReadRef, 1, FailKind::Pending(5_000));
    let client = connect_to(port);
    assert_eq!(client.read_ref("refs/heads/main").unwrap(), None);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    shutdown(shutdown_tx, handle);
}

#[test]
fn pending_then_aborted_then_pending_still_commits() {
    MIXED_SLEEPS.lock().unwrap().clear();
    let (port, shutdown_tx, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::AdvanceRefs, 3, FailKind::Mixed);
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client =
        ConnectTransport::connect_for_test_with_retry(uri, one_retry_backoff, record_mixed_sleep);
    assert_eq!(
        advance_for_pending_test(&client).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    let sleeps = MIXED_SLEEPS.lock().unwrap();
    assert_eq!(
        sleeps
            .iter()
            .filter(|d| **d == Duration::from_secs(1))
            .count(),
        2
    );
    assert_eq!(
        sleeps
            .iter()
            .filter(|d| **d == Duration::from_millis(9))
            .count(),
        1
    );
    shutdown(shutdown_tx, handle);
}

#[test]
fn unauthenticated_after_pending_renews_once() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server_internal(
        Rpc::AdvanceRefs,
        2,
        FailKind::PendingThenUnauthenticated,
        None,
        Some(Arc::clone(&captured)),
    );
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client = ConnectTransport::connect_for_test_with_retry(
        uri,
        one_retry_backoff,
        no_sleep_for_pending_test,
    );
    assert_eq!(
        advance_for_pending_test(&client).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let headers = captured.lock().unwrap();
    assert_eq!(
        header(&headers[0], "idempotency-key"),
        header(&headers[1], "idempotency-key")
    );
    assert_ne!(
        header(&headers[1], "idempotency-key"),
        header(&headers[2], "idempotency-key")
    );
    shutdown(shutdown_tx, handle);
}

#[test]
fn second_unauthenticated_without_new_pending_fails() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server_internal(
        Rpc::AdvanceRefs,
        3,
        FailKind::PendingThenTwoUnauthenticated,
        None,
        Some(Arc::clone(&captured)),
    );
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client = ConnectTransport::connect_for_test_with_retry(
        uri,
        one_retry_backoff,
        no_sleep_for_pending_test,
    );
    assert!(matches!(
        advance_for_pending_test(&client),
        Err(TransportError::AccessDenied)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let headers = captured.lock().unwrap();
    assert_eq!(
        header(&headers[0], "idempotency-key"),
        header(&headers[1], "idempotency-key")
    );
    assert_ne!(
        header(&headers[1], "idempotency-key"),
        header(&headers[2], "idempotency-key")
    );
    shutdown(shutdown_tx, handle);
}

#[test]
fn new_pending_resets_unauthenticated_renewal_allowance() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server_internal(
        Rpc::AdvanceRefs,
        4,
        FailKind::PendingUnauthenticatedTwice,
        None,
        Some(Arc::clone(&captured)),
    );
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client = ConnectTransport::connect_for_test_with_retry(
        uri,
        one_retry_backoff,
        no_sleep_for_pending_test,
    );
    assert_eq!(
        advance_for_pending_test(&client).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    let headers = captured.lock().unwrap();
    assert_eq!(
        header(&headers[2], "idempotency-key"),
        header(&headers[3], "idempotency-key")
    );
    assert_ne!(
        header(&headers[3], "idempotency-key"),
        header(&headers[4], "idempotency-key")
    );
    shutdown(shutdown_tx, handle);
}

fn header(headers: &http::HeaderMap, name: &str) -> String {
    headers.get(name).unwrap().to_str().unwrap().to_owned()
}

fn test_auth_headers(headers: &http::HeaderMap) -> mkit_core::write_auth::Headers {
    let get = |name| Some(header(headers, name));
    mkit_core::write_auth::Headers {
        version: get("x-envelope-version"),
        audience: get("x-audience"),
        repository: get("x-repository"),
        public_key: get("x-public-key"),
        signature: get("x-signature"),
        digest: get("x-digest"),
        commitment: get("x-content-commitment"),
        created_at: get("x-created-at"),
        expires_at: get("x-expires-at"),
        idempotency_key: get("idempotency-key"),
    }
}

static RENEWAL_CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000_000);
static RENEWAL_SLEEPS: AtomicUsize = AtomicUsize::new(0);

fn renewal_now() -> i64 {
    RENEWAL_CLOCK.load(Ordering::SeqCst)
}

fn advance_renewal_clock(_: Duration) {
    if RENEWAL_SLEEPS.fetch_add(1, Ordering::SeqCst) == 1 {
        RENEWAL_CLOCK.fetch_add(280_000, Ordering::SeqCst);
    }
}

#[test]
fn pending_reuses_signed_identity_then_renews_at_margin() {
    RENEWAL_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    RENEWAL_SLEEPS.store(0, Ordering::SeqCst);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server_internal(
        Rpc::AdvanceRefs,
        2,
        FailKind::Pending(1_000),
        None,
        Some(Arc::clone(&captured)),
    );
    let uri: http::Uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client = ConnectTransport::connect_for_test_with_signer(
        uri,
        Some(Arc::new(TestSigner(SigningKey::from_bytes(&[11; 32])))),
    )
    .with_clock_for_test(renewal_now)
    .with_retry_hooks_for_test(one_retry_backoff, advance_renewal_clock);
    assert_eq!(
        advance_for_pending_test(&client).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let headers = captured.lock().unwrap();
    assert_eq!(headers.len(), 3);
    assert_eq!(
        header(&headers[0], "idempotency-key"),
        header(&headers[1], "idempotency-key")
    );
    assert_eq!(
        header(&headers[0], "x-signature"),
        header(&headers[1], "x-signature")
    );
    assert_ne!(
        header(&headers[1], "idempotency-key"),
        header(&headers[2], "idempotency-key")
    );
    assert_ne!(
        header(&headers[1], "x-created-at"),
        header(&headers[2], "x-created-at")
    );
    assert_ne!(
        header(&headers[1], "x-expires-at"),
        header(&headers[2], "x-expires-at")
    );
    for headers in headers.iter() {
        let auth = test_auth_headers(headers);
        let audience = auth.audience.as_deref().unwrap();
        let repository = auth.repository.as_deref().unwrap();
        let commitment = auth.commitment.as_deref().unwrap();
        let at = auth.created_at.as_ref().unwrap().parse::<i64>().unwrap() + 1_000;
        mkit_core::write_auth::verify_headers(
            mkit_core::write_auth::Context {
                audience,
                repository,
            },
            "/mkit.transport.v1.TransportService/AdvanceRefs",
            Some(commitment),
            at,
            &auth,
        )
        .unwrap();
    }
    shutdown(shutdown_tx, handle);
}

static BOUNDARY_CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000_000);
static BOUNDARY_SLEEPS: AtomicUsize = AtomicUsize::new(0);

fn boundary_now() -> i64 {
    BOUNDARY_CLOCK.load(Ordering::SeqCst)
}

fn advance_boundary_clock(_: Duration) {
    let advance = if BOUNDARY_SLEEPS.fetch_add(1, Ordering::SeqCst) == 0 {
        270_000
    } else {
        1
    };
    BOUNDARY_CLOCK.fetch_add(advance, Ordering::SeqCst);
}

#[test]
fn poll_renews_before_the_worst_case_ladder_window() {
    BOUNDARY_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    BOUNDARY_SLEEPS.store(0, Ordering::SeqCst);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server_internal(
        Rpc::AdvanceRefs,
        2,
        FailKind::Pending(1_000),
        None,
        Some(Arc::clone(&captured)),
    );
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client = ConnectTransport::connect_for_test_with_signer(
        uri,
        Some(Arc::new(TestSigner(SigningKey::from_bytes(&[12; 32])))),
    )
    .with_clock_for_test(boundary_now)
    .with_retry_hooks_for_test(one_retry_backoff, advance_boundary_clock);
    assert_eq!(
        advance_for_pending_test(&client).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let headers = captured.lock().unwrap();
    assert_ne!(
        header(&headers[0], "idempotency-key"),
        header(&headers[1], "idempotency-key")
    );
    assert_eq!(
        header(&headers[1], "idempotency-key"),
        header(&headers[2], "idempotency-key")
    );
    shutdown(shutdown_tx, handle);
}

static AMBIGUOUS_CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000_000);

fn ambiguous_now() -> i64 {
    AMBIGUOUS_CLOCK.load(Ordering::SeqCst)
}

fn advance_ambiguous_clock(delay: Duration) {
    if delay == Duration::from_millis(9) {
        AMBIGUOUS_CLOCK.fetch_add(280_000, Ordering::SeqCst);
    }
}

#[test]
fn ambiguous_retry_keeps_identity_inside_renewal_margin() {
    AMBIGUOUS_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (port, shutdown_tx, handle, calls) = spawn_flaky_server_internal(
        Rpc::AdvanceRefs,
        2,
        FailKind::Mixed,
        None,
        Some(Arc::clone(&captured)),
    );
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client = ConnectTransport::connect_for_test_with_signer(
        uri,
        Some(Arc::new(TestSigner(SigningKey::from_bytes(&[13; 32])))),
    )
    .with_clock_for_test(ambiguous_now)
    .with_retry_hooks_for_test(one_retry_backoff, advance_ambiguous_clock);
    assert_eq!(
        advance_for_pending_test(&client).unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let headers = captured.lock().unwrap();
    assert_eq!(
        header(&headers[1], "idempotency-key"),
        header(&headers[2], "idempotency-key")
    );
    assert_eq!(
        header(&headers[1], "x-signature"),
        header(&headers[2], "x-signature")
    );
    shutdown(shutdown_tx, handle);
}

static DEADLINE_CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000_000);

fn deadline_now() -> i64 {
    DEADLINE_CLOCK.load(Ordering::SeqCst)
}

fn deadline_sleep(duration: Duration) {
    DEADLINE_CLOCK.fetch_add(
        i64::try_from(duration.as_millis()).unwrap(),
        Ordering::SeqCst,
    );
}

#[test]
fn pending_stops_at_deadline_without_another_attempt() {
    DEADLINE_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    let (port, shutdown_tx, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::AdvanceRefs, 10, FailKind::Pending(5_000));
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let client =
        ConnectTransport::connect_for_test_with_retry(uri, one_retry_backoff, deadline_sleep)
            .with_clock_for_test(deadline_now);
    let result = client.advance_refs_with_deadline(
        "refs/heads/feature",
        RefWriteCondition::Missing,
        &blake3_hash(b"head"),
        "refs/packmaps/feature",
        RefWriteCondition::Missing,
        &blake3_hash(b"packmap"),
        Some(1_700_000_002_500),
    );
    assert!(
        matches!(result, Err(TransportError::RemoteError(message)) if message.contains("deadline expired"))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(deadline_now(), 1_700_000_002_500);
    shutdown(shutdown_tx, handle);
}

#[test]
fn deadline_before_any_pending_has_neutral_error() {
    DEADLINE_CLOCK.store(1_700_000_000_000, Ordering::SeqCst);
    let uri = "http://127.0.0.1:1".parse().unwrap();
    let client = ConnectTransport::connect_for_test_with_retry(
        uri,
        one_retry_backoff,
        no_sleep_for_pending_test,
    )
    .with_clock_for_test(deadline_now);
    let result = client.advance_refs_with_deadline(
        "refs/heads/feature",
        RefWriteCondition::Missing,
        &blake3_hash(b"head"),
        "refs/packmaps/feature",
        RefWriteCondition::Missing,
        &blake3_hash(b"packmap"),
        Some(1_700_000_000_000),
    );
    assert!(
        matches!(result, Err(TransportError::RemoteError(message)) if message == "advance deadline expired")
    );
}

#[test]
fn pending_observer_cancel_is_checked_within_one_second() {
    let (port, shutdown_tx, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::AdvanceRefs, 10, FailKind::Pending(5_000));
    let uri = format!("http://127.0.0.1:{port}").parse().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let for_observer = Arc::clone(&cancelled);
    let client = ConnectTransport::connect_for_test(uri)
        .with_retry_hooks_for_test(one_retry_backoff, std::thread::sleep)
        .with_pending_observer(move |event| match event {
            PendingEvent::Waiting { .. } => !for_observer.load(Ordering::SeqCst),
            PendingEvent::Finished { .. } => true,
            _ => true,
        });
    let for_signal = Arc::clone(&cancelled);
    let signal = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        for_signal.store(true, Ordering::SeqCst);
    });
    let started = std::time::Instant::now();
    let result = advance_for_pending_test(&client);
    signal.join().unwrap();
    assert!(
        matches!(result, Err(TransportError::RemoteError(message)) if message == mkit_transport_connect::PENDING_INTERRUPTED_MESSAGE)
    );
    assert!(started.elapsed() < Duration::from_millis(1_200));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    shutdown(shutdown_tx, handle);
}
