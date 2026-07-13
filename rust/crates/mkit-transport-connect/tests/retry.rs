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

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use connectrpc::server::Server;
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, Router, ServiceRequest, ServiceResult,
    ServiceStream,
};
use futures::StreamExt;
use mkit_core::hash::hash as blake3_hash;
use mkit_core::protocol::{
    AdvanceOutcome, BackoffIterator, PackKey, RefWriteCondition, Transport, TransportError,
};
use mkit_transport_connect::{ConnectTransport, generated};
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
}

impl FailKind {
    fn to_connect_error(self, n: usize, fail_times: usize) -> ConnectError {
        match self {
            FailKind::Unavailable => {
                ConnectError::unavailable(format!("flaky failure #{} of {}", n + 1, fail_times))
            }
            FailKind::NotFound => ConnectError::not_found("flaky not-found failure"),
        }
    }
}

struct FlakyService {
    inner: Arc<MemoryTransport>,
    target: Rpc,
    fail_times: usize,
    fail_kind: FailKind,
    calls: Arc<AtomicUsize>,
}

impl FlakyService {
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
    async fn list_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
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
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::ReadRefRequest>,
    ) -> ServiceResult<generated::ReadRefResponse> {
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
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::UpdateRefRequest>,
    ) -> ServiceResult<generated::UpdateRefResponse> {
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
        Ok(Response::new(generated::UpdateRefResponse::default()))
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
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
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
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
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<generated::DownloadPackResponse>> {
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
    // `is_retryable` explicitly excludes — the call must surface on the
    // very first attempt even though the server is configured to "fail"
    // (from its own counter's perspective) 5 times.
    let (port, shutdown_tx, handle, calls) =
        spawn_flaky_server_with_kind(Rpc::PackExists, 5, FailKind::NotFound);
    let client = connect_to(port);

    let key = PackKey::new([0xEE; 32]);
    let err = client
        .pack_exists(&key)
        .expect_err("pack_exists surfaces PackNotFound immediately, no retry");
    assert!(matches!(err, TransportError::PackNotFound), "{err:?}");
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
