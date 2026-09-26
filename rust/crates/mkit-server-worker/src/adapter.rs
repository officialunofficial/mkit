//! The Workers fetch adapter (WP-M0-17): a `worker::Request` in, the
//! pipeline's Connect binding ([`mkit_server::connect::service`]) over
//! [`R2BlobStore`](crate::r2::R2BlobStore) and
//! [`DoNamespaceStore`](crate::ns_client::DoNamespaceStore), a
//! `worker::Response` out. A deployment's `#[event(fetch)]` calls `fetch`
//! (wasm32), and its `#[durable_object]` holds the `ns_object` (wasm32) of
//! its state.
//!
//! **Streaming.** Neither body is ever held whole (reconciliation R-25):
//!
//! - The request body is the Worker's `ReadableStream`, wrapped in
//!   [`LimitedBody`]: it counts bytes and fails the stream past
//!   `max_body_bytes`, and gives connectrpc the `Send + Sync` error type it
//!   needs. connectrpc collects unary bodies itself (at most 4 MiB) and
//!   reads client-streaming bodies message by message on a spawned reader
//!   (`spawn_local` on wasm32) through a depth-1 channel, so an upload
//!   holds about one `UploadPack` chunk. A body over the cap gets
//!   vcs-worker's 400 JSON `resource_exhausted`: before dispatch when its
//!   `Content-Length` says so, and in place of connectrpc's answer when a
//!   chunked body trips [`LimitedBody`] ([`over_cap_response`]).
//! - The response body streams frame by frame
//!   (`mkit_worker_common::adapter::respond_streamed`): a `DownloadPack`
//!   chunk is at most 800 KiB. A unary response is one frame, so a large
//!   `ListRefs` reply is held whole (about 45 bytes per ref: 1.2 MB for
//!   30,000 refs) until WP-1.27 pages it. A unary response connectrpc compressed
//!   itself (`Content-Encoding: gzip`, for a client that accepts it) is
//!   passed through with `encodeBody: "manual"`, so the runtime does not
//!   compress it a second time.
//!
//! **Deadline headers.** `connect-timeout-ms` and `grpc-timeout` are
//! dropped before dispatch (`is_deadline_header`): connectrpc turns them
//! into a deadline with `Instant::now()`, which panics on wasm32. A client's
//! deadline is therefore not enforced.
//!
//! **Pipeline.** Auth v2 with the default write quota, one repository
//! (`AUTH_REPOSITORY`) in the deployment-default namespace, a 64 MiB pack
//! cap (the M1 stopgap; resumable parts replace it) and the Worker clock.
//! It is built per request from the request's `Env`: building it costs no
//! I/O.
//!
//! **Test faults** (`test-faults` only): the pipeline gets
//! `WorkerFaults`, `GET /__mkit_test/stats` answers the default
//! partition's size, `TEST_QUOTA_*` vars replace the write quota, and each
//! request logs the most body bytes the adapter held at once, with its
//! path (`mkit-adapter peak-buffered-bytes <n> … path <path>`).

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
#[cfg(feature = "test-faults")]
use mkit_server::quota::QuotaLimits;
use mkit_server::sql::Capacity;

use crate::do_sql::{DO_CAPACITY, DO_FREE_MAX_BYTES};

/// The Worker var holding the canonical origin writes are signed for.
pub const AUDIENCE_VAR: &str = "AUTH_AUDIENCE";
/// The Worker var holding the repository identity writes are signed for.
pub const REPOSITORY_VAR: &str = "AUTH_REPOSITORY";
/// The Worker var naming the Cloudflare plan: `paid` or `free`.
pub const PLAN_VAR: &str = "WORKERS_PLAN";

/// The largest pack one `UploadPack` may declare: 64 MiB, vcs-worker's
/// cap. A documented M1 stopgap: resumable parts (WP-1.11) replace it.
pub const MAX_PACK_BYTES: u64 = 64 * 1024 * 1024;

/// Room for Connect framing on top of [`MAX_PACK_BYTES`]: a 5-byte
/// envelope and about 45 bytes of message fields around each chunk's data,
/// so any client whose chunks average 4 KiB or more fits (mkit sends
/// 800 KiB chunks).
const FRAMING_ALLOWANCE: usize = 1024 * 1024;

/// The default request body cap: a 64 MiB pack and its framing.
#[allow(clippy::cast_possible_truncation)] // 65 MiB fits every usize we build for
pub const DEFAULT_MAX_BODY_BYTES: usize = MAX_PACK_BYTES as usize + FRAMING_ALLOWANCE;

/// `Access-Control-Allow-Methods`.
pub const CORS_ALLOW_METHODS: &str = "POST, GET, OPTIONS";

/// Deployment settings read from the Worker's vars.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerConfig {
    /// `AUTH_AUDIENCE`: the canonical origin writes are signed for.
    pub audience: String,
    /// `AUTH_REPOSITORY`: the repository identity writes are signed for.
    pub repository: String,
    /// The request body cap, [`DEFAULT_MAX_BODY_BYTES`].
    pub max_body_bytes: usize,
    /// The R2 bucket binding ([`crate::r2::STORAGE_BINDING`]). Durable
    /// Object bindings come from [`crate::naming`].
    pub blob_binding: &'static str,
    /// `TEST_QUOTA_OPS`, `TEST_QUOTA_BYTES` and `TEST_QUOTA_WINDOW_MS`,
    /// when all three are set: the write quota instead of the default
    /// (`test-faults` builds only, for the wire suite's quota and growth
    /// cases).
    #[cfg(feature = "test-faults")]
    pub test_quota: Option<QuotaLimits>,
}

/// A missing or malformed var. The adapter answers every RPC
/// `unavailable` with this message, as vcs-worker answered writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

impl WorkerConfig {
    /// The settings from `var`, which looks a Worker var up by name.
    ///
    /// # Errors
    /// A missing `AUTH_AUDIENCE` or `AUTH_REPOSITORY` (vcs-worker parity:
    /// "`<VAR>` is not configured"), an invalid repository identity, or a malformed `TEST_QUOTA_*` var.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let required =
            |name: &str| var(name).ok_or_else(|| ConfigError(format!("{name} is not configured")));
        let audience = required(AUDIENCE_VAR)?;
        let repository = required(REPOSITORY_VAR)?;
        mkit_core::repo_identity::RepositoryIdentity::parse_bare_allowed(&repository).map_err(
            |_| ConfigError("AUTH_REPOSITORY is invalid (SPEC-TRANSPORT-CONNECT §7.4)".into()),
        )?;
        Ok(Self {
            audience,
            repository,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            blob_binding: crate::r2::STORAGE_BINDING,
            #[cfg(feature = "test-faults")]
            test_quota: test_quota(&var)?,
        })
    }

    /// The settings from `env`'s vars.
    ///
    /// # Errors
    /// As [`Self::from_vars`].
    #[cfg(target_arch = "wasm32")]
    pub fn from_env(env: &worker::Env) -> Result<Self, ConfigError> {
        Self::from_vars(|name| env.var(name).ok().map(|v| v.to_string()))
    }
}

/// `TEST_QUOTA_*`: all three or none.
#[cfg(feature = "test-faults")]
fn test_quota(var: &impl Fn(&str) -> Option<String>) -> Result<Option<QuotaLimits>, ConfigError> {
    fn parse<T: core::str::FromStr>(name: &str, v: Option<&str>) -> Result<T, ConfigError> {
        v.and_then(|v| v.trim().parse().ok())
            .ok_or_else(|| ConfigError(format!("{name} is not a number")))
    }
    let names = ["TEST_QUOTA_OPS", "TEST_QUOTA_BYTES", "TEST_QUOTA_WINDOW_MS"];
    let [ops, bytes, window] = names.map(var);
    if ops.is_none() && bytes.is_none() && window.is_none() {
        return Ok(None);
    }
    Ok(Some(QuotaLimits {
        max_ops: parse(names[0], ops.as_deref())?,
        max_bytes: parse(names[1], bytes.as_deref())?,
        window_ms: parse(names[2], window.as_deref())?,
    }))
}

/// The Durable Object storage cap for the `WORKERS_PLAN` var: `paid` is
/// [`DO_CAPACITY`] (10 GB), `free` or unset is `Capacity::new(`
/// [`DO_FREE_MAX_BYTES`]`)` (1 GB). Free is the default because it is safe
/// on either plan: a Free cap on a Paid account only stops writes early,
/// while a Paid cap on a Free account runs into the 1 GB hard limit, where
/// `SQLITE_FULL` inside a transaction resets the object.
///
/// # Errors
/// Any other value, with the Free cap to fall back to.
pub fn plan_capacity(plan: Option<&str>) -> Result<Capacity, (ConfigError, Capacity)> {
    let free = Capacity::new(DO_FREE_MAX_BYTES);
    match plan.map(str::trim) {
        Some(p) if p.eq_ignore_ascii_case("paid") => Ok(DO_CAPACITY),
        None => Ok(free),
        Some(p) if p.eq_ignore_ascii_case("free") => Ok(free),
        Some(p) => Err((
            ConfigError(format!("{PLAN_VAR} `{p}` is neither `paid` nor `free`")),
            free,
        )),
    }
}

/// Why a request body stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    /// More than the cap arrived.
    TooLarge {
        /// The cap, bytes.
        limit: usize,
    },
    /// The runtime failed to read the body (its detail).
    Read(String),
}

impl core::fmt::Display for BodyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { limit } => write!(f, "request body exceeds {limit} bytes"),
            Self::Read(detail) => write!(f, "request body read failed: {detail}"),
        }
    }
}

impl std::error::Error for BodyError {}

/// What the adapter observed of one request's bodies, shared by both: the
/// largest frame (the most body bytes held at once) and whether the
/// request body ran past its cap.
#[derive(Debug, Clone, Default)]
pub struct BodyWatch(Arc<WatchState>);

#[derive(Debug, Default)]
struct WatchState {
    peak: AtomicUsize,
    too_large: AtomicBool,
}

impl BodyWatch {
    /// Record a frame of `len` bytes.
    pub fn record(&self, len: usize) {
        self.0.peak.fetch_max(len, Ordering::Relaxed);
    }

    /// The largest frame recorded.
    #[must_use]
    pub fn peak(&self) -> usize {
        self.0.peak.load(Ordering::Relaxed)
    }

    /// The request body ran past its cap ([`BodyError::TooLarge`]).
    #[must_use]
    pub fn too_large(&self) -> bool {
        self.0.too_large.load(Ordering::Relaxed)
    }

    fn set_too_large(&self) {
        self.0.too_large.store(true, Ordering::Relaxed);
    }
}

/// The response to a request whose body ran past `limit` bytes, whatever
/// connectrpc answered: vcs-worker's HTTP 400 with the Connect JSON
/// [`body_too_large_json`], as for a `Content-Length` over the cap. A
/// chunked body has no `Content-Length`, so only the stream finds out; the
/// error connectrpc builds from a failed body read is `internal`.
#[must_use]
pub fn over_cap_response(watch: &BodyWatch, limit: usize) -> Option<(u16, String)> {
    watch.too_large().then(|| (400, body_too_large_json(limit)))
}

/// A body that fails once more than `limit` bytes have passed, maps its
/// inner error to [`BodyError`] and records each frame in a [`BodyWatch`].
/// Nothing is buffered: each frame passes through as it arrives.
#[derive(Debug)]
pub struct LimitedBody<B> {
    inner: B,
    limit: usize,
    seen: usize,
    peak: BodyWatch,
    failed: bool,
}

impl<B> LimitedBody<B> {
    /// `inner`, capped at `limit` bytes.
    #[must_use]
    pub fn new(inner: B, limit: usize, peak: BodyWatch) -> Self {
        Self {
            inner,
            limit,
            seen: 0,
            peak,
            failed: false,
        }
    }
}

impl<B> Body for LimitedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: core::fmt::Display,
{
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(None);
        }
        let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Ready(Some(Err(e))) => {
                this.failed = true;
                return Poll::Ready(Some(Err(BodyError::Read(e.to_string()))));
            }
            Poll::Ready(Some(Ok(frame))) => frame,
        };
        if let Some(data) = frame.data_ref() {
            this.peak.record(data.len());
            this.seen = this.seen.saturating_add(data.len());
            if this.seen > this.limit {
                this.failed = true;
                this.peak.set_too_large();
                return Poll::Ready(Some(Err(BodyError::TooLarge { limit: this.limit })));
            }
        }
        Poll::Ready(Some(Ok(frame)))
    }

    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Called with a request's peak frame when its response body is dropped.
pub type PeakReport = Box<dyn FnOnce(usize)>;

/// A response body that records each frame in a [`BodyWatch`] and, when
/// dropped (the request is over), hands the peak to `report`.
pub struct MeasuredBody<B> {
    inner: B,
    peak: BodyWatch,
    report: Option<PeakReport>,
}

impl<B: core::fmt::Debug> core::fmt::Debug for MeasuredBody<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeasuredBody")
            .field("inner", &self.inner)
            .field("peak", &self.peak)
            .finish_non_exhaustive()
    }
}

impl<B> MeasuredBody<B> {
    /// `inner`, measured into `peak`.
    #[must_use]
    pub fn new(inner: B, peak: BodyWatch, report: Option<PeakReport>) -> Self {
        Self {
            inner,
            peak,
            report,
        }
    }
}

impl<B> Drop for MeasuredBody<B> {
    fn drop(&mut self) {
        if let Some(report) = self.report.take() {
            report(self.peak.peak());
        }
    }
}

impl<B: Body<Data = Bytes> + Unpin> Body for MeasuredBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled
            && let Some(data) = frame.data_ref()
        {
            this.peak.record(data.len());
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Drive `svc` once with a request of any body type: the streaming
/// counterpart of `mkit_worker_common::adapter::dispatch_oneshot`, which
/// takes only a whole `Full<Bytes>` body.
pub async fn dispatch_oneshot_body<S, B>(svc: S, req: http::Request<B>) -> S::Response
where
    S: tower::Service<http::Request<B>, Error = core::convert::Infallible>,
{
    use tower::ServiceExt as _;
    match svc.oneshot(req).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// vcs-worker's answer to a body over the cap: HTTP 400, Connect JSON
/// `resource_exhausted`.
#[must_use]
pub fn body_too_large_json(limit: usize) -> String {
    format!(
        "{{\"code\":\"resource_exhausted\",\"message\":\"request body exceeds {limit} bytes\"}}"
    )
}

/// The Connect JSON of an `unavailable` error with `message`.
#[must_use]
pub fn unavailable_json(message: &str) -> String {
    let body = serde_json::json!({ "code": "unavailable", "message": message });
    body.to_string()
}

#[cfg(feature = "test-faults")]
pub use faults::{FINAL_CHUNK_FAULT, FaultState, WorkerFaults};

#[cfg(feature = "test-faults")]
mod faults {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex, PoisonError};

    use mkit_core::hash::Hash;
    use mkit_server::pipeline::{FailOnce, FaultHooks, FaultPoint, TestDirectives};
    use mkit_server::{MaybeSend, MaybeSync, Operation, ServerError};

    /// The `x-mkit-test-fault` token that fails an upload's final R2 chunk
    /// once per operation ([`crate::r2::R2BlobStore::fail_final_chunk_once`]).
    pub const FINAL_CHUNK_FAULT: &str = "final-chunk";

    /// The isolate's fault state: it outlives each request's pipeline, so
    /// a fault fires once per operation and its retry passes.
    #[derive(Debug, Default)]
    pub struct FaultState {
        once: FailOnce,
        final_chunk: Mutex<HashSet<Option<Hash>>>,
    }

    /// The Workers [`FaultHooks`]: vcs-worker's `after-reserve` and
    /// `after-put` ([`FailOnce`]), plus `final-chunk`, which arms the blob
    /// store's withheld-final-chunk fault at the reservation. The Durable
    /// Object's own fault (a batch writing a key containing
    /// `__test_fail_once-` fails once) needs no hook: `NsObject` wraps its
    /// connection in `FaultConn` under `test-faults`.
    pub struct WorkerFaults<A> {
        state: Arc<FaultState>,
        arm_final_chunk: A,
    }

    impl<A> core::fmt::Debug for WorkerFaults<A> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("WorkerFaults").finish_non_exhaustive()
        }
    }

    impl<A: Fn() + MaybeSend + MaybeSync> WorkerFaults<A> {
        /// Hooks over the isolate's `state`; `arm_final_chunk` arms the
        /// request's blob store.
        pub fn new(state: Arc<FaultState>, arm_final_chunk: A) -> Self {
            Self {
                state,
                arm_final_chunk,
            }
        }
    }

    impl<A: Fn() + MaybeSend + MaybeSync> FaultHooks for WorkerFaults<A> {
        async fn at(
            &self,
            point: FaultPoint,
            op: &Operation,
            directives: &TestDirectives,
        ) -> Result<(), ServerError> {
            if point == FaultPoint::AfterReserve
                && directives.fault.as_deref() == Some(FINAL_CHUNK_FAULT)
            {
                let scope = op.auth.as_ref().map(|a| a.replay_scope);
                let first = self
                    .state
                    .final_chunk
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(scope);
                if first {
                    (self.arm_final_chunk)();
                }
            }
            self.state.once.at(point, op, directives).await
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use glue::{fetch, ns_object, serve};

#[cfg(target_arch = "wasm32")]
mod glue {
    use std::sync::Arc;

    use mkit_server::auth_v2::{AuthV2Config, CORS_ALLOW_HEADERS};
    use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
    use mkit_server::upload::UploadLimits;
    use mkit_server::{Addressing, NamespaceKey, NoopMetrics, RepoId, RepoName};
    use mkit_worker_common::adapter::{
        copy_headers_filtered, copy_response_headers, is_deadline_header, respond_streamed,
        to_http_method,
    };
    use mkit_worker_common::body_cap::content_length_exceeds;
    use mkit_worker_common::cors::{cors_preflight_response, is_options_preflight, with_cors};
    use worker::{Env, Request, Response, State};

    use super::{
        BodyWatch, CORS_ALLOW_METHODS, ConfigError, LimitedBody, MAX_PACK_BYTES, MeasuredBody,
        PLAN_VAR, WorkerConfig, body_too_large_json, dispatch_oneshot_body, over_cap_response,
        plan_capacity, unavailable_json,
    };
    use crate::clock::WorkerClock;
    use crate::naming::Placement;
    use crate::ns_client::{StubTransport, WorkerNamespaceStore};
    use crate::ns_object::NsObject;
    use crate::r2::{EnvBucket, PACKS_KEYSPACE, R2BlobStore, WorkerBlobStore};

    /// The pipeline a request runs on.
    type WorkerPipeline = Pipeline<WorkerBlobStore, WorkerNamespaceStore, Hooks>;

    fn json_response(body: String, status: u16) -> worker::Result<Response> {
        let mut response = Response::error(body, status)?;
        response
            .headers_mut()
            .set("Content-Type", "application/json")?;
        Ok(response)
    }

    /// The pipeline for `cfg` over `env`'s bindings.
    fn pipeline(env: &Env, cfg: &WorkerConfig) -> Result<WorkerPipeline, ConfigError> {
        let bad = |e: &dyn core::fmt::Display| ConfigError(e.to_string());
        let auth = AuthV2Config::new(cfg.audience.as_str(), cfg.repository.as_str())
            .map_err(|e| bad(&e))?;
        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new(cfg.repository.as_str()).map_err(|e| bad(&e))?,
        };
        let limits = UploadLimits {
            max_total_bytes: MAX_PACK_BYTES,
            // vcs-worker had no chunk cap; the body cap bounds the count.
            max_chunks: u32::MAX,
        };
        #[allow(unused_mut)]
        let mut config =
            PipelineConfig::new(Addressing::Single { repo }, AuthMode::AuthV2(auth), limits);
        #[cfg(feature = "test-faults")]
        if let Some(quota) = cfg.test_quota {
            config.write_quota = Some(quota);
        }
        let blobs = R2BlobStore::new(
            EnvBucket::new(env.clone(), cfg.blob_binding),
            PACKS_KEYSPACE,
        )
        .with_max_bytes(MAX_PACK_BYTES);
        let meta = WorkerNamespaceStore::new(StubTransport::new(env.clone(), Placement::default()));
        #[cfg(feature = "test-faults")]
        let faulted = blobs.clone();
        let pipe = Pipeline::new(
            blobs,
            meta,
            Hooks::new(),
            config,
            Arc::new(WorkerClock),
            Arc::new(NoopMetrics),
        )
        .map_err(|e| bad(&e))?;
        #[cfg(feature = "test-faults")]
        let pipe = pipe.with_faults(super::WorkerFaults::new(test::fault_state(), move || {
            faulted.fail_final_chunk_once();
        }));
        Ok(pipe)
    }

    /// The `http::Request` connectrpc dispatches: `req`'s method, URL and
    /// headers (without the deadline headers) over its streaming body.
    fn http_request(
        req: &Request,
        max_body_bytes: usize,
        watch: &BodyWatch,
    ) -> worker::Result<http::Request<LimitedBody<worker::Body>>> {
        let body = req
            .inner()
            .body()
            .map_or_else(worker::Body::empty, worker::Body::new);
        let mut http_req = http::Request::builder()
            .method(to_http_method(req.method()))
            .uri(req.url()?.to_string())
            .body(LimitedBody::new(body, max_body_bytes, watch.clone()))
            .map_err(|e| worker::Error::RustError(format!("build http request: {e}")))?;
        copy_headers_filtered(req.headers().entries(), http_req.headers_mut(), |k| {
            !is_deadline_header(k)
        });
        Ok(http_req)
    }

    /// A deployment's whole `#[event(fetch)]`: [`serve`] with the
    /// [`WorkerConfig`] of `env`'s vars. With a var missing or malformed,
    /// every request but a CORS preflight is answered `unavailable` (HTTP
    /// 503) naming it.
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    pub async fn fetch(req: Request, env: Env) -> worker::Result<Response> {
        match WorkerConfig::from_env(&env) {
            Ok(cfg) => serve(req, env, &cfg).await,
            Err(_) if is_options_preflight(&req) => {
                cors_preflight_response(CORS_ALLOW_HEADERS, CORS_ALLOW_METHODS)
            }
            Err(e) => Ok(with_cors(json_response(unavailable_json(&e.0), 503)?)),
        }
    }

    /// Answer one request of a deployment (see the module docs).
    ///
    /// # Errors
    /// Only when the runtime fails to build a response.
    pub async fn serve(req: Request, env: Env, cfg: &WorkerConfig) -> worker::Result<Response> {
        if is_options_preflight(&req) {
            return cors_preflight_response(CORS_ALLOW_HEADERS, CORS_ALLOW_METHODS);
        }
        #[cfg(feature = "test-faults")]
        if req.method() == worker::Method::Get && req.path() == test::STATS_PATH {
            return Ok(with_cors(test::stats(&env).await?));
        }
        let length = req.headers().get("content-length").ok().flatten();
        if content_length_exceeds(length.as_deref(), cfg.max_body_bytes) {
            let body = body_too_large_json(cfg.max_body_bytes);
            return Ok(with_cors(json_response(body, 400)?));
        }
        let pipe = match pipeline(&env, cfg) {
            Ok(pipe) => pipe,
            Err(e) => return Ok(with_cors(json_response(unavailable_json(&e.0), 503)?)),
        };
        let watch = BodyWatch::default();
        let http_req = http_request(&req, cfg.max_body_bytes, &watch)?;
        // The binding takes an `Arc` and holds it in a `SendWrapper` on
        // wasm32, where the pipeline's Workers handles are `!Send`.
        #[allow(clippy::arc_with_non_send_sync)]
        let pipe = Arc::new(pipe);
        let http_resp = dispatch_oneshot_body(mkit_server::connect::service(pipe), http_req).await;
        // A unary body is read whole, and a client-streaming handler has
        // answered, before connectrpc returns its response: a body that
        // ran past the cap has tripped the watch by now.
        if let Some((status, body)) = over_cap_response(&watch, cfg.max_body_bytes) {
            return Ok(with_cors(json_response(body, status)?));
        }
        let status = http_resp.status().as_u16();
        let headers = http_resp.headers().clone();
        #[cfg(feature = "test-faults")]
        let report: Option<super::PeakReport> = {
            let path = req.path();
            Some(Box::new(move |bytes| test::report_peak(&path, bytes)))
        };
        #[cfg(not(feature = "test-faults"))]
        let report = None;
        let body = MeasuredBody::new(http_resp.into_body(), watch, report);
        let mut out = respond_streamed(status, body)?;
        if headers.contains_key(http::header::CONTENT_ENCODING) {
            // connectrpc compressed the body itself (a unary response to
            // `Accept-Encoding: gzip`): the runtime must pass it through,
            // not encode it a second time.
            out = out.with_encode_body(worker::EncodeBody::Manual);
        }
        copy_response_headers(&headers, &mut out);
        Ok(with_cors(out))
    }

    /// The Durable Object of a partition for `state`: its store capped for
    /// the plan in `env`'s `WORKERS_PLAN` var (see [`plan_capacity`]).
    #[must_use]
    pub fn ns_object(state: State, env: &Env) -> NsObject {
        let plan = env.var(PLAN_VAR).ok().map(|v| v.to_string());
        let capacity = plan_capacity(plan.as_deref()).unwrap_or_else(|(e, free)| {
            worker::console_error!("{e}; using the Workers Free cap");
            free
        });
        NsObject::new(state).0.with_capacity(capacity)
    }

    #[cfg(feature = "test-faults")]
    mod test {
        use std::sync::Arc;

        use mkit_server::{NamespaceKey, NamespaceStore, Partition};
        use worker::{Env, Response};

        use super::super::faults::FaultState;
        use crate::naming::Placement;
        use crate::ns_client::{StubTransport, WorkerNamespaceStore};

        /// The wire suite's stats hook (M0-07).
        pub(super) const STATS_PATH: &str = "/__mkit_test/stats";

        thread_local! {
            static FAULTS: Arc<FaultState> = Arc::default();
        }

        /// The isolate's fault state.
        pub(super) fn fault_state() -> Arc<FaultState> {
            FAULTS.with(Arc::clone)
        }

        /// `{bytes, keys}` of the deployment-default partition, which holds
        /// the replay records and quota windows.
        pub(super) async fn stats(env: &Env) -> worker::Result<Response> {
            let store =
                WorkerNamespaceStore::new(StubTransport::new(env.clone(), Placement::default()));
            let p = Partition::Namespace(NamespaceKey::deployment_default());
            match store.stats(&p).await {
                Ok(s) => {
                    Response::from_json(&serde_json::json!({ "bytes": s.bytes, "keys": s.keys }))
                }
                Err(e) => Response::error(e.to_string(), 503),
            }
        }

        /// Log the most body bytes a request held at once
        /// (`scripts/vcs-worker-conformance.sh --test-faults` checks it).
        /// Also logs the isolate's wasm linear memory, which only grows: a
        /// leak across requests shows as a climb toward the 128 MB isolate
        /// limit.
        /// The script bounds the streaming RPCs' lines only: a unary body is
        /// one frame (a whole `ListRefs` reply until WP-1.27's paging).
        pub(super) fn report_peak(path: &str, bytes: usize) {
            let memory = core::arch::wasm32::memory_size::<0>() * 65_536;
            worker::console_log!(
                "mkit-adapter peak-buffered-bytes {bytes} wasm-memory-bytes {memory} path {path}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use futures::executor::block_on;
    use http_body_util::{BodyExt as _, Full, StreamBody};

    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn config_requires_audience_and_repository() {
        let cfg = WorkerConfig::from_vars(vars(&[
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, "default"),
        ]))
        .unwrap();
        assert_eq!(cfg.audience, "https://vcs.example");
        assert_eq!(cfg.repository, "default");
        assert_eq!(cfg.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(cfg.blob_binding, "STORAGE");
        assert_eq!(
            WorkerConfig::from_vars(vars(&[(REPOSITORY_VAR, "default")])).unwrap_err(),
            ConfigError("AUTH_AUDIENCE is not configured".into())
        );
        assert_eq!(
            WorkerConfig::from_vars(vars(&[(AUDIENCE_VAR, "https://vcs.example")])).unwrap_err(),
            ConfigError("AUTH_REPOSITORY is not configured".into())
        );
    }

    #[test]
    fn config_validates_repository_grammar() {
        for repository in ["Upper", ".name", "root/name", "a/b", &"a".repeat(101)] {
            let err = WorkerConfig::from_vars(vars(&[
                (AUDIENCE_VAR, "https://vcs.example"),
                (REPOSITORY_VAR, repository),
            ]))
            .unwrap_err();
            assert_eq!(
                err,
                ConfigError("AUTH_REPOSITORY is invalid (SPEC-TRANSPORT-CONNECT §7.4)".into())
            );
        }
        let identity = format!("ed25519-{}/name", "a".repeat(64));
        let cfg = WorkerConfig::from_vars(vars(&[
            (AUDIENCE_VAR, "https://vcs.example"),
            (REPOSITORY_VAR, &identity),
        ]))
        .unwrap();
        assert_eq!(cfg.repository, identity);
    }

    #[cfg(feature = "test-faults")]
    #[test]
    fn test_quota_is_all_or_nothing() {
        let base = [(AUDIENCE_VAR, "https://x.example"), (REPOSITORY_VAR, "r")];
        let cfg = WorkerConfig::from_vars(vars(&base)).unwrap();
        assert_eq!(cfg.test_quota, None);
        let mut all = base.to_vec();
        all.extend([
            ("TEST_QUOTA_OPS", "7"),
            ("TEST_QUOTA_BYTES", "1024"),
            ("TEST_QUOTA_WINDOW_MS", "5000"),
        ]);
        let cfg = WorkerConfig::from_vars(vars(&all)).unwrap();
        assert_eq!(
            cfg.test_quota,
            Some(QuotaLimits {
                window_ms: 5000,
                max_ops: 7,
                max_bytes: 1024
            })
        );
        let mut partial = base.to_vec();
        partial.push(("TEST_QUOTA_OPS", "7"));
        assert!(WorkerConfig::from_vars(vars(&partial)).is_err());
    }

    /// `final-chunk` arms the blob store once per operation; `after-reserve`
    /// and `after-put` fail once per operation through `FailOnce`.
    #[cfg(feature = "test-faults")]
    #[test]
    fn worker_faults_fire_once_per_operation() {
        use mkit_core::protocol::PackKey;
        use mkit_core::write_auth::Authorized;
        use mkit_server::pipeline::{FaultHooks, FaultPoint, TestDirectives};
        use mkit_server::{
            NamespaceKey, OpKind, Operation, Principal, RepoId, RepoName, VerifiedAuth,
        };

        let op = |scope: u8| {
            let hex = |b: u8| format!("{b:02x}").repeat(32);
            let authorized = Authorized {
                scope: hex(scope),
                public_key: hex(1),
                nonce: hex(0),
                fingerprint: hex(2),
                commitment: format!("pack:{}:1", hex(3)),
                expires_at: 1,
            };
            let auth = VerifiedAuth::try_from(&authorized).unwrap();
            let repo = RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new("default").unwrap(),
            };
            let kind = OpKind::UploadPack {
                key: PackKey::new([3; 32]),
                declared_len: 1,
            };
            Operation::new(repo, Principal::Anonymous, Some(auth), kind)
        };
        let directives = |fault: &str| TestDirectives {
            fault: Some(fault.to_owned()),
            clock_skew_ms: 0,
        };
        let armed = Arc::new(AtomicUsize::new(0));
        let counter = armed.clone();
        let faults = WorkerFaults::new(Arc::default(), move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let at = |point, op: &Operation, fault| block_on(faults.at(point, op, &directives(fault)));
        // `final-chunk` never fails the hook itself: it arms the store.
        for _ in 0..2 {
            at(FaultPoint::AfterReserve, &op(1), FINAL_CHUNK_FAULT).unwrap();
        }
        assert_eq!(armed.load(Ordering::SeqCst), 1, "once per operation");
        at(FaultPoint::AfterReserve, &op(2), FINAL_CHUNK_FAULT).unwrap();
        assert_eq!(armed.load(Ordering::SeqCst), 2, "again for another one");
        at(FaultPoint::AfterAuthorize, &op(3), FINAL_CHUNK_FAULT).unwrap();
        assert_eq!(armed.load(Ordering::SeqCst), 2, "only at the reservation");
        // vcs-worker's tokens: the first attempt fails, its retry passes.
        for (point, token) in [
            (FaultPoint::AfterReserve, "after-reserve"),
            (FaultPoint::AfterBlobCommit, "after-put"),
        ] {
            assert!(at(point, &op(4), token).is_err());
            at(point, &op(4), token).unwrap();
        }
    }

    #[test]
    fn plan_capacity_defaults_to_free() {
        let free = Capacity::new(DO_FREE_MAX_BYTES);
        assert_eq!(plan_capacity(None).unwrap(), free);
        assert_eq!(plan_capacity(Some("free")).unwrap(), free);
        assert_eq!(plan_capacity(Some(" Paid ")).unwrap(), DO_CAPACITY);
        let (err, fallback) = plan_capacity(Some("enterprise")).unwrap_err();
        assert!(err.0.contains("enterprise"), "{err}");
        assert_eq!(fallback, free);
    }

    type Chunks = Vec<Result<Frame<Bytes>, BodyError>>;
    type Frames =
        StreamBody<futures::stream::Iter<std::vec::IntoIter<Result<Frame<Bytes>, BodyError>>>>;

    fn frames(chunks: &[&[u8]]) -> Frames {
        let items: Chunks = chunks
            .iter()
            .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
            .collect();
        StreamBody::new(futures::stream::iter(items))
    }

    #[test]
    fn limited_body_passes_frames_through_and_records_the_peak() {
        let peak = BodyWatch::default();
        let body = LimitedBody::new(frames(&[b"abc", b"defgh", b"ij"]), 10, peak.clone());
        let out = block_on(body.collect()).unwrap().to_bytes();
        assert_eq!(&out[..], b"abcdefghij");
        assert_eq!(peak.peak(), 5, "the largest frame, never the total");
    }

    #[test]
    fn limited_body_fails_past_the_cap_and_then_ends() {
        let peak = BodyWatch::default();
        let mut body = LimitedBody::new(frames(&[b"abc", b"defgh", b"ij"]), 7, peak);
        let first = block_on(body.frame()).unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"abc"));
        let err = block_on(body.frame()).unwrap().unwrap_err();
        assert_eq!(err, BodyError::TooLarge { limit: 7 });
        assert!(block_on(body.frame()).is_none());
        assert!(body.is_end_stream());
    }

    #[test]
    fn limited_body_maps_read_errors() {
        let items: Chunks = vec![Err(BodyError::Read("reset".into()))];
        let inner = StreamBody::new(futures::stream::iter(items));
        let mut body = LimitedBody::new(inner, 10, BodyWatch::default());
        let err = block_on(body.frame()).unwrap().unwrap_err();
        assert!(
            matches!(err, BodyError::Read(ref d) if d.contains("reset")),
            "{err}"
        );
    }

    #[test]
    fn measured_body_records_response_frames() {
        static REPORTED: AtomicUsize = AtomicUsize::new(0);
        fn report(n: usize) {
            REPORTED.store(n, Ordering::SeqCst);
        }
        let peak = BodyWatch::default();
        peak.record(3);
        let full = Full::new(Bytes::from_static(b"12345678"));
        let body = MeasuredBody::new(full, peak.clone(), Some(Box::new(report)));
        let out = block_on(body.collect()).unwrap().to_bytes();
        assert_eq!(out.len(), 8);
        assert_eq!(peak.peak(), 8);
        // Collecting consumed (dropped) the body: the peak was reported.
        assert_eq!(REPORTED.load(Ordering::SeqCst), 8);
    }

    #[test]
    fn default_body_cap_leaves_room_for_framing() {
        assert!(DEFAULT_MAX_BODY_BYTES as u64 > MAX_PACK_BYTES);
        assert!(body_too_large_json(5).contains("resource_exhausted"));
        let v: serde_json::Value = serde_json::from_str(&unavailable_json("a \"b\"")).unwrap();
        assert_eq!(v["code"], "unavailable");
        assert_eq!(v["message"], "a \"b\"");
    }

    /// The Connect binding over memory stores, open auth, 1 MiB packs.
    fn open_service() -> connectrpc::ConnectRpcService {
        use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
        use mkit_server::upload::UploadLimits;
        use mkit_server::{
            Addressing, MemoryBlobStore, MemoryKv, NamespaceKey, NoopMetrics, RepoId, RepoName,
            SystemClock,
        };

        let repo = RepoId {
            namespace: NamespaceKey::deployment_default(),
            name: RepoName::new("default").unwrap(),
        };
        let limits = UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        };
        let cfg = PipelineConfig::new(Addressing::Single { repo }, AuthMode::Open, limits);
        let pipe = Pipeline::new(
            MemoryBlobStore::default(),
            MemoryKv::default(),
            Hooks::new(),
            cfg,
            Arc::new(SystemClock),
            Arc::new(NoopMetrics),
        )
        .unwrap();
        mkit_server::connect::service(Arc::new(pipe))
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// A streaming request body reaches the service unbuffered: the Connect
    /// binding answers a unary RPC read from a multi-frame body.
    #[test]
    fn dispatch_streams_a_request_body_into_the_connect_binding() {
        let svc = open_service();
        let peak = BodyWatch::default();
        let body = LimitedBody::new(
            frames(&[b"{\"name\":", b"\"refs/heads/main\"}"]),
            1024,
            peak.clone(),
        );
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://w.example/mkit.transport.v1.TransportService/ReadRef")
            .header("content-type", "application/json")
            .header("connect-protocol-version", "1")
            .body(body)
            .unwrap();
        let runtime = runtime();
        let resp = runtime.block_on(dispatch_oneshot_body(svc, req));
        assert_eq!(resp.status(), 200);
        let out = runtime
            .block_on(resp.into_body().collect())
            .unwrap()
            .to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_ne!(
            v.get("exists").and_then(serde_json::Value::as_bool),
            Some(true),
            "{v}"
        );
        assert_eq!(peak.peak(), b"\"refs/heads/main\"}".len());
    }

    /// One Connect streaming envelope around a JSON message.
    fn envelope(msg: &serde_json::Value) -> Vec<u8> {
        let json = msg.to_string().into_bytes();
        let mut out = vec![0];
        out.extend_from_slice(&u32::try_from(json.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&json);
        out
    }

    /// A chunked (no `Content-Length`) `UploadPack` body that runs past the
    /// cap while its data stays within the declared size: connectrpc
    /// answers the failed read as an error of its own, and the adapter's
    /// watch has tripped by the time the response is back, so it answers
    /// 400 `resource_exhausted` as for a `Content-Length` over the cap.
    #[test]
    fn a_chunked_body_over_the_cap_is_resource_exhausted() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;

        const LIMIT: usize = 4096;
        let pack: Vec<u8> = (0..=255_u8).cycle().take(64 * 1024).collect();
        let id = STANDARD.encode(mkit_core::hash::hash(&pack));
        let mut messages: Vec<Vec<u8>> = vec![envelope(&serde_json::json!({
            "header": { "packId": id, "totalBytes": pack.len().to_string() }
        }))];
        for (i, data) in pack.chunks(1024).enumerate() {
            messages.push(envelope(&serde_json::json!({ "chunk": {
                "packId": id,
                "offset": (i * 1024).to_string(),
                "data": STANDARD.encode(data),
                "last": (i + 1) * 1024 == pack.len(),
            }})));
        }
        let parts: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
        let watch = BodyWatch::default();
        let body = LimitedBody::new(frames(&parts), LIMIT, watch.clone());
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://w.example/mkit.transport.v1.TransportService/UploadPack")
            .header("content-type", "application/connect+json")
            .header("connect-protocol-version", "1")
            .body(body)
            .unwrap();
        assert!(!req.headers().contains_key(http::header::CONTENT_LENGTH));
        let runtime = runtime();
        let resp = runtime.block_on(dispatch_oneshot_body(open_service(), req));
        assert!(watch.too_large(), "the cap tripped before the response");
        let connect = runtime
            .block_on(resp.into_body().collect())
            .unwrap()
            .to_bytes();
        let connect = String::from_utf8_lossy(&connect);
        assert!(!connect.contains("resource_exhausted"), "{connect}");
        let (status, json) = over_cap_response(&watch, LIMIT).unwrap();
        assert_eq!(status, 400);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["code"], "resource_exhausted");
        // Under the cap nothing is replaced.
        assert_eq!(over_cap_response(&BodyWatch::default(), LIMIT), None);
    }
}
