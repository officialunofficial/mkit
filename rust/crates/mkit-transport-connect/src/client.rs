//! [`ConnectTransport`] — the native `mkit.transport.v1.TransportService`
//! ConnectRPC client, implementing [`Transport`] for the `mkit+https://`
//! (and loopback-only `mkit+http://`) remote scheme.

use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use connectrpc::client::{CallOptions, ClientConfig, HttpClient};
use http::Uri;
use http::header::AUTHORIZATION;
use mkit_core::hash::Hash;
use mkit_core::protocol::async_shim::Executor as _;
use mkit_core::protocol::{
    AdvanceOutcome as CoreAdvanceOutcome, BackoffIterator, PACK_BODY_LIMIT, PACK_BODY_LIMIT_USIZE,
    PackKey, RefWriteCondition, RepositoryAddress, Transport, TransportError, TransportResult,
};
use mkit_core::refs::{Ref, validate_ref_name};
use mkit_core::repo_identity::{IdentityError, RepositoryIdentity};
use url::{Host, Url};

use crate::envelope::{EnvelopeSigner, EnvelopeTransport, RetryIdentity};
use crate::error::{ErrorContext, map_connect_error, pending_verification_delay};
use crate::executor::TokioExecutor;
use crate::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use crate::proto::mkit::transport::v1::{
    AdvanceOutcome as ProtoAdvanceOutcome, AdvanceRefsRequest, DownloadPackRequest,
    GetServerInfoRequest, GetServerInfoResponse, ListRefsRequest, PackChunk, PackExistsRequest,
    ReadRefRequest, RefExpectation, TransportServiceClient, UpdateRefRequest, UploadPackHeader,
    UploadPackRequest,
};

/// Capability discovery result, immutable for a transport's lifetime.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ServerInfoView {
    /// A validated v2 (or later) deployment advertisement.
    V2(Box<GetServerInfoResponse>),
    /// The discovery procedure is unimplemented on this server.
    Legacy,
    /// Discovery failed after retries or returned invalid capabilities.
    Unknown,
}

/// Invalid remote URL or repository path; no path spelling is repaired.
#[derive(Debug)]
#[non_exhaustive]
pub enum UrlIdentityError {
    /// URL parsing failed.
    Url(url::ParseError),
    /// A query or fragment would make the repository address ambiguous.
    QueryOrFragment,
    /// The URL is not literally `scheme://authority/path`, or URL parsing
    /// would rewrite its path (dot segments, backslashes, extra slashes).
    NonLiteralPath,
    /// The literal path is outside the repository identity grammar.
    Identity(IdentityError),
}

impl std::fmt::Display for UrlIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(e) => write!(f, "invalid URL: {e}"),
            Self::QueryOrFragment => {
                f.write_str("repository URLs cannot contain a non-empty query or fragment")
            }
            Self::NonLiteralPath => f.write_str(
                "repository URLs must be written as scheme://host/path, with a path URL parsing leaves unchanged",
            ),
            Self::Identity(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for UrlIdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Url(e) => Some(e),
            Self::Identity(e) => Some(e),
            Self::QueryOrFragment | Self::NonLiteralPath => None,
        }
    }
}

/// Read the repository identity from a remote URL's literal path.
///
/// # Errors
/// Returns [`UrlIdentityError`] for an invalid URL, query, fragment or identity.
pub fn repository_identity_from_url(url: &str) -> Result<RepositoryIdentity, UrlIdentityError> {
    let stripped = url.strip_prefix("mkit+").unwrap_or(url);
    let parsed = Url::parse(stripped).map_err(UrlIdentityError::Url)?;
    if parsed.query().is_some_and(|s| !s.is_empty())
        || parsed.fragment().is_some_and(|s| !s.is_empty())
    {
        return Err(UrlIdentityError::QueryOrFragment);
    }
    // WHATWG URL parsing repairs dot segments, backslashes and missing or
    // extra slashes after the scheme. Require the literal text to be
    // `scheme://authority/path` with the path the parser also sees, so those
    // repairs cannot alter repository routing.
    let scheme_sep = format!("{}://", parsed.scheme());
    let rest = match stripped.get(..scheme_sep.len()) {
        Some(head) if head.eq_ignore_ascii_case(&scheme_sep) => &stripped[scheme_sep.len()..],
        _ => return Err(UrlIdentityError::NonLiteralPath),
    };
    let path_start = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let raw_path = rest[path_start..].split(['?', '#']).next().unwrap_or("");
    if raw_path != parsed.path() && !(raw_path.is_empty() && parsed.path() == "/") {
        return Err(UrlIdentityError::NonLiteralPath);
    }
    let path = raw_path.trim_matches('/');
    RepositoryIdentity::parse_bare_allowed(if path.is_empty() { "default" } else { path })
        .map_err(UrlIdentityError::Identity)
}

fn valid_server_info(info: &GetServerInfoResponse) -> bool {
    info.protocol.as_deref() == Some("mkit.transport.v1")
        && info.spec_version.is_some_and(|v| v >= 2)
        && info
            .part_size
            .is_some_and(|v| v >= 8 * 1024 * 1024 && v.is_power_of_two())
        && info.max_list_refs_page_size.is_some_and(|v| v >= 1)
}

fn ref_hint(options: CallOptions, ref_name: Option<&str>) -> CallOptions {
    match ref_name.filter(|name| validate_ref_name(name)) {
        Some(name) => options.with_header("x-mkit-ref", name),
        None => options,
    }
}

/// A generous termination bound: at most 100,000 pages per listing.
/// This prevents cyclic cursors from holding a client forever.
const MAX_LIST_REFS_PAGES: usize = 100_000;

/// Bound on one listing's accumulated ref names plus 32-byte ids, so a server
/// cannot grow a paged listing without limit.
const MAX_LIST_REFS_BYTES: usize = 128 * 1024 * 1024;

const MAX_PENDING_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
const MIN_RENEWAL_MARGIN_MS: i64 = 30_000;
/// Returned when a pending observer asks the poll loop to stop.
pub const PENDING_INTERRUPTED_MESSAGE: &str = "pending verification interrupted";

/// Progress events for a ticket verification poll.
#[derive(Debug, Clone, Copy)]
pub enum PendingEvent {
    /// Emitted before each sleep slice. Returning `false` stops polling.
    Waiting { elapsed: Duration, next: Duration },
    /// Emitted after polling ends, so progress UIs can finish their line.
    Finished { elapsed: Duration, succeeded: bool },
}

/// Environment variable consulted at [`ConnectTransport::connect`] time for
/// an optional Bearer token — same name `mkit-transport-http` used
/// (`MKIT_API_TOKEN`), so switching a deployment from the retired JSON
/// dialect to this Connect client needs no operator-facing config change.
pub const TOKEN_ENV: &str = "MKIT_API_TOKEN";

/// Default timeout for cheap unary RPCs — `ListRefs`, `ReadRef`,
/// `UpdateRef`, `AdvanceRefs`, `PackExists`. These touch only ref/metadata
/// storage (no pack body on the wire), so a hung peer should fail fast
/// rather than tie up a caller for the multi-minute budget a pack transfer
/// needs. 20s is generous relative to any real ref-store round trip while
/// still bounding a stuck request to a duration a human retry loop can
/// tolerate; override via [`ConnectTransport::with_unary_timeout`] if a
/// deployment's ref store is reachable only over a slower path.
#[allow(clippy::duration_suboptimal_units)]
pub const UNARY_TIMEOUT: Duration = Duration::from_secs(20);

/// Default timeout for pack-transfer RPCs — `UploadPack`, `DownloadPack`.
/// Matches `mkit-transport-http::DEFAULT_TIMEOUT` — generous enough for a
/// large pack transfer over a slow link, bounded enough that a hung peer
/// can't wedge a caller indefinitely. Override via
/// [`ConnectTransport::with_pack_transfer_timeout`] for deployments moving
/// unusually large packs over unusually slow links.
#[allow(clippy::duration_suboptimal_units)]
pub const PACK_TRANSFER_TIMEOUT: Duration = Duration::from_secs(300);

/// Per-`UploadPack`-chunk data cap. Mirrors
/// `mkit_rpc::helpers::CHUNK_DATA_MAX` (the SSH/enc wire's per-frame pack
/// segment size) — not a shared constant because this crate deliberately
/// does not depend on `mkit-rpc` (a proto crate tied to the SSH wire), but
/// the value is kept in lockstep so pack chunking behaves identically
/// across every mkit transport.
const CHUNK_SIZE: usize = 800 * 1024;

/// Native ConnectRPC client for `mkit.transport.v1.TransportService` — the
/// implementation behind `mkit+https://` (SPEC-TRANSPORT-CONNECT).
///
/// Every `Transport` method is driven through the shared
/// [`mkit_core::protocol::retrying`] / [`BackoffIterator`] ladder — the same
/// driver `mkit-transport-http`/`-ssh`/`-enc` use (mkit#703) — so a
/// transient `ConnectionFailed` or 5xx/429-equivalent (`unavailable` /
/// `resource_exhausted`, see `crate::error::map_connect_error`) is
/// retried up to [`mkit_core::protocol::BACKOFF_MAX_ATTEMPTS`] times before
/// surfacing to the caller, instead of failing on the first attempt. Each
/// retry re-invokes the whole async call from scratch (a fresh request, and
/// for `download_pack`, a fresh stream), matching the shared driver's
/// contract that `op` must be self-contained per attempt. Mutating CAS ops
/// (`update_ref`/`advance_refs`) are safe to wrap unconditionally because
/// [`mkit_core::protocol::is_retryable`] already excludes
/// `TransportError::RefConflict` — a CAS conflict is never retried here;
/// retrying that is caller-level policy. A typed pending-verification reply
/// from `AdvanceRefs` uses a separate bounded polling loop around that ladder.
pub struct ConnectTransport {
    client: TransportServiceClient<EnvelopeTransport<HttpClient>>,
    executor: TokioExecutor,
    server_info: OnceLock<ServerInfoView>,
    repository: RepositoryIdentity,
    repository_text: String,
    origin: String,
    /// Per-call timeout applied to `ListRefs`/`ReadRef`/`UpdateRef`/
    /// `AdvanceRefs`/`PackExists`. See [`Self::with_unary_timeout`].
    unary_timeout: Duration,
    /// Per-call timeout applied to `UploadPack`/`DownloadPack`. See
    /// [`Self::with_pack_transfer_timeout`].
    pack_transfer_timeout: Duration,
    /// Retry-delay ladder factory. Production uses the spec ladder; tests
    /// inject a shorter ladder so retry assertions stay fast.
    backoff: fn() -> BackoffIterator,
    /// Sleep hook between retry attempts. Production sleeps for the full
    /// delay; tests inject a no-op or recorder.
    sleep: fn(Duration),
    now: fn() -> i64,
    pending_observer: Option<Arc<dyn Fn(PendingEvent) -> bool + Send + Sync>>,
}

// Manual Debug: `HttpClient` doesn't implement it, and a bearer token (if
// any) rides inside `client`'s `ClientConfig` default headers — never
// surface it via `{:?}`.
impl std::fmt::Debug for ConnectTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectTransport")
            .field("server_info", &self.server_info)
            .field("repository", &self.repository)
            .field("unary_timeout", &self.unary_timeout)
            .field("pack_transfer_timeout", &self.pack_transfer_timeout)
            .finish_non_exhaustive()
    }
}

/// Validate that `url` uses either `https://` (always allowed) or plain
/// `http://` pointing at a loopback host (`127.0.0.1`, `::1`, or
/// `localhost`). Mirrors `mkit-transport-http::validate_http_scheme` byte
/// for byte — both transports enforce the same "plaintext only to
/// loopback" policy (SPEC-TRANSPORT §3).
fn validate_http_scheme(url: &Url) -> TransportResult<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let ok = match url.host() {
                Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
                Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
                Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                None => false,
            };
            if ok {
                Ok(())
            } else {
                Err(TransportError::InsecureScheme)
            }
        }
        _ => Err(TransportError::InvalidResponse),
    }
}

/// Install a process-wide default `rustls` `CryptoProvider` if one isn't
/// already installed.
///
/// rustls 0.23 requires exactly one crypto backend to be the installed
/// default before `ClientConfig::builder()` can run; it does NOT
/// auto-select one when a consuming binary's dependency graph links more
/// than one backend crate (which `mkit-cli`'s does: `ring` arrives via
/// this crate's own explicit dependency below, `aws-lc-rs` via `rustls`'s
/// own default feature pulled in transitively by `connectrpc`/other
/// dependents) — calling `ClientConfig::builder()` in that situation
/// panics with "Could not automatically determine the process-level
/// CryptoProvider" rather than picking one silently. We therefore install
/// one explicitly. `install_default` returns `Err` if a provider (ours or
/// another crate's, e.g. an AWS SDK client's) is already installed
/// process-wide; either outcome is fine here — we only need SOME provider
/// installed before building a `ClientConfig`, not specifically ours.
fn ensure_crypto_provider() {
    let _ = connectrpc::rustls::crypto::ring::default_provider().install_default();
}

/// Build a default `rustls::ClientConfig` trusting the Mozilla root
/// program via `webpki-roots` — pure-Rust, no OS trust-store dependency
/// (portable across CI images and minimal containers, matching this
/// crate's zero-system-dependency posture for the vendored codegen path).
fn default_tls_config() -> Arc<connectrpc::rustls::ClientConfig> {
    ensure_crypto_provider();
    let mut roots = connectrpc::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        connectrpc::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

impl ConnectTransport {
    /// Parse `mkit+https://host/project` (or loopback-only
    /// `mkit+http://…`), strip the `mkit+` prefix, and build the transport.
    ///
    /// The token is sourced from `MKIT_API_TOKEN` at connect time (same
    /// variable `mkit-transport-http` reads). A missing variable is fine —
    /// public read endpoints remain accessible.
    ///
    /// RPCs use the fixed `/mkit.transport.v1.TransportService/<Method>`
    /// paths. The URL path is validated as a repository identity and sent
    /// as `X-Repository` on every RPC; an empty path names `default`.
    ///
    /// # Errors
    ///
    /// - [`TransportError::InvalidResponse`] — URL has no `mkit+` prefix,
    ///   is otherwise unparseable, uses a scheme other than `http`/`https`,
    ///   or its path, query or fragment is not a valid repository address;
    ///   [`repository_identity_from_url`] reports which.
    /// - [`TransportError::InsecureScheme`] — plain `http://` to a
    ///   non-loopback host.
    /// - [`TransportError::ConnectionFailed`] — the local tokio runtime
    ///   could not be constructed (resource exhaustion).
    pub fn connect(url: &str) -> TransportResult<Self> {
        Self::connect_with_signer(url, None)
    }

    /// Like [`Self::connect`], additionally signing every write RPC
    /// (`UpdateRef`, `AdvanceRefs`, `UploadPack`) with a write envelope
    /// (BLAKE3 digest + Ed25519 signature headers) when `signer` is
    /// `Some` — see the [`envelope`](crate::envelope) module. This is an
    /// ADDITIONAL auth mode alongside the bearer token read from
    /// [`TOKEN_ENV`]: a deployment can require either, both, or neither.
    /// `signer` is `None` behaves identically to [`Self::connect`] (reads
    /// and, on a server that doesn't require it, writes too, go out
    /// unsigned).
    ///
    /// # Errors
    ///
    /// Same as [`Self::connect`].
    pub fn connect_with_signer(
        url: &str,
        signer: Option<Arc<dyn EnvelopeSigner>>,
    ) -> TransportResult<Self> {
        let stripped = url
            .strip_prefix("mkit+")
            .ok_or(TransportError::InvalidResponse)?;
        let parsed = Url::parse(stripped).map_err(|_| TransportError::InvalidResponse)?;
        validate_http_scheme(&parsed)?;
        let repository =
            repository_identity_from_url(url).map_err(|_| TransportError::InvalidResponse)?;
        let origin = parsed.origin().ascii_serialization();

        // RPC routes are rooted at the origin; the identity travels in a header.
        let authority = format!(
            "{}://{}",
            parsed.scheme(),
            parsed
                .host_str()
                .map(|h| match parsed.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_owned(),
                })
                .ok_or(TransportError::InvalidResponse)?
        );
        let uri: Uri = authority
            .parse()
            .map_err(|_| TransportError::InvalidResponse)?;

        let token = env::var(TOKEN_ENV).ok().filter(|s| !s.is_empty());
        let transport = if parsed.scheme() == "https" {
            HttpClient::with_tls(default_tls_config())
        } else {
            HttpClient::plaintext()
        };
        let repository_text = repository.to_string();
        let transport =
            EnvelopeTransport::new(transport, signer, origin.clone(), repository_text.clone());

        // The underlying `ClientConfig` default is a defense-in-depth
        // fallback only: every RPC below sets an explicit per-call
        // [`CallOptions::with_timeout`] from `unary_timeout` /
        // `pack_transfer_timeout`, which always takes precedence (see
        // `connectrpc::client`'s `effective_options`). Seeded with the more
        // conservative (longer) `PACK_TRANSFER_TIMEOUT` so a future call
        // added here without an explicit per-call override fails safe
        // (generous, not premature) rather than the reverse.
        let mut config = ClientConfig::new(uri).with_default_timeout(PACK_TRANSFER_TIMEOUT);
        if let Some(token) = &token
            && let Ok(value) = http::HeaderValue::from_str(&format!("Bearer {token}"))
        {
            config = config.with_default_header(AUTHORIZATION, value);
        }

        let executor = TokioExecutor::new().map_err(|_| TransportError::ConnectionFailed)?;
        Ok(Self {
            client: TransportServiceClient::new(transport, config),
            executor,
            server_info: OnceLock::new(),
            repository,
            repository_text,
            origin,
            unary_timeout: UNARY_TIMEOUT,
            pack_transfer_timeout: PACK_TRANSFER_TIMEOUT,
            backoff: BackoffIterator::new,
            sleep: thread::sleep,
            now: crate::envelope::now_ms,
            pending_observer: None,
        })
    }

    /// Test-only constructor pointing at a plaintext base URI with no
    /// `mkit+` prefix stripping (mirrors
    /// `HttpTransport::new_for_test`) — used by the in-process
    /// integration test to target a locally bound server.
    #[doc(hidden)]
    #[must_use]
    pub fn connect_for_test(base_uri: Uri) -> Self {
        Self::connect_for_test_with_signer(base_uri, None)
    }

    /// Like [`Self::connect_for_test`], with an optional envelope signer —
    /// used by this crate's own envelope integration test.
    ///
    /// Uses a fast, no-sleep retry ladder (see [`test_backoff`]/[`no_sleep`])
    /// so existing happy-path integration tests aren't slowed down by the
    /// production 1s-32s ladder if a call happens to classify as retryable.
    #[doc(hidden)]
    #[must_use]
    pub fn connect_for_test_with_signer(
        base_uri: Uri,
        signer: Option<Arc<dyn EnvelopeSigner>>,
    ) -> Self {
        let audience = format!(
            "{}://{}",
            base_uri.scheme_str().unwrap_or("http"),
            base_uri.authority().expect("test authority")
        );
        let repository =
            repository_identity_from_url(&base_uri.to_string()).expect("test identity");
        let repository_text = repository.to_string();
        let config = ClientConfig::new(audience.parse().expect("test origin"))
            .with_default_timeout(Duration::from_secs(10));
        Self {
            client: TransportServiceClient::new(
                EnvelopeTransport::new(
                    HttpClient::plaintext(),
                    signer,
                    audience.clone(),
                    repository_text.clone(),
                ),
                config,
            ),
            executor: TokioExecutor::new().expect("tokio runtime for test transport"),
            server_info: OnceLock::new(),
            repository,
            repository_text,
            origin: audience,
            unary_timeout: UNARY_TIMEOUT,
            pack_transfer_timeout: PACK_TRANSFER_TIMEOUT,
            backoff: test_backoff,
            sleep: no_sleep,
            now: crate::envelope::now_ms,
            pending_observer: None,
        }
    }

    /// Like [`Self::connect_for_test_with_signer`], with explicit retry
    /// hooks — used by this crate's deterministic retry test to inject a
    /// short, fixed-attempt ladder and assert on the resulting attempt
    /// count.
    #[doc(hidden)]
    #[must_use]
    pub fn connect_for_test_with_retry(
        base_uri: Uri,
        backoff: fn() -> BackoffIterator,
        sleep: fn(Duration),
    ) -> Self {
        let mut transport = Self::connect_for_test_with_signer(base_uri, None);
        transport.backoff = backoff;
        transport.sleep = sleep;
        transport
    }

    /// Discover and cache deployment capabilities for this instance's lifetime.
    /// Legacy and failed discovery stay conservative, even if the server changes.
    pub fn server_info(&self) -> &ServerInfoView {
        self.server_info.get_or_init(|| {
            self.retrying(|| {
                self.executor.block_on(async {
                    match self
                        .client
                        .get_server_info_with_options(
                            GetServerInfoRequest::default(),
                            CallOptions::default().with_timeout(self.unary_timeout),
                        )
                        .await
                    {
                        Ok(response) => {
                            let info = response.into_owned();
                            Ok(if valid_server_info(&info) {
                                ServerInfoView::V2(Box::new(info))
                            } else {
                                ServerInfoView::Unknown
                            })
                        }
                        Err(e) if e.code == connectrpc::ErrorCode::Unimplemented => {
                            Ok(ServerInfoView::Legacy)
                        }
                        Err(e) => Err(map_connect_error(e, ErrorContext::Ref)),
                    }
                })
            })
            .unwrap_or(ServerInfoView::Unknown)
        })
    }

    /// Override the per-call timeout applied to cheap unary RPCs
    /// (`ListRefs`, `ReadRef`, `UpdateRef`, `AdvanceRefs`, `PackExists`).
    /// Defaults to [`UNARY_TIMEOUT`]. Independent of
    /// [`Self::with_pack_transfer_timeout`] — changing one does not affect
    /// the other.
    #[must_use]
    pub fn with_unary_timeout(mut self, timeout: Duration) -> Self {
        self.unary_timeout = timeout;
        self
    }

    /// Override the per-call timeout applied to pack-transfer RPCs
    /// (`UploadPack`, `DownloadPack`). Defaults to
    /// [`PACK_TRANSFER_TIMEOUT`]. Independent of
    /// [`Self::with_unary_timeout`] — changing one does not affect the
    /// other.
    #[must_use]
    pub fn with_pack_transfer_timeout(mut self, timeout: Duration) -> Self {
        self.pack_transfer_timeout = timeout;
        self
    }

    /// Observe pending verification waits and completion. A `false` return
    /// from a waiting event cancels polling before the next sleep slice.
    #[must_use]
    pub fn with_pending_observer(
        mut self,
        observer: impl Fn(PendingEvent) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.pending_observer = Some(Arc::new(observer));
        self
    }

    /// Inject a clock for deterministic polling tests.
    #[doc(hidden)]
    #[must_use]
    pub fn with_clock_for_test(mut self, now: fn() -> i64) -> Self {
        self.now = now;
        self
    }

    /// Inject retry and poll sleep hooks for deterministic client tests.
    #[doc(hidden)]
    #[must_use]
    pub fn with_retry_hooks_for_test(
        mut self,
        backoff: fn() -> BackoffIterator,
        sleep: fn(Duration),
    ) -> Self {
        self.backoff = backoff;
        self.sleep = sleep;
        self
    }

    fn pending_finished(&self, start_ms: i64, succeeded: bool) {
        if let Some(observer) = &self.pending_observer {
            observer(PendingEvent::Finished {
                elapsed: Duration::from_millis(
                    u64::try_from((self.now)().saturating_sub(start_ms)).unwrap_or(0),
                ),
                succeeded,
            });
        }
    }

    /// Poll a ticket-consuming advance until it commits or `deadline` expires.
    /// WP-1.17 passes the earliest consumed ticket expiry here. Until then,
    /// the maximum seven-day ticket lifetime bounds calls with no deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn advance_refs_with_deadline(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
        deadline: Option<i64>,
    ) -> TransportResult<CoreAdvanceOutcome> {
        let (head_expectation, head_expected_id) = condition_to_wire(head_condition);
        let (packmap_expectation, packmap_expected_id) = condition_to_wire(packmap_condition);
        let start_ms = (self.now)();
        let deadline = deadline.unwrap_or_else(|| start_ms.saturating_add(MAX_PENDING_MS));
        let margin_ms = i64::try_from(self.unary_timeout.as_millis())
            .unwrap_or(i64::MAX)
            .max(MIN_RENEWAL_MARGIN_MS);
        let mut identity = RetryIdentity::new_at(start_ms).map_err(TransportError::RemoteError)?;
        let mut saw_pending = false;
        let mut waiting_since_ms = start_ms;
        let mut renewed_after_unauthenticated = false;

        loop {
            let poll = self.retrying(|| {
                loop {
                    let now = (self.now)();
                    if now >= deadline {
                        return Err(TransportError::RemoteError(
                            "pending verification ticket deadline expired".to_owned(),
                        ));
                    }
                    if identity.expires_at_ms.saturating_sub(now) < margin_ms {
                        identity =
                            RetryIdentity::new_at(now).map_err(TransportError::RemoteError)?;
                    }
                    let options =
                        identity.apply(CallOptions::default().with_timeout(self.unary_timeout));
                    let response = self
                        .executor
                        .block_on(self.client.advance_refs_with_options(
                            AdvanceRefsRequest {
                                head_ref: Some(head_ref.to_owned()),
                                head_expectation: Some(head_expectation.into()),
                                head_expected_id: head_expected_id.clone(),
                                head_new_id: Some(head_value.to_vec()),
                                packmap_ref: Some(packmap_ref.to_owned()),
                                packmap_expectation: Some(packmap_expectation.into()),
                                packmap_expected_id: packmap_expected_id.clone(),
                                packmap_new_id: Some(packmap_value.to_vec()),
                                ..Default::default()
                            },
                            options,
                        ));
                    match response {
                        Ok(resp) => {
                            let resp = resp.into_owned();
                            let outcome = match resp.outcome.and_then(|o| o.as_known()) {
                                Some(ProtoAdvanceOutcome::Committed) => {
                                    CoreAdvanceOutcome::Committed
                                }
                                Some(ProtoAdvanceOutcome::HeadConflict) => {
                                    CoreAdvanceOutcome::HeadConflict
                                }
                                Some(ProtoAdvanceOutcome::PackmapConflict) => {
                                    CoreAdvanceOutcome::PackmapConflict
                                }
                                _ => return Err(TransportError::InvalidResponse),
                            };
                            return Ok(Ok(outcome));
                        }
                        Err(err) => {
                            if let Some(delay) = pending_verification_delay(&err) {
                                return Ok(Err(delay));
                            }
                            if saw_pending
                                && !renewed_after_unauthenticated
                                && err.code == connectrpc::ErrorCode::Unauthenticated
                            {
                                renewed_after_unauthenticated = true;
                                identity = RetryIdentity::new_at((self.now)())
                                    .map_err(TransportError::RemoteError)?;
                                continue;
                            }
                            return Err(map_connect_error(err, ErrorContext::Ref));
                        }
                    }
                }
            });
            let delay = match poll {
                Ok(Ok(outcome)) => {
                    if saw_pending {
                        self.pending_finished(waiting_since_ms, true);
                    }
                    return Ok(outcome);
                }
                Ok(Err(delay)) => {
                    if !saw_pending {
                        waiting_since_ms = (self.now)();
                    }
                    saw_pending = true;
                    delay
                }
                Err(error) => {
                    if saw_pending {
                        self.pending_finished(waiting_since_ms, false);
                    }
                    return Err(error);
                }
            };
            let mut remaining = delay;
            while !remaining.is_zero() {
                let now = (self.now)();
                if now >= deadline {
                    self.pending_finished(waiting_since_ms, false);
                    return Err(TransportError::RemoteError(
                        "pending verification ticket deadline expired".to_owned(),
                    ));
                }
                let until_deadline =
                    Duration::from_millis(u64::try_from(deadline.saturating_sub(now)).unwrap_or(0));
                let slice = remaining.min(Duration::from_secs(1)).min(until_deadline);
                if let Some(observer) = &self.pending_observer
                    && !observer(PendingEvent::Waiting {
                        elapsed: Duration::from_millis(
                            u64::try_from(now.saturating_sub(waiting_since_ms)).unwrap_or(0),
                        ),
                        next: slice,
                    })
                {
                    self.pending_finished(waiting_since_ms, false);
                    return Err(TransportError::RemoteError(
                        PENDING_INTERRUPTED_MESSAGE.to_owned(),
                    ));
                }
                (self.sleep)(slice);
                remaining -= slice;
            }
        }
    }

    fn download_pack_with_hint(
        &self,
        key: &PackKey,
        ref_name: Option<&str>,
    ) -> TransportResult<Vec<u8>> {
        // `block_on_local`, not `block_on`: see its doc comment — the
        // server-streaming `.message()` read here hits a rustc HRTB/GAT
        // limitation against the `Send`-bound trait method, not an actual
        // thread-safety issue.
        //
        // The whole stream (request through final chunk) is re-issued from
        // scratch on every retry attempt — a partially-read stream from a
        // failed prior attempt is never resumed.
        self.retrying(|| {
            self.executor.block_on_local(async {
                let options = ref_hint(
                    CallOptions::default().with_timeout(self.pack_transfer_timeout),
                    ref_name,
                );
                let mut stream = self
                    .client
                    .download_pack_with_options(
                        DownloadPackRequest {
                            pack_id: Some(key.as_bytes().to_vec()),
                            ..Default::default()
                        },
                        options,
                    )
                    .await
                    .map_err(|e| map_connect_error(e, ErrorContext::Ref))?;

                let first = stream
                    .message()
                    .await
                    .map_err(|e| map_connect_error(e, ErrorContext::Ref))?
                    .ok_or(TransportError::InvalidResponse)?;
                let total_bytes = match first.to_owned_message().body {
                    Some(DownloadBody::Header(h)) => h.total_bytes.unwrap_or(0),
                    _ => return Err(TransportError::InvalidResponse),
                };
                if total_bytes > PACK_BODY_LIMIT {
                    return Err(TransportError::PayloadTooLarge(
                        usize::try_from(total_bytes).unwrap_or(usize::MAX),
                    ));
                }

                let mut buf: Vec<u8> = Vec::with_capacity(
                    usize::try_from(total_bytes).unwrap_or(PACK_BODY_LIMIT_USIZE),
                );
                loop {
                    let next = stream
                        .message()
                        .await
                        .map_err(|e| map_connect_error(e, ErrorContext::Ref))?
                        .ok_or(TransportError::InvalidResponse)?;
                    match next.to_owned_message().body {
                        Some(DownloadBody::Chunk(c)) => {
                            let offset = c.offset.unwrap_or(0);
                            if offset != buf.len() as u64 {
                                return Err(TransportError::InvalidResponse);
                            }
                            let data = c.data.unwrap_or_default();
                            if buf.len().saturating_add(data.len()) > PACK_BODY_LIMIT_USIZE {
                                return Err(TransportError::PayloadTooLarge(
                                    buf.len() + data.len(),
                                ));
                            }
                            buf.extend_from_slice(&data);
                            if c.last.unwrap_or(false) {
                                break;
                            }
                        }
                        _ => return Err(TransportError::InvalidResponse),
                    }
                }
                if buf.len() as u64 != total_bytes {
                    return Err(TransportError::InvalidResponse);
                }
                Ok(buf)
            })
        })
    }

    fn pack_exists_with_hint(
        &self,
        key: &PackKey,
        ref_name: Option<&str>,
    ) -> TransportResult<bool> {
        self.retrying(|| {
            self.executor.block_on(async {
                let options = ref_hint(
                    CallOptions::default().with_timeout(self.unary_timeout),
                    ref_name,
                );
                let response = self
                    .client
                    .pack_exists_with_options(
                        PackExistsRequest {
                            pack_id: Some(key.as_bytes().to_vec()),
                            ..Default::default()
                        },
                        options,
                    )
                    .await
                    .map_err(|e| map_connect_error(e, ErrorContext::Ref));
                match response {
                    Ok(resp) => Ok(resp.into_owned().exists.unwrap_or(false)),
                    Err(TransportError::PackNotFound) => Ok(false),
                    Err(e) => Err(e),
                }
            })
        })
    }

    /// Drive `op` through the standard 5-attempt backoff ladder shared by
    /// every `mkit` transport. `op` is re-invoked from scratch on every
    /// attempt — every `Transport` method below builds and sends its
    /// request(s) *inside* the closure passed here (a fresh RPC call, or
    /// for `download_pack`, a fresh stream) rather than assuming any state
    /// from a failed prior attempt is still valid.
    ///
    /// Thin wrapper over the transport-agnostic
    /// [`mkit_core::protocol::retrying`] — mirrors
    /// `HttpTransport::retrying`/`SshTransport::retrying`/`EncTransport::
    /// retrying`'s shape byte for byte, adapted to this transport's
    /// `TransportResult<T>`-returning async calls instead of an HTTP
    /// `Response`.
    fn retrying<T>(&self, op: impl FnMut() -> TransportResult<T>) -> TransportResult<T> {
        mkit_core::protocol::retrying(op, self.backoff, self.sleep)
    }
}

/// Short, deterministic retry ladder for tests: 5 attempts, 1ms apart,
/// capped at 1ms. Mirrors `mkit-transport-http`'s `test_backoff`.
fn test_backoff() -> BackoffIterator {
    BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 5)
}

/// No-op sleep hook for tests — retry assertions run at full speed.
fn no_sleep(_delay: Duration) {}

fn bytes_to_hash(bytes: &[u8]) -> TransportResult<Hash> {
    <[u8; 32]>::try_from(bytes).map_err(|_| TransportError::InvalidResponse)
}

/// Encode a [`RefWriteCondition`] into the wire `(expectation, expected_id)`
/// pair. Shared by every CAS-carrying request this client builds.
fn condition_to_wire(c: RefWriteCondition) -> (RefExpectation, Option<Vec<u8>>) {
    match c {
        RefWriteCondition::Any => (RefExpectation::Any, None),
        RefWriteCondition::Missing => (RefExpectation::Missing, None),
        RefWriteCondition::Match(h) => (RefExpectation::Match, Some(h.to_vec())),
    }
}

/// Build the `UploadPackRequest` stream for one pack: one `header` message
/// followed by `ceil(len / CHUNK_SIZE)` `chunk` messages (or exactly one
/// empty `last = true` chunk for a zero-byte pack), matching
/// SPEC-TRANSPORT-CONNECT §6.1.
fn build_upload_requests(bytes: &[u8], key: &PackKey) -> Vec<UploadPackRequest> {
    let pack_id = key.as_bytes().to_vec();
    let mut requests = Vec::with_capacity(2 + bytes.len() / CHUNK_SIZE);
    requests.push(UploadPackRequest {
        body: Some(
            UploadPackHeader {
                pack_id: Some(pack_id.clone()),
                total_bytes: Some(bytes.len() as u64),
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    });

    if bytes.is_empty() {
        requests.push(UploadPackRequest {
            body: Some(
                PackChunk {
                    pack_id: Some(pack_id),
                    offset: Some(0),
                    data: Some(Vec::new()),
                    last: Some(true),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        });
        return requests;
    }

    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = (offset + CHUNK_SIZE).min(bytes.len());
        let last = end == bytes.len();
        requests.push(UploadPackRequest {
            body: Some(
                PackChunk {
                    pack_id: Some(pack_id.clone()),
                    #[allow(clippy::cast_possible_truncation)]
                    offset: Some(offset as u64),
                    data: Some(bytes[offset..end].to_vec()),
                    last: Some(last),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        });
        offset = end;
    }
    requests
}

impl Transport for ConnectTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        if bytes.len() as u64 > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(bytes.len()));
        }
        let requests = build_upload_requests(bytes, key);
        let identity = RetryIdentity::new().map_err(TransportError::RemoteError)?;
        self.retrying(|| {
            self.executor.block_on(async {
                let options = identity
                    .apply(CallOptions::default().with_timeout(self.pack_transfer_timeout))
                    .with_header(
                        "x-content-commitment",
                        format!(
                            "pack:{}:{}",
                            mkit_core::hash::to_hex(key.as_bytes()),
                            bytes.len()
                        ),
                    );
                self.client
                    .upload_pack_with_options(connectrpc::stream_iter(requests.clone()), options)
                    .await
                    .map(|_| ())
                    .map_err(|e| map_connect_error(e, ErrorContext::Upload))
            })
        })
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.download_pack_with_hint(key, None)
    }

    fn download_pack_via_ref(&self, key: &PackKey, ref_name: &str) -> TransportResult<Vec<u8>> {
        self.download_pack_with_hint(key, Some(ref_name))
    }

    fn download_blob_via_ref(&self, key: &PackKey, ref_name: &str) -> TransportResult<Vec<u8>> {
        self.download_pack_via_ref(key, ref_name)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.pack_exists_with_hint(key, None)
    }

    fn pack_exists_via_ref(&self, key: &PackKey, ref_name: &str) -> TransportResult<bool> {
        self.pack_exists_with_hint(key, Some(ref_name))
    }

    fn repository_address(&self) -> Option<RepositoryAddress<'_>> {
        Some(RepositoryAddress::new(&self.repository_text, &self.origin))
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        let (expectation, expected_id) = condition_to_wire(condition);
        let identity = RetryIdentity::new().map_err(TransportError::RemoteError)?;
        self.retrying(|| {
            self.executor.block_on(async {
                let options =
                    identity.apply(CallOptions::default().with_timeout(self.unary_timeout));
                self.client
                    .update_ref_with_options(
                        UpdateRefRequest {
                            name: Some(name.to_owned()),
                            expectation: Some(expectation.into()),
                            expected_id: expected_id.clone(),
                            new_id: Some(hash.to_vec()),
                            ..Default::default()
                        },
                        options,
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| map_connect_error(e, ErrorContext::Ref))
            })
        })
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.retrying(|| {
            self.executor.block_on(async {
                let options = CallOptions::default().with_timeout(self.unary_timeout);
                let response = self
                    .client
                    .read_ref_with_options(
                        ReadRefRequest {
                            name: Some(name.to_owned()),
                            ..Default::default()
                        },
                        options,
                    )
                    .await
                    .map_err(|e| map_connect_error(e, ErrorContext::Ref));
                let resp = match response {
                    Ok(resp) => resp.into_owned(),
                    Err(TransportError::PackNotFound) => return Ok(None),
                    Err(e) => return Err(e),
                };
                if resp.exists.unwrap_or(false) {
                    let id = resp.object_id.ok_or(TransportError::InvalidResponse)?;
                    Ok(Some(bytes_to_hash(&id)?))
                } else {
                    Ok(None)
                }
            })
        })
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        let mut refs: Vec<Ref> = Vec::new();
        let mut page_token = None;
        let mut seen_tokens = std::collections::HashSet::new();
        let mut listed_bytes = 0usize;
        for _ in 0..MAX_LIST_REFS_PAGES {
            let response = self.retrying(|| {
                self.executor.block_on(async {
                    self.client
                        .list_refs_with_options(
                            ListRefsRequest {
                                prefix: Some(prefix.to_owned()),
                                page_token: page_token.clone(),
                                // The server chooses its configured page cap (R-105).
                                ..Default::default()
                            },
                            CallOptions::default().with_timeout(self.unary_timeout),
                        )
                        .await
                        .map(|r| r.into_owned())
                        .map_err(|e| map_connect_error(e, ErrorContext::Ref))
                })
            })?;
            let page: Vec<Ref> = response
                .refs
                .into_iter()
                .map(|entry| {
                    Ok(Ref {
                        name: entry.name.ok_or(TransportError::InvalidResponse)?,
                        hash: Some(bytes_to_hash(
                            &entry.object_id.ok_or(TransportError::InvalidResponse)?,
                        )?),
                    })
                })
                .collect::<TransportResult<_>>()?;
            if let (Some(last), Some(first)) = (refs.last(), page.first())
                && first.name <= last.name
            {
                return Err(TransportError::InvalidResponse);
            }
            if page.windows(2).any(|pair| pair[0].name >= pair[1].name) {
                return Err(TransportError::InvalidResponse);
            }
            listed_bytes = page.iter().fold(listed_bytes, |acc, r| {
                acc.saturating_add(r.name.len()).saturating_add(32)
            });
            if listed_bytes > MAX_LIST_REFS_BYTES {
                return Err(TransportError::InvalidResponse);
            }
            refs.extend(page);
            let Some(next) = response.next_page_token.filter(|token| !token.is_empty()) else {
                return Ok(refs);
            };
            // Any repeated cursor, not only the previous one, is a cycle.
            if !seen_tokens.insert(next.clone()) {
                return Err(TransportError::InvalidResponse);
            }
            page_token = Some(next);
        }
        Err(TransportError::InvalidResponse)
    }

    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<CoreAdvanceOutcome> {
        self.advance_refs_with_deadline(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
            None,
        )
    }

    fn supports_atomic_advance(&self) -> bool {
        matches!(self.server_info(), ServerInfoView::V2(info) if info.atomic_advance == Some(true))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- connect() + URL parsing --------------------------------------

    #[test]
    fn connect_rejects_missing_mkit_prefix() {
        let err = ConnectTransport::connect("https://example.com/proj").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    #[test]
    fn connect_rejects_unknown_scheme() {
        let err = ConnectTransport::connect("mkit+ftp://example.com/proj").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    #[test]
    fn connect_rejects_plain_http_to_non_loopback_host() {
        let err = ConnectTransport::connect("mkit+http://example.com/proj").unwrap_err();
        assert!(matches!(err, TransportError::InsecureScheme));
    }

    #[test]
    fn connect_accepts_plain_http_for_loopback() {
        let t = ConnectTransport::connect("mkit+http://127.0.0.1:9/proj").unwrap();
        assert!(t.server_info.get().is_none());
    }

    #[test]
    fn connect_accepts_https_and_does_not_panic_building_tls_config() {
        // Regression test: rustls 0.23 panics building a `ClientConfig` if
        // no crypto provider is installed and more than one backend
        // feature is linked in the process (mkit#701) — this exercises
        // exactly that path. Construction does not make a network call.
        let t = ConnectTransport::connect("mkit+https://example.invalid/proj").unwrap();
        assert!(t.server_info.get().is_none());
    }

    #[test]
    fn connect_strips_url_path_from_the_connect_base_uri() {
        // SPEC-TRANSPORT-CONNECT §2: every RPC resolves to the FIXED path
        // `/mkit.transport.v1.TransportService/<Method>` — a `/project`
        // path segment on the `mkit+https://` URL must NOT become a
        // prefix on the Connect base URI (mkit#701 regression: an earlier
        // version of this code folded the path in, breaking every call
        // against a server mounted at the standard root path).
        let t = ConnectTransport::connect("mkit+https://example.invalid/myproj").unwrap();
        assert_eq!(
            t.client.config().base_uri().to_string(),
            "https://example.invalid/"
        );
    }

    #[test]
    fn test_constructor_routes_at_origin_and_keeps_identity() {
        let t = ConnectTransport::connect_for_test("http://127.0.0.1:9/myproj".parse().unwrap());
        assert_eq!(
            t.client.config().base_uri().to_string(),
            "http://127.0.0.1:9/"
        );
        assert_eq!(
            t.repository_address(),
            Some(RepositoryAddress::new("myproj", "http://127.0.0.1:9"))
        );
    }

    #[test]
    fn url_identity_table_preserves_literal_paths() {
        let ns = format!("ed25519-{}", "ab".repeat(32));
        for (path, expected) in [
            ("".to_owned(), "default".to_owned()),
            ("/".into(), "default".into()),
            ("/myproj".into(), "myproj".into()),
            (format!("/{ns}/name"), format!("{ns}/name")),
            (format!("/{ns}/name/"), format!("{ns}/name")),
            (
                format!("/0x{}/{}", "cd".repeat(20), "n".repeat(100)),
                format!("0x{}/{}", "cd".repeat(20), "n".repeat(100)),
            ),
            (
                format!("/{ns}/{}", "a".repeat(100)),
                format!("{ns}/{}", "a".repeat(100)),
            ),
        ] {
            let url = format!("mkit+https://example.invalid{path}");
            assert_eq!(
                repository_identity_from_url(&url).unwrap().to_string(),
                expected
            );
        }
        for path in [
            "/ns/name".to_owned(),
            "/Upper".into(),
            "/a%62".into(),
            format!("/{ns}//name"),
            "/name?q=1".into(),
            "/name#frag".into(),
            format!("/{ns}/{}", "a".repeat(101)),
            "/a/../name".into(),
            "/a\\name".into(),
            "/a/%2e%2e/name".into(),
        ] {
            let url = format!("mkit+https://example.invalid{path}");
            assert!(repository_identity_from_url(&url).is_err(), "{url}");
            assert!(matches!(
                ConnectTransport::connect(&url),
                Err(TransportError::InvalidResponse)
            ));
        }
        assert!(repository_identity_from_url("not a url").is_err());
        // Extra or missing slashes after the scheme move the path under WHATWG
        // parsing; the literal spelling is refused instead of reinterpreted.
        for url in [
            "mkit+http:///localhost/",
            "mkit+https:///myproj",
            "mkit+https:/host/x://y",
        ] {
            assert!(
                matches!(
                    repository_identity_from_url(url),
                    Err(UrlIdentityError::NonLiteralPath)
                ),
                "{url}"
            );
        }
        assert!(
            repository_identity_from_url(&format!("mkit+https:/0x{}/name", "cd".repeat(20)))
                .is_err()
        );
        assert_eq!(
            repository_identity_from_url("mkit+https://example.invalid/name?#")
                .unwrap()
                .name(),
            "name"
        );
    }

    // -- per-verb-class timeouts (mkit#798) ------------------------------

    #[test]
    fn timeouts_default_to_the_named_constants() {
        let t = ConnectTransport::connect("mkit+http://127.0.0.1:9/proj").unwrap();
        assert_eq!(t.unary_timeout, UNARY_TIMEOUT);
        assert_eq!(t.pack_transfer_timeout, PACK_TRANSFER_TIMEOUT);
        assert!(
            t.unary_timeout < t.pack_transfer_timeout,
            "the unary class must default shorter than the pack-transfer class"
        );
    }

    #[test]
    fn with_unary_timeout_and_with_pack_transfer_timeout_override_independently() {
        let t = ConnectTransport::connect("mkit+http://127.0.0.1:9/proj")
            .unwrap()
            .with_unary_timeout(Duration::from_millis(5))
            .with_pack_transfer_timeout(Duration::from_secs(600));
        assert_eq!(t.unary_timeout, Duration::from_millis(5));
        assert_eq!(t.pack_transfer_timeout, Duration::from_secs(600));
    }

    // -- condition_to_wire() --------------------------------------------

    #[test]
    fn condition_to_wire_any_has_no_expected_id() {
        let (exp, id) = condition_to_wire(RefWriteCondition::Any);
        assert_eq!(exp, RefExpectation::Any);
        assert_eq!(id, None);
    }

    #[test]
    fn condition_to_wire_missing_has_no_expected_id() {
        let (exp, id) = condition_to_wire(RefWriteCondition::Missing);
        assert_eq!(exp, RefExpectation::Missing);
        assert_eq!(id, None);
    }

    #[test]
    fn condition_to_wire_match_carries_the_hash() {
        let h = [0x42u8; 32];
        let (exp, id) = condition_to_wire(RefWriteCondition::Match(h));
        assert_eq!(exp, RefExpectation::Match);
        assert_eq!(id, Some(h.to_vec()));
    }

    // -- build_upload_requests() -----------------------------------------

    #[test]
    fn build_upload_requests_empty_pack_is_header_plus_one_empty_last_chunk() {
        let key = PackKey::new([0x11u8; 32]);
        let reqs = build_upload_requests(b"", &key);
        assert_eq!(reqs.len(), 2, "header + one empty last=true chunk");
    }

    #[test]
    fn build_upload_requests_chunks_at_chunk_size_boundary() {
        let key = PackKey::new([0x22u8; 32]);
        let data = vec![0u8; CHUNK_SIZE * 2 + 1];
        let reqs = build_upload_requests(&data, &key);
        // 1 header + 3 chunks (CHUNK_SIZE, CHUNK_SIZE, 1 byte).
        assert_eq!(reqs.len(), 4);
    }
}
