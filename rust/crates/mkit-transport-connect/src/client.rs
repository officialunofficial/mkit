//! [`ConnectTransport`] — the native `mkit.transport.v1.TransportService`
//! ConnectRPC client, implementing [`Transport`] for the `mkit+https://`
//! (and loopback-only `mkit+http://`) remote scheme.

use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use connectrpc::client::{CallOptions, ClientConfig};
use http::header::AUTHORIZATION;
use http::{HeaderMap, Uri};
use mkit_core::hash::Hash;
use mkit_core::protocol::async_shim::Executor as _;
use mkit_core::protocol::{
    AdvanceOutcome as CoreAdvanceOutcome, BackoffIterator, CommitOutcome, PACK_BODY_LIMIT,
    PACK_BODY_LIMIT_USIZE, PackKey, RefWriteCondition, RepositoryAddress, Transport,
    TransportError, TransportResult, UploadLimits,
};
use mkit_core::refs::{Ref, validate_ref_name};
use mkit_core::repo_identity::{IdentityError, RepositoryIdentity};
use mkit_core::upload_parts::{PartError, PartPlan, part_subtree_cv};
use mkit_core::write_auth::{ContentCommitment, PartCommitment};
use url::{Host, Url};

use crate::admission::{AdmissionPolicy, respond_to_challenge, retry_once};
use crate::envelope::{EnvelopeSigner, EnvelopeTransport, RetryIdentity};
use crate::error::{
    ErrorContext, map_connect_error, pending_retry_after, pending_verification_delay,
};
use crate::executor::TokioExecutor;
use crate::grant::{GrantCondition, GrantOperation, GrantRef, GrantRequest, GrantSource};
use crate::part_receipts::{MemoryPartReceiptStore, PartReceiptStore, StoredPart, TicketMetadata};
use crate::pooled_http::PooledHttpClient as HttpClient;
use crate::proto::mkit::transport::v1::__buffa::oneof::begin_upload_response::Result as BeginWireResult;
use crate::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use crate::proto::mkit::transport::v1::upload_part_request::Msg as PartWireMessage;
use crate::proto::mkit::transport::v1::{
    AdvanceOutcome as ProtoAdvanceOutcome, AdvanceRefsRequest, BeginUploadRequest,
    CompleteUploadRequest, DownloadPackRequest, GetGrantEpochRequest, GetServerInfoRequest,
    GetServerInfoResponse, ListRefsRequest, PackChunk, PackExistsRequest, ReadRefRequest,
    RefExpectation, RepoVisibility, SetGrantEpochRequest, SetRepoVisibilityRequest,
    TransportServiceClient, UpdateRefRequest, UploadPackHeader, UploadPackRequest,
    UploadPartHeader, UploadPartRequest, set_repo_visibility_request::Mode as VisibilityWireMode,
};
use crate::receipt::{AdmissionReceipt, observe_receipts};
use crate::status::StatusTransport;

/// The auth v2 audience of a `mkit+https://` / `mkit+http://` URL: its
/// origin, exactly as [`ConnectTransport`] signs requests for it. `None` for
/// a URL [`ConnectTransport::connect`] would refuse.
#[must_use]
pub fn audience_from_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url.strip_prefix("mkit+")?).ok()?;
    validate_http_scheme(&parsed).ok()?;
    Some(parsed.origin().ascii_serialization())
}

/// The outcome of a grant-epoch or visibility RPC (SPEC-WRITE-GRANTS §5.3,
/// §9.1). Revocation and a change to private are not complete until every
/// copy of the old state is gone, so the server answers `unavailable` with a
/// `Retry-After` until then. That is not an error: the caller sends the same
/// request again after `retry_after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion<T> {
    /// The server finished and answered.
    Done(T),
    /// Still completing. `retry_after` is the server's `Retry-After`
    /// (delay-seconds only), clamped to 1–60 s; missing or garbage is 1 s.
    Pending { retry_after: Duration },
}

/// A repository visibility (SPEC-WRITE-GRANTS §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityChoice {
    Public,
    Private,
}

/// The two modes of `SetRepoVisibility` (SPEC-WRITE-GRANTS §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityRequest<'a> {
    /// A signed auth v2 write by the repository owner. Needs an envelope
    /// signer on the transport; a grant never authorizes it.
    Envelope(VisibilityChoice),
    /// An owner-signed `mkit-repo-visibility:v1` statement in the §4.2
    /// encoding. Sent with no auth v2 envelope, and with `X-Repository`.
    Statement(&'a str),
}

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
        && info.max_parts.is_some_and(|v| v >= 1)
}

#[derive(Clone)]
struct CachedTicket {
    id: [u8; 32],
    token: Vec<u8>,
    part_size: u64,
    expires_unix_ms: i64,
}

impl std::fmt::Debug for CachedTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedTicket")
            .field("id", &self.id)
            .field("part_size", &self.part_size)
            .field("expires_unix_ms", &self.expires_unix_ms)
            .finish_non_exhaustive()
    }
}

enum BeginAnswer {
    AlreadyPresent,
    Ticket(CachedTicket),
    Ticketless,
}

enum BeginSpecial {
    Unimplemented,
    OpenCap,
    Rejected(String),
}

enum CompleteSpecial {
    Ticket,
    InvalidReceipt,
}

fn log_receipt_cleanup_error(action: &str, error: &TransportError) {
    log::warn!("upload receipt cache {action} failed: {error}");
}

fn upload_interrupted(saved: u32, total: u32) -> TransportError {
    TransportError::RemoteError(format!(
        "upload interrupted; {saved} of {total} parts saved, run `mkit push` again to resume"
    ))
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
#[non_exhaustive]
pub enum PendingEvent {
    /// Emitted before each sleep slice. Returning `false` stops polling.
    Waiting { elapsed: Duration, next: Duration },
    /// Emitted after polling ends, so progress UIs can finish their line.
    Finished { elapsed: Duration, succeeded: bool },
}

/// Progress for one multipart pack upload.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum UploadEvent {
    PartsPlanned {
        parts: u32,
        resumed: u32,
        saved_bytes: u64,
        bytes: u64,
    },
    PartSent {
        index: u32,
        parts: u32,
        saved_bytes: u64,
        bytes: u64,
        resumed: u32,
    },
    /// Cancellation check before a part begins; progress UIs can ignore it.
    BeforePart,
    Completing,
    Finished,
}

fn advance_deadline_error(saw_pending: bool) -> TransportError {
    let message = if saw_pending {
        "pending verification ticket deadline expired"
    } else {
        "advance deadline expired"
    };
    TransportError::RemoteError(message.to_owned())
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
/// needs. Cold indexed advances can scan denial metadata before committing.
/// The 30s caller default gives that bounded proof work more time without
/// changing the server's proof validity or physical request budgets. A stuck
/// unary request still fails independently of the pack-transfer deadline;
/// override via [`ConnectTransport::with_unary_timeout`] for a slower path.
#[allow(clippy::duration_suboptimal_units)]
pub const UNARY_TIMEOUT: Duration = Duration::from_secs(30);

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
    client: TransportServiceClient<EnvelopeTransport<StatusTransport<HttpClient>>>,
    executor: TokioExecutor,
    server_info: OnceLock<ServerInfoView>,
    repository: RepositoryIdentity,
    repository_text: String,
    origin: String,
    signer_key: Option<String>,
    grant_source: Option<Arc<dyn GrantSource>>,
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
    tickets: Mutex<HashMap<(String, PackKey), CachedTicket>>,
    unknown_ticketless: AtomicBool,
    receipts: Arc<dyn PartReceiptStore>,
    receipts_swept: AtomicBool,
    upload_observer: Option<Arc<dyn Fn(UploadEvent) -> bool + Send + Sync>>,
    receipt_observer: Option<crate::receipt::ReceiptObserver>,
    admission_policy: Option<AdmissionPolicy>,
    admission_runs: AtomicUsize,
    bearer: bool,
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
    /// - [`TransportError::TlsConfiguration`] — a selected HTTPS CA file
    ///   could not be read or validated.
    /// - [`TransportError::ConnectionFailed`] — the local tokio runtime
    ///   could not be constructed (resource exhaustion).
    pub fn connect(url: &str) -> TransportResult<Self> {
        Self::connect_with_signer(url, None)
    }

    /// Like [`Self::connect`], additionally signing repository reads and writes
    /// with an auth v2 envelope
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
        Self::connect_with_signer_and_ca_file(url, signer, None)
    }

    /// Construct a native client with an optional extra PEM trust file.
    /// `MKIT_SSL_CA_FILE` takes precedence over `ca_file`. Certificates add to
    /// the Mozilla roots; chain and hostname verification remain enabled.
    /// The same HTTP client serves every unary and streaming RPC.
    /// # Errors
    /// The errors from [`Self::connect`], plus invalid HTTPS trust configuration.
    pub fn connect_with_signer_and_ca_file(
        url: &str,
        signer: Option<Arc<dyn EnvelopeSigner>>,
        ca_file: Option<&std::path::Path>,
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
            HttpClient::with_tls(crate::tls::client_config(ca_file)?)
        } else {
            HttpClient::plaintext()
        };
        let repository_text = repository.to_string();
        let signer_key = signer.as_ref().map(|signer| signer.public_key_hex());
        let transport = EnvelopeTransport::new(
            StatusTransport(transport),
            signer,
            origin.clone(),
            repository_text.clone(),
        );

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
            signer_key,
            grant_source: None,
            unary_timeout: UNARY_TIMEOUT,
            pack_transfer_timeout: PACK_TRANSFER_TIMEOUT,
            backoff: BackoffIterator::new,
            sleep: thread::sleep,
            now: crate::envelope::now_ms,
            pending_observer: None,
            tickets: Mutex::new(HashMap::new()),
            unknown_ticketless: AtomicBool::new(false),
            receipts: Arc::new(MemoryPartReceiptStore::default()),
            receipts_swept: AtomicBool::new(false),
            upload_observer: None,
            receipt_observer: None,
            admission_policy: None,
            admission_runs: AtomicUsize::new(0),
            bearer: token.is_some(),
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
        let signer_key = signer.as_ref().map(|signer| signer.public_key_hex());
        Self {
            client: TransportServiceClient::new(
                EnvelopeTransport::new(
                    StatusTransport(HttpClient::plaintext()),
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
            signer_key,
            grant_source: None,
            unary_timeout: UNARY_TIMEOUT,
            pack_transfer_timeout: PACK_TRANSFER_TIMEOUT,
            backoff: test_backoff,
            sleep: no_sleep,
            now: crate::envelope::now_ms,
            pending_observer: None,
            tickets: Mutex::new(HashMap::new()),
            unknown_ticketless: AtomicBool::new(false),
            receipts: Arc::new(MemoryPartReceiptStore::default()),
            receipts_swept: AtomicBool::new(false),
            upload_observer: None,
            receipt_observer: None,
            admission_policy: None,
            admission_runs: AtomicUsize::new(0),
            bearer: false,
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

    /// The auth v2 audience this transport signs for: its origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The repository this transport addresses.
    #[must_use]
    pub fn repository(&self) -> &RepositoryIdentity {
        &self.repository
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

    /// Add a source of locally selected grants. The source is consulted only
    /// for signed repository reads and writes by a non-owner key. The CLI
    /// installs no source until its grant store is available.
    #[must_use]
    pub fn with_grant_source(mut self, source: Arc<dyn GrantSource>) -> Self {
        self.grant_source = Some(source);
        self
    }

    /// Use a caller-owned receipt store for resume across transport instances.
    #[must_use]
    pub fn with_receipt_store(mut self, store: Arc<dyn PartReceiptStore>) -> Self {
        self.receipts = store;
        self
    }

    /// Observe multipart progress. Returning false cancels between parts.
    #[must_use]
    pub fn with_upload_observer(
        mut self,
        observer: impl Fn(UploadEvent) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.upload_observer = Some(Arc::new(observer));
        self
    }

    fn grant_options(&self, options: CallOptions, operation: GrantOperation<'_>) -> CallOptions {
        if matches!(operation, GrantOperation::Part) {
            return options;
        }
        let (Some(source), Some(key), Some(namespace)) = (
            &self.grant_source,
            &self.signer_key,
            self.repository.namespace(),
        ) else {
            return options;
        };
        if namespace.to_string() == format!("ed25519-{key}") {
            return options;
        }
        let request = GrantRequest::new(&self.origin, &self.repository_text, key, operation);
        match source.select(&request) {
            Some(grant) => options.with_header("x-write-grant", grant),
            None => options,
        }
    }

    fn read_options(&self, options: CallOptions) -> TransportResult<CallOptions> {
        if self.signer_key.is_none() {
            return Ok(options);
        }
        let identity = RetryIdentity::new().map_err(TransportError::RemoteError)?;
        Ok(identity.apply(self.grant_options(options, GrantOperation::Read)))
    }

    fn begin_upload_for_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        head_ref: &str,
    ) -> TransportResult<BeginAnswer> {
        let info = self.server_info();
        match info {
            ServerInfoView::Legacy => return Ok(BeginAnswer::Ticketless),
            ServerInfoView::Unknown
                if self.signer_key.is_none() || self.unknown_ticketless.load(Ordering::Relaxed) =>
            {
                return Ok(BeginAnswer::Ticketless);
            }
            ServerInfoView::V2(info)
                if (bytes.len() as u64) < info.begin_upload_threshold_bytes.unwrap_or(0) =>
            {
                return Ok(BeginAnswer::Ticketless);
            }
            _ => {}
        }
        if self.signer_key.is_none() {
            return Err(TransportError::RemoteError(
                "server requires signed uploads; set `transport_auth = envelope`".to_owned(),
            ));
        }
        let mut identity =
            RetryIdentity::new_at((self.now)()).map_err(TransportError::RemoteError)?;
        let mut carried = HeaderMap::new();
        if self.bearer {
            carried.insert(AUTHORIZATION, http::HeaderValue::from_static("Bearer"));
        }
        let response = retry_once(
            self.admission_policy.as_ref(),
            &self.admission_runs,
            (
                &self.origin,
                &self.repository_text,
                "/mkit.transport.v1.TransportService/BeginUpload",
            ),
            &carried,
            self.bearer,
            |admission_headers| {
                if !admission_headers.is_empty() {
                    identity
                        .renew_if_lapsing((self.now)(), MIN_RENEWAL_MARGIN_MS)
                        .map_err(TransportError::RemoteError)?;
                }
                self.retrying(|| {
                    if (self.now)() >= identity.expires_at_ms {
                        identity = RetryIdentity::new_at((self.now)())
                            .map_err(TransportError::RemoteError)?;
                    }
                    let options = self
                        .grant_options(
                            identity.apply(CallOptions::default().with_timeout(self.unary_timeout)),
                            GrantOperation::BeginUpload { ref_name: head_ref },
                        )
                        .with_headers(
                            admission_headers
                                .iter()
                                .map(|(name, value)| (name.clone(), value.clone())),
                        );
                    match self
                        .executor
                        .block_on(self.client.begin_upload_with_options(
                            BeginUploadRequest {
                                r#ref: Some(head_ref.to_owned()),
                                pack_id: Some(key.as_bytes().to_vec()),
                                bytes: Some(bytes.len() as u64),
                                ..Default::default()
                            },
                            options,
                        )) {
                        Ok(result) => {
                            observe_receipts(
                                result.headers(),
                                "/mkit.transport.v1.TransportService/BeginUpload",
                                &self.receipt_observer,
                            );
                            Ok(Ok(result.into_owned()))
                        }
                        Err(err) if err.code == connectrpc::ErrorCode::Unimplemented => {
                            Ok(Err(BeginSpecial::Unimplemented))
                        }
                        Err(err) => {
                            // Admission detection must precede the open-ticket
                            // message check, even when a server uses 402 with
                            // the same text.
                            let mapped = map_connect_error(err.clone(), ErrorContext::Ref);
                            if matches!(
                                mapped,
                                TransportError::AdmissionRequired(_)
                                    | TransportError::InvalidResponse
                            ) {
                                return Err(mapped);
                            }
                            if err.code == connectrpc::ErrorCode::FailedPrecondition
                                && err.message.as_deref() == Some("too many open upload tickets")
                            {
                                Ok(Err(BeginSpecial::OpenCap))
                            } else if err.code == connectrpc::ErrorCode::FailedPrecondition {
                                Ok(Err(BeginSpecial::Rejected(err.message.unwrap_or_default())))
                            } else {
                                Err(mapped)
                            }
                        }
                    }
                })
            },
        )?;
        let response = match response {
            Ok(result) => result,
            Err(BeginSpecial::OpenCap) => {
                return Err(TransportError::RemoteError(
                    "too many open upload tickets".to_owned(),
                ));
            }
            Err(BeginSpecial::Rejected(message)) => {
                return Err(TransportError::RemoteError(format!(
                    "upload ticket rejected: {message}"
                )));
            }
            Err(BeginSpecial::Unimplemented) => match info {
                ServerInfoView::Unknown => {
                    self.unknown_ticketless.store(true, Ordering::Relaxed);
                    return Ok(BeginAnswer::Ticketless);
                }
                ServerInfoView::V2(info) if (bytes.len() as u64) > info.part_size.unwrap_or(0) => {
                    return Err(TransportError::RemoteError(
                        "server storage cannot accept packs over part_size".to_owned(),
                    ));
                }
                _ => {
                    return Err(TransportError::RemoteError(
                        "V2 server does not implement BeginUpload".to_owned(),
                    ));
                }
            },
        };
        match response.result {
            Some(BeginWireResult::AlreadyPresent(_)) => {
                if let Some(old) = self
                    .tickets
                    .lock()
                    .map_err(|_| TransportError::ProtocolError)?
                    .remove(&(head_ref.to_owned(), *key))
                    && let Err(error) = self.receipts.forget(&old.id)
                {
                    log_receipt_cleanup_error("already-present ticket", &error);
                }
                Ok(BeginAnswer::AlreadyPresent)
            }
            Some(BeginWireResult::Ticket(wire)) => {
                let id = wire
                    .id
                    .as_deref()
                    .and_then(|id| <[u8; 32]>::try_from(id).ok())
                    .ok_or(TransportError::InvalidResponse)?;
                let ticket = CachedTicket {
                    id,
                    token: wire.token.ok_or(TransportError::InvalidResponse)?,
                    part_size: wire.part_size.ok_or(TransportError::InvalidResponse)?,
                    expires_unix_ms: wire
                        .expires_unix_ms
                        .ok_or(TransportError::InvalidResponse)?,
                };
                if ticket.token.is_empty()
                    || ticket.part_size < 8 * 1024 * 1024
                    || !ticket.part_size.is_power_of_two()
                    || ticket.expires_unix_ms <= (self.now)()
                {
                    return Err(TransportError::InvalidResponse);
                }
                let old = self
                    .tickets
                    .lock()
                    .map_err(|_| TransportError::ProtocolError)?
                    .insert((head_ref.to_owned(), *key), ticket.clone());
                if let Some(old) = old.filter(|old| old.id != ticket.id)
                    && let Err(error) = self.receipts.forget(&old.id)
                {
                    log_receipt_cleanup_error("replaced ticket", &error);
                }
                Ok(BeginAnswer::Ticket(ticket))
            }
            _ => Err(TransportError::InvalidResponse),
        }
    }

    fn upload_pack_with_token(
        &self,
        bytes: &[u8],
        key: &PackKey,
        token: Option<&[u8]>,
    ) -> TransportResult<Result<(), ()>> {
        if bytes.len() as u64 > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(bytes.len()));
        }
        let mut identity =
            RetryIdentity::new_at((self.now)()).map_err(TransportError::RemoteError)?;
        self.retrying(|| {
            identity
                .renew_if_lapsing((self.now)(), MIN_RENEWAL_MARGIN_MS)
                .map_err(TransportError::RemoteError)?;
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
            let options = if token.is_some() {
                self.grant_options(options, GrantOperation::Part)
            } else {
                self.grant_options(options, GrantOperation::Write { refs: &[] })
            };
            let pack_id = key.as_bytes().to_vec();
            let header = UploadPackRequest {
                body: Some(
                    UploadPackHeader {
                        pack_id: Some(pack_id.clone()),
                        total_bytes: Some(bytes.len() as u64),
                        ticket_token: token.map(<[u8]>::to_vec),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            };
            let response = thread::scope(|scope| {
                let (sender, receiver) = tokio::sync::mpsc::channel(1);
                scope.spawn(move || {
                    if sender.blocking_send(header).is_err() {
                        return;
                    }
                    if bytes.is_empty() {
                        let _ = sender.blocking_send(UploadPackRequest {
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
                        return;
                    }
                    for (index, chunk) in bytes.chunks(CHUNK_SIZE).enumerate() {
                        let offset = index * CHUNK_SIZE;
                        if sender
                            .blocking_send(UploadPackRequest {
                                body: Some(
                                    PackChunk {
                                        pack_id: Some(pack_id.clone()),
                                        offset: Some(offset as u64),
                                        data: Some(chunk.to_vec()),
                                        last: Some(offset + chunk.len() == bytes.len()),
                                        ..Default::default()
                                    }
                                    .into(),
                                ),
                                ..Default::default()
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                });
                let requests = futures::stream::unfold(receiver, |mut receiver| async move {
                    receiver.recv().await.map(|message| (message, receiver))
                });
                self.executor
                    .block_on(self.client.upload_pack_with_options(requests, options))
            });
            match response {
                Ok(_) => Ok(Ok(())),
                Err(err)
                    if token.is_some() && err.code == connectrpc::ErrorCode::FailedPrecondition =>
                {
                    Ok(Err(()))
                }
                Err(err) => Err(map_connect_error(err, ErrorContext::Upload)),
            }
        })
    }

    fn part_plan(&self, bytes: &[u8], ticket: &CachedTicket) -> TransportResult<PartPlan> {
        let max_parts = match self.server_info() {
            ServerInfoView::V2(info) => info.max_parts.unwrap_or(0),
            _ => u32::MAX,
        };
        PartPlan::new(bytes.len() as u64, ticket.part_size, max_parts).map_err(|err| match err {
            PartError::TooManyParts => TransportError::RemoteError(
                "pack exceeds the server's maximum number of upload parts".to_owned(),
            ),
            _ => TransportError::ProtocolError,
        })
    }

    fn upload_part_once(
        &self,
        ticket: &CachedTicket,
        plan: &PartPlan,
        index: u32,
        bytes: &[u8],
    ) -> TransportResult<Result<Vec<u8>, ()>> {
        let subtree =
            part_subtree_cv(plan, index, bytes).map_err(|_| TransportError::ProtocolError)?;
        let commitment = ContentCommitment::Part(PartCommitment {
            ticket: ticket.id,
            index,
            subtree,
            len: bytes.len() as u64,
        })
        .to_string();
        let mut identity =
            RetryIdentity::new_at((self.now)()).map_err(TransportError::RemoteError)?;
        let mut renewed_after_unauthenticated = false;
        self.retrying(|| {
            identity
                .renew_if_lapsing((self.now)(), MIN_RENEWAL_MARGIN_MS)
                .map_err(TransportError::RemoteError)?;
            loop {
                let header = UploadPartRequest {
                    msg: Some(
                        UploadPartHeader {
                            ticket_token: Some(ticket.token.clone()),
                            index: Some(index),
                            ..Default::default()
                        }
                        .into(),
                    ),
                    ..Default::default()
                };
                let options = self.grant_options(
                    identity.apply(
                        CallOptions::default()
                            .with_timeout(self.pack_transfer_timeout)
                            .with_header("x-content-commitment", &commitment),
                    ),
                    GrantOperation::Part,
                );
                let response = thread::scope(|scope| {
                    let (sender, receiver) = tokio::sync::mpsc::channel(1);
                    scope.spawn(move || {
                        if sender.blocking_send(header).is_err() {
                            return;
                        }
                        for chunk in bytes.chunks(CHUNK_SIZE) {
                            if sender
                                .blocking_send(UploadPartRequest {
                                    msg: Some(PartWireMessage::Chunk(chunk.to_vec())),
                                    ..Default::default()
                                })
                                .is_err()
                            {
                                return;
                            }
                        }
                    });
                    let requests = futures::stream::unfold(receiver, |mut receiver| async move {
                        receiver.recv().await.map(|message| (message, receiver))
                    });
                    self.executor
                        .block_on(self.client.upload_part_with_options(requests, options))
                });
                match response {
                    Ok(response) => {
                        return response
                            .into_owned()
                            .receipt
                            .filter(|receipt| !receipt.is_empty() && receipt.len() <= 512)
                            .map(Ok)
                            .ok_or(TransportError::InvalidResponse);
                    }
                    Err(err) if err.code == connectrpc::ErrorCode::FailedPrecondition => {
                        return Ok(Err(()));
                    }
                    Err(err)
                        if err.code == connectrpc::ErrorCode::Unauthenticated
                            && !renewed_after_unauthenticated =>
                    {
                        renewed_after_unauthenticated = true;
                        identity = RetryIdentity::new_at((self.now)())
                            .map_err(TransportError::RemoteError)?;
                    }
                    Err(err) => return Err(map_connect_error(err, ErrorContext::Upload)),
                }
            }
        })
    }

    fn complete_upload_once(
        &self,
        ticket: &CachedTicket,
        receipts: &[Vec<u8>],
    ) -> TransportResult<Result<(), CompleteSpecial>> {
        let mut identity =
            RetryIdentity::new_at((self.now)()).map_err(TransportError::RemoteError)?;
        self.retrying(|| {
            identity
                .renew_if_lapsing((self.now)(), MIN_RENEWAL_MARGIN_MS)
                .map_err(TransportError::RemoteError)?;
            let options = self.grant_options(
                identity.apply(CallOptions::default().with_timeout(self.pack_transfer_timeout)),
                GrantOperation::Part,
            );
            match self
                .executor
                .block_on(self.client.complete_upload_with_options(
                    CompleteUploadRequest {
                        ticket_token: Some(ticket.token.clone()),
                        receipts: receipts.to_vec(),
                        ..Default::default()
                    },
                    options,
                )) {
                Ok(_) => Ok(Ok(())),
                Err(err) if err.code == connectrpc::ErrorCode::FailedPrecondition => {
                    Ok(Err(CompleteSpecial::Ticket))
                }
                Err(err) if err.code == connectrpc::ErrorCode::InvalidArgument => {
                    Ok(Err(CompleteSpecial::InvalidReceipt))
                }
                Err(err) => Err(map_connect_error(err, ErrorContext::Upload)),
            }
        })
    }

    fn upload_parts(
        &self,
        bytes: &[u8],
        key: &PackKey,
        head_ref: &str,
        ticket: &CachedTicket,
    ) -> TransportResult<Result<(), ()>> {
        let plan = self.part_plan(bytes, ticket)?;
        let meta = TicketMetadata {
            ticket_id: ticket.id,
            audience: self.origin.clone(),
            repository: self.repository_text.clone(),
            signer: self.signer_key.clone().unwrap_or_default(),
            head_ref: head_ref.to_owned(),
            pack_key: *key,
            bytes: bytes.len() as u64,
            part_size: ticket.part_size,
            expires_unix_ms: ticket.expires_unix_ms,
        };
        if !self.receipts_swept.swap(true, Ordering::Relaxed)
            && let Err(error) = self.receipts.sweep((self.now)())
        {
            log_receipt_cleanup_error("sweep", &error);
        }
        for invalid_retry in 0..2 {
            let mut parts = vec![None; plan.count() as usize];
            if invalid_retry == 0 {
                for receipt in self.receipts.load(&meta, &plan)? {
                    if let Some(slot) = parts.get_mut(receipt.index as usize) {
                        *slot = Some(receipt);
                    }
                }
            }
            let resumed = parts.iter().filter(|part| part.is_some()).count() as u32;
            let mut saved_bytes: u64 = parts.iter().flatten().map(|part| part.len).sum();
            self.upload_event(
                UploadEvent::PartsPlanned {
                    parts: plan.count(),
                    resumed,
                    saved_bytes,
                    bytes: bytes.len() as u64,
                },
                resumed,
                plan.count(),
            )?;
            for index in 0..plan.count() {
                if parts[index as usize].is_some() {
                    continue;
                }
                self.check_upload_cancel(
                    parts.iter().filter(|part| part.is_some()).count() as u32,
                    plan.count(),
                )?;
                let offset = usize::try_from(
                    plan.offset(index)
                        .map_err(|_| TransportError::ProtocolError)?,
                )
                .map_err(|_| TransportError::ProtocolError)?;
                let len = usize::try_from(
                    plan.expected_len(index)
                        .map_err(|_| TransportError::ProtocolError)?,
                )
                .map_err(|_| TransportError::ProtocolError)?;
                let slice = bytes
                    .get(offset..offset + len)
                    .ok_or(TransportError::ProtocolError)?;
                let receipt = match self.upload_part_once(ticket, &plan, index, slice)? {
                    Ok(receipt) => receipt,
                    Err(()) => return Ok(Err(())),
                };
                let part = StoredPart {
                    index,
                    len: len as u64,
                    receipt,
                    from_disk: false,
                };
                self.receipts.put(&meta, &part)?;
                saved_bytes += part.len;
                parts[index as usize] = Some(part);
                self.upload_event(
                    UploadEvent::PartSent {
                        index,
                        parts: plan.count(),
                        saved_bytes,
                        bytes: bytes.len() as u64,
                        resumed,
                    },
                    parts.iter().filter(|part| part.is_some()).count() as u32,
                    plan.count(),
                )?;
            }
            if parts.len() != plan.count() as usize || parts.iter().any(Option::is_none) {
                return Err(TransportError::ProtocolError);
            }
            let from_disk = parts.iter().flatten().any(|part| part.from_disk);
            let ordered: Vec<Vec<u8>> = parts
                .into_iter()
                .flatten()
                .map(|part| part.receipt)
                .collect();
            self.upload_event(UploadEvent::Completing, plan.count(), plan.count())?;
            match self.complete_upload_once(ticket, &ordered)? {
                Ok(()) => {
                    self.upload_event(UploadEvent::Finished, plan.count(), plan.count())?;
                    return Ok(Ok(()));
                }
                Err(CompleteSpecial::Ticket) => return Ok(Err(())),
                Err(CompleteSpecial::InvalidReceipt) if from_disk && invalid_retry == 0 => {
                    // Best-effort: the resend pass doesn't reload stored receipts.
                    if let Err(error) = self.receipts.forget(&ticket.id) {
                        log_receipt_cleanup_error("invalid receipt", &error);
                    }
                }
                Err(CompleteSpecial::InvalidReceipt) => return Err(TransportError::ProtocolError),
            }
        }
        Err(TransportError::ProtocolError)
    }

    fn check_upload_cancel(&self, saved: u32, total: u32) -> TransportResult<()> {
        if self
            .upload_observer
            .as_ref()
            .is_some_and(|observer| !observer(UploadEvent::BeforePart))
        {
            return Err(upload_interrupted(saved, total));
        }
        Ok(())
    }

    fn upload_event(&self, event: UploadEvent, saved: u32, total: u32) -> TransportResult<()> {
        if self
            .upload_observer
            .as_ref()
            .is_some_and(|observer| !observer(event))
        {
            return Err(upload_interrupted(saved, total));
        }
        Ok(())
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

    /// Observe bounded payment receipt headers on successful unary writes.
    #[must_use]
    pub fn with_admission_receipt_observer(
        mut self,
        observer: impl Fn(&AdmissionReceipt) + Send + Sync + 'static,
    ) -> Self {
        self.receipt_observer = Some(Arc::new(observer));
        self
    }

    /// Install a policy for one helper-backed retry of admitted writes.
    #[must_use]
    pub fn with_admission(mut self, policy: AdmissionPolicy) -> Self {
        self.admission_policy = Some(policy);
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
    #[doc(hidden)]
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
        match self.advance_refs_with_tickets(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
            &[],
            deadline,
        )? {
            CommitOutcome::Advanced(outcome) => Ok(outcome),
            _ => Err(TransportError::InvalidResponse),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn advance_refs_with_tickets(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
        ticket_ids: &[Vec<u8>],
        deadline: Option<i64>,
    ) -> TransportResult<CommitOutcome> {
        let (head_expectation, head_expected_id) = condition_to_wire(head_condition);
        let (packmap_expectation, packmap_expected_id) = condition_to_wire(packmap_condition);
        let start_ms = (self.now)();
        let deadline = deadline.unwrap_or_else(|| start_ms.saturating_add(MAX_PENDING_MS));
        let (attempts, ladder_sleep_ms) = (self.backoff)().fold((1_i64, 0_i64), |acc, delay| {
            (
                acc.0.saturating_add(1),
                acc.1
                    .saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX)),
            )
        });
        let margin_ms = i64::try_from(self.unary_timeout.as_millis())
            .unwrap_or(i64::MAX)
            .saturating_mul(attempts)
            .saturating_add(ladder_sleep_ms)
            .max(MIN_RENEWAL_MARGIN_MS);
        let mut identity = RetryIdentity::new_at(start_ms).map_err(TransportError::RemoteError)?;
        let mut saw_pending = false;
        let mut waiting_since_ms = start_ms;
        let mut renewed_after_unauthenticated = false;
        let mut lag_since_ms: Option<i64> = None;
        let mut admission_headers = HeaderMap::new();
        let mut helper_ran = false;
        let refs = [
            GrantRef::new(head_ref, grant_condition(head_condition)),
            GrantRef::new(packmap_ref, grant_condition(packmap_condition)),
        ];

        loop {
            // A pending reply is definitive: before its next poll, renew an
            // identity that cannot cover the next unary attempt. An ambiguous
            // failure inside the ladder retains its nonce until actual expiry.
            if saw_pending || lag_since_ms.is_some() {
                let now = (self.now)();
                if now < deadline && identity.expires_at_ms.saturating_sub(now) < margin_ms {
                    identity = match RetryIdentity::new_at(now) {
                        Ok(next) => next,
                        Err(message) => {
                            self.pending_finished(waiting_since_ms, false);
                            return Err(TransportError::RemoteError(message));
                        }
                    };
                }
            }
            let poll = self.retrying(|| {
                loop {
                    let now = (self.now)();
                    if now >= deadline {
                        return Err(advance_deadline_error(saw_pending));
                    }
                    if lag_since_ms.is_some_and(|start| now.saturating_sub(start) >= 60_000) {
                        return Err(TransportError::RemoteError(
                            "repository membership not yet visible after 60 seconds".to_owned(),
                        ));
                    }
                    if now >= identity.expires_at_ms {
                        identity =
                            RetryIdentity::new_at(now).map_err(TransportError::RemoteError)?;
                    }
                    let mut timeout_ms = deadline.saturating_sub(now);
                    if let Some(lag_start) = lag_since_ms {
                        timeout_ms = timeout_ms
                            .min(60_000_i64.saturating_sub(now.saturating_sub(lag_start)));
                    }
                    let timeout = self.unary_timeout.min(Duration::from_millis(
                        u64::try_from(timeout_ms).unwrap_or(0),
                    ));
                    let options = self
                        .grant_options(
                            identity.apply(CallOptions::default().with_timeout(timeout)),
                            GrantOperation::Write { refs: &refs },
                        )
                        .with_headers(
                            admission_headers
                                .iter()
                                .map(|(name, value)| (name.clone(), value.clone())),
                        );
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
                                ticket_ids: ticket_ids.to_vec(),
                                ..Default::default()
                            },
                            options,
                        ));
                    match response {
                        Ok(resp) => {
                            let (headers, resp, _) = resp.into_owned_parts();
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
                            if outcome == CoreAdvanceOutcome::Committed {
                                observe_receipts(
                                    &headers,
                                    "/mkit.transport.v1.TransportService/AdvanceRefs",
                                    &self.receipt_observer,
                                );
                            }
                            return Ok(Ok(CommitOutcome::Advanced(outcome)));
                        }
                        Err(err) => {
                            // A ticket-consuming advance never invokes the
                            // admission helper, but an HTTP 402 still surfaces
                            // as its typed challenge, regardless of the
                            // Connect error code used by the server.
                            let mapped = map_connect_error(err.clone(), ErrorContext::Ref);
                            if matches!(
                                mapped,
                                TransportError::AdmissionRequired(_)
                                    | TransportError::InvalidResponse
                            ) {
                                return Err(mapped);
                            }
                            if !ticket_ids.is_empty() {
                                if err.code == connectrpc::ErrorCode::FailedPrecondition {
                                    return Ok(Ok(
                                        if err.message.as_deref()
                                            == Some("delta base not available in this repository")
                                        {
                                            CommitOutcome::DeltaBaseUnavailable
                                        } else {
                                            CommitOutcome::TicketRejected
                                        },
                                    ));
                                }
                                if err.code == connectrpc::ErrorCode::InvalidArgument
                                    && err.message.as_deref()
                                        == Some(
                                            "packlist lists a pack that is not in this repository",
                                        )
                                {
                                    return Ok(Ok(CommitOutcome::PacklistNotInRepository));
                                }
                                if err.code == connectrpc::ErrorCode::Unavailable
                                    && err.message.as_deref()
                                        == Some("repository membership not yet visible")
                                {
                                    return Ok(Err((Duration::from_secs(2), true)));
                                }
                            }
                            // The 60-second window bounds consecutive lag
                            // answers only. Any other answer returns to the
                            // ticket deadline and ordinary unary timeout.
                            lag_since_ms = None;
                            if let Some(delay) = pending_verification_delay(&err) {
                                // This pending reply belongs to the re-signed
                                // identity, which now has its own one-shot
                                // unauthenticated recovery allowance.
                                renewed_after_unauthenticated = false;
                                return Ok(Err((delay, false)));
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
                            return Err(mapped);
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
                Ok(Err((delay, lag))) => {
                    if lag {
                        lag_since_ms.get_or_insert_with(|| (self.now)());
                    } else {
                        lag_since_ms = None;
                    }
                    if !saw_pending {
                        waiting_since_ms = (self.now)();
                    }
                    saw_pending = true;
                    delay
                }
                Err(error) => {
                    if ticket_ids.is_empty()
                        && let TransportError::AdmissionRequired(required) = error
                    {
                        if helper_ran {
                            return Err(TransportError::AdmissionRequired(Box::new(
                                required.with_reason(
                                    "remote challenged again after the admission helper ran",
                                ),
                            )));
                        }
                        let Some(policy) = self.admission_policy.as_ref() else {
                            return Err(TransportError::AdmissionRequired(required));
                        };
                        let mut carried = HeaderMap::new();
                        if self.bearer {
                            carried.insert(AUTHORIZATION, http::HeaderValue::from_static("Bearer"));
                        }
                        admission_headers = respond_to_challenge(
                            policy,
                            &self.admission_runs,
                            (
                                &self.origin,
                                &self.repository_text,
                                "/mkit.transport.v1.TransportService/AdvanceRefs",
                            ),
                            &carried,
                            self.bearer,
                            *required,
                        )?;
                        helper_ran = true;
                        if identity.expires_at_ms.saturating_sub((self.now)())
                            <= MIN_RENEWAL_MARGIN_MS
                        {
                            identity = RetryIdentity::new_at((self.now)())
                                .map_err(TransportError::RemoteError)?;
                        }
                        continue;
                    }
                    if saw_pending {
                        self.pending_finished(waiting_since_ms, false);
                    }
                    return Err(error);
                }
            };
            let mut remaining = delay;
            while !remaining.is_zero() {
                let now = (self.now)();
                if now >= deadline
                    || lag_since_ms.is_some_and(|start| now.saturating_sub(start) >= 60_000)
                {
                    self.pending_finished(waiting_since_ms, false);
                    return Err(if now >= deadline {
                        advance_deadline_error(true)
                    } else {
                        TransportError::RemoteError(
                            "repository membership not yet visible after 60 seconds".to_owned(),
                        )
                    });
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
                    self.read_options(
                        CallOptions::default().with_timeout(self.pack_transfer_timeout),
                    )?,
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
                    self.read_options(CallOptions::default().with_timeout(self.unary_timeout))?,
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

    /// `GetGrantEpoch` (SPEC-WRITE-GRANTS §5.3): the stored epoch of
    /// `namespace` at this deployment, 0 if it was never set. Unsigned, and
    /// with no `X-Repository`: the answer never depends on a repository.
    ///
    /// # Errors
    ///
    /// [`TransportError::InvalidRef`] for a namespace outside the grammar;
    /// transport failures otherwise.
    pub fn get_grant_epoch(&self, namespace: &str) -> TransportResult<Completion<u64>> {
        self.retrying(|| self.get_grant_epoch_attempt(namespace))
    }

    /// One `GetGrantEpoch` attempt, without the retry ladder: for advisory
    /// reads that must fail fast.
    ///
    /// # Errors
    ///
    /// As [`Self::get_grant_epoch`], on the first failure.
    pub fn get_grant_epoch_once(&self, namespace: &str) -> TransportResult<Completion<u64>> {
        self.get_grant_epoch_attempt(namespace)
    }

    fn get_grant_epoch_attempt(&self, namespace: &str) -> TransportResult<Completion<u64>> {
        self.executor.block_on(async {
            let result = self
                .client
                .get_grant_epoch_with_options(
                    GetGrantEpochRequest {
                        namespace: Some(namespace.to_owned()),
                        ..Default::default()
                    },
                    CallOptions::default().with_timeout(self.unary_timeout),
                )
                .await;
            completion(result, |resp| resp.into_owned().epoch)
        })
    }

    /// `SetGrantEpoch` (SPEC-WRITE-GRANTS §5.3) with an owner-signed
    /// `mkit-write-epoch:v1` statement in the §4.2 encoding. Unsigned (no
    /// auth v2 envelope) and with no `X-Repository`. The server returns the
    /// stored epoch once revocation completed, or `Pending`; send the
    /// identical statement again after `retry_after` (§5.2: the same epoch is
    /// a retry).
    ///
    /// # Errors
    ///
    /// [`TransportError::AccessDenied`] when the server rejects the statement
    /// (a step above the bound, a decrease, a wrong audience, a bad
    /// signature); transport failures otherwise.
    pub fn set_grant_epoch(&self, signed_statement: &str) -> TransportResult<Completion<u64>> {
        self.retrying(|| {
            self.executor.block_on(async {
                let result = self
                    .client
                    .set_grant_epoch_with_options(
                        SetGrantEpochRequest {
                            signed_statement: Some(signed_statement.to_owned()),
                            ..Default::default()
                        },
                        CallOptions::default().with_timeout(self.unary_timeout),
                    )
                    .await;
                completion(result, |resp| resp.into_owned().epoch)
            })
        })
    }

    /// `SetRepoVisibility` (SPEC-WRITE-GRANTS §9.1) for this transport's
    /// repository, which travels only in `X-Repository`.
    ///
    /// * [`VisibilityRequest::Envelope`] is a signed auth v2 write. A fresh
    ///   signature is made per call, which is safe to repeat: it sets a value.
    ///   No grant is attached.
    /// * [`VisibilityRequest::Statement`] carries no envelope.
    ///
    /// # Errors
    ///
    /// [`TransportError::AccessDenied`] for a rejected request;
    /// [`TransportError::RemoteError`] for envelope mode without a signer;
    /// transport failures otherwise.
    pub fn set_repo_visibility(
        &self,
        request: VisibilityRequest<'_>,
    ) -> TransportResult<Completion<()>> {
        let (mode, identity) = match request {
            VisibilityRequest::Envelope(choice) => {
                if self.signer_key.is_none() {
                    return Err(TransportError::RemoteError(
                        "envelope-mode SetRepoVisibility needs a signing identity".into(),
                    ));
                }
                let wire = match choice {
                    VisibilityChoice::Public => RepoVisibility::REPO_VISIBILITY_PUBLIC,
                    VisibilityChoice::Private => RepoVisibility::REPO_VISIBILITY_PRIVATE,
                };
                (
                    VisibilityWireMode::Visibility(wire.into()),
                    Some(RetryIdentity::new_at((self.now)()).map_err(TransportError::RemoteError)?),
                )
            }
            VisibilityRequest::Statement(text) => {
                (VisibilityWireMode::SignedStatement(text.to_owned()), None)
            }
        };
        self.retrying(|| {
            self.executor.block_on(async {
                let mut options = CallOptions::default().with_timeout(self.unary_timeout);
                if let Some(identity) = &identity {
                    options = identity.apply(options);
                }
                let result = self
                    .client
                    .set_repo_visibility_with_options(
                        SetRepoVisibilityRequest {
                            mode: Some(mode.clone()),
                            ..Default::default()
                        },
                        options,
                    )
                    .await;
                completion(result, |_| Some(()))
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

/// Map an epoch or visibility RPC result: `done` extracts the value from a
/// success (`None` is an invalid response), and a server `unavailable` with a
/// `Retry-After` is [`Completion::Pending`].
fn completion<R, T>(
    result: Result<R, connectrpc::ConnectError>,
    done: impl FnOnce(R) -> Option<T>,
) -> TransportResult<Completion<T>> {
    match result {
        Ok(resp) => done(resp)
            .map(Completion::Done)
            .ok_or(TransportError::InvalidResponse),
        Err(e) => pending_retry_after(&e).map_or_else(
            || Err(map_connect_error(e, ErrorContext::Ref)),
            |retry_after| Ok(Completion::Pending { retry_after }),
        ),
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

fn grant_condition(c: RefWriteCondition) -> GrantCondition {
    match c {
        RefWriteCondition::Missing => GrantCondition::Missing,
        RefWriteCondition::Match(_) => GrantCondition::Match,
        RefWriteCondition::Any => GrantCondition::Any,
    }
}

/// Build the `UploadPackRequest` stream for one pack: one `header` message
/// followed by `ceil(len / CHUNK_SIZE)` `chunk` messages (or exactly one
/// empty `last = true` chunk for a zero-byte pack), matching
/// SPEC-TRANSPORT-CONNECT §6.1.
#[cfg(test)]
fn build_upload_requests(
    bytes: &[u8],
    key: &PackKey,
    token: Option<&[u8]>,
) -> Vec<UploadPackRequest> {
    let pack_id = key.as_bytes().to_vec();
    let mut requests = Vec::with_capacity(2 + bytes.len() / CHUNK_SIZE);
    requests.push(UploadPackRequest {
        body: Some(
            UploadPackHeader {
                pack_id: Some(pack_id.clone()),
                total_bytes: Some(bytes.len() as u64),
                ticket_token: token.map(<[u8]>::to_vec),
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
        self.upload_pack_with_token(bytes, key, None).map(|_| ())
    }

    fn upload_pack_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        head_ref: &str,
    ) -> TransportResult<()> {
        for attempt in 0..2 {
            match self.begin_upload_for_ref(bytes, key, head_ref)? {
                BeginAnswer::AlreadyPresent => return Ok(()),
                BeginAnswer::Ticketless => return self.upload_pack(bytes, key),
                BeginAnswer::Ticket(ticket) => {
                    let result = if bytes.len() as u64 <= ticket.part_size {
                        self.upload_pack_with_token(bytes, key, Some(&ticket.token))?
                    } else {
                        self.upload_parts(bytes, key, head_ref, &ticket)?
                    };
                    if result.is_ok() {
                        return Ok(());
                    }
                    if attempt == 1 {
                        return Err(TransportError::RemoteError(
                            "upload ticket rejected".to_owned(),
                        ));
                    }
                }
            }
        }
        Err(TransportError::ProtocolError)
    }

    fn upload_blob_via_ref(
        &self,
        bytes: &[u8],
        key: &PackKey,
        head_ref: &str,
    ) -> TransportResult<()> {
        self.upload_pack_via_ref(bytes, key, head_ref)
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
        let mut identity =
            RetryIdentity::new_at((self.now)()).map_err(TransportError::RemoteError)?;
        let refs = [GrantRef::new(name, grant_condition(condition))];
        let mut carried = HeaderMap::new();
        if self.bearer {
            carried.insert(AUTHORIZATION, http::HeaderValue::from_static("Bearer"));
        }
        retry_once(
            self.admission_policy.as_ref(),
            &self.admission_runs,
            (
                &self.origin,
                &self.repository_text,
                "/mkit.transport.v1.TransportService/UpdateRef",
            ),
            &carried,
            self.bearer,
            |admission_headers| {
                // The retry after the admission helper may renew early: the
                // helper can take most of the validity window. Inside a ladder,
                // an ambiguous failure keeps its nonce until actual expiry.
                if !admission_headers.is_empty() {
                    let now = (self.now)();
                    if identity.expires_at_ms.saturating_sub(now) <= MIN_RENEWAL_MARGIN_MS {
                        identity =
                            RetryIdentity::new_at(now).map_err(TransportError::RemoteError)?;
                    }
                }
                self.retrying(|| {
                    self.executor.block_on(async {
                        let now = (self.now)();
                        if now >= identity.expires_at_ms {
                            identity =
                                RetryIdentity::new_at(now).map_err(TransportError::RemoteError)?;
                        }
                        let options = self
                            .grant_options(
                                identity
                                    .apply(CallOptions::default().with_timeout(self.unary_timeout)),
                                GrantOperation::Write { refs: &refs },
                            )
                            .with_headers(
                                admission_headers
                                    .iter()
                                    .map(|(name, value)| (name.clone(), value.clone())),
                            );
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
                            .map(|resp| {
                                observe_receipts(
                                    resp.headers(),
                                    "/mkit.transport.v1.TransportService/UpdateRef",
                                    &self.receipt_observer,
                                );
                            })
                            .map_err(|e| map_connect_error(e, ErrorContext::Ref))
                    })
                })
            },
        )
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.retrying(|| {
            self.executor.block_on(async {
                let options =
                    self.read_options(CallOptions::default().with_timeout(self.unary_timeout))?;
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
                            self.read_options(
                                CallOptions::default().with_timeout(self.unary_timeout),
                            )?,
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

    fn advance_refs_committing(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
        commit: &[PackKey],
    ) -> TransportResult<CommitOutcome> {
        let cached = self
            .tickets
            .lock()
            .map_err(|_| TransportError::ProtocolError)?;
        let selected: Vec<_> = commit
            .iter()
            .filter_map(|key| {
                cached
                    .get(&(head_ref.to_owned(), *key))
                    .map(|ticket| (*key, ticket.clone()))
            })
            .collect();
        drop(cached);
        let ids: Vec<Vec<u8>> = selected
            .iter()
            .map(|(_, ticket)| ticket.id.to_vec())
            .collect();
        if ids.len() > 7 || ids.len() != ids.iter().collect::<HashSet<_>>().len() {
            return Err(TransportError::InvalidRef(
                "advance contains more than seven or duplicate upload tickets".to_owned(),
            ));
        }
        if !ids.is_empty() {
            let branch = head_ref
                .strip_prefix("refs/heads/")
                .filter(|branch| !branch.is_empty());
            if branch.is_none_or(|branch| packmap_ref != format!("refs/mkit/packmap/{branch}")) {
                return Err(TransportError::InvalidRef(
                    "ticketed advance requires paired head and packmap refs".to_owned(),
                ));
            }
        }
        let deadline = selected
            .iter()
            .map(|(_, ticket)| ticket.expires_unix_ms)
            .min();
        if !ids.is_empty() && deadline.is_some_and(|expiry| expiry <= (self.now)()) {
            return Ok(CommitOutcome::TicketRejected);
        }
        let outcome = self.advance_refs_with_tickets(
            head_ref,
            head_condition,
            head_value,
            packmap_ref,
            packmap_condition,
            packmap_value,
            &ids,
            deadline,
        )?;
        if outcome == CommitOutcome::Advanced(CoreAdvanceOutcome::Committed) {
            let mut cached = self
                .tickets
                .lock()
                .map_err(|_| TransportError::ProtocolError)?;
            let mut consumed = Vec::new();
            for (key, ticket) in selected {
                let cache_key = (head_ref.to_owned(), key);
                if cached
                    .get(&cache_key)
                    .is_some_and(|current| current.id == ticket.id)
                {
                    cached.remove(&cache_key);
                    consumed.push(ticket.id);
                }
            }
            drop(cached);
            for id in consumed {
                if let Err(error) = self.receipts.forget(&id) {
                    log_receipt_cleanup_error("committed ticket", &error);
                }
            }
        }
        Ok(outcome)
    }

    fn upload_limits(&self) -> UploadLimits {
        match self.server_info() {
            ServerInfoView::V2(info) => UploadLimits {
                max_pack_bytes: info.max_pack_bytes,
                tickets_per_advance: self.signer_key.as_ref().map(|_| 7),
                ticket_threshold_bytes: self
                    .signer_key
                    .as_ref()
                    .map(|_| info.begin_upload_threshold_bytes.unwrap_or(0)),
            },
            ServerInfoView::Unknown
                if self.signer_key.is_some()
                    && !self.unknown_ticketless.load(Ordering::Relaxed) =>
            {
                UploadLimits {
                    max_pack_bytes: None,
                    tickets_per_advance: Some(7),
                    ticket_threshold_bytes: Some(0),
                }
            }
            _ => UploadLimits::default(),
        }
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

    struct TestSigner(&'static str);
    impl EnvelopeSigner for TestSigner {
        fn public_key_hex(&self) -> String {
            self.0.into()
        }
        fn sign_hex(&self, _message: &[u8; 32]) -> Result<String, String> {
            Ok("ab".repeat(64))
        }
    }
    struct TestGrants;
    impl GrantSource for TestGrants {
        fn select(&self, _request: &GrantRequest<'_>) -> Option<String> {
            Some("grant-value".into())
        }
    }

    #[test]
    fn grant_header_requires_non_owner_signer_and_non_part_path() {
        let key = "ab".repeat(32);
        let owner_url: Uri = format!("http://127.0.0.1/ed25519-{key}/photos")
            .parse()
            .unwrap();
        let address_url: Uri = "http://127.0.0.1/0x8ba1f109551bd432803012645ac136ddd64dba72/photos"
            .parse()
            .unwrap();
        let source: Arc<dyn GrantSource> = Arc::new(TestGrants);
        let owner = ConnectTransport::connect_for_test_with_signer(
            owner_url,
            Some(Arc::new(TestSigner(
                "abababababababababababababababababababababababababababababababab",
            ))),
        )
        .with_grant_source(source.clone());
        let unsigned = ConnectTransport::connect_for_test(address_url.clone())
            .with_grant_source(source.clone());
        assert!(
            unsigned
                .read_options(CallOptions::default())
                .unwrap()
                .headers()
                .get("idempotency-key")
                .is_none()
        );
        let grantee = ConnectTransport::connect_for_test_with_signer(
            address_url,
            Some(Arc::new(TestSigner(
                "abababababababababababababababababababababababababababababababab",
            ))),
        )
        .with_grant_source(source);
        for tx in [&owner, &unsigned] {
            assert!(
                tx.grant_options(CallOptions::default(), GrantOperation::Read)
                    .headers()
                    .get("x-write-grant")
                    .is_none()
            );
        }
        assert!(
            grantee
                .grant_options(CallOptions::default(), GrantOperation::Part)
                .headers()
                .get("x-write-grant")
                .is_none()
        );
        assert_eq!(
            grantee
                .grant_options(CallOptions::default(), GrantOperation::Read)
                .headers()["x-write-grant"],
            "grant-value"
        );
    }

    // -- connect() + URL parsing --------------------------------------

    #[test]
    fn audience_from_url_matches_the_transport_audience() {
        for url in [
            "mkit+https://git.example.com/0x8ba1f109551bd432803012645ac136ddd64dba72/site",
            "mkit+https://Git.Example.com:443/x",
            "mkit+https://git.example.com:8443",
            "mkit+http://127.0.0.1:8080/default",
        ] {
            let tx = ConnectTransport::connect(url).unwrap();
            assert_eq!(
                audience_from_url(url).as_deref(),
                Some(tx.origin()),
                "{url}"
            );
        }
        for bad in [
            "https://git.example.com",
            "mkit+ftp://x",
            "mkit+http://example.com",
            "mkit+",
        ] {
            assert_eq!(audience_from_url(bad), None, "{bad}");
        }
    }

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
        let reqs = build_upload_requests(b"", &key, None);
        assert_eq!(reqs.len(), 2, "header + one empty last=true chunk");
    }

    #[test]
    fn build_upload_requests_chunks_at_chunk_size_boundary() {
        let key = PackKey::new([0x22u8; 32]);
        let data = vec![0u8; CHUNK_SIZE * 2 + 1];
        let reqs = build_upload_requests(&data, &key, None);
        // 1 header + 3 chunks (CHUNK_SIZE, CHUNK_SIZE, 1 byte).
        assert_eq!(reqs.len(), 4);
    }
}
