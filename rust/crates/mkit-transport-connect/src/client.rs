//! Compatibility transport facade over `mkit-client` and `mkit-sync`.
use super::host::{HostClock, HostPolicy, HostSigner, map_source};
use crate::admission::AdmissionPolicy;
use crate::envelope::EnvelopeSigner;
#[cfg(test)]
use crate::envelope::RetryIdentity;
use crate::grant::{GrantCondition, GrantSource};
#[cfg(test)]
use crate::grant::{GrantOperation, GrantRequest};
use crate::part_receipts::{MemoryPartReceiptStore, PartReceiptStore};
use crate::proto::mkit::transport::v1::GetServerInfoResponse;
#[cfg(test)]
use crate::proto::mkit::transport::v1::{
    PackChunk, RefExpectation, UploadPackHeader, UploadPackRequest,
};
#[cfg(test)]
use connectrpc::client::{CallOptions, ClientConfig};
use http::Uri;
use mkit_client::{Client, Destination};
use mkit_core::hash::Hash;
use mkit_core::protocol::{
    AdvanceOutcome as CoreAdvanceOutcome, BackoffIterator, CommitOutcome, PackKey,
    RefWriteCondition, RepositoryAddress, Transport, TransportError, TransportResult, UploadLimits,
};
use mkit_core::refs::Ref;
use mkit_core::repo_identity::{IdentityError, RemoteIdentity, RepositoryIdentity};
use mkit_sync::NativeHttp;
use mkit_sync::{ClientSession, Executor};
use mkit_sync::{ClientSource, RemoteSource, SourceError};
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;
use url::{Host, Url};
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
    /// The namespace segment is outside both namespace grammars.
    Namespace(String),
    /// The name segment is outside the repository name grammar.
    Name(String),
}

/// The grammar sentence [`UrlIdentityError::Namespace`] and
/// [`UrlIdentityError::Name`] end with.
const URL_GRAMMARS: &str = "accepted namespaces are self-certifying \
    `ed25519-<64 lowercase hex>` or `0x<40 lowercase hex>`, or authority-mode \
    `[a-z0-9][a-z0-9._-]{0,71}` other than `root`, `ed25519-…` and `0x…`; \
    names are `[a-z0-9][a-z0-9._-]{0,99}` (SPEC-TRANSPORT-CONNECT §7.4)";

/// Escape `text` with `char::escape_default`, truncating to 64 escaped
/// characters plus `…` when longer, so an offending URL segment stays
/// printable and bounded in an error message.
fn escape_offending(text: &str) -> String {
    let mut escaped = text.chars().flat_map(char::escape_default);
    let mut out: String = escaped.by_ref().take(64).collect();
    if escaped.next().is_some() {
        out.push('…');
    }
    out
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
            Self::Namespace(ns) => write!(
                f,
                "namespace `{}` is outside both namespace grammars; {URL_GRAMMARS}",
                escape_offending(ns)
            ),
            Self::Name(name) => write!(
                f,
                "repository name `{}` is outside the name grammar; {URL_GRAMMARS}",
                escape_offending(name)
            ),
        }
    }
}

impl std::error::Error for UrlIdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Url(e) => Some(e),
            Self::Identity(e) => Some(e),
            Self::QueryOrFragment | Self::NonLiteralPath | Self::Namespace(_) | Self::Name(_) => {
                None
            }
        }
    }
}

/// The literal repository path text of `url`: the `mkit+` prefix stripped,
/// no non-empty query or fragment, and a path URL parsing leaves unchanged.
/// An empty path spells `default`.
fn repository_path_from_url(url: &str) -> Result<&str, UrlIdentityError> {
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
    Ok(if path.is_empty() { "default" } else { path })
}

/// Read the repository identity from a remote URL's literal path, in the
/// strict self-certifying grammar.
///
/// # Errors
/// Returns [`UrlIdentityError`] for an invalid URL, query, fragment or identity.
pub fn repository_identity_from_url(url: &str) -> Result<RepositoryIdentity, UrlIdentityError> {
    RepositoryIdentity::parse_bare_allowed(repository_path_from_url(url)?)
        .map_err(UrlIdentityError::Identity)
}

/// Read the remote repository identity from a remote URL's literal path, accepting
/// the union of the self-certifying and authority-mode namespace grammars
/// (SPEC-TRANSPORT-CONNECT §7.4).
///
/// # Errors
/// Returns [`UrlIdentityError`] for an invalid URL, query, fragment or
/// identity — [`UrlIdentityError::Namespace`] or [`UrlIdentityError::Name`]
/// name the offending segment.
pub fn remote_identity_from_url(url: &str) -> Result<RemoteIdentity, UrlIdentityError> {
    let text = repository_path_from_url(url)?;
    RemoteIdentity::parse_bare_allowed(text).map_err(|e| match e {
        IdentityError::Namespace => {
            UrlIdentityError::Namespace(text.split('/').next().unwrap_or(text).to_owned())
        }
        IdentityError::Name => UrlIdentityError::Name(
            text.split_once('/')
                .map_or(text, |(_, name)| name)
                .to_owned(),
        ),
        other => UrlIdentityError::Identity(other),
    })
}

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
#[cfg(test)]
const CHUNK_SIZE: usize = 800 * 1024;

/// Compatibility facade retaining synchronous transport and host policy configuration.
pub struct ConnectTransport {
    pub(crate) http: NativeHttp,
    pub(crate) session: ClientSession,
    server_info: OnceLock<ServerInfoView>,
    remote_identity: RemoteIdentity,
    pub(crate) repository: Option<RepositoryIdentity>,
    pub(crate) repository_text: String,
    pub(crate) origin: String,
    pub(crate) signer: Option<Arc<dyn EnvelopeSigner>>,
    pub(crate) signer_key: Option<String>,
    pub(crate) grant_source: Option<Arc<dyn GrantSource>>,
    pub(crate) unary_timeout: Duration,
    pub(crate) pack_transfer_timeout: Duration,
    pub(crate) backoff: fn() -> BackoffIterator,
    pub(crate) sleep: fn(Duration),
    pub(crate) now: fn() -> i64,
    pub(crate) pending_observer: Option<Arc<dyn Fn(PendingEvent) -> bool + Send + Sync>>,
    receipts: Arc<dyn PartReceiptStore>,
    pub(crate) upload_observer: Option<Arc<dyn Fn(UploadEvent) -> bool + Send + Sync>>,
    pub(crate) receipt_observer: Option<crate::receipt::ReceiptObserver>,
    pub(crate) admission_policy: Option<AdmissionPolicy>,
    pub(crate) admission_runs: AtomicUsize,
    pub(crate) token: Option<String>,
    #[cfg(test)]
    client: ConfigView,
}
#[cfg(test)]
struct ConfigView(ClientConfig);
#[cfg(test)]
impl ConfigView {
    fn config(&self) -> &ClientConfig {
        &self.0
    }
}
impl std::fmt::Debug for ConnectTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectTransport")
            .field("remote_identity", &self.remote_identity)
            .field("unary_timeout", &self.unary_timeout)
            .field("pack_transfer_timeout", &self.pack_transfer_timeout)
            .finish_non_exhaustive()
    }
}
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

/// Short, deterministic retry ladder for tests: 5 attempts, 1ms apart,
/// capped at 1ms. Mirrors `mkit-transport-http`'s `test_backoff`.
fn test_backoff() -> BackoffIterator {
    BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 5)
}

/// No-op sleep hook for tests — retry assertions run at full speed.
fn no_sleep(_delay: Duration) {}

/// Encode a [`RefWriteCondition`] into the wire `(expectation, expected_id)`
/// pair. Shared by every CAS-carrying request this client builds.
#[cfg(test)]
fn condition_to_wire(c: RefWriteCondition) -> (RefExpectation, Option<Vec<u8>>) {
    match c {
        RefWriteCondition::Any => (RefExpectation::Any, None),
        RefWriteCondition::Missing => (RefExpectation::Missing, None),
        RefWriteCondition::Match(h) => (RefExpectation::Match, Some(h.to_vec())),
    }
}

pub(crate) fn grant_condition(c: RefWriteCondition) -> GrantCondition {
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
    ///   or its path, query or fragment is not a valid remote identity;
    ///   [`remote_identity_from_url`] reports which.
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
        let identity =
            remote_identity_from_url(url).map_err(|_| TransportError::InvalidResponse)?;
        let http = if parsed.scheme() == "https" {
            NativeHttp::with_tls_config(crate::tls::client_config(ca_file)?.as_ref())
        } else {
            NativeHttp::new()
        }
        .map_err(|_| TransportError::ConnectionFailed)?;
        let token = env::var(TOKEN_ENV).ok().filter(|token| !token.is_empty());
        Ok(Self::new(
            http,
            parsed.origin().ascii_serialization(),
            identity,
            signer,
            token,
        ))
    }
    fn new(
        http: NativeHttp,
        origin: String,
        remote_identity: RemoteIdentity,
        signer: Option<Arc<dyn EnvelopeSigner>>,
        token: Option<String>,
    ) -> Self {
        let mut defaults = http::HeaderMap::new();
        if let Some(token) = &token
            && let Ok(mut value) = http::HeaderValue::from_str(&format!("Bearer {token}"))
        {
            value.set_sensitive(true);
            defaults.insert(http::header::AUTHORIZATION, value);
        }
        let http = http.with_default_headers(defaults);
        Self {
            http,
            session: ClientSession::default(),
            server_info: OnceLock::new(),
            repository: remote_identity.to_identity(),
            repository_text: remote_identity.to_string(),
            remote_identity,
            signer_key: signer.as_ref().map(|signer| signer.public_key_hex()),
            signer,
            origin: origin.clone(),
            token,
            grant_source: None,
            unary_timeout: UNARY_TIMEOUT,
            pack_transfer_timeout: PACK_TRANSFER_TIMEOUT,
            backoff: BackoffIterator::new,
            sleep: thread::sleep,
            now: crate::envelope::now_ms,
            pending_observer: None,
            receipts: Arc::new(MemoryPartReceiptStore::default()),
            upload_observer: None,
            receipt_observer: None,
            admission_policy: None,
            admission_runs: AtomicUsize::new(0),
            #[cfg(test)]
            client: ConfigView(ClientConfig::new(
                format!("{origin}/").parse().expect("validated origin"),
            )),
        }
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
        let origin = format!(
            "{}://{}",
            base_uri.scheme_str().unwrap_or("http"),
            base_uri.authority().expect("test authority")
        );
        let identity = remote_identity_from_url(&base_uri.to_string()).expect("test identity");
        let mut value = Self::new(
            NativeHttp::new()
                .expect("test native client")
                .allow_insecure_http(true),
            origin,
            identity,
            signer,
            None,
        );
        value.backoff = test_backoff;
        value.sleep = no_sleep;
        value
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
        Self::connect_for_test(base_uri).with_retry_hooks_for_test(backoff, sleep)
    }
    /// The auth v2 audience this transport signs for: its origin.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
    /// The remote repository identity this transport addresses, in the
    /// union of the two namespace grammars.
    #[must_use]
    pub fn remote_identity(&self) -> &RemoteIdentity {
        &self.remote_identity
    }
    /// The strict self-certifying identity of the addressed repository, or
    /// `None` when it lives in an opaque authority-mode namespace. Grants,
    /// grant epochs and owner statements need a self-certifying namespace;
    /// anything else should use [`Self::remote_identity`].
    #[must_use]
    pub fn repository(&self) -> Option<&RepositoryIdentity> {
        self.repository.as_ref()
    }
    /// Override the per-call timeout applied to cheap unary RPCs
    /// (`ListRefs`, `ReadRef`, `UpdateRef`, `AdvanceRefs`, `PackExists`).
    /// Defaults to [`UNARY_TIMEOUT`]. Independent of
    /// [`Self::with_pack_transfer_timeout`] — changing one does not affect
    /// the other.
    #[must_use]
    pub fn with_unary_timeout(mut self, timeout: Duration) -> Self {
        self.unary_timeout = timeout;
        self.http = self.http.with_metadata_timeout(timeout);
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
        self.http = self.http.with_transfer_timeout(timeout);
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
        observer: impl Fn(&crate::receipt::AdmissionReceipt) + Send + Sync + 'static,
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
    /// Borrow a configured native source for a complete synchronous operation.
    /// The session keeps tickets and capability discovery across calls.
    /// # Errors
    /// Returns configuration or session-binding failures before calling `operation`.
    pub fn with_source<R>(
        &self,
        operation: impl FnOnce(&dyn RemoteSource) -> R,
    ) -> TransportResult<R> {
        self.with_client_source_deadline(None, |source, policy| {
            Ok(operation(&super::host::HostSource(source, policy)))
        })
    }
    fn with_client_source<R>(
        &self,
        operation: impl FnOnce(
            &ClientSource<
                '_,
                NativeHttp,
                HostSigner<'_>,
                HostClock,
                NativeHttp,
                mkit_client::NoObserver,
                HostPolicy<'_>,
                HostPolicy<'_>,
            >,
        ) -> Result<R, SourceError>,
    ) -> TransportResult<R> {
        self.with_client_source_deadline(None, |source, _policy| operation(source))
    }
    fn with_client_source_deadline<R>(
        &self,
        deadline: Option<i64>,
        operation: impl FnOnce(
            &ClientSource<
                '_,
                NativeHttp,
                HostSigner<'_>,
                HostClock,
                NativeHttp,
                mkit_client::NoObserver,
                HostPolicy<'_>,
                HostPolicy<'_>,
            >,
            &HostPolicy<'_>,
        ) -> Result<R, SourceError>,
    ) -> TransportResult<R> {
        let signer = HostSigner::new(self.signer.as_deref())?;
        let clock = HostClock(self.now);
        let policy = HostPolicy::new(self);
        policy.set_deadline(deadline);
        let destination = Destination::new(self.origin.clone(), self.repository_text.clone())
            .map_err(|_| TransportError::InvalidResponse)?;
        let client = if self.signer.is_some() {
            Client::signed(&self.http, destination, &signer, &clock)
        } else {
            Client::unsigned(&self.http, destination)
                .with_unsigned_clock(&clock)
                .with_unsigned_writes()
        }
        .with_request_policy(&policy);
        let source = ClientSource::new(&client, &self.http)
            .with_session(&self.session)
            .map_err(|error| map_source(error, false))?
            .with_receipt_store(Arc::clone(&self.receipts))
            .with_write_recovery(&policy);
        let result = operation(&source, &policy).map_err(|error| policy.map_failure(error));
        policy.finished(false);
        result
    }
    /// Discover and cache deployment capabilities for this instance's lifetime.
    /// Legacy and failed discovery stay conservative, even if the server changes.
    pub fn server_info(&self) -> &ServerInfoView {
        self.server_info.get_or_init(|| {
            self.with_client_source(|source| {
                Ok(match source.server_info() {
                    Some(info) => ServerInfoView::V2(Box::new(info)),
                    None if source.discovery_is_legacy() => ServerInfoView::Legacy,
                    None => ServerInfoView::Unknown,
                })
            })
            .unwrap_or(ServerInfoView::Unknown)
        })
    }
    /// List refs with a caller's lower page cap, clamped to 100,000 pages.
    /// The cursor and retained-state limits stay fixed.
    ///
    /// # Errors
    /// Transport errors or `InvalidResponse` for invalid or excessive listings.
    pub fn list_refs_with_page_limit(
        &self,
        prefix: &str,
        max_pages: u32,
    ) -> TransportResult<Vec<Ref>> {
        self.with_client_source(|source| source.list_refs_with_page_limit(prefix, max_pages))
    }
    /// Poll a ticket-consuming advance until it commits or `deadline` expires.
    /// WP-1.17 passes the earliest consumed ticket expiry here. Until then,
    /// the maximum seven-day ticket lifetime bounds calls with no deadline.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn advance_refs_with_deadline(
        &self,
        head: &str,
        head_condition: RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: RefWriteCondition,
        node: &Hash,
        deadline: Option<i64>,
    ) -> TransportResult<CoreAdvanceOutcome> {
        self.with_client_source_deadline(deadline, |source, _policy| {
            source.advance_refs_with_deadline(
                head,
                head_condition,
                tip,
                packmap,
                packmap_condition,
                node,
                deadline,
            )
        })
    }
    fn with_client<R>(
        &self,
        operation: impl FnOnce(
            &Client<
                '_,
                NativeHttp,
                HostSigner<'_>,
                HostClock,
                mkit_client::NoObserver,
                HostPolicy<'_>,
            >,
        ) -> Result<R, mkit_client::Error>,
    ) -> TransportResult<Completion<R>> {
        let signer = HostSigner::new(self.signer.as_deref())?;
        let clock = HostClock(self.now);
        let policy = HostPolicy::new(self);
        let destination = Destination::new(self.origin.clone(), self.repository_text.clone())
            .map_err(|_| TransportError::InvalidResponse)?;
        let client = if self.signer.is_some() {
            Client::signed(&self.http, destination, &signer, &clock)
        } else {
            Client::unsigned(&self.http, destination)
        }
        .with_request_policy(&policy);
        match operation(&client) {
            Ok(value) => Ok(Completion::Done(value)),
            Err(mkit_client::Error::RetryAfter { ms }) => Ok(Completion::Pending {
                retry_after: Duration::from_millis(ms),
            }),
            Err(mkit_client::Error::Remote(remote))
                if remote.code == "unavailable" && remote.headers.contains_key("retry-after") =>
            {
                Ok(Completion::Pending {
                    retry_after: crate::error::parse_retry_after(
                        &remote
                            .headers
                            .get_all("retry-after")
                            .iter()
                            .filter_map(|v| v.to_str().ok().map(str::to_owned))
                            .collect::<Vec<_>>(),
                    ),
                })
            }
            Err(error) => Err(policy.map_client_failure(error)),
        }
    }
    /// One `GetGrantEpoch` attempt, without the retry ladder: for advisory
    /// reads that must fail fast.
    ///
    /// # Errors
    ///
    /// As [`Self::get_grant_epoch`], on the first failure.
    pub fn get_grant_epoch_once(&self, namespace: &str) -> TransportResult<Completion<u64>> {
        self.with_client(|client| {
            self.http
                .block_on(client.get_grant_epoch(namespace))
                .map(|reply| reply.value)
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
        self.retrying(|| self.get_grant_epoch_once(namespace))
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
    pub fn set_grant_epoch(&self, statement: &str) -> TransportResult<Completion<u64>> {
        self.retrying(|| {
            self.with_client(|client| {
                self.http
                    .block_on(client.set_grant_epoch(statement))
                    .map(|reply| reply.value)
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
        if matches!(request, VisibilityRequest::Envelope(_)) && self.signer.is_none() {
            return Err(TransportError::RemoteError(
                "envelope-mode SetRepoVisibility needs a signing identity".into(),
            ));
        }
        let identity = if matches!(request, VisibilityRequest::Envelope(_)) {
            let now = (self.now)();
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce)
                .map_err(|error| TransportError::RemoteError(error.to_string()))?;
            Some(mkit_client::Identity::new(
                nonce,
                now,
                now.saturating_add(mkit_core::write_auth::MAX_VALIDITY_MS),
            ))
        } else {
            None
        };
        self.retrying(|| {
            self.with_client(|client| match request {
                VisibilityRequest::Statement(statement) => self
                    .http
                    .block_on(client.visibility_statement(statement))
                    .map(|reply| reply.value),
                VisibilityRequest::Envelope(choice) => self
                    .http
                    .block_on(client.set_repo_visibility(
                        match choice {
                            VisibilityChoice::Public => mkit_client::Visibility::Public,
                            VisibilityChoice::Private => mkit_client::Visibility::Private,
                        },
                        identity.as_ref(),
                    ))
                    .map(|reply| reply.value),
            })
        })
    }
    fn retrying<T>(&self, operation: impl FnMut() -> TransportResult<T>) -> TransportResult<T> {
        mkit_core::protocol::retrying(operation, self.backoff, self.sleep)
    }
    #[cfg(test)]
    fn grant_options(&self, options: CallOptions, operation: GrantOperation<'_>) -> CallOptions {
        match super::host::select_grant(self, operation) {
            Some(grant) => options.with_header("x-write-grant", grant),
            None => options,
        }
    }
    #[cfg(test)]
    fn read_options(&self, options: CallOptions) -> TransportResult<CallOptions> {
        if self.signer_key.is_none() {
            Ok(options)
        } else {
            Ok(RetryIdentity::new()
                .map_err(TransportError::RemoteError)?
                .apply(self.grant_options(options, GrantOperation::Read)))
        }
    }
}
impl Transport for ConnectTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.with_client_source(|source| source.upload_pack_unhinted(bytes, key))
            .map_err(super::host::upload_error)
    }
    fn upload_pack_via_ref(&self, bytes: &[u8], key: &PackKey, name: &str) -> TransportResult<()> {
        self.with_client_source(|source| source.upload_pack_via_ref(bytes, key, name))
            .map_err(super::host::upload_error)
    }
    fn upload_blob_via_ref(&self, bytes: &[u8], key: &PackKey, name: &str) -> TransportResult<()> {
        self.upload_pack_via_ref(bytes, key, name)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.with_client_source(|source| source.download_pack_unhinted(key))
    }
    fn download_pack_via_ref(&self, key: &PackKey, name: &str) -> TransportResult<Vec<u8>> {
        self.with_client_source(|source| source.download_pack_via_ref(key, name))
    }
    fn download_blob_via_ref(&self, key: &PackKey, name: &str) -> TransportResult<Vec<u8>> {
        self.download_pack_via_ref(key, name)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.with_client_source(|source| source.pack_exists(key))
    }
    fn pack_exists_via_ref(&self, key: &PackKey, name: &str) -> TransportResult<bool> {
        self.with_client_source(|source| source.pack_exists_via_ref(key, name))
    }
    fn repository_address(&self) -> Option<RepositoryAddress<'_>> {
        Some(RepositoryAddress::new(&self.repository_text, &self.origin))
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        tip: &Hash,
    ) -> TransportResult<()> {
        self.with_client_source(|source| source.update_ref(name, condition, tip))
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.with_client_source(|source| source.read_ref(name))
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.list_refs_with_page_limit(prefix, mkit_core::ref_listing::MAX_PAGES)
    }
    fn advance_refs(
        &self,
        head: &str,
        head_condition: RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: RefWriteCondition,
        node: &Hash,
    ) -> TransportResult<CoreAdvanceOutcome> {
        self.advance_refs_with_deadline(
            head,
            head_condition,
            tip,
            packmap,
            packmap_condition,
            node,
            None,
        )
    }
    fn advance_refs_committing(
        &self,
        head: &str,
        head_condition: RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        packmap_condition: RefWriteCondition,
        node: &Hash,
        keys: &[PackKey],
    ) -> TransportResult<CommitOutcome> {
        self.with_client_source(|source| {
            source.advance_refs_committing(
                head,
                head_condition,
                tip,
                packmap,
                packmap_condition,
                node,
                keys,
            )
        })
    }
    fn upload_limits(&self) -> UploadLimits {
        self.with_client_source(|source| Ok(source.upload_limits()))
            .unwrap_or_default()
    }
    fn supports_atomic_advance(&self) -> bool {
        self.with_client_source(|source| Ok(source.supports_atomic_advance()))
            .unwrap_or(false)
    }

    fn atomic_advance_status(&self) -> Option<bool> {
        self.with_client_source(|source| Ok(source.atomic_advance_status()))
            .ok()
            .flatten()
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
        // `ns` is a valid authority-mode namespace, so the strict identity
        // parser refuses it while the union address parser accepts it.
        let opaque_url = "mkit+https://example.invalid/ns/name";
        assert!(repository_identity_from_url(opaque_url).is_err());
        assert!(remote_identity_from_url(opaque_url).is_ok());
        assert!(ConnectTransport::connect(opaque_url).is_ok());
        for path in [
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

    #[test]
    fn url_remote_identity_table_accepts_authority_mode_namespaces() {
        let ns = format!("ed25519-{}", "ab".repeat(32));
        let uuid = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
        for (path, expected) in [
            ("".to_owned(), "default".to_owned()),
            (format!("/{uuid}/public"), format!("{uuid}/public")),
            (format!("/{uuid}/public/"), format!("{uuid}/public")),
            (format!("/{ns}/name"), format!("{ns}/name")),
        ] {
            let url = format!("mkit+https://example.invalid{path}");
            let remote = remote_identity_from_url(&url).unwrap();
            assert_eq!(remote.to_string(), expected);
            assert_eq!(
                remote.to_identity().is_some(),
                expected == format!("{ns}/name") || expected == "default"
            );
        }
        // The union is also the identity grammar for `connect`.
        let t = ConnectTransport::connect(&format!("mkit+https://example.invalid/{uuid}/public"))
            .unwrap();
        assert_eq!(t.remote_identity().to_string(), format!("{uuid}/public"));
        assert!(t.repository().is_none());
        assert_eq!(t.repository_text, format!("{uuid}/public"));
        let t =
            ConnectTransport::connect(&format!("mkit+https://example.invalid/{ns}/name")).unwrap();
        assert_eq!(
            t.repository().map(ToString::to_string),
            Some(format!("{ns}/name"))
        );
    }

    #[test]
    fn url_remote_identity_errors_name_the_offending_segment() {
        let uuid = "019c88c3-a904-7bd1-8a5d-3182a0c6978a";
        let err = remote_identity_from_url("mkit+https://example.invalid/Bad/repo")
            .unwrap_err()
            .to_string();
        for needle in ["`Bad`", "ed25519-", "[a-z0-9][a-z0-9._-]{0,71}", "§7.4"] {
            assert!(err.contains(needle), "{err} missing {needle}");
        }
        let err = remote_identity_from_url(&format!("mkit+https://example.invalid/{uuid}/Repo"))
            .unwrap_err()
            .to_string();
        for needle in ["`Repo`", "§7.4"] {
            assert!(err.contains(needle), "{err} missing {needle}");
        }
        // Offending bytes URL parsing preserves are escaped, not echoed raw.
        let err = remote_identity_from_url("mkit+https://example.invalid/a'b/repo")
            .unwrap_err()
            .to_string();
        assert!(err.contains("a\\'b"), "{err}");
        assert_eq!(escape_offending("a\u{7}b"), "a\\u{7}b");
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
