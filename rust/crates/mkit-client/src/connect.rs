use crate::seams::{
    Attempt, FailureDiagnostic, FailureKind, FailureObserver, NoObserver, NoRequestPolicy,
    Observer, RequestContext, RequestPolicy, ResponseProfile, SignError, SigningRequest,
    UnsignedRequestContext, WriteIntent,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use buffa::Message;
use http::{HeaderMap, HeaderValue, Request, Response};
use mkit_core::{
    admission::{MAX_CHALLENGES, MAX_DESCRIPTION_BYTES, MAX_VALUE_BYTES, validate_challenges},
    hash::{Hash, hash, to_hex},
    protocol::{AdmissionChallengeEntry, AdmissionRequired},
    write_auth::{ContentCommitment, Context, MAX_VALIDITY_MS, Operation},
};
use serde::Deserialize;
use std::time::Duration;

const SERVICE: &str = "/mkit.transport.v1.TransportService/";
const DOWNLOAD_PACK: &str = "/mkit.transport.v1.TransportService/DownloadPack";
/// Default cap on one buffered HTTP response.
pub(crate) const RESPONSE_LIMIT: usize = 1024 * 1024;
/// A `ListRefs` page is at most 2 MiB when encoded (SPEC-TRANSPORT-CONNECT §7.9).
pub(crate) const LIST_REFS_LIMIT: usize = 2 * 1024 * 1024;
const CHALLENGE_TYPE: &str = "mkit.transport.v1.AdmissionChallenge";
const PENDING_TYPE: &str = "mkit.transport.v1.PendingVerification";
const MEMBERSHIP_TYPE: &str = "mkit.transport.v1.MembershipNotVisible";
/// Public message older servers send for a membership lag without the typed
/// detail. Only the fallback in [`membership_lag`] reads it.
const MEMBERSHIP_LAG: &str = "repository membership not yet visible";

/// Injectable HTTP channel. Bound the response while receiving it, refuse
/// redirects, and retain the exact request for any ambiguous retry. Transport
/// errors must never be disguised as a successful or pending RPC response.
#[allow(async_fn_in_trait)]
pub trait HttpTransport {
    async fn send(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
    ) -> Result<Response<Vec<u8>>, String>;

    /// Whether this channel can fetch pack locations without RPC credentials.
    /// Channels without an implementation, including browser hosts, do not
    /// opt in. A host must also refuse redirects and bound response bytes.
    fn supports_pack_locations(&self) -> bool {
        false
    }

    /// Explicit test-host override for loopback HTTP fixtures. Production
    /// channels keep this false and require HTTPS locations.
    #[doc(hidden)]
    fn allows_test_pack_location_http(&self) -> bool {
        false
    }

    /// Fetch a location with a fresh credential-free GET. Never apply RPC
    /// policies, auth-v2 headers, tokens, cookies, or default credentials.
    /// HTTPS is required; loopback HTTP is reserved for test hosts. The local
    /// timeout must be clamped to the channel timeout and must not become a header.
    ///
    /// # Errors
    /// A fetch, protocol, timeout, or response-size failure.
    async fn fetch_pack_location(
        &self,
        _url: &str,
        _response_limit: usize,
        _timeout: Option<Duration>,
    ) -> Result<Vec<u8>, String> {
        Err("pack locations are unsupported".into())
    }

    /// Exchange a buffered request with optional host failure diagnostics.
    /// The concrete diagnostic type preserves conditional future thread safety.
    ///
    /// # Errors
    /// Returns classified channel failures, optionally mapped by the observer.
    async fn send_diagnosed<D: FailureObserver + ?Sized>(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
        observer: &D,
    ) -> Result<Response<Vec<u8>>, Error> {
        let procedure = request.uri().path().to_owned();
        self.send_classified(request, response_limit)
            .await
            .map_err(|failure| {
                let cause = failure.to_string();
                observer
                    .map_failure(&FailureDiagnostic {
                        procedure: &procedure,
                        kind: FailureKind::Channel,
                        status: None,
                        headers: None,
                        body: None,
                        parsed_error: None,
                        cause: &cause,
                        limit: Some(response_limit),
                    })
                    .unwrap_or_else(|| channel_error(failure))
            })
    }

    /// Exchange a pulled body with optional host failure diagnostics.
    /// Existing channels keep their streaming or buffered implementation.
    /// Concrete body, sink and diagnostic types preserve conditional future
    /// thread safety; explicitly erased or local callbacks remain supported.
    ///
    /// # Errors
    /// Returns channel or callback failures.
    async fn send_stream_diagnosed<
        B: crate::RequestStream + ?Sized,
        S: crate::ResponseStream + ?Sized,
        D: FailureObserver + ?Sized,
    >(
        &self,
        request: Request<()>,
        body: &mut B,
        response_limit: usize,
        sink: &mut S,
        _observer: &D,
    ) -> Result<(), Error> {
        self.send_stream(request, body, response_limit, sink).await
    }

    /// Exchange a pulled request body and incrementally deliver the decoded
    /// response. The default buffers both sides through `send_classified`;
    /// native channels can override it to retain only bounded chunks.
    ///
    /// # Errors
    /// Returns channel failures or the request/response callback's typed error.
    async fn send_stream<B: crate::RequestStream + ?Sized, S: crate::ResponseStream + ?Sized>(
        &self,
        request: Request<()>,
        body: &mut B,
        response_limit: usize,
        sink: &mut S,
    ) -> Result<(), Error> {
        crate::stream::buffered(self, request, body, response_limit, sink).await
    }

    /// Classify channel failures without inferring retry safety from messages.
    /// Existing channels remain terminal unless they explicitly classify an I/O
    /// failure as transient. The host still decides whether and when to retry.
    ///
    /// # Errors
    /// Returns a classified channel failure when the exchange cannot complete.
    async fn send_classified(
        &self,
        request: Request<Vec<u8>>,
        response_limit: usize,
    ) -> Result<Response<Vec<u8>>, ChannelError> {
        self.send(request, response_limit)
            .await
            .map_err(ChannelError::Refused)
    }
}

/// Host-supplied I/O bound carried locally in HTTP request extensions. Channels
/// that support it shorten their configured budget; it never appears on wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTimeout(pub Duration);

/// Request extension asking a native channel to advertise its effective I/O
/// budget. The marker alone supplies no timeout and does not change signatures.
#[derive(Clone, Copy, Debug)]
pub struct AdvertiseRequestTimeout;

fn verify_location_download(bytes: &[u8], key: &Hash) -> Result<(), Error> {
    if mkit_core::pack::pack_key(bytes) != *key {
        return Err(Error::Invalid("pack content commitment"));
    }
    Ok(())
}

fn channel_error(error: ChannelError) -> Error {
    match error {
        ChannelError::Transient(cause) => Error::Connection(cause),
        ChannelError::TimedOut(cause) => Error::RequestTimeout(cause),
        ChannelError::Refused(cause) => Error::Transport(cause),
    }
}

struct PolicyObserver<'a, P: RequestPolicy + ?Sized> {
    policy: Option<&'a P>,
    procedure: &'a str,
}
impl<P: RequestPolicy + ?Sized> FailureObserver for PolicyObserver<'_, P> {
    fn map_failure(&self, failure: &FailureDiagnostic<'_>) -> Option<Error> {
        self.policy.and_then(|policy| {
            policy.map_failure(&FailureDiagnostic {
                procedure: self.procedure,
                ..*failure
            })
        })
    }
    fn response_profile(&self) -> ResponseProfile {
        self.policy.map_or_else(ResponseProfile::default, |policy| {
            policy.response_profile(self.procedure)
        })
    }
}

/// A channel's explicit distinction between exchange failures and refusals.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChannelError {
    /// A connection or response-body I/O failure. Its request may have
    /// reached the server; a retry must retain the authenticated identity.
    #[error("{0}")]
    Transient(String),
    /// The per-request I/O budget ended. This is terminal for the channel's
    /// logical call; a host may decide to start another operation.
    #[error("{0}")]
    TimedOut(String),
    /// A security, negotiation, framing or resource-bound refusal. Repeating
    /// the request unchanged cannot be assumed safe or useful.
    #[error("{0}")]
    Refused(String),
}

/// Host-owned epoch clock, secure entropy and scheduling. No runtime or
/// platform clock is used by the primitive.
#[allow(async_fn_in_trait)]
pub trait Clock {
    fn now_ms(&self) -> i64;
    fn nonce(&self) -> Result<Hash, String>;
    async fn wait(&self, duration: Duration);
}

/// An async Ed25519 signer (the digest has already been domain separated).
///
/// The client calls [`Signer::sign_operation`], which receives the structured
/// operation next to the digest. Its default delegates to [`Signer::sign`], so a
/// plain digest signer keeps working; override it to enforce what a key may
/// sign.
#[allow(async_fn_in_trait)]
pub trait Signer {
    fn public_key(&self) -> [u8; 32];
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String>;

    /// Sign `digest`, the domain separated digest of `request`. Refuse with
    /// [`SignError::Refused`] to block this operation only.
    ///
    /// # Errors
    /// A refusal, or a failure to sign.
    async fn sign_operation(
        &self,
        request: &SigningRequest<'_>,
        digest: &Hash,
    ) -> Result<[u8; 64], SignError> {
        let _ = request;
        Ok(self.sign(digest).await?)
    }
}

/// Destination identity bound into every signature. The origin must be
/// canonical (no credentials, query, fragment, path or default port).
#[derive(Clone, Debug)]
pub struct Destination {
    pub(crate) origin: String,
    pub(crate) repository: String,
}
impl Destination {
    pub fn new(origin: String, repository: String) -> Result<Self, Error> {
        mkit_core::write_auth::validate_audience(&origin)
            .map_err(|_| Error::Invalid("canonical origin"))?;
        mkit_core::repo_identity::RemoteIdentity::parse_bare_allowed(&repository)
            .map_err(|_| Error::Invalid("repository identity"))?;
        Ok(Self { origin, repository })
    }
    /// The canonical origin every request is sent to and signed for.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The repository identity every request addresses.
    #[must_use]
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Discover canonical capabilities before preparing a bounded plan.
    pub async fn server_info<T: HttpTransport>(
        &self,
        transport: &T,
    ) -> Result<crate::proto::GetServerInfoResponse, Error> {
        let request = self.info_request()?;
        let (bytes, _) = send_checked(transport, request, RESPONSE_LIMIT).await?;
        crate::proto::GetServerInfoResponse::decode_from_slice(&bytes)
            .map_err(|_| Error::Invalid("server info protobuf"))
    }

    /// An unsigned Connect request for `method`.
    pub(crate) fn plain_request(
        &self,
        method: &str,
        body: Vec<u8>,
        streaming: bool,
    ) -> Result<Request<Vec<u8>>, Error> {
        Request::post(format!("{}{SERVICE}{method}", self.origin))
            .header(
                "content-type",
                if streaming {
                    "application/connect+proto"
                } else {
                    "application/proto"
                },
            )
            .header("connect-protocol-version", "1")
            .header("x-repository", &self.repository)
            .body(body)
            .map_err(|_| Error::Invalid("HTTP request"))
    }

    pub(crate) fn info_request(&self) -> Result<Request<Vec<u8>>, Error> {
        Request::post(format!("{}{SERVICE}GetServerInfo", self.origin))
            .header("content-type", "application/proto")
            .header("connect-protocol-version", "1")
            .header("x-repository", &self.repository)
            .body(Vec::new())
            .map_err(|_| Error::Invalid("HTTP request"))
    }
}

/// Connect error details remain available to host admission/policy code.
#[derive(Clone, Debug, Deserialize)]
pub struct Detail {
    #[serde(rename = "type")]
    pub type_url: String,
    pub value: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct RemoteError {
    pub code: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub details: Vec<Detail>,
    #[serde(skip)]
    pub status: u16,
    #[serde(skip)]
    pub headers: HeaderMap,
}

/// Request identity of one signed call: the nonce (which is also the
/// `Idempotency-Key`) and its validity window. A caller that persists it can
/// replay the same call after a restart; the server then answers from its saved
/// reply instead of applying the operation again (SPEC-TRANSPORT-CONNECT §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Identity {
    pub nonce: Hash,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}
impl Identity {
    /// Restore an identity, for example one persisted before a restart.
    #[must_use]
    pub fn new(nonce: Hash, created_at_ms: i64, expires_at_ms: i64) -> Self {
        Self {
            nonce,
            created_at_ms,
            expires_at_ms,
        }
    }

    /// The `Idempotency-Key` header value: the nonce as 64 lowercase hex.
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        to_hex(&self.nonce)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        let window = self.expires_at_ms.saturating_sub(self.created_at_ms);
        if window <= 0 || window > MAX_VALIDITY_MS {
            return Err(Error::Invalid("identity validity window"));
        }
        Ok(())
    }
}

/// A successful per-RPC result with the identity the request used. The identity
/// is `None` for unclocked unsigned calls, reads without signing and discovery.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Reply<R> {
    pub value: R,
    pub identity: Option<Identity>,
}

/// Failures. Per-RPC calls return the typed, resumable outcomes
/// ([`Error::PendingVerification`], [`Error::MembershipNotVisible`],
/// [`Error::RetryAfter`], [`Error::PaymentRequired`]) instead of waiting.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("limit: {0}")]
    Limit(&'static str),
    #[error("invalid response/input: {0}")]
    Invalid(&'static str),
    #[error("transport: {0}")]
    Transport(String),
    /// An explicitly transient channel failure. Scheduling remains host-owned.
    #[error("transport: {0}")]
    Connection(String),
    /// The channel's request budget expired, without an automatic retry.
    #[error("transport: {0}")]
    RequestTimeout(String),
    #[error("signing: {0}")]
    Signing(String),
    #[error("Connect {0:?}")]
    Remote(Box<RemoteError>),
    #[error("pack: {0}")]
    Pack(#[from] mkit_core::pack::PackError),
    #[error("packlist: {0}")]
    Packlist(#[from] mkit_core::transfer::PackListError),
    #[error("push deadline expired")]
    Deadline,
    /// The signed validity window ended before dispatch; nothing was sent.
    #[error("signed request expired before dispatch")]
    EnvelopeExpired,
    /// The [`Observer`] vetoed a write; nothing was signed or sent.
    #[error("write vetoed: {0}")]
    Vetoed(String),
    /// The [`Signer`] refused the operation; nothing was sent.
    #[error("signer refused: {0}")]
    SignerRefused(String),
    /// An observer returned a hard-reserved request header
    /// (SPEC-TRANSPORT-CONNECT section 5.1); nothing was signed or sent.
    #[error("reserved request header `{0}`")]
    ReservedHeader(String),
    /// The server requires an out-of-protocol action (STC §5.1). Every
    /// challenge is carried, in the server's order; the raw `WWW-Authenticate`
    /// and `PAYMENT-REQUIRED` values ride along for an admission helper. A 402
    /// without a Connect body still yields this, with no challenges.
    #[error("{0}")]
    PaymentRequired(Box<AdmissionRequired>),
    /// A consumed pack is still under verification; ask again after the hint.
    #[error("verification pending, retry after {retry_after:?}")]
    PendingVerification { retry_after: Duration },
    /// A ticket's repository membership is not visible yet (index lag).
    #[error("repository membership not yet visible")]
    MembershipNotVisible,
    /// `unavailable` with a `Retry-After` hint, clamped to 1-60 s.
    #[error("retry after {ms} ms")]
    RetryAfter { ms: u64 },
    #[error("object sink: {0}")]
    Sink(String),
    #[error("object {id} rejected: {reason}")]
    Signature { id: String, reason: String },
}

impl Error {
    /// True for a failed CAS precondition (`failed_precondition`).
    #[must_use]
    pub fn is_ref_conflict(&self) -> bool {
        matches!(self, Self::Remote(error) if error.code == "failed_precondition")
    }

    /// Map a raw remote error onto its typed, resumable outcome. Other errors
    /// pass through. Whole-push code keeps the raw form and waits itself.
    pub(crate) fn typed(self) -> Self {
        let Self::Remote(error) = self else {
            return self;
        };
        if let Some(retry_after) = pending_delay(&error) {
            return Self::PendingVerification { retry_after };
        }
        if error.code == "unavailable" {
            if membership_lag(&error) {
                return Self::MembershipNotVisible;
            }
            if let Some(ms) = retry_after_ms(&error.headers) {
                return Self::RetryAfter { ms };
            }
        }
        Self::Remote(error)
    }
}

pub(crate) struct Rpc<'a, T, S, C, O = NoObserver, P: ?Sized = NoRequestPolicy> {
    pub(crate) transport: &'a T,
    /// `None` makes every request anonymous.
    pub(crate) auth: Option<(&'a S, &'a C)>,
    pub(crate) unsigned_clock: Option<&'a C>,
    pub(crate) observer: &'a O,
    pub(crate) request_policy: Option<&'a P>,
    pub(crate) destination: &'a Destination,
    pub(crate) deadline_ms: i64,
    pub(crate) location_lifetime: Option<&'a std::sync::OnceLock<Option<u64>>>,
}

/// Per-call options: a caller-owned identity, an optional `X-Mkit-Ref` hint
/// (STC §7.9) and the response cap.
#[derive(Clone, Copy)]
pub(crate) struct Opts<'a> {
    pub(crate) identity: Option<&'a Identity>,
    pub(crate) hint: Option<&'a str>,
    pub(crate) limit: usize,
    /// One local budget shared by location negotiation, fetch and streaming fallback.
    pub(crate) local_budget: Option<(std::time::Instant, Duration)>,
    /// Present for write RPCs: what the observer is told before the attempt.
    pub(crate) intent: Option<&'a WriteIntent<'a>>,
}
impl Default for Opts<'_> {
    fn default() -> Self {
        Self {
            identity: None,
            hint: None,
            limit: RESPONSE_LIMIT,
            local_budget: None,
            intent: None,
        }
    }
}

/// A built request and the identity it carries.
pub(crate) struct Built {
    pub(crate) request: Request<Vec<u8>>,
    pub(crate) identity: Option<Identity>,
}

/// The result of the signing pipeline.
pub(crate) struct Signed {
    pub(crate) headers: HeaderMap,
    pub(crate) identity: Identity,
}

type Raw = (Vec<u8>, HeaderMap, Option<Identity>, http::StatusCode);

impl<'a, T, S, C> Rpc<'a, T, S, C> {
    pub(crate) fn signed(
        transport: &'a T,
        signer: &'a S,
        clock: &'a C,
        destination: &'a Destination,
        deadline_ms: i64,
    ) -> Self {
        Self {
            transport,
            auth: Some((signer, clock)),
            unsigned_clock: None,
            observer: &NoObserver,
            request_policy: None,
            destination,
            deadline_ms,
            location_lifetime: None,
        }
    }
}

impl<'a, T, S, C, O, P: ?Sized> Rpc<'a, T, S, C, O, P> {
    pub(crate) fn observed<Q: Observer>(self, observer: &'a Q) -> Rpc<'a, T, S, C, Q, P> {
        Rpc {
            transport: self.transport,
            auth: self.auth,
            unsigned_clock: self.unsigned_clock,
            observer,
            request_policy: self.request_policy,
            destination: self.destination,
            deadline_ms: self.deadline_ms,
            location_lifetime: self.location_lifetime,
        }
    }
}

impl<T: HttpTransport, S: Signer, C: Clock, O: Observer, P: RequestPolicy + ?Sized>
    Rpc<'_, T, S, C, O, P>
{
    pub(crate) async fn unary<Q: Message, R: Message + Default>(
        &self,
        method: &str,
        message: &Q,
    ) -> Result<R, Error> {
        Ok(self.unary_with(method, message, Opts::default()).await?.0)
    }

    pub(crate) async fn unary_with<Q: Message, R: Message + Default>(
        &self,
        method: &str,
        message: &Q,
        opts: Opts<'_>,
    ) -> Result<(R, Option<Identity>), Error> {
        let body = message.encode_to_vec();
        let commitment = format!("body:{}", to_hex(&hash(&body)));
        let (bytes, headers, identity, status) =
            self.call(method, body, &commitment, false, opts).await?;
        let value = self.decode_message(method, &bytes, &headers, status)?;
        Ok((value, identity))
    }

    /// Owner statements and deployment epochs intentionally carry no envelope.
    pub(crate) async fn unsigned_unary<Q: Message, R: Message + Default>(
        &self,
        method: &str,
        message: &Q,
        include_repository: bool,
    ) -> Result<(R, Option<Identity>), Error> {
        let unsigned = Self {
            transport: self.transport,
            auth: None,
            unsigned_clock: None,
            observer: self.observer,
            request_policy: self.request_policy,
            destination: self.destination,
            deadline_ms: self.deadline_ms,
            location_lifetime: self.location_lifetime,
        };
        let body = message.encode_to_vec();
        let commitment = format!("body:{}", to_hex(&hash(&body)));
        let mut request = unsigned
            .build(method, body, &commitment, false, Opts::default(), 1)
            .await?
            .request;
        if !include_repository {
            request.headers_mut().remove("x-repository");
        }
        let (bytes, headers, status) = unsigned.send_response(&request, RESPONSE_LIMIT).await?;
        if let Some(policy) = self.request_policy {
            let procedure = format!("{SERVICE}{method}");
            policy.after_unsigned_response(
                &UnsignedRequestContext {
                    procedure: &procedure,
                    audience: &self.destination.origin,
                    repository: &self.destination.repository,
                    intent: None,
                },
                &headers,
            );
        }
        let value = self.decode_message(method, &bytes, &headers, status)?;
        Ok((value, None))
    }

    pub(crate) async fn stream_with<Q: Message, R: Message + Default>(
        &self,
        method: &str,
        messages: impl IntoIterator<Item = Q>,
        commitment: &str,
        opts: Opts<'_>,
    ) -> Result<(R, Option<Identity>), Error> {
        let opts = self.response_options(method, opts);
        let mut body = crate::stream::Chunks(
            messages
                .into_iter()
                .map(|message| framed(&message.encode_to_vec())),
        );
        let sink = crate::stream::Decoder::profiled(
            crate::stream::SingleFrame::default(),
            opts.limit,
            self.response_profile(method),
        );
        let (sink, identity, headers, status) = self
            .stream_call(method, Vec::new(), &mut body, commitment, opts, sink)
            .await?;
        let bytes = sink
            .sink
            .bytes
            .ok_or(Error::Invalid("stream response count"))?;
        let value = self.decode_message(method, &bytes, &headers, status)?;
        Ok((value, identity))
    }

    /// A packmap node: capped like any other RPC response.
    pub(crate) async fn download(&self, key: Hash, head_ref: &str) -> Result<Vec<u8>, Error> {
        let opts = Opts {
            hint: Some(head_ref),
            ..Opts::default()
        };
        Ok(self
            .download_with(key, RESPONSE_LIMIT as u64, opts)
            .await?
            .0)
    }

    /// Download one pack of at most `cap` bytes. Incremental channels retain
    /// one bounded Connect frame beside the returned pack.
    pub(crate) async fn download_with(
        &self,
        key: Hash,
        cap: u64,
        opts: Opts<'_>,
    ) -> Result<(Vec<u8>, Option<Identity>), Error> {
        let lifetime = self.pack_location_lifetime().await;
        if let Some(lifetime) = lifetime {
            let opts = Opts {
                local_budget: self
                    .remaining_request_timeout(DOWNLOAD_PACK, opts.local_budget)?
                    .map(|timeout| (std::time::Instant::now(), timeout)),
                ..opts
            };
            if let Ok((pack, identity)) = self.download_attempt(key, cap, opts, true).await {
                if let Some(location) = pack.location {
                    if let Ok(bytes) = self
                        .fetch_location(key, cap, lifetime, location, opts.local_budget)
                        .await
                    {
                        return Ok((bytes, identity));
                    }
                } else {
                    verify_location_download(&pack.bytes, &key)?;
                    return Ok((pack.bytes, identity));
                }
            }
            self.remaining_request_timeout(DOWNLOAD_PACK, opts.local_budget)?;
            // The opt-in changes the signed request body. Build and sign the
            // fallback as a separate call, retaining the caller's ref hint.
            let (pack, identity) = self
                .download_attempt(
                    key,
                    cap,
                    Opts {
                        identity: None,
                        ..opts
                    },
                    false,
                )
                .await?;
            verify_location_download(&pack.bytes, &key)?;
            return Ok((pack.bytes, identity));
        }
        let (pack, identity) = self.download_attempt(key, cap, opts, false).await?;
        Ok((pack.bytes, identity))
    }

    async fn pack_location_lifetime(&self) -> Option<u64> {
        if !self.transport.supports_pack_locations() || cfg!(target_arch = "wasm32") {
            return None;
        }
        let cache = self.location_lifetime?;
        if let Some(lifetime) = cache.get() {
            return *lifetime;
        }
        let info = self.destination.server_info(self.transport).await.ok()?;
        let lifetime = info
            .max_pack_location_lifetime_ms
            .filter(|max| *max > 0 && info.supports_pack_locations == Some(true));
        let _ = cache.set(lifetime);
        lifetime
    }

    async fn fetch_location(
        &self,
        key: Hash,
        cap: u64,
        lifetime: u64,
        location: crate::proto::DownloadPackLocation,
        local_budget: Option<(std::time::Instant, Duration)>,
    ) -> Result<Vec<u8>, Error> {
        let size = location
            .total_bytes
            .ok_or(Error::Invalid("location size"))?;
        if size > cap {
            return Err(Error::Limit("pack download"));
        }
        let expires = location
            .expires_at_ms
            .filter(|v| *v > 0)
            .ok_or(Error::Invalid("location expiry"))?;
        if let Some(clock) = self.auth.map(|(_, clock)| clock).or(self.unsigned_clock) {
            let remaining = expires
                .checked_sub(clock.now_ms())
                .and_then(|v| u64::try_from(v).ok());
            if !remaining.is_some_and(|v| v > 0 && v <= lifetime) {
                return Err(Error::Invalid("location expiry"));
            }
        }
        let url = location.url.ok_or(Error::Invalid("location URL"))?;
        let uri: http::Uri = url.parse().map_err(|_| Error::Invalid("location URL"))?;
        let host = uri.host().ok_or(Error::Invalid("location host"))?;
        let loopback = host == "localhost" || host == "127.0.0.1" || host == "[::1]";
        if uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || !(uri.scheme_str() == Some("https")
                || (self.transport.allows_test_pack_location_http()
                    && loopback
                    && uri.scheme_str() == Some("http")))
            || url.contains('#')
        {
            return Err(Error::Invalid("location URL"));
        }
        let timeout = self.remaining_request_timeout(DOWNLOAD_PACK, local_budget)?;
        let bytes = self
            .transport
            .fetch_pack_location(
                &url,
                usize::try_from(size).map_err(|_| Error::Limit("pack download"))?,
                timeout,
            )
            .await
            .map_err(Error::Transport)?;
        // Location bytes never honor a host's streaming hash-verification
        // override: an external host is untrusted until both checks pass.
        if bytes.len() as u64 != size || mkit_core::pack::pack_key(&bytes) != key {
            return Err(Error::Invalid("pack location content commitment"));
        }
        Ok(bytes)
    }

    async fn download_attempt(
        &self,
        key: Hash,
        cap: u64,
        opts: Opts<'_>,
        accept_location: bool,
    ) -> Result<(crate::stream::Pack, Option<Identity>), Error> {
        let request = crate::proto::DownloadPackRequest {
            pack_id: Some(key.to_vec()),
            accept_location: accept_location.then_some(true),
            ..Default::default()
        };
        let body = framed(&request.encode_to_vec())?;
        let commitment = format!("body:{}", to_hex(&hash(&body)));
        let overhead = usize::try_from(cap / 512)
            .unwrap_or(usize::MAX)
            .saturating_add(8192);
        let limit = usize::try_from(cap)
            .unwrap_or(usize::MAX)
            .saturating_add(overhead);
        let opts = self.response_options("DownloadPack", Opts { limit, ..opts });
        let limit = opts.limit;
        let mut chunks = crate::stream::Chunks(std::iter::once(Ok(body)));
        let sink = crate::stream::Decoder::profiled(
            crate::stream::Pack::profiled(key, cap, self.response_profile("DownloadPack"))
                .accept_locations(accept_location),
            limit,
            self.response_profile("DownloadPack"),
        );
        let (sink, identity, _, _) = self
            .stream_call(
                "DownloadPack",
                Vec::new(),
                &mut chunks,
                &commitment,
                Opts { limit, ..opts },
                sink,
            )
            .await?;
        Ok((sink.sink, identity))
    }

    fn apply_ref_hint<B>(
        &self,
        method: &str,
        request: &mut Request<B>,
        hint: Option<&str>,
    ) -> Result<(), Error> {
        let hint = hint.filter(|hint| {
            !self.response_profile(method).ignore_invalid_ref_hints
                || mkit_core::refs::validate_ref_name(hint)
        });
        if let Some(hint) = hint {
            request.headers_mut().insert(
                "x-mkit-ref",
                HeaderValue::from_str(hint).map_err(|_| Error::Invalid("ref hint"))?,
            );
        }
        Ok(())
    }

    async fn stream_call<B: crate::RequestStream + ?Sized, R: crate::ResponseStream>(
        &self,
        method: &str,
        body: Vec<u8>,
        chunks: &mut B,
        commitment: &str,
        opts: Opts<'_>,
        sink: R,
    ) -> Result<(R, Option<Identity>, HeaderMap, http::StatusCode), Error> {
        let Built {
            mut request,
            identity,
        } = self.build(method, body, commitment, true, opts, 1).await?;
        self.apply_ref_hint(method, &mut request, opts.hint)?;
        let (parts, _) = request.into_parts();
        let request = Request::from_parts(parts, ());
        let procedure = format!("{SERVICE}{method}");
        let diagnostics = PolicyObserver {
            policy: self.request_policy,
            procedure: &procedure,
        };
        let mut checked =
            crate::stream::Checked::diagnosed(&request, sink, opts.limit, &diagnostics);
        self.transport
            .send_stream_diagnosed(request, chunks, opts.limit, &mut checked, &diagnostics)
            .await?;
        self.observe_response(method, commitment, opts, identity, checked.headers()?)?;
        let headers = checked.headers()?.clone();
        let status = checked.status()?;
        Ok((checked.sink, identity, headers, status))
    }

    async fn call(
        &self,
        method: &str,
        body: Vec<u8>,
        commitment: &str,
        streaming: bool,
        opts: Opts<'_>,
    ) -> Result<Raw, Error> {
        let Built {
            mut request,
            identity,
        } = self
            .build(method, body, commitment, streaming, opts, 1)
            .await?;
        self.apply_ref_hint(method, &mut request, opts.hint)?;
        let (bytes, headers, status) = self.send_response(&request, opts.limit).await?;
        self.observe_response(method, commitment, opts, identity, &headers)?;
        Ok((bytes, headers, identity, status))
    }

    fn response_options<'b>(&self, method: &str, opts: Opts<'b>) -> Opts<'b> {
        let procedure = format!("{SERVICE}{method}");
        Opts {
            limit: self.request_policy.map_or(opts.limit, |policy| {
                policy.response_limit(&procedure, opts.limit)
            }),
            ..opts
        }
    }
    pub(crate) fn response_profile(&self, method: &str) -> ResponseProfile {
        let procedure = format!("{SERVICE}{method}");
        self.request_policy
            .map_or_else(ResponseProfile::default, |policy| {
                policy.response_profile(&procedure)
            })
    }
    fn decode_message<R: Message + Default>(
        &self,
        method: &str,
        bytes: &[u8],
        headers: &HeaderMap,
        status: http::StatusCode,
    ) -> Result<R, Error> {
        R::decode_from_slice(bytes).map_err(|error| {
            let procedure = format!("{SERVICE}{method}");
            let kind = if matches!(error, buffa::DecodeError::ElementMemoryLimitExceeded) {
                FailureKind::DecodeResourceLimit
            } else {
                FailureKind::Decode
            };
            let cause = error.to_string();
            self.request_policy
                .and_then(|policy| {
                    policy.map_failure(&FailureDiagnostic {
                        procedure: &procedure,
                        kind,
                        status: Some(status),
                        headers: Some(headers),
                        body: Some(bytes),
                        parsed_error: None,
                        cause: &cause,
                        limit: None,
                    })
                })
                .unwrap_or(Error::Invalid("protobuf response"))
        })
    }

    fn observe_response(
        &self,
        method: &str,
        commitment: &str,
        opts: Opts<'_>,
        identity: Option<Identity>,
        headers: &HeaderMap,
    ) -> Result<(), Error> {
        if let (Some(policy), Some((signer, _)), Some(identity)) =
            (self.request_policy, self.auth, identity)
        {
            let procedure = format!("{SERVICE}{method}");
            let context = RequestContext {
                signing: SigningRequest {
                    procedure: &procedure,
                    audience: &self.destination.origin,
                    repository: &self.destination.repository,
                    commitment: ContentCommitment::parse(commitment)
                        .map_err(|_| Error::Invalid("signed operation"))?,
                    attempt: Attempt::new(
                        1,
                        identity.nonce,
                        identity.created_at_ms,
                        identity.expires_at_ms,
                    ),
                },
                intent: opts.intent.copied(),
                public_key: signer.public_key(),
            };
            policy.after_response(&context, headers);
        } else if let Some(policy) = self.request_policy {
            let procedure = format!("{SERVICE}{method}");
            policy.after_unsigned_response(
                &UnsignedRequestContext {
                    procedure: &procedure,
                    audience: &self.destination.origin,
                    repository: &self.destination.repository,
                    intent: opts.intent.copied(),
                },
                headers,
            );
        }
        Ok(())
    }

    /// Build (and sign) one request. A caller-supplied identity is used
    /// exactly; otherwise one is generated from the clock. `attempt` numbers
    /// the envelope for the observer and signer.
    pub(crate) async fn build(
        &self,
        method: &str,
        body: Vec<u8>,
        commitment: &str,
        streaming: bool,
        opts: Opts<'_>,
        attempt: u32,
    ) -> Result<Built, Error> {
        if self.auth.is_none() || method == "GetServerInfo" {
            let (metadata, identity) = if self.auth.is_none() {
                self.unsigned_metadata(method, opts, attempt).await?
            } else {
                (HeaderMap::new(), None)
            };
            let mut request = if method == "GetServerInfo" {
                self.destination.info_request()?
            } else {
                self.destination.plain_request(method, body, streaming)?
            };
            request.headers_mut().extend(metadata);
            if method != "GetServerInfo"
                && let Some(policy) = self.request_policy
            {
                let procedure = format!("{SERVICE}{method}");
                let context = UnsignedRequestContext {
                    procedure: &procedure,
                    audience: &self.destination.origin,
                    repository: &self.destination.repository,
                    intent: opts.intent.copied(),
                };
                let headers = policy
                    .unsigned_headers(&context)
                    .map_err(|veto| Error::Vetoed(veto.reason().to_owned()))?
                    .validate()?;
                request.headers_mut().extend(headers);
            }
            if let Some((_, clock)) = self.auth
                && opts.identity.is_none()
                && clock.now_ms() >= self.deadline_ms
            {
                return Err(Error::Deadline);
            }
            self.apply_request_timeout(method, &mut request, opts.local_budget)?;
            if let (Some(clock), Some(identity)) = (self.unsigned_clock, identity)
                && clock.now_ms() >= identity.expires_at_ms
            {
                return Err(self.expired(&identity));
            }
            return Ok(Built { request, identity });
        }
        let procedure = format!("{SERVICE}{method}");
        let signed = self.sign(&procedure, commitment, opts, attempt).await?;
        let mut request = self.destination.plain_request(method, body, streaming)?;
        request.headers_mut().extend(signed.headers);
        self.apply_request_timeout(method, &mut request, opts.local_budget)?;
        Ok(Built {
            request,
            identity: Some(signed.identity),
        })
    }

    fn apply_request_timeout(
        &self,
        method: &str,
        request: &mut Request<Vec<u8>>,
        local_budget: Option<(std::time::Instant, Duration)>,
    ) -> Result<(), Error> {
        let procedure = format!("{SERVICE}{method}");
        if self
            .request_policy
            .is_some_and(|policy| policy.advertise_request_timeout(&procedure))
        {
            request.extensions_mut().insert(AdvertiseRequestTimeout);
        }
        if let Some(timeout) = self.remaining_request_timeout(&procedure, local_budget)? {
            request.extensions_mut().insert(RequestTimeout(timeout));
        }
        Ok(())
    }

    fn remaining_request_timeout(
        &self,
        procedure: &str,
        local_budget: Option<(std::time::Instant, Duration)>,
    ) -> Result<Option<Duration>, Error> {
        let host_timeout = self
            .request_policy
            .and_then(|policy| policy.request_timeout(procedure));
        let remaining =
            local_budget.map(|(started, budget)| budget.saturating_sub(started.elapsed()));
        let timeout = match (host_timeout, remaining) {
            (Some(host), Some(remaining)) => Some(host.min(remaining)),
            (host, remaining) => host.or(remaining),
        };
        if timeout.is_some_and(|timeout| timeout.is_zero()) {
            return Err(Error::Deadline);
        }
        Ok(timeout)
    }

    async fn unsigned_metadata(
        &self,
        method: &str,
        opts: Opts<'_>,
        attempt: u32,
    ) -> Result<(HeaderMap, Option<Identity>), Error> {
        let eligible = opts.intent.is_some()
            && matches!(
                method,
                "UpdateRef"
                    | "AdvanceRefs"
                    | "BeginUpload"
                    | "UploadPack"
                    | "UploadPart"
                    | "CompleteUpload"
            );
        let Some(clock) = self.unsigned_clock.filter(|_| eligible) else {
            if opts.identity.is_some() {
                return Err(Error::Invalid("identity requires a signer"));
            }
            return Ok((HeaderMap::new(), None));
        };
        let identity = if let Some(identity) = opts.identity {
            identity.validate()?;
            *identity
        } else {
            let created = clock.now_ms();
            if created >= self.deadline_ms {
                return Err(Error::Deadline);
            }
            Identity::new(
                clock.nonce().map_err(Error::Signing)?,
                created,
                created
                    .saturating_add(MAX_VALIDITY_MS)
                    .min(self.deadline_ms),
            )
        };
        if clock.now_ms() >= identity.expires_at_ms {
            return Err(self.expired(&identity));
        }
        let mut headers = self
            .observer
            .before_dispatch(
                opts.intent.ok_or(Error::Invalid("unsigned write intent"))?,
                &Attempt::new(
                    attempt,
                    identity.nonce,
                    identity.created_at_ms,
                    identity.expires_at_ms,
                ),
            )
            .await
            .map_err(|veto| Error::Vetoed(veto.reason().to_owned()))?
            .validate()?;
        for (name, value) in [
            ("idempotency-key", identity.idempotency_key()),
            ("x-created-at", identity.created_at_ms.to_string()),
            ("x-expires-at", identity.expires_at_ms.to_string()),
        ] {
            headers.insert(
                name,
                HeaderValue::from_str(&value)
                    .map_err(|_| Error::Invalid("write identity header"))?,
            );
        }
        Ok((headers, Some(identity)))
    }

    /// A window clamped to the push deadline ended because the push did.
    fn expired(&self, id: &Identity) -> Error {
        if id.expires_at_ms == self.deadline_ms {
            Error::Deadline
        } else {
            Error::EnvelopeExpired
        }
    }

    fn apply_policy(
        &self,
        signing: SigningRequest<'_>,
        intent: Option<WriteIntent<'_>>,
        extra: &mut HeaderMap,
        public_key: Hash,
    ) -> Result<(), Error> {
        if let Some(policy) = self.request_policy {
            let context = RequestContext {
                signing,
                intent,
                public_key,
            };
            let headers = policy
                .headers(&context)
                .map_err(|veto| Error::Vetoed(veto.reason().to_owned()))?
                .validate()?;
            for (name, value) in &headers {
                if extra.insert(name.clone(), value.clone()).is_some() {
                    return Err(Error::Invalid("duplicate request policy header"));
                }
            }
        }
        Ok(())
    }

    /// The seam pipeline for one envelope: identity, observer, signer, deadline
    /// check. Returns the auth v2 headers (and the observer's extra ones) and
    /// the identity. Needs a signer.
    pub(crate) async fn sign(
        &self,
        procedure: &str,
        commitment: &str,
        opts: Opts<'_>,
        attempt: u32,
    ) -> Result<Signed, Error> {
        let (signer, clock) = self.auth.ok_or(Error::Invalid("signed client required"))?;
        let id = if let Some(id) = opts.identity {
            id.validate()?;
            *id
        } else {
            let created = clock.now_ms();
            if created >= self.deadline_ms {
                return Err(Error::Deadline);
            }
            Identity {
                nonce: clock.nonce().map_err(Error::Signing)?,
                created_at_ms: created,
                expires_at_ms: created
                    .saturating_add(MAX_VALIDITY_MS)
                    .min(self.deadline_ms),
            }
        };
        // An envelope that has already ended is refused before any policy runs.
        if clock.now_ms() >= id.expires_at_ms {
            return Err(self.expired(&id));
        }
        let nonce = id.idempotency_key();
        let digest = Operation {
            context: Context {
                audience: &self.destination.origin,
                repository: &self.destination.repository,
            },
            procedure,
            commitment,
            created_at: id.created_at_ms,
            expires_at: id.expires_at_ms,
            nonce: &nonce,
        }
        .digest()
        .map_err(|_| Error::Invalid("signed operation"))?;
        let parsed =
            ContentCommitment::parse(commitment).map_err(|_| Error::Invalid("signed operation"))?;
        let attempt = Attempt {
            number: attempt,
            nonce: id.nonce,
            created_at_ms: id.created_at_ms,
            expires_at_ms: id.expires_at_ms,
        };
        // 1. Observer: may veto, may add headers. Reserved names are refused
        //    here, before a signature exists.
        let mut extra = match opts.intent {
            Some(intent) => self
                .observer
                .before_dispatch(intent, &attempt)
                .await
                .map_err(|veto| Error::Vetoed(veto.reason().to_owned()))?
                .validate()?,
            None => HeaderMap::new(),
        };
        // 2. Signer: sees the structured operation.
        let request = SigningRequest {
            procedure,
            audience: &self.destination.origin,
            repository: &self.destination.repository,
            commitment: parsed,
            attempt,
        };
        self.apply_policy(
            request,
            opts.intent.copied(),
            &mut extra,
            signer.public_key(),
        )?;
        let signature = signer
            .sign_operation(&request, &digest)
            .await
            .map_err(SignError::into_error)?;
        // 3. Deadline: an envelope that has expired is never dispatched.
        if clock.now_ms() >= id.expires_at_ms {
            return Err(self.expired(&id));
        }
        let mut headers = extra;
        for (name, value) in [
            ("x-envelope-version", "2".to_owned()),
            ("x-audience", self.destination.origin.clone()),
            ("x-repository", self.destination.repository.clone()),
            ("x-content-commitment", commitment.to_owned()),
            ("x-created-at", id.created_at_ms.to_string()),
            ("x-expires-at", id.expires_at_ms.to_string()),
            ("idempotency-key", nonce),
            ("x-public-key", to_hex(&signer.public_key())),
            ("x-signature", to_hex_bytes(&signature)),
        ] {
            headers.insert(
                name,
                HeaderValue::from_str(&value).map_err(|_| Error::Invalid("auth header"))?,
            );
        }
        if let Some(value) = commitment.strip_prefix("body:") {
            headers.insert(
                "x-digest",
                HeaderValue::from_str(value).map_err(|_| Error::Invalid("digest header"))?,
            );
        }
        Ok(Signed {
            headers,
            identity: id,
        })
    }

    pub(crate) async fn send(
        &self,
        request: &Request<Vec<u8>>,
        limit: usize,
    ) -> Result<(Vec<u8>, HeaderMap), Error> {
        let (bytes, headers, _) = self.send_response(request, limit).await?;
        Ok((bytes, headers))
    }

    async fn send_response(
        &self,
        request: &Request<Vec<u8>>,
        limit: usize,
    ) -> Result<(Vec<u8>, HeaderMap, http::StatusCode), Error> {
        let mut copy = Request::new(request.body().clone());
        *copy.method_mut() = request.method().clone();
        *copy.uri_mut() = request.uri().clone();
        *copy.headers_mut() = request.headers().clone();
        if let Some(timeout) = request.extensions().get::<RequestTimeout>() {
            copy.extensions_mut().insert(*timeout);
        }
        if request
            .extensions()
            .get::<AdvertiseRequestTimeout>()
            .is_some()
        {
            copy.extensions_mut().insert(AdvertiseRequestTimeout);
        }
        let procedure = request.uri().path();
        let limit = self
            .request_policy
            .map_or(limit, |policy| policy.response_limit(procedure, limit));
        let diagnostics = PolicyObserver {
            policy: self.request_policy,
            procedure,
        };
        let content_type = copy.headers().get("content-type").cloned();
        let response = self
            .transport
            .send_diagnosed(copy, limit, &diagnostics)
            .await?;
        let status = response.status();
        let (bytes, headers) =
            decode_response_diagnosed(response, content_type.as_ref(), limit, &diagnostics)?;
        Ok((bytes, headers, status))
    }
}

pub(crate) async fn send_checked<T: HttpTransport>(
    transport: &T,
    request: Request<Vec<u8>>,
    limit: usize,
) -> Result<(Vec<u8>, HeaderMap), Error> {
    let content_type = request.headers().get("content-type").cloned();
    let response =
        transport
            .send_classified(request, limit)
            .await
            .map_err(|error| match error {
                ChannelError::Transient(cause) => Error::Connection(cause),
                ChannelError::TimedOut(cause) => Error::RequestTimeout(cause),
                ChannelError::Refused(cause) => Error::Transport(cause),
            })?;
    decode_response(response, content_type.as_ref(), limit)
}

pub(crate) fn decode_response(
    response: Response<Vec<u8>>,
    content_type: Option<&HeaderValue>,
    limit: usize,
) -> Result<(Vec<u8>, HeaderMap), Error> {
    decode_response_diagnosed(
        response,
        content_type,
        limit,
        &PolicyObserver::<NoRequestPolicy> {
            policy: None,
            procedure: "",
        },
    )
}

pub(crate) fn decode_response_diagnosed<D: FailureObserver + ?Sized>(
    response: Response<Vec<u8>>,
    content_type: Option<&HeaderValue>,
    limit: usize,
    observer: &D,
) -> Result<(Vec<u8>, HeaderMap), Error> {
    let profile = observer.response_profile();
    if response.body().len() > limit {
        return Err(observer
            .map_failure(&FailureDiagnostic {
                procedure: "",
                kind: FailureKind::WireLimit,
                status: Some(response.status()),
                headers: Some(response.headers()),
                body: Some(&response.body()[..limit]),
                parsed_error: None,
                cause: "RPC response exceeds limit",
                limit: Some(limit),
            })
            .unwrap_or(Error::Limit("RPC response")));
    }
    if !response.status().is_success() {
        let parsed = parse_remote_error(response.body(), response.status(), profile);
        if response.status().as_u16() == 402 || challenged(parsed.as_ref().ok()) {
            return Err(Error::PaymentRequired(Box::new(admission_required(
                parsed.ok().as_ref(),
                response.headers(),
            )?)));
        }
        let mut error = parsed.map_err(|error| {
            observer
                .map_failure(&FailureDiagnostic {
                    procedure: "",
                    kind: FailureKind::Http,
                    status: Some(response.status()),
                    headers: Some(response.headers()),
                    body: Some(response.body()),
                    parsed_error: None,
                    cause: &error.to_string(),
                    limit: Some(limit),
                })
                .unwrap_or(Error::Invalid("Connect error JSON"))
        })?;
        error.status = response.status().as_u16();
        error.headers = response.headers().clone();
        let mapped = observer.map_failure(&FailureDiagnostic {
            procedure: "",
            kind: FailureKind::Http,
            status: Some(response.status()),
            headers: Some(response.headers()),
            body: Some(response.body()),
            parsed_error: Some(&error),
            cause: &error.message,
            limit: Some(limit),
        });
        return Err(mapped.unwrap_or_else(|| Error::Remote(Box::new(error))));
    }
    let supplied_type = response.headers().get("content-type");
    let type_ok = supplied_type == content_type
        || (supplied_type.is_none() && profile.allow_missing_content_type)
        || (profile.allow_content_type_prefix
            && supplied_type
                .zip(content_type)
                .is_some_and(|(supplied, expected)| {
                    supplied.as_bytes().starts_with(expected.as_bytes())
                }));
    if (!profile.allow_other_success_status && response.status() != http::StatusCode::OK)
        || !type_ok
        || response
            .headers()
            .get("content-encoding")
            .is_some_and(|value| value != "identity")
        || response
            .headers()
            .get("connect-content-encoding")
            .is_some_and(|value| value != "identity")
    {
        return Err(observer
            .map_failure(&FailureDiagnostic {
                procedure: "",
                kind: FailureKind::Headers,
                status: Some(response.status()),
                headers: Some(response.headers()),
                body: Some(response.body()),
                parsed_error: None,
                cause: "Connect response status/encoding",
                limit: Some(limit),
            })
            .unwrap_or(Error::Invalid("Connect response status/encoding")));
    }
    let (parts, body) = response.into_parts();
    Ok((body, parts.headers))
}

fn parse_remote_error(
    bytes: &[u8],
    status: http::StatusCode,
    profile: ResponseProfile,
) -> Result<RemoteError, serde_json::Error> {
    #[derive(Deserialize)]
    struct Fields {
        code: Option<String>,
        message: Option<String>,
        #[serde(default)]
        details: Vec<Detail>,
    }
    if !profile.allow_incomplete_error_fields {
        return serde_json::from_slice(bytes);
    }
    let fields: Fields = serde_json::from_slice(bytes)?;
    let fallback = match status.as_u16() {
        400 => "internal",
        401 => "unauthenticated",
        403 => "permission_denied",
        404 => "unimplemented",
        408 => "deadline_exceeded",
        429 | 502 | 503 | 504 => "unavailable",
        _ => "unknown",
    };
    let code = fields
        .code
        .filter(|code| {
            matches!(
                code.as_str(),
                "canceled"
                    | "unknown"
                    | "invalid_argument"
                    | "deadline_exceeded"
                    | "not_found"
                    | "already_exists"
                    | "permission_denied"
                    | "resource_exhausted"
                    | "failed_precondition"
                    | "aborted"
                    | "out_of_range"
                    | "unimplemented"
                    | "internal"
                    | "unavailable"
                    | "data_loss"
                    | "unauthenticated"
            )
        })
        .unwrap_or_else(|| fallback.to_owned());
    Ok(RemoteError {
        code,
        message: fields.message.unwrap_or_default(),
        details: fields.details,
        status: status.as_u16(),
        headers: HeaderMap::new(),
    })
}

fn strip_type(url: &str) -> &str {
    url.strip_prefix("type.googleapis.com/").unwrap_or(url)
}

fn challenge_details(error: &RemoteError) -> Vec<&Detail> {
    error
        .details
        .iter()
        .filter(|detail| strip_type(&detail.type_url) == CHALLENGE_TYPE)
        .collect()
}

/// A challenge is a 402, or `permission_denied` carrying the challenge detail.
fn challenged(error: Option<&RemoteError>) -> bool {
    error.is_some_and(|e| e.code == "permission_denied" && !challenge_details(e).is_empty())
}

/// Visible challenge-header values: at most eight, each bounded printable ASCII.
fn header_values(headers: &HeaderMap, name: &str) -> Result<Vec<String>, Error> {
    let mut values = Vec::new();
    for value in headers.get_all(name) {
        let bytes = value.as_bytes();
        if values.len() == MAX_CHALLENGES
            || bytes.len() > MAX_VALUE_BYTES
            || !bytes
                .iter()
                .all(|b| *b == b'\t' || (0x20..=0x7e).contains(b))
        {
            return Err(Error::Invalid("admission header"));
        }
        values.push(String::from_utf8_lossy(bytes).into_owned());
    }
    Ok(values)
}

/// Build the admission result from a Connect error (when the body was one) and
/// the response's challenge headers. Header values stay unparsed: they are an
/// RFC 9110 challenge list a helper reads (STC §5.1).
fn admission_required(
    error: Option<&RemoteError>,
    headers: &HeaderMap,
) -> Result<AdmissionRequired, Error> {
    let invalid = || Error::Invalid("admission challenge");
    let details = error.map(challenge_details).unwrap_or_default();
    if details.len() > 1 {
        return Err(invalid());
    }
    let (challenges, description) = if let Some(detail) = details.first() {
        let encoded = detail.value.as_deref().unwrap_or("");
        if encoded.len() > 88_836 {
            return Err(invalid());
        }
        let bytes = STANDARD_NO_PAD
            .decode(encoded)
            .or_else(|_| STANDARD.decode(encoded))
            .map_err(|_| invalid())?;
        let decoded =
            crate::proto::AdmissionChallenge::decode_from_slice(&bytes).map_err(|_| invalid())?;
        let description = decoded.description.unwrap_or_default();
        let pairs: Vec<(String, String)> = decoded
            .challenges
            .into_iter()
            .map(|c| (c.scheme.unwrap_or_default(), c.value.unwrap_or_default()))
            .collect();
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        validate_challenges(&borrowed, &description).map_err(|_| invalid())?;
        debug_assert!(description.len() <= MAX_DESCRIPTION_BYTES);
        (
            pairs
                .into_iter()
                .map(|(scheme, value)| AdmissionChallengeEntry { scheme, value })
                .collect(),
            description,
        )
    } else {
        (Vec::new(), String::new())
    };
    Ok(AdmissionRequired::new(
        challenges,
        description,
        header_values(headers, "www-authenticate")?,
        header_values(headers, "payment-required")?,
    ))
}

/// `Retry-After` delay-seconds only, clamped to 1-60 s, as milliseconds.
fn retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get("retry-after")?.to_str().ok()?.trim();
    if value.is_empty() || value.len() > 10 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(value.parse::<u64>().ok()?.clamp(1, 60) * 1000)
}

/// Whether an `unavailable` answer is the membership-lag condition. The typed
/// `MembershipNotVisible` detail decides; the exact public message is a
/// fallback for servers that predate the detail.
pub(crate) fn membership_lag(error: &RemoteError) -> bool {
    error.code == "unavailable"
        && (error.details.iter().any(|detail| {
            detail
                .type_url
                .strip_prefix("type.googleapis.com/")
                .unwrap_or(&detail.type_url)
                == MEMBERSHIP_TYPE
        }) || error.message == MEMBERSHIP_LAG)
}

pub(crate) fn pending_delay(error: &RemoteError) -> Option<Duration> {
    if error.code != "unavailable" {
        return None;
    }
    let mut details = error.details.iter().filter(|detail| {
        detail
            .type_url
            .strip_prefix("type.googleapis.com/")
            .unwrap_or(&detail.type_url)
            == PENDING_TYPE
    });
    let detail = details.next()?;
    if details.next().is_some() {
        return None;
    }
    let bytes = STANDARD_NO_PAD
        .decode(detail.value.as_deref()?)
        .or_else(|_| STANDARD.decode(detail.value.as_deref().unwrap_or_default()))
        .ok()?;
    let pending = crate::proto::PendingVerification::decode_from_slice(&bytes).ok()?;
    let hint = u64::from(pending.retry_after_ms.unwrap_or(0)).clamp(1000, 60_000);
    let header = error
        .headers
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_mul(1000)
        .clamp(1000, 60_000);
    Some(Duration::from_millis(hint.max(header)))
}

fn to_hex_bytes(bytes: &[u8]) -> String {
    mkit_core::hash::to_hex_bytes(bytes)
}
pub(crate) fn framed(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = Vec::new();
    frame(&mut body, bytes)?;
    Ok(body)
}
pub(crate) fn frame(body: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    body.push(0);
    body.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| Error::Limit("Connect frame"))?
            .to_be_bytes(),
    );
    body.extend_from_slice(bytes);
    Ok(())
}

/// Lazily parsed Connect frames: yields each data frame, then stops at a clean
/// end frame; a missing, malformed or error end frame is an `Err`. Nothing is
/// collected, so a hostile run of tiny frames costs no allocation here.
#[cfg(test)]
pub(crate) struct Frames<'a> {
    rest: &'a [u8],
    done: bool,
}
#[cfg(test)]
impl<'a> Frames<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            rest: bytes,
            done: false,
        }
    }
}
#[cfg(test)]
impl<'a> Iterator for Frames<'a> {
    type Item = Result<&'a [u8], Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let fail = |this: &mut Self, error: Error| {
            this.done = true;
            Some(Err(error))
        };
        let rest = self.rest;
        if rest.is_empty() {
            return fail(self, Error::Invalid("missing Connect end frame"));
        }
        if rest.len() < 5 {
            return fail(self, Error::Invalid("Connect frame header"));
        }
        let flag = rest[0];
        let len = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]) as usize;
        let Some(frame) = rest.get(5..5_usize.saturating_add(len)) else {
            return fail(self, Error::Invalid("truncated Connect frame"));
        };
        self.rest = &rest[5 + len..];
        match flag {
            0 => Some(Ok(frame)),
            2 if self.rest.is_empty() => {
                self.done = true;
                match end_error(frame) {
                    Ok(()) => None,
                    Err(error) => Some(Err(error)),
                }
            }
            _ => fail(self, Error::Invalid("Connect frame flags/order")),
        }
    }
}

/// The end frame of a stream under default response rules.
#[cfg(test)]
pub(crate) fn end_error(frame: &[u8]) -> Result<(), Error> {
    end_error_diagnosed(
        frame,
        http::StatusCode::OK,
        &HeaderMap::new(),
        ResponseProfile::default(),
        &PolicyObserver::<NoRequestPolicy> {
            policy: None,
            procedure: "",
        },
    )
}

/// Interpret a terminal error with the same host-selected envelope rules and
/// admission headers as a unary response. Terminal JSON never supplies its own
/// HTTP status or replaces the actual response headers.
pub(crate) fn end_error_diagnosed<D: FailureObserver + ?Sized>(
    frame: &[u8],
    status: http::StatusCode,
    headers: &HeaderMap,
    profile: ResponseProfile,
    observer: &D,
) -> Result<(), Error> {
    let end: serde_json::Value =
        serde_json::from_slice(frame).map_err(|_| Error::Invalid("Connect end JSON"))?;
    let Some(error) = end.get("error") else {
        return Ok(());
    };
    if error.is_null() && profile.allow_incomplete_error_fields {
        return Ok(());
    }
    let bytes = serde_json::to_vec(error).map_err(|_| Error::Invalid("Connect end error"))?;
    let mut remote = parse_remote_error(&bytes, status, profile)
        .map_err(|_| Error::Invalid("Connect end error"))?;
    if challenged(Some(&remote)) {
        return Err(Error::PaymentRequired(Box::new(admission_required(
            Some(&remote),
            headers,
        )?)));
    }
    remote.status = status.as_u16();
    remote.headers = headers.clone();
    let mapped = observer.map_failure(&FailureDiagnostic {
        procedure: "",
        kind: FailureKind::Http,
        status: Some(status),
        headers: Some(headers),
        body: Some(frame),
        parsed_error: Some(&remote),
        cause: &remote.message,
        limit: None,
    });
    Err(mapped.unwrap_or_else(|| Error::Remote(Box::new(remote))))
}

#[cfg(test)]
pub(crate) fn decode_stream(bytes: &[u8]) -> Result<Vec<&[u8]>, Error> {
    Frames::new(bytes).collect()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod channel_tests {
    use super::*;

    struct ExistingChannel;
    impl HttpTransport for ExistingChannel {
        async fn send(&self, _: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
            Err("unavailable: deterministic refusal".to_owned())
        }
    }

    struct ClassifiedChannel(bool);
    impl HttpTransport for ClassifiedChannel {
        async fn send(&self, _: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
            panic!("classified send must be used")
        }

        async fn send_classified(
            &self,
            _: Request<Vec<u8>>,
            _: usize,
        ) -> Result<Response<Vec<u8>>, ChannelError> {
            if self.0 {
                Err(ChannelError::TimedOut(
                    "client-side deadline exceeded".to_owned(),
                ))
            } else {
                Err(ChannelError::Transient("connection reset".to_owned()))
            }
        }
    }

    fn ready<F: std::future::Future>(future: F) -> F::Output {
        match std::pin::pin!(future)
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("test channel must complete immediately"),
        }
    }

    struct TimeoutPolicy(Duration);
    impl RequestPolicy for TimeoutPolicy {
        fn headers(&self, _: &RequestContext<'_>) -> Result<crate::RequestHeaders, crate::Veto> {
            Ok(crate::RequestHeaders::new())
        }
        fn request_timeout(&self, procedure: &str) -> Option<Duration> {
            assert_eq!(procedure, "/mkit.transport.v1.TransportService/ReadRef");
            Some(self.0)
        }
    }
    struct TimeoutChannel(std::cell::Cell<Option<Duration>>);
    impl HttpTransport for TimeoutChannel {
        async fn send(
            &self,
            request: Request<Vec<u8>>,
            _: usize,
        ) -> Result<Response<Vec<u8>>, String> {
            self.0.set(
                request
                    .extensions()
                    .get::<RequestTimeout>()
                    .map(|timeout| timeout.0),
            );
            let reply = crate::proto::ReadRefResponse {
                exists: Some(false),
                ..Default::default()
            };
            Ok(Response::builder()
                .header("content-type", "application/proto")
                .body(reply.encode_to_vec())
                .unwrap())
        }
    }
    #[test]
    fn host_request_timeout_is_preserved_through_the_rpc_request_copy() {
        let channel = TimeoutChannel(std::cell::Cell::new(None));
        let destination =
            Destination::new("https://example.invalid".to_owned(), "default".to_owned()).unwrap();
        let policy = TimeoutPolicy(Duration::from_millis(25));
        let client = crate::Client::anonymous(&channel, destination).with_request_policy(&policy);
        ready(client.read_ref("refs/heads/main", None)).unwrap();
        assert_eq!(channel.0.get(), Some(Duration::from_millis(25)));
    }

    #[test]
    fn a_zero_host_budget_refuses_before_dispatch() {
        let channel = TimeoutChannel(std::cell::Cell::new(None));
        let destination =
            Destination::new("https://example.invalid".to_owned(), "default".to_owned()).unwrap();
        let policy = TimeoutPolicy(Duration::ZERO);
        let client = crate::Client::anonymous(&channel, destination).with_request_policy(&policy);
        assert!(matches!(
            ready(client.read_ref("refs/heads/main", None)),
            Err(Error::Deadline)
        ));
        assert_eq!(channel.0.get(), None);
    }

    #[test]
    fn explicit_channel_timeouts_remain_distinct_from_transient_io() {
        let error = ready(send_checked(
            &ClassifiedChannel(true),
            Request::new(Vec::new()),
            1024,
        ))
        .expect_err("request timeout");
        assert!(
            matches!(error, Error::RequestTimeout(cause) if cause == "client-side deadline exceeded")
        );
    }

    #[test]
    fn existing_string_channels_are_terminal_without_message_inference() {
        let error = ready(send_checked(
            &ExistingChannel,
            Request::new(Vec::new()),
            1024,
        ))
        .expect_err("channel refusal");
        assert!(
            matches!(error, Error::Transport(cause) if cause == "unavailable: deterministic refusal")
        );
    }

    #[test]
    fn explicit_channel_transience_survives_the_rpc_boundary() {
        let error = ready(send_checked(
            &ClassifiedChannel(false),
            Request::new(Vec::new()),
            1024,
        ))
        .expect_err("connection failure");
        assert!(matches!(error, Error::Connection(cause) if cause == "connection reset"));
    }
}
