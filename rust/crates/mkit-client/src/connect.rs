use crate::seams::{
    Attempt, NoObserver, Observer, RequestContext, RequestPolicy, SignError, SigningRequest,
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

/// A channel's explicit distinction between exchange failures and refusals.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChannelError {
    /// A connection, response-body I/O or timeout failure. Its request may have
    /// reached the server; a retry must retain the authenticated identity.
    #[error("{0}")]
    Transient(String),
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
/// is `None` for anonymous and discovery calls.
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

pub(crate) struct Rpc<'a, T, S, C, O = NoObserver> {
    pub(crate) transport: &'a T,
    /// `None` makes every request anonymous.
    pub(crate) auth: Option<(&'a S, &'a C)>,
    pub(crate) observer: &'a O,
    pub(crate) request_policy: Option<&'a dyn RequestPolicy>,
    pub(crate) destination: &'a Destination,
    pub(crate) deadline_ms: i64,
}

/// Per-call options: a caller-owned identity, an optional `X-Mkit-Ref` hint
/// (STC §7.9) and the response cap.
#[derive(Clone, Copy)]
pub(crate) struct Opts<'a> {
    pub(crate) identity: Option<&'a Identity>,
    pub(crate) hint: Option<&'a str>,
    pub(crate) limit: usize,
    /// Present for write RPCs: what the observer is told before the attempt.
    pub(crate) intent: Option<&'a WriteIntent<'a>>,
}
impl Default for Opts<'_> {
    fn default() -> Self {
        Self {
            identity: None,
            hint: None,
            limit: RESPONSE_LIMIT,
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

type Raw = (Vec<u8>, HeaderMap, Option<Identity>);

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
            observer: &NoObserver,
            request_policy: None,
            destination,
            deadline_ms,
        }
    }
}

impl<'a, T, S, C, O> Rpc<'a, T, S, C, O> {
    pub(crate) fn observed<P: Observer>(self, observer: &'a P) -> Rpc<'a, T, S, C, P> {
        Rpc {
            transport: self.transport,
            auth: self.auth,
            observer,
            request_policy: self.request_policy,
            destination: self.destination,
            deadline_ms: self.deadline_ms,
        }
    }
}

impl<T: HttpTransport, S: Signer, C: Clock, O: Observer> Rpc<'_, T, S, C, O> {
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
        let (bytes, _, identity) = self.call(method, body, &commitment, false, opts).await?;
        let value =
            R::decode_from_slice(&bytes).map_err(|_| Error::Invalid("protobuf response"))?;
        Ok((value, identity))
    }

    pub(crate) async fn stream_with<Q: Message, R: Message + Default>(
        &self,
        method: &str,
        messages: impl IntoIterator<Item = Q>,
        commitment: &str,
        opts: Opts<'_>,
    ) -> Result<(R, Option<Identity>), Error> {
        let mut body = Vec::new();
        for message in messages {
            frame(&mut body, &message.encode_to_vec())?;
        }
        let (bytes, _, identity) = self.call(method, body, commitment, true, opts).await?;
        let frames = decode_stream(&bytes)?;
        if frames.len() != 1 {
            return Err(Error::Invalid("stream response count"));
        }
        let value =
            R::decode_from_slice(frames[0]).map_err(|_| Error::Invalid("protobuf response"))?;
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

    /// Download one pack of at most `cap` bytes. The buffered response is
    /// bounded by the cap plus Connect and chunk framing.
    pub(crate) async fn download_with(
        &self,
        key: Hash,
        cap: u64,
        opts: Opts<'_>,
    ) -> Result<(Vec<u8>, Option<Identity>), Error> {
        use crate::proto::{
            DownloadPackRequest, DownloadPackResponse, download_pack_response::Body,
        };
        let request = DownloadPackRequest {
            pack_id: Some(key.to_vec()),
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
        let (bytes, _, identity) = self
            .call(
                "DownloadPack",
                body,
                &commitment,
                true,
                Opts { limit, ..opts },
            )
            .await?;
        let mut out = Vec::new();
        let mut expected: Option<u64> = None;
        let mut last = false;
        for frame in Frames::new(&bytes) {
            let frame = frame?;
            let response = DownloadPackResponse::decode_from_slice(frame)
                .map_err(|_| Error::Invalid("download protobuf"))?;
            match response.body {
                Some(Body::Header(header)) if expected.is_none() && out.is_empty() => {
                    let size = header.total_bytes.ok_or(Error::Invalid("download size"))?;
                    if size > cap {
                        return Err(Error::Limit("pack download"));
                    }
                    expected = Some(size);
                    // Reserve once, so growth never holds two copies. A lying
                    // header cannot reserve more than the response holds.
                    out.reserve_exact(usize::try_from(size).unwrap_or(0).min(bytes.len()));
                }
                Some(Body::Chunk(chunk)) if expected.is_some() && !last => {
                    if chunk.pack_id.as_deref() != Some(key.as_slice())
                        || chunk.offset != Some(out.len() as u64)
                    {
                        return Err(Error::Invalid("download chunk identity"));
                    }
                    let data = chunk
                        .data
                        .as_deref()
                        .ok_or(Error::Invalid("download chunk"))?;
                    if (out.len() as u64).saturating_add(data.len() as u64) > expected.unwrap_or(0)
                    {
                        return Err(Error::Invalid("download exceeds declared size"));
                    }
                    out.extend_from_slice(data);
                    last = chunk.last.ok_or(Error::Invalid("download last marker"))?;
                }
                _ => return Err(Error::Invalid("download order")),
            }
        }
        if !last || expected != Some(out.len() as u64) || mkit_core::pack::pack_key(&out) != key {
            return Err(Error::Invalid("pack content commitment"));
        }
        Ok((out, identity))
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
        if let Some(hint) = opts.hint {
            request.headers_mut().insert(
                "x-mkit-ref",
                HeaderValue::from_str(hint).map_err(|_| Error::Invalid("ref hint"))?,
            );
        }
        let (bytes, headers) = self.send(&request, opts.limit).await?;
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
            policy.after_response(&context, &headers);
        } else if let Some(policy) = self.request_policy {
            let procedure = format!("{SERVICE}{method}");
            policy.after_unsigned_response(
                &UnsignedRequestContext {
                    procedure: &procedure,
                    audience: &self.destination.origin,
                    repository: &self.destination.repository,
                    intent: opts.intent.copied(),
                },
                &headers,
            );
        }
        Ok((bytes, headers, identity))
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
            if opts.identity.is_some() && self.auth.is_none() {
                return Err(Error::Invalid("identity requires a signer"));
            }
            let mut request = if method == "GetServerInfo" {
                self.destination.info_request()?
            } else {
                self.destination.plain_request(method, body, streaming)?
            };
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
            return Ok(Built {
                request,
                identity: None,
            });
        }
        let procedure = format!("{SERVICE}{method}");
        let signed = self.sign(&procedure, commitment, opts, attempt).await?;
        let mut request = self.destination.plain_request(method, body, streaming)?;
        request.headers_mut().extend(signed.headers);
        Ok(Built {
            request,
            identity: Some(signed.identity),
        })
    }

    /// A window clamped to the push deadline ended because the push did.
    fn expired(&self, id: &Identity) -> Error {
        if id.expires_at_ms == self.deadline_ms {
            Error::Deadline
        } else {
            Error::EnvelopeExpired
        }
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
        if let Some(policy) = self.request_policy {
            let context = RequestContext {
                signing: request,
                intent: opts.intent.copied(),
                public_key: signer.public_key(),
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
        let mut copy = Request::new(request.body().clone());
        *copy.method_mut() = request.method().clone();
        *copy.uri_mut() = request.uri().clone();
        *copy.headers_mut() = request.headers().clone();
        send_checked(self.transport, copy, limit).await
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
                ChannelError::Refused(cause) => Error::Transport(cause),
            })?;
    if response.body().len() > limit {
        return Err(Error::Limit("RPC response"));
    }
    if !response.status().is_success() {
        let parsed = serde_json::from_slice::<RemoteError>(response.body());
        if response.status().as_u16() == 402 || challenged(parsed.as_ref().ok()) {
            return Err(Error::PaymentRequired(Box::new(admission_required(
                parsed.ok().as_ref(),
                response.headers(),
            )?)));
        }
        let mut error = parsed.map_err(|_| Error::Invalid("Connect error JSON"))?;
        error.status = response.status().as_u16();
        error.headers = response.headers().clone();
        return Err(Error::Remote(Box::new(error)));
    }
    if response.status() != http::StatusCode::OK
        || response.headers().get("content-type") != content_type.as_ref()
        || response
            .headers()
            .get("content-encoding")
            .is_some_and(|v| v != "identity")
        || response
            .headers()
            .get("connect-content-encoding")
            .is_some_and(|v| v != "identity")
    {
        return Err(Error::Invalid("Connect response status/encoding"));
    }
    let (parts, body) = response.into_parts();
    Ok((body, parts.headers))
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
pub(crate) struct Frames<'a> {
    rest: &'a [u8],
    done: bool,
}
impl<'a> Frames<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self {
            rest: bytes,
            done: false,
        }
    }
}
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

/// The end frame of a stream: `{}` or `{"error": ...}`. A challenge error
/// becomes `PaymentRequired`, like a unary one.
fn end_error(frame: &[u8]) -> Result<(), Error> {
    let end: serde_json::Value =
        serde_json::from_slice(frame).map_err(|_| Error::Invalid("Connect end JSON"))?;
    let Some(error) = end.get("error") else {
        return Ok(());
    };
    let remote: RemoteError =
        serde_json::from_value(error.clone()).map_err(|_| Error::Invalid("Connect end error"))?;
    if challenged(Some(&remote)) {
        return Err(Error::PaymentRequired(Box::new(admission_required(
            Some(&remote),
            &HeaderMap::new(),
        )?)));
    }
    Err(Error::Remote(Box::new(remote)))
}

pub(crate) fn decode_stream(bytes: &[u8]) -> Result<Vec<&[u8]>, Error> {
    Frames::new(bytes).collect()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod channel_tests {
    use super::*;
    use std::future::Future as _;

    struct ExistingChannel;
    impl HttpTransport for ExistingChannel {
        async fn send(&self, _: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
            Err("unavailable: deterministic refusal".to_owned())
        }
    }

    struct ClassifiedChannel;
    impl HttpTransport for ClassifiedChannel {
        async fn send(&self, _: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
            panic!("classified send must be used")
        }

        async fn send_classified(
            &self,
            _: Request<Vec<u8>>,
            _: usize,
        ) -> Result<Response<Vec<u8>>, ChannelError> {
            Err(ChannelError::Transient("connection reset".to_owned()))
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
            &ClassifiedChannel,
            Request::new(Vec::new()),
            1024,
        ))
        .expect_err("connection failure");
        assert!(matches!(error, Error::Connection(cause) if cause == "connection reset"));
    }
}
