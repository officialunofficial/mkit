//! Host policy seams: an operation-scoped signer and a pre-dispatch observer.
//!
//! The client keeps no policy. For every signed request it runs, in order:
//!
//! 1. **observer** ([`Observer::before_dispatch`], writes only), which may veto
//!    and may return extra headers for this attempt;
//! 2. **signer** ([`Signer::sign_operation`]), which sees the structured
//!    operation it signs and may refuse;
//! 3. **deadline check**: a signed window that has already ended is never sent;
//! 4. **dispatch**.
//!
//! A veto or refusal stops the call before any later step, so nothing is signed
//! after a veto and nothing is sent after either. Both seams see the same
//! [`Attempt`]. A retry that builds a new envelope runs steps 1-4 again with a
//! new attempt.

use crate::connect::Error;
use http::{HeaderMap, HeaderName, HeaderValue};
use mkit_core::{hash::Hash, refs::RefWriteCondition, write_auth::ContentCommitment};

/// Full procedure names of the `mkit.transport.v1` write RPCs.
pub mod procedures {
    macro_rules! procedure {
        ($name:ident, $method:literal) => {
            #[doc = concat!("`", $method, "`.")]
            pub const $name: &str = concat!("/mkit.transport.v1.TransportService/", $method);
        };
    }
    procedure!(BEGIN_UPLOAD, "BeginUpload");
    procedure!(UPLOAD_PACK, "UploadPack");
    procedure!(UPLOAD_PART, "UploadPart");
    procedure!(COMPLETE_UPLOAD, "CompleteUpload");
    procedure!(ADVANCE_REFS, "AdvanceRefs");
    procedure!(UPDATE_REF, "UpdateRef");
}

/// One signed envelope: the nonce and window the signature covers, and which
/// try of the call this is.
///
/// `number` counts the envelopes built for one call in this process, from 1. A
/// replay of the same bytes (a caller replaying an [`Identity`](crate::Identity)
/// after a restart, a transport retry, or a pending-verification poll while the
/// envelope is valid) is not a new attempt: it carries the same nonce, so a
/// host keys its per-attempt record on `nonce`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attempt {
    pub number: u32,
    pub nonce: Hash,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

/// What a [`Signer`](crate::Signer) is asked to sign, next to the domain
/// separated digest. Covers every auth v2 envelope: unary (`body:`), whole-pack
/// (`pack:`) and part (`part:`) commitments.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SigningRequest<'a> {
    /// Full procedure, for example [`procedures::UPDATE_REF`].
    pub procedure: &'a str,
    /// Canonical origin the signature is bound to.
    pub audience: &'a str,
    pub repository: &'a str,
    pub commitment: ContentCommitment,
    /// Validity window and nonce; `attempt.number` is the try.
    pub attempt: Attempt,
}

/// Why a signer did not sign.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// Policy refused this operation. Becomes [`Error::SignerRefused`].
    Refused(String),
    /// The signer could not run (key unavailable, device error). Becomes
    /// [`Error::Signing`].
    Failed(String),
}
impl From<String> for SignError {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}
impl SignError {
    pub(crate) fn into_error(self) -> Error {
        match self {
            Self::Refused(reason) => Error::SignerRefused(reason),
            Self::Failed(reason) => Error::Signing(reason),
        }
    }
}

/// An observer's refusal of a write. Becomes [`Error::Vetoed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Veto(pub String);
impl Veto {
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// How a ref is written.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefTarget {
    /// Set the ref to this object id.
    Set(Hash),
    /// Delete the ref.
    Delete,
    /// Copy the published branch pair of `source` to the destination
    /// (`AdvanceRefs` with `source_ref`). The new value is the source's.
    CopyFrom {
        source: String,
        expected_tip: Option<Hash>,
    },
}

/// One ref move a request carries: name, precondition and new value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefMove {
    pub name: String,
    pub old: RefWriteCondition,
    pub new: RefTarget,
}
impl RefMove {
    #[must_use]
    pub fn new(name: impl Into<String>, old: RefWriteCondition, new: RefTarget) -> Self {
        Self {
            name: name.into(),
            old,
            new,
        }
    }
}

/// A write about to be dispatched. Fields not meaningful for a procedure are
/// empty. Build one with [`WriteIntent::new`] to sign a custom envelope.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct WriteIntent<'a> {
    /// Full procedure, for example [`procedures::ADVANCE_REFS`].
    pub procedure: &'a str,
    /// The exact ref moves the request carries (`UpdateRef`, `AdvanceRefs`).
    pub ref_moves: &'a [RefMove],
    /// The ref a `BeginUpload` reserves for.
    pub target_ref: Option<&'a str>,
    /// The pack being reserved or uploaded.
    pub pack_id: Option<Hash>,
    /// Pack bytes (`BeginUpload`, `UploadPack`) or part bytes (`UploadPart`).
    pub bytes: Option<u64>,
    /// Tickets: the one an `UploadPart` / `CompleteUpload` uses, or those an
    /// `AdvanceRefs` consumes. A per-RPC `complete_upload` takes only the opaque
    /// token, so it reports none; a whole push does.
    pub ticket_ids: &'a [Hash],
    pub part_index: Option<u32>,
    /// Ids of the objects the pack introduces. `Some` only when the caller knows
    /// all of them: a whole push whose entries are all raw objects. A delta
    /// entry's id is not known without applying it, so a pack holding one
    /// reports `None`, and so does every per-RPC upload.
    pub new_objects: Option<&'a [Hash]>,
}
impl<'a> WriteIntent<'a> {
    #[must_use]
    pub fn new(procedure: &'a str) -> Self {
        Self {
            procedure,
            ref_moves: &[],
            target_ref: None,
            pack_id: None,
            bytes: None,
            ticket_ids: &[],
            part_index: None,
            new_objects: None,
        }
    }
    /// The RPC name without its service prefix.
    #[must_use]
    pub fn method(&self) -> &'a str {
        self.procedure.rsplit('/').next().unwrap_or(self.procedure)
    }
    #[must_use]
    pub fn with_ref_moves(mut self, moves: &'a [RefMove]) -> Self {
        self.ref_moves = moves;
        self
    }
    #[must_use]
    pub fn with_target_ref(mut self, target: &'a str) -> Self {
        self.target_ref = Some(target);
        self
    }
    #[must_use]
    pub fn with_pack(mut self, id: Hash, bytes: u64) -> Self {
        self.pack_id = Some(id);
        self.bytes = Some(bytes);
        self
    }
    #[must_use]
    pub fn with_tickets(mut self, ids: &'a [Hash]) -> Self {
        self.ticket_ids = ids;
        self
    }
    #[must_use]
    pub fn with_part(mut self, index: u32, bytes: u64) -> Self {
        self.part_index = Some(index);
        self.bytes = Some(bytes);
        self
    }
    #[must_use]
    pub fn with_new_objects(mut self, ids: Option<&'a [Hash]>) -> Self {
        self.new_objects = ids;
        self
    }
}

/// Extra request headers for one attempt, not signed. Names are checked
/// against the hard-reserved list of SPEC-TRANSPORT-CONNECT section 5.1 before
/// anything is signed.
#[derive(Clone, Debug, Default)]
pub struct AttemptHeaders(Vec<(String, String)>);
impl AttemptHeaders {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Add a header, for example `traceparent` or a request id.
    #[must_use]
    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.push((name.into(), value.into()));
        self
    }

    pub(crate) fn validate(self) -> Result<HeaderMap, Error> {
        let mut map = HeaderMap::new();
        for (name, value) in self.0 {
            let parsed = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| Error::Invalid("attempt header name"))?;
            if is_reserved_header(parsed.as_str()) {
                return Err(Error::ReservedHeader(parsed.to_string()));
            }
            let value = HeaderValue::from_str(&value)
                .map_err(|_| Error::Invalid("attempt header value"))?;
            if map.insert(parsed, value).is_some() {
                return Err(Error::Invalid("duplicate attempt header"));
            }
        }
        Ok(map)
    }
}

const RESERVED_EXACT: &[&str] = &[
    "x-public-key",
    "x-signature",
    "x-digest",
    "x-created-at",
    "x-expires-at",
    "x-envelope-version",
    "x-audience",
    "x-repository",
    "x-content-commitment",
    "x-write-grant",
    "host",
    "transfer-encoding",
    "cookie",
    "idempotency-key",
    "authorization",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];
const RESERVED_PREFIX: &[&str] = &["x-mkit-", "x-forwarded-", "content-", "connect-", "proxy-"];

/// Hard-reserved request headers (SPEC-TRANSPORT-CONNECT section 5.1): the
/// auth v2 envelope, `X-Mkit-*`, `X-Forwarded-*`, framing and hop-by-hop
/// headers. `Authorization` is refused as well, because the client cannot know
/// whether its transport already sends one.
#[must_use]
pub fn is_reserved_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    RESERVED_EXACT.contains(&name.as_str())
        || RESERVED_PREFIX
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// Host policy run before a write is signed or sent. The default does nothing.
#[allow(async_fn_in_trait)]
pub trait Observer {
    /// Called once per attempt, before the attempt is signed, for every write
    /// RPC. `Err` vetoes the write: nothing is signed or sent. `Ok` may add
    /// headers for this attempt.
    ///
    /// # Errors
    /// A [`Veto`] stops the call with [`Error::Vetoed`].
    async fn before_dispatch(
        &self,
        intent: &WriteIntent<'_>,
        attempt: &Attempt,
    ) -> Result<AttemptHeaders, Veto> {
        let _ = (intent, attempt);
        Ok(AttemptHeaders::default())
    }
}

/// The observer of a client that has none.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoObserver;
impl Observer for NoObserver {}
