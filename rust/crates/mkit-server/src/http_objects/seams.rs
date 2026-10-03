//! The hand-off points later work packages fill. Every default is inert: no
//! tokens, no admission, no takedown, and proofs answer 416.

use std::sync::Arc;

use mkit_core::hash::Hash;

use super::body::EndHook;
use super::reach::{Reachability, TtlReachability};
use super::{HttpObjectResponse, HttpObjectsConfig};
use crate::repo::RepoId;
use crate::{BoxFuture, MaybeSend, MaybeSync, Redacted, ServerError};

/// §3 step 5, filled by WP-4.15: check a present token's syntax, key id and
/// signature **before** the repository lookup. The result is held until the
/// repository's visibility is known; a public repository ignores it. The
/// token is never logged.
pub trait TokenGate: MaybeSend + MaybeSync {
    /// Retain a redacted verified statement until visibility is known.
    fn precheck(
        &self,
        token: &Redacted,
        now_ms: i64,
    ) -> Result<crate::url_token::Prechecked, crate::url_token::TokenRejected>;
    /// Configured maximum token lifetime, used by stateless binding checks.
    fn ttl_ms(&self) -> u64;
}

/// No keys are configured; private reads fail with the uniform 404.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTokens;
impl TokenGate for NoTokens {
    fn precheck(
        &self,
        _: &Redacted,
        _: i64,
    ) -> Result<crate::url_token::Prechecked, crate::url_token::TokenRejected> {
        Err(crate::url_token::TokenRejected)
    }
    fn ttl_ms(&self) -> u64 {
        0
    }
}
impl TokenGate for crate::url_token::UrlTokenConfig {
    fn precheck(
        &self,
        token: &Redacted,
        now_ms: i64,
    ) -> Result<crate::url_token::Prechecked, crate::url_token::TokenRejected> {
        self.precheck(token.expose(), now_ms)
    }
    fn ttl_ms(&self) -> u64 {
        self.ttl_ms()
    }
}

/// One admitted read (§7), filled by WP-4.13, which adds the request's
/// credential headers.
#[derive(Debug)]
#[non_exhaustive]
pub(crate) struct AdmitRequest<'a> {
    /// A HEAD declares the GET byte count but sends no body.
    #[cfg(test)]
    pub head: bool,
    /// A ref path rather than an object id.
    #[cfg(test)]
    pub ref_path: bool,
    /// The selected GET body length, after ordinary Range or proof selection.
    pub declared_bytes: u64,
    /// Selected payment credentials; never contains Bearer credentials.
    pub credential_headers: &'a [crate::pipeline::CredentialHeader],
}

/// What an admitted read adds to its 200 or 206.
#[derive(Default)]
pub(crate) struct Admitted {
    /// Success means the response is `private` (§5.3).
    pub private: bool,
    /// Passthrough headers such as `Payment-Receipt`.
    pub headers: Vec<(&'static str, String)>,
    /// Called once when the body ends (`ReadServed{bytes}`), also for a HEAD
    /// with zero bytes.
    pub on_end: Option<EndHook>,
}

impl core::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Admitted")
            .field("private", &self.private)
            .field("on_end", &self.on_end.is_some())
            .finish_non_exhaustive()
    }
}

/// The admission verdict.
#[derive(Debug)]
pub(crate) enum AdmitDecision {
    /// Serve the content.
    Allow(Admitted),
    /// A challenge supplied by a test seam.
    #[cfg(test)]
    Respond(HttpObjectResponse),
}

/// §3 step 11: read Admission, when configured.
pub(crate) trait HttpAdmission: MaybeSend + MaybeSync {
    /// Whether read Admission is configured. A 304 then selects the private
    /// cache policy, without calling [`Self::admit`] (§5.3).
    fn is_configured(&self) -> bool {
        true
    }

    /// Admit or challenge one read.
    fn admit<'a>(
        &'a self,
        request: &'a AdmitRequest<'a>,
    ) -> BoxFuture<'a, Result<AdmitDecision, ServerError>>;
}

/// No read Admission is configured.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NoAdmission;

impl HttpAdmission for NoAdmission {
    fn is_configured(&self) -> bool {
        false
    }

    fn admit<'a>(
        &'a self,
        _: &'a AdmitRequest<'a>,
    ) -> BoxFuture<'a, Result<AdmitDecision, ServerError>> {
        Box::pin(async { Ok(AdmitDecision::Allow(Admitted::default())) })
    }
}

/// The takedown verdict for a resolved leaf.
#[derive(Debug)]
pub enum TakedownVerdict {
    /// Continue.
    Clear,
    /// §3 step 7: blocked but not yet tombstoned, the uniform 404.
    NotFound,
    /// §3 step 8: answer 451 with this response.
    Respond(HttpObjectResponse),
}

/// §3 steps 7 and 8, filled by WP-5.9a: tombstones and blocks.
pub trait TakedownGate: MaybeSend + MaybeSync {
    /// The reachability walk's per-object stop predicate: never descend
    /// through a blocked or tombstoned manifest.
    fn stops_descent(&self, _repo: &RepoId, _id: &Hash) -> bool {
        false
    }

    /// Decide for a leaf already proven a reachable member. A cached
    /// reachability proof skips the walk and its [`Self::stops_descent`], so
    /// this must also refuse a chunk that only a blocked or tombstoned
    /// manifest reaches (§4).
    fn check<'a>(
        &'a self,
        repo: &'a RepoId,
        leaf: &'a Hash,
    ) -> BoxFuture<'a, Result<TakedownVerdict, ServerError>>;
}

/// Nothing is blocked or tombstoned.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTakedown;

impl TakedownGate for NoTakedown {
    fn check<'a>(
        &'a self,
        _: &'a RepoId,
        _: &'a Hash,
    ) -> BoxFuture<'a, Result<TakedownVerdict, ServerError>> {
        Box::pin(async { Ok(TakedownVerdict::Clear) })
    }
}

/// Canonical repository objects supplied to a proof builder. Reads verify
/// membership and integrity and share one bounded decode allowance.
pub trait ProofSource: MaybeSend {
    /// Read one canonical object; never concatenated extracted file bytes.
    fn read(&mut self, id: Hash) -> BoxFuture<'_, Result<Vec<u8>, ServerError>>;
}

/// Selected proof. Preparation constructs no Merkle or Bao proofs.
#[derive(Debug, Clone)]
pub struct PreparedProof {
    /// Published-reachable commit or remix.
    pub commit: Hash,
    /// Leaf matched by the exact decoded path.
    pub leaf: Hash,
    /// Path below the commit's tree.
    pub path: Vec<Vec<u8>>,
    /// Inclusive content range, or canonical Object selector.
    pub range: Option<(u64, u64)>,
    /// Exact encoded GET length, checked before Admission.
    pub encoded_len: u64,
    /// Cross-chunk range uses MKDS; all other selections use MKDP.
    pub span: bool,
}

/// Build only the already selected representation, after common Admission.
pub trait ProofServer: MaybeSend + MaybeSync {
    /// Whether the adapter can build proofs. Unsupported selections return
    /// 416 before admission, rather than reserving an unservable request.
    fn is_supported(&self) -> bool {
        true
    }
    /// Return encoded bytes; the common path enforces the planned length.
    fn build<'a>(
        &'a self,
        request: &'a PreparedProof,
        source: &'a mut dyn ProofSource,
    ) -> BoxFuture<'a, Result<Vec<u8>, ServerError>>;
}

/// Workers gain canonical-object prefetch in WP-4.14b-2.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedProofs;
impl ProofServer for UnsupportedProofs {
    fn is_supported(&self) -> bool {
        false
    }
    fn build<'a>(
        &'a self,
        _: &'a PreparedProof,
        _: &'a mut dyn ProofSource,
    ) -> BoxFuture<'a, Result<Vec<u8>, ServerError>> {
        Box::pin(async {
            Err(ServerError::new(
                crate::Code::OutOfRange,
                "proof unsupported",
            ))
        })
    }
}

/// Every seam of one HTTP-objects deployment.
#[derive(Clone)]
#[non_exhaustive]
pub struct HttpSeams {
    /// §3 step 5 (WP-4.15).
    pub tokens: Arc<dyn TokenGate>,
    /// Retains asynchronous read finalization on cancellation. Required for reservations.
    pub read_runtime: Option<super::HttpReadRuntime>,
    /// §3 step 11 (WP-4.13).
    pub(crate) admission: Arc<dyn HttpAdmission>,
    /// §3 steps 7-8 (WP-5.9a).
    pub takedown: Arc<dyn TakedownGate>,
    /// Proof representations (WP-4.14b).
    pub proofs: Arc<dyn ProofServer>,
    /// Reachability answers (WP-5.3a).
    pub reachability: Arc<dyn Reachability>,
}

impl HttpSeams {
    /// The inert defaults for `cfg`.
    #[must_use]
    pub fn new(cfg: &HttpObjectsConfig) -> Self {
        Self {
            tokens: Arc::new(NoTokens),
            read_runtime: None,
            admission: Arc::new(NoAdmission),
            takedown: Arc::new(NoTakedown),
            proofs: Arc::new(UnsupportedProofs),
            reachability: Arc::new(TtlReachability::new(
                cfg.reachability_lag_ms,
                cfg.reach_cache_entries,
            )),
        }
    }
}

impl core::fmt::Debug for HttpSeams {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpSeams").finish_non_exhaustive()
    }
}
