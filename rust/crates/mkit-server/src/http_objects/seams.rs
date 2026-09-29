//! The hand-off points later work packages fill. Every default is inert: no
//! tokens, no admission, no takedown, and proofs answer 416.

use std::sync::Arc;

use mkit_core::hash::Hash;
use mkit_core::object::ObjectType;

use super::body::EndHook;
use super::reach::{Reachability, TtlReachability};
use super::route::{Query, Target};
use super::{HttpObjectResponse, HttpObjectsConfig};
use crate::repo::RepoId;
use crate::{BoxFuture, MaybeSend, MaybeSync, Redacted, ServerError};

/// §3 step 5, filled by WP-4.15: check a present token's syntax, key id and
/// signature **before** the repository lookup. The result is held until the
/// repository's visibility is known; a public repository ignores it. The
/// token is never logged.
pub trait TokenGate: MaybeSend + MaybeSync {
    /// Whether the token passed its precheck.
    fn precheck(&self, target: &Target, token: &Redacted) -> bool;
}

/// No tokens are issued yet: every precheck passes and nothing reads it.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTokens;

impl TokenGate for NoTokens {
    fn precheck(&self, _: &Target, _: &Redacted) -> bool {
        true
    }
}

/// One admitted read (§7), filled by WP-4.13.
#[derive(Debug)]
pub struct AdmitRequest<'a> {
    /// The selected repository.
    pub repo: &'a RepoId,
    /// A HEAD declares the GET byte count but sends no body.
    pub head: bool,
    /// A ref path rather than an object id.
    pub ref_path: bool,
    /// The selected GET body length, after ordinary Range selection.
    pub declared_bytes: u64,
}

/// What an admitted read adds to its 200 or 206.
#[derive(Default)]
pub struct Admitted {
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
pub enum AdmitDecision {
    /// Serve the content.
    Allow(Admitted),
    /// Answer with this instead (a 402 challenge).
    Respond(HttpObjectResponse),
}

/// §3 step 11: read Admission, when configured.
pub trait HttpAdmission: MaybeSend + MaybeSync {
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
pub struct NoAdmission;

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

    /// Decide for a leaf already proven a reachable member.
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

/// A `?proof=1` request that resolved to a reachable leaf.
#[derive(Debug)]
pub struct ProofRequest<'a> {
    /// The selected repository.
    pub repo: &'a RepoId,
    /// The resolved leaf.
    pub leaf: Hash,
    /// Its object type.
    pub ty: ObjectType,
    /// The resolved commit of a ref path.
    pub commit: Option<Hash>,
    /// A ref path rather than an object id.
    pub ref_path: bool,
    /// The parsed query (`range`, `commit`, `path`).
    pub query: &'a Query,
}

/// WP-4.14b owns every `proof=1` representation: MKDP and MKDS, their `ETag`s,
/// caps and `Accept-Ranges: none`.
pub trait ProofServer: MaybeSend + MaybeSync {
    /// The complete response for a proof request.
    fn serve<'a>(
        &'a self,
        request: &'a ProofRequest<'a>,
    ) -> BoxFuture<'a, Result<HttpObjectResponse, ServerError>>;
}

/// Proofs are unsupported until WP-4.14b: 416, which §3 step 10 allows for an
/// unsupported proof.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedProofs;

impl ProofServer for UnsupportedProofs {
    fn serve<'a>(
        &'a self,
        _: &'a ProofRequest<'a>,
    ) -> BoxFuture<'a, Result<HttpObjectResponse, ServerError>> {
        Box::pin(async { Ok(HttpObjectResponse::error(416)) })
    }
}

/// Every seam of one HTTP-objects deployment.
#[derive(Clone)]
pub struct HttpSeams {
    /// §3 step 5 (WP-4.15).
    pub tokens: Arc<dyn TokenGate>,
    /// §3 step 11 (WP-4.13).
    pub admission: Arc<dyn HttpAdmission>,
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
