//! The `test-faults` seam (reconciliation R-11): [`FaultHooks`] called at
//! five points of the pipeline, and per-request [`TestDirectives`] read
//! from request headers.
//!
//! This module exists only with the `test-faults` feature, which no
//! release build enables. Without it the header names, the parsing code
//! and every fault-point call are compiled out of the binary.

use core::future::Future;
use std::collections::HashSet;
use std::sync::Mutex;

use mkit_core::hash::Hash;

use crate::error::ServerError;
use crate::op::Operation;
use crate::rt::{BoxFuture, MaybeSend, MaybeSync};

/// Header naming a fault for this request, e.g. `after-reserve`.
pub const FAULT_HEADER: &str = "x-mkit-test-fault";

/// Header shifting the business clock by a signed number of milliseconds
/// for this request only.
pub const CLOCK_SKEW_HEADER: &str = "x-mkit-test-clock-skew-ms";

/// Where the pipeline calls [`FaultHooks::at`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// After stage 1 (identity), before the replay lookup.
    AfterAuthenticate,
    /// After stage 2, before admission: the authorize→apply barrier.
    AfterAuthorize,
    /// `UploadPack`: after the reservation, before any chunk is written
    /// (`vcs-worker`'s `after-reserve`).
    AfterReserve,
    /// `UploadPack`: after the blob committed, before the final batch
    /// (`vcs-worker`'s `after-put`).
    AfterBlobCommit,
    /// After the final batch is planned (its deadline fixed), before
    /// `apply`. Fires on every planning attempt.
    BeforeFinalApply,
}

/// Test hooks the pipeline calls at each [`FaultPoint`].
pub trait FaultHooks: MaybeSend + MaybeSync {
    /// Called at each point. Ok → continue; Err → the pipeline returns that
    /// error as if the stage failed. An impl may also *wait* here: WP-1.25
    /// and WP-2.8 build the authorize→apply barrier (the revoke race, and
    /// the paused write whose lease expires, which pauses after planning)
    /// on this seam.
    fn at(
        &self,
        point: FaultPoint,
        op: &Operation,
        directives: &TestDirectives,
    ) -> impl Future<Output = Result<(), ServerError>> + MaybeSend;
}

/// The object-safe form the pipeline stores.
pub(crate) trait DynFaultHooks: MaybeSend + MaybeSync {
    fn at_boxed<'a>(
        &'a self,
        point: FaultPoint,
        op: &'a Operation,
        directives: &'a TestDirectives,
    ) -> BoxFuture<'a, Result<(), ServerError>>;
}

impl<F: FaultHooks> DynFaultHooks for F {
    fn at_boxed<'a>(
        &'a self,
        point: FaultPoint,
        op: &'a Operation,
        directives: &'a TestDirectives,
    ) -> BoxFuture<'a, Result<(), ServerError>> {
        Box::pin(self.at(point, op, directives))
    }
}

/// Per-request test directives, parsed from headers only under
/// `test-faults`: [`FAULT_HEADER`] (`vcs-worker` parity: `after-reserve`,
/// `after-put`) and [`CLOCK_SKEW_HEADER`] (added to the business clock for
/// this request, so black-box suites on `wrangler dev` exercise expiry
/// without sleeping; WP-1.14, WP-2.8). The skew never feeds a `NotAfter`
/// deadline, which uses the real clock; the backend evaluates it on its
/// own clock anyway.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestDirectives {
    /// The fault token, if any.
    pub fault: Option<String>,
    /// Business-clock skew, ms.
    pub clock_skew_ms: i64,
}

impl TestDirectives {
    /// Read the directives through `get`, which looks a header up by its
    /// lowercase name.
    ///
    /// # Errors
    /// `invalid_argument` for a skew that is not a decimal `i64`.
    pub fn from_headers(get: impl Fn(&str) -> Option<String>) -> Result<Self, ServerError> {
        let clock_skew_ms = match get(CLOCK_SKEW_HEADER) {
            Some(v) => v.trim().parse().map_err(|_| {
                ServerError::invalid_argument("x-mkit-test-clock-skew-ms is not an integer")
            })?,
            None => 0,
        };
        Ok(Self {
            fault: get(FAULT_HEADER).filter(|f| !f.is_empty()),
            clock_skew_ms,
        })
    }
}

/// `vcs-worker`'s `test_fault` (`auth_v2.mjs --fault`): when the request's
/// [`FAULT_HEADER`] is `after-reserve` or `after-put`, the matching point
/// ([`FaultPoint::AfterReserve`], [`FaultPoint::AfterBlobCommit`]) fails
/// with `internal` once per replay scope; a retry of the same operation
/// passes and resumes.
#[derive(Debug, Default)]
pub struct FailOnce {
    failed: Mutex<HashSet<(FaultPoint, Option<Hash>)>>,
}

impl FailOnce {
    /// No fault has fired yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl FaultHooks for FailOnce {
    async fn at(
        &self,
        point: FaultPoint,
        op: &Operation,
        directives: &TestDirectives,
    ) -> Result<(), ServerError> {
        let token = match point {
            FaultPoint::AfterReserve => "after-reserve",
            FaultPoint::AfterBlobCommit => "after-put",
            _ => return Ok(()),
        };
        if directives.fault.as_deref() != Some(token) {
            return Ok(());
        }
        let scope = op.auth.as_ref().map(|a| a.replay_scope);
        let first = self
            .failed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((point, scope));
        if first {
            return Err(ServerError::internal("injected test fault", token));
        }
        Ok(())
    }
}
