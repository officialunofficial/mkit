//! The `test-faults` seam (reconciliation R-11): [`FaultHooks`] called at
//! six points of the pipeline, and per-request [`TestDirectives`] read
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
use crate::op::{OpKind, Operation};
use crate::rt::{BoxFuture, MaybeSend, MaybeSync};
use crate::store::{Batch, codec};

/// Header naming a fault for this request, e.g. `after-reserve`.
pub const FAULT_HEADER: &str = "x-mkit-test-fault";

/// Header shifting the business clock by a signed number of milliseconds
/// for this request only.
pub const CLOCK_SKEW_HEADER: &str = "x-mkit-test-clock-skew-ms";

/// Delay before the committed `UpdateRef`'s test timer, in milliseconds.
pub const TIMER_MS_HEADER: &str = "x-mkit-test-timer-ms";
/// Ref whose shard is ticked before `ListRefs`.
pub const RUN_TIMERS_HEADER: &str = "x-mkit-test-run-timers";

/// Epoch bump before `ListRefs`.
pub const BUMP_EPOCH_HEADER: &str = "x-mkit-test-bump-epoch";
/// Declare coordinator lease-table recovery before `ListRefs`.
pub const LEASE_RECOVERED_HEADER: &str = "x-mkit-test-lease-recovered";
/// Delay source relay delivery after a committed write, in milliseconds.
pub const RELAY_DELAY_MS_HEADER: &str = "x-mkit-test-relay-delay-ms";

/// Source-local test marker. A release build cannot read or write it.
pub(crate) fn relay_delay_key() -> crate::Key {
    crate::Key::new(&b"tdr\0"[..])
}

/// Attach a delivery hold to the same batch as a test ref commit.
pub(crate) fn delay_relay_batch(
    batch: Batch,
    directives: &TestDirectives,
    op: &Operation,
    now_ms: u64,
) -> Batch {
    // Skip the marker on a full batch: the planner sized it (pruning
    // included) without this test-only op.
    if let Some(delay) = directives.relay_delay_ms
        && matches!(op.kind, OpKind::UpdateRef(_) | OpKind::AdvanceRefs { .. })
        && batch.preconditions.len() + batch.writes.len() < crate::store::MAX_BATCH_OPS
    {
        batch.put(
            relay_delay_key(),
            codec::encode_u64(now_ms.saturating_add(delay)),
        )
    } else {
        batch
    }
}

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
    /// After a durable lease grant, before the shard installs it.
    AfterLeaseGrant,
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
    /// Test timer delay on a committed `UpdateRef`.
    pub timer_ms: Option<u64>,
    /// Epoch to bump before `ListRefs`.
    pub bump_epoch: Option<u64>,
    /// Declare lease-table recovery before `ListRefs`.
    pub lease_recovered: bool,
    /// Ref shard to tick before `ListRefs`.
    pub run_timers: Option<String>,
    /// Delay relay delivery from this ref shard until business time plus this value.
    pub relay_delay_ms: Option<u64>,
}

impl TestDirectives {
    /// Read the directives through `get`, which looks a header up by its
    /// lowercase name.
    ///
    /// # Errors
    /// `invalid_argument` for a malformed skew, epoch, recovery, or timer directive.
    pub fn from_headers(get: impl Fn(&str) -> Option<String>) -> Result<Self, ServerError> {
        let clock_skew_ms = match get(CLOCK_SKEW_HEADER) {
            Some(v) => v.trim().parse().map_err(|_| {
                ServerError::invalid_argument("x-mkit-test-clock-skew-ms is not an integer")
            })?,
            None => 0,
        };
        let timer_ms = get(TIMER_MS_HEADER)
            .map(|v| {
                v.trim().parse::<u64>().map_err(|_| {
                    ServerError::invalid_argument("x-mkit-test-timer-ms is not an unsigned integer")
                })
            })
            .transpose()?;
        let run_timers = get(RUN_TIMERS_HEADER);
        let relay_delay_ms = get(RELAY_DELAY_MS_HEADER)
            .map(|v| {
                v.trim().parse::<u64>().map_err(|_| {
                    ServerError::invalid_argument(
                        "x-mkit-test-relay-delay-ms is not an unsigned integer",
                    )
                })
            })
            .transpose()?;
        if run_timers
            .as_ref()
            .is_some_and(|name| !crate::refs::validate_ref_name(name))
        {
            return Err(ServerError::invalid_argument(
                "x-mkit-test-run-timers is not a ref name",
            ));
        }
        let bump_epoch = get(BUMP_EPOCH_HEADER)
            .map(|v| {
                v.trim().parse::<u64>().map_err(|_| {
                    ServerError::invalid_argument(
                        "x-mkit-test-bump-epoch is not an unsigned integer",
                    )
                })
            })
            .transpose()?;
        let lease_recovered = match get(LEASE_RECOVERED_HEADER).as_deref() {
            None => false,
            Some("1") => true,
            Some(_) => {
                return Err(ServerError::invalid_argument(
                    "x-mkit-test-lease-recovered must be 1",
                ));
            }
        };
        Ok(Self {
            bump_epoch,
            lease_recovered,
            timer_ms,
            run_timers,
            relay_delay_ms,
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

/// Schedule only after the ref batch really committed (never on replay/conflict).
pub(crate) async fn schedule_timer<S: crate::NamespaceStore>(
    directives: &TestDirectives,
    store: &S,
    p: &crate::Partition,
    repo: &crate::RepoName,
    name: &str,
    business_now: u64,
) -> Result<(), ServerError> {
    use crate::store::keys;
    use crate::timers::registry::kinds;
    use crate::{Batch, BatchOutcome, Value};
    let Some(delay) = directives.timer_ms else {
        return Ok(());
    };
    let reference = [repo.as_str().as_bytes(), b"\0", name.as_bytes()].concat();
    let batch = Batch::new().put(
        keys::timer(
            business_now.saturating_add(delay),
            kinds::TEST.get(),
            &reference,
        ),
        Value::default(),
    );
    match store.apply(p, batch).await {
        Ok(BatchOutcome::Committed) => Ok(()),
        outcome => Err(ServerError::internal(
            "test timer scheduling failed",
            format!("{outcome:?}"),
        )),
    }
}
/// Borrow the pipeline's store as a relay target without cloning a Worker
/// adapter or changing its partition routing.
struct BorrowedStore<'a, S>(&'a S);

impl<S: crate::NamespaceStore> crate::NamespaceStore for BorrowedStore<'_, S> {
    fn capabilities(&self) -> crate::StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(
        &self,
        p: &crate::Partition,
        k: &crate::Key,
    ) -> Result<Option<crate::Value>, crate::StoreError> {
        self.0.get(p, k).await
    }
    async fn scan(
        &self,
        p: &crate::Partition,
        start: &crate::Key,
        end: &crate::Key,
        after: Option<&crate::Cursor>,
        limit: u32,
    ) -> Result<crate::ScanPage, crate::StoreError> {
        self.0.scan(p, start, end, after, limit).await
    }
    async fn apply(
        &self,
        p: &crate::Partition,
        batch: Batch,
    ) -> Result<crate::BatchOutcome, crate::StoreError> {
        self.0.apply(p, batch).await
    }
    async fn stats(
        &self,
        p: &crate::Partition,
    ) -> Result<crate::PartitionStats, crate::StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), crate::StoreError> {
        self.0.probe().await
    }
}

/// Tick the requested ref shard before the ordinary listing.
pub(crate) async fn run_timers<S: crate::NamespaceStore>(
    directives: &TestDirectives,
    store: &S,
    shards: &dyn super::ShardMap,
    repo: &crate::RepoId,
    clock: &dyn crate::Clock,
    business_now: u64,
) -> Result<(), ServerError> {
    use crate::relay::{NoHook, RelayBudget, RelayHandler};
    use crate::timers::{TickBudget, TimerRegistry, run_due, test_kind::TestTimer};
    if let Some(name) = &directives.run_timers {
        let partition = shards.ref_shard(repo, name);
        let registry = TimerRegistry::new()
            .register(TestTimer)
            .register(RelayHandler {
                target: BorrowedStore(store),
                hook: NoHook,
                budget: RelayBudget::default(),
            });
        // Bounded: rows this registry doesn't know (for example other timer
        // kinds) can keep a tick stopped on budget with nothing fired.
        for _ in 0..64 {
            let report = run_due(
                store,
                &partition,
                &registry,
                clock,
                business_now,
                &TickBudget::default(),
            )
            .await
            .map_err(|e| ServerError::internal("test timer tick failed", e))?;
            if report.fired == 0 {
                if report.failed > 0 {
                    return Err(ServerError::unavailable(format!(
                        "test timer tick failed: {report:?}"
                    )));
                }
                if report.raced > 0 || report.stopped_on_budget || report.deferred > 0 {
                    continue;
                }
                return Ok(());
            }
        }
        return Err(ServerError::unavailable(
            "test timers did not drain within 64 ticks",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod timer_tests {
    use super::*;
    #[test]
    fn timer_directives_validate_values() {
        for (header, value) in [
            (TIMER_MS_HEADER, "-1"),
            (TIMER_MS_HEADER, "18446744073709551616"),
            (RELAY_DELAY_MS_HEADER, "-1"),
            (RUN_TIMERS_HEADER, "bad ref"),
        ] {
            assert!(TestDirectives::from_headers(|h| (h == header).then(|| value.into())).is_err());
        }
        let d = TestDirectives::from_headers(|h| match h {
            TIMER_MS_HEADER => Some("1000".into()),
            RUN_TIMERS_HEADER => Some("refs/heads/x".into()),
            RELAY_DELAY_MS_HEADER => Some("10000".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(d.timer_ms, Some(1000));
        assert_eq!(d.run_timers.as_deref(), Some("refs/heads/x"));
        assert_eq!(d.relay_delay_ms, Some(10_000));
    }
}
