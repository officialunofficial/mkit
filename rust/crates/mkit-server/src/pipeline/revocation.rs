//! Epoch changes serialize with grants in the coordinator. Pushes and
//! acknowledgements are separate guarded transactions, always in that order.

use crate::authority::FenceKind;
use crate::error::ServerError;
use crate::repo::NamespaceKey;
use crate::store::{
    Batch, BatchOutcome, MultipartBlobStore, NamespaceStore, Partition, Precondition, Value, codec,
    keys, restore::mark_lease_table_recovered,
};
use mkit_attest::grant::{EpochTransition, epoch_transition};

use super::{HookSet, Pipeline, internal, lease::observed_guard, meta_error, ms};

/// Largest allowed epoch increment (SPEC-WRITE-GRANTS §1.1).
pub const MAX_EPOCH_STEP: u64 = mkit_attest::grant::MAX_EPOCH_STEP;
const PAGE_SIZE: u32 = 4;
// A frozen clock and acknowledged/expired rows must not permit an unbounded
// walk. Each slice reads at most 32 rows in eight pages, besides four bounded
// push loops (one attempt, at most five store calls each).
const MAX_SCAN_PAGES: u32 = 8;
// Bound contention even with a frozen injected clock.
const MAX_PUSH_ATTEMPTS: u32 = 1;

/// One revocation slice processes at most four shards, within this time budget.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RevokeBudget {
    /// Milliseconds of elapsed pipeline time allowed between store calls.
    pub max_elapsed_ms: u64,
}

impl RevokeBudget {
    /// A positive elapsed-time budget; each slice visits at most four shards.
    #[must_use]
    pub const fn new(max_elapsed_ms: u64) -> Self {
        Self {
            max_elapsed_ms: if max_elapsed_ms == 0 {
                1
            } else {
                max_elapsed_ms
            },
        }
    }
}

impl Default for RevokeBudget {
    fn default() -> Self {
        Self::new(1000)
    }
}

/// Completion is reported only after every lease is acknowledged or expired,
/// and any declared recovery holdoff has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevokeProgress {
    /// No old-epoch write can still commit.
    Complete,
    /// Outstanding shards counted so far. At a budget stop this is a lower
    /// bound (at least one); recovery holdoff alone also returns one.
    Pending {
        /// Conservative lower bound on remaining work.
        remaining: u64,
    },
}

/// An epoch-bound scan checkpoint is only an optimization. Completed prefix
/// rows cannot become outstanding again at the same epoch: live renewal
/// preserves their ack, expired renewal acknowledges that epoch immediately,
/// and any newly inserted row grants the coordinator's current epoch.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeCheckpoint {
    generation: u64,
    recovery: Option<codec::LeaseRecovery>,
    cursor: Vec<u8>,
}

struct CoordinatorState {
    kind: FenceKind,
    epoch_value: Option<Value>,
    epoch: u64,
    config_version: u64,
    recovery: Option<codec::LeaseRecovery>,
}

fn generation(row: &codec::LeasedShard, kind: FenceKind) -> u64 {
    match kind {
        FenceKind::Grant => row.epoch,
        FenceKind::Authority => row.authority_generation.unwrap_or(0),
    }
}
fn acked(row: &codec::LeasedShard, kind: FenceKind) -> Option<u64> {
    match kind {
        FenceKind::Grant => Some(row.acked_epoch),
        FenceKind::Authority => row.acked_authority_generation,
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Advance the coordinator epoch, serialized with every epoch lease grant.
    ///
    /// # Errors
    /// `invalid_argument` unless the increment is in `1..=1024`;
    /// `unavailable` on repeated contention, or a mapped storage failure.
    pub async fn bump_epoch(&self, ns: &NamespaceKey, new_epoch: u64) -> Result<(), ServerError> {
        match self.transition_epoch(ns, new_epoch).await? {
            EpochTransition::Advance => Ok(()),
            EpochTransition::Retry | EpochTransition::Reject => Err(ServerError::invalid_argument(
                "epoch increment must be between 1 and 1024",
            )),
        }
    }

    /// CAS the epoch. A lost CAS re-reads and re-classifies, including a
    /// concurrent winner that installed the same epoch (a valid retry).
    pub(super) async fn transition_epoch(
        &self,
        ns: &NamespaceKey,
        new_epoch: u64,
    ) -> Result<EpochTransition, ServerError> {
        self.transition_fence(ns, new_epoch, FenceKind::Grant).await
    }

    pub(super) async fn transition_fence(
        &self,
        ns: &NamespaceKey,
        new_epoch: u64,
        kind: FenceKind,
    ) -> Result<EpochTransition, ServerError> {
        let p = self.shards.coordinator(ns);
        for _ in 0..super::coordinator::CREATION_ATTEMPTS {
            let current = self.meta.get(&p, &kind.key()).await.map_err(meta_error)?;
            let epoch = current
                .as_ref()
                .map(codec::decode_u64)
                .transpose()
                .map_err(meta_error)?
                .unwrap_or(0);
            let transition = epoch_transition(epoch, new_epoch);
            if transition != EpochTransition::Advance {
                return Ok(transition);
            }
            let batch = Batch::new()
                .require(observed_guard(kind.key(), current.as_ref()))
                .put(kind.key(), codec::encode_u64(new_epoch));
            match self.apply_meta(&p, batch).await? {
                BatchOutcome::Committed => return Ok(EpochTransition::Advance),
                BatchOutcome::PreconditionFailed { .. } => {}
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(internal("epoch bump had no deadline"));
                }
            }
        }
        Err(ServerError::unavailable("epoch contention; retry").with_header("Retry-After", "1"))
    }

    /// Declare lease-table recovery using the real pipeline clock.
    /// Any procedure that restores or rebuilds a coordinator partition MUST
    /// call this before serving writes for that namespace. The durable marker
    /// prevents completion for `epoch_lease + margin` after recovery.
    ///
    /// # Errors
    /// A mapped storage failure, or `internal` for an impossible batch outcome.
    pub async fn mark_lease_table_recovered(&self, ns: &NamespaceKey) -> Result<(), ServerError> {
        mark_lease_table_recovered(
            &self.meta,
            &self.shards.coordinator(ns),
            ms(self.clock.now_ms()),
        )
        .await
        .map_err(meta_error)
    }

    async fn coordinator_state(
        &self,
        p: &Partition,
        kind: FenceKind,
    ) -> Result<CoordinatorState, ServerError> {
        let rows = self
            .meta
            .get_many(
                p,
                &[kind.key(), keys::namespace_record(), keys::lease_recovery()],
            )
            .await
            .map_err(meta_error)?;
        let [epoch, nr, lr] = rows.as_slice() else {
            return Err(internal("revocation get_many returned the wrong row count"));
        };
        Ok(CoordinatorState {
            kind,
            epoch: epoch
                .as_ref()
                .map(codec::decode_u64)
                .transpose()
                .map_err(meta_error)?
                .unwrap_or(0),
            epoch_value: epoch.clone(),
            config_version: nr
                .as_ref()
                .map(codec::decode_namespace_record)
                .transpose()
                .map_err(meta_error)?
                .map_or(1, |n| n.config_version),
            recovery: lr
                .as_ref()
                .map(codec::decode_lease_recovery)
                .transpose()
                .map_err(meta_error)?,
        })
    }

    fn recovery_pending(&self, state: &CoordinatorState) -> bool {
        state
            .recovery
            .and_then(codec::LeaseRecovery::recovery_time)
            .is_some_and(|resumed| {
                ms(self.clock.now_ms())
                    < resumed
                        .saturating_add(self.cfg.epoch_lease_ms)
                        .saturating_add(self.cfg.lease_margin_ms)
            })
    }

    fn revoke_budget_passed(&self, start: u64, budget: RevokeBudget) -> bool {
        ms(self.clock.now_ms()).saturating_sub(start) >= budget.max_elapsed_ms.max(1)
    }

    async fn read_revoke_cursor(
        &self,
        p: &Partition,
        state: &CoordinatorState,
    ) -> Result<(Option<Value>, Option<crate::store::Cursor>), ServerError> {
        let raw = self
            .meta
            .get(p, &keys::revoke_cursor(state.kind == FenceKind::Authority))
            .await
            .map_err(meta_error)?;
        let cursor = if let Some(raw) = raw.as_ref() {
            let bytes = raw.as_bytes();
            if bytes.len() > 32_768 || bytes.first() != Some(&1) {
                return Err(internal("invalid revocation checkpoint"));
            }
            let checkpoint: RevokeCheckpoint = serde_json::from_slice(&bytes[1..])
                .map_err(|_| internal("invalid revocation checkpoint"))?;
            if checkpoint.cursor.len() > crate::store::MAX_KEY_BYTES {
                return Err(internal("oversized revocation cursor"));
            }
            (checkpoint.generation == state.epoch && checkpoint.recovery == state.recovery)
                .then(|| crate::store::Cursor::new(checkpoint.cursor))
        } else {
            None
        };
        Ok((raw, cursor))
    }

    async fn save_revoke_cursor(
        &self,
        p: &Partition,
        state: &CoordinatorState,
        prior: Option<&Value>,
        cursor: Option<crate::store::Cursor>,
    ) -> Result<bool, ServerError> {
        let key = keys::revoke_cursor(state.kind == FenceKind::Authority);
        let recovery = state.recovery.as_ref().map(codec::encode_lease_recovery);
        let batch = Batch::new()
            .require(observed_guard(key.clone(), prior))
            .require(observed_guard(state.kind.key(), state.epoch_value.as_ref()))
            .require(observed_guard(keys::lease_recovery(), recovery.as_ref()));
        let batch = if let Some(cursor) = cursor {
            let checkpoint = RevokeCheckpoint {
                generation: state.epoch,
                recovery: state.recovery,
                cursor: cursor.as_bytes().to_vec(),
            };
            let mut bytes = vec![1];
            bytes.extend(
                serde_json::to_vec(&checkpoint)
                    .map_err(|_| internal("cannot encode revocation checkpoint"))?,
            );
            batch.put(key, Value::new(bytes))
        } else {
            batch.delete(key)
        };
        match self.apply_meta(p, batch).await? {
            BatchOutcome::Committed => Ok(true),
            BatchOutcome::PreconditionFailed { .. } => Ok(false),
            BatchOutcome::DeadlinePassed { .. } => Err(internal("checkpoint had no deadline")),
        }
    }

    /// Push and acknowledge at most four live shards in one bounded slice.
    /// Outside a declared recovery hold-off, `ls.acked_epoch = n` only if the
    /// shard's el durably holds epoch >= n, or all older-epoch writes are already
    /// past their commit deadline. Recovery fences surviving copies until then.
    /// Renewal alone never raises a live row's acknowledgement.
    ///
    /// # Errors
    /// A mapped storage or codec failure. Contention leaves progress pending.
    pub async fn revoke_step(
        &self,
        ns: &NamespaceKey,
        budget: &RevokeBudget,
    ) -> Result<RevokeProgress, ServerError> {
        self.revoke_fence_step(ns, budget, FenceKind::Grant).await
    }

    pub(super) async fn revoke_fence_step(
        &self,
        ns: &NamespaceKey,
        budget: &RevokeBudget,
        kind: FenceKind,
    ) -> Result<RevokeProgress, ServerError> {
        let start = ms(self.clock.now_ms());
        let coordinator = self.shards.coordinator(ns);
        let state = self.coordinator_state(&coordinator, kind).await?;
        let (first, end) = keys::class_range(keys::TAG_LEASED_SHARD);
        let (cursor_value, mut cursor) = self.read_revoke_cursor(&coordinator, &state).await?;
        let mut checkpoint = cursor.clone();
        let (mut visited, mut remaining, mut prefix_complete) = (0, 0_u64, true);
        let mut pages = 0;
        loop {
            if pages == MAX_SCAN_PAGES || self.revoke_budget_passed(start, *budget) {
                self.save_revoke_cursor(&coordinator, &state, cursor_value.as_ref(), checkpoint)
                    .await?;
                return Ok(RevokeProgress::Pending {
                    remaining: remaining.max(1),
                });
            }
            let page = self
                .meta
                .scan(&coordinator, &first, &end, cursor.as_ref(), PAGE_SIZE)
                .await
                .map_err(meta_error)?;
            pages += 1;
            if page.entries.len() > PAGE_SIZE as usize {
                return Err(internal("revocation scan exceeded its row bound"));
            }
            for (key, value) in page.entries {
                if self.revoke_budget_passed(start, *budget) {
                    self.save_revoke_cursor(
                        &coordinator,
                        &state,
                        cursor_value.as_ref(),
                        checkpoint,
                    )
                    .await?;
                    return Ok(RevokeProgress::Pending {
                        remaining: remaining.max(1),
                    });
                }
                let row = codec::decode_leased_shard(&value).map_err(meta_error)?;
                if row.expires_at_ms <= ms(self.clock.now_ms())
                    || acked(&row, state.kind) == Some(state.epoch)
                {
                    continue;
                }
                if acked(&row, state.kind).is_some_and(|n| n > state.epoch) || visited == 4 {
                    remaining += 1;
                    prefix_complete = false;
                    continue;
                }
                visited += 1;
                if !self
                    .push_and_ack(&coordinator, (&key, value), &state, start, budget)
                    .await?
                {
                    remaining += 1;
                    prefix_complete = false;
                }
            }
            if prefix_complete {
                checkpoint = page.next.clone();
            }
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        // Detect a newer epoch or recovery declaration during the slice.
        let latest = self.coordinator_state(&coordinator, kind).await?;
        if remaining == 0 && latest.epoch == state.epoch && !self.recovery_pending(&latest) {
            if self
                .save_revoke_cursor(&coordinator, &state, cursor_value.as_ref(), None)
                .await?
            {
                Ok(RevokeProgress::Complete)
            } else {
                Ok(RevokeProgress::Pending { remaining: 1 })
            }
        } else {
            self.save_revoke_cursor(
                &coordinator,
                &state,
                cursor_value.as_ref(),
                if latest.epoch == state.epoch && latest.recovery == state.recovery {
                    checkpoint
                } else {
                    None
                },
            )
            .await?;
            Ok(RevokeProgress::Pending {
                remaining: remaining.max(1),
            })
        }
    }

    #[allow(clippy::too_many_lines)] // The guarded push-before-ack sequence preserves both independently updated generations.
    async fn push_and_ack(
        &self,
        coordinator: &Partition,
        (key, mut value): (&crate::store::Key, Value),
        state: &CoordinatorState,
        start: u64,
        budget: &RevokeBudget,
    ) -> Result<bool, ServerError> {
        let Some(keys::ParsedKey::LeasedShard { repo, shard_ref }) = keys::parse(key) else {
            return Err(internal("invalid leased-shard key"));
        };
        let Partition::Coordinator(ns) = coordinator else {
            return Err(internal("revoke outside coordinator"));
        };
        let p = Partition::Ref {
            ns: ns.clone(),
            repo,
            shard_ref,
        };
        for _ in 0..MAX_PUSH_ATTEMPTS {
            if self.revoke_budget_passed(start, *budget) {
                return Ok(false);
            }
            let mut row = codec::decode_leased_shard(&value).map_err(meta_error)?;
            if row.expires_at_ms <= ms(self.clock.now_ms())
                || acked(&row, state.kind) == Some(state.epoch)
            {
                return Ok(true);
            }
            if generation(&row, state.kind) > state.epoch
                || acked(&row, state.kind).is_some_and(|n| n > state.epoch)
            {
                return Ok(false);
            }
            let old = self
                .meta
                .get(&p, &keys::epoch_lease())
                .await
                .map_err(meta_error)?;
            if let Some(old) = old.as_ref() {
                let old = codec::decode_epoch_lease(old).map_err(meta_error)?;
                // A stale slice must never undo a newer push or shorten a
                // concurrent renewal. Retry that coordinator observation.
                if match state.kind {
                    FenceKind::Grant => old.epoch,
                    FenceKind::Authority => old.authority_generation.unwrap_or(0),
                } > state.epoch
                {
                    return Ok(false);
                }
                if old.expires_at_ms > row.expires_at_ms {
                    let Some(latest) = self.meta.get(coordinator, key).await.map_err(meta_error)?
                    else {
                        return Ok(true);
                    };
                    value = latest;
                    continue;
                }
            }
            if self.revoke_budget_passed(start, *budget) {
                return Ok(false);
            }
            let prior = old
                .as_ref()
                .map(codec::decode_epoch_lease)
                .transpose()
                .map_err(meta_error)?;
            let lease = codec::EpochLease {
                authority_ready: prior.and_then(|el| el.authority_ready),
                epoch: if state.kind == FenceKind::Grant {
                    state.epoch
                } else {
                    prior.map_or(row.epoch, |el| el.epoch)
                },
                authority_generation: if state.kind == FenceKind::Authority {
                    Some(state.epoch)
                } else {
                    prior
                        .and_then(|el| el.authority_generation)
                        .or(row.authority_generation)
                },
                expires_at_ms: row.expires_at_ms,
                config_version: state.config_version,
            };
            let push = Batch::new()
                .require(observed_guard(keys::epoch_lease(), old.as_ref()))
                .put(keys::epoch_lease(), codec::encode_epoch_lease(&lease));
            match self.apply_meta(&p, push).await? {
                BatchOutcome::PreconditionFailed { .. } => continue,
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(internal("epoch push had no deadline"));
                }
                BatchOutcome::Committed => {}
            }
            if self.revoke_budget_passed(start, *budget) {
                return Ok(false);
            }
            match state.kind {
                FenceKind::Grant => row.acked_epoch = state.epoch,
                FenceKind::Authority => row.acked_authority_generation = Some(state.epoch),
            }
            let ack = Batch::new()
                .require(Precondition::Equals(key.clone(), value))
                .require(observed_guard(state.kind.key(), state.epoch_value.as_ref()))
                .put(key.clone(), codec::encode_leased_shard(&row));
            match self.apply_meta(coordinator, ack).await? {
                BatchOutcome::Committed => return Ok(true),
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(internal("epoch acknowledgement had no deadline"));
                }
                BatchOutcome::PreconditionFailed { .. } => {
                    let Some(latest) = self.meta.get(coordinator, key).await.map_err(meta_error)?
                    else {
                        return Ok(true);
                    };
                    value = latest;
                }
            }
        }
        Ok(false)
    }

    /// Test-only bump driver used by the `ListRefs` directive. No HTTP route.
    ///
    /// # Errors
    /// The bump/step error, or `unavailable` after ten seconds or 10,000 steps.
    /// The step cap also terminates when an injected clock stays frozen.
    #[cfg(feature = "test-faults")]
    pub async fn test_bump_epoch(
        &self,
        ns: &NamespaceKey,
        new_epoch: u64,
    ) -> Result<(), ServerError> {
        self.bump_epoch(ns, new_epoch).await?;
        let start = ms(self.clock.now_ms());
        for _ in 0..10_000 {
            if self.revoke_step(ns, &RevokeBudget::default()).await? == RevokeProgress::Complete {
                return Ok(());
            }
            if ms(self.clock.now_ms()).saturating_sub(start) >= 10_000 {
                return Err(ServerError::unavailable("epoch revocation pending; retry"));
            }
            // Yield even when the memory store completes synchronously.
            let mut yielded = false;
            core::future::poll_fn(|cx| {
                if yielded {
                    core::task::Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    core::task::Poll::Pending
                }
            })
            .await;
        }
        Err(ServerError::unavailable("epoch revocation pending; retry"))
    }
}

#[cfg(all(test, feature = "memory", feature = "test-faults"))]
mod tests {
    use super::*;
    use crate::pipeline::{AuthMode, Hooks, PipelineConfig, Sharding};
    use crate::upload::UploadLimits;
    use crate::{
        Addressing, Clock, Code, ManualClock, MemoryBlobStore, MemoryKv, NoopMetrics, RepoId,
        RepoName,
    };
    use std::sync::Arc;

    #[tokio::test]
    async fn test_bump_epoch_terminates_with_a_frozen_clock_during_recovery() {
        let clock = Arc::new(ManualClock::new(100_000));
        let namespace = NamespaceKey::deployment_default();
        let repo = RepoId {
            namespace: namespace.clone(),
            name: RepoName::new("room").expect("valid test repository"),
        };
        let mut cfg = PipelineConfig::new(
            Addressing::Single { repo },
            AuthMode::Open,
            UploadLimits {
                max_total_bytes: 64,
                max_chunks: 16,
            },
        );
        cfg.sharding = Sharding::D34;
        let pipe = Pipeline::new(
            MemoryBlobStore::default(),
            MemoryKv::with_clock(clock.clone()),
            Hooks::new(),
            cfg,
            clock.clone(),
            Arc::new(NoopMetrics),
        )
        .expect("valid pipeline configuration");
        pipe.mark_lease_table_recovered(&namespace)
            .await
            .expect("recovery marker commits");
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            pipe.test_bump_epoch(&namespace, 1),
        )
        .await
        .expect("step cap must terminate despite frozen pipeline clock")
        .expect_err("recovery holdoff cannot complete at frozen time");
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(clock.now_ms(), 100_000);
        assert_eq!(
            pipe.revoke_step(&namespace, &RevokeBudget::default())
                .await
                .expect("revoke step succeeds"),
            RevokeProgress::Pending { remaining: 1 },
        );
    }
}
