//! Epoch changes serialize with grants in the coordinator. Pushes and
//! acknowledgements are separate guarded transactions, always in that order.

use crate::error::ServerError;
use crate::repo::NamespaceKey;
use crate::store::{
    Batch, BatchOutcome, BlobStore, NamespaceStore, Partition, Precondition, Value, codec, keys,
};

use super::{HookSet, Pipeline, internal, lease::observed_guard, meta_error, ms};

/// Largest allowed epoch increment (SPEC-WRITE-GRANTS §1.1).
pub const MAX_EPOCH_STEP: u64 = 1024;
const PAGE_SIZE: u32 = 4;
// Bound contention even with a frozen injected clock.
const MAX_PUSH_ATTEMPTS: u32 = 32;

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
type RevokeCheckpoint = (u64, Option<codec::LeaseRecovery>, crate::store::Cursor);

#[derive(Default)]
pub(super) struct RevokeCursors(
    std::sync::Mutex<std::collections::BTreeMap<NamespaceKey, RevokeCheckpoint>>,
);

impl RevokeCursors {
    fn get(&self, ns: &NamespaceKey, state: &CoordinatorState) -> Option<crate::store::Cursor> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(ns)
            .filter(|(e, recovery, _)| *e == state.epoch && *recovery == state.recovery)
            .map(|(_, _, cursor)| cursor.clone())
    }

    fn set(
        &self,
        ns: &NamespaceKey,
        state: &CoordinatorState,
        cursor: Option<crate::store::Cursor>,
    ) {
        let mut cursors = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cursor) = cursor {
            cursors.insert(ns.clone(), (state.epoch, state.recovery, cursor));
        } else {
            cursors.remove(ns);
        }
    }
}

struct CoordinatorState {
    epoch_value: Option<Value>,
    epoch: u64,
    config_version: u64,
    recovery: Option<codec::LeaseRecovery>,
}

impl<B: BlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Advance the coordinator epoch, serialized with every epoch lease grant.
    /// The grant RPC and its owner-signature verification are WP-2.8.
    ///
    /// # Errors
    /// `invalid_argument` unless the increment is in `1..=1024`;
    /// `unavailable` on repeated contention, or a mapped storage failure.
    pub async fn bump_epoch(&self, ns: &NamespaceKey, new_epoch: u64) -> Result<(), ServerError> {
        let p = self.shards.coordinator(ns);
        for _ in 0..super::coordinator::CREATION_ATTEMPTS {
            let current = self
                .meta
                .get(&p, &keys::grant_epoch())
                .await
                .map_err(meta_error)?;
            let epoch = current
                .as_ref()
                .map(codec::decode_u64)
                .transpose()
                .map_err(meta_error)?
                .unwrap_or(0);
            if new_epoch <= epoch || new_epoch - epoch > MAX_EPOCH_STEP {
                return Err(ServerError::invalid_argument(
                    "epoch increment must be between 1 and 1024",
                ));
            }
            let batch = Batch::new()
                .require(observed_guard(keys::grant_epoch(), current.as_ref()))
                .put(keys::grant_epoch(), codec::encode_u64(new_epoch));
            match self.meta.apply(&p, batch).await.map_err(meta_error)? {
                BatchOutcome::Committed => return Ok(()),
                BatchOutcome::PreconditionFailed { .. } => {}
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(internal("epoch bump had no deadline"));
                }
            }
        }
        Err(ServerError::unavailable("epoch contention; retry"))
    }

    /// Declare lease-table recovery using the real pipeline clock.
    /// Any procedure that restores or rebuilds a coordinator partition MUST
    /// call this before serving writes for that namespace. The durable marker
    /// prevents completion for `epoch_lease + margin` after recovery.
    ///
    /// # Errors
    /// A mapped storage failure, or `internal` for an impossible batch outcome.
    pub async fn mark_lease_table_recovered(&self, ns: &NamespaceKey) -> Result<(), ServerError> {
        let batch = Batch::new().put(
            keys::lease_recovery(),
            codec::encode_lease_recovery(&codec::LeaseRecovery {
                resumed_at_ms: ms(self.clock.now_ms()),
            }),
        );
        match self
            .meta
            .apply(&self.shards.coordinator(ns), batch)
            .await
            .map_err(meta_error)?
        {
            BatchOutcome::Committed => Ok(()),
            _ => Err(internal("recovery marker batch unexpectedly failed")),
        }
    }

    async fn coordinator_state(&self, p: &Partition) -> Result<CoordinatorState, ServerError> {
        let rows = self
            .meta
            .get_many(
                p,
                &[
                    keys::grant_epoch(),
                    keys::namespace_record(),
                    keys::lease_recovery(),
                ],
            )
            .await
            .map_err(meta_error)?;
        let [epoch, nr, lr] = rows.as_slice() else {
            return Err(internal("revocation get_many returned the wrong row count"));
        };
        Ok(CoordinatorState {
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
        state.recovery.is_some_and(|lr| {
            ms(self.clock.now_ms())
                < lr.resumed_at_ms
                    .saturating_add(self.cfg.epoch_lease_ms)
                    .saturating_add(self.cfg.lease_margin_ms)
        })
    }

    fn revoke_budget_passed(&self, start: u64, budget: RevokeBudget) -> bool {
        ms(self.clock.now_ms()).saturating_sub(start) >= budget.max_elapsed_ms.max(1)
    }

    /// Push and acknowledge at most four live shards in one bounded slice.
    /// `ls.acked_epoch = n` only if the shard's el durably holds epoch >= n,
    /// or all older-epoch writes are already past their commit deadline.
    /// Renewal alone never raises a live row's acknowledgement.
    ///
    /// # Errors
    /// A mapped storage or codec failure. Contention leaves progress pending.
    pub async fn revoke_step(
        &self,
        ns: &NamespaceKey,
        budget: &RevokeBudget,
    ) -> Result<RevokeProgress, ServerError> {
        let start = ms(self.clock.now_ms());
        let coordinator = self.shards.coordinator(ns);
        let state = self.coordinator_state(&coordinator).await?;
        let (first, end) = keys::class_range(keys::TAG_LEASED_SHARD);
        let mut cursor = self.revocation_cursors.get(ns, &state);
        let mut checkpoint = cursor.clone();
        let (mut visited, mut remaining, mut prefix_complete) = (0, 0_u64, true);
        loop {
            if self.revoke_budget_passed(start, *budget) {
                self.revocation_cursors.set(ns, &state, checkpoint);
                return Ok(RevokeProgress::Pending {
                    remaining: remaining.max(1),
                });
            }
            let page = self
                .meta
                .scan(&coordinator, &first, &end, cursor.as_ref(), PAGE_SIZE)
                .await
                .map_err(meta_error)?;
            for (key, value) in page.entries {
                if self.revoke_budget_passed(start, *budget) {
                    self.revocation_cursors.set(ns, &state, checkpoint);
                    return Ok(RevokeProgress::Pending {
                        remaining: remaining.max(1),
                    });
                }
                let row = codec::decode_leased_shard(&value).map_err(meta_error)?;
                if row.expires_at_ms <= ms(self.clock.now_ms()) || row.acked_epoch == state.epoch {
                    continue;
                }
                if row.acked_epoch > state.epoch || visited == 4 {
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
        let latest = self.coordinator_state(&coordinator).await?;
        if remaining == 0 && latest.epoch == state.epoch && !self.recovery_pending(&latest) {
            self.revocation_cursors.set(ns, &state, None);
            Ok(RevokeProgress::Complete)
        } else {
            self.revocation_cursors.set(
                ns,
                &state,
                if latest.epoch == state.epoch && latest.recovery == state.recovery {
                    checkpoint
                } else {
                    None
                },
            );
            Ok(RevokeProgress::Pending {
                remaining: remaining.max(1),
            })
        }
    }

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
            if row.expires_at_ms <= ms(self.clock.now_ms()) || row.acked_epoch == state.epoch {
                return Ok(true);
            }
            if row.epoch > state.epoch || row.acked_epoch > state.epoch {
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
                if old.epoch > state.epoch {
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
            let lease = codec::EpochLease {
                epoch: state.epoch,
                expires_at_ms: row.expires_at_ms,
                config_version: state.config_version,
            };
            let push = Batch::new()
                .require(observed_guard(keys::epoch_lease(), old.as_ref()))
                .put(keys::epoch_lease(), codec::encode_epoch_lease(&lease));
            match self.meta.apply(&p, push).await.map_err(meta_error)? {
                BatchOutcome::PreconditionFailed { .. } => continue,
                BatchOutcome::DeadlinePassed { .. } => {
                    return Err(internal("epoch push had no deadline"));
                }
                BatchOutcome::Committed => {}
            }
            if self.revoke_budget_passed(start, *budget) {
                return Ok(false);
            }
            row.acked_epoch = state.epoch;
            let ack = Batch::new()
                .require(Precondition::Equals(key.clone(), value))
                .require(observed_guard(
                    keys::grant_epoch(),
                    state.epoch_value.as_ref(),
                ))
                .put(key.clone(), codec::encode_leased_shard(&row));
            match self
                .meta
                .apply(coordinator, ack)
                .await
                .map_err(meta_error)?
            {
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
    /// The bump/step error, or `unavailable` if completion takes ten seconds.
    #[cfg(feature = "test-faults")]
    pub async fn test_bump_epoch(
        &self,
        ns: &NamespaceKey,
        new_epoch: u64,
    ) -> Result<(), ServerError> {
        self.bump_epoch(ns, new_epoch).await?;
        let start = ms(self.clock.now_ms());
        loop {
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
    }
}
