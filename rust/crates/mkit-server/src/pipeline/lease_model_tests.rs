//! Protocol model: this checks the acknowledgement/deadline protocol rather
//! than executing production code. Memory/SQLite pipeline regressions protect
//! the implementation. Each action is one partition transaction or delayed
//! observation; installation, push, and ack can all remain unfinished.

use crate::store::codec::{EpochLease, LeaseRecovery, LeasedShard};
use proptest::prelude::*;

const LEASE_MS: u64 = 30_000;
const MARGIN_MS: u64 = 5_000;
const APPLY_WINDOW_MS: u64 = 10_000;
const MIN_BUDGET_MS: u64 = 1_000;
const SHARDS: usize = 2;

#[derive(Clone, Copy, Debug)]
struct PlannedWrite {
    shard: usize,
    epoch: u64,
    observed: Option<EpochLease>,
    install: Option<EpochLease>,
    deadline: u64,
}

#[derive(Clone, Copy, Debug)]
struct Push {
    shard: usize,
    target: u64,
    row: LeasedShard,
    observed: Option<EpochLease>,
    committed: bool,
}

#[derive(Debug, Default)]
struct Model {
    now: u64,
    epoch: u64,
    rows: [Option<LeasedShard>; SHARDS],
    copies: [Option<EpochLease>; SHARDS],
    writes: Vec<PlannedWrite>,
    pushes: Vec<Push>,
    completed_epoch: u64,
    recovery: Option<LeaseRecovery>,
    // Backend clocks differ from coordinator time by strictly less than margin.
    backend_skew_ms: [i64; SHARDS],
}

impl Model {
    fn lease(epoch: u64, expires_at_ms: u64) -> EpochLease {
        EpochLease {
            authority_ready: None,
            authority_generation: None,
            epoch,
            expires_at_ms,
            config_version: 1,
        }
    }

    fn deadline(&self, lease: EpochLease) -> u64 {
        lease
            .expires_at_ms
            .saturating_sub(MARGIN_MS)
            .min(self.now.saturating_add(APPLY_WINDOW_MS))
    }

    fn plan(&mut self, shard: usize) {
        let Some(lease) = self.copies[shard] else {
            return;
        };
        if lease
            .expires_at_ms
            .saturating_sub(MARGIN_MS)
            .saturating_sub(self.now)
            < MIN_BUDGET_MS
        {
            return;
        }
        self.writes.push(PlannedWrite {
            shard,
            epoch: lease.epoch,
            observed: Some(lease),
            install: None,
            deadline: self.deadline(lease),
        });
    }

    // Coordinator transaction: e and ls are read/guarded together, so a
    // concurrent epoch bump cannot grant a lease at an unobserved epoch.
    // Installation is deliberately delayed until this write's apply.
    fn renew(&mut self, shard: usize, preserve_live_ack: bool) {
        let old = self.rows[shard];
        let expires_at_ms = old
            .map_or(0, |row| row.expires_at_ms)
            .max(self.now.saturating_add(LEASE_MS));
        let acked_epoch = if preserve_live_ack {
            old.filter(|row| row.expires_at_ms > self.now)
                .map_or(self.epoch, |row| row.acked_epoch)
        } else {
            self.epoch
        };
        let row = LeasedShard {
            authority_generation: None,
            acked_authority_generation: None,
            epoch: self.epoch,
            expires_at_ms,
            acked_epoch,
            relay_watermark_ms: old.map_or(0, |row| row.relay_watermark_ms),
            sweep_due_ms: expires_at_ms,
        };
        self.rows[shard] = Some(row);
        let install = Self::lease(self.epoch, expires_at_ms);
        assert_eq!(install.expires_at_ms, row.expires_at_ms);
        self.writes.push(PlannedWrite {
            shard,
            epoch: self.epoch,
            observed: self.copies[shard],
            install: Some(install),
            deadline: self.deadline(install),
        });
    }

    fn observe_push(&mut self, shard: usize) {
        let Some(row) = self.rows[shard] else {
            return;
        };
        if row.acked_epoch >= self.epoch || row.expires_at_ms <= self.now {
            return;
        }
        let observed = self.copies[shard];
        // A stale revoke slice must refresh ls rather than shorten a newer
        // renewal, or overwrite an epoch installed by a newer revoke slice.
        if observed
            .is_some_and(|copy| copy.epoch > self.epoch || copy.expires_at_ms > row.expires_at_ms)
        {
            return;
        }
        self.pushes.push(Push {
            shard,
            target: self.epoch,
            row,
            observed,
            committed: false,
        });
    }

    fn apply_push(&mut self, selection: usize) {
        if self.pushes.is_empty() {
            return;
        }
        let index = selection % self.pushes.len();
        let push = &mut self.pushes[index];
        if push.committed {
            return;
        }
        if self.copies[push.shard] == push.observed {
            self.copies[push.shard] = Some(Self::lease(push.target, push.row.expires_at_ms));
            push.committed = true;
        } else {
            // A failed Equals requires a new observation before any ack.
            self.pushes.swap_remove(index);
        }
    }

    fn ack(&mut self, selection: usize) {
        if self.pushes.is_empty() {
            return;
        }
        let index = selection % self.pushes.len();
        let push = self.pushes[index];
        if !push.committed {
            return;
        }
        self.pushes.swap_remove(index);
        if self.epoch == push.target
            && self.rows[push.shard] == Some(push.row)
            && push.row.expires_at_ms > self.now
            && push.row.acked_epoch < push.target
        {
            self.rows[push.shard] = Some(LeasedShard {
                authority_generation: None,
                acked_authority_generation: None,
                acked_epoch: push.target,
                ..push.row
            });
        }
    }

    fn complete(&mut self) -> bool {
        let recovery_passed = self.recovery.is_none_or(|marker| {
            self.now >= marker.resumed_at_ms.saturating_add(LEASE_MS + MARGIN_MS)
        });
        let complete = recovery_passed
            && self.rows.iter().all(|row| {
                row.is_none_or(|row| row.acked_epoch == self.epoch || row.expires_at_ms <= self.now)
            });
        if complete {
            self.completed_epoch = self.completed_epoch.max(self.epoch);
        }
        complete
    }

    // Returns true only for a committed write violating §5.6.
    fn apply(&mut self, selection: usize) -> bool {
        if self.writes.is_empty() {
            return false;
        }
        let write = self.writes.swap_remove(selection % self.writes.len());
        let backend_now = self
            .now
            .saturating_add_signed(self.backend_skew_ms[write.shard]);
        if backend_now > write.deadline || self.copies[write.shard] != write.observed {
            return false;
        }
        if let Some(install) = write.install {
            self.copies[write.shard] = Some(install);
        }
        write.epoch < self.completed_epoch
    }

    fn sweep(&mut self, shard: usize) {
        if self.rows[shard].is_some_and(|row| row.expires_at_ms <= self.now) {
            self.rows[shard] = None;
        }
    }
}

// Bias revocation and completion, and advance to both sides of the lease's
// deadline/expiry instead of spending most schedules far past every lease.
fn action_strategy() -> impl Strategy<Value = (u8, u8, u64)> {
    // Integer buckets retain the weighted distribution without allocating a
    // nested union strategy for each generated action.
    (0u8..38, any::<u8>(), 0u64..40_001).prop_map(|(bucket, selection, elapsed)| {
        let action = match bucket {
            0..=3 => 0,   // Plan a write.
            4..=7 => 1,   // Commit renewal; leave installation delayed.
            8..=12 => 2,  // Bump.
            13..=15 => 3, // Observe push.
            16..=18 => 4, // Commit push CAS.
            19..=21 => 5, // Ack CAS.
            22..=25 => 6, // Apply a delayed write.
            26 => 7,      // Sweep expired row.
            27 => 8,      // Arbitrary clock advance.
            28..=32 => 9, // Test Complete.
            _ => 10,      // Advance close to deadline or expiry.
        };
        (action, selection, elapsed)
    })
}

fn check_schedule(
    actions: impl IntoIterator<Item = (u8, u8, u64)>,
    backend_skew_ms: [i64; SHARDS],
) -> Result<(), proptest::test_runner::TestCaseError> {
    let mut model = Model {
        backend_skew_ms,
        ..Model::default()
    };
    for (action, selection, elapsed) in actions {
        let selection = usize::from(selection);
        let shard = selection % SHARDS;
        match action {
            0 => model.plan(shard),
            1 => model.renew(shard, true),
            2 => {
                model.epoch += 1;
                model.complete(); // Exercise completion immediately after bump too.
            }
            3 => model.observe_push(shard),
            4 => model.apply_push(selection),
            5 => model.ack(selection),
            6 => prop_assert!(
                !model.apply(selection),
                "old-epoch write committed: {model:?}"
            ),
            7 => model.sweep(shard),
            8 => model.now = model.now.saturating_add(elapsed),
            9 => {
                model.complete();
            }
            _ => {
                if let Some(lease) = model.copies[shard] {
                    let boundary = if selection.is_multiple_of(2) {
                        lease.expires_at_ms
                    } else {
                        lease.expires_at_ms.saturating_sub(MARGIN_MS)
                    };
                    let offset = i64::try_from(elapsed % 3).unwrap() - 1;
                    model.now = model.now.max(boundary.saturating_add_signed(offset));
                    model.complete();
                }
            }
        }
    }
    model.complete();
    while !model.writes.is_empty() {
        prop_assert!(
            !model.apply(0),
            "old-epoch write committed after final completion: {model:?}"
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]
    #[test]
    fn completed_revocation_fences_every_older_planned_write(
        actions in prop::collection::vec(action_strategy(), 1..500),
        backend_skew_ms in prop::array::uniform2(-4_999i64..5_000),
    ) {
        check_schedule(actions, backend_skew_ms)?;
    }
}

fn old_write_and_delayed_renewal(preserve_live_ack: bool) -> Model {
    let mut model = Model::default();
    model.renew(0, true);
    assert!(!model.apply(0)); // First grant durably installs el(epoch 0).
    model.plan(0); // A pauses with an epoch-0 batch before apply.
    model.epoch = 1;
    model.renew(0, preserve_live_ack); // B pauses after coordinator grant.
    model
}

#[test]
fn original_premature_ack_counterexample_and_preserved_ack_fix() {
    let mut broken = old_write_and_delayed_renewal(false);
    assert!(broken.complete());
    assert!(
        broken.apply(0),
        "original brief must reproduce old-epoch commit after Complete"
    );

    for cancel_renewal in [false, true] {
        let mut fixed = old_write_and_delayed_renewal(true);
        if cancel_renewal {
            fixed.writes.pop();
        } // B never installs its grant.
        assert!(
            !fixed.complete(),
            "renewal alone cannot acknowledge installation"
        );
        fixed.observe_push(0);
        fixed.apply_push(0);
        assert!(
            !fixed.complete(),
            "committed push alone has not acknowledged ls"
        );
        fixed.ack(0);
        assert!(fixed.complete());
        assert!(!fixed.apply(0), "A's old el guard must fail after push");
        if !cancel_renewal {
            assert!(
                !fixed.apply(0),
                "B's delayed installation must also respect its el guard"
            );
        }
    }
}

#[test]
fn declared_recovery_waits_from_resume_instead_of_namespace_creation() {
    let namespace_created_at_ms = 0;
    let mut model = Model {
        now: 100_000,
        epoch: 1,
        ..Model::default()
    };
    assert!(namespace_created_at_ms < model.now - LEASE_MS - MARGIN_MS);
    assert!(
        model.complete(),
        "empty table without recovery implies no lost leases"
    );
    model.recovery = Some(LeaseRecovery {
        authority_fence: None,
        authority_ready: None,
        activation_only: None,
        resumed_at_ms: model.now,
    });
    assert!(
        !model.complete(),
        "old namespace creation time cannot bypass recovery"
    );
    model.now = 134_999;
    assert!(!model.complete());
    model.now = 135_000;
    assert!(model.complete());
}

#[test]
fn expired_row_renewal_ack_is_safe_because_old_batch_deadline_passed() {
    let mut model = old_write_and_delayed_renewal(true);
    model.writes.pop(); // Cancel B's delayed installation.
    model.now = LEASE_MS;
    model.renew(0, true);
    assert_eq!(model.rows[0].unwrap().acked_epoch, 1);
    assert!(model.complete());
    assert!(
        !model.apply(0),
        "A's NotAfter deadline passed even while el is unchanged"
    );
}

#[test]
fn raced_push_cannot_ack_until_a_new_observation_commits() {
    let mut model = old_write_and_delayed_renewal(true);
    model.observe_push(0);
    assert!(!model.apply(1)); // B installs, racing the push's old el observation.
    model.apply_push(0);
    model.ack(0);
    assert_eq!(model.rows[0].unwrap().acked_epoch, 0);
    assert!(!model.complete());
    model.observe_push(0);
    model.apply_push(0); // Re-pushing epoch 1 still commits a guarded write.
    model.ack(0);
    assert!(model.complete());
    assert!(!model.apply(0));
}

#[test]
fn push_then_delayed_renewal_then_ack_requires_repush() {
    let mut model = Model::default();
    model.renew(0, true);
    assert!(!model.apply(0));
    model.plan(0); // A retains an epoch-0 batch.
    model.epoch = 1;
    model.observe_push(0);
    model.apply_push(0);
    assert_eq!(model.copies[0].unwrap().epoch, 1);

    model.now = 1;
    model.renew(0, true); // B extends ls after the push but before its ack.
    assert_eq!(model.rows[0].unwrap().acked_epoch, 0);
    model.ack(0); // Equals(ls, old row) fails; no acknowledgement is installed.
    assert_eq!(model.rows[0].unwrap().acked_epoch, 0);
    assert!(!model.complete());

    model.observe_push(0);
    model.apply_push(0);
    model.ack(0);
    assert_eq!(model.rows[0].unwrap().acked_epoch, 1);
    assert_eq!(
        model.copies[0].unwrap().expires_at_ms,
        model.rows[0].unwrap().expires_at_ms
    );
    assert!(model.complete());
    assert!(
        !model.apply(0),
        "A cannot commit against the overwritten epoch-0 el"
    );
}

#[test]
fn push_then_installed_renewal_then_stale_ack_preserves_extended_lease() {
    let mut model = Model::default();
    model.renew(0, true);
    assert!(!model.apply(0));
    model.epoch = 1;
    model.observe_push(0);
    model.apply_push(0); // Epoch 1 push pauses before ack of the 30000 lease.

    model.now = 24_500;
    model.renew(0, true);
    assert!(!model.apply(0)); // B durably installs the extension to 54500.
    assert_eq!(model.copies[0].unwrap().expires_at_ms, 54_500);
    model.ack(0); // The old ls observation cannot acknowledge this extension.
    assert_eq!(model.rows[0].unwrap().acked_epoch, 0);
    assert!(!model.complete());
    model.observe_push(0);
    model.apply_push(0);
    model.ack(0);
    assert_eq!(model.copies[0].unwrap().expires_at_ms, 54_500);
    assert_eq!(model.rows[0].unwrap().expires_at_ms, 54_500);
    assert!(model.complete());

    model.plan(0); // Epoch 1 write remains within its 34500 deadline.
    assert_eq!(model.writes[0].epoch, 1);
    assert_eq!(model.writes[0].deadline, 34_500);
    model.epoch = 2;
    model.now = 30_000;
    assert!(
        !model.complete(),
        "the extended lease is still live at the original expiry"
    );
    model.observe_push(0);
    model.apply_push(0);
    model.ack(0);
    assert!(model.complete());
    assert!(
        !model.apply(0),
        "epoch 1 write must fail el guard after epoch 2 Complete"
    );
}

#[test]
fn excessive_backend_skew_negative_control_finds_old_epoch_commit() {
    use proptest::test_runner::{RngSeed, TestError, TestRunner};

    // Use the same action generator and safety property as the positive run.
    // A lagging backend can accept an old deadline after coordinator expiry;
    // positive skew instead rejects writes earlier, so it cannot expose this
    // violation. Fix the seed and disable persistence for this deliberately
    // failing experiment; the runner searches until it finds a counterexample.
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 10_000,
        rng_seed: RngSeed::Fixed(0),
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    let strategy = (
        prop::collection::vec(action_strategy(), 1..500),
        -10_000i64..=-5_001,
    );
    let result = runner.run(&strategy, |(actions, excessive_lag_ms)| {
        check_schedule(actions, [excessive_lag_ms, 0])
    });
    assert!(
        matches!(result, Err(TestError::Fail(_, _))),
        "the generated excessive-skew experiment must find a safety violation: {result:?}"
    );
}
