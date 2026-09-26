//! Tests of the suite itself: the registries list every case once, the
//! memory backend skips only what it cannot support, a conforming backend
//! with unusual choices (one-entry pages) passes, and each deliberately
//! broken backend fails the case written to catch it.

use std::collections::BTreeSet;
use std::sync::Arc;

use mkit_server::{
    Batch, BatchOutcome, Clock, Cursor, Key, MemoryBlobStore, MemoryKv, NamespaceStore, Partition,
    PartitionStats, Precondition, ScanPage, StoreCapabilities, StoreError, Value,
};
use mkit_server_conformance::storage::{CaseResult, KvHarness, blob_cases, kv_cases};

/// A way to break (or merely stretch) a conforming `MemoryKv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutation {
    /// Conforming: every page holds one entry, whatever the limit.
    OneEntryPages,
    /// Ends the scan after the first entry of every page.
    DropNext,
    /// Restarts a scan from `start` on a cursor outside the range.
    AcceptForeignCursor,
    /// Ignores `NotAfter`.
    IgnoreDeadline,
    /// Applies the batch's first write even when a precondition fails.
    TornBatch,
    /// Applies writes in reverse order.
    ReverseWrites,
    /// Reads an empty value as absent.
    EmptyIsAbsent,
}

struct Mutant {
    inner: MemoryKv,
    mutation: Mutation,
}

impl NamespaceStore for Mutant {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        let value = self.inner.get(p, key).await?;
        let hide = self.mutation == Mutation::EmptyIsAbsent;
        Ok(value.filter(|v| !(hide && v.as_bytes().is_empty())))
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        let outside = after
            .is_some_and(|c| c.as_bytes() < start.as_bytes() || c.as_bytes() >= end.as_bytes());
        let after = after.filter(|_| !(outside && self.mutation == Mutation::AcceptForeignCursor));
        match self.mutation {
            Mutation::OneEntryPages => self.inner.scan(p, start, end, after, limit.min(1)).await,
            Mutation::DropNext => {
                let page = self.inner.scan(p, start, end, after, 1).await?;
                let next = if limit == 1 { page.next } else { None };
                Ok(ScanPage {
                    entries: page.entries,
                    next,
                })
            }
            _ => self.inner.scan(p, start, end, after, limit).await,
        }
    }

    async fn apply(&self, p: &Partition, mut batch: Batch) -> Result<BatchOutcome, StoreError> {
        match self.mutation {
            Mutation::IgnoreDeadline => {
                batch
                    .preconditions
                    .retain(|pre| !matches!(pre, Precondition::NotAfter(_)));
            }
            Mutation::ReverseWrites => batch.writes.reverse(),
            _ => {}
        }
        let first = batch.writes.first().cloned();
        let outcome = self.inner.apply(p, batch).await?;
        if let (Mutation::TornBatch, BatchOutcome::PreconditionFailed { .. }, Some(write)) =
            (self.mutation, &outcome, first)
        {
            self.inner
                .apply(
                    p,
                    Batch {
                        preconditions: vec![],
                        writes: vec![write],
                    },
                )
                .await?;
        }
        Ok(outcome)
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.inner.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

#[derive(Clone, Copy)]
struct Harness(Mutation);

impl KvHarness for Harness {
    type Store = Mutant;

    fn store(&self) -> Mutant {
        self.wrap(MemoryKv::default())
    }

    fn store_with_clock(&self, clock: Arc<dyn Clock>) -> Option<Mutant> {
        Some(self.wrap(MemoryKv::with_clock(clock)))
    }

    fn store_with_capacity(&self, bytes: u64) -> Option<Mutant> {
        Some(self.wrap(MemoryKv::default().with_capacity_limit(bytes)))
    }
}

impl Harness {
    fn wrap(self, inner: MemoryKv) -> Mutant {
        Mutant {
            inner,
            mutation: self.0,
        }
    }
}

/// Run every kv case on `harness`: the names that failed and that skipped.
fn run_kv(harness: Harness) -> (BTreeSet<&'static str>, BTreeSet<&'static str>) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (mut failed, mut skipped) = (BTreeSet::new(), BTreeSet::new());
    for (name, case) in kv_cases::<Harness>() {
        match runtime.block_on(runtime.spawn(case(harness))) {
            Ok(Ok(CaseResult::Pass)) => {}
            Ok(Ok(CaseResult::Skip(_))) => {
                skipped.insert(name);
            }
            Ok(Err(_)) | Err(_) => {
                failed.insert(name);
            }
        }
    }
    (failed, skipped)
}

#[test]
fn registries_list_every_case_once() {
    let names: Vec<_> = kv_cases::<Harness>()
        .into_iter()
        .map(|c| c.0)
        .chain(
            blob_cases::<fn() -> MemoryBlobStore>()
                .into_iter()
                .map(|c| c.0),
        )
        .collect();
    let unique: BTreeSet<_> = names.iter().collect();
    assert_eq!(unique.len(), names.len());
    assert!(names.len() >= 52, "{} cases", names.len());
    for prefix in ["kv_not_after_", "dur_", "idx_", "blob_"] {
        assert!(names.iter().any(|n| n.starts_with(prefix)), "{prefix}");
    }
    assert_eq!(
        names
            .iter()
            .filter(|n| n.starts_with("kv_not_after_"))
            .count(),
        7
    );
}

#[test]
fn one_entry_pages_conform_and_only_crash_restart_skips() {
    let (failed, skipped) = run_kv(Harness(Mutation::OneEntryPages));
    assert!(failed.is_empty(), "{failed:?}");
    let want: BTreeSet<_> = ["dur_crash_restart_atomic_at_last_commit"].into();
    assert_eq!(skipped, want);
}

#[test]
fn each_mutation_fails_the_case_that_targets_it() {
    for (mutation, case) in [
        (Mutation::DropNext, "kv_scan_short_page_still_returns_next"),
        (
            Mutation::AcceptForeignCursor,
            "kv_scan_foreign_cursor_rejected",
        ),
        (
            Mutation::IgnoreDeadline,
            "kv_not_after_past_deadline_fails_writing_nothing",
        ),
        (
            Mutation::IgnoreDeadline,
            "kv_not_after_pre_epoch_clock_fails_closed",
        ),
        (Mutation::TornBatch, "kv_failed_batch_writes_nothing"),
        (Mutation::TornBatch, "dur_cancelled_apply_is_all_or_nothing"),
        (
            Mutation::ReverseWrites,
            "kv_put_delete_same_key_last_write_wins",
        ),
        (
            Mutation::EmptyIsAbsent,
            "kv_empty_value_distinct_from_absent",
        ),
    ] {
        let (failed, _) = run_kv(Harness(mutation));
        assert!(failed.contains(case), "{mutation:?} passed {case}");
    }
}
