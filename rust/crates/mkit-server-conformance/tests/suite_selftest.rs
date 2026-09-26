//! Tests of the suite itself: the registries list every case once, a
//! conforming backend with unusual choices (one-entry pages) passes, and
//! each deliberately broken backend fails the case written to catch it.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::{Bytes, BytesMut};
use futures::StreamExt as _;
use mkit_server::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, Clock, CommitOutcome,
    Cursor, Key, MemoryBlobStore, MemoryKv, MemoryPackSink, NamespaceStore, PackSink, Partition,
    PartitionStats, Precondition, ScanPage, StoreCapabilities, StoreError, Value,
};
use mkit_server_conformance::storage::{
    BlobHarness, Case, KvHarness, Outcome, blob_cases, kv_cases, verdict,
};

/// A way to break (or merely stretch) a conforming `MemoryKv`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutation {
    /// Conforming: every page holds one entry, whatever the limit.
    OneEntryPages,
    /// Ends the scan after the first entry of every page.
    DropNext,
    /// Restarts a scan from `start` on a cursor outside the range.
    AcceptForeignCursor,
    /// Resumes a scan at the cursor's key, not strictly after it.
    InclusiveCursor,
    /// Ignores `NotAfter`.
    IgnoreDeadline,
    /// Reports a missed deadline as a failed precondition.
    DeadlineAsPrecondition,
    /// Applies the batch's first write even when a precondition fails.
    TornBatch,
    /// Applies writes in reverse order.
    ReverseWrites,
    /// Reads an empty value as absent.
    EmptyIsAbsent,
    /// Claims `RefsOnly`, but writes a rejected batch before erroring.
    WriteBeforeUnsupported,
    /// Once full, rejects delete-only batches too.
    FullOnDeleteOnly,
}

struct Mutant {
    inner: MemoryKv,
    mutation: Mutation,
    full: AtomicBool,
}

impl NamespaceStore for Mutant {
    fn capabilities(&self) -> StoreCapabilities {
        if self.mutation == Mutation::WriteBeforeUnsupported {
            return StoreCapabilities::refs_only();
        }
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
        let cursor = after.map(|c| Key::new(c.clone().into_bytes()));
        let inside = cursor.as_ref().is_none_or(|c| start <= c && c < end);
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
            Mutation::AcceptForeignCursor if !inside => {
                self.inner.scan(p, start, end, None, limit).await
            }
            Mutation::InclusiveCursor if cursor.is_some() && inside => {
                let from = cursor.unwrap_or_default();
                self.inner.scan(p, &from, end, None, limit).await
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
            Mutation::WriteBeforeUnsupported => {
                if let Err(e) = batch.validate(&StoreCapabilities::refs_only()) {
                    let writes = Batch {
                        preconditions: vec![],
                        writes: batch.writes,
                    };
                    let _ = self.inner.apply(p, writes).await;
                    return Err(e);
                }
            }
            Mutation::FullOnDeleteOnly if self.full.load(Ordering::SeqCst) && !batch.has_put() => {
                return Err(StoreError::Full);
            }
            _ => {}
        }
        let first = batch.writes.first().cloned();
        let deadline = batch
            .preconditions
            .iter()
            .position(|pre| matches!(pre, Precondition::NotAfter(_)));
        let outcome = self.inner.apply(p, batch).await;
        if matches!(outcome, Err(StoreError::Full)) {
            self.full.store(true, Ordering::SeqCst);
        }
        let outcome = outcome?;
        match (self.mutation, &outcome) {
            (Mutation::TornBatch, BatchOutcome::PreconditionFailed { .. }) => {
                if let Some(write) = first {
                    let torn = Batch {
                        preconditions: vec![],
                        writes: vec![write],
                    };
                    self.inner.apply(p, torn).await?;
                }
            }
            (Mutation::DeadlineAsPrecondition, BatchOutcome::DeadlinePassed { .. }) => {
                return Ok(BatchOutcome::PreconditionFailed {
                    index: deadline.unwrap_or(0),
                    observed: None,
                });
            }
            _ => {}
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

impl Harness {
    fn wrap(self, inner: MemoryKv) -> Mutant {
        Mutant {
            inner,
            mutation: self.0,
            full: AtomicBool::new(false),
        }
    }
}

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

    fn expected_skips(&self) -> &'static [&'static str] {
        &["dur_crash_restart_atomic_at_last_commit"]
    }
}

/// A way to break a conforming `MemoryBlobStore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlobMutation {
    /// Commits an upload whose sink is dropped.
    CommitOnDrop,
    /// Returns every body as one buffer.
    WholeBuffer,
}

struct BlobMutant {
    inner: MemoryBlobStore,
    mutation: BlobMutation,
}

struct MutantSink {
    inner: Option<MemoryPackSink>,
    commit_on_drop: bool,
}

impl Drop for MutantSink {
    fn drop(&mut self) {
        if let (true, Some(sink)) = (self.commit_on_drop, self.inner.take()) {
            let _ = futures::executor::block_on(sink.commit());
        }
    }
}

impl PackSink for MutantSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        self.inner.as_mut().expect("live sink").write(chunk).await
    }

    async fn commit(mut self) -> Result<CommitOutcome, StoreError> {
        self.inner.take().expect("live sink").commit().await
    }

    async fn abort(mut self) {
        self.inner.take().expect("live sink").abort().await;
    }
}

impl BlobStore for BlobMutant {
    type Sink = MutantSink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<MutantSink, StoreError> {
        Ok(MutantSink {
            inner: Some(self.inner.begin(key, len).await?),
            commit_on_drop: self.mutation == BlobMutation::CommitOnDrop,
        })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let body = self.inner.get(key, range).await?;
        let (BlobMutation::WholeBuffer, Some(BlobBody::Stream { mut stream, .. })) =
            (self.mutation, body)
        else {
            return self.inner.get(key, range).await;
        };
        let mut all = BytesMut::new();
        while let Some(piece) = stream.next().await {
            all.extend_from_slice(&piece?);
        }
        Ok(Some(BlobBody::Bytes(all.freeze())))
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        self.inner.head(key).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        self.inner.delete(key).await
    }
}

#[derive(Clone, Copy)]
struct BlobHarnessOf(BlobMutation);

impl BlobHarness for BlobHarnessOf {
    type Store = BlobMutant;

    fn store(&self) -> BlobMutant {
        BlobMutant {
            inner: MemoryBlobStore::default(),
            mutation: self.0,
        }
    }
}

/// Run `cases` on `harness`: the names that failed (including undeclared
/// skips, and passes of declared skips).
fn failures<H: Copy>(cases: Vec<Case<H>>, harness: H, declared: &[&str]) -> BTreeSet<&'static str> {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut failed = BTreeSet::new();
    for (name, case) in cases {
        let outcome: Outcome = match runtime.block_on(runtime.spawn(case(harness))) {
            Ok(outcome) => outcome,
            Err(panic) => Err(format!("panicked: {panic}")),
        };
        if verdict(name, declared, outcome).is_err() {
            failed.insert(name);
        }
    }
    failed
}

fn kv_failures(mutation: Mutation) -> BTreeSet<&'static str> {
    let harness = Harness(mutation);
    failures(kv_cases::<Harness>(), harness, harness.expected_skips())
}

#[test]
fn registries_list_every_case_once() {
    let names: Vec<_> = kv_cases::<Harness>()
        .into_iter()
        .map(|c| c.0)
        .chain(blob_cases::<BlobHarnessOf>().into_iter().map(|c| c.0))
        .collect();
    let unique: BTreeSet<_> = names.iter().collect();
    assert_eq!(unique.len(), names.len());
    assert!(names.len() >= 52, "{} cases", names.len());
    for prefix in ["kv_not_after_", "dur_", "idx_", "blob_"] {
        assert!(names.iter().any(|n| n.starts_with(prefix)), "{prefix}");
    }
    let not_after = names.iter().filter(|n| n.starts_with("kv_not_after_"));
    assert_eq!(not_after.count(), 7);
}

#[test]
fn one_entry_pages_conform() {
    let failed = kv_failures(Mutation::OneEntryPages);
    assert!(failed.is_empty(), "{failed:?}");
}

#[test]
fn each_kv_mutation_fails_the_case_that_targets_it() {
    for (mutation, case) in [
        (Mutation::DropNext, "kv_scan_short_page_still_returns_next"),
        (
            Mutation::AcceptForeignCursor,
            "kv_scan_foreign_cursor_rejected",
        ),
        (
            Mutation::InclusiveCursor,
            "kv_scan_cursor_resumes_strictly_after",
        ),
        (
            Mutation::IgnoreDeadline,
            "kv_not_after_past_deadline_fails_writing_nothing",
        ),
        (
            Mutation::IgnoreDeadline,
            "kv_not_after_pre_epoch_clock_fails_closed",
        ),
        (
            Mutation::DeadlineAsPrecondition,
            "kv_not_after_past_deadline_fails_writing_nothing",
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
        (
            Mutation::WriteBeforeUnsupported,
            "kv_refs_only_rejects_other_classes",
        ),
        (
            Mutation::FullOnDeleteOnly,
            "kv_full_store_rejects_writes_but_serves_reads_and_deletes",
        ),
    ] {
        let failed = kv_failures(mutation);
        assert!(failed.contains(case), "{mutation:?} passed {case}");
    }
}

#[test]
fn each_blob_mutation_fails_the_case_that_targets_it() {
    for (mutation, case) in [
        (
            BlobMutation::CommitOnDrop,
            "blob_dropped_sink_leaves_nothing",
        ),
        (BlobMutation::WholeBuffer, "blob_get_large_is_streamed"),
    ] {
        let failed = failures(blob_cases::<BlobHarnessOf>(), BlobHarnessOf(mutation), &[]);
        assert!(failed.contains(case), "{mutation:?} passed {case}");
    }
}

#[test]
fn undeclared_skips_and_passing_declared_skips_fail() {
    let skip = Ok(mkit_server_conformance::storage::CaseResult::Skip("why"));
    let pass = Ok(mkit_server_conformance::storage::CaseResult::Pass);
    assert!(verdict("a", &[], skip.clone()).is_err());
    assert!(verdict("a", &["a"], skip).is_ok());
    assert!(verdict("a", &["a"], pass.clone()).is_err());
    assert!(verdict("a", &[], pass).is_ok());
}
