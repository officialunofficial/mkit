//! Serial rounds and storage calls of the fork Copy phase, measured on a
//! store whose every call sleeps 30 ms of paused time: calls inside one
//! wave overlap, so elapsed time over 30 ms is the number of serial rounds.
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod fork_support;
use fork_support::*;
use mkit_attest::grant::Visibility;
use mkit_server::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, RangeScan, RepoId,
    RepoName, ScanPage, StoreCapabilities, StoreError, Value, Write,
    budget::SliceBudget,
    fork::{ForkEnv, ForkLimits, ForkSpec, Phase},
    store::adapter_spi::keys,
};
use std::sync::{
    Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::time::Instant;

const ROUND_MS: u64 = 30;

/// `Counting` with a paused-time sleep per call, a known read allowance (as
/// the Workers store reports, so waves are active) and a mark at every
/// write of the fork job row.
struct Timed<'a> {
    inner: &'a Counting,
    job: Key,
    calls: AtomicU64,
    marks: Mutex<Vec<(u64, Instant, Phase)>>,
}

impl Timed<'_> {
    async fn pause(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(ROUND_MS)).await;
    }
}

impl NamespaceStore for Timed<'_> {
    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }
    fn read_call_allowance(&self) -> Option<u32> {
        Some(u32::MAX)
    }
    async fn get(&self, p: &Partition, k: &Key) -> Result<Option<Value>, StoreError> {
        self.pause().await;
        self.inner.get(p, k).await
    }
    async fn get_many(&self, p: &Partition, k: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        self.pause().await;
        self.inner.get_many(p, k).await
    }
    async fn scan_many(&self, p: &Partition, r: &[RangeScan]) -> Result<Vec<ScanPage>, StoreError> {
        self.pause().await;
        self.inner.scan_many(p, r).await
    }
    async fn scan(
        &self,
        partition: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.pause().await;
        self.inner.scan(partition, start, end, after, limit).await
    }
    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.pause().await;
        for write in &batch.writes {
            if let Write::Put(k, v) = write
                && *k == self.job
            {
                let job = mkit_server::fork::decode_job(v).unwrap();
                self.marks.lock().unwrap().push((
                    self.calls.load(Ordering::SeqCst),
                    Instant::now(),
                    job.phase,
                ));
            }
        }
        self.inner.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.pause().await;
        self.inner.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.inner.probe().await
    }
}

/// Fork `files` single-blob files and return (copy rounds, copy calls,
/// slices used by the whole fork, copied rows).
async fn measure(files: u32, extract: Option<u64>) -> (u128, u64, u32, u64) {
    let source = Source::build_full("source", files, 0, |mut c| {
        c.takedown_denial = false;
        c
    })
    .await;
    let dest = RepoId {
        namespace: source.repo.namespace.clone(),
        name: RepoName::new("forked").unwrap(),
    };
    let spec = ForkSpec {
        source: source.repo.clone(),
        source_ref: "refs/heads/main".into(),
        expected_tip: source.head,
        dest: dest.clone(),
        dest_visibility: Visibility::Public,
    };
    let timed = Timed {
        inner: &source.store,
        job: keys::fork_job(&dest.name),
        calls: AtomicU64::new(0),
        marks: Mutex::default(),
    };
    let env = ForkEnv {
        publication_policy: None,
        store: &timed,
        shards: source.shards.as_ref(),
        clock: source.clock.as_ref(),
        takedown_denial: false,
        extract_min_bytes: extract,
        limits: ForkLimits::default(),
    };
    mkit_server::fork::start_with(&env, &spec, None, None)
        .await
        .unwrap();
    let (mut slices, mut copied) = (0, 0);
    let first = timed.calls.load(Ordering::SeqCst);
    let start = Instant::now();
    loop {
        slices += 1;
        let report = mkit_server::fork::step(&env, &dest, &SliceBudget::new(600))
            .await
            .unwrap();
        copied = report.job.copied.max(copied);
        if report.job.finished() || slices > 50 {
            assert_eq!(report.job.phase, Phase::Done, "{:?}", report.job.failure);
            break;
        }
    }
    let marks = timed.marks.lock().unwrap().clone();
    // The Register-phase advance leaves the job in Copy; the Copy advance
    // that ends the phase leaves it in Count. Slice cuts inside Copy show as
    // marks that stay in Copy.
    let mut begin = (first, start);
    let (mut copy_calls, mut copy_time) = (0_u64, 0_u128);
    for (calls, at, phase) in marks {
        if phase == Phase::Copy {
            if begin.0 == first {
                begin = (calls, at);
            }
        } else if phase == Phase::Count && begin.0 != first {
            copy_calls = calls - begin.0;
            copy_time = (at - begin.1).as_millis();
            begin = (first, start);
        }
    }
    (copy_time / u128::from(ROUND_MS), copy_calls, slices, copied)
}

/// Before parallel copy these cost 35, 112 and 340 rounds (the last over
/// three slices). The bounds leave room for the fixture, not for a return to
/// one partition per round.
#[tokio::test(start_paused = true)]
async fn copy_rounds_500() {
    let (rounds, calls, slices, copied) = measure(500, Some(65_536)).await;
    println!("copy 500 files: copy rounds={rounds} calls={calls} slices={slices} copied={copied}");
    assert!(
        rounds <= 12 && calls <= 40 && slices == 1,
        "{rounds} {calls} {slices}"
    );
}

#[tokio::test(start_paused = true)]
async fn copy_rounds_3000() {
    let (rounds, calls, slices, copied) = measure(3_000, Some(65_536)).await;
    println!("copy 3000 files: copy rounds={rounds} calls={calls} slices={slices} copied={copied}");
    assert!(
        rounds <= 20 && calls <= 70 && slices == 1,
        "{rounds} {calls} {slices}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_fork_of_ten_thousand_files_copies_within_one_slice() {
    let (rounds, calls, slices, copied) = measure(10_000, Some(65_536)).await;
    println!(
        "copy 10000 files: copy rounds={rounds} calls={calls} slices={slices} copied={copied}"
    );
    assert!(
        rounds <= 45 && calls <= 200 && slices == 1,
        "{rounds} {calls} {slices}"
    );
    assert!(copied >= 10_000);
}
