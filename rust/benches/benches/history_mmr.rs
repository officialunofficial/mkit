//! `history-mmr` feature: journaled-MMR `open_at` (cold + warm), a
//! single warm append, and a backfill series across a couple of
//! branch-history sizes.
//!
//! Zero prior coverage before this file (issue #644) — and
//! `history-mmr` wasn't even wired up as an `mkit-benches` feature.
//! Build/run with:
//!
//!     cargo bench -p mkit-benches --features history-mmr --bench history_mmr
//!
//! The `backfill` series is the direct regression net called for by
//! the epic (#634): `docs/specs/SPEC-HISTORY-PROOF.md`'s backfill cost
//! estimate turned out to be wrong by orders of magnitude, with
//! nothing in CI to catch it. [`mkit_core::history::rebuild_from_chain`]
//! (via [`mkit_core::history::CommitHistory::append`]) currently
//! fsyncs the journal on *every* appended leaf for the journaled
//! backend, so this series should show clearly superlinear-looking
//! wallclock cost per commit until the batched-backfill fix in this
//! epic lands.
//!
//! Numbers are wallclock ms; smaller is better. Real journal I/O, so
//! sample size is kept small (see `criterion_group!` below) to keep a
//! full (non-`--test`) run fast.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::hash::{Hash, hash};
use mkit_core::history::{self, CommitHistory, TokioExecutor};
use mkit_core::layout::RepoLayout;

const BRANCH: &str = "main";
/// Leaf count for the "warm" `open_at` fixture — big enough that
/// re-deriving in-memory state from the on-disk journal is doing real
/// work, small enough that building the one-time fixture is quick.
const WARM_OPEN_LEAVES: u64 = 500;
/// A couple of branch-history sizes for the backfill series. Kept
/// modest: `CommitHistory::append`'s journaled backend fsyncs on every
/// leaf (see module docs), so this is real disk I/O per commit, not a
/// hot loop.
const BACKFILL_SIZES: &[(u64, &str)] = &[(50, "50 commits"), (250, "250 commits")];

fn synth(i: u64) -> Hash {
    hash(&i.to_be_bytes())
}

fn time_ms(f: impl FnMut()) -> f64 {
    time_one(0, 1, f) * 1000.0
}

fn fresh_layout() -> (tempfile::TempDir, RepoLayout) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    std::fs::create_dir_all(layout.common_dir()).unwrap();
    (dir, layout)
}

/// Build a synthetic first-parent chain `chain[0]` (root) ..
/// `chain[n-1]` (tip) and the `parent_of` map [`history::rebuild_from_chain`]
/// walks. Store-agnostic — no `ObjectStore` involved, mirroring how
/// `rebuild_from_chain` itself takes a caller-supplied walker.
fn synthetic_chain(n: u64) -> (Hash, HashMap<Hash, Option<Hash>>) {
    let chain: Vec<Hash> = (0..n).map(synth).collect();
    let mut parents: HashMap<Hash, Option<Hash>> = HashMap::with_capacity(chain.len());
    parents.insert(chain[0], None);
    for w in chain.windows(2) {
        parents.insert(w[1], Some(w[0]));
    }
    (chain[chain.len() - 1], parents)
}

fn bench_open_at(c: &mut Criterion, samples: &mut Vec<Sample>) {
    // Real callers share one process-wide executor across many
    // open_at calls (see mkit-cli's `history_executor()`), so hold one
    // fixed here too — we want to isolate journal-open cost, not
    // tokio-runtime bootstrap cost.
    let exec: Arc<TokioExecutor> = Arc::new(TokioExecutor::new().expect("tokio runtime"));

    // -- Cold: first-ever open of an empty branch journal. --------------
    c.bench_function("history_mmr/open_at cold", |b| {
        b.iter_with_setup(fresh_layout, |(_dir, layout)| {
            CommitHistory::open_at(exec.clone(), &layout, BRANCH).unwrap();
        });
    });
    {
        let (_dir, layout) = fresh_layout();
        let ms = time_ms(|| {
            CommitHistory::open_at(exec.clone(), &layout, BRANCH).unwrap();
        });
        samples.push(Sample {
            category: "history_mmr".into(),
            axis: "open_at cold".into(),
            library: "open_at".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    // -- Warm: re-open a journal that already holds WARM_OPEN_LEAVES
    // commits. Fixture is built once (not per criterion iteration):
    // open_at only reads/re-derives state, it never mutates the
    // journal, so repeatedly reopening the same on-disk fixture is
    // safe and avoids paying the WARM_OPEN_LEAVES append cost on every
    // sample. -------------------------------------------------------
    let (_warm_dir, warm_layout) = fresh_layout();
    {
        let mut h = CommitHistory::open_at(exec.clone(), &warm_layout, BRANCH).unwrap();
        for i in 0..WARM_OPEN_LEAVES {
            h.append(&synth(i)).unwrap();
        }
    }
    c.bench_function("history_mmr/open_at warm", |b| {
        b.iter(|| {
            CommitHistory::open_at(exec.clone(), &warm_layout, BRANCH).unwrap();
        });
    });
    {
        let ms = time_ms(|| {
            CommitHistory::open_at(exec.clone(), &warm_layout, BRANCH).unwrap();
        });
        samples.push(Sample {
            category: "history_mmr".into(),
            axis: format!("open_at warm ({WARM_OPEN_LEAVES} leaves)"),
            library: "open_at".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }
}

fn bench_single_append(c: &mut Criterion, samples: &mut Vec<Sample>) {
    let exec: Arc<TokioExecutor> = Arc::new(TokioExecutor::new().expect("tokio runtime"));
    // A handful of prior appends so the timed append is a steady-state
    // ("warm") append into an already-open history, not the first leaf
    // ever written.
    const PRIME_LEAVES: u64 = 10;

    c.bench_function("history_mmr/append (warm, single leaf)", |b| {
        b.iter_with_setup(
            || {
                let (dir, layout) = fresh_layout();
                let mut h = CommitHistory::open_at(exec.clone(), &layout, BRANCH).unwrap();
                for i in 0..PRIME_LEAVES {
                    h.append(&synth(i)).unwrap();
                }
                (dir, h)
            },
            |(_dir, mut h)| {
                h.append(&synth(PRIME_LEAVES)).unwrap();
            },
        );
    });
    {
        let (_dir, layout) = fresh_layout();
        let mut h = CommitHistory::open_at(exec.clone(), &layout, BRANCH).unwrap();
        for i in 0..PRIME_LEAVES {
            h.append(&synth(i)).unwrap();
        }
        let ms = time_ms(|| {
            h.append(&synth(PRIME_LEAVES)).unwrap();
        });
        samples.push(Sample {
            category: "history_mmr".into(),
            axis: "append (warm, single leaf)".into(),
            library: "append".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }
}

fn bench_backfill(c: &mut Criterion, samples: &mut Vec<Sample>) {
    let exec: Arc<TokioExecutor> = Arc::new(TokioExecutor::new().expect("tokio runtime"));

    for &(n, axis) in BACKFILL_SIZES {
        let (tip, parents) = synthetic_chain(n);

        c.bench_function(&format!("history_mmr/backfill/{axis}"), |b| {
            b.iter_with_setup(
                || {
                    let (dir, layout) = fresh_layout();
                    let h = CommitHistory::open_at(exec.clone(), &layout, BRANCH).unwrap();
                    (dir, h)
                },
                |(_dir, mut h)| {
                    history::rebuild_from_chain::<_, _, Infallible>(&mut h, tip, |hash| {
                        Ok(parents.get(hash).copied().flatten())
                    })
                    .unwrap();
                },
            );
        });

        let (_dir, layout) = fresh_layout();
        let mut h = CommitHistory::open_at(exec.clone(), &layout, BRANCH).unwrap();
        let ms = time_ms(|| {
            history::rebuild_from_chain::<_, _, Infallible>(&mut h, tip, |hash| {
                Ok(parents.get(hash).copied().flatten())
            })
            .unwrap();
        });
        samples.push(Sample {
            category: "history_mmr".into(),
            axis: axis.into(),
            library: "backfill".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }
}

fn bench_history_mmr(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();
    bench_open_at(c, &mut samples);
    bench_single_append(c, &mut samples);
    bench_backfill(c, &mut samples);
    mkit_benches::write_summary("history_mmr", &samples);
}

// Every series here does real journal I/O (the journaled MMR fsyncs on
// every append), and `backfill/250 commits` alone is 250 fsyncs per
// iteration — criterion's default sample_size (100) would make a full
// run take a very long time. 10 (criterion's minimum) matches the
// convention `pack_shard_transfer.rs` already uses for its own slow,
// I/O-bound series.
criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_history_mmr
);
criterion_main!(benches);
