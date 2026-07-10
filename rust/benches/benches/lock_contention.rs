//! `repo_lock` acquire/release round-trip and contended-handoff latency.
//!
//! Zero prior coverage before this file (issue #644): a grep for
//! `repo_lock` across `rust/benches/` previously returned nothing.
//!
//! The `contended_handoff` series doubles as the regression guard for
//! issue #635's fix to [`mkit_core::repo_lock::acquire`]'s poll loop:
//! today a losing acquirer retries on a fixed-interval sleep
//! ([`mkit_core::repo_lock::DEFAULT_SLEEP`], 50ms) rather than blocking
//! on the holder's release, so a waiter that just missed the winning
//! `create_new` can sit idle for up to a full poll quantum after the
//! lock is actually free. This bench pins the holder's release to a
//! few ms after the waiter starts contending, so the measured latency
//! is dominated by that poll quantum, not by hold duration — once
//! #635 lands (presumably a blocking wait rather than sleep-poll), this
//! number should collapse from ~50ms towards low single-digit ms.
//!
//! Numbers are wallclock ms; smaller is better. Both series involve
//! real filesystem locking (and, for the contended series, real
//! thread sleeps), so sample size is kept small — see the
//! `criterion_group!` config below — to keep a full (non-`--test`) run
//! fast.

use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::repo_lock;

const LOCK_NAME: &str = "bench.lock";
/// How long the holder keeps the lock before releasing, once the
/// waiter has signalled it is about to contend. Long enough that the
/// waiter is guaranteed to have lost the `create_new` race and entered
/// its poll-sleep before we release (avoiding a lucky race where the
/// waiter's very first attempt happens to land after release).
const HOLD_AFTER_CONTENTION: Duration = Duration::from_millis(5);

fn time_ms(f: impl FnMut()) -> f64 {
    time_one(0, 1, f) * 1000.0
}

/// Uncontended acquire+release round trip: no other holder, so this is
/// pure create-file + `flock` + unlink cost.
fn uncontended_round_trip(dir: &Path) {
    let lock = repo_lock::acquire_default(dir, LOCK_NAME).unwrap();
    drop(lock);
}

/// Two acquirers contend for the same lock: this thread holds it,
/// spawns a waiter that immediately starts trying to acquire the same
/// lock, holds for [`HOLD_AFTER_CONTENTION`] past the waiter's first
/// attempt, then releases. Returns the waiter's acquire-to-success
/// latency in ms.
fn contended_handoff_ms(dir: &Path) -> f64 {
    let held = repo_lock::acquire_default(dir, LOCK_NAME).unwrap();

    let dir_owned = dir.to_path_buf();
    let (ready_tx, ready_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        ready_tx.send(()).unwrap();
        let start = Instant::now();
        let lock = repo_lock::acquire_default(&dir_owned, LOCK_NAME).unwrap();
        let elapsed = start.elapsed();
        drop(lock);
        elapsed
    });

    // Block until the waiter thread is alive and about to make its
    // first attempt, then give it long enough to lose the create race
    // and enter its poll-sleep before we release.
    ready_rx.recv().unwrap();
    thread::sleep(HOLD_AFTER_CONTENTION);
    drop(held);

    waiter.join().unwrap().as_secs_f64() * 1000.0
}

fn bench_lock_contention(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    c.bench_function("lock_contention/uncontended_round_trip", |b| {
        b.iter_with_setup(
            || tempfile::tempdir().unwrap(),
            |dir| uncontended_round_trip(dir.path()),
        );
    });
    {
        let dir = tempfile::tempdir().unwrap();
        let ms = time_ms(|| uncontended_round_trip(dir.path()));
        samples.push(Sample {
            category: "lock_contention".into(),
            axis: "uncontended round trip".into(),
            library: "repo_lock".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    c.bench_function("lock_contention/contended_handoff", |b| {
        b.iter_with_setup(
            || tempfile::tempdir().unwrap(),
            |dir| {
                contended_handoff_ms(dir.path());
            },
        );
    });
    {
        let dir = tempfile::tempdir().unwrap();
        let ms = contended_handoff_ms(dir.path());
        samples.push(Sample {
            category: "lock_contention".into(),
            axis: "contended handoff (2 acquirers)".into(),
            library: "repo_lock".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    mkit_benches::write_summary("lock_contention", &samples);
}

// Both series involve a real thread handoff with a multi-ms sleep in
// the loop; criterion's default sample_size (100) would make a full
// run take minutes. 10 (criterion's minimum) is plenty to see the
// distribution and matches the convention `pack_shard_transfer.rs`
// already uses for its own slow, I/O-bound series.
criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_lock_contention
);
criterion_main!(benches);
