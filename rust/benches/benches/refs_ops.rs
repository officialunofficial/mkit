//! Ref-write latency across the three [`RefWriteCondition`] CAS
//! variants, plus `list_refs` at increasing ref counts.
//!
//! Zero prior coverage before this file (issue #644): a grep for
//! `refs::` across `rust/benches/` previously returned nothing, so
//! every performance claim about ref writes was unverifiable by CI.
//!
//! Numbers are wallclock ms; smaller is better. Real writes hit the
//! disk, so absolute values are machine/filesystem dependent — the
//! interesting signal is the relative cost across CAS variants and
//! the `list_refs` growth curve.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::hash::{Hash, hash};
use mkit_core::layout::RepoLayout;
use mkit_core::refs::{self, RefWriteCondition};

const BRANCH: &str = "main";
const LIST_REFS_COUNTS: &[(usize, &str)] =
    &[(100, "100 refs"), (1_000, "1k refs"), (10_000, "10k refs")];

fn synth(i: u64) -> Hash {
    hash(&i.to_be_bytes())
}

/// Wallclock milliseconds for a single un-warmed invocation of `f`. See
/// `store_write.rs`'s identical helper for the rationale: durability
/// paths (and here, real directory I/O) want one real pass timed, not
/// a warmed-cache average.
fn time_ms(f: impl FnMut()) -> f64 {
    time_one(0, 1, f) * 1000.0
}

fn bench_refs_update(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    // -- Any: unconditional write into a fresh (empty) repo. -----------
    c.bench_function("refs_update/Any", |b| {
        b.iter_with_setup(
            || {
                let dir = tempfile::tempdir().unwrap();
                let layout = RepoLayout::single(dir.path());
                (dir, layout)
            },
            |(_dir, layout)| {
                refs::update_ref(&layout, BRANCH, RefWriteCondition::Any, &synth(0)).unwrap();
            },
        );
    });
    {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let ms = time_ms(|| {
            refs::update_ref(&layout, BRANCH, RefWriteCondition::Any, &synth(0)).unwrap();
        });
        samples.push(Sample {
            category: "refs_update".into(),
            axis: "Any".into(),
            library: "update_ref".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    // -- Missing: O_EXCL write into a fresh repo where the ref does not
    // yet exist, so the precondition is satisfied every iteration. -----
    c.bench_function("refs_update/Missing", |b| {
        b.iter_with_setup(
            || {
                let dir = tempfile::tempdir().unwrap();
                let layout = RepoLayout::single(dir.path());
                (dir, layout)
            },
            |(_dir, layout)| {
                refs::update_ref(&layout, BRANCH, RefWriteCondition::Missing, &synth(0)).unwrap();
            },
        );
    });
    {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let ms = time_ms(|| {
            refs::update_ref(&layout, BRANCH, RefWriteCondition::Missing, &synth(0)).unwrap();
        });
        samples.push(Sample {
            category: "refs_update".into(),
            axis: "Missing".into(),
            library: "update_ref".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    // -- Match: pre-populate the ref with a known hash, then CAS against
    // that exact value (the satisfied-precondition path). ---------------
    c.bench_function("refs_update/Match", |b| {
        b.iter_with_setup(
            || {
                let dir = tempfile::tempdir().unwrap();
                let layout = RepoLayout::single(dir.path());
                let current = synth(0);
                refs::update_ref(&layout, BRANCH, RefWriteCondition::Any, &current).unwrap();
                (dir, layout, current)
            },
            |(_dir, layout, current)| {
                refs::update_ref(
                    &layout,
                    BRANCH,
                    RefWriteCondition::Match(current),
                    &synth(1),
                )
                .unwrap();
            },
        );
    });
    {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let current = synth(0);
        refs::update_ref(&layout, BRANCH, RefWriteCondition::Any, &current).unwrap();
        let ms = time_ms(|| {
            refs::update_ref(
                &layout,
                BRANCH,
                RefWriteCondition::Match(current),
                &synth(1),
            )
            .unwrap();
        });
        samples.push(Sample {
            category: "refs_update".into(),
            axis: "Match".into(),
            library: "update_ref".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    mkit_benches::write_summary("refs_update", &samples);
}

/// `list_refs` at increasing ref counts, to catch an O(n) directory-walk
/// regression in ref listing. Fixtures are built once per size (not
/// once per criterion iteration — `list_refs` is read-only, so the same
/// on-disk ref tree can be listed repeatedly without staleness or dedup
/// concerns).
fn bench_list_refs(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, axis) in LIST_REFS_COUNTS {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        for i in 0..n as u64 {
            refs::update_ref(
                &layout,
                &format!("bench/{i}"),
                RefWriteCondition::Any,
                &synth(i),
            )
            .unwrap();
        }

        c.bench_function(&format!("list_refs/{axis}"), |b| {
            b.iter(|| refs::list_refs(&layout).unwrap());
        });

        let ms = time_ms(|| {
            let _ = refs::list_refs(&layout).unwrap();
        });
        samples.push(Sample {
            category: "list_refs".into(),
            axis: axis.into(),
            library: "list_refs".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    mkit_benches::write_summary("list_refs", &samples);
}

criterion_group!(benches, bench_refs_update, bench_list_refs);
criterion_main!(benches);
