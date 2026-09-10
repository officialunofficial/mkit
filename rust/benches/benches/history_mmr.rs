//! Canonical ancestry snapshot publication and verified reload costs.
use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::{
    hash::Hash,
    history::{AncestrySnapshot, CommitHistory},
    layout::RepoLayout,
    object::{Commit, Identity, Object, Tree},
    refs::{self, RefWriteCondition},
    serialize::serialize,
    store::ObjectStore,
};

fn fixture(count: u64) -> (tempfile::TempDir, RepoLayout, ObjectStore, Hash) {
    let dir = tempfile::tempdir().unwrap();
    let layout = RepoLayout::single(dir.path());
    let store = ObjectStore::init(&layout).unwrap();
    refs::init(&layout).unwrap();
    let tree = store
        .write(&serialize(&Object::Tree(Tree { entries: vec![] })).unwrap())
        .unwrap();
    let mut parents = vec![];
    let mut tip = [0; 32];
    for i in 0..count {
        let commit = Commit::new_unannotated(
            tree,
            parents,
            Identity::opaque(b"bench".to_vec()),
            [0; 32],
            i.to_le_bytes().to_vec(),
            0,
            [0; 64],
        );
        tip = store
            .write(&serialize(&Object::Commit(commit)).unwrap())
            .unwrap();
        parents = vec![tip];
    }
    (dir, layout, store, tip)
}

/// Repeated single-commit publishes to the same branch — the steady state
/// of real `mkit commit` usage, as opposed to `bench_history_mmr`'s single
/// bulk publish of a `count`-deep history built entirely out-of-band.
///
/// `history::ancestry::advance` used to re-walk and re-verify the *entire*
/// first-parent chain from `store` on every fast-forward publish, an
/// intentional integrity check (see the CHANGELOG entry for the
/// chain-splicing fast path that was prototyped and reverted rather than
/// weaken it) that made publishing N commits one at a time cost O(N) store
/// reads per publish, O(N^2) total. That's since been bounded: a
/// fast-forward now verifies its new suffix in full plus a rotating,
/// scheduled window of the reused prefix (`history::ancestry::decide_chain`,
/// `ScrubState` — see the CHANGELOG entry and SPEC-HISTORY-PROOF §4.5 for
/// the full design and the prior-art research behind it), not the whole
/// prefix every time, while still re-verifying every leaf from the store at
/// least once every 64 fast-forwards or 7 days, whichever comes first — the
/// integrity check is bounded and scheduled, not weakened or dropped.
/// `read_current`'s MMB rebuild of the *previous* snapshot no longer
/// contributes to any of this either: it's skipped entirely for `advance`'s
/// comparison-only need (`read_current_descriptor`), and the new snapshot's
/// own MMB is now built as one batch instead of N single-leaf ones.
///
/// None of this shows up in *this* bench's numbers: at 100-300 commits, the
/// scrub window (minimum 512 leaves) covers the entire prefix in one pass
/// every time, so every publish here still does a full walk exactly like
/// before — and even where the window does kick in, this bench's
/// fsync-dominated wall-clock cost swamps a store-read difference this
/// small (see CHANGELOG for the earlier MMB-rebuild reductions, hidden the
/// same way). `history::ancestry::tests::profile_scrub_window_vs_full_walk_every_publish`
/// (manual, `--ignored`) isolates the effect at a chain length long enough
/// to show it. This bench remains the regression guard for the per-publish
/// fsync/durability-pipeline cost, which the scrub window does not and
/// should not change.
fn bench_sequential_publish(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    fn fixture_chain(count: u64) -> (tempfile::TempDir, RepoLayout, ObjectStore, Vec<Hash>) {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let store = ObjectStore::init(&layout).unwrap();
        refs::init(&layout).unwrap();
        let tree = store
            .write(&serialize(&Object::Tree(Tree { entries: vec![] })).unwrap())
            .unwrap();
        let mut parents = vec![];
        let mut commits = Vec::with_capacity(count as usize);
        for i in 0..count {
            let commit = Commit::new_unannotated(
                tree,
                parents,
                Identity::opaque(b"bench".to_vec()),
                [0; 32],
                i.to_le_bytes().to_vec(),
                0,
                [0; 64],
            );
            let h = store
                .write(&serialize(&Object::Commit(commit)).unwrap())
                .unwrap();
            parents = vec![h];
            commits.push(h);
        }
        (dir, layout, store, commits)
    }

    for count in [100u64, 300] {
        let axis = format!("{count} commits, one publish each");
        c.bench_function(&format!("history_mmr/sequential_publish/{count}"), |b| {
            b.iter_with_setup(
                || fixture_chain(count),
                |(_dir, layout, store, commits)| {
                    for h in &commits {
                        refs::update_ref_with_ancestry(
                            &layout,
                            "main",
                            RefWriteCondition::Any,
                            h,
                            &store,
                        )
                        .unwrap();
                    }
                },
            );
        });
        let (_dir, layout, store, commits) = fixture_chain(count);
        let ms = time_one(0, 1, || {
            for h in &commits {
                refs::update_ref_with_ancestry(&layout, "main", RefWriteCondition::Any, h, &store)
                    .unwrap();
            }
        }) * 1000.0;
        samples.push(Sample {
            category: "history_mmr".into(),
            axis,
            library: "sequential_publish".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    mkit_benches::write_summary("history_mmr_sequential", &samples);
}

fn bench_history_mmr(c: &mut Criterion) {
    let mut samples = vec![];
    for count in [50, 250] {
        let axis = format!("{count} commits");
        c.bench_function(&format!("history_mmr/publish/{count}"), |b| {
            b.iter_with_setup(
                || fixture(count),
                |(_dir, layout, store, tip)| {
                    refs::update_ref_with_ancestry(
                        &layout,
                        "main",
                        RefWriteCondition::Missing,
                        &tip,
                        &store,
                    )
                    .unwrap();
                },
            );
        });
        let (_dir, layout, store, tip) = fixture(count);
        let mut result = None;
        let elapsed = time_one(0, 1, || {
            result = Some(refs::update_ref_with_ancestry(
                &layout,
                "main",
                RefWriteCondition::Missing,
                &tip,
                &store,
            ));
        });
        result.unwrap().unwrap();
        samples.push(Sample {
            category: "history_mmr".into(),
            axis: axis.clone(),
            library: "publish".into(),
            value: elapsed * 1000.0,
            unit: Unit::Millis,
        });
        c.bench_function(&format!("history_mmr/load/{count}"), |b| {
            b.iter(|| std::hint::black_box(AncestrySnapshot::load(&layout, "main").unwrap()));
        });
        let elapsed = time_one(0, 1, || {
            std::hint::black_box(AncestrySnapshot::load(&layout, "main").unwrap());
        });
        samples.push(Sample {
            category: "history_mmr".into(),
            axis,
            library: "load".into(),
            value: elapsed * 1000.0,
            unit: Unit::Millis,
        });
    }
    mkit_benches::write_summary("history_mmr", &samples);
}

/// In-memory `CommitHistory` tree construction only (one batched `extend`
/// over the whole chain, matching `AncestrySnapshot::build`'s call shape)
/// — no `ObjectStore`, no filesystem, no fsync. `bench_history_mmr`'s
/// `publish`/`load` series go through the full durable-publish pipeline
/// (~10 fsync/`sync_dir` calls), which dominates their wall-clock cost and
/// hides this. A regression guard for that specific cost; NOT where the
/// MMR-to-MMB switch's claimed benefit (bounded *per-append* worst case,
/// see SPEC-HISTORY-PROOF §1) would show up — total node/hash count across
/// a whole chain differs from MMR by well under 1% at realistic history
/// sizes (see CHANGELOG), and a single batched `extend` does all the
/// merging in one pass regardless of structure, so a single append's
/// worst-case boundary case is invisible here by construction.
fn bench_in_memory_build(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for count in [50u64, 250, 1000, 5000] {
        let hashes: Vec<Hash> = (0..count)
            .map(|i| mkit_core::hash::hash(&i.to_be_bytes()))
            .collect();
        let axis = format!("{count} commits");

        c.bench_function(&format!("history_mmr/in_memory_build/{count}"), |b| {
            b.iter(|| {
                let mut h = CommitHistory::open();
                h.extend(&hashes).unwrap();
                std::hint::black_box(h.root())
            });
        });
        let mut result = None;
        let elapsed = time_one(0, 1, || {
            let mut h = CommitHistory::open();
            h.extend(&hashes).unwrap();
            result = Some(h.root());
        });
        std::hint::black_box(result.unwrap());
        samples.push(Sample {
            category: "history_mmr".into(),
            axis,
            library: "in_memory_build".into(),
            value: elapsed * 1000.0,
            unit: Unit::Millis,
        });
    }

    mkit_benches::write_summary("history_mmr_in_memory_build", &samples);
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_history_mmr, bench_sequential_publish, bench_in_memory_build);
criterion_main!(benches);
