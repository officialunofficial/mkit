//! Canonical ancestry snapshot publication and verified reload costs.
use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one};
use mkit_core::{
    hash::Hash,
    history::AncestrySnapshot,
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
/// bulk publish of a `count`-deep history built entirely out-of-band. Each
/// `update_ref_with_ancestry` call used to re-walk and re-verify the
/// *entire* first-parent chain from scratch (`history::ancestry::advance`'s
/// `first_parent_chain(store, target)`), so publishing N commits one at a
/// time cost O(N) per publish, O(N^2) total; it also built the same
/// in-memory MMR twice per publish (once to validate before persisting the
/// intent, again in `finish` to actually write it) regardless of chain
/// length. This isolates that pattern.
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
criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_history_mmr, bench_sequential_publish);
criterion_main!(benches);
