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
criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_history_mmr);
criterion_main!(benches);
