//! Inter-file fan-out for checkout/clone/reset/restore of *many small
//! files*: `ops::restore::restore_tree_to_worktree_with` defers plain
//! (non-chunked) file writes and materialises them on a small pool of
//! scoped worker threads, while `restore_tree_to_worktree` keeps the
//! original one-file-at-a-time loop.
//!
//! `files/<n>_x_4k`: restore `n` distinct 4 KiB files (spread over 50
//! directories) into a fresh tempdir — sequential vs parallel.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::Object;
use mkit_core::ops::restore::{
    RestoreError, RestoreOptions, restore_tree_to_worktree, restore_tree_to_worktree_with,
};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;
use tempfile::TempDir;

const FILE_COUNTS: &[usize] = &[100, 1_000, 5_000];

fn build_source_tree(n: usize) -> (TempDir, ObjectStore, Hash) {
    let src = tempfile::tempdir().expect("tempdir");
    for i in 0..n {
        let dir = src.path().join(format!("d{}", i % 50));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let mut data = format!("mkit restore-small-files fixture #{i}\n").into_bytes();
        data.resize(4096, b'x');
        std::fs::write(dir.join(format!("f{i}")), data).expect("write");
    }
    let store_dir = tempfile::tempdir().expect("tempdir");
    let store = ObjectStore::init(&RepoLayout::single(store_dir.path())).expect("init");
    let wb = store.batch();
    let tree = worktree::build_tree(&wb, src.path()).expect("build tree");
    wb.commit().expect("commit");
    (store_dir, store, tree)
}

fn bench_small_files(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();
    for &n in FILE_COUNTS {
        let axis = format!("files/{n}_x_4k");
        let (_d, store, tree) = build_source_tree(n);

        let seq_ms = time_one_with_setup(
            1,
            9,
            || tempfile::tempdir().expect("tempdir"),
            |t| {
                restore_tree_to_worktree(&store, &tree, t.path(), &RestoreOptions::default())
                    .expect("restore");
            },
        ) * 1000.0;
        let par_ms = time_one_with_setup(
            1,
            9,
            || tempfile::tempdir().expect("tempdir"),
            |t| {
                restore_tree_to_worktree_with(
                    &store,
                    &tree,
                    None,
                    t.path(),
                    &RestoreOptions::default(),
                    &|s: &ObjectStore, hs: &[Hash]| {
                        hs.iter()
                            .map(|h| match s.read_object(h)? {
                                Object::Blob(b) => Ok(b.data),
                                _ => Err(RestoreError::NotABlob),
                            })
                            .collect()
                    },
                )
                .expect("restore");
            },
        ) * 1000.0;

        eprintln!("restore_small_files/{axis}: sequential {seq_ms:.3} ms, parallel {par_ms:.3} ms");
        for (library, value) in [("sequential", seq_ms), ("parallel", par_ms)] {
            samples.push(Sample {
                category: "restore_small_files".into(),
                axis: axis.clone(),
                library: library.into(),
                value,
                unit: Unit::Millis,
            });
        }
    }
    let _ = c;
    mkit_benches::write_summary("restore_small_files", &samples);
}

criterion_group!(benches, bench_small_files);
criterion_main!(benches);
