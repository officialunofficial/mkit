//! End-to-end checkout of a directory of many small files:
//! `ops::restore::restore_tree_to_worktree`. Each file is an independent
//! read + BLAKE3-verify + tmp-file write + rename, so the per-directory
//! blob loop is the fan-out target (see `restore_chunk_fanout.rs` for
//! the intra-file `ChunkedBlob` shape).
//!
//! `files/<n>`: one flat directory of `n` 4 KiB files, restored into a
//! fresh tempdir.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::ops::restore::{RestoreOptions, restore_tree_to_worktree};
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

const FILE_COUNTS: &[usize] = &[64, 512, 4096];

fn build_source_tree(n: usize) -> (tempfile::TempDir, ObjectStore, Hash) {
    let src = tempfile::tempdir().expect("tempdir");
    for i in 0..n {
        let mut v = format!("mkit restore small-file fixture #{i}\n").into_bytes();
        v.resize(4096, b'x');
        std::fs::write(src.path().join(format!("f{i:05}.txt")), v).expect("write");
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
        let (_d, store, tree) = build_source_tree(n);
        let ms = time_one_with_setup(
            1,
            9,
            || tempfile::tempdir().expect("tempdir"),
            |target| {
                restore_tree_to_worktree(&store, &tree, target.path(), &RestoreOptions::default())
                    .expect("restore");
            },
        ) * 1000.0;
        eprintln!("restore_small_files/files/{n}: {ms:.3} ms");
        samples.push(Sample {
            category: "restore_small_files".into(),
            axis: format!("files/{n}"),
            library: "mkit".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }
    let _ = c;
    mkit_benches::write_summary("restore_small_files", &samples);
}

criterion_group!(benches, bench_small_files);
criterion_main!(benches);
