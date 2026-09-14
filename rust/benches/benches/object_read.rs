//! `Tree` decode cost on the read path: [`ObjectStore::read_object`]
//! (through the store, id-verified) and [`mkit_core::serialize::deserialize`]
//! (in-memory, no I/O) for a tree with many entries.
//!
//! Regression guard for the read_object double-decode fix: `read_object`
//! used to `deserialize` a merkelized object's bytes twice — once inside
//! [`Self::read`]'s BMT-root id check, once again to produce the returned
//! [`mkit_core::Object`] — because the id check and the decode were two
//! separate, uncoordinated calls into the same parser. `read_object` now
//! decodes once and reuses that decode for both the id check and the
//! return value. `deserialize`'s own per-entry cost also dropped a
//! `Vec<u8>` clone of the entry name that `read_tree` kept around only
//! to compare the *next* entry's name against it — the just-pushed
//! entry already holds that name, so the clone was pure waste.
//!
//! Numbers are wallclock ms; smaller is better.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{EntryMode, Object, Tree, TreeEntry};
use mkit_core::store::ObjectStore;
use mkit_core::{hash, serialize};

const COUNTS: &[(usize, &str)] = &[(100, "100 entries"), (1000, "1000 entries")];

/// A `Tree` with `n` sorted, distinct entries and arbitrary (not
/// necessarily present) child hashes — `read_object`/`deserialize`
/// never look children up, so this is enough to exercise the decode.
fn tree_with_entries(n: usize) -> Tree {
    let entries = (0..n)
        .map(|i| TreeEntry {
            name: format!("file-{i:06}.txt").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: hash::hash(&i.to_le_bytes()),
        })
        .collect();
    Tree { entries }
}

fn bench_object_read(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, axis) in COUNTS {
        let tree = tree_with_entries(n);
        let bytes = serialize::serialize(&Object::Tree(tree)).unwrap();

        // --- in-memory decode only, no store/I/O involved --------------
        c.bench_function(&format!("object_read/deserialize/{axis}"), |b| {
            b.iter(|| serialize::deserialize(&bytes).unwrap());
        });
        let ms = time_one_with_setup(
            5,
            20,
            || (),
            |()| {
                serialize::deserialize(&bytes).unwrap();
            },
        ) * 1000.0;
        samples.push(Sample {
            category: "object-read".into(),
            axis: format!("deserialize/{axis}"),
            library: "mkit".into(),
            value: ms,
            unit: Unit::Millis,
        });

        // --- through the store: read_raw + id-verify + decode ----------
        c.bench_function(&format!("object_read/read_object/{axis}"), |b| {
            b.iter_with_setup(
                || {
                    let dir = tempfile::tempdir().unwrap();
                    let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                    let h = store.write(&bytes).unwrap();
                    (dir, store, h)
                },
                |(_dir, store, h)| store.read_object(&h).unwrap(),
            );
        });
        let ms = time_one_with_setup(
            5,
            20,
            || {
                let dir = tempfile::tempdir().unwrap();
                let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                let h = store.write(&bytes).unwrap();
                (dir, store, h)
            },
            |(_dir, store, h)| {
                store.read_object(&h).unwrap();
            },
        ) * 1000.0;
        samples.push(Sample {
            category: "object-read".into(),
            axis: format!("read_object/{axis}"),
            library: "mkit".into(),
            value: ms,
            unit: Unit::Millis,
        });
    }

    mkit_benches::write_summary("object_read", &samples);
}

criterion_group!(benches, bench_object_read);
criterion_main!(benches);
