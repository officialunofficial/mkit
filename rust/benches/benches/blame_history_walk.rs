//! `ops::blame::blame_file` at increasing per-file history length.
//!
//! Regression guard for the common-**leading-run** elision in
//! `ops::blame`'s `match_lines`: blame replays a file's ancestor chain one
//! step at a time, calling the LCS matcher once per edge. Its DP core is
//! `O(m*n)` in *both* time and space (a `Vec<Vec<u32>>` table sized off the
//! two full line counts), and — unlike `ops::diff`'s Myers core, which pays
//! `O((n+m)*d)` for an edit of size `d` regardless — the naive matcher pays
//! for the whole file's size on *every single step* of a long history, even
//! when each step only touches a couple of lines near the end. Eliding the
//! shared leading run before the DP runs shrinks each step's table down
//! toward the size of that step's actual edit.
//!
//! `full_rewrite` is the control: every commit replaces the entire file
//! (no shared prefix at all), so elision finds nothing to trim and this
//! scenario's numbers should be unaffected by the change (not a
//! regression) — it's kept at a much smaller line count than
//! `append_near_end` for the same reason `diff_edit_script.rs`'s
//! `no_common_affix` is: the underlying `O(m*n)` cost is unrelated to this
//! optimization and blows up fast.
//!
//! Numbers are wallclock ms; smaller is better.

use criterion::{Criterion, criterion_group, criterion_main};
use mkit_benches::{Sample, Unit, time_one_with_setup};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::ops::blame::blame_file;
use mkit_core::store::ObjectStore;
use mkit_core::{Hash, serialize};

const FILE_PATH: &str = "f.txt";
/// (line count, history length, axis label).
const APPEND_SCENARIOS: &[(usize, usize, &str)] = &[
    (2_000, 50, "2k lines x 50 commits"),
    (2_000, 200, "2k lines x 200 commits"),
    (10_000, 200, "10k lines x 200 commits"),
];
/// `full_rewrite` only: `O(m*n)` per step with nothing to elide makes a
/// long history at realistic file sizes impractical (unrelated to this
/// change — see module doc).
const REWRITE_SCENARIOS: &[(usize, usize, &str)] = &[(500, 50, "500 lines x 50 commits")];

fn put_blob(store: &ObjectStore, data: &[u8]) -> Hash {
    let bytes = serialize::serialize(&Object::Blob(Blob {
        data: data.to_vec(),
    }))
    .unwrap();
    store.write(&bytes).unwrap()
}

fn put_commit(store: &ObjectStore, content: &[u8], parents: Vec<Hash>, seq: u64) -> Hash {
    let blob = put_blob(store, content);
    let tree = Object::Tree(Tree {
        entries: vec![TreeEntry {
            name: FILE_PATH.as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob,
        }],
    });
    let tree_hash = store.write(&serialize::serialize(&tree).unwrap()).unwrap();
    let commit = Object::Commit(Commit::new_unannotated(
        tree_hash,
        parents,
        Identity::opaque(seq.to_le_bytes()),
        [0u8; 32],
        b"msg".to_vec(),
        seq,
        [0u8; 64],
    ));
    store
        .write(&serialize::serialize(&commit).unwrap())
        .unwrap()
}

fn lines(n: usize, make: impl Fn(usize) -> String) -> Vec<u8> {
    let mut out = String::with_capacity(n * 8);
    for i in 0..n {
        out.push_str(&make(i));
        out.push('\n');
    }
    out.into_bytes()
}

/// `history_len` commits on an `n`-line file, each one only touching a
/// couple of lines near the end — the common "append a log line" /
/// "tweak the last function" editing shape. Every version shares a long
/// leading run with the one before it.
fn build_append_history(store: &ObjectStore, n: usize, history_len: usize) -> Hash {
    let mut parent = None;
    let mut head = None;
    for step in 0..history_len {
        let content = lines(n, |i| {
            if i == n - 1 {
                format!("line {i} step {step}")
            } else {
                format!("line {i}")
            }
        });
        let parents = parent.map(|p| vec![p]).unwrap_or_default();
        let c = put_commit(store, &content, parents, step as u64);
        parent = Some(c);
        head = Some(c);
    }
    head.unwrap()
}

/// `history_len` commits on an `n`-line file, each one replacing every
/// line — no shared prefix between any two adjacent versions.
fn build_rewrite_history(store: &ObjectStore, n: usize, history_len: usize) -> Hash {
    let mut parent = None;
    let mut head = None;
    for step in 0..history_len {
        let content = lines(n, |i| format!("step {step} line {i}"));
        let parents = parent.map(|p| vec![p]).unwrap_or_default();
        let c = put_commit(store, &content, parents, step as u64);
        parent = Some(c);
        head = Some(c);
    }
    head.unwrap()
}

fn run_one(
    c: &mut Criterion,
    samples: &mut Vec<Sample>,
    name: &str,
    axis: &str,
    build: impl Fn(&ObjectStore) -> Hash,
) {
    c.bench_function(&format!("blame_history_walk/{axis}/{name}"), |b| {
        b.iter_with_setup(
            || {
                let dir = tempfile::tempdir().unwrap();
                let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
                let head = build(&store);
                (dir, store, head)
            },
            |(_dir, store, head)| blame_file(&store, head, FILE_PATH).unwrap(),
        );
    });
    let ms = time_one_with_setup(
        2,
        10,
        || {
            let dir = tempfile::tempdir().unwrap();
            let store = ObjectStore::init(&RepoLayout::single(dir.path())).unwrap();
            let head = build(&store);
            (dir, store, head)
        },
        |(_dir, store, head)| {
            std::hint::black_box(blame_file(&store, head, FILE_PATH).unwrap());
        },
    ) * 1000.0;
    eprintln!("blame_history_walk/{axis}/{name}: {ms:.4} ms");
    samples.push(Sample {
        category: "blame_history_walk".into(),
        axis: axis.into(),
        library: name.into(),
        value: ms,
        unit: Unit::Millis,
    });
}

fn bench_blame_history_walk(c: &mut Criterion) {
    let mut samples: Vec<Sample> = Vec::new();

    for &(n, history_len, axis) in APPEND_SCENARIOS {
        run_one(c, &mut samples, "append_near_end", axis, |store| {
            build_append_history(store, n, history_len)
        });
    }
    for &(n, history_len, axis) in REWRITE_SCENARIOS {
        run_one(c, &mut samples, "full_rewrite", axis, |store| {
            build_rewrite_history(store, n, history_len)
        });
    }

    mkit_benches::write_summary("blame_history_walk", &samples);
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = bench_blame_history_walk);
criterion_main!(benches);
