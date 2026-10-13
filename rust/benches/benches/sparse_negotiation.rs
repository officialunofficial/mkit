//! Sparse-witness traversal cost on a synthetic monorepo tree.
//!
//! The "server" is an in-memory map of tree id -> Tree. Each fetch builds a
//! witness, encodes it to the wire envelope and decodes it again, so bytes
//! are real wire bytes. `verify_sparse_hierarchy` is the client. Time is CPU
//! only: there is no network, so round trips are counted, not timed.
//!
//! Env: `SPARSE_FAN` (dirs per level, default 100), `SPARSE_FILES` (files per
//! leaf dir, default 100). Defaults give 1,000,000 files in 10,101 trees.

use mkit_core::hash::{Hash, hash};
use mkit_core::merkle::compute_tree_id;
use mkit_core::object::{EntryMode, Tree, TreeEntry};
use mkit_core::sparse::{
    SparseError, SparseResponse, SparseWireError, build_sparse, decode_sparse_response,
    encode_sparse_response, verify_sparse_hierarchy,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;

type Store = HashMap<Hash, Tree>;

fn file_entry(i: usize, seed: u64) -> TreeEntry {
    TreeEntry {
        name: format!("f{i:06}.rs").into_bytes(),
        mode: EntryMode::Blob,
        object_hash: hash(&[&i.to_le_bytes()[..], &seed.to_le_bytes()].concat()),
    }
}

/// Build a `levels`-deep tree; returns the tree id. `edit` flips one file in
/// the leaf at path `edit` (e.g. [42, 7]) to model a one-file change.
fn build(store: &mut Store, fan: usize, files: usize, level: usize, path: &mut Vec<usize>, edit: Option<&[usize]>) -> Hash {
    let mut entries = Vec::new();
    if level == 2 {
        let dir_seed = (path[0] * 1000 + path[1]) as u64 + 1;
        let edited = edit.is_some_and(|e| e == path.as_slice());
        for i in 0..files {
            let seed = if edited && i == 0 { dir_seed ^ 0xABCD_0000 } else { dir_seed };
            entries.push(file_entry(i, seed));
        }
    } else {
        for d in 0..fan {
            path.push(d);
            let id = build(store, fan, files, level + 1, path, edit);
            path.pop();
            entries.push(TreeEntry {
                name: format!("d{d:03}").into_bytes(),
                mode: EntryMode::Tree,
                object_hash: id,
            });
        }
    }
    let t = Tree { entries };
    let id = compute_tree_id(&t);
    store.insert(id, t);
    id
}

struct Stats {
    fetches: usize,
    bytes: usize,
    entries: usize,
    secs: f64,
    misses: usize,
}

fn traverse(
    store: &Store,
    root: Hash,
    filter: &[&str],
    cache: &mut HashSet<(Hash, Vec<PathBuf>)>,
) -> Result<Stats, SparseWireError> {
    let filter: Vec<PathBuf> = filter.iter().map(PathBuf::from).collect();
    let (mut fetches, mut bytes, mut misses) = (0, 0, 0);
    let t0 = Instant::now();
    let out = verify_sparse_hierarchy(root, &filter, |id, f| {
        fetches += 1;
        let key = (*id, f.to_vec());
        let resp: SparseResponse = build_sparse(&store[id], f).map_err(|_| SparseWireError::TooLarge)?;
        let wire = encode_sparse_response(&resp)?;
        let resp = decode_sparse_response(&wire)?;
        if cache.insert(key) {
            misses += 1;
            bytes += wire.len();
        }
        Ok(resp)
    })?;
    Ok(Stats { fetches, bytes, entries: out.len(), secs: t0.elapsed().as_secs_f64(), misses })
}

fn kib(b: usize) -> String {
    if b >= 1 << 20 { format!("{:.2} MiB", b as f64 / 1048576.0) } else { format!("{:.1} KiB", b as f64 / 1024.0) }
}

fn main() {
    let fan: usize = std::env::var("SPARSE_FAN").ok().map_or(100, |s| s.parse().unwrap());
    let files: usize = std::env::var("SPARSE_FILES").ok().map_or(100, |s| s.parse().unwrap());
    let mut store = Store::new();
    let t0 = Instant::now();
    let root = build(&mut store, fan, files, 0, &mut Vec::new(), None);
    let total_files = fan * fan * files;
    let all_tree_bytes: usize = store.values().map(|t| t.entries.iter().map(|e| 37 + e.name.len()).sum::<usize>() + 10).sum();
    println!("tree: {total_files} files, {} trees, ~{} of tree metadata, built in {:.2}s\n", store.len(), kib(all_tree_bytes), t0.elapsed().as_secs_f64());

    println!("== A. cold traversal (empty client cache) ==");
    println!("{:<34} {:>8} {:>12} {:>10} {:>10}", "filter", "fetches", "wire bytes", "entries", "cpu ms");
    let scenarios: Vec<(&str, Vec<&str>)> = vec![
        ("one leaf dir (d042/d007)", vec!["d042/d007"]),
        ("ten scattered leaf dirs", vec!["d001/d002", "d011/d012", "d021/d022", "d031/d032", "d041/d042", "d051/d052", "d061/d062", "d071/d072", "d081/d082", "d091/d092"]),
        ("one top dir (d042)", vec!["d042"]),
        ("everything (.)", vec!["."]),
    ];
    for (name, f) in &scenarios {
        let mut cache = HashSet::new();
        match traverse(&store, root, f, &mut cache) {
            Ok(s) => println!("{:<34} {:>8} {:>12} {:>10} {:>10.1}", name, s.fetches, kib(s.bytes), s.entries, s.secs * 1e3),
            Err(e) => println!("{:<34} error: {e}", name),
        }
    }

    println!("\n== B. warm client, then one-file edit in d042/d007 (re-fetch cost) ==");
    println!("{:<34} {:>8} {:>12} {:>10}", "filter (cache = prior commit)", "refetch", "wire bytes", "of cold");
    let mut store2 = store.clone();
    let root2 = build(&mut store2, fan, files, 0, &mut Vec::new(), Some(&[42, 7]));
    for (name, f) in &scenarios {
        let mut cache = HashSet::new();
        let (Ok(cold), Ok(warm)) = (traverse(&store, root, f, &mut cache), traverse(&store2, root2, f, &mut cache)) else {
            println!("{:<34} error (see A)", name);
            continue;
        };
        println!("{:<34} {:>8} {:>12} {:>9.1}%", name, warm.misses, kib(warm.bytes), 100.0 * warm.bytes as f64 / cold.bytes as f64);
    }

    println!("\n== C. flat directory (one tree, N files) vs wire cap ==");
    println!("{:>9} {:>14} {:>10}", "files", "witness", "result");
    for n in [10_000, 100_000, 250_000, 400_000, 700_000] {
        let t = Tree { entries: (0..n).map(|i| file_entry(i, 0)).collect() };
        let f = [PathBuf::from("f000001.rs")];
        match build_sparse(&t, &f) {
            Ok(r) => println!("{n:>9} {:>14} {:>10}", kib(r.proof.tree_bytes.len()), "ok"),
            Err(SparseError::TooLarge) => println!("{n:>9} {:>14} {:>10}", "-", "TooLarge (needs full metadata path)"),
            Err(e) => println!("{n:>9} {:>14} {e}", "-"),
        }
    }
}
