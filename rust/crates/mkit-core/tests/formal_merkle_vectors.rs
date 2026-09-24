//! Differential-test vector exporter for the Lean model of
//! `docs/specs/SPEC-MERKLE-OBJECTS.md` (Linear MKIT-24, `formal/lean/`).
//!
//! Writes golden (exhaustive small) and seeded-random BMT cases to a text
//! file: per tree the leaf digests, a hash-oracle table of every
//! position-hash / node / finalize / wrap evaluation the construction uses,
//! the Rust root and id, and per single / multi / range proof the proven
//! position(s), the proof's `leaf_count`, its siblings, their
//! `(level, index)` positions and the Rust verifier's verdict, plus
//! adversarial variants (§6 tamper rows, wrong positions, reordered /
//! repeated / zero positions) with Rust's verdict on each.
//! `formal/lean/scripts/difftest-merkle.sh` then runs the Lean
//! `merkle_difftest` executable, which recomputes sibling selection (§5.3),
//! proofs, roots and every verdict (§5.4/§5.5) from the exported oracle and
//! fails on any disagreement.
//!
//! Ignored by default (it writes a multi-MB file):
//! `cargo test -p mkit-core --test formal_merkle_vectors -- --ignored`.
//! Env: `MKIT_FORMAL_MERKLE_OUT` (output path, default under
//! `CARGO_TARGET_TMPDIR`), `MKIT_FORMAL_SEED` (u64), `MKIT_FORMAL_TREES`
//! (random tree count).
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use mkit_core::hash::{Hash, Hasher, domain_digest, to_hex};
use mkit_core::merkle::{self, ObjectKind, Proof};
use mkit_core::object::{ChunkedBlob, EntryMode, Tree, TreeEntry};

/// splitmix64: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick(&mut self, n: usize) -> usize {
        usize::try_from(self.below(u64::try_from(n).unwrap())).unwrap()
    }
    fn pick32(&mut self, n: usize) -> u32 {
        u32::try_from(self.pick(n)).unwrap()
    }
    fn hash(&mut self) -> Hash {
        let mut h = [0u8; 32];
        for c in h.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        h
    }
}

fn h2(a: &[u8], b: &[u8]) -> Hash {
    let mut h = Hasher::new();
    h.update(a).update(b);
    h.finalize()
}

/// Independent re-derivation of the SPEC §3 leaf digests (the Rust helpers are
/// crate-private); `Case::new` asserts the resulting root equals merkle.rs's.
fn tree_leaf(e: &TreeEntry) -> Hash {
    let mut body = Vec::new();
    body.extend_from_slice(&u32::try_from(e.name.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&e.name);
    body.push(e.mode as u8);
    body.extend_from_slice(&e.object_hash);
    domain_digest(b"mkit-tree-entry-v1", &body)
}

fn meta_leaf(cb: &ChunkedBlob) -> Hash {
    let mut body = Vec::new();
    body.extend_from_slice(&cb.total_size.to_le_bytes());
    body.extend_from_slice(&cb.chunk_size.to_le_bytes());
    domain_digest(b"mkit-cblob-meta-v1", &body)
}

enum Obj {
    Tree(Tree),
    Chunked(ChunkedBlob),
}

struct Case {
    obj: Obj,
    leaves: Vec<Hash>,
    id: Hash,
    /// `(level, index)` of every node digest, for mapping proof siblings back.
    at: HashMap<Hash, (usize, usize)>,
}

impl Case {
    fn new(obj: Obj, out: &mut String, name: &str) -> Self {
        let (kind, leaves, inner, id) = match &obj {
            Obj::Tree(t) => (
                "tree",
                t.entries.iter().map(tree_leaf).collect::<Vec<_>>(),
                merkle::tree_inner_root(t),
                merkle::compute_tree_id(t),
            ),
            Obj::Chunked(cb) => {
                let mut l = vec![meta_leaf(cb)];
                l.extend_from_slice(&cb.chunks);
                (
                    "chunked",
                    l,
                    merkle::chunked_inner_root(cb),
                    merkle::compute_chunked_id(cb),
                )
            }
        };
        let n = leaves.len();
        writeln!(out, "TREE {name} {kind} {n}").unwrap();
        let empty = mkit_core::hash::hash(b"");
        writeln!(out, "EMPTY {}", to_hex(&empty)).unwrap();
        out.push_str("LEAVES");
        for l in &leaves {
            write!(out, " {}", to_hex(l)).unwrap();
        }
        out.push('\n');
        // Oracle: every hash evaluation of §1.1, computed with BLAKE3 directly.
        let mut level: Vec<Hash> = if n == 0 {
            vec![empty]
        } else {
            leaves
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    let o = h2(&u32::try_from(i).unwrap().to_be_bytes(), l);
                    writeln!(out, "L {i} {} {}", to_hex(l), to_hex(&o)).unwrap();
                    o
                })
                .collect()
        };
        let mut at = HashMap::new();
        let mut lvl = 0;
        loop {
            for (k, d) in level.iter().enumerate() {
                assert!(at.insert(*d, (lvl, k)).is_none(), "duplicate node digest");
            }
            if level.len() <= 1 {
                break;
            }
            let next: Vec<Hash> = level
                .chunks(2)
                .map(|p| {
                    let r = if p.len() == 2 { &p[1] } else { &p[0] };
                    let o = h2(&p[0], r);
                    writeln!(out, "N {} {} {}", to_hex(&p[0]), to_hex(r), to_hex(&o)).unwrap();
                    o
                })
                .collect();
            level = next;
            lvl += 1;
        }
        let root = h2(&u32::try_from(n).unwrap().to_be_bytes(), &level[0]);
        writeln!(out, "F {n} {} {}", to_hex(&level[0]), to_hex(&root)).unwrap();
        assert_eq!(
            root, inner,
            "exporter BMT disagrees with merkle.rs ({name})"
        );
        let wk = match obj {
            Obj::Tree(_) => ObjectKind::Tree,
            Obj::Chunked(_) => ObjectKind::ChunkedBlob,
        };
        assert_eq!(merkle::wrap_id(wk, &root), id);
        writeln!(out, "W {kind} {} {}", to_hex(&root), to_hex(&id)).unwrap();
        writeln!(out, "ROOT {}", to_hex(&inner)).unwrap();
        writeln!(out, "ID {}", to_hex(&id)).unwrap();
        Self {
            obj,
            leaves,
            id,
            at,
        }
    }

    fn emit(&self, out: &mut String, tag: &str, positions: &[u32], proof: &Proof, accept: bool) {
        let pos: Vec<String> = positions.iter().map(u32::to_string).collect();
        let sibpos: Vec<String> = proof
            .siblings
            .iter()
            .map(|s| {
                let (l, k) = self.at[s];
                format!("{l}:{k}")
            })
            .collect();
        let sibs: Vec<String> = proof.siblings.iter().map(to_hex).collect();
        let dash = |v: Vec<String>| {
            if v.is_empty() {
                "-".to_owned()
            } else {
                v.join(",")
            }
        };
        writeln!(
            out,
            "PROOF {tag} {} {} {} {} {}",
            pos.join(","),
            proof.leaf_count,
            dash(sibpos),
            dash(sibs),
            u8::from(accept)
        )
        .unwrap();
    }

    /// Rust id-based single-leaf verdict (§5.4; §5.5 for chunks).
    fn verify_single(&self, pos: u32, proof: &Proof) -> bool {
        let leaf = self.leaves[pos as usize];
        match &self.obj {
            Obj::Tree(t) => {
                merkle::verify_tree_entry(&self.id, &t.entries[pos as usize], pos, proof).is_ok()
            }
            Obj::Chunked(_) => merkle::verify_chunk(&self.id, &leaf, pos, proof).is_ok(),
        }
    }

    /// Rust multi verdict for elements given in this (possibly unsorted or
    /// repeated) position order, each with its honest leaf.
    fn verify_multi(&self, positions: &[u32], proof: &Proof) -> bool {
        match &self.obj {
            Obj::Tree(t) => {
                let es: Vec<(TreeEntry, u32)> = positions
                    .iter()
                    .map(|&i| (t.entries[i as usize].clone(), i))
                    .collect();
                merkle::verify_tree_entries_multi(&self.id, &es, proof).is_ok()
            }
            Obj::Chunked(_) => {
                let cs: Vec<(Hash, u32)> = positions
                    .iter()
                    .map(|&i| (self.leaves[i as usize], i))
                    .collect();
                merkle::verify_chunks_multi(&self.id, &cs, proof).is_ok()
            }
        }
    }

    /// Rust range verdict for the honest leaves `start..start + count`.
    fn verify_range(&self, start: u32, count: u32, proof: &Proof) -> bool {
        let (a, b) = (start as usize, (start + count) as usize);
        match &self.obj {
            Obj::Tree(t) => {
                merkle::verify_tree_entries_range(&self.id, start, &t.entries[a..b], proof).is_ok()
            }
            Obj::Chunked(_) => {
                merkle::verify_chunks_range(&self.id, start, &self.leaves[a..b], proof).is_ok()
            }
        }
    }

    /// `ADV <mode> <positions> <leaf_count> <siblings> <verdict>`: a tampered
    /// or unusual proof/claim and the Rust verifier's verdict on it.
    fn adv(out: &mut String, mode: &str, pos: &str, proof: &Proof, accept: bool) {
        let sibs: Vec<String> = proof.siblings.iter().map(to_hex).collect();
        let sibs = if sibs.is_empty() {
            "-".to_owned()
        } else {
            sibs.join(",")
        };
        let pos = if pos.is_empty() { "-" } else { pos };
        writeln!(
            out,
            "ADV {mode} {pos} {} {sibs} {}",
            proof.leaf_count,
            u8::from(accept)
        )
        .unwrap();
    }

    /// §6 tamper rows applied to an honest proof: `leaf_count` ±1, a dropped,
    /// an extra, a swapped and a substituted sibling.
    fn tampered(&self, proof: &Proof) -> Vec<Proof> {
        let mut v = Vec::new();
        let mut p = proof.clone();
        p.leaf_count += 1;
        v.push(p);
        if proof.leaf_count > 0 {
            let mut p = proof.clone();
            p.leaf_count -= 1;
            v.push(p);
        }
        if !proof.siblings.is_empty() {
            let mut p = proof.clone();
            p.siblings.pop();
            v.push(p);
        }
        let mut p = proof.clone();
        p.siblings
            .push(self.leaves.first().copied().unwrap_or_default());
        v.push(p);
        if proof.siblings.len() >= 2 && proof.siblings[0] != proof.siblings[1] {
            let mut p = proof.clone();
            p.siblings.swap(0, 1);
            v.push(p);
        }
        // An in-tree node digest (level 0, index 0) in the wrong slot.
        let node00 = self
            .at
            .iter()
            .find(|(_, lk)| **lk == (0, 0))
            .map(|(d, _)| *d);
        if let (Some(d), Some(&s0)) = (node00, proof.siblings.first())
            && d != s0
        {
            let mut p = proof.clone();
            p.siblings[0] = d;
            v.push(p);
        }
        v
    }

    /// Single-leaf proof of position `pos`, plus a wrong-position negative
    /// and tampered variants.
    fn single(&self, out: &mut String, pos: u32) {
        let count = u32::try_from(self.leaves.len()).unwrap();
        let other = (pos + 1) % count;
        let proof = match &self.obj {
            Obj::Tree(tree) => merkle::build_tree_entry_proof(tree, pos).unwrap(),
            Obj::Chunked(cb) => merkle::build_chunk_proof(cb, pos).unwrap(),
        };
        // §5.5: verify_chunk must reject position 0 (the meta leaf).
        let accept = self.verify_single(pos, &proof);
        self.emit(out, "single", &[pos], &proof, accept);
        if other != pos {
            // Leaf `pos`'s digest claimed at position `other`, same proof.
            let leaf = self.leaves[pos as usize];
            let wrong = match &self.obj {
                Obj::Tree(t) => {
                    let e = &t.entries[pos as usize];
                    merkle::verify_tree_entry(&self.id, e, other, &proof).is_ok()
                }
                Obj::Chunked(_) => merkle::verify_chunk(&self.id, &leaf, other, &proof).is_ok(),
            };
            writeln!(out, "WRONGPOS {pos} {other} {}", u8::from(wrong)).unwrap();
        }
        for p in self.tampered(&proof) {
            let v = self.verify_single(pos, &p);
            Self::adv(out, "single", &pos.to_string(), &p, v);
        }
    }

    fn multi(&self, out: &mut String, positions: &[u32]) {
        let proof = match &self.obj {
            Obj::Tree(t) => {
                merkle::build_tree_entries_multi_proof(t, positions.iter().copied()).unwrap()
            }
            Obj::Chunked(cb) => {
                merkle::build_chunks_multi_proof(cb, positions.iter().copied()).unwrap()
            }
        };
        let accept = self.verify_multi(positions, &proof);
        self.emit(out, "multi", positions, &proof, accept);
        let csv = |ps: &[u32]| ps.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        // §5.4: any element order is accepted; a repeated or zero position set is not.
        let rev: Vec<u32> = positions.iter().rev().copied().collect();
        Self::adv(
            out,
            "multi",
            &csv(&rev),
            &proof,
            self.verify_multi(&rev, &proof),
        );
        let mut dup = positions.to_vec();
        dup.push(positions[0]);
        Self::adv(
            out,
            "multi",
            &csv(&dup),
            &proof,
            self.verify_multi(&dup, &proof),
        );
        Self::adv(out, "multi", "", &proof, self.verify_multi(&[], &proof));
        for p in self.tampered(&proof) {
            let v = self.verify_multi(positions, &p);
            Self::adv(out, "multi", &csv(positions), &p, v);
        }
    }

    /// Range proof of `start..=end`, plus shifted-start and tampered variants.
    fn range(&self, out: &mut String, start: u32, end: u32) {
        let proof = match &self.obj {
            Obj::Tree(t) => merkle::build_tree_entries_range_proof(t, start, end).unwrap(),
            Obj::Chunked(cb) => merkle::build_chunks_range_proof(cb, start, end).unwrap(),
        };
        let count = end - start + 1;
        let accept = self.verify_range(start, count, &proof);
        let tag = format!("{start},{count}");
        self.emit(out, "range", &[start, end], &proof, accept);
        let n = u32::try_from(self.leaves.len()).unwrap();
        if end + 1 < n {
            // The same leaves claimed one position to the right.
            let shifted: Vec<Hash> = self.leaves[start as usize..=end as usize].to_vec();
            let v = match &self.obj {
                Obj::Tree(t) => merkle::verify_tree_entries_range(
                    &self.id,
                    start + 1,
                    &t.entries[start as usize..=end as usize],
                    &proof,
                )
                .is_ok(),
                Obj::Chunked(_) => {
                    merkle::verify_chunks_range(&self.id, start + 1, &shifted, &proof).is_ok()
                }
            };
            writeln!(out, "SHIFTRANGE {start} {count} {}", u8::from(v)).unwrap();
        }
        for p in self.tampered(&proof) {
            let v = self.verify_range(start, count, &p);
            Self::adv(out, "range", &tag, &p, v);
        }
    }
}

fn tree_obj(rng: &mut Rng, n: usize) -> Obj {
    let entries = (0..n)
        .map(|i| TreeEntry {
            name: format!("e{i:07}").into_bytes(),
            mode: EntryMode::Blob,
            object_hash: rng.hash(),
        })
        .collect();
    Obj::Tree(Tree { entries })
}

/// A `ChunkedBlob` with `n` BMT leaves (`n - 1` chunks, `n >= 1`).
fn chunked_obj(rng: &mut Rng, n: usize) -> Obj {
    Obj::Chunked(ChunkedBlob {
        total_size: rng.next() >> 20,
        chunk_size: u32::try_from(rng.below(1 << 20)).unwrap(),
        chunks: (1..n).map(|_| rng.hash()).collect(),
    })
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().map_or(default, |v| {
        let v = v.trim();
        v.strip_prefix("0x").map_or_else(
            || v.parse().unwrap(),
            |h| u64::from_str_radix(h, 16).unwrap(),
        )
    })
}

#[test]
#[ignore = "writes the Lean differential-test vectors; run via formal/lean/scripts/difftest-merkle.sh"]
fn export_formal_merkle_vectors() {
    let seed = env_u64("MKIT_FORMAL_SEED", 0x006d_6b69_742d_3234);
    let trees = env_u64("MKIT_FORMAL_TREES", 80);
    let path = std::env::var("MKIT_FORMAL_MERKLE_OUT").map_or_else(
        |_| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("formal_merkle_vectors.txt"),
        PathBuf::from,
    );
    let mut rng = Rng(seed);
    let mut out = format!("MKIT-MERKLE-VECTORS 1 seed={seed:#x}\n");

    // Golden: §4 empty Tree (pinned id), then every position of every small
    // tree, both kinds (chunked covers the §5.5 position-0 rejection), every
    // range for n <= 12, and every non-empty position subset for n <= 5.
    let empty = Case::new(
        Obj::Tree(Tree { entries: vec![] }),
        &mut out,
        "golden-empty-tree",
    );
    assert_eq!(empty.id, merkle::TREE_EMPTY_ID);
    // §5.4: the all-default proof over zero positions against the empty
    // Tree's id must be rejected (multi and range forms).
    let dflt = Proof::default();
    Case::adv(&mut out, "multi", "", &dflt, empty.verify_multi(&[], &dflt));
    Case::adv(
        &mut out,
        "range",
        "0,0",
        &dflt,
        empty.verify_range(0, 0, &dflt),
    );
    out.push_str("END\n");
    for n in 1..=33usize {
        for (kind, obj) in [
            ("tree", tree_obj(&mut rng, n)),
            ("chunked", chunked_obj(&mut rng, n)),
        ] {
            let c = Case::new(obj, &mut out, &format!("golden-{kind}-{n}"));
            for i in 0..u32::try_from(n).unwrap() {
                c.single(&mut out, i);
            }
            if n <= 12 {
                for a in 0..u32::try_from(n).unwrap() {
                    for b in a..u32::try_from(n).unwrap() {
                        c.range(&mut out, a, b);
                    }
                }
            }
            if n <= 5 {
                for mask in 1u32..(1 << n) {
                    let ps: Vec<u32> = (0..u32::try_from(n).unwrap())
                        .filter(|i| mask & (1 << i) != 0)
                        .collect();
                    c.multi(&mut out, &ps);
                }
            }
            out.push_str("END\n");
        }
    }

    // Random: sizes biased to power-of-two boundaries plus uniform ones.
    let edges = [
        63usize, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
    ];
    for t in 0..trees {
        let n = if let Some(&e) = usize::try_from(t).ok().and_then(|t| edges.get(t)) {
            e
        } else if rng.below(2) == 0 {
            1 + rng.pick(64)
        } else {
            1 + rng.pick(1100)
        };
        let obj = if rng.below(2) == 0 {
            tree_obj(&mut rng, n)
        } else {
            chunked_obj(&mut rng, n)
        };
        let c = Case::new(obj, &mut out, &format!("random-{t}"));
        let n32 = u32::try_from(n).unwrap();
        let mut singles = vec![0, n32 - 1];
        singles.extend((0..4).map(|_| rng.pick32(n)));
        singles.sort_unstable();
        singles.dedup();
        for i in singles {
            c.single(&mut out, i);
        }
        for _ in 0..3 {
            let k = 1 + rng.pick(n.min(12));
            let mut ps: Vec<u32> = (0..k).map(|_| rng.pick32(n)).collect();
            ps.sort_unstable();
            ps.dedup();
            c.multi(&mut out, &ps);
        }
        for _ in 0..3 {
            let (a, b) = (rng.pick32(n), rng.pick32(n));
            c.range(&mut out, a.min(b), a.max(b));
        }
        out.push_str("END\n");
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(&path, out).unwrap();
    eprintln!("wrote {}", path.display());
}
