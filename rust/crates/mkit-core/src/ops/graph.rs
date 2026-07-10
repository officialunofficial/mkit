//! Commit-graph traversal helpers.
//!
//! This module exposes [`collect_ancestor_set`]. Higher-level walks
//! (`is_ancestor`, `find_merge_base`) live in [`super::merge`] alongside
//! the merge algorithm that consumes them.
//!
//! Bound: at most [`MAX_ANCESTORS`] (`10_000`) commits are visited per
//! call. Beyond that the walk stops silently — callers asking about
//! pathologically deep histories get a partial answer rather than an
//! OOM.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::hash::BuildHasher;

use crate::hash::Hash;
use crate::object::{Object, ObjectType};
use crate::store::{ObjectStore, StoreError};

/// Hard cap on commits visited per call.
pub const MAX_ANCESTORS: usize = 10_000;

/// Collect the set of all ancestor commits of `start`, including
/// `start` itself, by DFS over `Commit::parents`. The walk:
///
/// * Adds `start` to `set` even if its object is not in the store
///   (the hash is recorded, then the missing-object error
///   short-circuits the parent walk for that node).
/// * Treats non-commit objects at a hash as terminators (no parents to
///   follow).
/// * Stops cleanly after [`MAX_ANCESTORS`] inserts.
///
/// # Errors
///
/// Only [`StoreError::Io`] / [`StoreError::HashMismatch`] /
/// [`StoreError::ObjectTooLarge`] / [`StoreError::Decode`] propagate.
/// `ObjectNotFound` is *swallowed* — see test
/// `handles_non_existent_parent_gracefully`.
pub fn collect_ancestor_set<S: BuildHasher>(
    store: &ObjectStore,
    start: Hash,
    set: &mut HashSet<Hash, S>,
) -> Result<(), StoreError> {
    let mut stack: Vec<Hash> = Vec::new();
    stack.push(start);

    let mut count: usize = 0;
    while let Some(current) = stack.pop() {
        if count >= MAX_ANCESTORS {
            break;
        }
        if !set.insert(current) {
            continue;
        }
        count += 1;

        match store.read_object(&current) {
            Ok(Object::Commit(c)) => {
                for &parent in &c.parents {
                    stack.push(parent);
                }
            }
            // Non-commit (or unreadable) — stop walking from this node,
            // but we keep the hash in `set`.
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Hard cap on the total number of objects [`reachable_objects`] will
/// visit per call. Matches the scale of [`MAX_ANCESTORS`] but applies
/// to the full object closure (commits + trees + blobs + chunks), so it
/// is intentionally larger. A repo that exceeds this cap has to split
/// pushes — the push-path is the only caller for now.
pub const MAX_REACHABLE: usize = 10_000_000;

/// Collect every object reachable from commit `root` — the full closure
/// needed to reconstruct the commit on a fresh store. Walks, in order:
///
/// 1. `root` commit → its `tree_hash` + every `parent`.
/// 2. each tree → every entry's `object_hash` (blob / tree / chunked-blob).
/// 3. nested trees → recurse.
/// 4. chunked-blob manifests → every `chunks[i]` hash.
///
/// Deltas are not produced by any path the push code drives, and remix
/// objects are walked like commits (tree + parents) per SPEC-OBJECTS §6.
///
/// Returns a [`BTreeSet`] so iteration order is deterministic — the
/// push code uses that to build reproducible packfiles. Deduplication
/// happens naturally via the set.
///
/// # Errors
///
/// - [`StoreError::ObjectNotFound`] if `root` itself is missing from
///   the store. Missing *referenced* objects (e.g. a tree listing a
///   blob that got pruned) are a harder failure and propagate via the
///   same variant — callers pushing partial repos should fix their
///   store before pushing.
/// - Other [`StoreError`] variants propagate as-is.
pub fn reachable_objects(store: &ObjectStore, root: &Hash) -> Result<BTreeSet<Hash>, StoreError> {
    reachable_closure(store, std::iter::once(root))
}

/// Collect every object reachable from **any** of `roots` — the
/// multi-root generalization of [`reachable_objects`]. This is the
/// closure `mkit gc` (#233) keeps live: seed it with the full retention
/// root set from [`super::gc::collect_roots`] and every object NOT in the
/// result is unreachable.
///
/// Identical walk semantics to [`reachable_objects`] (commits/remixes →
/// tree + parents, trees → entries, chunked-blobs → chunks, tags →
/// target, blobs/deltas are leaves), deduped via the returned
/// [`BTreeSet`], and capped at [`MAX_REACHABLE`] total objects. With a
/// single root the result is byte-identical to [`reachable_objects`].
///
/// # Errors
///
/// Propagates [`StoreError`] as [`reachable_objects`] does — notably
/// [`StoreError::ObjectNotFound`] for a missing root or referenced
/// object, so a caller (gc) fails closed rather than under-counting the
/// live set.
pub fn reachable_closure<'a, I>(store: &ObjectStore, roots: I) -> Result<BTreeSet<Hash>, StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    // Push-path callers tolerate cap truncation (they split pushes), so
    // the truncation flag is dropped here. gc must NOT — it uses
    // [`reachable_closure_checked`] and fails closed.
    reachable_closure_checked(store, roots).map(|(out, _truncated)| out)
}

/// Like [`reachable_closure`] but also reports whether the
/// [`MAX_REACHABLE`] cap truncated the walk (`true` = incomplete). A
/// caller that would *delete* unreachable objects (gc) MUST treat
/// `truncated == true` as fatal: beyond the cap the "unreachable" verdict
/// is unsound, so pruning would drop live data.
///
/// # Errors
///
/// Propagates [`StoreError`] as [`reachable_objects`] does.
pub fn reachable_closure_checked<'a, I>(
    store: &ObjectStore,
    roots: I,
) -> Result<(BTreeSet<Hash>, bool), StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    reachable_closure_checked_with_cap(store, roots, MAX_REACHABLE)
}

/// Same walk as [`reachable_closure_checked`], but with a caller-supplied
/// cap instead of the hardcoded [`MAX_REACHABLE`] (10 million).
///
/// Test-only injection point: `gc`'s fail-closed `Truncated` abort has
/// no other way to exercise a truncation without actually constructing
/// ten million objects. `pub(crate)`, not part of the public API — real
/// external callers MUST use [`reachable_closure_checked`] (or
/// [`reachable_closure`]) instead.
pub(crate) fn reachable_closure_checked_with_cap<'a, I>(
    store: &ObjectStore,
    roots: I,
    cap: usize,
) -> Result<(BTreeSet<Hash>, bool), StoreError>
where
    I: IntoIterator<Item = &'a Hash>,
{
    let mut out: BTreeSet<Hash> = BTreeSet::new();
    let mut queue: VecDeque<Hash> = VecDeque::new();
    for root in roots {
        queue.push_back(*root);
    }

    let mut truncated = false;
    while let Some(h) = queue.pop_front() {
        if out.len() >= cap {
            // Still had work to do but hit the cap — the closure is
            // incomplete.
            truncated = true;
            break;
        }
        if !out.insert(h) {
            continue;
        }
        // Classify the node via the cheap 6-byte prologue check
        // (`object_type`) instead of a full read+verify+decode
        // (`read_object`) — INV-14. Missing objects bubble up here
        // exactly as `read_object` would: a reachable-set walk for a
        // push must refuse to build a known-broken pack.
        let ty = store.object_type(&h)?;
        if matches!(ty, ObjectType::Blob | ObjectType::Delta) {
            // Leaves — nothing to walk, so there is nothing more to learn
            // about this node than its type. Skip the full read entirely:
            // its content (and therefore its BLAKE3 integrity) is never
            // consulted by reachability. Whoever actually reads this
            // object's bytes later (pack build, checkout, ...) still gets
            // the full verified read via `store.read`/`read_object`.
            continue;
        }

        // Every other kind needs its decoded body to find its children,
        // so this still pays for a full read+verify+decode.
        let obj = store.read_object(&h)?;
        match obj {
            Object::Commit(c) => {
                queue.push_back(c.tree_hash);
                for p in c.parents {
                    queue.push_back(p);
                }
            }
            Object::Remix(r) => {
                queue.push_back(r.tree_hash);
                for p in r.parents {
                    queue.push_back(p);
                }
                // Remix `sources` are foreign-repo pointers (SPEC-OBJECTS
                // §6) — by definition NOT in our store, so don't queue them.
            }
            Object::Tree(t) => {
                for e in t.entries {
                    queue.push_back(e.object_hash);
                }
            }
            Object::ChunkedBlob(cb) => {
                for c in cb.chunks {
                    queue.push_back(c);
                }
            }
            Object::Tag(t) => {
                // An annotated/signed tag points at one target object
                // (SPEC-OBJECTS §6a). Walk it so a tag is a valid pack
                // root.
                queue.push_back(t.target);
            }
            Object::Blob(_) | Object::Delta(_) => {
                // Unreachable: `object_type` already filtered these out
                // above. Kept so the match stays exhaustive if a new
                // object kind is ever added.
                unreachable!("blob/delta leaves are short-circuited before read_object")
            }
        }
    }
    Ok((out, truncated))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
#[allow(clippy::many_single_char_names)] // single-letter commit names keep the test tables compact
mod tests {
    use super::*;
    use crate::hash;
    use crate::object::EntryMode;
    use crate::object::{Blob, Commit, Identity, Object, Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    fn store() -> (TempDir, ObjectStore) {
        let d = TempDir::new().unwrap();
        let s = ObjectStore::init(&crate::layout::RepoLayout::single(d.path())).unwrap();
        (d, s)
    }

    fn put_blob(s: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        s.write(&bytes).unwrap()
    }

    fn put_tree(s: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let bytes = serialize::serialize(&Object::Tree(Tree { entries })).unwrap();
        s.write(&bytes).unwrap()
    }

    fn make_single_file_tree(s: &ObjectStore, name: &[u8], data: &[u8]) -> Hash {
        let blob = put_blob(s, data);
        put_tree(
            s,
            vec![TreeEntry {
                name: name.to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        )
    }

    fn make_commit(s: &ObjectStore, tree: Hash, parents: &[Hash], message: &str) -> Hash {
        let c = Commit {
            tree_hash: tree,
            parents: parents.to_vec(),
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: message.as_bytes().to_vec(),
            timestamp: message.len() as u64, // tiny per-commit divergence avoids store dedup
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        };
        let bytes = serialize::serialize(&Object::Commit(c)).unwrap();
        s.write(&bytes).unwrap()
    }

    #[test]
    fn linear_chain_3_commits() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f", b"data");
        let c1 = make_commit(&s, tree, &[], "c1");
        let c2 = make_commit(&s, tree, &[c1], "c2");
        let c3 = make_commit(&s, tree, &[c2], "c3");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c3, &mut set).unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&c1));
        assert!(set.contains(&c2));
        assert!(set.contains(&c3));
    }

    #[test]
    fn diamond_dag() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let c1 = make_commit(&s, tree, &[], "c1");
        let c2 = make_commit(&s, tree, &[c1], "c2");
        let c3 = make_commit(&s, tree, &[c1], "c3");
        let c4 = make_commit(&s, tree, &[c2, c3], "c4");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c4, &mut set).unwrap();
        assert_eq!(set.len(), 4);
        assert!(set.contains(&c1));
        assert!(set.contains(&c2));
        assert!(set.contains(&c3));
        assert!(set.contains(&c4));
    }

    #[test]
    fn root_commit_alone() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let c1 = make_commit(&s, tree, &[], "root");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c1, &mut set).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&c1));
    }

    #[test]
    fn handles_non_existent_parent_gracefully() {
        let (_d, s) = store();
        let tree = make_single_file_tree(&s, b"f.txt", b"data");
        let fake_parent = hash::hash(b"nonexistent-parent");
        let c1 = make_commit(&s, tree, &[fake_parent], "orphan");

        let mut set = HashSet::new();
        collect_ancestor_set(&s, c1, &mut set).unwrap();
        // Both c1 and the fake hash end up in the set; the fake hash
        // doesn't continue the walk because the object lookup fails.
        assert_eq!(set.len(), 2);
        assert!(set.contains(&c1));
        assert!(set.contains(&fake_parent));
    }

    #[test]
    fn empty_store_records_starting_hash() {
        let (_d, s) = store();
        let fake = hash::hash(b"does-not-exist");
        let mut set = HashSet::new();
        collect_ancestor_set(&s, fake, &mut set).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&fake));
    }

    // =================================================================
    // reachable_objects — full closure from a commit.
    // =================================================================

    #[test]
    fn reachable_single_commit_includes_tree_and_blob() {
        let (_d, s) = store();
        let blob = put_blob(&s, b"hi");
        let tree = put_tree(
            &s,
            vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        let c1 = make_commit(&s, tree, &[], "c1");
        let reach = reachable_objects(&s, &c1).unwrap();
        assert!(reach.contains(&c1));
        assert!(reach.contains(&tree));
        assert!(reach.contains(&blob));
        assert_eq!(reach.len(), 3);
    }

    #[test]
    fn reachable_walks_parents_and_dedups() {
        let (_d, s) = store();
        let t = make_single_file_tree(&s, b"f", b"x");
        let c1 = make_commit(&s, t, &[], "c1");
        let c2 = make_commit(&s, t, &[c1], "c2");
        let reach = reachable_objects(&s, &c2).unwrap();
        // c1, c2, one shared tree, one shared blob
        assert_eq!(reach.len(), 4);
        assert!(reach.contains(&c1));
        assert!(reach.contains(&c2));
        assert!(reach.contains(&t));
    }

    #[test]
    fn reachable_walks_nested_trees() {
        let (_d, s) = store();
        let leaf = put_blob(&s, b"leaf");
        let inner = put_tree(
            &s,
            vec![TreeEntry {
                name: b"leaf".to_vec(),
                mode: EntryMode::Blob,
                object_hash: leaf,
            }],
        );
        let outer = put_tree(
            &s,
            vec![TreeEntry {
                name: b"sub".to_vec(),
                mode: EntryMode::Tree,
                object_hash: inner,
            }],
        );
        let c1 = make_commit(&s, outer, &[], "c");
        let reach = reachable_objects(&s, &c1).unwrap();
        assert!(reach.contains(&outer));
        assert!(reach.contains(&inner));
        assert!(reach.contains(&leaf));
    }

    #[test]
    fn reachable_walks_chunked_blob_chunks() {
        use crate::object::ChunkedBlob;
        let (_d, s) = store();
        let c0 = put_blob(&s, b"A");
        let c1 = put_blob(&s, b"B");
        let cb_bytes = serialize::serialize(&Object::ChunkedBlob(ChunkedBlob {
            total_size: 2,
            chunk_size: 1,
            chunks: vec![c0, c1],
        }))
        .unwrap();
        let cb = s.write(&cb_bytes).unwrap();
        let tree = put_tree(
            &s,
            vec![TreeEntry {
                name: b"big".to_vec(),
                mode: EntryMode::Blob,
                object_hash: cb,
            }],
        );
        let commit = make_commit(&s, tree, &[], "c");
        let reach = reachable_objects(&s, &commit).unwrap();
        assert!(reach.contains(&cb));
        assert!(reach.contains(&c0));
        assert!(reach.contains(&c1));
    }

    #[test]
    fn reachable_missing_root_errors() {
        let (_d, s) = store();
        let fake = hash::hash(b"nope");
        let err = reachable_objects(&s, &fake).unwrap_err();
        assert!(matches!(err, StoreError::ObjectNotFound(_)));
    }

    // =================================================================
    // object_type() short-circuit (#636 / INV-14) — the walk must
    // classify blob/delta leaves via the cheap type-prologue check
    // instead of a full read+verify+decode, without changing the
    // reachable/unreachable classification of any object (INV-3).
    // =================================================================

    /// Flip a byte well past the 6-byte type prologue (offset 0..6, which
    /// `object_type()` reads) so the object's on-disk *content* no longer
    /// matches its BLAKE3 hash, while its type tag stays intact.
    fn corrupt_payload_byte(s: &ObjectStore, h: &Hash) {
        use std::fs::OpenOptions;
        use std::io::{Read, Seek, SeekFrom, Write};
        let path = s.path_for(h);
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(SeekFrom::Start(6)).unwrap();
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte).unwrap();
        f.seek(SeekFrom::Start(6)).unwrap();
        f.write_all(&[byte[0] ^ 0xFF]).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn reachable_closure_matches_expected_set_for_mixed_graph() {
        // Correctness proxy for "byte-identical to the old full-read path":
        // a hand-computed expected set over a graph that exercises every
        // node kind the walk handles (commit chain, tree, nested tree,
        // chunked-blob manifest, plain blobs).
        let (_d, s) = store();
        let leaf1 = put_blob(&s, b"leaf-one");
        let inner = put_tree(
            &s,
            vec![TreeEntry {
                name: b"leaf".to_vec(),
                mode: EntryMode::Blob,
                object_hash: leaf1,
            }],
        );
        let chunk_a = put_blob(&s, b"chunk-a");
        let chunk_b = put_blob(&s, b"chunk-b");
        let cb_bytes = serialize::serialize(&Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 14,
            chunk_size: 7,
            chunks: vec![chunk_a, chunk_b],
        }))
        .unwrap();
        let cb = s.write(&cb_bytes).unwrap();
        let outer = put_tree(
            &s,
            vec![
                TreeEntry {
                    name: b"big".to_vec(),
                    mode: EntryMode::Blob,
                    object_hash: cb,
                },
                TreeEntry {
                    name: b"sub".to_vec(),
                    mode: EntryMode::Tree,
                    object_hash: inner,
                },
            ],
        );
        let c1 = make_commit(&s, outer, &[], "c1");
        let c2 = make_commit(&s, outer, &[c1], "c2");

        let reach = reachable_objects(&s, &c2).unwrap();
        let expected: BTreeSet<Hash> = [c1, c2, outer, inner, leaf1, cb, chunk_a, chunk_b]
            .into_iter()
            .collect();
        assert_eq!(reach, expected);
    }

    #[test]
    fn reachable_closure_short_circuits_corrupted_blob_leaf() {
        let (_d, s) = store();
        let blob = put_blob(&s, &vec![0xABu8; 4096]);
        let tree = put_tree(
            &s,
            vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        let c1 = make_commit(&s, tree, &[], "c1");

        corrupt_payload_byte(&s, &blob);

        // Sanity: a full read+verify of this object now fails — proves the
        // corruption is real and would have broken the old `read_object`
        // path had it still been called for this leaf.
        assert!(matches!(
            s.read_object(&blob),
            Err(StoreError::HashMismatch { .. })
        ));

        // The walk must still succeed, and the blob must still be
        // classified reachable: reachability only needs to know this node
        // has no children, and the intact type prologue already answers
        // that. Content integrity is a concern for whoever reads the bytes
        // later, not for this classification.
        let (reach, truncated) = reachable_closure_checked(&s, [c1].iter()).unwrap();
        assert!(!truncated);
        assert!(reach.contains(&c1));
        assert!(reach.contains(&tree));
        assert!(reach.contains(&blob));
        assert_eq!(reach.len(), 3);
    }

    #[test]
    fn reachable_closure_still_fails_closed_on_corrupted_tree() {
        // A non-leaf node (tree) still needs its decoded body to find its
        // children, so corruption there must still surface as an error —
        // proving the short-circuit is targeted at true leaves (blob/
        // delta) only, not a blanket weakening of verification.
        let (_d, s) = store();
        let blob = put_blob(&s, b"hi");
        let tree = put_tree(
            &s,
            vec![TreeEntry {
                name: b"f".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        );
        let c1 = make_commit(&s, tree, &[], "c1");

        corrupt_payload_byte(&s, &tree);

        let err = reachable_closure_checked(&s, [c1].iter()).unwrap_err();
        assert!(matches!(err, StoreError::HashMismatch { .. }));
    }
}
