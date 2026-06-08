//! 3-way tree merge + commit-graph merge-base + ancestry test.
//!
//! `merge_trees` lockstep-walks the three sorted entry arrays
//! (base / ours / theirs) and applies the decision matrix documented
//! above each branch in `merge_entries_recursive`. When all three sides
//! have a path with `EntryMode::Tree`, we recurse into the three
//! subtrees rather than emitting a tree-level conflict; this lets
//! per-file conflicts inside a directory be reported at their full path
//! (`src/main.rs` rather than `src`).
//!
//! `find_merge_base` walks the full DAG on both sides — it is NOT
//! limited to first-parent — so merge bases reachable only through a
//! merge commit's secondary parent are still found. Among multiple
//! common ancestors we pick the one with the smallest total depth:
//! (depth in A's ancestor tree) + (depth in B's BFS).

use std::collections::HashMap;
use std::collections::HashSet;

use crate::hash::Hash;
use crate::object::{EntryMode, Object, Tree, TreeEntry};
use crate::serialize;
use crate::store::{MAX_TREE_DEPTH, ObjectStore, StoreError};

/// Distinct conflict kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictKind {
    /// Both sides modified the same path to different content.
    ModifyModify,
    /// One side deleted the path while the other modified it.
    DeleteModify,
    /// Both sides created the path with different content.
    AddAdd,
}

/// Single conflict report. `base_hash`, `ours_hash`, `theirs_hash` are
/// `None` whenever the corresponding side does not contain the path
/// (Add/Add has no base; Delete/Modify has no hash on the deleting
/// side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub path: String,
    pub kind: ConflictKind,
    pub base_hash: Option<Hash>,
    pub ours_hash: Option<Hash>,
    pub theirs_hash: Option<Hash>,
    /// Tree mode of the ours-side entry (`None` when ours deleted the
    /// path). Carried so a downstream resolver can stage the ours-side
    /// with its real exec/symlink mode instead of defaulting to a plain
    /// blob (#214).
    pub ours_mode: Option<EntryMode>,
    /// Tree mode of the theirs-side entry (`None` when theirs deleted
    /// the path).
    pub theirs_mode: Option<EntryMode>,
}

/// Result of [`merge_trees`]. The `tree_hash` is always populated —
/// even on conflict — using "ours wins in the merged tree" as the
/// tie-breaker. Callers must check `has_conflicts()` before treating
/// the result as a clean merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeResult {
    pub tree_hash: Hash,
    pub conflicts: Vec<Conflict>,
}

impl MergeResult {
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// 3-way merge of three trees identified by their hashes (or `None` to
/// represent the empty tree). Always writes the merged tree to `store`
/// and returns its hash, even when `conflicts` is non-empty (the merged
/// tree contains "ours" at every conflicting path so a downstream
/// resolver can see what we picked).
///
/// # Errors
///
/// Propagates [`StoreError`] from object reads and the final tree write.
pub fn merge_trees(
    store: &ObjectStore,
    base_hash: Option<Hash>,
    ours_hash: Option<Hash>,
    theirs_hash: Option<Hash>,
) -> Result<MergeResult, StoreError> {
    let base_entries = load_entries(store, base_hash)?;
    let ours_entries = load_entries(store, ours_hash)?;
    let theirs_entries = load_entries(store, theirs_hash)?;

    let mut merged: Vec<TreeEntry> = Vec::new();
    let mut conflicts: Vec<Conflict> = Vec::new();
    merge_entries_recursive(
        store,
        &base_entries,
        &ours_entries,
        &theirs_entries,
        "",
        &mut merged,
        &mut conflicts,
        0,
    )?;

    let tree_hash = put_tree(store, merged)?;
    Ok(MergeResult {
        tree_hash,
        conflicts,
    })
}

/// Find the lowest-cost common ancestor of two commits. Returns
/// `Ok(None)` when the histories share no ancestor.
///
/// Definition of "lowest-cost": walk B breadth-first; for every node
/// also reachable from A (taken from a precomputed ancestor-depth map
/// of A), the cost is `depth_in_A + depth_in_B`; take the candidate
/// with smallest total depth, breaking ties by first-seen order in B's
/// BFS. This is NOT necessarily a unique LCA when histories cross
/// multiple times, but it is the behaviour the tests pin.
///
/// # Errors
///
/// Propagates [`StoreError`] from any commit-object read other than
/// `ObjectNotFound`, which is treated as "this branch terminates here".
pub fn find_merge_base(store: &ObjectStore, a: Hash, b: Hash) -> Result<Option<Hash>, StoreError> {
    if a == b {
        return Ok(Some(a));
    }
    let ancestors_a = collect_ancestors_with_depth(store, a)?;

    // BFS over B.
    let mut queue: Vec<(Hash, usize)> = Vec::new();
    queue.push((b, 0));

    let mut best: Option<(Hash, usize)> = None;
    let mut head = 0usize;
    while head < queue.len() {
        let (node, depth) = queue[head];
        head += 1;
        if let Some((_, best_total)) = best
            && depth > best_total
        {
            break;
        }
        if let Some(&ancestor_depth) = ancestors_a.get(&node) {
            let total = ancestor_depth + depth;
            match best {
                None => best = Some((node, total)),
                Some((_, t)) if total < t => best = Some((node, total)),
                _ => {}
            }
        }
        match store.read_object(&node) {
            Ok(Object::Commit(c)) => {
                for &p in &c.parents {
                    queue.push((p, depth + 1));
                }
            }
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(best.map(|(h, _)| h))
}

/// Returns `true` when `ancestor` is reachable from `descendant` by
/// walking parent pointers. `ancestor == descendant` returns `true`.
///
/// # Errors
///
/// Propagates [`StoreError`] from commit-object reads (other than
/// `ObjectNotFound`, which terminates the local walk silently).
pub fn is_ancestor(
    store: &ObjectStore,
    ancestor: Hash,
    descendant: Hash,
) -> Result<bool, StoreError> {
    if ancestor == descendant {
        return Ok(true);
    }
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut stack: Vec<Hash> = Vec::new();
    stack.push(descendant);

    while let Some(current) = stack.pop() {
        if !seen.insert(current) {
            continue;
        }
        if current == ancestor {
            return Ok(true);
        }
        match store.read_object(&current) {
            Ok(Object::Commit(c)) => {
                for &p in &c.parents {
                    stack.push(p);
                }
            }
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------

fn load_entries(store: &ObjectStore, hash: Option<Hash>) -> Result<Vec<TreeEntry>, StoreError> {
    match hash {
        Some(h) => match store.read_object(&h)? {
            Object::Tree(t) => Ok(t.entries),
            other => Err(StoreError::Decode(
                crate::object::MkitError::InvalidObjectType(other.object_type() as u8),
            )),
        },
        None => Ok(Vec::new()),
    }
}

fn put_tree(store: &ObjectStore, entries: Vec<TreeEntry>) -> Result<Hash, StoreError> {
    let bytes = serialize::serialize(&Object::Tree(Tree { entries }))?;
    store.write(&bytes)
}

/// The raw bytes of a single-object `Blob`, or `None` for a `ChunkedBlob`
/// (large file) or any non-blob — those skip the line-level merge and fall
/// back to a conflict. Blobs that `add`/`build_tree` produce are single
/// `Blob` objects below the chunk threshold, so this covers the source
/// files a 3-way text merge applies to.
fn single_blob_bytes(store: &ObjectStore, h: Hash) -> Result<Option<Vec<u8>>, StoreError> {
    match store.read_object(&h)? {
        Object::Blob(b) => Ok(Some(b.data)),
        _ => Ok(None),
    }
}

/// Attempt a line-level 3-way merge of a both-sides-modified regular-file
/// blob (#298). Returns the hash of the merged blob when ours/theirs
/// changed disjoint regions of base, or `None` to fall back to a
/// modify/modify conflict (overlapping changes, a binary side, or a
/// chunked/large blob). Genuine store I/O errors propagate.
fn try_text_merge(
    store: &ObjectStore,
    base_h: Hash,
    ours_h: Hash,
    theirs_h: Hash,
) -> Result<Option<Hash>, StoreError> {
    let (Some(base), Some(ours), Some(theirs)) = (
        single_blob_bytes(store, base_h)?,
        single_blob_bytes(store, ours_h)?,
        single_blob_bytes(store, theirs_h)?,
    ) else {
        return Ok(None);
    };
    match crate::ops::merge_blob_3way(&base, &ours, &theirs) {
        Some(merged) => {
            // Store as a single Blob — same shape (and hash) `add` produces
            // for sub-threshold content, so the merged object dedups.
            let bytes = serialize::serialize(&Object::Blob(crate::object::Blob { data: merged }))?;
            Ok(Some(store.write(&bytes)?))
        }
        None => Ok(None),
    }
}

fn collect_ancestors_with_depth(
    store: &ObjectStore,
    start: Hash,
) -> Result<HashMap<Hash, usize>, StoreError> {
    let mut ancestors: HashMap<Hash, usize> = HashMap::new();
    let mut queue: Vec<(Hash, usize)> = Vec::new();
    queue.push((start, 0));

    let mut head = 0usize;
    while head < queue.len() {
        let (node, depth) = queue[head];
        head += 1;
        // First-write-wins.
        if ancestors.contains_key(&node) {
            continue;
        }
        ancestors.insert(node, depth);
        match store.read_object(&node) {
            Ok(Object::Commit(c)) => {
                for &p in &c.parents {
                    queue.push((p, depth + 1));
                }
            }
            Ok(_) | Err(StoreError::ObjectNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(ancestors)
}

fn hash_and_mode_eq(a: &TreeEntry, b: &TreeEntry) -> bool {
    a.mode == b.mode && a.object_hash == b.object_hash
}

fn min_of_three<'a>(
    a: Option<&'a [u8]>,
    b: Option<&'a [u8]>,
    c: Option<&'a [u8]>,
) -> Option<&'a [u8]> {
    let mut result: Option<&'a [u8]> = a;
    if let Some(bv) = b {
        result = match result {
            Some(r) if r <= bv => Some(r),
            _ => Some(bv),
        };
    }
    if let Some(cv) = c {
        result = match result {
            Some(r) if r <= cv => Some(r),
            _ => Some(cv),
        };
    }
    result
}

fn join_path(prefix: &str, name: &[u8]) -> String {
    let name_str = String::from_utf8_lossy(name);
    if prefix.is_empty() {
        name_str.into_owned()
    } else {
        let mut s = String::with_capacity(prefix.len() + 1 + name_str.len());
        s.push_str(prefix);
        s.push('/');
        s.push_str(&name_str);
        s
    }
}

fn add_entry(out: &mut Vec<TreeEntry>, name: &[u8], mode: EntryMode, object_hash: Hash) {
    out.push(TreeEntry {
        name: name.to_vec(),
        mode,
        object_hash,
    });
}

#[allow(clippy::too_many_arguments)]
fn recurse_subtree_merge(
    store: &ObjectStore,
    base_sub: Option<Hash>,
    ours_sub: Option<Hash>,
    theirs_sub: Option<Hash>,
    entry_name: &[u8],
    prefix: &str,
    merged: &mut Vec<TreeEntry>,
    conflicts: &mut Vec<Conflict>,
    depth: usize,
) -> Result<(), StoreError> {
    let sub_prefix = join_path(prefix, entry_name);
    let base_entries = load_entries(store, base_sub)?;
    let ours_entries = load_entries(store, ours_sub)?;
    let theirs_entries = load_entries(store, theirs_sub)?;

    let mut sub_merged: Vec<TreeEntry> = Vec::new();
    merge_entries_recursive(
        store,
        &base_entries,
        &ours_entries,
        &theirs_entries,
        &sub_prefix,
        &mut sub_merged,
        conflicts,
        depth + 1,
    )?;

    let sub_hash = put_tree(store, sub_merged)?;
    add_entry(merged, entry_name, EntryMode::Tree, sub_hash);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn merge_entries_recursive(
    store: &ObjectStore,
    base_entries: &[TreeEntry],
    ours_entries: &[TreeEntry],
    theirs_entries: &[TreeEntry],
    prefix: &str,
    merged: &mut Vec<TreeEntry>,
    conflicts: &mut Vec<Conflict>,
    depth: usize,
) -> Result<(), StoreError> {
    if depth > MAX_TREE_DEPTH {
        return Err(StoreError::TreeTooDeep);
    }
    let mut bi = 0usize;
    let mut oi = 0usize;
    let mut ti = 0usize;

    while bi < base_entries.len() || oi < ours_entries.len() || ti < theirs_entries.len() {
        let b_name: Option<&[u8]> = base_entries.get(bi).map(|e| e.name.as_slice());
        let o_name: Option<&[u8]> = ours_entries.get(oi).map(|e| e.name.as_slice());
        let t_name: Option<&[u8]> = theirs_entries.get(ti).map(|e| e.name.as_slice());

        let Some(min_name) = min_of_three(b_name, o_name, t_name) else {
            break;
        };

        let has_base = b_name.is_some_and(|n| n == min_name);
        let has_ours = o_name.is_some_and(|n| n == min_name);
        let has_theirs = t_name.is_some_and(|n| n == min_name);

        let base_entry = if has_base {
            Some(&base_entries[bi])
        } else {
            None
        };
        let ours_entry = if has_ours {
            Some(&ours_entries[oi])
        } else {
            None
        };
        let theirs_entry = if has_theirs {
            Some(&theirs_entries[ti])
        } else {
            None
        };

        if has_base {
            bi += 1;
        }
        if has_ours {
            oi += 1;
        }
        if has_theirs {
            ti += 1;
        }

        match (has_base, has_ours, has_theirs) {
            (true, true, true) => {
                let b = base_entry.unwrap();
                let o = ours_entry.unwrap();
                let t = theirs_entry.unwrap();
                let b_eq_o = hash_and_mode_eq(b, o);
                let b_eq_t = hash_and_mode_eq(b, t);
                let o_eq_t = hash_and_mode_eq(o, t);
                if b_eq_o && b_eq_t {
                    add_entry(merged, min_name, b.mode, b.object_hash);
                } else if b_eq_t && !b_eq_o {
                    // Theirs unchanged, ours changed -> take ours.
                    if b.mode == EntryMode::Tree && o.mode == EntryMode::Tree {
                        recurse_subtree_merge(
                            store,
                            Some(b.object_hash),
                            Some(o.object_hash),
                            Some(b.object_hash),
                            min_name,
                            prefix,
                            merged,
                            conflicts,
                            depth,
                        )?;
                    } else {
                        add_entry(merged, min_name, o.mode, o.object_hash);
                    }
                } else if b_eq_o && !b_eq_t {
                    // Ours unchanged, theirs changed -> take theirs.
                    if b.mode == EntryMode::Tree && t.mode == EntryMode::Tree {
                        recurse_subtree_merge(
                            store,
                            Some(b.object_hash),
                            Some(b.object_hash),
                            Some(t.object_hash),
                            min_name,
                            prefix,
                            merged,
                            conflicts,
                            depth,
                        )?;
                    } else {
                        add_entry(merged, min_name, t.mode, t.object_hash);
                    }
                } else if o_eq_t {
                    // Both changed the same way.
                    if b.mode == EntryMode::Tree && o.mode == EntryMode::Tree {
                        recurse_subtree_merge(
                            store,
                            Some(b.object_hash),
                            Some(o.object_hash),
                            Some(t.object_hash),
                            min_name,
                            prefix,
                            merged,
                            conflicts,
                            depth,
                        )?;
                    } else {
                        add_entry(merged, min_name, o.mode, o.object_hash);
                    }
                } else if b.mode == EntryMode::Tree
                    && o.mode == EntryMode::Tree
                    && t.mode == EntryMode::Tree
                {
                    // Three-way subtree change — recurse to find per-file conflicts.
                    recurse_subtree_merge(
                        store,
                        Some(b.object_hash),
                        Some(o.object_hash),
                        Some(t.object_hash),
                        min_name,
                        prefix,
                        merged,
                        conflicts,
                        depth,
                    )?;
                } else if o.mode == t.mode
                    && matches!(o.mode, EntryMode::Blob | EntryMode::Executable)
                    && let Some(merged_hash) =
                        try_text_merge(store, b.object_hash, o.object_hash, t.object_hash)?
                {
                    // Both changed the same regular file, but on disjoint
                    // lines — auto-merge the content (#298). Mode is shared,
                    // so it carries over unambiguously.
                    add_entry(merged, min_name, o.mode, merged_hash);
                } else {
                    // Both changed differently and the content can't be
                    // line-merged (overlap / binary / mode mismatch / chunked)
                    // -> modify/modify conflict.
                    conflicts.push(Conflict {
                        path: join_path(prefix, min_name),
                        kind: ConflictKind::ModifyModify,
                        base_hash: Some(b.object_hash),
                        ours_hash: Some(o.object_hash),
                        theirs_hash: Some(t.object_hash),
                        ours_mode: Some(o.mode),
                        theirs_mode: Some(t.mode),
                    });
                    // Ours wins in the merged tree.
                    add_entry(merged, min_name, o.mode, o.object_hash);
                }
            }
            (false, true, false) => {
                let o = ours_entry.unwrap();
                add_entry(merged, min_name, o.mode, o.object_hash);
            }
            (false, false, true) => {
                let t = theirs_entry.unwrap();
                add_entry(merged, min_name, t.mode, t.object_hash);
            }
            (false, true, true) => {
                let o = ours_entry.unwrap();
                let t = theirs_entry.unwrap();
                if hash_and_mode_eq(o, t) {
                    add_entry(merged, min_name, o.mode, o.object_hash);
                } else if o.mode == EntryMode::Tree && t.mode == EntryMode::Tree {
                    recurse_subtree_merge(
                        store,
                        None,
                        Some(o.object_hash),
                        Some(t.object_hash),
                        min_name,
                        prefix,
                        merged,
                        conflicts,
                        depth,
                    )?;
                } else {
                    conflicts.push(Conflict {
                        path: join_path(prefix, min_name),
                        kind: ConflictKind::AddAdd,
                        base_hash: None,
                        ours_hash: Some(o.object_hash),
                        theirs_hash: Some(t.object_hash),
                        ours_mode: Some(o.mode),
                        theirs_mode: Some(t.mode),
                    });
                    add_entry(merged, min_name, o.mode, o.object_hash);
                }
            }
            (true, true, false) => {
                let b = base_entry.unwrap();
                let o = ours_entry.unwrap();
                if hash_and_mode_eq(b, o) {
                    // Ours unchanged, theirs deleted -> delete.
                } else {
                    conflicts.push(Conflict {
                        path: join_path(prefix, min_name),
                        kind: ConflictKind::DeleteModify,
                        base_hash: Some(b.object_hash),
                        ours_hash: Some(o.object_hash),
                        theirs_hash: None,
                        ours_mode: Some(o.mode),
                        theirs_mode: None,
                    });
                    add_entry(merged, min_name, o.mode, o.object_hash);
                }
            }
            (true, false, true) => {
                let b = base_entry.unwrap();
                let t = theirs_entry.unwrap();
                if hash_and_mode_eq(b, t) {
                    // Theirs unchanged, ours deleted -> delete.
                } else {
                    conflicts.push(Conflict {
                        path: join_path(prefix, min_name),
                        kind: ConflictKind::DeleteModify,
                        base_hash: Some(b.object_hash),
                        ours_hash: None,
                        theirs_hash: Some(t.object_hash),
                        ours_mode: None,
                        theirs_mode: Some(t.mode),
                    });
                    add_entry(merged, min_name, t.mode, t.object_hash);
                }
            }
            (true, false, false) => {
                // Both deleted -> delete.
            }
            (false, false, false) => {
                // unreachable — `min_of_three` returns None in this case
                // and we'd have broken out of the loop above.
                break;
            }
        }
    }
    Ok(())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
#[allow(clippy::many_single_char_names)] // single-letter commit names keep the test tables compact
mod tests {
    use super::*;
    use crate::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    fn store() -> (TempDir, ObjectStore) {
        let d = TempDir::new().unwrap();
        let s = ObjectStore::init(d.path()).unwrap();
        (d, s)
    }
    fn put_blob(s: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        s.write(&bytes).unwrap()
    }
    fn make_tree(s: &ObjectStore, entries: Vec<TreeEntry>) -> Hash {
        let bytes = serialize::serialize(&Object::Tree(Tree { entries })).unwrap();
        s.write(&bytes).unwrap()
    }
    fn entry(name: &[u8], mode: EntryMode, h: Hash) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode,
            object_hash: h,
        }
    }
    fn make_commit(s: &ObjectStore, tree: Hash, parents: &[Hash], message: &str) -> Hash {
        let c = Commit {
            tree_hash: tree,
            parents: parents.to_vec(),
            author: Identity::ed25519([0; 32]),
            signer: [0; 32],
            message: message.as_bytes().to_vec(),
            timestamp: message.len() as u64,
            message_hash: [0; 32],
            content_digest: [0; 32],
            signature: [0; 64],
        };
        let bytes = serialize::serialize(&Object::Commit(c)).unwrap();
        s.write(&bytes).unwrap()
    }
    fn tree_entries(s: &ObjectStore, h: Hash) -> Vec<TreeEntry> {
        match s.read_object(&h).unwrap() {
            Object::Tree(t) => t.entries,
            other => panic!("expected tree, got {other}"),
        }
    }
    fn find_entry<'a>(entries: &'a [TreeEntry], name: &[u8]) -> Option<&'a TreeEntry> {
        entries.iter().find(|e| e.name == name)
    }

    #[test]
    fn merge_identical_trees() {
        let (_d, s) = store();
        let blob_a = put_blob(&s, b"aaa");
        let tree = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, blob_a)]);
        let r = merge_trees(&s, Some(tree), Some(tree), Some(tree)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(r.tree_hash, tree);
    }

    #[test]
    fn merge_ours_adds_file() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let ours = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(ours), Some(base)).unwrap();
        assert!(!r.has_conflicts());
        let entries = tree_entries(&s, r.tree_hash);
        assert_eq!(entries.len(), 2);
        assert_eq!(find_entry(&entries, b"a.txt").unwrap().object_hash, a);
        assert_eq!(find_entry(&entries, b"b.txt").unwrap().object_hash, b);
    }

    #[test]
    fn merge_theirs_adds_file() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let c = put_blob(&s, b"ccc");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let theirs = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"c.txt", EntryMode::Blob, c),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(base), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        let entries = tree_entries(&s, r.tree_hash);
        assert_eq!(entries.len(), 2);
        assert_eq!(find_entry(&entries, b"c.txt").unwrap().object_hash, c);
    }

    #[test]
    fn merge_both_add_different_files() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let c = put_blob(&s, b"ccc");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let ours = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let theirs = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"c.txt", EntryMode::Blob, c),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 3);
    }

    #[test]
    fn merge_both_add_same_file_same_content() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let twin = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(twin), Some(twin)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(
            find_entry(&tree_entries(&s, r.tree_hash), b"b.txt")
                .unwrap()
                .object_hash,
            b
        );
    }

    #[test]
    fn merge_both_add_same_file_different_content() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b1 = put_blob(&s, b"bbb-ours");
        let b2 = put_blob(&s, b"bbb-theirs");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let ours = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b1),
            ],
        );
        let theirs = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b2),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts());
        assert_eq!(r.conflicts.len(), 1);
        let c = &r.conflicts[0];
        assert_eq!(c.path, "b.txt");
        assert_eq!(c.kind, ConflictKind::AddAdd);
        assert_eq!(c.base_hash, None);
        assert_eq!(c.ours_hash, Some(b1));
        assert_eq!(c.theirs_hash, Some(b2));
    }

    #[test]
    fn merge_ours_modifies() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"v1");
        let v2 = put_blob(&s, b"v2");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(base)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(
            find_entry(&tree_entries(&s, r.tree_hash), b"a.txt")
                .unwrap()
                .object_hash,
            v2
        );
    }

    #[test]
    fn merge_theirs_modifies() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"v1");
        let v2 = put_blob(&s, b"v2");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
        let theirs = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);
        let r = merge_trees(&s, Some(base), Some(base), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(
            find_entry(&tree_entries(&s, r.tree_hash), b"a.txt")
                .unwrap()
                .object_hash,
            v2
        );
    }

    #[test]
    fn merge_both_modify_same_way() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"v1");
        let v2 = put_blob(&s, b"v2");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
        let modified = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);
        let r = merge_trees(&s, Some(base), Some(modified), Some(modified)).unwrap();
        assert!(!r.has_conflicts());
    }

    #[test]
    fn merge_both_modify_differently() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"v1");
        let v2 = put_blob(&s, b"v2-ours");
        let v3 = put_blob(&s, b"v3-theirs");
        let base = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v1)]);
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v2)]);
        let theirs = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, v3)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts());
        let c = &r.conflicts[0];
        assert_eq!(c.path, "a.txt");
        assert_eq!(c.kind, ConflictKind::ModifyModify);
        assert_eq!(c.base_hash, Some(v1));
        assert_eq!(c.ours_hash, Some(v2));
        assert_eq!(c.theirs_hash, Some(v3));
    }

    #[test]
    fn merge_ours_deletes() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(base)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 1);
    }

    #[test]
    fn merge_theirs_deletes() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let theirs = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let r = merge_trees(&s, Some(base), Some(base), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 1);
    }

    #[test]
    fn merge_both_delete() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let base = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b),
            ],
        );
        let both = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let r = merge_trees(&s, Some(base), Some(both), Some(both)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 1);
    }

    #[test]
    fn merge_delete_vs_modify() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b1 = put_blob(&s, b"bbb-v1");
        let b2 = put_blob(&s, b"bbb-v2");
        let base = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b1),
            ],
        );
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let theirs = make_tree(
            &s,
            vec![
                entry(b"a.txt", EntryMode::Blob, a),
                entry(b"b.txt", EntryMode::Blob, b2),
            ],
        );
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts());
        let c = &r.conflicts[0];
        assert_eq!(c.path, "b.txt");
        assert_eq!(c.kind, ConflictKind::DeleteModify);
        assert_eq!(c.base_hash, Some(b1));
        assert_eq!(c.ours_hash, None);
        assert_eq!(c.theirs_hash, Some(b2));
    }

    #[test]
    fn merge_nested_tree_changes() {
        let (_d, s) = store();
        let main_v1 = put_blob(&s, b"fn main() {}");
        let main_v2 = put_blob(&s, b"fn main() { run(); }");
        let util = put_blob(&s, b"fn util() {}");
        let base_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, main_v1)]);
        let base = make_tree(&s, vec![entry(b"src", EntryMode::Tree, base_sub)]);
        let ours_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, main_v2)]);
        let ours = make_tree(&s, vec![entry(b"src", EntryMode::Tree, ours_sub)]);
        let theirs_sub = make_tree(
            &s,
            vec![
                entry(b"main.rs", EntryMode::Blob, main_v1),
                entry(b"util.rs", EntryMode::Blob, util),
            ],
        );
        let theirs = make_tree(&s, vec![entry(b"src", EntryMode::Tree, theirs_sub)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        let root = tree_entries(&s, r.tree_hash);
        assert_eq!(root.len(), 1);
        let src = tree_entries(&s, root[0].object_hash);
        assert_eq!(src.len(), 2);
        assert_eq!(find_entry(&src, b"main.rs").unwrap().object_hash, main_v2);
        assert_eq!(find_entry(&src, b"util.rs").unwrap().object_hash, util);
    }

    #[test]
    fn merge_nested_conflict_path_is_full() {
        let (_d, s) = store();
        let v1 = put_blob(&s, b"original");
        let v2 = put_blob(&s, b"ours-change");
        let v3 = put_blob(&s, b"theirs-change");
        let base_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, v1)]);
        let base = make_tree(&s, vec![entry(b"src", EntryMode::Tree, base_sub)]);
        let ours_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, v2)]);
        let ours = make_tree(&s, vec![entry(b"src", EntryMode::Tree, ours_sub)]);
        let theirs_sub = make_tree(&s, vec![entry(b"main.rs", EntryMode::Blob, v3)]);
        let theirs = make_tree(&s, vec![entry(b"src", EntryMode::Tree, theirs_sub)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts());
        assert_eq!(r.conflicts[0].path, "src/main.rs");
        assert_eq!(r.conflicts[0].kind, ConflictKind::ModifyModify);
        assert_eq!(r.conflicts[0].base_hash, Some(v1));
        assert_eq!(r.conflicts[0].ours_hash, Some(v2));
        assert_eq!(r.conflicts[0].theirs_hash, Some(v3));
    }

    #[test]
    fn merge_empty_base() {
        let (_d, s) = store();
        let a = put_blob(&s, b"aaa");
        let b = put_blob(&s, b"bbb");
        let ours = make_tree(&s, vec![entry(b"a.txt", EntryMode::Blob, a)]);
        let theirs = make_tree(&s, vec![entry(b"b.txt", EntryMode::Blob, b)]);
        let r = merge_trees(&s, None, Some(ours), Some(theirs)).unwrap();
        assert!(!r.has_conflicts());
        assert_eq!(tree_entries(&s, r.tree_hash).len(), 2);
    }

    // ---- find_merge_base ----

    #[test]
    fn find_merge_base_linear() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let a = make_commit(&s, empty, &[], "A");
        let b = make_commit(&s, empty, &[a], "B");
        let c = make_commit(&s, empty, &[b], "C");
        let d = make_commit(&s, empty, &[b], "D");
        assert_eq!(find_merge_base(&s, c, d).unwrap(), Some(b));
    }

    #[test]
    fn find_merge_base_root() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let a = make_commit(&s, empty, &[], "A");
        let b = make_commit(&s, empty, &[a], "B");
        let c = make_commit(&s, empty, &[a], "C");
        assert_eq!(find_merge_base(&s, b, c).unwrap(), Some(a));
    }

    #[test]
    fn find_merge_base_no_common_ancestor() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let x = make_commit(&s, empty, &[], "X");
        let y = make_commit(&s, empty, &[], "Y");
        assert_eq!(find_merge_base(&s, x, y).unwrap(), None);
    }

    #[test]
    fn find_merge_base_same_commit() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let a = make_commit(&s, empty, &[], "A");
        assert_eq!(find_merge_base(&s, a, a).unwrap(), Some(a));
    }

    #[test]
    fn find_merge_base_walks_non_first_parents() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let root = make_commit(&s, empty, &[], "root");
        let left = make_commit(&s, empty, &[root], "left");
        let right = make_commit(&s, empty, &[root], "right");
        let m = make_commit(&s, empty, &[left, right], "merge");
        let tip = make_commit(&s, empty, &[m], "tip");
        assert_eq!(find_merge_base(&s, tip, right).unwrap(), Some(right));
    }

    #[test]
    fn is_ancestor_walks_merge_parents() {
        let (_d, s) = store();
        let empty = make_tree(&s, vec![]);
        let root = make_commit(&s, empty, &[], "root");
        let left = make_commit(&s, empty, &[root], "left");
        let right = make_commit(&s, empty, &[root], "right");
        let m = make_commit(&s, empty, &[left, right], "merge");

        assert!(is_ancestor(&s, root, m).unwrap());
        assert!(is_ancestor(&s, right, m).unwrap());
        assert!(!is_ancestor(&s, m, right).unwrap());
    }

    #[test]
    fn merge_both_modify_disjoint_lines_auto_merges() {
        let (_d, s) = store();
        let base_b = put_blob(&s, b"a\nb\nc\nd\ne\n");
        let ours_b = put_blob(&s, b"A\nb\nc\nd\ne\n"); // line 1
        let theirs_b = put_blob(&s, b"a\nb\nc\nd\nE\n"); // line 5
        let base = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, base_b)]);
        let ours = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, ours_b)]);
        let theirs = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, theirs_b)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(
            !r.has_conflicts(),
            "disjoint line edits should auto-merge (#298), got {:?}",
            r.conflicts
        );
        let f = find_entry(&tree_entries(&s, r.tree_hash), b"f.txt")
            .unwrap()
            .object_hash;
        let merged = match s.read_object(&f).unwrap() {
            Object::Blob(b) => b.data,
            other => panic!("merged f.txt not a blob: {other:?}"),
        };
        assert_eq!(merged, b"A\nb\nc\nd\nE\n");
    }

    #[test]
    fn merge_both_modify_same_line_still_conflicts() {
        let (_d, s) = store();
        let base_b = put_blob(&s, b"a\nb\nc\n");
        let ours_b = put_blob(&s, b"a\nOURS\nc\n"); // line 2
        let theirs_b = put_blob(&s, b"a\nTHEIRS\nc\n"); // line 2 — overlaps
        let base = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, base_b)]);
        let ours = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, ours_b)]);
        let theirs = make_tree(&s, vec![entry(b"f.txt", EntryMode::Blob, theirs_b)]);
        let r = merge_trees(&s, Some(base), Some(ours), Some(theirs)).unwrap();
        assert!(r.has_conflicts(), "same-line edits must still conflict");
        assert_eq!(r.conflicts[0].kind, ConflictKind::ModifyModify);
    }
}
