//! GC retention roots — the complete set of object hashes that
//! `mkit gc` (#233) must treat as live, plus the live-object closure
//! over them.
//!
//! Pruning is only safe if the root set is **complete**: anything gc can
//! reach from a root is kept; everything else is reclaimable. Missing a
//! root means deleting a live object, so this collector is deliberately
//! exhaustive and **fails closed** — if any source can't be read, the
//! whole collection errors and the caller must abort rather than prune
//! against an under-counted root set.
//!
//! Roots, by source:
//! - **HEAD** (incl. detached) and every `refs/heads`, `refs/tags`, and
//!   `refs/remotes/<remote>` ref.
//! - **Stash** entries — each stashed commit and its recorded parent.
//! - **In-progress operations** — merge (`MERGE_HEAD`), cherry-pick
//!   (`CHERRY_PICK_HEAD`), rebase (`onto` + every `todo`/`done` commit),
//!   the `ORIG_HEAD` saved by those ops and by `reset`, and the conflict
//!   sidecar's base/ours/theirs blob hashes.
//! - **Attestations** — every `attestations/<commit>/` directory pins
//!   its commit so an attested commit is never orphaned.
//!
//! NOTE ON RECOVERY (#260): the per-branch history journal stores only
//! opaque MMR digests, so commits superseded by `commit --amend`,
//! `reset`, or `rebase` are **not** recoverable from it and are **not**
//! roots here. Reclaiming them safely needs a dedicated recovery log +
//! retention/grace policy — the follow-up half of #260, tracked
//! separately. This module is the reachability foundation only.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use crate::hash::{self, Hash};
use crate::store::{ObjectStore, StoreError};

use super::conflict_state::{self, ORIG_HEAD};
use super::graph::reachable_closure;
use super::rebase;
use super::stash;
use crate::refs::{self, REMOTES_DIR};

/// Directory under `.mkit/` holding per-commit attestation envelopes.
/// Owned here (not in `mkit-attest`) so the core collector stays free of
/// a reverse crate dependency — it only reads directory *names*.
const ATTESTATIONS_DIR: &str = "attestations";

/// Errors from collecting the retention root set. Every underlying
/// source error is wrapped so the collector can fail closed.
#[derive(Debug, thiserror::Error)]
pub enum GcRootsError {
    #[error("refs: {0}")]
    Refs(#[from] refs::RefError),
    #[error("stash: {0}")]
    Stash(#[from] stash::StashError),
    #[error("conflict state: {0}")]
    ConflictState(#[from] conflict_state::ConflictStateError),
    #[error("rebase state: {0}")]
    Rebase(#[from] rebase::RebaseError),
    #[error("object store: {0}")]
    Store(#[from] StoreError),
    #[error("malformed object id on disk: {0}")]
    BadHash(#[from] hash::FromHexError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// Collect the complete set of GC retention roots for the repo at
/// `mkit_dir` (the `.mkit` directory). The returned hashes are roots,
/// not the closure — feed them to [`reachable_closure`] (or use
/// [`live_objects`]) to get the full keep-set.
///
/// The all-zero hash is filtered out (an unset ref / `ORIG_HEAD`).
///
/// # Errors
///
/// [`GcRootsError`] if any source (refs, stash, op state, attestation
/// dir) cannot be read — the caller must then abort, never prune.
pub fn collect_roots(mkit_dir: &Path) -> Result<BTreeSet<Hash>, GcRootsError> {
    let mut roots: BTreeSet<Hash> = BTreeSet::new();
    let add = |h: Hash, set: &mut BTreeSet<Hash>| {
        if h != hash::ZERO {
            set.insert(h);
        }
    };

    // HEAD (covers a detached HEAD not present under refs/heads).
    if let Some(h) = refs::resolve_head(mkit_dir)? {
        add(h, &mut roots);
    }

    // Branches + tags.
    for r in refs::list_refs(mkit_dir)? {
        if let Some(h) = r.hash {
            add(h, &mut roots);
        }
    }
    for r in refs::list_tags(mkit_dir)? {
        if let Some(h) = r.hash {
            add(h, &mut roots);
        }
    }

    // Remote-tracking refs, across every remote namespace on disk.
    for remote in list_remote_names(mkit_dir)? {
        for r in refs::list_remote_refs(mkit_dir, &remote)? {
            if let Some(h) = r.hash {
                add(h, &mut roots);
            }
        }
    }

    // Stash: each stashed commit and the HEAD it was based on.
    let repo_root = mkit_dir.parent().unwrap_or(mkit_dir);
    for entry in stash::list(repo_root)?.entries {
        add(entry.commit_hash, &mut roots);
        add(entry.parent_hash, &mut roots);
    }

    // ORIG_HEAD (written by reset and by the in-progress ops below).
    if let Some(h) = read_optional_hash(&mkit_dir.join(ORIG_HEAD))? {
        add(h, &mut roots);
    }

    // In-progress merge / cherry-pick.
    if let Some(m) = conflict_state::read_merge_state(mkit_dir)? {
        add(m.merge_head, &mut roots);
        add(m.orig_head, &mut roots);
    }
    if let Some(c) = conflict_state::read_cherry_pick_state(mkit_dir)? {
        add(c.cherry_pick_head, &mut roots);
        add(c.orig_head, &mut roots);
    }

    // In-progress rebase: target + every commit still to replay or
    // already replayed onto the new base.
    if rebase::is_rebase_in_progress(mkit_dir) {
        let st = rebase::read_state(mkit_dir)?;
        add(st.orig_head, &mut roots);
        add(st.onto, &mut roots);
        for h in st.todo.into_iter().chain(st.done) {
            add(h, &mut roots);
        }
    }

    // Conflict sidecar: base/ours/theirs blobs needed to resolve an
    // in-progress conflict (empty when no conflict is recorded).
    for c in conflict_state::read_conflicts(mkit_dir)? {
        for h in [c.base_hash, c.ours_hash, c.theirs_hash]
            .into_iter()
            .flatten()
        {
            add(h, &mut roots);
        }
    }

    // Attested commits — pinned so an attestation never dangles.
    for h in attested_commits(mkit_dir)? {
        add(h, &mut roots);
    }

    Ok(roots)
}

/// The full live-object keep-set for `mkit gc`: the reachable closure
/// over every retention root from [`collect_roots`].
///
/// # Errors
///
/// [`GcRootsError`] if roots cannot be collected, or a [`StoreError`]
/// (e.g. a root or referenced object missing) during the walk.
pub fn live_objects(store: &ObjectStore, mkit_dir: &Path) -> Result<BTreeSet<Hash>, GcRootsError> {
    let roots = collect_roots(mkit_dir)?;
    Ok(reachable_closure(store, roots.iter())?)
}

/// Names of every remote namespace under `refs/remotes/`. Empty (not an
/// error) when the directory is absent.
fn list_remote_names(mkit_dir: &Path) -> Result<Vec<String>, io::Error> {
    let dir = mkit_dir.join(REMOTES_DIR);
    let mut names = Vec::new();
    let rd = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(names),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && let Some(name) = entry.file_name().to_str()
        {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// Commit hashes that have at least one attestation envelope, taken from
/// the `attestations/<commit-hex>/` directory names. Non-hex directory
/// names are ignored (defensive); a missing dir yields an empty set.
fn attested_commits(mkit_dir: &Path) -> Result<Vec<Hash>, io::Error> {
    let dir = mkit_dir.join(ATTESTATIONS_DIR);
    let mut out = Vec::new();
    let rd = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some(name) = entry.file_name().to_str()
            && let Ok(h) = hash::from_hex(name)
        {
            out.push(h);
        }
    }
    Ok(out)
}

/// Read a single 64-hex object id from `path`, trimming trailing
/// whitespace. `Ok(None)` if the file is absent.
fn read_optional_hash(path: &Path) -> Result<Option<Hash>, GcRootsError> {
    let raw = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(hash::from_hex(trimmed)?))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::EntryMode;
    use crate::object::{Blob, Commit, Identity, Object, Tree, TreeEntry};
    use crate::serialize;
    use std::fs;
    use tempfile::TempDir;

    /// A repo with an initialized `.mkit` dir + object store.
    fn repo() -> (TempDir, ObjectStore) {
        let d = TempDir::new().unwrap();
        let store = ObjectStore::init(d.path()).unwrap();
        refs::init(&d.path().join(crate::MKIT_DIR)).unwrap();
        (d, store)
    }

    fn mkit_dir(d: &TempDir) -> std::path::PathBuf {
        d.path().join(crate::MKIT_DIR)
    }

    /// Write a loose ref file (e.g. `refs/heads/main`) — the on-disk
    /// form `list_refs`/`list_tags` read.
    fn write_ref(md: &Path, rel: &str, h: &Hash) {
        let path = md.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{}\n", hash::to_hex(h))).unwrap();
    }

    fn write_blob(s: &ObjectStore, data: &[u8]) -> Hash {
        s.write(
            &serialize::serialize(&Object::Blob(Blob {
                data: data.to_vec(),
            }))
            .unwrap(),
        )
        .unwrap()
    }

    /// Commit a single-file tree; returns `(commit, blob)` hashes.
    fn commit_one(s: &ObjectStore, name: &[u8], data: &[u8], parents: Vec<Hash>) -> (Hash, Hash) {
        let blob = write_blob(s, data);
        let tree = s
            .write(
                &serialize::serialize(&Object::Tree(Tree {
                    entries: vec![TreeEntry {
                        name: name.to_vec(),
                        mode: EntryMode::Blob,
                        object_hash: blob,
                    }],
                }))
                .unwrap(),
            )
            .unwrap();
        let commit = s
            .write(
                &serialize::serialize(&Object::Commit(Commit {
                    tree_hash: tree,
                    parents,
                    author: Identity::opaque(b"t".to_vec()),
                    signer: [0u8; 32],
                    message: name.to_vec(),
                    // Per-commit divergence so distinct fixtures don't dedup.
                    timestamp: name.len() as u64,
                    message_hash: [0u8; 32],
                    content_digest: [0u8; 32],
                    signature: [0u8; 64],
                }))
                .unwrap(),
            )
            .unwrap();
        (commit, blob)
    }

    #[test]
    fn collect_roots_includes_branches_and_tags() {
        let (d, s) = repo();
        let md = mkit_dir(&d);
        let (c1, _) = commit_one(&s, b"a", b"a", vec![]);
        let (c2, _) = commit_one(&s, b"b", b"b", vec![]);
        write_ref(&md, "refs/heads/main", &c1);
        write_ref(&md, "refs/tags/v1", &c2);

        let roots = collect_roots(&md).unwrap();
        assert!(roots.contains(&c1), "branch tip must be a root");
        assert!(roots.contains(&c2), "tag target must be a root");
    }

    #[test]
    fn collect_roots_includes_orig_head_and_attested_commit() {
        let (d, s) = repo();
        let md = mkit_dir(&d);
        let (orig, _) = commit_one(&s, b"o", b"o", vec![]);
        let (att, _) = commit_one(&s, b"x", b"x", vec![]);
        fs::write(md.join(ORIG_HEAD), format!("{}\n", hash::to_hex(&orig))).unwrap();
        fs::create_dir_all(md.join(ATTESTATIONS_DIR).join(hash::to_hex(&att))).unwrap();

        let roots = collect_roots(&md).unwrap();
        assert!(roots.contains(&orig), "ORIG_HEAD must be a root");
        assert!(roots.contains(&att), "attested commit must be a root");
    }

    #[test]
    fn live_objects_keeps_only_reachable_closure() {
        let (d, s) = repo();
        let md = mkit_dir(&d);
        let (kept, kept_blob) = commit_one(&s, b"keep", b"keep", vec![]);
        // An unreferenced commit + blob: reachable from no root.
        let (orphan, orphan_blob) = commit_one(&s, b"orphan", b"orphan", vec![]);
        write_ref(&md, "refs/heads/main", &kept);

        let live = live_objects(&s, &md).unwrap();
        assert!(
            live.contains(&kept) && live.contains(&kept_blob),
            "kept closure live"
        );
        assert!(
            !live.contains(&orphan) && !live.contains(&orphan_blob),
            "unreferenced objects must not be live"
        );
    }

    #[test]
    fn reachable_closure_is_union_of_single_root_closures() {
        let (_d, s) = repo();
        let (c1, b1) = commit_one(&s, b"a", b"a", vec![]);
        let (c2, b2) = commit_one(&s, b"b", b"b", vec![]);
        let multi = reachable_closure(&s, [&c1, &c2]).unwrap();
        let single1 = super::super::graph::reachable_objects(&s, &c1).unwrap();
        let single2 = super::super::graph::reachable_objects(&s, &c2).unwrap();
        let union: BTreeSet<Hash> = single1.union(&single2).copied().collect();
        assert_eq!(multi, union);
        assert!([c1, b1, c2, b2].iter().all(|h| multi.contains(h)));
    }
}
