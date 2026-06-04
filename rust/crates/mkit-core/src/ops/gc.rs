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
//! - **Recovery log** — every commit recorded as superseded by a
//!   history-rewriting op (see [`super::recovery`]); retained so it stays
//!   recoverable until `recovery::expire` drops it past the window.
//!
//! RECOVERY (#260): commits superseded by `commit --amend`, `reset`, or
//! `rebase` are unrecoverable from the opaque-digest history journal, so
//! [`super::recovery`] logs them (the commands record the old tip before
//! moving the ref) and they are roots here.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use crate::hash::{self, Hash};
use crate::store::{ObjectStore, StoreError};

use super::conflict_state::{self, ORIG_HEAD};
use super::graph::reachable_closure_checked;
use super::rebase::{self, REBASE_DIR};
use super::recovery;
use super::stash;
use crate::refs::{self, HEADS_DIR, REMOTES_DIR, TAGS_DIR};

/// Directory under `.mkit/` holding per-commit attestation envelopes.
/// Owned here (not in `mkit-attest`) so the core collector stays free of
/// a reverse crate dependency — it only reads directory *names*.
const ATTESTATIONS_DIR: &str = "attestations";

/// Depth cap for the strict ref walk. Refs nest by `/` in the name;
/// anything deeper than this on disk is treated as an error (fail
/// closed) rather than silently truncated.
const MAX_REF_WALK_DEPTH: usize = 64;

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
    #[error("recovery log: {0}")]
    Recovery(#[from] recovery::RecoveryError),
    #[error("object store: {0}")]
    Store(#[from] StoreError),
    #[error("malformed object id on disk: {0}")]
    BadHash(#[from] hash::FromHexError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// The reachable-object walk hit [`super::graph::MAX_REACHABLE`]
    /// before completing. The live set is incomplete, so a caller must
    /// abort rather than treat beyond-cap objects as prunable.
    #[error("object graph exceeds the reachability cap; refusing to compute a partial keep-set")]
    Truncated,
    /// A ref directory nested deeper than [`MAX_REF_WALK_DEPTH`].
    #[error("ref tree too deep at {0} (fail closed)")]
    RefTooDeep(String),
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

    // Branches, tags, and remote-tracking refs. We deliberately do NOT
    // use `refs::list_refs`/`list_tags`/`list_remote_refs` here: those
    // are lenient (they yield `hash: None` for malformed content, skip
    // unreadable files, and silently stop at a depth cap), which would
    // let a corrupt ref drop out of the root set while collection still
    // "succeeds" — exactly the fail-open hole gc cannot tolerate. The
    // strict walk below errors on any unreadable / undecodable / too-deep
    // ref instead.
    for ns in [HEADS_DIR, TAGS_DIR, REMOTES_DIR] {
        walk_ref_roots_strict(&mkit_dir.join(ns), ns, 0, &mut roots)?;
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
    // in-progress conflict. Merge/cherry-pick write `.mkit/mkit-conflicts`;
    // rebase writes its sidecar inside `.mkit/rebase-apply/`. Both are
    // empty/absent when no conflict is recorded.
    for dir in [mkit_dir.to_path_buf(), mkit_dir.join(REBASE_DIR)] {
        for c in conflict_state::read_conflicts(&dir)? {
            for h in [c.base_hash, c.ours_hash, c.theirs_hash]
                .into_iter()
                .flatten()
            {
                add(h, &mut roots);
            }
        }
    }

    // Attested commits — pinned so an attestation never dangles.
    for h in attested_commits(mkit_dir)? {
        add(h, &mut roots);
    }

    // Recovery log — commits superseded by amend/reset/rebase, retained
    // so they stay recoverable. Clock-free here: `recovery::expire` (a
    // gc maintenance step) drops entries past the retention window so
    // they stop pinning objects.
    for h in recovery::roots(mkit_dir)? {
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
    let (live, truncated) = reachable_closure_checked(store, roots.iter())?;
    if truncated {
        return Err(GcRootsError::Truncated);
    }
    Ok(live)
}

/// Strict, fail-closed walk of a ref namespace directory (e.g.
/// `refs/heads`), inserting every ref's target hash into `roots`.
///
/// Unlike `refs::list_refs`, this errors instead of skipping on:
/// unreadable files ([`io::Error`]), undecodable content
/// ([`hash::FromHexError`]), and excessive nesting
/// ([`GcRootsError::RefTooDeep`]). Dot-files are skipped (lock/temp
/// cruft), and an absent namespace dir yields no roots. The all-zero
/// hash (an unset ref) is excluded.
fn walk_ref_roots_strict(
    dir: &Path,
    rel: &str,
    depth: usize,
    roots: &mut BTreeSet<Hash>,
) -> Result<(), GcRootsError> {
    if depth > MAX_REF_WALK_DEPTH {
        return Err(GcRootsError::RefTooDeep(rel.to_owned()));
    }
    let rd = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for entry in rd {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_ref_roots_strict(&entry.path(), &format!("{rel}/{name}"), depth + 1, roots)?;
            continue;
        }
        if !ft.is_file() || name.starts_with('.') {
            // Skip non-files and lock/temp cruft (e.g. `*.lock`, dotfiles).
            continue;
        }
        // Strict: read + decode, erroring (fail closed) on any failure.
        let raw = fs::read_to_string(entry.path())?;
        let h = hash::from_hex(raw.trim())?;
        if h != hash::ZERO {
            roots.insert(h);
        }
    }
    Ok(())
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
        let multi = super::super::graph::reachable_closure(&s, [&c1, &c2]).unwrap();
        let single1 = super::super::graph::reachable_objects(&s, &c1).unwrap();
        let single2 = super::super::graph::reachable_objects(&s, &c2).unwrap();
        let union: BTreeSet<Hash> = single1.union(&single2).copied().collect();
        assert_eq!(multi, union);
        assert!([c1, b1, c2, b2].iter().all(|h| multi.contains(h)));
    }

    #[test]
    fn strict_walk_picks_up_nested_remote_ref() {
        let (d, s) = repo();
        let md = mkit_dir(&d);
        let (c, _) = commit_one(&s, b"r", b"r", vec![]);
        write_ref(&md, "refs/remotes/origin/main", &c);
        assert!(
            collect_roots(&md).unwrap().contains(&c),
            "nested remote-tracking ref must be a root"
        );
    }

    #[test]
    fn collect_roots_includes_recovery_log_entries() {
        let (d, s) = repo();
        let md = mkit_dir(&d);
        let (superseded, _) = commit_one(&s, b"old", b"old", vec![]);
        super::super::recovery::record(
            &md,
            &super::super::recovery::RecoveryEntry {
                timestamp: 1,
                op: "amend".into(),
                superseded,
                branch: "main".into(),
            },
        )
        .unwrap();
        assert!(
            collect_roots(&md).unwrap().contains(&superseded),
            "a superseded commit in the recovery log must be a root"
        );
    }

    #[test]
    fn collect_roots_fails_closed_on_malformed_ref() {
        let (d, _s) = repo();
        let md = mkit_dir(&d);
        // A corrupt ref file (not 64-hex) must error, never be silently
        // dropped — else gc could prune the object it should pin.
        let bad = md.join("refs/heads/corrupt");
        fs::create_dir_all(bad.parent().unwrap()).unwrap();
        fs::write(&bad, b"not-a-valid-object-id\n").unwrap();
        assert!(
            matches!(collect_roots(&md), Err(GcRootsError::BadHash(_))),
            "malformed ref must fail closed"
        );
    }

    #[test]
    fn strict_walk_skips_lock_and_dotfile_cruft() {
        let (d, s) = repo();
        let md = mkit_dir(&d);
        let (c, _) = commit_one(&s, b"m", b"m", vec![]);
        write_ref(&md, "refs/heads/main", &c);
        // Atomic-write temp files are dotfiles; a stale one must not
        // break collection.
        fs::write(md.join("refs/heads").join(".main.tmp.123.4"), b"garbage").unwrap();
        let roots = collect_roots(&md).unwrap();
        assert!(roots.contains(&c), "real ref still collected past cruft");
    }
}
