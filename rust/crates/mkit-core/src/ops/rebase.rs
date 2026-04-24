//! Rebase state machine.
//!
//! Persists rebase state under `.mkit/rebase-apply/` as five files:
//!
//! - `head-name`  : symbolic name of the branch being rebased
//! - `orig-head`  : 64-hex BLAKE3 of the tip before rebase started
//! - `onto`       : 64-hex BLAKE3 of the rebase target
//! - `todo`       : newline-separated list of remaining commits
//! - `done`       : newline-separated list of replayed commits
//!
//! Trailing newlines are tolerated on read and always written.
//!
//! [`collect_commits_to_replay`] walks the first-parent chain from
//! the rebase head until it hits `onto` or any ancestor of `onto`.
//! It returns commits in oldest-first order. To avoid pulling in the
//! sibling-track `graph` module, the ancestor walk is inlined here
//! as a private helper that mirrors `src/graph.zig::collectAncestorSet`
//! (DFS, capped at `10_000` commits).

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::{self, HEX_LEN, Hash};
use crate::object::Object;
use crate::store::ObjectStore;

/// Directory under `.mkit/` that holds the persisted rebase state.
pub const REBASE_DIR: &str = "rebase-apply";

const HEAD_NAME_FILE: &str = "head-name";
const ORIG_HEAD_FILE: &str = "orig-head";
const ONTO_FILE: &str = "onto";
const TODO_FILE: &str = "todo";
const DONE_FILE: &str = "done";

const MAX_HEAD_NAME_BYTES: u64 = 4096;
const MAX_HASH_FILE_BYTES: u64 = 128;
const MAX_HASH_LIST_BYTES: u64 = 1024 * 1024;

/// Maximum commits walked by [`collect_commits_to_replay`] before bail-out.
/// Mirrors the Zig safety cap.
const MAX_REPLAY_DEPTH: usize = 10_000;

/// Maximum commits visited by the inlined ancestor walk.
const MAX_ANCESTORS: usize = 10_000;

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
pub enum RebaseError {
    /// `read_state` was called but `.mkit/rebase-apply/` does not exist.
    #[error("no rebase in progress")]
    NoRebaseInProgress,
    /// On-disk state is malformed (bad hex, missing file, etc.).
    #[error("rebase state on disk is malformed")]
    InvalidRebaseState,
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Object decode failure during the walk.
    #[error(transparent)]
    Object(#[from] crate::object::MkitError),
    /// Object-store failure during the walk.
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}

/// Result alias.
pub type RebaseResult<T> = Result<T, RebaseError>;

/// Persisted rebase state. Mirrors `src/rebase.zig::RebaseState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseState {
    /// Name of the branch being rebased (e.g. `main`, `feature/x`).
    pub head_name: String,
    /// Tip of `head_name` before rebase started.
    pub orig_head: Hash,
    /// The commit being rebased onto.
    pub onto: Hash,
    /// Remaining commits to replay (oldest-first).
    pub todo: Vec<Hash>,
    /// Commits already replayed.
    pub done: Vec<Hash>,
}

/// Returns `true` when `<mkit_dir>/rebase-apply/` exists.
#[must_use]
pub fn is_rebase_in_progress(mkit_dir: &Path) -> bool {
    mkit_dir.join(REBASE_DIR).is_dir()
}

/// Read rebase state from `<mkit_dir>/rebase-apply/`.
///
/// # Errors
/// - [`RebaseError::NoRebaseInProgress`] if the directory does not exist.
/// - [`RebaseError::InvalidRebaseState`] if any file is malformed.
pub fn read_state(mkit_dir: &Path) -> RebaseResult<RebaseState> {
    let dir = mkit_dir.join(REBASE_DIR);
    if !dir.is_dir() {
        return Err(RebaseError::NoRebaseInProgress);
    }

    let head_name = read_text_capped(&dir.join(HEAD_NAME_FILE), MAX_HEAD_NAME_BYTES)
        .map_err(|_| RebaseError::InvalidRebaseState)?;
    let head_name = trim_trailing(&head_name).to_string();

    let orig_head = read_hex_hash(&dir.join(ORIG_HEAD_FILE))?;
    let onto = read_hex_hash(&dir.join(ONTO_FILE))?;

    let todo = read_hash_list(&dir.join(TODO_FILE))?;
    let done = read_hash_list(&dir.join(DONE_FILE))?;

    Ok(RebaseState {
        head_name,
        orig_head,
        onto,
        todo,
        done,
    })
}

/// Persist `state` to `<mkit_dir>/rebase-apply/`.
///
/// # Errors
/// - [`RebaseError::Io`] for filesystem failures.
pub fn write_state(mkit_dir: &Path, state: &RebaseState) -> RebaseResult<()> {
    let dir = mkit_dir.join(REBASE_DIR);
    fs::create_dir_all(&dir)?;

    write_with_newline(&dir.join(HEAD_NAME_FILE), state.head_name.as_bytes())?;
    write_with_newline(
        &dir.join(ORIG_HEAD_FILE),
        hash::to_hex(&state.orig_head).as_bytes(),
    )?;
    write_with_newline(&dir.join(ONTO_FILE), hash::to_hex(&state.onto).as_bytes())?;
    write_hash_list(&dir.join(TODO_FILE), &state.todo)?;
    write_hash_list(&dir.join(DONE_FILE), &state.done)?;
    Ok(())
}

/// Remove `<mkit_dir>/rebase-apply/`. Idempotent.
///
/// # Errors
/// - [`RebaseError::Io`] for filesystem failures other than "not found".
pub fn cleanup_rebase(mkit_dir: &Path) -> RebaseResult<()> {
    let dir = mkit_dir.join(REBASE_DIR);
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(RebaseError::Io(e)),
    }
}

/// Walk first-parent chain from `head_hash` back, stopping when we reach
/// `onto_hash` or any ancestor of it. Returns commits in oldest-first
/// order (ready for replay). Caps the walk at [`MAX_REPLAY_DEPTH`].
///
/// # Errors
/// - [`RebaseError::Store`] / [`RebaseError::Object`] for store failures.
pub fn collect_commits_to_replay(
    store: &ObjectStore,
    head_hash: Hash,
    onto_hash: Hash,
) -> RebaseResult<Vec<Hash>> {
    if head_hash == onto_hash {
        return Ok(Vec::new());
    }

    let mut onto_ancestors: HashSet<Hash> = HashSet::new();
    collect_ancestor_set(store, onto_hash, &mut onto_ancestors);

    let mut commits: Vec<Hash> = Vec::new();
    let mut current = head_hash;
    let mut depth = 0usize;

    while depth < MAX_REPLAY_DEPTH {
        if current == onto_hash || onto_ancestors.contains(&current) {
            break;
        }
        commits.push(current);

        let Ok(obj) = store.read_object(&current) else {
            break;
        };
        let Object::Commit(commit) = obj else { break };
        if commit.parents.is_empty() {
            break;
        }
        current = commit.parents[0];
        depth += 1;
    }

    commits.reverse();
    Ok(commits)
}

// -- Internal helpers --------------------------------------------------------

/// Inlined port of `src/graph.zig::collectAncestorSet`. Kept private so
/// the sibling-track `graph` module owns the public surface.
fn collect_ancestor_set(store: &ObjectStore, start: Hash, set: &mut HashSet<Hash>) {
    let mut stack: Vec<Hash> = vec![start];
    let mut count = 0usize;
    while let Some(current) = stack.pop() {
        if count >= MAX_ANCESTORS {
            break;
        }
        if !set.insert(current) {
            continue;
        }
        count += 1;
        let Ok(obj) = store.read_object(&current) else {
            continue;
        };
        if let Object::Commit(commit) = obj {
            for p in commit.parents {
                stack.push(p);
            }
        }
    }
}

fn read_hex_hash(path: &Path) -> RebaseResult<Hash> {
    let raw =
        read_text_capped(path, MAX_HASH_FILE_BYTES).map_err(|_| RebaseError::InvalidRebaseState)?;
    let trimmed = trim_trailing(&raw);
    hash::from_hex(trimmed).map_err(|_| RebaseError::InvalidRebaseState)
}

fn read_hash_list(path: &Path) -> RebaseResult<Vec<Hash>> {
    let raw = match read_text_capped(path, MAX_HASH_LIST_BYTES) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(RebaseError::Io(e)),
    };
    let trimmed = trim_trailing(&raw);
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for line in trimmed.split('\n') {
        let line = line.trim_end_matches(['\r', ' ']);
        if line.is_empty() {
            continue;
        }
        if line.len() != HEX_LEN {
            return Err(RebaseError::InvalidRebaseState);
        }
        let h = hash::from_hex(line).map_err(|_| RebaseError::InvalidRebaseState)?;
        out.push(h);
    }
    Ok(out)
}

fn write_hash_list(path: &Path, hashes: &[Hash]) -> RebaseResult<()> {
    if hashes.is_empty() {
        write_with_newline(path, b"")?;
        return Ok(());
    }
    let mut buf = String::with_capacity(hashes.len() * (HEX_LEN + 1));
    for h in hashes {
        buf.push_str(&hash::to_hex(h));
        buf.push('\n');
    }
    fs::write(path, buf.as_bytes())?;
    Ok(())
}

fn write_with_newline(path: &Path, content: &[u8]) -> io::Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(content.len() + 1);
    buf.extend_from_slice(content);
    if buf.last().copied() != Some(b'\n') {
        buf.push(b'\n');
    }
    fs::write(path, buf)
}

fn read_text_capped(path: &Path, cap: u64) -> io::Result<String> {
    let meta = fs::metadata(path)?;
    if meta.len() > cap {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    let raw = fs::read(path)?;
    String::from_utf8(raw).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8"))
}

fn trim_trailing(s: &str) -> &str {
    s.trim_end_matches(['\n', '\r', ' '])
}

/// Convenience: full path to the rebase-apply directory under `mkit_dir`.
#[must_use]
pub fn rebase_dir_path(mkit_dir: &Path) -> PathBuf {
    mkit_dir.join(REBASE_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{Commit, Identity, Tree, TreeEntry};
    use crate::serialize;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::init(dir.path()).unwrap();
        (dir, store)
    }

    fn put_blob(store: &ObjectStore, data: &[u8]) -> Hash {
        let bytes = serialize::serialize(&Object::Blob(crate::object::Blob {
            data: data.to_vec(),
        }))
        .unwrap();
        store.write(&bytes).unwrap()
    }

    fn put_tree(store: &ObjectStore, name: &str, blob_h: Hash) -> Hash {
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: crate::object::EntryMode::Blob,
                object_hash: blob_h,
            }],
        });
        let bytes = serialize::serialize(&tree).unwrap();
        store.write(&bytes).unwrap()
    }

    fn put_commit(store: &ObjectStore, tree_h: Hash, parents: Vec<Hash>, ts: u64) -> Hash {
        let commit = Object::Commit(Commit::new_unannotated(
            tree_h,
            parents,
            Identity::ed25519([0u8; 32]),
            [0u8; 32],
            b"msg".to_vec(),
            ts,
            [0u8; 64],
        ));
        let bytes = serialize::serialize(&commit).unwrap();
        store.write(&bytes).unwrap()
    }

    #[test]
    fn state_roundtrip_writes_recoverable_files() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();

        let state = RebaseState {
            head_name: "feature-branch".to_string(),
            orig_head: hash::hash(b"orig-head"),
            onto: hash::hash(b"onto"),
            todo: vec![hash::hash(b"t1"), hash::hash(b"t2")],
            done: vec![hash::hash(b"d1")],
        };
        write_state(&mkit, &state).unwrap();

        // Files should exist on disk — this models the "mid-rebase crash
        // leaves recoverable state" invariant.
        let dir = mkit.join(REBASE_DIR);
        assert!(dir.join("head-name").is_file());
        assert!(dir.join("orig-head").is_file());
        assert!(dir.join("onto").is_file());
        assert!(dir.join("todo").is_file());
        assert!(dir.join("done").is_file());

        let read = read_state(&mkit).unwrap();
        assert_eq!(read, state);
    }

    #[test]
    fn state_roundtrip_with_empty_todo_and_done() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();

        let state = RebaseState {
            head_name: "main".to_string(),
            orig_head: hash::hash(b"head"),
            onto: hash::hash(b"onto"),
            todo: Vec::new(),
            done: Vec::new(),
        };
        write_state(&mkit, &state).unwrap();
        let read = read_state(&mkit).unwrap();
        assert_eq!(read, state);
    }

    #[test]
    fn is_rebase_in_progress_detection() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        assert!(!is_rebase_in_progress(&mkit));
        fs::create_dir_all(mkit.join(REBASE_DIR)).unwrap();
        assert!(is_rebase_in_progress(&mkit));
    }

    #[test]
    fn cleanup_removes_state_dir() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        fs::create_dir_all(mkit.join(REBASE_DIR)).unwrap();
        fs::write(mkit.join(REBASE_DIR).join("head-name"), b"main\n").unwrap();
        assert!(is_rebase_in_progress(&mkit));
        cleanup_rebase(&mkit).unwrap();
        assert!(!is_rebase_in_progress(&mkit));
    }

    #[test]
    fn cleanup_on_missing_dir_is_noop() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        cleanup_rebase(&mkit).unwrap();
    }

    #[test]
    fn read_state_when_no_rebase_returns_error() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let err = read_state(&mkit).unwrap_err();
        assert!(matches!(err, RebaseError::NoRebaseInProgress));
    }

    #[test]
    fn collect_commits_on_linear_chain() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let c1 = put_commit(&store, tree, vec![], 1);
        let c2 = put_commit(&store, tree, vec![c1], 2);
        let c3 = put_commit(&store, tree, vec![c2], 3);
        let c4 = put_commit(&store, tree, vec![c3], 4);

        let res = collect_commits_to_replay(&store, c4, c2).unwrap();
        assert_eq!(res, vec![c3, c4]);
    }

    #[test]
    fn collect_commits_same_commit_returns_empty() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let c1 = put_commit(&store, tree, vec![], 1);
        let res = collect_commits_to_replay(&store, c1, c1).unwrap();
        assert!(res.is_empty());
    }

    #[test]
    fn collect_commits_y_shape_stops_at_ancestor_of_onto() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let c1 = put_commit(&store, tree, vec![], 1);
        let c2 = put_commit(&store, tree, vec![c1], 2);
        let c3 = put_commit(&store, tree, vec![c2], 3);
        let c4 = put_commit(&store, tree, vec![c1], 4);
        let c5 = put_commit(&store, tree, vec![c4], 5);

        // Replay feature (c5) onto main (c3): should yield [c4, c5].
        let res = collect_commits_to_replay(&store, c5, c3).unwrap();
        assert_eq!(res, vec![c4, c5]);
    }
}
