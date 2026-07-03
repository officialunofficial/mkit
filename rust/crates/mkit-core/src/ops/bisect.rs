//! Bisect.
//!
//! Stores state in `.mkit/bisect` (a single file, NOT a directory). The
//! on-disk format is a plain-text manifest:
//!
//! ```text
//! <orig_head_hex>
//! <orig_branch_or_empty>
//! <bad_hash_or_empty>
//! <good_hash_1>
//! <good_hash_2>
//! ...
//! skip:<skipped_hash_1>
//! skip:<skipped_hash_2>
//! ...
//! ```
//!
//! The `skip:` prefix lines are additive — old state files without them
//! deserialize with an empty `skipped` set. [`pick_midpoint_skip`] skips
//! over any candidate whose hash is in `skipped`, searching neighbors.
//!
//! Trailing whitespace on any line is tolerated on read.
//!
//! [`enumerate_range`] and [`pick_midpoint`] form the search core; the
//! caller drives the loop, calling `pick_midpoint` on the candidates
//! returned by `enumerate_range` and updating `bad`/`good` based on the
//! tester's verdict. [`BisectStep`] is a convenience response type.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::{self, HEX_LEN, Hash, ZERO};
use crate::object::Object;
use crate::store::ObjectStore;

/// Single-file state path under `<mkit_dir>`.
pub const BISECT_FILE: &str = "bisect";

const MAX_BISECT_FILE_BYTES: u64 = 1024 * 1024;

/// Maximum commits visited by the inlined ancestor walk.
const MAX_ANCESTORS: usize = 10_000;

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
pub enum BisectError {
    #[error("no bisect in progress")]
    NoBisectInProgress,
    #[error("bisect state on disk is malformed")]
    InvalidBisectState,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Object(#[from] crate::object::MkitError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}

/// Result alias.
pub type BisectResult<T> = Result<T, BisectError>;

/// Persisted bisect state.
///
/// Commits in `skipped` are excluded from midpoint selection. Old state
/// files without `skip:` lines deserialize with an empty `skipped` set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BisectState {
    /// HEAD as it was when bisect started.
    pub orig_head: Hash,
    /// Branch HEAD pointed at when bisect started, or `None` for detached.
    pub orig_branch: Option<String>,
    /// The known-bad commit, or `None` if not yet provided.
    pub bad_hash: Option<Hash>,
    /// All known-good commits.
    pub good_hashes: Vec<Hash>,
    /// Commits explicitly skipped by `mkit bisect skip`. Excluded from
    /// midpoint selection; neighbour search falls back to the nearest
    /// non-skipped candidate.
    pub skipped: BTreeSet<Hash>,
}

/// Outcome of a single bisect iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BisectStep {
    /// We are now testing this commit. `remaining` is the candidate
    /// count BEFORE this iteration's pick.
    Testing { hash: Hash, remaining: usize },
    /// First-bad commit identified.
    Found(Hash),
    /// Only skipped commits remain between good and bad, so the first-bad
    /// commit is ambiguous — it could be `bad` or any commit in `skipped`
    /// (git's "The first bad commit could be any of …"). Distinguished from
    /// [`Found`](BisectStep::Found) so callers don't report a skipped-over
    /// guess as definitive.
    Ambiguous { bad: Hash, skipped: Vec<Hash> },
    /// We need both at least one good and a bad before we can compute a midpoint.
    NeedMore,
}

/// Returns `true` when `<mkit_dir>/bisect` exists.
#[must_use]
pub fn is_bisect_in_progress(mkit_dir: &Path) -> bool {
    mkit_dir.join(BISECT_FILE).is_file()
}

/// Read bisect state from `<mkit_dir>/bisect`.
///
/// # Errors
/// - [`BisectError::NoBisectInProgress`] if the file does not exist.
/// - [`BisectError::InvalidBisectState`] for any malformed line.
pub fn read_state(mkit_dir: &Path) -> BisectResult<BisectState> {
    let path = mkit_dir.join(BISECT_FILE);
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(BisectError::NoBisectInProgress);
        }
        Err(e) => return Err(BisectError::Io(e)),
    };
    if meta.len() == 0 {
        return Err(BisectError::InvalidBisectState);
    }
    if meta.len() > MAX_BISECT_FILE_BYTES {
        return Err(BisectError::InvalidBisectState);
    }
    let raw = fs::read_to_string(&path)?;

    let mut lines = raw.split('\n');

    let orig_head_line = lines.next().ok_or(BisectError::InvalidBisectState)?;
    let orig_head_trim = orig_head_line.trim_end_matches(['\r', ' ']);
    if orig_head_trim.is_empty() {
        return Err(BisectError::InvalidBisectState);
    }
    let orig_head = hash::from_hex(orig_head_trim).map_err(|_| BisectError::InvalidBisectState)?;

    let branch_line = lines.next().ok_or(BisectError::InvalidBisectState)?;
    let branch_trim = branch_line.trim_end_matches(['\r', ' ']);
    let orig_branch = if branch_trim.is_empty() {
        None
    } else {
        Some(branch_trim.to_string())
    };

    let bad_line = lines.next().ok_or(BisectError::InvalidBisectState)?;
    let bad_trim = bad_line.trim_end_matches(['\r', ' ']);
    let bad_hash = if bad_trim.is_empty() {
        None
    } else {
        Some(hash::from_hex(bad_trim).map_err(|_| BisectError::InvalidBisectState)?)
    };

    let mut good_hashes = Vec::new();
    let mut skipped = BTreeSet::new();
    for line in lines {
        let line = line.trim_end_matches(['\r', ' ']);
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("skip:") {
            // Skipped hash entry (additive extension; old parsers do not
            // write these, so old state files get an empty skipped set).
            if rest.len() != HEX_LEN {
                return Err(BisectError::InvalidBisectState);
            }
            let h = hash::from_hex(rest).map_err(|_| BisectError::InvalidBisectState)?;
            skipped.insert(h);
        } else {
            if line.len() != HEX_LEN {
                return Err(BisectError::InvalidBisectState);
            }
            let h = hash::from_hex(line).map_err(|_| BisectError::InvalidBisectState)?;
            good_hashes.push(h);
        }
    }

    Ok(BisectState {
        orig_head,
        orig_branch,
        bad_hash,
        good_hashes,
        skipped,
    })
}

/// Persist `state` to `<mkit_dir>/bisect`.
///
/// # Errors
/// - [`BisectError::Io`] for filesystem failures.
pub fn write_state(mkit_dir: &Path, state: &BisectState) -> BisectResult<()> {
    let mut buf = String::new();
    buf.push_str(&hash::to_hex(&state.orig_head));
    buf.push('\n');
    if let Some(b) = &state.orig_branch {
        buf.push_str(b);
    }
    buf.push('\n');
    if let Some(bad) = &state.bad_hash {
        buf.push_str(&hash::to_hex(bad));
    }
    buf.push('\n');
    for g in &state.good_hashes {
        buf.push_str(&hash::to_hex(g));
        buf.push('\n');
    }
    for s in &state.skipped {
        buf.push_str("skip:");
        buf.push_str(&hash::to_hex(s));
        buf.push('\n');
    }
    // Atomic + durable write (write-to-temp, fsync, rename, fsync parent
    // dir) so a crash mid-write cannot leave a truncated bisect state file
    // that `read_state` would reject as InvalidBisectState. Matches the
    // rest of the ops state writers (stash/recovery/restore).
    crate::atomic::write_atomic(&mkit_dir.join(BISECT_FILE), buf.as_bytes(), true)?;
    Ok(())
}

/// Remove `<mkit_dir>/bisect`. Idempotent.
///
/// # Errors
/// - [`BisectError::Io`] for filesystem failures other than "not found".
pub fn cleanup_bisect(mkit_dir: &Path) -> BisectResult<()> {
    let path = mkit_dir.join(BISECT_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(BisectError::Io(e)),
    }
}

/// Convenience: full path to the bisect state file under `mkit_dir`.
#[must_use]
pub fn bisect_file_path(mkit_dir: &Path) -> PathBuf {
    mkit_dir.join(BISECT_FILE)
}

/// Walk ancestors of `bad`, stopping at any commit that is `good` or an
/// ancestor of `good`. Returns the candidate set in BFS order from `bad`.
///
/// # Errors
/// - [`BisectError::Store`] / [`BisectError::Object`] for store failures.
pub fn enumerate_range(
    store: &ObjectStore,
    bad: Hash,
    good_hashes: &[Hash],
) -> BisectResult<Vec<Hash>> {
    let mut good_set: HashSet<Hash> = HashSet::new();
    for g in good_hashes {
        collect_ancestor_set(store, *g, &mut good_set);
    }

    let mut visited: HashSet<Hash> = HashSet::new();
    let mut candidates: Vec<Hash> = Vec::new();
    let mut queue: Vec<Hash> = vec![bad];
    let mut head = 0usize;
    while head < queue.len() {
        let current = queue[head];
        head += 1;
        if !visited.insert(current) {
            continue;
        }
        if good_set.contains(&current) {
            continue;
        }
        candidates.push(current);
        let Ok(obj) = store.read_object(&current) else {
            continue;
        };
        if let Object::Commit(commit) = obj {
            for p in commit.parents {
                queue.push(p);
            }
        }
    }
    Ok(candidates)
}

/// Pick the midpoint commit. Returns `Hash::ZERO` when `candidates` is
/// empty.
#[must_use]
pub fn pick_midpoint(candidates: &[Hash]) -> Hash {
    if candidates.is_empty() {
        return ZERO;
    }
    candidates[candidates.len() / 2]
}

/// Pick the midpoint commit, skipping over any commit in `skipped`.
///
/// Starts at `candidates[len/2]` (the natural midpoint). If that commit
/// is in `skipped`, searches outward — alternating lower and upper
/// neighbors — until a non-skipped candidate is found. Returns `ZERO`
/// only when all candidates are skipped (or the list is empty).
///
/// This implements a skip-neighbor scan.
#[must_use]
pub fn pick_midpoint_skip(candidates: &[Hash], skipped: &BTreeSet<Hash>) -> Hash {
    if candidates.is_empty() {
        return ZERO;
    }
    let mid = candidates.len() / 2;
    // Walk outward from mid: try mid, mid-1, mid+1, mid-2, mid+2, …
    for delta in 0..=candidates.len() {
        // Positive direction: mid + delta
        if let Some(idx) = mid.checked_add(delta).filter(|&i| i < candidates.len()) {
            let h = candidates[idx];
            if !skipped.contains(&h) {
                return h;
            }
        }
        // Negative direction: mid - delta (skip delta==0 to avoid double-check)
        if let (true, Some(idx)) = (delta > 0, mid.checked_sub(delta)) {
            let h = candidates[idx];
            if !skipped.contains(&h) {
                return h;
            }
        }
    }
    // All candidates are skipped.
    ZERO
}

/// Drive a single bisect iteration: enumerate the range, then pick the
/// midpoint or report completion.
///
/// - If both `bad_hash` and at least one `good_hash` are present:
///     - Empty candidate set ⇒ [`BisectStep::Found`] (the only suspect
///       is `bad_hash` itself, but the candidate set excludes good
///       ancestors; if it's empty the bug is at `bad`).
///     - One candidate ⇒ [`BisectStep::Found`].
///     - Otherwise pick the midpoint and return [`BisectStep::Testing`].
/// - Otherwise return [`BisectStep::NeedMore`].
///
/// # Errors
/// - [`BisectError::Store`] / [`BisectError::Object`] for store failures.
pub fn next_step(store: &ObjectStore, state: &BisectState) -> BisectResult<BisectStep> {
    let Some(bad) = state.bad_hash else {
        return Ok(BisectStep::NeedMore);
    };
    if state.good_hashes.is_empty() {
        return Ok(BisectStep::NeedMore);
    }
    let candidates = enumerate_range(store, bad, &state.good_hashes)?;
    if candidates.is_empty() {
        return Ok(BisectStep::Found(bad));
    }
    // Filter out skipped commits for the Found-check, but keep them in
    // the candidate list for neighbor search.
    let non_skipped: Vec<Hash> = candidates
        .iter()
        .copied()
        .filter(|h| !state.skipped.contains(h))
        .collect();
    // Skipped commits that are still in the live range — the candidates
    // that make the answer ambiguous if nothing testable is left to
    // disambiguate them.
    let skipped_in_range: Vec<Hash> = candidates
        .iter()
        .copied()
        .filter(|h| state.skipped.contains(h))
        .collect();
    if non_skipped.len() == 1 {
        let only = non_skipped[0];
        // The lone survivor is normally the first-bad commit. But when it is
        // the `bad` boundary itself and in-range candidates were skipped, the
        // first bad commit is ambiguous — it could be `bad` or any skipped
        // one (git's "only skipped commits left") — so don't report a guess
        // as definitive.
        if only == bad && !skipped_in_range.is_empty() {
            return Ok(BisectStep::Ambiguous {
                bad,
                skipped: skipped_in_range,
            });
        }
        return Ok(BisectStep::Found(only));
    }
    if non_skipped.is_empty() {
        // Defensive: every candidate (bad not among them) is skipped.
        return Ok(BisectStep::Ambiguous {
            bad,
            skipped: skipped_in_range,
        });
    }
    let mid = pick_midpoint_skip(&candidates, &state.skipped);
    Ok(BisectStep::Testing {
        hash: mid,
        remaining: candidates.len(),
    })
}

// -- Internal helpers --------------------------------------------------------

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
        store.write(&serialize::serialize(&tree).unwrap()).unwrap()
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
        store
            .write(&serialize::serialize(&commit).unwrap())
            .unwrap()
    }

    #[test]
    fn state_roundtrip_with_branch_and_bad() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let state = BisectState {
            orig_head: hash::hash(b"orig-head"),
            orig_branch: Some("main".to_string()),
            bad_hash: Some(hash::hash(b"bad")),
            good_hashes: vec![hash::hash(b"g1"), hash::hash(b"g2")],
            skipped: BTreeSet::new(),
        };
        write_state(&mkit, &state).unwrap();
        let read = read_state(&mkit).unwrap();
        assert_eq!(read, state);
    }

    #[test]
    fn state_roundtrip_with_no_branch_no_bad() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let state = BisectState {
            orig_head: hash::hash(b"head"),
            orig_branch: None,
            bad_hash: None,
            good_hashes: Vec::new(),
            skipped: BTreeSet::new(),
        };
        write_state(&mkit, &state).unwrap();
        let read = read_state(&mkit).unwrap();
        assert_eq!(read, state);
    }

    #[test]
    fn state_roundtrip_with_skipped_hashes() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let s1 = hash::hash(b"skip1");
        let s2 = hash::hash(b"skip2");
        let mut skipped = BTreeSet::new();
        skipped.insert(s1);
        skipped.insert(s2);
        let state = BisectState {
            orig_head: hash::hash(b"head"),
            orig_branch: Some("main".to_string()),
            bad_hash: Some(hash::hash(b"bad")),
            good_hashes: vec![hash::hash(b"good")],
            skipped,
        };
        write_state(&mkit, &state).unwrap();
        let read = read_state(&mkit).unwrap();
        assert_eq!(read, state);
        assert_eq!(read.skipped.len(), 2);
        assert!(read.skipped.contains(&s1));
        assert!(read.skipped.contains(&s2));
    }

    #[test]
    fn write_state_creates_missing_dir_and_overwrites_atomically() {
        // Regression: write_state now uses the durable atomic helper
        // (write-to-temp + rename) instead of a bare fs::write. Verify it
        // (a) creates the parent dir when absent, (b) cleanly overwrites an
        // existing state file, and (c) leaves no `.bisect.tmp.*` sibling
        // behind after the rename.
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        // Note: directory intentionally NOT pre-created.
        let first = BisectState {
            orig_head: hash::hash(b"head"),
            orig_branch: Some("main".to_string()),
            bad_hash: Some(hash::hash(b"bad")),
            good_hashes: vec![hash::hash(b"g1")],
            skipped: BTreeSet::new(),
        };
        write_state(&mkit, &first).unwrap();
        assert_eq!(read_state(&mkit).unwrap(), first);

        let second = BisectState {
            orig_head: hash::hash(b"head2"),
            orig_branch: None,
            bad_hash: None,
            good_hashes: Vec::new(),
            skipped: BTreeSet::new(),
        };
        write_state(&mkit, &second).unwrap();
        assert_eq!(read_state(&mkit).unwrap(), second);

        // No temp artefact left in the directory: only the bisect file.
        let stray: Vec<_> = fs::read_dir(&mkit)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != BISECT_FILE)
            .collect();
        assert!(stray.is_empty(), "stray temp files left behind: {stray:?}");
    }

    #[test]
    fn old_state_file_without_skip_deserializes_with_empty_skipped() {
        // Simulate a state file written by an old parser (no `skip:` lines).
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let orig_head = hash::hash(b"orig");
        let bad = hash::hash(b"bad");
        let good = hash::hash(b"good");
        // Write the old format manually (no skip: lines).
        let content = format!(
            "{}\n\n{}\n{}\n",
            hash::to_hex(&orig_head),
            hash::to_hex(&bad),
            hash::to_hex(&good)
        );
        fs::write(mkit.join(BISECT_FILE), content.as_bytes()).unwrap();
        let read = read_state(&mkit).unwrap();
        assert_eq!(read.orig_head, orig_head);
        assert_eq!(read.bad_hash, Some(bad));
        assert_eq!(read.good_hashes, vec![good]);
        assert!(
            read.skipped.is_empty(),
            "old files must deserialize with empty skipped"
        );
    }

    #[test]
    fn read_state_when_no_bisect_returns_error() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        let err = read_state(&mkit).unwrap_err();
        assert!(matches!(err, BisectError::NoBisectInProgress));
    }

    #[test]
    fn read_state_rejects_empty_file() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        fs::write(mkit.join(BISECT_FILE), b"").unwrap();
        let err = read_state(&mkit).unwrap_err();
        assert!(matches!(err, BisectError::InvalidBisectState));
    }

    #[test]
    fn is_bisect_in_progress_detection() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        assert!(!is_bisect_in_progress(&mkit));
        fs::write(mkit.join(BISECT_FILE), b"placeholder").unwrap();
        assert!(is_bisect_in_progress(&mkit));
    }

    #[test]
    fn cleanup_removes_state_file() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        fs::write(mkit.join(BISECT_FILE), b"x\n").unwrap();
        cleanup_bisect(&mkit).unwrap();
        assert!(!is_bisect_in_progress(&mkit));
    }

    #[test]
    fn cleanup_on_missing_file_is_noop() {
        let tmp = TempDir::new().unwrap();
        let mkit = tmp.path().join(".mkit");
        fs::create_dir_all(&mkit).unwrap();
        cleanup_bisect(&mkit).unwrap();
    }

    #[test]
    fn pick_midpoint_returns_middle_element() {
        let c1 = hash::hash(b"c1");
        let c2 = hash::hash(b"c2");
        let c3 = hash::hash(b"c3");
        let c4 = hash::hash(b"c4");
        let c5 = hash::hash(b"c5");
        // len=5, 5/2=2 → c3
        assert_eq!(pick_midpoint(&[c1, c2, c3, c4, c5]), c3);
        // len=4, 4/2=2 → c3
        assert_eq!(pick_midpoint(&[c1, c2, c3, c4]), c3);
        assert_eq!(pick_midpoint(&[c1]), c1);
    }

    #[test]
    fn pick_midpoint_empty_returns_zero() {
        assert_eq!(pick_midpoint(&[]), ZERO);
    }

    #[test]
    fn enumerate_range_on_linear_chain() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let mut commits = Vec::new();
        commits.push(put_commit(&store, tree, vec![], 1));
        for i in 1..8 {
            let parent = commits[i - 1];
            commits.push(put_commit(&store, tree, vec![parent], (i + 1) as u64));
        }
        // bad=c8 (index 7), good=[c2 (index 1)]
        // Candidates should be c3..c8 (6 commits), starting BFS from c8.
        let cands = enumerate_range(&store, commits[7], &[commits[1]]).unwrap();
        assert_eq!(cands.len(), 6);
        assert_eq!(cands[0], commits[7]);
    }

    #[test]
    fn enumerate_range_with_diamond_merge() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"d");
        let tree = put_tree(&store, "f.txt", blob);
        let c1 = put_commit(&store, tree, vec![], 1);
        let c2 = put_commit(&store, tree, vec![c1], 2);
        let c3 = put_commit(&store, tree, vec![c1], 3);
        let c4 = put_commit(&store, tree, vec![c2, c3], 4);
        let cands = enumerate_range(&store, c4, &[c1]).unwrap();
        assert_eq!(cands.len(), 3);
        assert_eq!(cands[0], c4);
    }

    #[test]
    fn enumerate_range_same_good_and_bad_yields_empty() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"d");
        let tree = put_tree(&store, "f.txt", blob);
        let c1 = put_commit(&store, tree, vec![], 1);
        let cands = enumerate_range(&store, c1, &[c1]).unwrap();
        assert!(cands.is_empty());
    }

    #[test]
    fn next_step_need_more_when_no_bad() {
        let (_d, store) = fresh_store();
        let state = BisectState {
            orig_head: ZERO,
            orig_branch: None,
            bad_hash: None,
            good_hashes: vec![hash::hash(b"x")],
            skipped: BTreeSet::new(),
        };
        assert_eq!(next_step(&store, &state).unwrap(), BisectStep::NeedMore);
    }

    #[test]
    fn next_step_drives_bisect_to_completion() {
        // good < midpoint < bad → midpoint selection.
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let mut commits = Vec::new();
        commits.push(put_commit(&store, tree, vec![], 1));
        for i in 1..6 {
            let parent = commits[i - 1];
            commits.push(put_commit(&store, tree, vec![parent], (i + 1) as u64));
        }
        // bad = c6 (index 5), good = [c1 (index 0)]
        let mut state = BisectState {
            orig_head: commits[5],
            orig_branch: None,
            bad_hash: Some(commits[5]),
            good_hashes: vec![commits[0]],
            skipped: BTreeSet::new(),
        };
        // Drive the bisect, simulating a "first-bad = c4" scenario:
        // c1 good; c2..c5 unknown; c6 bad. Truth = c4 (index 3) is first bad.
        let truth = commits[3];

        let mut iters = 0;
        loop {
            assert!(iters < 8, "bisect should converge within 8 iterations");
            iters += 1;
            match next_step(&store, &state).unwrap() {
                BisectStep::Found(h) => {
                    assert_eq!(h, truth);
                    break;
                }
                BisectStep::Testing { hash, .. } => {
                    // Test: anything older than truth is good, truth and
                    // newer is bad.
                    let idx = commits.iter().position(|c| *c == hash).unwrap();
                    let truth_idx = commits.iter().position(|c| *c == truth).unwrap();
                    if idx < truth_idx {
                        state.good_hashes.push(hash);
                    } else {
                        state.bad_hash = Some(hash);
                    }
                }
                BisectStep::NeedMore => panic!("unexpected NeedMore"),
                BisectStep::Ambiguous { .. } => panic!("unexpected ambiguous"),
            }
        }
    }

    #[test]
    fn skip_advances_midpoint_to_neighbor() {
        // Linear chain: c1 < c2 < c3 < c4 < c5 < c6
        // good=c1, bad=c6, natural midpoint=c3 (index 2 of candidates c2..c6).
        // Skip c3 → should pick neighbor (c2 or c4).
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let mut commits = Vec::new();
        commits.push(put_commit(&store, tree, vec![], 1)); // c1 = index 0
        for i in 1..6 {
            let parent = commits[i - 1];
            commits.push(put_commit(&store, tree, vec![parent], (i + 1) as u64));
        }
        // Enumerate range first to know what the natural midpoint would be.
        let cands = enumerate_range(&store, commits[5], &[commits[0]]).unwrap();
        // Natural midpoint without skip.
        let natural_mid = pick_midpoint(&cands);
        assert_ne!(natural_mid, ZERO, "should have a natural midpoint");

        // Now skip the natural midpoint.
        let mut skipped = BTreeSet::new();
        skipped.insert(natural_mid);

        let skipped_mid = pick_midpoint_skip(&cands, &skipped);
        assert_ne!(
            skipped_mid, ZERO,
            "should find a neighbor when mid is skipped"
        );
        assert_ne!(
            skipped_mid, natural_mid,
            "skip must advance past the natural midpoint"
        );
        assert!(
            !skipped.contains(&skipped_mid),
            "returned hash must not be in skipped set"
        );
    }

    #[test]
    fn next_step_skip_advances_then_finds() {
        // 5-commit chain: c1 good, c6 bad, truth = c4 (index 3).
        // Skip a good-side commit (c2) far from the truth: it is bypassed as
        // `good` advances, so bisect still converges definitively (a skip
        // that STRANDED the truth next to `bad` would instead be ambiguous —
        // covered by the CLI `bisect run` tests).
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"data");
        let tree = put_tree(&store, "f.txt", blob);
        let mut commits = Vec::new();
        commits.push(put_commit(&store, tree, vec![], 1));
        for i in 1..6 {
            let p = commits[i - 1];
            commits.push(put_commit(&store, tree, vec![p], (i + 1) as u64));
        }
        let truth = commits[3]; // c4

        let mut skipped = BTreeSet::new();
        skipped.insert(commits[1]); // skip c2, a good-side commit

        let mut state = BisectState {
            orig_head: commits[5],
            orig_branch: None,
            bad_hash: Some(commits[5]),
            good_hashes: vec![commits[0]],
            skipped,
        };

        let mut iters = 0;
        loop {
            assert!(iters < 10, "bisect with skip should converge");
            iters += 1;
            match next_step(&store, &state).unwrap() {
                BisectStep::Found(_) => break,
                BisectStep::Testing { hash, .. } => {
                    let idx = commits.iter().position(|c| *c == hash).unwrap();
                    let truth_idx = commits.iter().position(|c| *c == truth).unwrap();
                    if idx < truth_idx {
                        state.good_hashes.push(hash);
                    } else {
                        state.bad_hash = Some(hash);
                    }
                }
                BisectStep::NeedMore => panic!("unexpected NeedMore"),
                BisectStep::Ambiguous { .. } => panic!("unexpected ambiguous"),
            }
        }
    }

    #[test]
    fn pick_midpoint_skip_all_skipped_returns_zero() {
        let c1 = hash::hash(b"c1");
        let c2 = hash::hash(b"c2");
        let c3 = hash::hash(b"c3");
        let mut skipped = BTreeSet::new();
        skipped.insert(c1);
        skipped.insert(c2);
        skipped.insert(c3);
        assert_eq!(pick_midpoint_skip(&[c1, c2, c3], &skipped), ZERO);
    }
}
