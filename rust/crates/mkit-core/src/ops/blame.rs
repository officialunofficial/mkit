//! Blame.
//!
//! Walks the first-parent chain from a head commit, collecting the
//! `(commit, blob)` pair for the file path at each step. Then replays
//! the diffs forward (oldest → newest), attributing each line in the
//! final blob to the commit that introduced it.
//!
//! Line matching uses a simple LCS DP table. For typical source files
//! (a few thousand lines) this is fine; binary blobs / generated code
//! are not in scope.
//!
//! Output formatting (used by goldens) is `<short>\t<line_num>\t<text>`,
//! where `<short>` is the 12-char prefix of the commit hash. See
//! [`format_blame_text`].

use std::fmt::Write as _;

use crate::hash::{self, Hash};
use crate::object::{EntryMode, Identity, Object};
use crate::store::ObjectStore;

/// Hard cap on the per-side line count fed to the LCS matcher. The DP
/// table is O(m*n) u32 entries: at 100 000 lines × 100 000 lines this
/// is ≈ 40 GiB, so we refuse anything past this limit rather than let
/// an attacker-supplied blob drive the decoder into swap/OOM.
pub const BLAME_MAX_LINES: usize = 100_000;

/// Per-line blame attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameLine {
    /// 1-based line number in the final blob.
    pub line_num: usize,
    /// Commit that last touched this line.
    pub commit_hash: Hash,
    /// Author Identity of `commit_hash`, deep-copied from the commit
    /// object so the result is self-contained.
    pub author: Identity,
    /// Commit timestamp.
    pub timestamp: u64,
    /// Final line text (no trailing newline).
    pub text: Vec<u8>,
}

/// Result of [`blame_file`]: per-line attributions in 1..=N order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameResult {
    pub lines: Vec<BlameLine>,
}

/// Knobs controlling how [`blame_file_with`] attributes lines. The
/// default (all-false) reproduces [`blame_file`]'s exact-match behavior;
/// this struct is the extension point for the blame parity work (`-w`
/// today; `-M`/`-C`/ignore-revs to follow).
#[derive(Debug, Clone, Copy, Default)]
pub struct BlameOptions {
    /// Ignore whitespace when matching a line against its parent
    /// revision, so a whitespace-only edit (reindent, tab↔space, spacing
    /// tweak) does not reattribute the line. Mirrors `git blame -w`,
    /// which ignores *all* whitespace, not just runs of it.
    pub ignore_whitespace: bool,
}

/// Errors raised by this module.
#[derive(Debug, thiserror::Error)]
pub enum BlameError {
    #[error("requested object is not a commit")]
    NotACommit,
    #[error("requested object is not a blob or chunked-blob")]
    NotABlob,
    #[error("file '{0}' was not found at any commit in history")]
    FileNotFound(String),
    /// Either side of the LCS input exceeded [`BLAME_MAX_LINES`].
    /// Returned rather than allocating a DP table proportional to the
    /// attacker-supplied line counts.
    #[error("file has too many lines for blame ({lines} > {max})", max = BLAME_MAX_LINES)]
    FileTooLarge { lines: usize },
    #[error(transparent)]
    Object(#[from] crate::object::MkitError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}

/// Fallible-result alias for this module's operations.
pub type BlameOutcome<T> = Result<T, BlameError>;

/// Blame `file_path` at `head_hash` with default options (exact line
/// matching). Convenience wrapper over [`blame_file_with`].
///
/// # Errors
/// See [`blame_file_with`].
pub fn blame_file(
    store: &ObjectStore,
    head_hash: Hash,
    file_path: &str,
) -> BlameOutcome<BlameResult> {
    blame_file_with(store, head_hash, file_path, &BlameOptions::default())
}

/// Blame `file_path` at `head_hash`. Walks first-parent ancestry,
/// stops when the file disappears, and uses LCS to map lines forward.
/// `opts` tunes matching (see [`BlameOptions`]).
///
/// # Errors
/// - [`BlameError::FileNotFound`] if the file does not exist at `head_hash`.
/// - [`BlameError::NotACommit`] if `head_hash` is not a commit object.
/// - [`BlameError::FileTooLarge`] if any blob on the history chain has
///   more than [`BLAME_MAX_LINES`] lines.
///
/// # Panics
/// Panics only on internal logic violations: it is unreachable for the
/// "oldest entry" lookup below to fail, since we early-return on an
/// empty history just above it.
pub fn blame_file_with(
    store: &ObjectStore,
    head_hash: Hash,
    file_path: &str,
    opts: &BlameOptions,
) -> BlameOutcome<BlameResult> {
    #[derive(Clone)]
    struct HistoryEntry {
        commit_hash: Hash,
        blob_hash: Hash,
        author: Identity,
        timestamp: u64,
    }
    #[derive(Clone)]
    struct Attribution {
        commit_hash: Hash,
        author: Identity,
        timestamp: u64,
    }

    let mut history: Vec<HistoryEntry> = Vec::new();
    let mut current = Some(head_hash);
    while let Some(commit_hash) = current {
        let obj = store.read_object(&commit_hash)?;
        let Object::Commit(commit) = obj else {
            return Err(BlameError::NotACommit);
        };
        let blob_hash = find_blob_in_tree(store, commit.tree_hash, file_path)?;
        if let Some(bh) = blob_hash {
            history.push(HistoryEntry {
                commit_hash,
                blob_hash: bh,
                author: commit.author.clone(),
                timestamp: commit.timestamp,
            });
            current = commit.parents.first().copied();
        } else {
            break;
        }
    }
    // Oldest entry: every line attributed to it. An empty history means the
    // file was never present in any commit along the walk.
    let Some(oldest) = history.last().cloned() else {
        return Err(BlameError::FileNotFound(file_path.to_string()));
    };
    let oldest_lines = load_blob_lines(store, oldest.blob_hash)?;
    let mut attributions: Vec<Attribution> = oldest_lines
        .iter()
        .map(|_| Attribution {
            commit_hash: oldest.commit_hash,
            author: oldest.author.clone(),
            timestamp: oldest.timestamp,
        })
        .collect();

    // Walk from second-oldest to newest, applying LCS-based attribution.
    if history.len() > 1 {
        let mut idx = history.len() - 1;
        while idx > 0 {
            idx -= 1;
            let newer = &history[idx];
            let older = &history[idx + 1];

            if newer.blob_hash == older.blob_hash {
                continue;
            }

            let old_lines = load_blob_lines(store, older.blob_hash)?;
            let new_lines = load_blob_lines(store, newer.blob_hash)?;
            // With `-w`, match on whitespace-stripped keys so a
            // whitespace-only edit pairs the lines (and thus inherits the
            // older attribution); the raw `new_lines` are still what gets
            // emitted, so output bytes are unchanged.
            let mapping = if opts.ignore_whitespace {
                let old_keys: Vec<Vec<u8>> = old_lines.iter().map(|l| strip_ws(l)).collect();
                let new_keys: Vec<Vec<u8>> = new_lines.iter().map(|l| strip_ws(l)).collect();
                match_lines_checked(&old_keys, &new_keys)?
            } else {
                match_lines_checked(&old_lines, &new_lines)?
            };

            let mut new_attrs: Vec<Attribution> = Vec::with_capacity(new_lines.len());
            for (ni, _) in new_lines.iter().enumerate() {
                let attr = match mapping[ni] {
                    Some(old_idx) if old_idx < attributions.len() => attributions[old_idx].clone(),
                    _ => Attribution {
                        commit_hash: newer.commit_hash,
                        author: newer.author.clone(),
                        timestamp: newer.timestamp,
                    },
                };
                new_attrs.push(attr);
            }
            attributions = new_attrs;
        }
    }

    let head_blob = history[0].blob_hash;
    let final_lines = load_blob_lines(store, head_blob)?;
    let mut out = Vec::with_capacity(final_lines.len());
    for (i, text) in final_lines.into_iter().enumerate() {
        let a = &attributions[i];
        out.push(BlameLine {
            line_num: i + 1,
            commit_hash: a.commit_hash,
            author: a.author.clone(),
            timestamp: a.timestamp,
            text,
        });
    }
    Ok(BlameResult { lines: out })
}

/// Walk a `/`-separated tree path and return the leaf blob hash, or
/// `None` if any component is missing or has the wrong kind.
///
/// # Errors
/// - [`BlameError::Store`] / [`BlameError::Object`] for store failures.
pub fn find_blob_in_tree(
    store: &ObjectStore,
    tree_hash: Hash,
    path: &str,
) -> BlameOutcome<Option<Hash>> {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    if components.is_empty() {
        return Ok(None);
    }
    let mut current_tree = tree_hash;
    for (ci, component) in components.iter().enumerate() {
        let obj = store.read_object(&current_tree)?;
        let Object::Tree(tree) = obj else {
            return Ok(None);
        };
        let is_last = ci == components.len() - 1;
        let mut found_subtree = None;
        let mut matched = false;
        for entry in &tree.entries {
            if entry.name.as_slice() == component.as_bytes() {
                matched = true;
                if is_last {
                    return match entry.mode {
                        EntryMode::Blob | EntryMode::Executable => Ok(Some(entry.object_hash)),
                        _ => Ok(None),
                    };
                }
                if entry.mode == EntryMode::Tree {
                    found_subtree = Some(entry.object_hash);
                    break;
                }
                return Ok(None);
            }
        }
        if !matched {
            return Ok(None);
        }
        if let Some(t) = found_subtree {
            current_tree = t;
        }
    }
    Ok(None)
}

/// Load a blob (or chunked-blob) and split into lines (no trailing
/// newline preserved as a synthetic empty line).
fn load_blob_lines(store: &ObjectStore, blob_hash: Hash) -> BlameOutcome<Vec<Vec<u8>>> {
    let obj = store.read_object(&blob_hash)?;
    let data: Vec<u8> = match obj {
        Object::Blob(b) => b.data,
        Object::ChunkedBlob(cb) => {
            let mut buf: Vec<u8> = Vec::with_capacity(usize::try_from(cb.total_size).unwrap_or(0));
            for ch in cb.chunks {
                let chunk_obj = store.read_object(&ch)?;
                let Object::Blob(b) = chunk_obj else {
                    return Err(BlameError::NotABlob);
                };
                buf.extend_from_slice(&b.data);
            }
            buf
        }
        _ => return Err(BlameError::NotABlob),
    };
    Ok(split_lines(&data))
}

/// Whitespace-insensitive comparison key for a line: every ASCII
/// whitespace byte removed. Matches `git blame -w` (ignore-all-space),
/// which collapses `foo(a, b)`, `foo(a,b)`, and `    foo(a,  b)` to the
/// same key so a whitespace-only edit doesn't reattribute the line.
fn strip_ws(line: &[u8]) -> Vec<u8> {
    line.iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect()
}

fn split_lines(data: &[u8]) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<Vec<u8>> = data.split(|b| *b == b'\n').map(<[u8]>::to_vec).collect();
    if data.last().copied() == Some(b'\n') && !out.is_empty() {
        out.pop();
    }
    out
}

/// Size-checked LCS line matcher. Returns
/// [`BlameError::FileTooLarge`] if either side exceeds
/// [`BLAME_MAX_LINES`] rather than allocating an O(m*n) DP table. This
/// is the only public entry point; the unbounded inner matcher is
/// private so external callers cannot trip the O(m*n) allocation.
///
/// # Errors
/// - [`BlameError::FileTooLarge`] if `old_lines.len()` or
///   `new_lines.len()` exceeds [`BLAME_MAX_LINES`].
pub fn match_lines_checked<T: AsRef<[u8]>>(
    old_lines: &[T],
    new_lines: &[T],
) -> BlameOutcome<Vec<Option<usize>>> {
    if old_lines.len() > BLAME_MAX_LINES {
        return Err(BlameError::FileTooLarge {
            lines: old_lines.len(),
        });
    }
    if new_lines.len() > BLAME_MAX_LINES {
        return Err(BlameError::FileTooLarge {
            lines: new_lines.len(),
        });
    }
    Ok(match_lines(old_lines, new_lines))
}

/// LCS line matching. For each line in `new_lines`, returns the index
/// in `old_lines` it corresponds to, or `None` for inserted/changed.
///
/// NOTE: This function allocates an O(m*n) DP table with no size guard,
/// so it is kept private; all callers go through the size-checked
/// [`match_lines_checked`] wrapper.
#[must_use]
fn match_lines<T: AsRef<[u8]>>(old_lines: &[T], new_lines: &[T]) -> Vec<Option<usize>> {
    let m = old_lines.len();
    let n = new_lines.len();
    // dp is (m+1) x (n+1).
    let mut dp = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            if old_lines[i - 1].as_ref() == new_lines[j - 1].as_ref() {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }
    let mut mapping: Vec<Option<usize>> = vec![None; n];
    let mut i = m;
    let mut j = n;
    while i > 0 && j > 0 {
        if old_lines[i - 1].as_ref() == new_lines[j - 1].as_ref() {
            mapping[j - 1] = Some(i - 1);
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    mapping
}

/// Pinned text formatting for goldens. Format:
///
/// ```text
/// <short_hash>\t<line_num>\t<text>\n
/// ```
///
/// where `<short_hash>` is the 12-character lowercase-hex prefix.
#[must_use]
pub fn format_blame_text(result: &BlameResult) -> String {
    let mut out = String::new();
    for line in &result.lines {
        let hex = hash::to_hex(&line.commit_hash);
        let short = &hex[..12];
        let _ = write!(out, "{}\t{}\t", short, line.line_num);
        out.push_str(&String::from_utf8_lossy(&line.text));
        out.push('\n');
    }
    out
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

    fn put_single_file_tree(store: &ObjectStore, name: &str, blob: Hash) -> Hash {
        let tree = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        });
        store.write(&serialize::serialize(&tree).unwrap()).unwrap()
    }

    fn put_file_commit(
        store: &ObjectStore,
        filename: &str,
        content: &[u8],
        parents: Vec<Hash>,
        author_mid: u64,
        ts: u64,
    ) -> Hash {
        let blob = put_blob(store, content);
        let tree = put_single_file_tree(store, filename, blob);
        let commit = Object::Commit(Commit::new_unannotated(
            tree,
            parents,
            Identity::opaque(author_mid.to_le_bytes()),
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
    fn blame_single_commit_attributes_all_lines_to_it() {
        let (_d, store) = fresh_store();
        let c = put_file_commit(&store, "f.txt", b"l1\nl2\nl3\n", vec![], 42, 1000);
        let r = blame_file(&store, c, "f.txt").unwrap();
        assert_eq!(r.lines.len(), 3);
        for (i, line) in r.lines.iter().enumerate() {
            assert_eq!(line.line_num, i + 1);
            assert_eq!(line.commit_hash, c);
            assert_eq!(line.timestamp, 1000);
            assert_eq!(line.author.kind, crate::object::IdentityKind::Opaque);
        }
        assert_eq!(r.lines[0].text, b"l1");
        assert_eq!(r.lines[1].text, b"l2");
        assert_eq!(r.lines[2].text, b"l3");
    }

    #[test]
    fn strip_ws_removes_all_whitespace() {
        assert_eq!(strip_ws(b"  foo(a,  b)\t"), b"foo(a,b)".to_vec());
        assert_eq!(strip_ws(b"abc"), b"abc".to_vec());
        assert_eq!(strip_ws(b" \t "), b"".to_vec());
    }

    #[test]
    fn blame_w_ignores_whitespace_only_change() {
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"foo(a, b)\nkeep\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"foo(a,b)\nkeep\n", vec![c_a], 2, 200);

        // Default: the whitespace-only edit reattributes line 1 to c_b.
        let plain = blame_file(&store, c_b, "f.txt").unwrap();
        assert_eq!(plain.lines[0].commit_hash, c_b);

        // -w: line 1 keeps c_a, but output still shows the current bytes.
        let opts = BlameOptions {
            ignore_whitespace: true,
        };
        let w = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(
            w.lines[0].commit_hash, c_a,
            "a whitespace-only change must not steal blame"
        );
        assert_eq!(
            w.lines[0].text, b"foo(a,b)",
            "output keeps the current bytes"
        );
        assert_eq!(w.lines[1].commit_hash, c_a);
    }

    #[test]
    fn blame_w_still_attributes_real_content_change() {
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"a\nb\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"a\nB CHANGED\n", vec![c_a], 2, 200);
        let opts = BlameOptions {
            ignore_whitespace: true,
        };
        let w = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(w.lines[0].commit_hash, c_a);
        assert_eq!(
            w.lines[1].commit_hash, c_b,
            "a non-whitespace change is still attributed normally under -w"
        );
    }

    #[test]
    fn blame_two_commits_with_modified_middle() {
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"a\nb\nc\n", vec![], 42, 1000);
        let c_b = put_file_commit(&store, "f.txt", b"a\nMOD\nc\n", vec![c_a], 42, 2000);
        let r = blame_file(&store, c_b, "f.txt").unwrap();
        assert_eq!(r.lines.len(), 3);
        assert_eq!(r.lines[0].commit_hash, c_a);
        assert_eq!(r.lines[1].commit_hash, c_b);
        assert_eq!(r.lines[2].commit_hash, c_a);
        assert_eq!(r.lines[1].text, b"MOD");
    }

    #[test]
    fn blame_three_commits_progressive_changes() {
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"a\nb\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"a\nb\nc\n", vec![c_a], 2, 200);
        let c_c = put_file_commit(&store, "f.txt", b"a\nX\nc\n", vec![c_b], 3, 300);
        let r = blame_file(&store, c_c, "f.txt").unwrap();
        assert_eq!(r.lines.len(), 3);
        assert_eq!(r.lines[0].commit_hash, c_a, "a from A");
        assert_eq!(r.lines[1].commit_hash, c_c, "X from C");
        assert_eq!(r.lines[2].commit_hash, c_b, "c from B");
    }

    #[test]
    fn blame_tracks_additions() {
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"a\nb\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"a\nNEW\nb\n", vec![c_a], 1, 200);
        let r = blame_file(&store, c_b, "f.txt").unwrap();
        assert_eq!(r.lines.len(), 3);
        assert_eq!(r.lines[0].commit_hash, c_a);
        assert_eq!(r.lines[1].commit_hash, c_b);
        assert_eq!(r.lines[2].commit_hash, c_a);
    }

    #[test]
    fn blame_tracks_deletions() {
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"a\nb\nc\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"a\nc\n", vec![c_a], 1, 200);
        let r = blame_file(&store, c_b, "f.txt").unwrap();
        assert_eq!(r.lines.len(), 2);
        assert_eq!(r.lines[0].commit_hash, c_a);
        assert_eq!(r.lines[1].commit_hash, c_a);
    }

    #[test]
    fn blame_file_not_found_returns_error() {
        let (_d, store) = fresh_store();
        let c = put_file_commit(&store, "real.txt", b"x\n", vec![], 1, 100);
        let err = blame_file(&store, c, "missing.txt").unwrap_err();
        assert!(matches!(err, BlameError::FileNotFound(_)));
    }

    #[test]
    fn lcs_identical_lines() {
        let lines: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let m = match_lines(&lines, &lines);
        assert_eq!(m, vec![Some(0), Some(1), Some(2)]);
    }

    #[test]
    fn lcs_completely_different() {
        let old: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let new: Vec<&[u8]> = vec![b"x", b"y", b"z"];
        let m = match_lines(&old, &new);
        assert_eq!(m, vec![None, None, None]);
    }

    #[test]
    fn split_lines_handles_trailing_newline() {
        assert_eq!(
            split_lines(b"a\nb\nc\n"),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[test]
    fn split_lines_handles_no_trailing_newline() {
        assert_eq!(
            split_lines(b"a\nb\nc"),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]
        );
    }

    #[test]
    fn split_lines_empty() {
        assert!(split_lines(b"").is_empty());
    }

    #[test]
    fn find_blob_in_nested_tree() {
        let (_d, store) = fresh_store();
        let blob = put_blob(&store, b"hello\n");
        let inner = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"main.txt".to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob,
            }],
        });
        let inner_h = store.write(&serialize::serialize(&inner).unwrap()).unwrap();
        let outer = Object::Tree(Tree {
            entries: vec![TreeEntry {
                name: b"src".to_vec(),
                mode: EntryMode::Tree,
                object_hash: inner_h,
            }],
        });
        let outer_h = store.write(&serialize::serialize(&outer).unwrap()).unwrap();
        let found = find_blob_in_tree(&store, outer_h, "src/main.txt").unwrap();
        assert_eq!(found, Some(blob));
        let missing = find_blob_in_tree(&store, outer_h, "src/none.txt").unwrap();
        assert_eq!(missing, None);
    }

    #[test]
    fn match_lines_rejects_oversize_inputs() {
        // G13 regression: the LCS DP table allocation is O(m*n). For
        // attacker-controlled blobs with millions of lines this means
        // gigabytes of heap. Cap both dimensions with BLAME_MAX_LINES
        // and return a FileTooLarge error rather than over-allocating.
        let n = super::BLAME_MAX_LINES + 1;
        let old: Vec<&[u8]> = vec![b"x"; n];
        let new: Vec<&[u8]> = vec![b"y"; 1];
        let err = super::match_lines_checked(&old, &new).unwrap_err();
        assert!(
            matches!(err, BlameError::FileTooLarge { lines } if lines == n),
            "got {err:?}"
        );

        let old2: Vec<&[u8]> = vec![b"a"; 1];
        let new2: Vec<&[u8]> = vec![b"b"; n];
        let err2 = super::match_lines_checked(&old2, &new2).unwrap_err();
        assert!(
            matches!(err2, BlameError::FileTooLarge { lines } if lines == n),
            "got {err2:?}"
        );
    }
}
