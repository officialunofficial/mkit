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

use std::collections::HashMap;
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
/// default (all-false / all-zero) reproduces [`blame_file`]'s exact-match
/// behavior; this struct is the extension point for the blame parity work
/// (`-w`, `-M`, `-C` today; ignore-revs / `--reverse` to follow).
#[derive(Debug, Clone, Copy, Default)]
pub struct BlameOptions {
    /// Ignore whitespace when matching a line against its parent
    /// revision, so a whitespace-only edit (reindent, tab↔space, spacing
    /// tweak) does not reattribute the line. Mirrors `git blame -w`,
    /// which ignores *all* whitespace, not just runs of it.
    pub ignore_whitespace: bool,
    /// Detect lines moved or copied **within the same file** (git `-M`):
    /// a contiguous block the line-matcher would call "new" but which
    /// appears verbatim elsewhere in the parent revision inherits that
    /// block's origin instead of the editing commit.
    pub detect_moves: bool,
    /// Detect lines copied **from other files** (git `-C`), as a level:
    /// `0` off; `1` searches files changed in the same commit; `2`+
    /// searches every file in the parent commit. Any level `>= 1` also
    /// enables [`Self::detect_moves`]. A copied block's origin is resolved
    /// by blaming the source file, matching git's attribution.
    pub copy_detection: u8,
    /// Minimum alphanumeric characters a moved block must contain for
    /// `-M` to credit it to the source (git's default is 20). A block
    /// below the threshold stays with the editing commit.
    pub move_threshold: usize,
    /// Like [`Self::move_threshold`] but for `-C` copies (git's default
    /// is 40).
    pub copy_threshold: usize,
}

impl BlameOptions {
    /// Move detection is on explicitly via `-M`, or implicitly because a
    /// copy level (`-C`) was requested — git's `-C` implies `-M`.
    fn moves_enabled(self) -> bool {
        self.detect_moves || self.copy_detection > 0
    }
}

/// A line's resolved origin: the commit that introduced it, with the
/// author/timestamp copied so the result is self-contained.
#[derive(Clone)]
struct Attribution {
    commit_hash: Hash,
    author: Identity,
    timestamp: u64,
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
// History walk + LCS attribution + the -M/-C resolution read most
// naturally as one linear pass; the pieces are factored into helpers below
// (`resolve_runs`, `copy_candidates`, …) but the spine stays here.
#[allow(clippy::too_many_lines)]
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

    // Move/copy (-M/-C) caches, shared across the whole blame and built
    // lazily — untouched when detection is off. `blob_lines`: a source
    // blob's ordered lines (for contiguous block matching). `origin`: per
    // (commit, path), a content→origin map produced by blaming the source
    // file, used to credit a copied block to its true author.
    let mut blob_lines_cache: HashMap<Hash, Vec<Vec<u8>>> = HashMap::new();
    let mut origin_cache: HashMap<(Hash, String), HashMap<Vec<u8>, Attribution>> = HashMap::new();

    // Boundary copy detection (-C): the file first appears at `oldest`, so
    // every line is credited there by default — but a block may have been
    // copied from *other* files in `oldest`'s parent (e.g. a new file split
    // out of an existing one). The forward walk can't see this (there is no
    // earlier version of *this* file), so resolve it against the parent.
    // No within-file `-M` source exists here, so only `-C` applies.
    let boundary_parent = if opts.copy_detection > 0 {
        commit_parent(store, oldest.commit_hash)?
    } else {
        None
    };
    if let Some(parent) = boundary_parent {
        let cands = copy_candidates(
            store,
            parent,
            oldest.commit_hash,
            file_path,
            opts.copy_detection,
        )?;
        resolve_runs(
            store,
            &oldest_lines,
            opts.ignore_whitespace,
            |_| true, // at the boundary every line is "unmatched"
            None,
            opts.move_threshold,
            opts.copy_detection,
            opts.copy_threshold,
            &cands,
            parent,
            &mut blob_lines_cache,
            &mut origin_cache,
            &mut attributions,
        )?;
    }

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
            // All matching policy (size guard, `-w` normalization,
            // tie-breaking) lives in the matcher; the replay below only
            // consumes the resulting mapping.
            let mapping = match_lines_with_options(&old_lines, &new_lines, *opts)?;

            // Provisional attribution: matched lines inherit the parent's
            // origin; unmatched lines are credited to `newer` until move
            // (-M) / copy (-C) detection reassigns them below.
            let newer_attr = Attribution {
                commit_hash: newer.commit_hash,
                author: newer.author.clone(),
                timestamp: newer.timestamp,
            };
            let mut new_attrs: Vec<Attribution> = (0..new_lines.len())
                .map(|ni| match mapping[ni] {
                    Some(oi) if oi < attributions.len() => attributions[oi].clone(),
                    _ => newer_attr.clone(),
                })
                .collect();

            if opts.moves_enabled() {
                let old_keys: Vec<Vec<u8>> = old_lines
                    .iter()
                    .map(|l| line_key(l, opts.ignore_whitespace))
                    .collect();
                let copy_cands = if opts.copy_detection > 0 {
                    copy_candidates(
                        store,
                        older.commit_hash,
                        newer.commit_hash,
                        file_path,
                        opts.copy_detection,
                    )?
                } else {
                    Vec::new()
                };
                resolve_runs(
                    store,
                    &new_lines,
                    opts.ignore_whitespace,
                    |ni| mapping[ni].is_none(),
                    Some((&old_keys, attributions.as_slice())),
                    opts.move_threshold,
                    opts.copy_detection,
                    opts.copy_threshold,
                    &copy_cands,
                    older.commit_hash,
                    &mut blob_lines_cache,
                    &mut origin_cache,
                    &mut new_attrs,
                )?;
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

/// Comparison key for a line under the active options: whitespace-stripped
/// when `-w` is set (so move detection agrees with the `-w` matcher),
/// otherwise the raw bytes.
fn line_key(line: &[u8], ignore_whitespace: bool) -> Vec<u8> {
    if ignore_whitespace {
        strip_ws(line)
    } else {
        line.to_vec()
    }
}

/// Reassign the origin of moved (`-M`) / copied (`-C`) blocks among the
/// lines the matcher left unmatched, writing into `out`.
///
/// Walks maximal runs of consecutive unmatched lines (per `is_unmatched`).
/// For each run, mirroring git:
/// 1. **`-M`** — if a within-file source is given and the run appears
///    verbatim as a contiguous block in it (keyed under `-w`), and the run
///    holds at least `move_threshold` alphanumeric characters, each line
///    inherits the matching source line's origin.
/// 2. **`-C`** — otherwise, if `copy_level > 0` and the run clears
///    `copy_threshold`, search the candidate files for the block; on a hit
///    each line is credited via the source file's blame (`origin_cache`).
///
/// A run that clears neither stays as `out` had it (the editing commit).
/// Detection is whole-run and first-match — a partial move inside a larger
/// insertion isn't split out (a documented simplification vs git's greedy
/// sub-block matching).
#[allow(clippy::too_many_arguments)]
fn resolve_runs(
    store: &ObjectStore,
    new_lines: &[Vec<u8>],
    ignore_whitespace: bool,
    is_unmatched: impl Fn(usize) -> bool,
    move_source: Option<(&[Vec<u8>], &[Attribution])>,
    move_threshold: usize,
    copy_level: u8,
    copy_threshold: usize,
    copy_cands: &[(String, Hash)],
    source_commit: Hash,
    blob_lines_cache: &mut HashMap<Hash, Vec<Vec<u8>>>,
    origin_cache: &mut HashMap<(Hash, String), HashMap<Vec<u8>, Attribution>>,
    out: &mut [Attribution],
) -> BlameOutcome<()> {
    // Keys for within-file matching: stripped under `-w`, raw otherwise.
    let new_keys: Vec<Vec<u8>> = new_lines
        .iter()
        .map(|l| line_key(l, ignore_whitespace))
        .collect();

    let mut ni = 0;
    while ni < new_lines.len() {
        if !is_unmatched(ni) {
            ni += 1;
            continue;
        }
        let start = ni;
        while ni < new_lines.len() && is_unmatched(ni) {
            ni += 1;
        }
        let run = start..ni;
        let alnum = block_alnum(new_lines, run.clone());

        // -M: contiguous block within the parent revision of this file.
        let moved =
            move_source
                .filter(|_| alnum >= move_threshold)
                .and_then(|(old_keys, old_attrs)| {
                    find_block(old_keys, &new_keys[run.clone()]).map(|oi| (oi, old_attrs))
                });
        if let Some((oi, old_attrs)) = moved {
            for (k, idx) in run.clone().enumerate() {
                if oi + k < old_attrs.len() {
                    out[idx] = old_attrs[oi + k].clone();
                }
            }
            continue;
        }

        // -C: contiguous block in another file changed in / present at the
        // parent commit.
        if copy_level > 0 && alnum >= copy_threshold {
            let needle = &new_lines[run.clone()];
            for (path, blob) in copy_cands {
                if !blob_lines_cache.contains_key(blob) {
                    let lines = load_blob_lines(store, *blob)?;
                    blob_lines_cache.insert(*blob, lines);
                }
                // Require the run to appear as a contiguous block in the
                // source (a real move/copy, not scattered coincidences);
                // attribution itself is per-line via the source's blame.
                if find_block(&blob_lines_cache[blob], needle).is_none() {
                    continue;
                }
                let key = (source_commit, path.clone());
                if !origin_cache.contains_key(&key) {
                    let map = source_origins(store, source_commit, path)?;
                    origin_cache.insert(key.clone(), map);
                }
                for idx in run.clone() {
                    if let Some(attr) = origin_cache[&key].get(&new_lines[idx]) {
                        out[idx] = attr.clone();
                    }
                }
                break;
            }
        }
    }
    Ok(())
}

/// First start index in `hay` where `needle` occurs as a contiguous run,
/// or `None`. Used to locate a moved/copied block in a source file.
fn find_block(hay: &[Vec<u8>], needle: &[Vec<u8>]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| hay[i..i + needle.len()] == needle[..])
}

/// Count ASCII-alphanumeric bytes across `lines[range]` — git's unit for
/// the `-M`/`-C` detection threshold.
fn block_alnum(lines: &[Vec<u8>], range: std::ops::Range<usize>) -> usize {
    lines[range]
        .iter()
        .flat_map(|l| l.iter())
        .filter(|b| b.is_ascii_alphanumeric())
        .count()
}

/// Build a content→origin map for `path` at `commit` by blaming it with
/// default options (so `-C` never recurses). First occurrence of each
/// line's content wins, mirroring git crediting the earliest source line.
fn source_origins(
    store: &ObjectStore,
    commit: Hash,
    path: &str,
) -> BlameOutcome<HashMap<Vec<u8>, Attribution>> {
    let res = blame_file_with(store, commit, path, &BlameOptions::default())?;
    let mut map: HashMap<Vec<u8>, Attribution> = HashMap::with_capacity(res.lines.len());
    for l in res.lines {
        map.entry(l.text).or_insert(Attribution {
            commit_hash: l.commit_hash,
            author: l.author,
            timestamp: l.timestamp,
        });
    }
    Ok(map)
}

/// Source files to search for copies, per git's `-C` level: level 1 =
/// files whose blob differs between the parent (`older`) and child
/// (`newer`) commit (the files "changed in the commit"); level >= 2 =
/// every file in the parent commit. The blamed path is always excluded.
fn copy_candidates(
    store: &ObjectStore,
    older: Hash,
    newer: Hash,
    target_path: &str,
    level: u8,
) -> BlameOutcome<Vec<(String, Hash)>> {
    let older_blobs = commit_blobs(store, older)?;
    if level >= 2 {
        return Ok(older_blobs
            .into_iter()
            .filter(|(p, _)| p != target_path)
            .collect());
    }
    let newer_blobs = commit_blobs(store, newer)?;
    let newer_map: HashMap<&str, Hash> =
        newer_blobs.iter().map(|(p, h)| (p.as_str(), *h)).collect();
    Ok(older_blobs
        .into_iter()
        .filter(|(p, h)| p != target_path && newer_map.get(p.as_str()) != Some(h))
        .collect())
}

/// First-parent of a commit, or `None` for a root commit.
fn commit_parent(store: &ObjectStore, commit: Hash) -> BlameOutcome<Option<Hash>> {
    let Object::Commit(c) = store.read_object(&commit)? else {
        return Err(BlameError::NotACommit);
    };
    Ok(c.parents.first().copied())
}

/// Every `(path, blob_hash)` reachable from a commit's tree.
fn commit_blobs(store: &ObjectStore, commit: Hash) -> BlameOutcome<Vec<(String, Hash)>> {
    let Object::Commit(c) = store.read_object(&commit)? else {
        return Err(BlameError::NotACommit);
    };
    let mut out = Vec::new();
    collect_tree_blobs(store, c.tree_hash, "", &mut out)?;
    Ok(out)
}

/// Recursively collect `(path, blob_hash)` for every blob under a tree.
/// Symlinks are skipped (not blamable content).
fn collect_tree_blobs(
    store: &ObjectStore,
    tree_hash: Hash,
    prefix: &str,
    out: &mut Vec<(String, Hash)>,
) -> BlameOutcome<()> {
    let Object::Tree(tree) = store.read_object(&tree_hash)? else {
        return Ok(());
    };
    for entry in tree.entries {
        let name = String::from_utf8_lossy(&entry.name);
        match entry.mode {
            EntryMode::Blob | EntryMode::Executable => {
                out.push((format!("{prefix}{name}"), entry.object_hash));
            }
            EntryMode::Tree => {
                let child_prefix = format!("{prefix}{name}/");
                collect_tree_blobs(store, entry.object_hash, &child_prefix, out)?;
            }
            EntryMode::Symlink => {}
        }
    }
    Ok(())
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
    // Rust's `is_ascii_whitespace` is space/\t/\n/\r/\x0C; git's xdiff
    // `isspace` also treats vertical tab (\x0B) as whitespace, so strip it
    // too to keep the parity claim exact. (\n is already stripped by the
    // line split, but include it for completeness.)
    line.iter()
        .copied()
        .filter(|b| !(b.is_ascii_whitespace() || *b == 0x0B))
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

/// Line-correspondence matcher used by the blame replay: given the parent
/// and child blob lines plus [`BlameOptions`], return for each child line
/// the matched parent index, or `None` if it is new/changed.
///
/// This is the **single, size-checked** matcher and the one place that
/// owns *matching policy* — the [`BLAME_MAX_LINES`] fast-fail (which is
/// also the only guard against the O(m·n) DP-table blow-up), `-w`
/// whitespace normalization, and the position-stable LCS tie-breaking —
/// so [`blame_file_with`] only has to replay the mapping. It is the
/// extension point for future matching modes.
///
/// # Errors
/// - [`BlameError::FileTooLarge`] if either side exceeds [`BLAME_MAX_LINES`].
fn match_lines_with_options(
    old_lines: &[Vec<u8>],
    new_lines: &[Vec<u8>],
    opts: BlameOptions,
) -> BlameOutcome<Vec<Option<usize>>> {
    // Size-check before the DP table (and before any derived per-line
    // buffers) so an oversized blob fails fast.
    check_line_count(old_lines.len())?;
    check_line_count(new_lines.len())?;
    if opts.ignore_whitespace {
        // Match on whitespace-stripped keys so a whitespace-only edit
        // pairs the lines; the caller still emits the raw bytes.
        let old_keys: Vec<Vec<u8>> = old_lines.iter().map(|l| strip_ws(l)).collect();
        let new_keys: Vec<Vec<u8>> = new_lines.iter().map(|l| strip_ws(l)).collect();
        Ok(match_lines(&old_keys, &new_keys))
    } else {
        Ok(match_lines(old_lines, new_lines))
    }
}

/// Reject a side whose line count would drive the O(m*n) DP table past
/// [`BLAME_MAX_LINES`]. Shared by the matcher (and reused for the size-cap
/// regression tests).
fn check_line_count(lines: usize) -> BlameOutcome<()> {
    if lines > BLAME_MAX_LINES {
        return Err(BlameError::FileTooLarge { lines });
    }
    Ok(())
}

/// LCS line matching. For each line in `new_lines`, returns the index
/// in `old_lines` it corresponds to, or `None` for inserted/changed.
///
/// NOTE: This function allocates an O(m*n) DP table with no size guard,
/// so it is kept private; all callers go through the size-checked
/// [`match_lines_with_options`] entry point.
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
    // Reconstruct via the dp relations rather than a greedy diagonal-first
    // rule. When `new[j-1]` isn't required for an optimal LCS
    // (`dp[i][j] == dp[i][j-1]`), leave it unmatched so that an *earlier*
    // equal line takes the match instead; likewise drop an unneeded
    // `old[i-1]`. Only when neither can be dropped is it a true diagonal
    // match. This keeps duplicate lines — and, under `-w`, lines that are
    // only whitespace-equal — position-stable, so a unchanged line keeps
    // its original commit while a genuinely new duplicate is attributed to
    // the newer one (matching git).
    while i > 0 && j > 0 {
        if dp[i][j] == dp[i][j - 1] {
            j -= 1;
        } else if dp[i][j] == dp[i - 1][j] {
            i -= 1;
        } else {
            mapping[j - 1] = Some(i - 1);
            i -= 1;
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

    /// Commit a set of `(filename, content)` files as one tree.
    fn put_multi_file_commit(
        store: &ObjectStore,
        files: &[(&str, &[u8])],
        parents: Vec<Hash>,
        author_mid: u64,
        ts: u64,
    ) -> Hash {
        let mut entries: Vec<TreeEntry> = files
            .iter()
            .map(|(name, content)| TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: put_blob(store, content),
            })
            .collect();
        // Tree entries are stored in name order; the store rejects any
        // other ordering on read.
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = store
            .write(&serialize::serialize(&Object::Tree(Tree { entries })).unwrap())
            .unwrap();
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

    // A line with 22 alphanumeric characters — comfortably over git's
    // default -M threshold of 20, so a move of it is detected.
    const LONG_LINE: &[u8] = b"let quick_brown_fox_total = 1;";
    // Two lines, 42 alphanumeric characters total — over git's default -C
    // threshold of 40, so a copy of the block is detected.
    const BLOCK_A: &[u8] = b"fn handler_alpha() { compute(); }";
    const BLOCK_B: &[u8] = b"fn handler_bravo() { compute(); }";

    #[test]
    fn blame_m_attributes_within_file_move_to_origin() {
        // A long line (>= the 20-char -M threshold) is moved to the end of
        // the file. Without -M the matcher calls it new (credit c_b); with
        // -M it inherits its origin (c_a), matching `git blame -M`.
        let (_d, store) = fresh_store();
        let v1 = [LONG_LINE, b"B", b"C", b""].join(&b'\n'); // trailing newline
        let v2 = [b"B" as &[u8], b"C", LONG_LINE, b""].join(&b'\n');
        let c_a = put_file_commit(&store, "f.txt", &v1, vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", &v2, vec![c_a], 2, 200);

        let plain = blame_file(&store, c_b, "f.txt").unwrap();
        assert_eq!(plain.lines[2].text, LONG_LINE);
        assert_eq!(
            plain.lines[2].commit_hash, c_b,
            "default: moved line is new"
        );

        let opts = BlameOptions {
            detect_moves: true,
            move_threshold: 20,
            ..Default::default()
        };
        let m = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(m.lines[2].text, LONG_LINE);
        assert_eq!(
            m.lines[2].commit_hash, c_a,
            "-M attributes the moved line to its origin"
        );
        assert!(
            m.lines.iter().all(|l| l.commit_hash == c_a),
            "every line predates c_b under -M"
        );
    }

    #[test]
    fn blame_m_ignores_moves_below_threshold() {
        // A short moved line (1 alnum char) is below the threshold, so even
        // with -M it stays on the editing commit — matching git, which does
        // not associate sub-threshold moves.
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"a\nB\nC\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"B\nC\na\n", vec![c_a], 2, 200);
        let opts = BlameOptions {
            detect_moves: true,
            move_threshold: 20,
            ..Default::default()
        };
        let m = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(m.lines[2].text, b"a");
        assert_eq!(
            m.lines[2].commit_hash, c_b,
            "a sub-threshold move is not detected"
        );
    }

    #[test]
    fn blame_c_attributes_copy_from_other_file_to_origin() {
        // c_a has a.txt = block + `zzz`; c_b removes the block from a.txt
        // and adds it to a brand-new b.txt (both files change in c_b).
        // Blaming b.txt with -C must credit the block to c_a, exercising the
        // boundary pass (b.txt has no parent version).
        let (_d, store) = fresh_store();
        let a1 = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let c_a = put_multi_file_commit(&store, &[("a.txt", &a1)], vec![], 1, 100);
        let bfile = [BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let c_b = put_multi_file_commit(
            &store,
            &[("a.txt", b"zzz\n"), ("b.txt", &bfile)],
            vec![c_a],
            2,
            200,
        );

        let plain = blame_file(&store, c_b, "b.txt").unwrap();
        assert_eq!(
            plain.lines[0].commit_hash, c_b,
            "default: copied block is new"
        );

        let opts = BlameOptions {
            copy_detection: 1,
            copy_threshold: 40,
            ..Default::default()
        };
        let c = blame_file_with(&store, c_b, "b.txt", &opts).unwrap();
        assert_eq!(c.lines[0].text, BLOCK_A);
        assert_eq!(c.lines[1].text, BLOCK_B);
        assert!(
            c.lines.iter().all(|l| l.commit_hash == c_a),
            "-C credits the copied block to its origin commit"
        );
    }

    #[test]
    fn blame_c_level1_skips_unchanged_files_until_level2() {
        // dst.txt copies a block verbatim from src.txt, which is NOT
        // modified in the copying commit. git `-C` (level 1) only searches
        // files changed in the commit, so it misses this; `-C -C` (level 2)
        // searches every parent file and finds it.
        let (_d, store) = fresh_store();
        let block = [BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let c_a = put_multi_file_commit(&store, &[("src.txt", &block)], vec![], 1, 100);
        let c_b = put_multi_file_commit(
            &store,
            &[("src.txt", &block), ("dst.txt", &block)],
            vec![c_a],
            2,
            200,
        );

        let l1 = BlameOptions {
            copy_detection: 1,
            copy_threshold: 40,
            ..Default::default()
        };
        let r1 = blame_file_with(&store, c_b, "dst.txt", &l1).unwrap();
        assert!(
            r1.lines.iter().all(|l| l.commit_hash == c_b),
            "-C level 1 ignores the unchanged source file"
        );

        let l2 = BlameOptions {
            copy_detection: 2,
            copy_threshold: 40,
            ..Default::default()
        };
        let r2 = blame_file_with(&store, c_b, "dst.txt", &l2).unwrap();
        assert!(
            r2.lines.iter().all(|l| l.commit_hash == c_a),
            "-C -C searches every parent file and finds the source"
        );
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
        // Vertical tab (\x0B) and form feed (\x0C) are whitespace to git's
        // xdiff `isspace`; strip both for parity.
        assert_eq!(strip_ws(b"a\x0Bb\x0Cc"), b"abc".to_vec());
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
            ..Default::default()
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
            ..Default::default()
        };
        let w = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(w.lines[0].commit_hash, c_a);
        assert_eq!(
            w.lines[1].commit_hash, c_b,
            "a non-whitespace change is still attributed normally under -w"
        );
    }

    #[test]
    fn blame_w_keeps_position_for_whitespace_equal_duplicate() {
        // Regression (PR #464 review P1): old `ab`, new `ab` + `a b`.
        // Stripping whitespace collapses both new lines to the key `ab`,
        // so a position-blind LCS would pair the *second* new line with
        // the old one and report line 1 as new — the reverse of git.
        // `git blame -w` keeps line 1 on the original commit and line 2 on
        // the new one; assert mkit matches.
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"ab\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"ab\na b\n", vec![c_a], 2, 200);
        let opts = BlameOptions {
            ignore_whitespace: true,
            ..Default::default()
        };
        let w = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(w.lines.len(), 2);
        assert_eq!(w.lines[0].commit_hash, c_a, "unchanged line 1 keeps c_a");
        assert_eq!(w.lines[1].commit_hash, c_b, "added line 2 is c_b");
        assert_eq!(w.lines[1].text, b"a b", "output keeps the current bytes");
    }

    #[test]
    fn blame_w_blank_line_duplicate_is_position_stable() {
        // The same duplicate-key hazard with blank lines (review P1 calls
        // it out explicitly): inserting a second blank line must credit the
        // *added* blank to the new commit and leave the original blank on
        // its commit, matching `git blame -w` (verified against real git).
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"x\n\ny\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"x\n\n\ny\n", vec![c_a], 2, 200);
        let opts = BlameOptions {
            ignore_whitespace: true,
            ..Default::default()
        };
        let w = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(w.lines.len(), 4);
        assert_eq!(w.lines[0].commit_hash, c_a, "x");
        assert_eq!(w.lines[1].commit_hash, c_a, "original blank");
        assert_eq!(w.lines[2].commit_hash, c_b, "added blank is new");
        assert_eq!(w.lines[3].commit_hash, c_a, "y");
    }

    #[test]
    fn blame_duplicate_line_addition_is_position_stable() {
        // Same stability property without `-w`: appending a genuine
        // duplicate of an existing line must attribute the *new* (second)
        // occurrence to the newer commit, not the first.
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"x\n", vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", b"x\nx\n", vec![c_a], 2, 200);
        let r = blame_file(&store, c_b, "f.txt").unwrap();
        assert_eq!(r.lines[0].commit_hash, c_a, "original line keeps c_a");
        assert_eq!(r.lines[1].commit_hash, c_b, "appended duplicate is c_b");
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
    fn lcs_duplicate_key_matches_earliest_new_line() {
        // One old line, two identical new lines: the matcher must pair the
        // *first* new line (the unchanged one) and leave the second as an
        // insertion, so blame keeps the original on line 1. A greedy
        // diagonal-first backtrack would instead pair the last occurrence.
        let old: Vec<&[u8]> = vec![b"ab"];
        let new: Vec<&[u8]> = vec![b"ab", b"ab"];
        assert_eq!(match_lines(&old, &new), vec![Some(0), None]);
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
        let opts = BlameOptions::default();
        let old: Vec<Vec<u8>> = vec![b"x".to_vec(); n];
        let new: Vec<Vec<u8>> = vec![b"y".to_vec(); 1];
        let err = super::match_lines_with_options(&old, &new, opts).unwrap_err();
        assert!(
            matches!(err, BlameError::FileTooLarge { lines } if lines == n),
            "got {err:?}"
        );

        let old2: Vec<Vec<u8>> = vec![b"a".to_vec(); 1];
        let new2: Vec<Vec<u8>> = vec![b"b".to_vec(); n];
        let err2 = super::match_lines_with_options(&old2, &new2, opts).unwrap_err();
        assert!(
            matches!(err2, BlameError::FileTooLarge { lines } if lines == n),
            "got {err2:?}"
        );
    }
}
