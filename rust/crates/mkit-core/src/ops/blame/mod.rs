//! Blame.
//!
//! Attributes each line of a file to the commit that introduced it. The walk
//! is **merge-aware** (git's default): it collects the file's ancestor
//! subgraph from the head commit, processes commits oldest → newest (parents
//! before children), and at a merge passes each line to the first parent
//! that still contains it — so a line merged in from a side branch is
//! credited to the commit that wrote it, not the merge.
//! [`BlameOptions::first_parent`] restricts the walk to first parents,
//! reproducing the older linear-history attribution. Reverse blame
//! ([`blame_file_reverse`]) is first-parent only by definition.
//!
//! Line matching uses a simple LCS DP table. For typical source files
//! (a few thousand lines) this is fine; binary blobs / generated code
//! are not in scope.
//!
//! Output formatting (used by goldens) is `<short>\t<line_num>\t<text>`,
//! where `<short>` is the 12-char prefix of the commit hash. See
//! [`format_blame_text`].

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::rc::Rc;
use std::sync::Arc;

use crate::hash::{self, Hash};
use crate::object::{EntryMode, Identity, Object};
use crate::store::ObjectStore;

mod move_copy;
mod walk;

use walk::{WalkCtx, attribute_commit, build_file_dag, topo_order};

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
    /// 1-based line number in the origin commit's version of the file —
    /// git porcelain's "original line number". Equals [`Self::line_num`]
    /// unless lines were inserted/removed above this one after it was
    /// introduced, or it was copied in from another file (then it is the
    /// line number in that source).
    pub orig_line_num: usize,
    /// Commit that last touched this line.
    pub commit_hash: Hash,
    /// Author Identity of `commit_hash`, deep-copied from the commit
    /// object so the result is self-contained.
    pub author: Identity,
    /// Commit timestamp.
    pub timestamp: u64,
    /// The origin commit is a file-history root (no relevant parent still
    /// has the file) — git porcelain's `boundary` marker.
    pub boundary: bool,
    /// Source file path when this line was copied from **another** file
    /// (`-C`); `None` when it lives in the blamed path. Feeds git
    /// porcelain's `filename` field.
    pub source_path: Option<String>,
    /// Final line text (no trailing newline).
    pub text: Vec<u8>,
}

/// Result of [`blame_file`]: per-line attributions in 1..=N order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlameResult {
    pub lines: Vec<BlameLine>,
}

/// Detect lines moved **within a file** (git `-M`). Each `On` state
/// carries its own threshold, so there is no way to express an invalid
/// "enabled but zero-threshold" state — [`Default`] is [`Off`].
///
/// [`Off`]: MoveDetection::Off
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MoveDetection {
    /// No within-file move detection.
    #[default]
    Off,
    /// Credit a moved block of at least `threshold` alphanumeric
    /// characters to its origin.
    On {
        /// Minimum alphanumeric characters for a block to qualify.
        threshold: usize,
    },
}

impl MoveDetection {
    /// git's default `-M` (threshold 20 alphanumeric characters).
    pub const GIT_DEFAULT: Self = Self::On { threshold: 20 };
}

/// Detect lines copied **from other files** (git `-C`). `On` carries a
/// search `level` (1 = files changed in the same commit; 2+ = every file
/// in the parent commit) and a `threshold`. [`Default`] is [`Off`].
///
/// [`Off`]: CopyDetection::Off
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CopyDetection {
    /// No cross-file copy detection.
    #[default]
    Off,
    /// Credit a copied block of at least `threshold` alphanumeric
    /// characters to its origin, searching at the given `level`.
    On {
        /// Search breadth: 1 = files changed in the commit; 2+ = every
        /// file in the parent commit.
        level: u8,
        /// Minimum alphanumeric characters for a block to qualify.
        threshold: usize,
    },
}

impl CopyDetection {
    /// git's default `-C` at the given level (threshold 40).
    #[must_use]
    pub const fn git_default(level: u8) -> Self {
        Self::On {
            level,
            threshold: 40,
        }
    }
}

/// Knobs controlling how [`blame_file_with`] attributes lines. The
/// default (no `-w`, detection off, empty ignore set) reproduces
/// [`blame_file`]'s exact-match behavior; this struct is the extension
/// point for the blame parity work (`-w`, `-M`, `-C`, ignore-revs today;
/// `--reverse` to follow).
///
/// Not `Copy`: [`Self::ignore_revs`] owns an `Arc`. It is passed by
/// reference (`&BlameOptions`) on the hot path; the `Arc` lets copy-source
/// blames share the same set without re-cloning it.
#[derive(Debug, Clone, Default)]
pub struct BlameOptions {
    /// Ignore whitespace when matching a line against its parent
    /// revision, so a whitespace-only edit (reindent, tab↔space, spacing
    /// tweak) does not reattribute the line. Mirrors `git blame -w`,
    /// which ignores *all* whitespace, not just runs of it.
    pub ignore_whitespace: bool,
    /// Within-file move detection (git `-M`).
    pub moves: MoveDetection,
    /// Cross-file copy detection (git `-C`). `On` implies move detection
    /// even when [`Self::moves`] is [`MoveDetection::Off`] — git's `-C`
    /// implies `-M`.
    pub copies: CopyDetection,
    /// Commits to skip during attribution, like `git blame --ignore-rev`
    /// / `--ignore-revs-file`. When a line would be credited to a commit
    /// in this set (a mass-reformat / license-header / rename "noise"
    /// commit), blame falls through to the previous commit that actually
    /// changed the line. A commit whose lines have no counterpart in its
    /// parent (a genuine insertion) stays on the ignored commit, matching
    /// git's default (no `blame.markUnblamableLines` marker).
    ///
    /// Behind an [`Arc`] so a `-C` copy-source blame can share the same set
    /// (it inherits the active ignore-revs) with an `O(1)` refcount bump
    /// rather than deep-cloning the whole set per source.
    pub ignore_revs: Arc<HashSet<Hash>>,
    /// Refine `--ignore-rev` fall-through with content matching instead of
    /// git's positional per-hunk guess (mkit-only, opt-in; no-op unless
    /// [`Self::ignore_revs`] is non-empty). git pairs a fallen-through line
    /// with whatever line sits at the same offset in the hunk, because a
    /// textual diff is all it has; mkit hashes line content, so it can
    /// often identify the line's *true* surviving origin even when a
    /// reformat/reorder moved it to a different offset — e.g. a
    /// moved-and-reindented line matched to its real origin rather than to
    /// whatever happens to sit at the same position.
    ///
    /// The refinement is **never worse than git's positional
    /// `--ignore-rev`, by construction**: a line whose positional guess is
    /// already a real parent line (`Some`) is only re-pointed when the
    /// content evidence is a *genuine moved block* — a run of ≥ 2
    /// file-adjacent lines matching contiguously — never for an isolated
    /// single-line key coincidence (which could otherwise land an edited
    /// line on an unrelated duplicate, strictly worse than positional). A
    /// line the positional pass left unattributed (`None` — a genuine
    /// insertion) may additionally be filled from a single exact-content
    /// match anywhere in the parent, since that only ever improves on
    /// "credited to the ignored commit". Trivial keys (blank lines,
    /// `}`-only lines, sub-3-byte tokens) are never reattributed. When no
    /// qualifying evidence exists the result is identical to the positional
    /// default, so every line is attributed at least as well as plain
    /// `--ignore-rev`.
    ///
    /// The default (`false`) keeps `--ignore-rev` byte-identical to git —
    /// this is a documented divergence, not a change to the default.
    pub ignore_rev_precise: bool,
    /// Follow only each commit's first parent, like `git blame
    /// --first-parent`. The default (`false`) is git's merge-aware walk:
    /// at a merge, a line is credited to whichever parent's side actually
    /// wrote it (the first parent that still contains it), so a line merged
    /// in from a side branch is attributed to its authoring commit rather
    /// than the merge. With `--first-parent`, the walk follows the
    /// first-parent chain only, so such a line is credited to the merge
    /// commit — the older linear-history behavior.
    pub first_parent: bool,
}

impl BlameOptions {
    /// The effective `-M` mode: explicit [`Self::moves`] if set, else the
    /// git default when copy detection is on (git's `-C` implies `-M`),
    /// else off.
    fn effective_move(&self) -> MoveDetection {
        match self.moves {
            MoveDetection::On { .. } => self.moves,
            MoveDetection::Off if matches!(self.copies, CopyDetection::On { .. }) => {
                MoveDetection::GIT_DEFAULT
            }
            MoveDetection::Off => MoveDetection::Off,
        }
    }

    /// Whether any move/copy detection is requested.
    fn detection_enabled(&self) -> bool {
        matches!(self.effective_move(), MoveDetection::On { .. })
            || matches!(self.copies, CopyDetection::On { .. })
    }

    /// Whether `commit` is in the [`Self::ignore_revs`] skip set.
    #[must_use]
    fn is_ignored(&self, commit: &Hash) -> bool {
        self.ignore_revs.contains(commit)
    }
}

/// A line's resolved origin: the commit that introduced it, with the
/// author/timestamp copied so the result is self-contained.
#[derive(Clone)]
struct Attribution {
    commit_hash: Hash,
    author: Identity,
    timestamp: u64,
    /// 1-based line number in the origin commit's version of the file
    /// (git porcelain's original line number). Propagates unchanged as the
    /// line is carried back through history.
    orig_line_num: usize,
    /// The origin commit is a file-history root (git porcelain `boundary`).
    boundary: bool,
    /// Set when this line was copied from another file (`-C`); the source
    /// path. `None` for a line living in the blamed path.
    source_path: Option<String>,
}

impl From<BlameLine> for Attribution {
    fn from(l: BlameLine) -> Self {
        Self {
            commit_hash: l.commit_hash,
            author: l.author,
            timestamp: l.timestamp,
            orig_line_num: l.orig_line_num,
            boundary: l.boundary,
            source_path: l.source_path,
        }
    }
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
    /// `--reverse`: the requested `<start>` is not a first-parent ancestor
    /// of `<end>`, so there is no forward chain to walk between them.
    #[error("reverse blame: '{start}' is not a first-parent ancestor of '{end}'")]
    ReverseRange { start: String, end: String },
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

/// Blame `file_path` at `head_hash`. Walks the file's ancestor subgraph in
/// topological order, attributing each line to the commit that introduced it.
/// The default is git's **merge-aware** walk (a line merged from a side branch
/// is credited to the commit that wrote it); [`BlameOptions::first_parent`]
/// restricts the walk to first parents. `opts` also tunes matching (`-w`,
/// `-M`/`-C`, `--ignore-rev`).
///
/// # Errors
/// - [`BlameError::FileNotFound`] if the file does not exist at `head_hash`.
/// - [`BlameError::NotACommit`] if `head_hash` is not a commit object.
/// - [`BlameError::FileTooLarge`] if any blob fed to the matcher has more than
///   [`BLAME_MAX_LINES`] lines.
///
/// # Note
/// The merge-aware walk processes the file's whole ancestor subgraph (every
/// merge parent that still has the file), so unlike git's backward queue —
/// which stops once every line is attributed — it can read the file's entire
/// history (potentially `O(all file-touching commits)`) even after the head's
/// lines are resolved. Per-commit attribution memos are `Rc`-shared and
/// released as soon as a commit's children are done, so peak memory stays
/// bounded; `--first-parent` is the escape hatch for very large histories. A
/// future optimization could prune to line-owning commits the way git's
/// backward blame queue does.
///
/// # Panics
/// Never in practice: the head commit is the last node in topological order
/// and is never another commit's parent, so its attribution memo is still
/// present when the result is materialized.
pub fn blame_file_with(
    store: &ObjectStore,
    head_hash: Hash,
    file_path: &str,
    opts: &BlameOptions,
) -> BlameOutcome<BlameResult> {
    // The head must contain the file (`FileNotFound` otherwise).
    let Object::Commit(head_commit) = store.read_object(&head_hash)? else {
        return Err(BlameError::NotACommit);
    };
    if find_blob_in_tree(store, head_commit.tree_hash, file_path)?.is_none() {
        return Err(BlameError::FileNotFound(file_path.to_string()));
    }

    let (nodes, children) = build_file_dag(store, head_hash, file_path, opts.first_parent)?;
    let order = topo_order(&nodes, head_hash);

    let ctx = WalkCtx {
        store,
        opts,
        nodes: &nodes,
        file_path,
    };
    // The detector owns its own caches and is a no-op when detection is off.
    let mut detector = move_copy::Detector::new(store, opts);
    let mut memo: HashMap<Hash, Rc<[Attribution]>> = HashMap::with_capacity(nodes.len());
    let mut remaining = children;

    for &commit in &order {
        let attrs = attribute_commit(&ctx, &memo, &mut detector, commit)?;
        memo.insert(commit, attrs);
        // Release a parent's memo once its last child has been attributed.
        for &parent in &nodes[&commit].parents {
            if let Some(left) = remaining.get_mut(&parent) {
                *left -= 1;
                if *left == 0 {
                    memo.remove(&parent);
                }
            }
        }
    }

    let head_attrs = memo
        .get(&head_hash)
        .expect("head is processed last and is never a parent, so never freed");
    let final_lines = load_blob_lines(store, nodes[&head_hash].blob_hash)?;
    let mut out = Vec::with_capacity(final_lines.len());
    for (i, text) in final_lines.into_iter().enumerate() {
        let a = &head_attrs[i];
        out.push(BlameLine {
            line_num: i + 1,
            orig_line_num: a.orig_line_num,
            commit_hash: a.commit_hash,
            author: a.author.clone(),
            timestamp: a.timestamp,
            boundary: a.boundary,
            source_path: a.source_path.clone(),
            text,
        });
    }
    Ok(BlameResult { lines: out })
}

/// One step of the reverse blame's forward chain: the commit and the blob
/// the path resolves to there (`None` if the file is absent at that commit).
struct ReverseEntry {
    commit_hash: Hash,
    blob: Option<Hash>,
    author: Identity,
    timestamp: u64,
}

impl From<&ReverseEntry> for Attribution {
    fn from(e: &ReverseEntry) -> Self {
        Self {
            commit_hash: e.commit_hash,
            author: e.author.clone(),
            timestamp: e.timestamp,
            // Reverse blame doesn't track porcelain origin fields; the
            // final `BlameLine` fills sensible defaults (orig = final line,
            // no boundary/copy). `-M`/`-C` are rejected under `--reverse`.
            orig_line_num: 0,
            boundary: false,
            source_path: None,
        }
    }
}

/// Collect the first-parent chain from `end` down to `start`, returned
/// **oldest-first** (`[0]` is `start`, last is `end`). Unlike forward blame
/// this does not stop where the file disappears — a gap in the file's
/// presence kills lines but must not truncate the walk before `start`.
///
/// # Errors
/// [`BlameError::ReverseRange`] if `start` is not reached on `end`'s
/// first-parent chain.
fn collect_reverse_chain(
    store: &ObjectStore,
    start_hash: Hash,
    end_hash: Hash,
    file_path: &str,
) -> BlameOutcome<Vec<ReverseEntry>> {
    let mut chain: Vec<ReverseEntry> = Vec::new();
    let mut current = Some(end_hash);
    let mut reached_start = false;
    while let Some(commit_hash) = current {
        let Object::Commit(commit) = store.read_object(&commit_hash)? else {
            return Err(BlameError::NotACommit);
        };
        let blob = find_blob_in_tree(store, commit.tree_hash, file_path)?;
        chain.push(ReverseEntry {
            commit_hash,
            blob,
            author: commit.author.clone(),
            timestamp: commit.timestamp,
        });
        if commit_hash == start_hash {
            reached_start = true;
            break;
        }
        current = commit.parents.first().copied();
    }
    if !reached_start {
        return Err(BlameError::ReverseRange {
            start: hash::to_hex(&start_hash),
            end: hash::to_hex(&end_hash),
        });
    }
    // Reorder to oldest-first so the caller can walk it forward.
    chain.reverse();
    Ok(chain)
}

/// Reverse blame (`git blame --reverse <start>..<end>`): instead of "which
/// commit introduced each line," answer "what is the **last** commit, in the
/// range, in which each line of `<start>` still existed."
///
/// The lines blamed (and the text in the output) are `<start>`'s version of
/// `file_path`. The range is followed along `<end>`'s **first-parent** chain
/// down to `<start>` (mkit blame is first-parent only, like its forward
/// pass), then walked **forward** (oldest → newest); each start line advances
/// its attribution to every commit it survives into, and freezes at the last
/// one before it is changed or removed. A line that does not survive even
/// the first step stays on `<start>` itself (git prints such a line with a
/// `^` boundary marker; mkit's tab format carries no `^`, matching its
/// existing boundary-marker omission). `opts` tunes matching, so `-w`
/// traces a line through a whitespace-only edit the same way it does for
/// forward blame.
///
/// Independent of `-M`/`-C` and `--ignore-rev`: reverse blame walks line
/// survival via the LCS matcher only, so those detection options do not
/// apply here (the CLI rejects the combination).
///
/// An empty range (`start_hash == end_hash`) has no step to walk, so every
/// line is attributed to `start`. git rejects an empty range outright; the
/// CLI does too (`resolve_reverse_range`), so this only surfaces for direct
/// core callers.
///
/// # Errors
/// - [`BlameError::ReverseRange`] if `<start>` is not a first-parent
///   ancestor of `<end>`.
/// - [`BlameError::FileNotFound`] if `file_path` does not exist at `<start>`.
/// - [`BlameError::NotACommit`] if either endpoint is not a commit.
/// - [`BlameError::FileTooLarge`] if any blob on the chain exceeds
///   [`BLAME_MAX_LINES`].
pub fn blame_file_reverse(
    store: &ObjectStore,
    start_hash: Hash,
    end_hash: Hash,
    file_path: &str,
    opts: &BlameOptions,
) -> BlameOutcome<BlameResult> {
    let chain = collect_reverse_chain(store, start_hash, end_hash, file_path)?;

    // The blamed content is `start`'s version of the file.
    let Some(start_blob) = chain[0].blob else {
        return Err(BlameError::FileNotFound(file_path.to_string()));
    };
    let start_lines = load_blob_lines(store, start_blob)?;
    check_line_count(start_lines.len())?;

    // For each start line, track its index in the *current* commit's blob
    // (`None` once the line is gone) and its last-seen attribution, which
    // begins at `start` and advances forward as the line survives.
    let mut cur_idx: Vec<Option<usize>> = (0..start_lines.len()).map(Some).collect();
    let mut attributions: Vec<Attribution> = vec![Attribution::from(&chain[0]); start_lines.len()];
    // Count of still-alive lines, so the dead-everything early-exit is O(1)
    // per step instead of rescanning `cur_idx`.
    let mut live = start_lines.len();

    let mut prev_blob = start_blob;
    let mut prev_lines = start_lines.clone();
    for entry in &chain[1..] {
        // Every start line is dead and a dead line never resurrects, so
        // there is nothing left to attribute — stop walking the range.
        if live == 0 {
            break;
        }
        let newer_attr = Attribution::from(entry);
        let Some(blob) = entry.blob else {
            // File absent here: every still-alive line is last seen at the
            // previous commit. Once dead a line never resurrects.
            cur_idx.fill(None);
            live = 0;
            continue;
        };
        if blob == prev_blob {
            // Unchanged file: every alive line survives and advances.
            for (j, c) in cur_idx.iter().enumerate() {
                if c.is_some() {
                    attributions[j] = newer_attr.clone();
                }
            }
            continue;
        }
        let new_lines = load_blob_lines(store, blob)?;
        // `mapping[ni]` = the prev-blob index that new line `ni` came from;
        // invert it to "where did each prev line go?".
        let mapping = match_lines_with_options(&prev_lines, &new_lines, opts)?;
        let mut prev_to_new: Vec<Option<usize>> = vec![None; prev_lines.len()];
        for (ni, m) in mapping.iter().enumerate() {
            if let Some(oi) = *m {
                prev_to_new[oi] = Some(ni);
            }
        }
        for (j, c) in cur_idx.iter_mut().enumerate() {
            if let Some(p) = *c {
                if let Some(q) = prev_to_new.get(p).copied().flatten() {
                    // Line survives into this commit: advance attribution.
                    *c = Some(q);
                    attributions[j] = newer_attr.clone();
                } else {
                    // Line is gone here: it was last seen at the previous
                    // commit, so its attribution stays put.
                    *c = None;
                    live -= 1;
                }
            }
        }
        prev_blob = blob;
        prev_lines = new_lines;
    }

    let mut out = Vec::with_capacity(start_lines.len());
    for (i, text) in start_lines.into_iter().enumerate() {
        let a = &attributions[i];
        out.push(BlameLine {
            line_num: i + 1,
            // Reverse blame has no origin-side line tracking; use the final
            // line number so porcelain still emits a coherent header.
            orig_line_num: i + 1,
            commit_hash: a.commit_hash,
            author: a.author.clone(),
            timestamp: a.timestamp,
            boundary: false,
            source_path: None,
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
            for ch in &cb.chunks {
                let chunk_obj = store.read_object(ch)?;
                let Object::Blob(b) = chunk_obj else {
                    return Err(BlameError::NotABlob);
                };
                buf.extend_from_slice(&b.data);
            }
            cb.check_reassembled_size(buf.len())?;
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

/// A content key with fewer than this many non-whitespace bytes is
/// "trivial" — blank lines, lone `}`/`)`, one- or two-character tokens —
/// and is never content-reattributed by `--ignore-rev-precise`, so such
/// lines don't "teleport" to a coincidental duplicate.
pub(super) const TRIVIAL_KEY_MIN_LEN: usize = 3;

/// Whether a line's content key is trivial for `--ignore-rev-precise`.
///
/// The length is measured on the **whitespace-stripped** form regardless of
/// the `-w` flag: `line_key` only strips whitespace under `-w`, so without
/// it a reindented `"    }"` is 5 raw bytes and would clear a naive
/// `key.len() < 3` guard — letting an indented brace teleport. Stripping for
/// the length check alone (the matching key itself is untouched) keeps the
/// guard honest either way.
pub(super) fn is_trivial_key(key: &[u8]) -> bool {
    strip_ws(key).len() < TRIVIAL_KEY_MIN_LEN
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
    opts: &BlameOptions,
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

/// For a step whose `newer` commit is *ignored* (`git blame
/// --ignore-rev`), map each new line to the parent line it should inherit
/// blame from instead of crediting the ignored commit.
///
/// `mapping` is the LCS result (new index → matched old index, or `None`).
/// The matched anchors split both sides into hunks; within each hunk — a
/// maximal run of unmatched new lines bounded by anchors — the k-th
/// unmatched new line is paired positionally with the k-th unmatched old
/// line in the same hunk. A new line with no counterpart (the hunk added
/// more lines than it removed) is left `None`, so the caller keeps it on
/// the ignored commit. This reproduces git's `guess_line_blames` for the
/// reformat case and its fall-through to unmatched insertions; verified
/// field-by-field against real `git blame --ignore-rev`.
fn ignore_fallthrough(mapping: &[Option<usize>], old_len: usize) -> Vec<Option<usize>> {
    let n = mapping.len();
    let mut fall: Vec<Option<usize>> = vec![None; n];
    // `next_old` is the first old index not yet consumed by an anchor; the
    // unmatched old lines of the current hunk are `[next_old, hunk_end)`,
    // where `hunk_end` is the old index of the anchor closing the hunk (or
    // `old_len` for a trailing hunk).
    let mut next_old = 0usize;
    let mut ni = 0usize;
    while ni < n {
        let Some(anchor_old) = mapping[ni] else {
            // Start of an unmatched-new run; find where it ends.
            let hunk_new_start = ni;
            while ni < n && mapping[ni].is_none() {
                ni += 1;
            }
            // The closing anchor's old index bounds this hunk's unmatched
            // old lines (`old_len` for a trailing hunk). The loop exits a run
            // only at a matched anchor, and LCS anchors are increasing, so
            // this is always `>= next_old`.
            let hunk_old_end = mapping.get(ni).copied().flatten().unwrap_or(old_len);
            // Pair the unmatched old lines `[next_old, hunk_old_end)` with
            // the unmatched new lines positionally; extras stay unpaired.
            let mut oi = next_old;
            let mut nj = hunk_new_start;
            while nj < ni && oi < hunk_old_end {
                fall[nj] = Some(oi);
                nj += 1;
                oi += 1;
            }
            next_old = hunk_old_end;
            continue;
        };
        // Anchor: it consumes old index `anchor_old`; the next hunk's
        // unmatched old lines begin just after it.
        next_old = anchor_old + 1;
        ni += 1;
    }
    fall
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

    /// SPEC-OBJECTS §7: "The concatenated length MUST equal `total_size`."
    /// Blame loads file content through chunked-blob reassembly, which
    /// must reject a manifest whose forged `total_size` disagrees with
    /// its (valid) chunks.
    #[test]
    fn blame_rejects_chunked_total_size_mismatch() {
        let (_d, store) = fresh_store();
        let chunk = put_blob(&store, b"one line\n");
        let cb = Object::ChunkedBlob(crate::object::ChunkedBlob {
            total_size: 4096,
            chunk_size: 0,
            chunks: vec![chunk],
        });
        let cb_h = store.write(&serialize::serialize(&cb).unwrap()).unwrap();
        let tree = put_single_file_tree(&store, "big.bin", cb_h);
        let commit = Object::Commit(Commit::new_unannotated(
            tree,
            vec![],
            Identity::opaque(1u64.to_le_bytes()),
            [0u8; 32],
            b"msg".to_vec(),
            100,
            [0u8; 64],
        ));
        let head = store
            .write(&serialize::serialize(&commit).unwrap())
            .unwrap();
        let err = blame_file(&store, head, "big.bin").unwrap_err();
        assert!(
            matches!(
                err,
                BlameError::Object(crate::object::MkitError::ChunkedBlobSizeMismatch {
                    expected: 4096,
                    actual: 9,
                })
            ),
            "expected ChunkedBlobSizeMismatch, got {err:?}"
        );
    }

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
            moves: MoveDetection::On { threshold: 20 },
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
    fn blame_m_threshold_boundary_is_inclusive() {
        // Boundary: git's `-M<n>` is a *lower bound* (n-or-more alnum
        // chars), so a block of exactly the threshold is detected and one
        // char short is not. `exact` has exactly 20 alnum chars, `short` 19.
        // They are kept non-adjacent (separated by anchors / a new line) so
        // each is an independent single-line block, not one merged block.
        // Verified against real `git blame -M`.
        let (_d, store) = fresh_store();
        let exact: &[u8] = b"abcdefghijklmnopqrst"; // 20 alnum
        let short: &[u8] = b"abcdefghijklmnopqrs"; // 19 alnum
        let v1 = [exact, b"MID", short, b"B", b"C", b""].join(&b'\n');
        let v2 = [b"B" as &[u8], b"C", exact, b"NEWX", short, b""].join(&b'\n');
        let c_a = put_file_commit(&store, "f.txt", &v1, vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", &v2, vec![c_a], 2, 200);

        let opts = BlameOptions {
            moves: MoveDetection::On { threshold: 20 },
            ..Default::default()
        };
        let m = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        // Child order: B, C, exact, NEWX, short.
        assert_eq!(m.lines[2].text, exact);
        assert_eq!(
            m.lines[2].commit_hash, c_a,
            "exactly-threshold (20) move is detected (>= is inclusive)"
        );
        assert_eq!(m.lines[4].text, short);
        assert_eq!(
            m.lines[4].commit_hash, c_b,
            "one char short of the threshold stays on the editing commit"
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
            moves: MoveDetection::On { threshold: 20 },
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
    fn blame_m_detects_sub_block_move_adjacent_to_new_line() {
        // Review P1: a moved block sitting next to a genuinely-new line.
        // Parent: LONG1, LONG2, B, C. Child: B, C, NEW, LONG1, LONG2.
        // git -M credits LONG1/LONG2 to the parent and keeps NEW on the
        // child; whole-run matching would miss it (the run NEW+LONG1+LONG2
        // isn't contiguous in the parent). Verified against real git.
        let (_d, store) = fresh_store();
        let v1 = [LONG_LINE, BLOCK_A, b"B", b"C", b""].join(&b'\n');
        let v2 = [b"B" as &[u8], b"C", b"NEWLINE", LONG_LINE, BLOCK_A, b""].join(&b'\n');
        let c_a = put_file_commit(&store, "f.txt", &v1, vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", &v2, vec![c_a], 2, 200);

        let opts = BlameOptions {
            moves: MoveDetection::On { threshold: 20 },
            ..Default::default()
        };
        let m = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        // Child order: B, C, NEWLINE, LONG1, BLOCK_A.
        assert_eq!(m.lines[2].text, b"NEWLINE");
        assert_eq!(
            m.lines[2].commit_hash, c_b,
            "the genuinely-new line stays on c_b"
        );
        assert_eq!(m.lines[3].text, LONG_LINE);
        assert_eq!(
            m.lines[3].commit_hash, c_a,
            "the moved block reverts to c_a"
        );
        assert_eq!(
            m.lines[4].commit_hash, c_a,
            "…including the second moved line"
        );
    }

    #[test]
    fn blame_w_c_detects_copy_with_whitespace_change() {
        // Review P1: a block copied into a new file *with a reindent*.
        // Under plain -C the changed whitespace hides the copy; under
        // -w -C it must still be credited to the origin commit. Verified
        // against real `git blame -w -C`.
        let (_d, store) = fresh_store();
        let a1 = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let c_a = put_multi_file_commit(&store, &[("a.txt", &a1)], vec![], 1, 100);
        // b.txt copies the block but reindents each line.
        let reindented = {
            let mut v = Vec::new();
            v.extend_from_slice(b"    ");
            v.extend_from_slice(BLOCK_A);
            v.push(b'\n');
            v.extend_from_slice(b"    ");
            v.extend_from_slice(BLOCK_B);
            v.push(b'\n');
            v
        };
        let c_b = put_multi_file_commit(
            &store,
            &[("a.txt", b"zzz\n"), ("b.txt", &reindented)],
            vec![c_a],
            2,
            200,
        );

        // Plain -C: the reindent hides the copy; lines stay on c_b.
        let plain_c = BlameOptions {
            copies: CopyDetection::On {
                level: 1,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, c_b, "b.txt", &plain_c).unwrap();
        assert!(
            r.lines.iter().all(|l| l.commit_hash == c_b),
            "without -w a reindented copy is not detected"
        );

        // -w -C: normalized keys see through the reindent → credit c_a.
        let w_c = BlameOptions {
            ignore_whitespace: true,
            copies: CopyDetection::On {
                level: 1,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, c_b, "b.txt", &w_c).unwrap();
        assert!(
            r.lines.iter().all(|l| l.commit_hash == c_a),
            "-w -C credits a reindented copy to its origin"
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
            copies: CopyDetection::On {
                level: 1,
                threshold: 40,
            },
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
            copies: CopyDetection::On {
                level: 1,
                threshold: 40,
            },
            ..Default::default()
        };
        let r1 = blame_file_with(&store, c_b, "dst.txt", &l1).unwrap();
        assert!(
            r1.lines.iter().all(|l| l.commit_hash == c_b),
            "-C level 1 ignores the unchanged source file"
        );

        let l2 = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r2 = blame_file_with(&store, c_b, "dst.txt", &l2).unwrap();
        assert!(
            r2.lines.iter().all(|l| l.commit_hash == c_a),
            "-C -C searches every parent file and finds the source"
        );
    }

    #[test]
    fn blame_w_c_credits_copy_through_prior_whitespace_edit() {
        // Review P1: the copy *source* must be blamed with the active `-w`,
        // so a copied block traces through a prior whitespace-only edit in
        // the source file. d1 = indented block; d2 dedents it (ws-only); d3
        // copies it to b.txt. `git blame -w -C` credits d1, not the d2
        // reformat. (With BlameOptions::default() for the source blame this
        // wrongly credited d2.) Verified against real git.
        let (_d, store) = fresh_store();
        let indented = {
            let mut v = Vec::new();
            for b in [BLOCK_A, BLOCK_B] {
                v.extend_from_slice(b"    ");
                v.extend_from_slice(b);
                v.push(b'\n');
            }
            v.extend_from_slice(b"zzz\n");
            v
        };
        let d1 = put_multi_file_commit(&store, &[("a.txt", &indented)], vec![], 1, 100);
        let dedented = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let d2 = put_multi_file_commit(&store, &[("a.txt", &dedented)], vec![d1], 2, 200);
        let block = [BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let d3 = put_multi_file_commit(
            &store,
            &[("a.txt", b"zzz\n"), ("b.txt", &block)],
            vec![d2],
            3,
            300,
        );

        let opts = BlameOptions {
            ignore_whitespace: true,
            copies: CopyDetection::On {
                level: 1,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, d3, "b.txt", &opts).unwrap();
        assert!(
            r.lines.iter().all(|l| l.commit_hash == d1),
            "the source blame keeps -w → credits the original, not the reformat"
        );
    }

    #[test]
    fn blame_c_credits_copy_through_prior_same_file_move() {
        // Review P1: the copy *source* must be blamed with the implied `-M`,
        // so a copied block traces through a prior same-file move in the
        // source. d1 = block then X,Y; d2 moves the block below X,Y; d3
        // copies it to b.txt. `git blame -C` credits d1, not the d2 move.
        // (With BlameOptions::default() this wrongly credited d2.) Verified
        // against real git.
        let (_d, store) = fresh_store();
        let v1 = [BLOCK_A, BLOCK_B, b"X", b"Y", b""].join(&b'\n');
        let d1 = put_multi_file_commit(&store, &[("a.txt", &v1)], vec![], 1, 100);
        let v2 = [b"X" as &[u8], b"Y", BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let d2 = put_multi_file_commit(&store, &[("a.txt", &v2)], vec![d1], 2, 200);
        let block = [BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let d3 = put_multi_file_commit(
            &store,
            &[("a.txt", b"X\nY\n"), ("b.txt", &block)],
            vec![d2],
            3,
            300,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 1,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, d3, "b.txt", &opts).unwrap();
        assert!(
            r.lines.iter().all(|l| l.commit_hash == d1),
            "the source blame keeps implied -M → credits the original, not the move"
        );
    }

    #[test]
    fn blame_c_alone_implies_within_file_m() {
        // Review test gap: `-C` with `moves: Off` must still detect a
        // within-file move (git's `-C` implies `-M`), via effective_move()
        // returning GIT_DEFAULT. A long block moved within the *blamed*
        // file is credited to its origin with only copies set.
        let (_d, store) = fresh_store();
        let v1 = [LONG_LINE, BLOCK_A, b"B", b"C", b""].join(&b'\n');
        let v2 = [b"B" as &[u8], b"C", LONG_LINE, BLOCK_A, b""].join(&b'\n');
        let c_a = put_file_commit(&store, "f.txt", &v1, vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", &v2, vec![c_a], 2, 200);

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 1,
                threshold: 40,
            },
            ..Default::default() // moves: Off — the implication is under test
        };
        let m = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(m.lines[2].text, LONG_LINE);
        assert_eq!(
            m.lines[2].commit_hash, c_a,
            "-C implies -M, so the within-file move reverts to its origin"
        );
    }

    #[test]
    fn blame_m_many_single_line_moves_no_stack_overflow() {
        // Review P1 (#2): N independent single-line moves used to recurse N
        // deep. With the work-stack it must just complete. Reverse 400 long,
        // distinct lines: each is its own move block, so all revert to c_a.
        let (_d, store) = fresh_store();
        let lines: Vec<String> = (0..400)
            .map(|i| format!("let unique_symbol_number_{i:05} = compute({i});"))
            .collect();
        let mut v1 = lines.join("\n");
        v1.push('\n');
        let mut rev: Vec<&str> = lines.iter().map(String::as_str).collect();
        rev.reverse();
        let mut v2 = rev.join("\n");
        v2.push('\n');
        let c_a = put_file_commit(&store, "f.txt", v1.as_bytes(), vec![], 1, 100);
        let c_b = put_file_commit(&store, "f.txt", v2.as_bytes(), vec![c_a], 2, 200);

        let opts = BlameOptions {
            moves: MoveDetection::On { threshold: 20 },
            ..Default::default()
        };
        let m = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(m.lines.len(), 400);
        assert!(
            m.lines.iter().all(|l| l.commit_hash == c_a),
            "every reordered long line is a move → all revert to c_a"
        );
    }

    #[test]
    fn blame_m_large_new_block_terminates() {
        // Review P1 (#1): a large genuinely-new block with no move/copy
        // match must not blow up the (previously cubic) search. 3000 new,
        // distinct lines that appear in no source: all stay on the editing
        // commit, and the call returns promptly via the source key-index.
        use std::fmt::Write as _;
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"seed\n", vec![], 1, 100);
        let mut v2 = String::from("seed\n");
        for i in 0..3000 {
            let _ = writeln!(v2, "brand_new_distinct_line_number_{i:06}");
        }
        let c_b = put_file_commit(&store, "f.txt", v2.as_bytes(), vec![c_a], 2, 200);

        let opts = BlameOptions {
            moves: MoveDetection::On { threshold: 20 },
            ..Default::default()
        };
        let m = blame_file_with(&store, c_b, "f.txt", &opts).unwrap();
        assert_eq!(m.lines.len(), 3001);
        assert_eq!(m.lines[0].commit_hash, c_a, "the seed line is unchanged");
        assert!(
            m.lines[1..].iter().all(|l| l.commit_hash == c_b),
            "the large new block stays on the editing commit"
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

    /// Convenience: a `BlameOptions` that ignores the given commits with
    /// `--ignore-rev-precise` on, `-w` (content matching needs `-w` to
    /// agree with the matcher the same way `-M`/`-C` do).
    fn ignoring_precise(revs: &[Hash]) -> BlameOptions {
        BlameOptions {
            ignore_revs: Arc::new(revs.iter().copied().collect()),
            ignore_rev_precise: true,
            ignore_whitespace: true,
            ..Default::default()
        }
    }

    /// Convenience: a `BlameOptions` that ignores the given commits.
    fn ignoring(revs: &[Hash]) -> BlameOptions {
        BlameOptions {
            ignore_revs: Arc::new(revs.iter().copied().collect()),
            ..Default::default()
        }
    }

    #[test]
    fn blame_ignore_rev_falls_through_reformat() {
        // A reformat commit (changes a line's bytes only) is ignored, so
        // its line falls through to the commit that owns the parent line —
        // but the output still shows the reformatted bytes. Mirrors
        // `git blame --ignore-rev <reformat>` (verified against real git).
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"alpha\nbeta\ngamma\n", vec![], 1, 100);
        let c_b = put_file_commit(
            &store,
            "f.txt",
            b"alpha\n  beta  \ngamma\n",
            vec![c_a],
            2,
            200,
        );

        // Without ignore: the reformat steals line 2.
        let plain = blame_file(&store, c_b, "f.txt").unwrap();
        assert_eq!(plain.lines[1].commit_hash, c_b);

        let r = blame_file_with(&store, c_b, "f.txt", &ignoring(&[c_b])).unwrap();
        assert_eq!(
            r.lines[1].commit_hash, c_a,
            "ignored reformat falls through to the original commit"
        );
        assert_eq!(r.lines[1].text, b"  beta  ", "output keeps current bytes");
        assert!(
            r.lines.iter().all(|l| l.commit_hash == c_a),
            "no line is credited to the ignored commit"
        );
    }

    #[test]
    fn blame_ignore_rev_keeps_genuine_insertion() {
        // A line genuinely *added* by the ignored commit has no counterpart
        // in the parent, so git leaves it on the ignored commit (no
        // `blame.markUnblamableLines` marker by default). Verified against
        // real `git blame --ignore-rev`.
        let (_d, store) = fresh_store();
        let c_a = put_file_commit(&store, "f.txt", b"alpha\nbeta\n", vec![], 1, 100);
        let c_b = put_file_commit(
            &store,
            "f.txt",
            b"alpha\nbeta\nBRANDNEW\ngamma\n",
            vec![c_a],
            2,
            200,
        );

        let r = blame_file_with(&store, c_b, "f.txt", &ignoring(&[c_b])).unwrap();
        assert_eq!(r.lines[0].commit_hash, c_a, "alpha");
        assert_eq!(r.lines[1].commit_hash, c_a, "beta");
        assert_eq!(
            r.lines[2].commit_hash, c_b,
            "a genuine insertion stays on the ignored commit"
        );
        assert_eq!(r.lines[3].commit_hash, c_b, "…and the second insertion");
    }

    #[test]
    fn blame_ignore_rev_pairs_changed_lines_to_distinct_origins() {
        // Two adjacent changed lines in the ignored commit pair positionally
        // with their two parent lines, which have *different* origins: the
        // first parent line came from c2, the second from c1. git credits
        // each fallen-through line to its own parent's origin (verified).
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"L1\nL2\nL3\nL4\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"L1\nL2x\nL3\nL4\n", vec![c1], 2, 200);
        let c3 = put_file_commit(&store, "f.txt", b"L1\nL2y\nL3y\nL4\n", vec![c2], 3, 300);

        let r = blame_file_with(&store, c3, "f.txt", &ignoring(&[c3])).unwrap();
        assert_eq!(r.lines[1].commit_hash, c2, "L2y inherits L2x's origin (c2)");
        assert_eq!(r.lines[2].commit_hash, c1, "L3y inherits L3's origin (c1)");
        assert!(r.lines.iter().all(|l| l.commit_hash != c3));
    }

    #[test]
    fn blame_ignore_rev_unequal_hunk_more_added() {
        // 1 line removed, 2 added in the ignored commit: the *first* added
        // line pairs with the removed line (falls through); the extra added
        // line stays on the ignored commit. Verified against real git.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"L1\nMID\nL3\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"L1\nMIDa\nMIDb\nL3\n", vec![c1], 2, 200);

        let r = blame_file_with(&store, c2, "f.txt", &ignoring(&[c2])).unwrap();
        assert_eq!(r.lines[1].commit_hash, c1, "MIDa falls through to c1");
        assert_eq!(r.lines[2].commit_hash, c2, "MIDb has no pair → stays on c2");
    }

    #[test]
    fn blame_ignore_rev_unequal_hunk_more_removed() {
        // 2 removed, 1 added: the single added line pairs with the *first*
        // removed line; the extra removed line simply vanishes. Verified.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"L1\nM1\nM2\nL3\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"L1\nMERGED\nL3\n", vec![c1], 2, 200);

        let r = blame_file_with(&store, c2, "f.txt", &ignoring(&[c2])).unwrap();
        assert_eq!(r.lines[1].commit_hash, c1, "MERGED falls through to c1");
    }

    #[test]
    fn blame_ignore_root_commit_keeps_its_lines() {
        // Ignoring the oldest commit in the walk: its lines have no parent
        // version of the file to fall through to, so they stay on it —
        // matching `git blame --ignore-rev <root>`.
        let (_d, store) = fresh_store();
        let root = put_file_commit(&store, "f.txt", b"a\nb\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"a\nb\nc\n", vec![root], 2, 200);

        let r = blame_file_with(&store, c2, "f.txt", &ignoring(&[root])).unwrap();
        assert_eq!(r.lines[0].commit_hash, root, "a stays on the ignored root");
        assert_eq!(r.lines[1].commit_hash, root, "b stays on the ignored root");
        assert_eq!(r.lines[2].commit_hash, c2, "c is unaffected");
    }

    #[test]
    fn blame_ignore_multiple_revs_chains_through() {
        // Two stacked reformats, both ignored: line falls through both to
        // the original author.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"keep\nx\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"keep\n x \n", vec![c1], 2, 200);
        let c3 = put_file_commit(&store, "f.txt", b"keep\n  x  \n", vec![c2], 3, 300);

        let r = blame_file_with(&store, c3, "f.txt", &ignoring(&[c2, c3])).unwrap();
        assert_eq!(
            r.lines[1].commit_hash, c1,
            "line falls through both ignored reformats to c1"
        );
    }

    #[test]
    fn blame_ignore_rev_fallthrough_not_overwritten_by_move_detection() {
        // Review: `--ignore-rev` + `-M`. An ignored commit replaces the last
        // line (`x`) in place with a duplicate of the first line (`dup`,
        // >= 20 alnum). The trailing hunk is 1-for-1, so ignore-rev
        // fallthrough pairs the new line with the *replaced* parent line
        // (`x`, origin c1). But `dup`'s key also appears at line 0 of the
        // parent, so the move detector *would* credit it to `dup`'s origin
        // (c0). Fallthrough must win: detection runs only on lines it did
        // not resolve.
        let (_d, store) = fresh_store();
        let dup: &[u8] = b"dupaaaaaaaaaaaaaaaaa"; // 20 alnum
        let mid: &[u8] = b"MIDLINE";
        let x_v0: &[u8] = b"exoldbbbbbbbbbbbbbbb";
        let x_v1: &[u8] = b"exnewbbbbbbbbbbbbbbb";
        let c0 = put_file_commit(
            &store,
            "f.txt",
            &[dup, mid, x_v0, b""].join(&b'\n'),
            vec![],
            1,
            100,
        );
        // c1 changes the last line (origin → c1); `dup`/`mid` keep origin c0.
        let c1 = put_file_commit(
            &store,
            "f.txt",
            &[dup, mid, x_v1, b""].join(&b'\n'),
            vec![c0],
            2,
            200,
        );
        // c2 (ignored) replaces the last line with a duplicate of `dup`.
        let c2 = put_file_commit(
            &store,
            "f.txt",
            &[dup, mid, dup, b""].join(&b'\n'),
            vec![c1],
            3,
            300,
        );

        let opts = BlameOptions {
            moves: MoveDetection::On { threshold: 20 },
            ignore_revs: Arc::new([c2].into_iter().collect()),
            ..Default::default()
        };
        let r = blame_file_with(&store, c2, "f.txt", &opts).unwrap();
        assert_eq!(
            r.lines[2].commit_hash, c1,
            "fallthrough (replaced parent line → c1) wins; -M does not overwrite it to c0"
        );
        // Sanity: plain --ignore-rev (no -M) gives the same line-2 origin.
        let plain = blame_file_with(&store, c2, "f.txt", &ignoring(&[c2])).unwrap();
        assert_eq!(
            plain.lines[2].commit_hash, c1,
            "-M did not change the result"
        );
    }

    // --- `--ignore-rev-precise` (#496) ---------------------------------

    #[test]
    fn blame_ignore_rev_precise_reattributes_moved_reindented_lines() {
        // A reformat commit reorders three distinct-origin lines and
        // reindents them. Under -w the LCS matcher recognizes ZZZ as
        // unchanged content wherever it landed and matches it directly
        // (so it needs no fall-through at all: LCS itself is already
        // content-aware for an exact, if relocated, match). That leaves
        // YYY and XXX with NO positional counterpart in their own
        // hunk — git's `--ignore-rev` treats them as genuine insertions
        // and credits them to the noise commit itself.
        // `--ignore-rev-precise` searches the parent's unmatched lines
        // across the WHOLE file (not just the enclosing hunk), so it finds
        // YYY's and XXX's true origins even though the positional pass
        // found no local candidate for either. Not pinned against git — no
        // git equivalent exists; documented mkit-only divergence (#496).
        let (_d, store) = fresh_store();
        let c0 = put_file_commit(&store, "f.txt", b"keep\ntail\n", vec![], 1, 100);
        let c1 = put_file_commit(&store, "f.txt", b"keep\nXXX\ntail\n", vec![c0], 2, 200);
        let c2 = put_file_commit(&store, "f.txt", b"keep\nXXX\nYYY\ntail\n", vec![c1], 3, 300);
        let c3 = put_file_commit(
            &store,
            "f.txt",
            b"keep\nXXX\nYYY\nZZZ\ntail\n",
            vec![c2],
            4,
            400,
        );
        let c4 = put_file_commit(
            &store,
            "f.txt",
            b"keep\n  ZZZ\n  YYY\n  XXX\ntail\n",
            vec![c3],
            5,
            500,
        );

        // Positional (git-identical) fall-through: YYY and XXX have no
        // in-hunk counterpart (ZZZ already consumed the only anchor
        // available between `keep` and `tail`), so git's default leaves
        // them on the ignored commit.
        let positional_opts = BlameOptions {
            ignore_whitespace: true,
            ignore_revs: Arc::new([c4].into_iter().collect()),
            ..Default::default()
        };
        let positional = blame_file_with(&store, c4, "f.txt", &positional_opts).unwrap();
        assert_eq!(
            positional.lines[1].commit_hash, c3,
            "ZZZ is recognized unchanged by the LCS matcher itself (needs no fall-through)"
        );
        assert_eq!(
            positional.lines[2].commit_hash, c4,
            "positional: YYY has no in-hunk counterpart, stays on the ignored commit"
        );
        assert_eq!(
            positional.lines[3].commit_hash, c4,
            "positional: XXX has no in-hunk counterpart, stays on the ignored commit"
        );

        // Precise: content matching searches the whole parent file (not
        // just YYY/XXX's own, counterpart-less hunk) and finds each true
        // origin.
        let precise = blame_file_with(&store, c4, "f.txt", &ignoring_precise(&[c4])).unwrap();
        assert_eq!(
            precise.lines[1].commit_hash, c3,
            "ZZZ is unaffected by precise mode (already resolved by plain LCS)"
        );
        assert_eq!(
            precise.lines[2].commit_hash, c2,
            "precise: YYY correctly attributed to its true origin"
        );
        assert_eq!(
            precise.lines[3].commit_hash, c1,
            "precise: XXX correctly attributed to its true origin"
        );
        assert_eq!(precise.lines[0].commit_hash, c0, "keep is unaffected");
        assert_eq!(precise.lines[4].commit_hash, c0, "tail is unaffected");
    }

    #[test]
    fn blame_ignore_rev_precise_unequal_hunk_surplus_stays_put() {
        // The ignored commit splits one line into three fabricated lines
        // with no content match anywhere in the parent. Both modes pair the
        // first split line positionally (the only candidate) and leave the
        // two surplus lines on the ignored commit — `--ignore-rev-precise`
        // must not invent a match where none exists.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"L1\nMID\nL3\n", vec![], 1, 100);
        let c2 = put_file_commit(
            &store,
            "f.txt",
            b"L1\nMIDaaa\nMIDbbb\nMIDccc\nL3\n",
            vec![c1],
            2,
            200,
        );

        let plain = blame_file_with(&store, c2, "f.txt", &ignoring(&[c2])).unwrap();
        let precise = blame_file_with(&store, c2, "f.txt", &ignoring_precise(&[c2])).unwrap();
        for r in [&plain, &precise] {
            assert_eq!(r.lines[1].commit_hash, c1, "MIDaaa falls through to c1");
            assert_eq!(
                r.lines[2].commit_hash, c2,
                "MIDbbb has no pair -> stays on c2"
            );
            assert_eq!(
                r.lines[3].commit_hash, c2,
                "MIDccc has no pair -> stays on c2"
            );
        }
    }

    #[test]
    fn blame_ignore_rev_precise_no_match_falls_back_to_positional() {
        // A single fabricated line replacing a single parent line, with no
        // other candidate anywhere in the file: precise mode has nothing to
        // find, so it falls back to exactly the positional result.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"L1\nA\nL3\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"L1\nFABRICATED\nL3\n", vec![c1], 2, 200);

        let plain = blame_file_with(&store, c2, "f.txt", &ignoring(&[c2])).unwrap();
        let precise = blame_file_with(&store, c2, "f.txt", &ignoring_precise(&[c2])).unwrap();
        assert_eq!(plain.lines[1].commit_hash, c1);
        assert_eq!(
            precise.lines[1].commit_hash, plain.lines[1].commit_hash,
            "no content candidate exists anywhere in the parent: precise matches positional"
        );
    }

    #[test]
    fn precise_overrides_trivial_key_guard() {
        // Unit-test the helper directly (mirroring
        // `ignore_fallthrough_pairs_per_hunk`'s direct-call style), pinning
        // the trivial-key guard: a positional guess for a line whose key is
        // under 3 bytes is kept even when a perfect, unclaimed content match
        // sits elsewhere in the parent — while a longer key on the same call
        // is still correctly reattributed when it has no positional guess
        // (a `None` genuine-insertion slot the whole-file search can fill).
        //
        // new = ["ab" (trivial, 2 bytes), "REALZZZ" (7 bytes)]
        // old = ["REALZZZ", "ab", "FILLER"]           (all LCS-unmatched)
        // positional (`fall`): new0 -> old2 ("FILLER", arbitrary/wrong),
        //                       new1 -> None (no in-hunk counterpart).
        let mapping = vec![None, None];
        let fall = vec![Some(2), None];
        let new_lines = vec![b"ab".to_vec(), b"REALZZZ".to_vec()];
        let parent_lines = vec![b"REALZZZ".to_vec(), b"ab".to_vec(), b"FILLER".to_vec()];
        let matched = vec![false, false];

        let out = super::walk::precise_overrides(&super::walk::PreciseRequest {
            mapping: &mapping,
            fall: &fall,
            new_lines: &new_lines,
            parent_lines: &parent_lines,
            matched: &matched,
            ignore_whitespace: false,
        });
        assert_eq!(
            out[0],
            Some(2),
            "trivial key 'ab' keeps its positional guess even though a perfect \
             unclaimed match ('ab' at old index 1) exists"
        );
        assert_eq!(
            out[1],
            Some(0),
            "non-trivial key 'REALZZZ' fills its None positional slot from its \
             true content match (old index 0)"
        );
    }

    #[test]
    fn precise_overrides_never_teleports_edited_line_worse_than_positional() {
        // Regression for the #523 review counterexample proving the earlier
        // "never worse than positional" claim FALSE. The fix makes it true
        // by construction: a slot whose positional guess is already a real
        // parent line (`Some(j)`) is only re-pointed by a *genuine moved
        // block* (a run of >= 2 file-adjacent lines), never by an isolated
        // single-line key coincidence.
        //
        // parent = [A, foo, B1, B2, bar, C]  (old idx 0..=5)
        // new    = [A, bar, B1, B2, C]        (new idx 0..=4)
        // The ignored commit edits foo->bar (old idx 1) and deletes an
        // unrelated `bar` authored by commit X (old idx 4). LCS anchors
        // A/B1/B2/C, so mapping[bar]=None and the positional fall pairs the
        // edited `bar` with old idx 1 (`foo`) — the line's TRUE positional
        // predecessor. The only unmatched old `bar` is at old idx 4.
        //
        // Old behavior: content override sends new1 to old idx 4, blaming the
        // edited line on X — strictly worse than positional. New behavior:
        // that single-line coincidence cannot displace the filled positional
        // guess, so out[1] stays Some(1).
        let mapping = vec![Some(0), None, Some(2), Some(3), Some(5)];
        let fall = vec![None, Some(1), None, None, None];
        let new_lines = vec![
            b"A".to_vec(),
            b"bar".to_vec(),
            b"B1".to_vec(),
            b"B2".to_vec(),
            b"C".to_vec(),
        ];
        let parent_lines = vec![
            b"A".to_vec(),
            b"foo".to_vec(),
            b"B1".to_vec(),
            b"B2".to_vec(),
            b"bar".to_vec(),
            b"C".to_vec(),
        ];
        let matched = vec![false; new_lines.len()];

        let out = super::walk::precise_overrides(&super::walk::PreciseRequest {
            mapping: &mapping,
            fall: &fall,
            new_lines: &new_lines,
            parent_lines: &parent_lines,
            matched: &matched,
            ignore_whitespace: false,
        });
        assert_eq!(
            out[1],
            Some(1),
            "edited `bar` keeps its positional predecessor (foo @ old idx 1)"
        );
        assert_ne!(
            out[1],
            Some(4),
            "must NOT teleport to the unrelated `bar` @ old idx 4 (commit X)"
        );
        assert_eq!(
            out,
            vec![None, Some(1), None, None, None],
            "no slot is attributed worse than the positional fall-through"
        );
    }

    #[test]
    fn precise_overrides_reindented_brace_does_not_teleport_without_w() {
        // Regression for #523 finding #2: without `-w`, `line_key` keeps raw
        // bytes, so a reindented `"    }"` is a 5-byte key that clears a
        // naive `len < 3` guard and would teleport to any other same-indent
        // `"    }"` in the parent. The trivial-key guard now measures the
        // WHITESPACE-STRIPPED length regardless of `-w`, so `"    }"` -> `}`
        // (1 byte) is trivial and stays put.
        //
        // The brace is a genuine-insertion slot (fall = None — its positional
        // counterpart consumed by an anchor), which the never-worse rule
        // would otherwise let a single exact match fill; only the
        // stripped-length guard prevents the teleport here.
        let mapping = vec![None];
        let fall = vec![None];
        let new_lines = vec![b"    }".to_vec()];
        let parent_lines = vec![b"    }".to_vec()]; // unrelated same-indent brace
        let matched = vec![false];

        let out = super::walk::precise_overrides(&super::walk::PreciseRequest {
            mapping: &mapping,
            fall: &fall,
            new_lines: &new_lines,
            parent_lines: &parent_lines,
            matched: &matched,
            ignore_whitespace: false,
        });
        assert_eq!(
            out[0], None,
            "an indented brace is trivial once whitespace-stripped; it must not \
             teleport to an unrelated brace even without -w"
        );
    }

    #[test]
    fn ignore_fallthrough_pairs_per_hunk() {
        // Unit-test the pairing helper directly against the verified rules.
        // mapping: new→old, None = unmatched.
        // old=[0,1,2,3], new anchors at 0 and 3, two unmatched between →
        // pair new1↔old1, new2↔old2.
        let mapping = vec![Some(0), None, None, Some(3)];
        assert_eq!(
            super::ignore_fallthrough(&mapping, 4),
            vec![None, Some(1), Some(2), None]
        );
        // More added than removed: old hunk has one line, new hunk two →
        // first pairs, second unpaired.
        let mapping = vec![Some(0), None, None, Some(2)];
        assert_eq!(
            super::ignore_fallthrough(&mapping, 3),
            vec![None, Some(1), None, None]
        );
        // Trailing insertion with no removed lines → all unpaired.
        let mapping = vec![Some(0), Some(1), None, None];
        assert_eq!(
            super::ignore_fallthrough(&mapping, 2),
            vec![None, None, None, None]
        );
    }

    #[test]
    fn reverse_attributes_each_line_to_last_commit_it_survived() {
        // Verified against `git blame --reverse c1..c4`: blames c1's lines
        // (keep, doomed, also); survivors go to the end, the removed line
        // freezes at the last commit it existed in.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"keep\ndoomed\nalso\n", vec![], 1, 100);
        let c2 = put_file_commit(
            &store,
            "f.txt",
            b"keep\ndoomed\nalso\nextra\n",
            vec![c1],
            2,
            200,
        );
        let c3 = put_file_commit(&store, "f.txt", b"keep\nalso\nextra\n", vec![c2], 3, 300);
        let c4 = put_file_commit(&store, "f.txt", b"keep\nalso\nextra2\n", vec![c3], 4, 400);

        let r = blame_file_reverse(&store, c1, c4, "f.txt", &BlameOptions::default()).unwrap();
        assert_eq!(r.lines.len(), 3, "blames the start (c1) version's 3 lines");
        assert_eq!(r.lines[0].text, b"keep");
        assert_eq!(r.lines[0].commit_hash, c4, "keep survives to the end");
        assert_eq!(r.lines[1].text, b"doomed");
        assert_eq!(r.lines[1].commit_hash, c2, "doomed last existed in c2");
        assert_eq!(r.lines[2].text, b"also");
        assert_eq!(r.lines[2].commit_hash, c4, "also survives to the end");
    }

    #[test]
    fn reverse_line_removed_immediately_stays_on_start() {
        // A start line removed in the very first included commit never
        // survives a step, so it is attributed to `start` itself (git marks
        // it with `^`). Verified against real git.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"keep\ngone\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"keep\n", vec![c1], 2, 200);
        let c3 = put_file_commit(&store, "f.txt", b"keep\nnew\n", vec![c2], 3, 300);

        let r = blame_file_reverse(&store, c1, c3, "f.txt", &BlameOptions::default()).unwrap();
        assert_eq!(r.lines[0].commit_hash, c3, "keep survives to the end");
        assert_eq!(
            r.lines[1].commit_hash, c1,
            "gone never survived a step → stays on start"
        );
        assert_eq!(r.lines[1].text, b"gone");
    }

    #[test]
    fn reverse_modified_line_freezes_before_the_edit() {
        // A line modified every commit: the start version last exists in
        // start (it is changed in the next commit). Verified against git.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"a\nMOD\nc\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"a\nMOD2\nc\n", vec![c1], 2, 200);
        let c3 = put_file_commit(&store, "f.txt", b"a\nMOD3\nc\n", vec![c2], 3, 300);

        let r = blame_file_reverse(&store, c1, c3, "f.txt", &BlameOptions::default()).unwrap();
        assert_eq!(r.lines[0].commit_hash, c3, "a survives");
        assert_eq!(r.lines[1].commit_hash, c1, "MOD changed in c2 → last in c1");
        assert_eq!(r.lines[2].commit_hash, c3, "c survives");
    }

    #[test]
    fn reverse_unchanged_commit_advances_attribution() {
        // A commit that does not touch the file still counts as a commit the
        // line existed in, so attribution advances through it.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"a\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"a\n", vec![c1], 2, 200); // identical
        let c3 = put_file_commit(&store, "f.txt", b"b\n", vec![c2], 3, 300); // a removed

        let r = blame_file_reverse(&store, c1, c3, "f.txt", &BlameOptions::default()).unwrap();
        assert_eq!(
            r.lines[0].commit_hash, c2,
            "a last existed in the unchanged c2, gone by c3"
        );
    }

    #[test]
    fn reverse_open_end_walks_to_provided_end() {
        // Sanity that the range is honored: stopping the range at c2 freezes
        // every still-living line at c2.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"keep\ndoomed\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"keep\ndoomed\nx\n", vec![c1], 2, 200);
        let _c3 = put_file_commit(&store, "f.txt", b"keep\nx\n", vec![c2], 3, 300);

        let r = blame_file_reverse(&store, c1, c2, "f.txt", &BlameOptions::default()).unwrap();
        assert!(
            r.lines.iter().all(|l| l.commit_hash == c2),
            "with the range ending at c2 both start lines last exist in c2"
        );
    }

    #[test]
    fn reverse_traces_through_whitespace_edit_under_w() {
        // `-w`: a whitespace-only reformat should not count as the line
        // disappearing, so the line survives past the reformat.
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"foo(a, b)\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"foo(a,b)\n", vec![c1], 2, 200); // ws-only
        let c3 = put_file_commit(&store, "f.txt", b"changed\n", vec![c2], 3, 300);

        // Without -w the reformat in c2 "ends" the original line at c1.
        let plain = blame_file_reverse(&store, c1, c3, "f.txt", &BlameOptions::default()).unwrap();
        assert_eq!(
            plain.lines[0].commit_hash, c1,
            "ws edit ends the line at c1"
        );

        let w = BlameOptions {
            ignore_whitespace: true,
            ..Default::default()
        };
        let rw = blame_file_reverse(&store, c1, c3, "f.txt", &w).unwrap();
        assert_eq!(
            rw.lines[0].commit_hash, c2,
            "-w traces the line through the reformat → last exists in c2"
        );
    }

    #[test]
    fn reverse_start_not_ancestor_errors() {
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "f.txt", b"a\n", vec![], 1, 100);
        // A sibling commit not on c1's first-parent chain.
        let other = put_file_commit(&store, "f.txt", b"z\n", vec![], 9, 900);
        let err =
            blame_file_reverse(&store, other, c1, "f.txt", &BlameOptions::default()).unwrap_err();
        assert!(
            matches!(err, BlameError::ReverseRange { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn reverse_missing_path_in_start_errors() {
        let (_d, store) = fresh_store();
        let c1 = put_file_commit(&store, "other.txt", b"x\n", vec![], 1, 100);
        let c2 = put_file_commit(&store, "f.txt", b"y\n", vec![c1], 2, 200);
        let err =
            blame_file_reverse(&store, c1, c2, "f.txt", &BlameOptions::default()).unwrap_err();
        assert!(matches!(err, BlameError::FileNotFound(_)), "got {err:?}");
    }

    // ---- merge-aware walk (#458) -----------------------------------------
    // All scenarios verified against real `git blame` / `git blame
    // --first-parent` (2.50.1); mkit hashes differ, so assert by commit.

    /// base → {main adds main-line, feature adds feature-line} → merge.
    /// Returns (base, main, feat, merge). P1 of the merge is `main`.
    fn diamond_distinct(store: &ObjectStore) -> (Hash, Hash, Hash, Hash) {
        let base = put_file_commit(store, "f.txt", b"base1\nbase2\n", vec![], 1, 100);
        let feat = put_file_commit(
            store,
            "f.txt",
            b"base1\nbase2\nfeature\n",
            vec![base],
            2,
            200,
        );
        let main = put_file_commit(store, "f.txt", b"main\nbase1\nbase2\n", vec![base], 3, 300);
        let merge = put_file_commit(
            store,
            "f.txt",
            b"main\nbase1\nbase2\nfeature\n",
            vec![main, feat],
            4,
            400,
        );
        (base, main, feat, merge)
    }

    #[test]
    fn blame_merge_aware_credits_side_branch_lines() {
        // Default (merge-aware): the side-branch line is credited to the
        // commit that wrote it, not the merge.
        let (_d, store) = fresh_store();
        let (base, main, feat, merge) = diamond_distinct(&store);
        let r = blame_file(&store, merge, "f.txt").unwrap();
        assert_eq!(r.lines[0].commit_hash, main, "main-line → main");
        assert_eq!(r.lines[1].commit_hash, base, "base1 → base");
        assert_eq!(r.lines[2].commit_hash, base, "base2 → base");
        assert_eq!(r.lines[3].commit_hash, feat, "feature → feature commit");
        assert!(
            r.lines.iter().all(|l| l.commit_hash != merge),
            "none → merge"
        );
    }

    #[test]
    fn blame_first_parent_credits_merge_for_side_branch_line() {
        // `--first-parent`: the side branch is never followed, so the
        // feature line first appears (to that walk) at the merge.
        let (_d, store) = fresh_store();
        let (base, main, _feat, merge) = diamond_distinct(&store);
        let opts = BlameOptions {
            first_parent: true,
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "f.txt", &opts).unwrap();
        assert_eq!(r.lines[0].commit_hash, main, "main-line → main");
        assert_eq!(r.lines[1].commit_hash, base);
        assert_eq!(r.lines[3].commit_hash, merge, "feature line → merge");
    }

    #[test]
    fn blame_merge_identical_line_goes_to_first_parent() {
        // Both branches add the SAME line; git credits the first parent.
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"base\n", vec![], 1, 100);
        let feat = put_file_commit(&store, "f.txt", b"base\nshared\n", vec![base], 2, 200);
        let main = put_file_commit(&store, "f.txt", b"base\nshared\n", vec![base], 3, 300);
        let merge = put_file_commit(&store, "f.txt", b"base\nshared\n", vec![main, feat], 4, 400);
        let r = blame_file(&store, merge, "f.txt").unwrap();
        assert_eq!(r.lines[1].commit_hash, main, "shared line → first parent");
        assert!(r.lines.iter().all(|l| l.commit_hash != feat));
    }

    #[test]
    fn blame_evil_merge_attributes_new_line_to_merge() {
        // The merge blob introduces a line present in neither parent: it is
        // introduced by the merge commit.
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"base\n", vec![], 1, 100);
        let feat = put_file_commit(&store, "f.txt", b"base\nfeat\n", vec![base], 2, 200);
        let main = put_file_commit(&store, "f.txt", b"main\nbase\n", vec![base], 3, 300);
        let merge = put_file_commit(
            &store,
            "f.txt",
            b"main\nbase\nfeat\nEVIL\n",
            vec![main, feat],
            4,
            400,
        );
        let r = blame_file(&store, merge, "f.txt").unwrap();
        assert_eq!(r.lines[0].commit_hash, main);
        assert_eq!(r.lines[1].commit_hash, base);
        assert_eq!(r.lines[2].commit_hash, feat);
        assert_eq!(r.lines[3].commit_hash, merge, "the evil line → merge");
    }

    #[test]
    fn blame_octopus_merge_credits_each_branch() {
        // A 3-parent merge: each branch's line is credited to its commit.
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"base\n", vec![], 1, 100);
        let b1 = put_file_commit(&store, "f.txt", b"base\nb1\n", vec![base], 2, 200);
        let b2 = put_file_commit(&store, "f.txt", b"base\nb2\n", vec![base], 3, 300);
        let b3 = put_file_commit(&store, "f.txt", b"base\nb3\n", vec![base], 4, 400);
        let merge = put_file_commit(
            &store,
            "f.txt",
            b"base\nb1\nb2\nb3\n",
            vec![b1, b2, b3],
            5,
            500,
        );
        let r = blame_file(&store, merge, "f.txt").unwrap();
        assert_eq!(r.lines[0].commit_hash, base);
        assert_eq!(r.lines[1].commit_hash, b1);
        assert_eq!(r.lines[2].commit_hash, b2);
        assert_eq!(r.lines[3].commit_hash, b3);
    }

    #[test]
    fn blame_m_merge_credits_move_from_second_parent() {
        // A long line L is written on the SECOND merge parent and the merge
        // moves it to the file's end. `git blame -M` credits the moved line
        // to the 2nd-parent commit that wrote it, NOT the merge — the detector
        // must run against the second parent, not the first only. (Pinned
        // against real `git blame -M`, git 2.50.1.)
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"X\nY\n", vec![], 1, 100);
        // First parent: an unrelated edit, no L.
        let p1 = put_file_commit(&store, "f.txt", b"X\nY\nZ\n", vec![base], 2, 200);
        // Second parent: writes L at the top.
        let v2 = [LONG_LINE, b"X", b"Y", b""].join(&b'\n');
        let c2 = put_file_commit(&store, "f.txt", &v2, vec![base], 3, 300);
        // Merge (p1 first, c2 second): L moved to the end.
        let vm = [b"X" as &[u8], b"Y", b"Z", LONG_LINE, b""].join(&b'\n');
        let merge = put_file_commit(&store, "f.txt", &vm, vec![p1, c2], 4, 400);

        let opts = BlameOptions {
            moves: MoveDetection::On { threshold: 20 },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "f.txt", &opts).unwrap();
        // Child order: X, Y, Z, L.
        assert_eq!(r.lines[3].text, LONG_LINE);
        assert_eq!(
            r.lines[3].commit_hash, c2,
            "-M credits the move to the 2nd-parent origin, not the merge"
        );
        assert_eq!(r.lines[2].commit_hash, p1, "Z stays on the first parent");
    }

    #[test]
    fn blame_m_merge_move_prefers_first_parent() {
        // Both parents independently wrote the SAME long line L at the top;
        // the merge moves L to the end so neither parent's matcher explains it
        // in place. `git blame -M` credits the FIRST parent (the merge-walk's
        // first-parent-wins tie-break also governs the move detector). Pinned
        // against real `git blame -M`.
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"X\nY\n", vec![], 1, 100);
        let v = [LONG_LINE, b"X", b"Y", b""].join(&b'\n');
        let p1 = put_file_commit(&store, "f.txt", &v, vec![base], 2, 200);
        let c2 = put_file_commit(&store, "f.txt", &v, vec![base], 3, 300);
        let vm = [b"X" as &[u8], b"Y", LONG_LINE, b""].join(&b'\n');
        let merge = put_file_commit(&store, "f.txt", &vm, vec![p1, c2], 4, 400);

        let opts = BlameOptions {
            moves: MoveDetection::On { threshold: 20 },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "f.txt", &opts).unwrap();
        // Child order: X, Y, L.
        assert_eq!(r.lines[2].text, LONG_LINE);
        assert_eq!(
            r.lines[2].commit_hash, p1,
            "-M move at a merge prefers the first parent on a tie"
        );
        assert!(
            r.lines.iter().all(|l| l.commit_hash != c2),
            "the second parent never wins the tie"
        );
    }

    #[test]
    fn blame_ignore_rev_merge_falls_through_to_second_parent() {
        // An ignored merge resolves a modify/delete conflict by keeping a
        // NOISE version of the feature line. The first parent DELETED that
        // line (no positional counterpart in its conflicted hunk), so the
        // fall-through must cross to the SECOND parent that actually wrote the
        // content — `git blame --ignore-rev <merge>` credits the feature
        // commit, not the merge. (Pinned against real git 2.50.1.)
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"TOP\nMID\nBOT\n", vec![], 1, 100);
        // First parent: deletes MID.
        let p1 = put_file_commit(&store, "f.txt", b"TOP\nBOT\n", vec![base], 2, 200);
        // Second parent: rewrites MID to real content.
        let v2 = [b"TOP" as &[u8], b"REAL_CONTENT_OF_B_LINE", b"BOT", b""].join(&b'\n');
        let c2 = put_file_commit(&store, "f.txt", &v2, vec![base], 3, 300);
        // Merge keeps a noise version of the feature line.
        let vm = [b"TOP" as &[u8], b"  REAL_CONTENT_OF_B_LINE  X", b"BOT", b""].join(&b'\n');
        let merge = put_file_commit(&store, "f.txt", &vm, vec![p1, c2], 4, 400);

        let r = blame_file_with(&store, merge, "f.txt", &ignoring(&[merge])).unwrap();
        assert_eq!(r.lines[1].text, b"  REAL_CONTENT_OF_B_LINE  X");
        assert_eq!(
            r.lines[1].commit_hash, c2,
            "ignored merge falls through across to the 2nd parent's origin"
        );
    }

    #[test]
    fn blame_ignore_rev_merge_prefers_first_parent_counterpart() {
        // Both parents have a positional counterpart in the conflicted hunk;
        // the ignored merge's fall-through prefers the FIRST parent (git's
        // positional fall-through is first-parent-wins, the same tie-break the
        // merge walk uses elsewhere). Pinned against real git.
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"a\nb\nc\n", vec![], 1, 100);
        let p1 = put_file_commit(
            &store,
            "f.txt",
            b"a\nMAIN_B_VERSION\nc\n",
            vec![base],
            2,
            200,
        );
        let v2 = [b"a" as &[u8], b"REAL_CONTENT_OF_B_LINE", b"c", b""].join(&b'\n');
        let c2 = put_file_commit(&store, "f.txt", &v2, vec![base], 3, 300);
        let vm = [b"a" as &[u8], b"  REAL_CONTENT_OF_B_LINE  X", b"c", b""].join(&b'\n');
        let merge = put_file_commit(&store, "f.txt", &vm, vec![p1, c2], 4, 400);

        let r = blame_file_with(&store, merge, "f.txt", &ignoring(&[merge])).unwrap();
        assert_eq!(
            r.lines[1].commit_hash, p1,
            "fall-through prefers the first parent on a positional tie"
        );
        assert!(
            r.lines.iter().all(|l| l.commit_hash != c2),
            "the second parent does not win when the first parent has a counterpart"
        );
    }

    #[test]
    fn blame_ignore_rev_precise_merge_second_parent_composition() {
        // Composes `--ignore-rev-precise` with the per-parent merge walk
        // (`apply_ignore_fallthrough`'s loop over every relevant parent):
        // the FIRST parent lacks the swapped content entirely (no positional
        // counterpart at all, so it contributes nothing and the walk falls
        // through to the next parent — same shape as
        // `blame_ignore_rev_merge_falls_through_to_second_parent`), and the
        // SECOND parent has the same moved-and-reindented reformat as
        // `blame_ignore_rev_precise_reattributes_moved_reindented_lines`
        // (ZZZ is recognized unchanged by plain LCS; YYY and XXX have no
        // in-hunk counterpart and are genuine insertions under the
        // positional default). Precise mode's whole-file search must run
        // against the SECOND parent's file (the one that actually has the
        // content), not the first parent's, which never pairs anything at
        // all. Tokens are >= 3 bytes so the trivial-key guard doesn't apply.
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"TOP\nBOT\n", vec![], 1, 100);
        // First (ignored merge's first) parent: never had XXX/YYY/ZZZ at all.
        let p1 = put_file_commit(&store, "f.txt", b"TOP\nBOT\n", vec![base], 2, 200);
        // Second parent: builds up XXX, YYY, ZZZ with distinct origins.
        let c_x = put_file_commit(&store, "f.txt", b"TOP\nXXX\nBOT\n", vec![base], 3, 300);
        let c_y = put_file_commit(&store, "f.txt", b"TOP\nXXX\nYYY\nBOT\n", vec![c_x], 4, 400);
        let c_z = put_file_commit(
            &store,
            "f.txt",
            b"TOP\nXXX\nYYY\nZZZ\nBOT\n",
            vec![c_y],
            5,
            500,
        );
        // Ignored merge: reorders + reindents XXX/YYY/ZZZ (same shape as the
        // non-merge reindent test).
        let merge = put_file_commit(
            &store,
            "f.txt",
            b"TOP\n  ZZZ\n  YYY\n  XXX\nBOT\n",
            vec![p1, c_z],
            6,
            600,
        );

        let positional_opts = BlameOptions {
            ignore_whitespace: true,
            ignore_revs: Arc::new([merge].into_iter().collect()),
            ..Default::default()
        };
        let positional = blame_file_with(&store, merge, "f.txt", &positional_opts).unwrap();
        assert_eq!(
            positional.lines[1].commit_hash, c_z,
            "ZZZ is recognized unchanged by the LCS matcher itself, against the 2nd parent"
        );
        assert_eq!(
            positional.lines[2].commit_hash, merge,
            "positional: YYY has no in-hunk counterpart on either parent, stays on the merge"
        );
        assert_eq!(
            positional.lines[3].commit_hash, merge,
            "positional: XXX has no in-hunk counterpart on either parent, stays on the merge"
        );

        let precise = blame_file_with(&store, merge, "f.txt", &ignoring_precise(&[merge])).unwrap();
        assert_eq!(
            precise.lines[1].commit_hash, c_z,
            "ZZZ is unaffected by precise mode (already resolved by plain LCS)"
        );
        assert_eq!(
            precise.lines[2].commit_hash, c_y,
            "precise: YYY correctly attributed to its true origin via the 2nd parent's whole file"
        );
        assert_eq!(
            precise.lines[3].commit_hash, c_x,
            "precise: XXX correctly attributed to its true origin via the 2nd parent's whole file"
        );
        assert!(
            positional.lines.iter().all(|l| l.commit_hash != p1)
                && precise.lines.iter().all(|l| l.commit_hash != p1),
            "the content-less first parent never wins"
        );
    }

    #[test]
    fn blame_c_merge_credits_copy_from_second_parent() {
        // `-C` merge parity: the blamed file already EXISTS in the parents and
        // a merge appends a block that lives in `src.txt` on the SECOND parent.
        // `git blame -C -C <merge> -- b.txt` credits the SECOND parent (`c2`),
        // enumerating that parent's tree to find the copy source — it does NOT
        // credit the merge. Pinned against real git 2.50.1:
        //   base: b.txt="hello"; p1 adds m.txt; c2 adds src.txt with the block;
        //   merge(p1,c2) appends the block to b.txt
        //   => `git blame -C -C` credits c2/src.txt for the appended lines.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("b.txt", b"hello\n")], vec![], 1, 100);
        let p1 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("m.txt", b"main only\n")],
            vec![base],
            2,
            200,
        );
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let c2 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("src.txt", &src)],
            vec![base],
            3,
            300,
        );
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("b.txt", &bmerge),
                ("m.txt", b"main only\n"),
                ("src.txt", &src),
            ],
            vec![p1, c2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        // Child order: hello, BLOCK_A, BLOCK_B.
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, c2,
            "a modified file's appended block is copied across to the second parent's tree (git credits c2)"
        );
        assert_eq!(
            r.lines[2].commit_hash, c2,
            "the whole copied block is credited to c2"
        );
        // The unchanged first line stays on its own origin, not the merge.
        assert_ne!(r.lines[1].commit_hash, merge);
    }

    #[test]
    fn blame_c_merge_credits_copy_from_third_octopus_parent() {
        // `-C -C` searches EVERY relevant merge parent's tree, not just the
        // first two. Octopus merge(p1, p2, p3): the copy source lives only in
        // `src.txt` on the THIRD parent; real git credits p3 for the appended
        // block (pinned against git 2.50.1). Guards against a first-/second-
        // parent-only search.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("b.txt", b"hello\n")], vec![], 1, 100);
        let p1 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("x.txt", b"x only\n")],
            vec![base],
            2,
            200,
        );
        let p2 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("y.txt", b"y only\n")],
            vec![base],
            3,
            300,
        );
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let p3 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("src.txt", &src)],
            vec![base],
            4,
            400,
        );
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("b.txt", &bmerge),
                ("x.txt", b"x only\n"),
                ("y.txt", b"y only\n"),
                ("src.txt", &src),
            ],
            vec![p1, p2, p3],
            5,
            500,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, p3,
            "the copied block is traced to the third octopus parent's tree"
        );
    }

    #[test]
    fn blame_c_merge_source_only_in_merge_tree_credits_merge() {
        // Counterpart guard: when the copy source (`src.txt`) is introduced by
        // the MERGE itself and no parent's tree holds the block, real git
        // credits the merge — the cross-parent search must not manufacture a
        // parent credit. Pinned against git 2.50.1.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("b.txt", b"hello\n")], vec![], 1, 100);
        let p1 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("m.txt", b"main only\n")],
            vec![base],
            2,
            200,
        );
        let c2 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("o.txt", b"other\n")],
            vec![base],
            3,
            300,
        );
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        // src.txt exists only in the merge's own tree (no parent has it).
        let merge = put_multi_file_commit(
            &store,
            &[
                ("b.txt", &bmerge),
                ("m.txt", b"main only\n"),
                ("o.txt", b"other\n"),
                ("src.txt", &src),
            ],
            vec![p1, c2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, merge,
            "no parent holds the source, so the appended block stays on the merge (git parity)"
        );
    }

    #[test]
    fn blame_c_merge_copy_tie_prefers_deduped_second_parent() {
        // Real `git blame -C -C` recipe (git 2.50.1):
        //   base: b.txt="hello"
        //   p1  = base + s1.txt(BLOCK_A,BLOCK_B,"zzz")
        //   c2  = base + s2.txt(BLOCK_A,BLOCK_B,"zzz")   (same block, 2nd parent)
        //   merge(p1,c2): b.txt="hello"+BLOCK_A+BLOCK_B  (both s1.txt,s2.txt kept)
        //   $ git blame -C -C -l b.txt
        //   -> lines 2-3 credited to c2/s2.txt, NOT p1 (confirmed independent of
        //      file name: "aaa.txt" on c2 still beats "zzz.txt" on p1).
        // Mechanism (see move_copy's module note): p1 keeps its porigin, so
        // its -C candidates are only files MODIFIED between p1 and the merge
        // — s1.txt is unchanged, hence invisible. c2's b.txt blob is
        // identical to p1's, so c2's porigin is deduped and c2 gets the
        // whole-tree search, which finds s2.txt.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("b.txt", b"hello\n")], vec![], 1, 100);
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let p1 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s1.txt", &src)],
            vec![base],
            2,
            200,
        );
        let c2 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s2.txt", &src)],
            vec![base],
            3,
            300,
        );
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[("b.txt", &bmerge), ("s1.txt", &src), ("s2.txt", &src)],
            vec![p1, c2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, c2,
            "a copy tie across parents resolves to the non-first parent (git parity)"
        );
        assert_eq!(r.lines[2].commit_hash, c2);
        assert!(
            r.lines.iter().all(|l| l.commit_hash != p1),
            "the first parent never wins an interior -C tie"
        );
    }

    #[test]
    fn blame_c_merge_copy_tie_octopus_prefers_first_non_first_parent() {
        // Real git recipe (git 2.50.1) — a 3-way octopus tie where the FIRST
        // parent has NO candidate at all and parents 2 and 3 both do:
        //   base: b.txt="hello"
        //   p1  = base + pm.txt("p1 only")            (no candidate)
        //   c2  = base + s2.txt(BLOCK_A,BLOCK_B,"zzz") (candidate)
        //   c3  = base + s3.txt(BLOCK_A,BLOCK_B,"zzz") (same candidate)
        //   merge(p1,c2,c3): b.txt="hello"+BLOCK_A+BLOCK_B
        //   $ git blame -C -C -l b.txt  -> credited to c2 (the SECOND parent,
        //   i.e. the FIRST of the two tied non-first parents), NOT c3 (the
        //   literal last parent). This disproves plain "last-parent-wins".
        //   Mechanism: p1 keeps its porigin (modified-files channel only —
        //   pm.txt has no block); c2's and c3's identical b.txt blobs are
        //   deduped to porigin-less, so both get whole-tree searches in
        //   parent order and c2, searched first, claims the block.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("b.txt", b"hello\n")], vec![], 1, 100);
        let p1 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("pm.txt", b"p1 only\n")],
            vec![base],
            2,
            200,
        );
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let c2 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s2.txt", &src)],
            vec![base],
            3,
            300,
        );
        let c3 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s3.txt", &src)],
            vec![base],
            4,
            400,
        );
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[("b.txt", &bmerge), ("s2.txt", &src), ("s3.txt", &src)],
            vec![p1, c2, c3],
            5,
            500,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, c2,
            "the first NON-first parent (in order) wins the octopus tie, not the literal last parent"
        );
        assert_eq!(r.lines[2].commit_hash, c2);
    }

    #[test]
    fn blame_c_merge_copy_source_only_on_first_parent_stays_on_merge() {
        // Counterpart guard, no tie involved: the block's ONLY candidate
        // source lives on the FIRST parent (p1's s1.txt); the second parent
        // has an unrelated file and no candidate at all. Real git recipe
        // (git 2.50.1):
        //   base: b.txt="hello"
        //   p1  = base + s1.txt(BLOCK_A,BLOCK_B,"zzz")
        //   c2  = base + m.txt("other unrelated content")
        //   merge(p1,c2): b.txt="hello"+BLOCK_A+BLOCK_B
        //   $ git blame -C -C -l b.txt -> credited to the MERGE commit
        //   itself, NOT p1, even though p1's candidate is uncontested.
        //   Mechanism: p1 keeps its porigin, so its -C candidates are only
        //   files MODIFIED between p1 and the merge — s1.txt is unchanged,
        //   hence invisible. c2 is deduped (same b.txt blob) and gets the
        //   whole-tree search, but c2's tree has no block. See
        //   blame_c_level1_merge_modified_source_credits_first_parent for
        //   the converse: a first-parent source that IS modified gets
        //   credited.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("b.txt", b"hello\n")], vec![], 1, 100);
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let p1 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s1.txt", &src)],
            vec![base],
            2,
            200,
        );
        let c2 = put_multi_file_commit(
            &store,
            &[
                ("b.txt", b"hello\n"),
                ("m.txt", b"other unrelated content\n"),
            ],
            vec![base],
            3,
            300,
        );
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("b.txt", &bmerge),
                ("s1.txt", &src),
                ("m.txt", b"other unrelated content\n"),
            ],
            vec![p1, c2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, merge,
            "an uncontested -C source on the first parent is never traced (git parity)"
        );
        assert_eq!(r.lines[2].commit_hash, merge);
    }

    #[test]
    fn blame_c_merge_unmodified_first_parent_source_with_fileless_second_stays_on_merge() {
        // Modify/delete merge where the SECOND parent deleted the blamed
        // file: the filtered DAG sees a single relevant parent, but the
        // commit is still a true two-parent merge and p1's unchanged
        // s1.txt must stay invisible (modified-files channel). Guards the
        // old bug where `is_merge` was keyed on the FILTERED parent list,
        // making this shape look linear and tracing the block to p1.
        // Real git recipe (git 2.50.1):
        //   base: b.txt="hello", sbase.txt
        //   p1  = base + s1.txt(BLOCK_A,BLOCK_B,"zzz")   (keeps b.txt)
        //   p2  = base - b.txt                            (deleted)
        //   merge(p1,p2): b.txt="hello"+BLOCK_A+BLOCK_B; s1.txt unchanged
        //   $ git blame -C -C b.txt -> block stays on the MERGE.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(
            &store,
            &[
                ("b.txt", b"hello\n"),
                ("sbase.txt", b"source header line\n"),
            ],
            vec![],
            1,
            100,
        );
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let p1 = put_multi_file_commit(
            &store,
            &[
                ("b.txt", b"hello\n"),
                ("sbase.txt", b"source header line\n"),
                ("s1.txt", &src),
            ],
            vec![base],
            2,
            200,
        );
        let p2 = put_multi_file_commit(
            &store,
            &[("sbase.txt", b"source header line\n")],
            vec![base],
            3,
            300,
        );
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("b.txt", &bmerge),
                ("sbase.txt", b"source header line\n"),
                ("s1.txt", &src),
            ],
            vec![p1, p2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, merge,
            "a fileless second parent does not make the merge linear: p1's \
             unchanged source stays invisible and the block stays on the merge (git parity)"
        );
        assert_eq!(r.lines[2].commit_hash, merge);
    }

    #[test]
    fn blame_c_merge_file_deleting_parent_supplies_copy_source() {
        // A parent that DELETED the blamed file is still `-C -C` searched —
        // porigin-less parents get the whole-tree channel. Guards the old
        // bug where detection iterated only the file-bearing (filtered)
        // parents and p2's tree was never offered.
        // Real git recipe (git 2.50.1):
        //   base: f.txt="hello", s.txt="source header line"
        //   p1  = base                                    (unchanged)
        //   p2  = base - f.txt; s.txt gains BLOCK_A+BLOCK_B
        //   merge(p1,p2): f.txt="hello"+BLOCK_A+BLOCK_B; s.txt = p2's
        //   $ git blame -C -C f.txt -> block credited to p2 (via s.txt).
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(
            &store,
            &[("f.txt", b"hello\n"), ("s.txt", b"source header line\n")],
            vec![],
            1,
            100,
        );
        let p1 = put_multi_file_commit(
            &store,
            &[("f.txt", b"hello\n"), ("s.txt", b"source header line\n")],
            vec![base],
            2,
            200,
        );
        let src = [
            b"source header line" as &[u8],
            BLOCK_A,
            BLOCK_B,
            b"zzz",
            b"",
        ]
        .join(&b'\n');
        let p2 = put_multi_file_commit(&store, &[("s.txt", &src)], vec![base], 3, 300);
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[("f.txt", &bmerge), ("s.txt", &src)],
            vec![p1, p2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "f.txt", &opts).unwrap();
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, p2,
            "the parent that deleted the blamed file is whole-tree searched \
             and its source claims the block (git parity)"
        );
        assert_eq!(r.lines[2].commit_hash, p2);
    }

    #[test]
    fn blame_c_merge_fileless_first_parent_unmodified_second_source_stays_on_merge() {
        // Octopus where the FIRST parent deleted the blamed file and the
        // second parent's tree holds the block in a source UNCHANGED at
        // the merge. p1 is porigin-less (whole tree — no block there); p2
        // is the first file-bearing parent so it KEEPS its porigin and only
        // its modified files are candidates — s2.txt is unchanged, hence
        // invisible; p3's b.txt blob dedups against p2's (whole tree — no
        // block). Guards the old bug where the filtered index made p2 look
        // like "the first parent" for the wrong reason (and, on the fixed
        // real-parent model, would have wrongly whole-tree-searched p2).
        // Real git recipe (git 2.50.1):
        //   base: b.txt="hello", s2.txt="source header line"
        //   p1  = base - b.txt
        //   p2  = base with s2.txt = BLOCK_A+BLOCK_B+... (gains the block)
        //   p3  = base + o.txt
        //   merge(p1,p2,p3): b.txt="hello"+BLOCK; s2.txt = p2's; o.txt kept
        //   $ git blame -C -C b.txt -> block stays on the MERGE.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s2.txt", b"source header line\n")],
            vec![],
            1,
            100,
        );
        let p1 = put_multi_file_commit(
            &store,
            &[("s2.txt", b"source header line\n")],
            vec![base],
            2,
            200,
        );
        let src = [
            b"source header line" as &[u8],
            BLOCK_A,
            BLOCK_B,
            b"zzz",
            b"",
        ]
        .join(&b'\n');
        let p2 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s2.txt", &src)],
            vec![base],
            3,
            300,
        );
        let p3 = put_multi_file_commit(
            &store,
            &[
                ("b.txt", b"hello\n"),
                ("s2.txt", b"source header line\n"),
                ("o.txt", b"other\n"),
            ],
            vec![base],
            4,
            400,
        );
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[("b.txt", &bmerge), ("s2.txt", &src), ("o.txt", b"other\n")],
            vec![p1, p2, p3],
            5,
            500,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[1].text, BLOCK_A);
        assert_eq!(
            r.lines[1].commit_hash, merge,
            "the first file-bearing parent keeps its porigin even when the real \
             first parent is fileless; its unchanged source stays invisible (git parity)"
        );
        assert_eq!(r.lines[2].commit_hash, merge);
    }

    #[test]
    fn blame_c_level1_merge_modified_source_credits_first_parent() {
        // Plain `-C` (level 1) at a true merge: the source file IS modified
        // between the first parent and the merge (the block moved out of
        // s1.txt into b.txt), so it is a modified-files-channel candidate
        // and the FIRST parent gets the credit — there is no first-parent
        // carve-out in git, at any level. Guards the old bug where the
        // carve-out unconditionally zeroed the first parent's copy search.
        // Real git recipe (git 2.50.1), same result with -C and -C -C:
        //   base: b.txt="hello", s1.txt="source header line"
        //   p1  = base with s1.txt gaining BLOCK_A+BLOCK_B
        //   p2  = base + o.txt
        //   merge(p1,p2): b.txt="hello"+BLOCK; s1.txt back to base's (block
        //   moved out); o.txt kept
        //   $ git blame -C b.txt -> block credited to P1 (via s1.txt).
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s1.txt", b"source header line\n")],
            vec![],
            1,
            100,
        );
        let src = [
            b"source header line" as &[u8],
            BLOCK_A,
            BLOCK_B,
            b"zzz",
            b"",
        ]
        .join(&b'\n');
        let p1 = put_multi_file_commit(
            &store,
            &[("b.txt", b"hello\n"), ("s1.txt", &src)],
            vec![base],
            2,
            200,
        );
        let p2 = put_multi_file_commit(
            &store,
            &[
                ("b.txt", b"hello\n"),
                ("s1.txt", b"source header line\n"),
                ("o.txt", b"other\n"),
            ],
            vec![base],
            3,
            300,
        );
        let bmerge = [b"hello" as &[u8], BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("b.txt", &bmerge),
                ("s1.txt", b"source header line\n"),
                ("o.txt", b"other\n"),
            ],
            vec![p1, p2],
            4,
            400,
        );

        for level in [1u8, 2] {
            let opts = BlameOptions {
                copies: CopyDetection::On {
                    level,
                    threshold: 40,
                },
                ..Default::default()
            };
            let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
            assert_eq!(r.lines[1].text, BLOCK_A);
            assert_eq!(
                r.lines[1].commit_hash, p1,
                "a source modified between the first parent and the merge is a \
                 level-{level} candidate and credits the first parent (git parity)"
            );
        }
    }

    #[test]
    fn blame_c_boundary_first_parent_mode_still_searches_first_parent() {
        // `--first-parent -C -C` at a merge boundary: the real parent list
        // is truncated to the first parent (git's first_scapegoat does the
        // same), which is porigin-less for a newly-added file and therefore
        // whole-tree searched — the source on p1 is credited exactly as in
        // the merge-aware walk. Real git recipe (git 2.50.1):
        //   base: x.txt
        //   p1  = base + s1.txt(BLOCK_A,BLOCK_B,"zzz")
        //   p2  = base + o.txt
        //   merge(p1,p2): + n.txt = BLOCK_A+BLOCK_B   (new file)
        //   $ git blame --first-parent -C -C n.txt -> credited to P1.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("x.txt", b"x\n")], vec![], 1, 100);
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let p1 = put_multi_file_commit(
            &store,
            &[("x.txt", b"x\n"), ("s1.txt", &src)],
            vec![base],
            2,
            200,
        );
        let p2 = put_multi_file_commit(
            &store,
            &[("x.txt", b"x\n"), ("o.txt", b"other\n")],
            vec![base],
            3,
            300,
        );
        let newf = [BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("x.txt", b"x\n"),
                ("s1.txt", &src),
                ("o.txt", b"other\n"),
                ("n.txt", &newf),
            ],
            vec![p1, p2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            first_parent: true,
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "n.txt", &opts).unwrap();
        assert_eq!(r.lines[0].text, BLOCK_A);
        assert_eq!(
            r.lines[0].commit_hash, p1,
            "--first-parent truncates the boundary search to the real first \
             parent, which is still whole-tree searched (git parity)"
        );
        assert_eq!(r.lines[1].commit_hash, p1);
    }

    #[test]
    fn blame_c_merge_mixed_within_file_move_beats_copy_on_tie() {
        // Real git recipe (git 2.50.1), `-M -C -C`: a length-1 tie between an
        // within-file `-M` move source on the FIRST parent and a cross-file
        // `-C` copy source on the second parent for the SAME moved line:
        //   base: f.txt="X\nY\n"
        //   p1  = f.txt=LONG_LINE+"X\nY\n"           (own prior version: -M source)
        //   c2  = base f.txt (unchanged) + other.txt=LONG_LINE+"other stuff\n" (-C source)
        //   merge(p1,c2): f.txt="X\nY\n"+LONG_LINE   (moved to the end)
        //   $ git blame -M -C -C -l f.txt -> LONG_LINE credited to p1 (the
        //   `-M` move), not c2's `-C` copy. `-M` is unaffected by `-C`'s
        //   first-parent carve-out and keeps its own first-parent-wins tie.
        let (_d, store) = fresh_store();
        let base = put_file_commit(&store, "f.txt", b"X\nY\n", vec![], 1, 100);
        let v1 = [LONG_LINE, b"X", b"Y", b""].join(&b'\n');
        let p1 = put_file_commit(&store, "f.txt", &v1, vec![base], 2, 200);
        let c2 = put_multi_file_commit(
            &store,
            &[
                ("f.txt", b"X\nY\n"),
                ("other.txt", &[LONG_LINE, b"other stuff", b""].join(&b'\n')),
            ],
            vec![base],
            3,
            300,
        );
        let vm = [b"X" as &[u8], b"Y", LONG_LINE, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("f.txt", &vm),
                ("other.txt", &[LONG_LINE, b"other stuff", b""].join(&b'\n')),
            ],
            vec![p1, c2],
            4,
            400,
        );

        let opts = BlameOptions {
            moves: MoveDetection::On { threshold: 20 },
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "f.txt", &opts).unwrap();
        assert_eq!(r.lines[2].text, LONG_LINE);
        assert_eq!(
            r.lines[2].commit_hash, p1,
            "-M's within-file move on the first parent still wins the tie over -C's copy on the second"
        );
    }

    #[test]
    fn blame_c_merge_boundary_copy_from_second_parent() {
        // -C merge residual #2, closed. Real git recipe (git 2.50.1): the
        // blamed file (`b.txt`) is ADDED by the merge — no parent contains
        // it at all — and its sole copy source lives on the SECOND parent:
        //   base: base.txt="base"
        //   p1  = base + m.txt("main only")            (no candidate)
        //   c2  = base + src.txt(BLOCK_A,BLOCK_B,"zzz") (candidate)
        //   merge(p1,c2): adds b.txt=BLOCK_A+BLOCK_B (new path, no parent has it)
        //   $ git blame -C -C -l b.txt -> credited to c2/src.txt.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("base.txt", b"base\n")], vec![], 1, 100);
        let p1 = put_multi_file_commit(
            &store,
            &[("base.txt", b"base\n"), ("m.txt", b"main only\n")],
            vec![base],
            2,
            200,
        );
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let c2 = put_multi_file_commit(
            &store,
            &[("base.txt", b"base\n"), ("src.txt", &src)],
            vec![base],
            3,
            300,
        );
        let bnew = [BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("base.txt", b"base\n"),
                ("m.txt", b"main only\n"),
                ("src.txt", &src),
                ("b.txt", &bnew),
            ],
            vec![p1, c2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[0].text, BLOCK_A);
        assert_eq!(
            r.lines[0].commit_hash, c2,
            "a boundary -C source on a non-first parent is traced (git parity)"
        );
        assert_eq!(r.lines[1].commit_hash, c2);
    }

    #[test]
    fn blame_c_merge_boundary_copy_octopus_third_parent() {
        // Real git recipe (git 2.50.1): boundary case (file wholly new),
        // 3-way octopus merge, source only on the THIRD parent:
        //   base: base.txt="base"
        //   p1 = base + pm.txt("p1 only")   (no candidate)
        //   c2 = base + cm.txt("c2 only")   (no candidate)
        //   c3 = base + s3.txt(BLOCK_A,BLOCK_B,"zzz")  (candidate)
        //   merge(p1,c2,c3): adds b.txt=BLOCK_A+BLOCK_B (new path)
        //   $ git blame -C -C -l b.txt -> credited to c3. Guards the
        //   boundary search against stopping after the first two parents.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("base.txt", b"base\n")], vec![], 1, 100);
        let p1 = put_multi_file_commit(
            &store,
            &[("base.txt", b"base\n"), ("pm.txt", b"p1 only\n")],
            vec![base],
            2,
            200,
        );
        let c2 = put_multi_file_commit(
            &store,
            &[("base.txt", b"base\n"), ("cm.txt", b"c2 only\n")],
            vec![base],
            3,
            300,
        );
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let c3 = put_multi_file_commit(
            &store,
            &[("base.txt", b"base\n"), ("s3.txt", &src)],
            vec![base],
            4,
            400,
        );
        let bnew = [BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("base.txt", b"base\n"),
                ("pm.txt", b"p1 only\n"),
                ("cm.txt", b"c2 only\n"),
                ("s3.txt", &src),
                ("b.txt", &bnew),
            ],
            vec![p1, c2, c3],
            5,
            500,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[0].text, BLOCK_A);
        assert_eq!(
            r.lines[0].commit_hash, c3,
            "the boundary search walks every real parent, not just the first two"
        );
        assert_eq!(r.lines[1].commit_hash, c3);
    }

    #[test]
    fn blame_c_merge_boundary_copy_tie_prefers_first_parent() {
        // The boundary case's tie-break is the OPPOSITE of the interior
        // case's: real git recipe (git 2.50.1), both parents have the SAME
        // candidate for a wholly-new file:
        //   base: base.txt="base"
        //   p1 = base + s1.txt(BLOCK_A,BLOCK_B,"zzz")
        //   c2 = base + s2.txt(BLOCK_A,BLOCK_B,"zzz")  (same block)
        //   merge(p1,c2): adds b.txt=BLOCK_A+BLOCK_B (new path)
        //   $ git blame -C -C -l b.txt -> credited to p1 (the FIRST parent),
        //   unlike the interior tie (which excludes the first parent
        //   entirely). The boundary search includes every real parent,
        //   first-found-wins in natural order, so the first parent CAN win.
        let (_d, store) = fresh_store();
        let base = put_multi_file_commit(&store, &[("base.txt", b"base\n")], vec![], 1, 100);
        let src = [BLOCK_A, BLOCK_B, b"zzz", b""].join(&b'\n');
        let p1 = put_multi_file_commit(
            &store,
            &[("base.txt", b"base\n"), ("s1.txt", &src)],
            vec![base],
            2,
            200,
        );
        let c2 = put_multi_file_commit(
            &store,
            &[("base.txt", b"base\n"), ("s2.txt", &src)],
            vec![base],
            3,
            300,
        );
        let bnew = [BLOCK_A, BLOCK_B, b""].join(&b'\n');
        let merge = put_multi_file_commit(
            &store,
            &[
                ("base.txt", b"base\n"),
                ("s1.txt", &src),
                ("s2.txt", &src),
                ("b.txt", &bnew),
            ],
            vec![p1, c2],
            4,
            400,
        );

        let opts = BlameOptions {
            copies: CopyDetection::On {
                level: 2,
                threshold: 40,
            },
            ..Default::default()
        };
        let r = blame_file_with(&store, merge, "b.txt", &opts).unwrap();
        assert_eq!(r.lines[0].text, BLOCK_A);
        assert_eq!(
            r.lines[0].commit_hash, p1,
            "the boundary copy tie prefers the first parent (git parity) — unlike the interior tie"
        );
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
        let err = super::match_lines_with_options(&old, &new, &opts).unwrap_err();
        assert!(
            matches!(err, BlameError::FileTooLarge { lines } if lines == n),
            "got {err:?}"
        );

        let old2: Vec<Vec<u8>> = vec![b"a".to_vec(); 1];
        let new2: Vec<Vec<u8>> = vec![b"b".to_vec(); n];
        let err2 = super::match_lines_with_options(&old2, &new2, &opts).unwrap_err();
        assert!(
            matches!(err2, BlameError::FileTooLarge { lines } if lines == n),
            "got {err2:?}"
        );
    }
}
