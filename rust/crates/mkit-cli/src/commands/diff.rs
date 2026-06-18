//! `mkit diff` — show changes as a unified patch.
//!
//! Modes:
//!
//! - no args — HEAD tree vs a fresh worktree snapshot;
//! - `--staged` / `--cached` — HEAD tree vs the staged index tree
//!   (what `mkit commit` would record);
//! - one revision (`<rev>`) — that revision's tree vs the worktree (or
//!   vs the staged index with `--staged`);
//! - two revisions (`<a> <b>`) or a range (`<a>..<b>`) — diff the two
//!   resolved trees against each other.
//!
//! A leading positional that is not a resolvable revision is treated as
//! the start of the pathspec list; a leading positional that *looks*
//! like a revision (ref / commit / range) but fails to resolve is a
//! hard error rather than a silent empty diff (#207).
//!
//! Trailing positional paths (pathspecs) filter the output to entries
//! at or below those paths. The default output is a Git-compatible
//! unified diff: a git-shaped `diff --git a/<p> b/<p>` header per changed
//! path (with `new file mode`/`deleted file mode`/`index`/`--- a/p`/`+++ b/p`
//! lines, `/dev/null` for adds/deletes) followed by Myers-diff hunks (or a
//! `Binary files … differ` line). The `index` ids are abbreviated BLAKE3
//! prefixes — the one inherent divergence from `git diff`.
//!
//! `--name-only` / `--name-status` switch to summary output: one record
//! per changed path — just the path, or an `A`/`D`/`M` status letter
//! (`T` for an mkit mode change) plus the path. Special-byte paths are
//! C-style quoted (git `core.quotePath`); `-z` instead NUL-terminates
//! records and emits raw paths (and, for `--name-status`, NUL-terminates
//! the status letter and path as separate fields).

use std::io::Write;

use clap::Parser;
use mkit_core::hash::Hash;
use mkit_core::object::{EntryMode, Object};
use mkit_core::ops::merge::find_merge_base;
use mkit_core::ops::{DiffEntry, DiffKind, diff_line_counts, diff_trees, unified_hunks};
use mkit_core::refs;
use mkit_core::store::{EphemeralSink, ObjectSource, ObjectStore};
use mkit_core::worktree;

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit diff",
    about = "Show changes as a unified patch (HEAD vs worktree, --staged, or two trees)."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct DiffOpts {
    /// Diff the staged index tree against HEAD (the change `mkit commit`
    /// would record) instead of HEAD vs worktree.
    #[arg(long, visible_alias = "cached")]
    staged: bool,

    /// Show only the names of changed files, one per line, instead of a
    /// patch (like `git diff --name-only`).
    #[arg(long, conflicts_with = "name_status")]
    name_only: bool,

    /// Show a status letter (`A`/`D`/`M`; `T` for an mkit mode change)
    /// and the name of each changed file (like `git diff --name-status`).
    #[arg(long)]
    name_status: bool,

    /// Show a diffstat: per-file changed-line counts and a `+`/`-` graph,
    /// plus a summary line (like `git diff --stat`). Honors `COLUMNS`
    /// (default 80) for the graph width.
    #[arg(long, conflicts_with_all = ["name_only", "name_status"])]
    stat: bool,

    /// Diff against the merge base of the revisions, like `git diff
    /// --merge-base`. With one revision: `merge-base(<rev>, HEAD)` vs the
    /// worktree. With two: `merge-base(<a>, <b>)` vs `<b>`. (Equivalent to
    /// the `<a>...<b>` symmetric range, but spelled as a flag.)
    #[arg(long = "merge-base", conflicts_with = "staged")]
    merge_base: bool,

    /// NUL-terminate `--name-only` / `--name-status` records and emit raw
    /// (unquoted) paths — like `git diff -z`. In `--name-status`, the
    /// status letter and path are each NUL-terminated. Only valid with
    /// `--name-only` / `--name-status`.
    #[arg(short = 'z')]
    z: bool,

    /// Optional revisions (refs, full/short hashes, `HEAD~n`, or an
    /// `A..B` range) followed by optional pathspecs to limit the
    /// output. With no revisions, diffs HEAD vs worktree (or HEAD vs
    /// index with --staged). A leading argument that is not a resolvable
    /// revision starts the pathspec list.
    args: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<DiffOpts>("mkit diff", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    // `-z` only governs the `--name-only` / `--name-status` record
    // framing (per the parity matrix); it has no defined meaning for the
    // unified-patch output yet, so reject it rather than silently ignore.
    if opts.z && !(opts.name_only || opts.name_status) {
        return emit_err(
            "`-z` is only valid with `--name-only` or `--name-status`",
            exit::USAGE,
        );
    }
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    // Worktree/index snapshot trees are ephemeral: they live in this
    // in-memory overlay, never in the durable store — no flush cost,
    // no garbage objects. Reads fall through to the store.
    let snapshot = EphemeralSink::new(&store);

    let (old_tree, new_tree, pathspecs) = match resolve_diff_endpoints(
        &store,
        &snapshot,
        &mkit_dir,
        &cwd,
        opts.staged,
        opts.merge_base,
        &opts.args,
    ) {
        Ok(v) => v,
        Err((msg, code)) => return emit_err(&msg, code),
    };

    let result = match diff_trees(&snapshot, old_tree, new_tree) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("diff: {e}"), exit::GENERAL_ERROR),
    };

    let normalized: Vec<String> = pathspecs.iter().map(|p| normalize_pathspec(p)).collect();
    let selected = result
        .entries
        .iter()
        .filter(|e| normalized.is_empty() || path_matches_any(&e.path, &normalized));

    let mut stdout = std::io::stdout().lock();
    if opts.stat {
        return match render_stat(&mut stdout, &snapshot, selected) {
            Ok(()) => exit::OK,
            Err(msg) => emit_err(&msg, exit::GENERAL_ERROR),
        };
    }
    for e in selected {
        let res = if opts.name_only || opts.name_status {
            emit_entry_name(&mut stdout, e, opts.name_status, opts.z);
            Ok(())
        } else {
            emit_entry_patch(&mut stdout, &snapshot, e)
        };
        if let Err(msg) = res {
            return emit_err(&msg, exit::GENERAL_ERROR);
        }
    }
    exit::OK
}

/// One row of `--stat` output: a display name plus its change shape.
struct StatRow {
    /// Display name — C-style quoted (git `core.quotePath`) when needed.
    name: String,
    change: StatChange,
}

enum StatChange {
    /// Text change: added / deleted line counts.
    Text { added: usize, deleted: usize },
    /// Binary change: old / new byte sizes (rendered as `Bin … bytes`).
    Binary { old_len: usize, new_len: usize },
}

/// Render `git diff --stat`-compatible output: one `<name> | <count>
/// <graph>` row per changed file, then a `N files changed, …` summary.
///
/// Layout matches git: the name column is padded to the longest display
/// name, the count column is right-aligned to the widest total, and the
/// `+`/`-` graph is scaled to the terminal width when the largest change
/// would overflow it. Width = `COLUMNS` (if a positive integer) else 80,
/// exactly as git does even when stdout is not a tty.
pub(super) fn render_stat<'a, S: ObjectSource + ?Sized>(
    out: &mut impl Write,
    store: &S,
    entries: impl Iterator<Item = &'a DiffEntry>,
) -> Result<(), String> {
    // Gather per-file change shapes (and the blob bytes we need to count).
    let mut rows: Vec<StatRow> = Vec::new();
    for e in entries {
        let name = c_quote_name(&e.path);
        let change = if e.kind == DiffKind::ModeChanged {
            // Pure mode flip — no content delta. git shows `| 0`.
            StatChange::Text {
                added: 0,
                deleted: 0,
            }
        } else {
            let old_bytes = match e.old_hash {
                Some(h) => read_blob(store, &h)?,
                None => Vec::new(),
            };
            let new_bytes = match e.new_hash {
                Some(h) => read_blob(store, &h)?,
                None => Vec::new(),
            };
            match diff_line_counts(&old_bytes, &new_bytes) {
                Some((added, deleted)) => StatChange::Text { added, deleted },
                None => StatChange::Binary {
                    old_len: old_bytes.len(),
                    new_len: new_bytes.len(),
                },
            }
        };
        rows.push(StatRow { name, change });
    }
    if rows.is_empty() {
        return Ok(());
    }

    // Column metrics. `max_change` and the count-column width come from
    // text rows only (binary rows render `Bin …`, not a number).
    let name_width = rows
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0);
    let max_change = rows
        .iter()
        .filter_map(|r| match r.change {
            StatChange::Text { added, deleted } => Some(added + deleted),
            StatChange::Binary { .. } => None,
        })
        .max()
        .unwrap_or(0);
    let number_width = decimal_width(max_change);

    // Graph width: COLUMNS (or 80) minus the fixed framing (leading space,
    // " | ", the count column, and the space before the graph) — the
    // reservation git uses, derived empirically as `name + number + 6`.
    let total_width = terminal_columns();
    let graph_width = total_width
        .saturating_sub(name_width)
        .saturating_sub(number_width)
        .saturating_sub(6)
        .max(1);
    // git scales the graph only when the largest change can't fit.
    let scaled = max_change > graph_width;

    for r in &rows {
        match r.change {
            StatChange::Text { added, deleted } => {
                let total = added + deleted;
                let graph = stat_graph(added, deleted, graph_width, max_change, scaled);
                // git emits `| 0` with no trailing space/graph for a
                // zero-change row (empty-file add, mode-only); the graph
                // (and its leading space) appear only when there is one.
                if graph.is_empty() {
                    writeln!(
                        out,
                        " {name:<name_width$} | {total:>number_width$}",
                        name = r.name
                    )
                } else {
                    writeln!(
                        out,
                        " {name:<name_width$} | {total:>number_width$} {graph}",
                        name = r.name,
                    )
                }
                .map_err(|e| format!("write: {e}"))?;
            }
            StatChange::Binary { old_len, new_len } => {
                writeln!(
                    out,
                    " {name:<name_width$} | Bin {old_len} -> {new_len} bytes",
                    name = r.name,
                )
                .map_err(|e| format!("write: {e}"))?;
            }
        }
    }

    writeln!(out, "{}", stat_summary(&rows)).map_err(|e| format!("write: {e}"))?;
    Ok(())
}

/// The ` N files changed[, I insertions(+)][, D deletions(-)]` summary
/// line, matching git's `print_stat_summary`. git's clause rule: show
/// insertions when `ins != 0 || del == 0`, and deletions when
/// `del != 0 || ins == 0`. So a one-sided change shows only its side
/// (`1 file changed, 1 insertion(+)`), while a zero-change diff (mode-only,
/// binary-only, empty-file add) shows BOTH `0 insertions(+), 0
/// deletions(-)`. Pluralization is git's (`insertion`/`insertions`).
fn stat_summary(rows: &[StatRow]) -> String {
    use std::fmt::Write as _;
    let (mut ins, mut del) = (0usize, 0usize);
    for r in rows {
        if let StatChange::Text { added, deleted } = r.change {
            ins += added;
            del += deleted;
        }
    }
    let mut summary = format!(
        " {} {} changed",
        rows.len(),
        if rows.len() == 1 { "file" } else { "files" }
    );
    if ins != 0 || del == 0 {
        let _ = write!(
            summary,
            ", {ins} insertion{}(+)",
            if ins == 1 { "" } else { "s" }
        );
    }
    if del != 0 || ins == 0 {
        let _ = write!(
            summary,
            ", {del} deletion{}(-)",
            if del == 1 { "" } else { "s" }
        );
    }
    summary
}

/// The `+`/`-` graph for one file. Unscaled: literal `added` `+` then
/// `deleted` `-`. Scaled (git's algorithm): scale the total to the graph
/// width via [`scale_linear`], then split it across `+`/`-`.
fn stat_graph(
    added: usize,
    deleted: usize,
    graph_width: usize,
    max_change: usize,
    scaled: bool,
) -> String {
    let (plus, minus) = if scaled {
        let mut total = scale_linear(added + deleted, graph_width, max_change);
        if total < 2 && added > 0 && deleted > 0 {
            total = 2;
        }
        if added < deleted {
            let a = scale_linear(added, graph_width, max_change);
            (a, total - a)
        } else {
            let d = scale_linear(deleted, graph_width, max_change);
            (total - d, d)
        }
    } else {
        (added, deleted)
    };
    let mut g = "+".repeat(plus);
    g.push_str(&"-".repeat(minus));
    g
}

/// git's diffstat scaling: map `it` changes onto `width` columns. Returns
/// 0 for no change, else at least 1 (so any change shows at least one
/// mark) — `1 + it*(width-1)/max_change`, integer arithmetic, matching
/// git's `scale_linear`.
fn scale_linear(it: usize, width: usize, max_change: usize) -> usize {
    if it == 0 {
        return 0;
    }
    1 + it * (width - 1) / max_change
}

/// Number of decimal digits needed to print `n` (at least 1, for `0`).
fn decimal_width(n: usize) -> usize {
    let mut w = 1;
    let mut v = n;
    while v >= 10 {
        v /= 10;
        w += 1;
    }
    w
}

/// Graph width source: `COLUMNS` when it parses to a positive integer,
/// else git's piped default of 80.
fn terminal_columns() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.trim().parse::<usize>().ok())
        .filter(|&c| c > 0)
        .unwrap_or(80)
}

/// Display name for stat/summary rows: C-style quoted like git's default
/// `core.quotePath` when the path has special bytes, else the raw path.
fn c_quote_name(path: &str) -> String {
    super::c_quote_path(path).unwrap_or_else(|| path.to_string())
}

/// Status letter for `--name-status`. mkit's `ModeChanged` maps to `T`
/// (git's type-change letter) — a documented mkit extension, since mkit
/// tracks a pure mode flip as its own diff kind.
fn name_status_letter(kind: DiffKind) -> char {
    match kind {
        DiffKind::Added => 'A',
        DiffKind::Removed => 'D',
        DiffKind::Modified => 'M',
        DiffKind::ModeChanged => 'T',
    }
}

/// Emit one `--name-only` / `--name-status` record for a changed entry.
///
/// Newline mode: `<path>\n` (name-only) or `<letter>\t<path>\n`
/// (name-status); a path with special bytes is C-style quoted like git's
/// default `core.quotePath`. `-z` mode: paths are raw (unquoted) and
/// records are NUL-terminated — `<path>\0`, or `<letter>\0<path>\0` where
/// the status letter and path are each their own NUL-terminated field
/// (matching `git diff --name-status -z`).
fn emit_entry_name(out: &mut impl Write, e: &DiffEntry, name_status: bool, z: bool) {
    if z {
        if name_status {
            let _ = write!(out, "{}\0", name_status_letter(e.kind));
        }
        let _ = write!(out, "{}\0", e.path);
        return;
    }
    let path = super::c_quote_path(&e.path);
    let shown = path.as_deref().unwrap_or(&e.path);
    if name_status {
        let _ = writeln!(out, "{}\t{shown}", name_status_letter(e.kind));
    } else {
        let _ = writeln!(out, "{shown}");
    }
}

/// `(old_tree, new_tree, pathspecs)` triple computed from the args.
type DiffEndpoints = (Option<Hash>, Option<Hash>, Vec<String>);

/// Decide the `old_tree` / `new_tree` / pathspecs triple from the
/// `staged` flag and the positional args. Returns `(message, exit_code)`
/// on error so the caller can route it through `emit_err`.
///
/// Cases:
/// - `--staged <rev>...` (any positionals) — usage contradiction
///   (#223): `--staged` already fixes both endpoints (HEAD vs index).
/// - `<a>..<b> [paths…]` — range form; both ends resolved to trees.
/// - `<a> <b> [paths…]` — two revisions, when both resolve.
/// - `<a> [paths…]` — one revision vs worktree (or vs index w/--staged
///   only in the no-positional case, handled above).
/// - no leading revision — default HEAD-vs-worktree / HEAD-vs-index,
///   all positionals are pathspecs.
/// `--merge-base` endpoint resolution. One revision: `merge-base(rev,
/// HEAD)` vs the worktree; two revisions: `merge-base(a, b)` vs `b`.
/// Trailing positionals are pathspecs. Annotated tags are peeled to their
/// commit before the merge-base walk, like git.
fn resolve_merge_base_endpoints(
    store: &ObjectStore,
    snapshot: &EphemeralSink<'_>,
    mkit_dir: &std::path::Path,
    cwd: &std::path::Path,
    args: &[String],
) -> Result<DiffEndpoints, (String, u8)> {
    let first = args.first().ok_or_else(|| {
        (
            "`--merge-base` requires at least one revision".to_string(),
            exit::USAGE,
        )
    })?;
    let a = peel_tags(
        store,
        revspec::resolve_revision(store, mkit_dir, first)
            .map_err(|e| (format!("bad revision '{first}': {e}"), exit::DATAERR))?,
    );

    // A second positional that resolves to a revision selects the
    // two-revision form. One that only *looks* like a revision but fails to
    // resolve is a hard error (#207); anything else is a pathspec, leaving
    // the single-revision (vs worktree) form.
    if let Some(second) = args.get(1) {
        match revspec::resolve_revision(store, mkit_dir, second) {
            Ok(h) => {
                let b = peel_tags(store, h);
                let base = merge_base_of(store, a, b)?;
                let old = object_to_tree(store, &base).map_err(|e| (e, exit::GENERAL_ERROR))?;
                let new = object_to_tree(store, &b).map_err(|e| (e, exit::GENERAL_ERROR))?;
                return Ok((Some(old), Some(new), args[2..].to_vec()));
            }
            // A 2nd positional that fails to resolve is treated as a pathspec
            // ONLY when it is clearly path-shaped (names an existing worktree
            // path, or contains `/`). Otherwise it is an ambiguous bad
            // revision — a typo'd `<b>` — which we surface, rather than
            // silently falling back to the single-rev form and emitting an
            // empty diff (matching git's "ambiguous argument" behavior).
            Err(e)
                if matches!(e, revspec::RevError::Unknown(_))
                    && looks_like_pathspec(cwd, second) => {}
            Err(e) => return Err((format!("bad revision '{second}': {e}"), exit::DATAERR)),
        }
    }

    // Single revision: merge-base(rev, HEAD) vs the worktree.
    let head = refs::resolve_head(mkit_dir)
        .map_err(|e| (format!("resolve HEAD: {e}"), exit::GENERAL_ERROR))?
        .ok_or_else(|| {
            (
                "HEAD has no commit to take a merge base with".to_string(),
                exit::GENERAL_ERROR,
            )
        })?;
    let head = peel_tags(store, head);
    let base = merge_base_of(store, a, head)?;
    let old = object_to_tree(store, &base).map_err(|e| (e, exit::GENERAL_ERROR))?;
    let new = worktree_tree_filtered(store, snapshot, cwd)?;
    Ok((Some(old), Some(new), args[1..].to_vec()))
}

/// Resolve the single merge base of `a` and `b`, mapping "no base" to a
/// clear error (matches git's `--merge-base` failure on unrelated histories).
fn merge_base_of(store: &ObjectStore, a: Hash, b: Hash) -> Result<Hash, (String, u8)> {
    find_merge_base(store, a, b)
        .map_err(|e| (format!("merge base: {e}"), exit::GENERAL_ERROR))?
        .ok_or_else(|| {
            (
                "no merge base between the given revisions".to_string(),
                exit::DATAERR,
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn resolve_diff_endpoints(
    store: &ObjectStore,
    snapshot: &EphemeralSink<'_>,
    mkit_dir: &std::path::Path,
    cwd: &std::path::Path,
    staged: bool,
    merge_base: bool,
    args: &[String],
) -> Result<DiffEndpoints, (String, u8)> {
    // `--merge-base <a> [<b>] [paths…]` — diff the merge base of the given
    // revision(s) rather than the revisions themselves. Resolved before
    // any other form (clap already rejects `--merge-base --staged`).
    if merge_base {
        return resolve_merge_base_endpoints(store, snapshot, mkit_dir, cwd, args);
    }

    // #223: `--staged` with explicit revisions is contradictory —
    // `--staged` already pins HEAD vs the index. Pathspecs are fine, but
    // a leading argument that *looks* like a revision is not, and must
    // fail closed: if it resolves it is the contradiction (#223), and if
    // it does not it is a bad revision (#207). Either way we error rather
    // than silently treating a typo'd hash as a no-match pathspec (which
    // would empty-succeed and diverge from `git diff --cached <bad-rev>`).
    // A non-rev-looking leading arg (e.g. `path/`, `file.txt`) still falls
    // through as a pathspec filter.
    if staged {
        if let Some(first) = args.first()
            && looks_like_rev_request(first)
        {
            if revspec::resolve_revision(store, mkit_dir, strip_range_end(first).0).is_ok() {
                return Err((
                    "`--staged` diffs HEAD vs the index; it cannot take an explicit revision"
                        .to_string(),
                    exit::USAGE,
                ));
            }
            return Err((
                format!("bad revision '{first}': not a known ref, commit, or short hash"),
                exit::DATAERR,
            ));
        }
        // No leading revision: HEAD vs index, all positionals = pathspecs.
        let head = head_tree(store, mkit_dir).map_err(|e| (e, exit::GENERAL_ERROR))?;
        let idx = index_tree(cwd, store, snapshot).map_err(|e| (e, exit::GENERAL_ERROR))?;
        return Ok((head, idx, args.to_vec()));
    }

    // Symmetric range `A...B` = diff the merge base of A and B against B
    // (git semantics). Must be checked before `A..B` (which it contains).
    if let Some(first) = args.first()
        && let Some((a, b)) = split_symmetric(first)
    {
        // Peel annotated/signed tags to their commit before merge-base
        // resolution, like git (and like `log` does for its range bases).
        let commit_a = peel_tags(
            store,
            revspec::resolve_revision(store, mkit_dir, a)
                .map_err(|e| (format!("bad revision '{a}': {e}"), exit::DATAERR))?,
        );
        let commit_b = peel_tags(
            store,
            revspec::resolve_revision(store, mkit_dir, b)
                .map_err(|e| (format!("bad revision '{b}': {e}"), exit::DATAERR))?,
        );
        let mb = find_merge_base(store, commit_a, commit_b)
            .map_err(|e| (format!("merge base: {e}"), exit::GENERAL_ERROR))?
            .ok_or_else(|| {
                (
                    format!("no merge base between '{a}' and '{b}'"),
                    exit::DATAERR,
                )
            })?;
        let old = object_to_tree(store, &mb).map_err(|e| (e, exit::GENERAL_ERROR))?;
        let new = object_to_tree(store, &commit_b).map_err(|e| (e, exit::GENERAL_ERROR))?;
        return Ok((Some(old), Some(new), args[1..].to_vec()));
    }

    // Range form `A..B` as the first positional.
    if let Some(first) = args.first()
        && let Some((a, b)) = split_range(first)
    {
        let old = rev_to_tree(store, mkit_dir, a)?;
        let new = rev_to_tree(store, mkit_dir, b)?;
        return Ok((Some(old), Some(new), args[1..].to_vec()));
    }

    // Try to peel one or two leading revisions.
    let first_rev = args
        .first()
        .and_then(|a| try_rev_to_tree(store, mkit_dir, a));
    match first_rev {
        None => {
            // No leading revision → default HEAD vs worktree; all
            // positionals are pathspecs. If the first arg *looked* like
            // a revision but failed to resolve, error loudly (#207)
            // rather than silently treating it as a pathspec.
            if let Some(first) = args.first()
                && looks_like_rev_request(first)
            {
                return Err((
                    format!("bad revision '{first}': not a known ref, commit, or short hash"),
                    exit::DATAERR,
                ));
            }
            let head = head_tree(store, mkit_dir).map_err(|e| (e, exit::GENERAL_ERROR))?;
            let new = Some(worktree_tree_filtered(store, snapshot, cwd)?);
            Ok((head, new, args.to_vec()))
        }
        Some(Err(e)) => Err(e),
        Some(Ok(old)) => {
            // One revision resolved. Is the second positional also a
            // revision? If so, two-rev mode; otherwise rev-vs-worktree.
            let second_rev = args
                .get(1)
                .and_then(|a| try_rev_to_tree(store, mkit_dir, a));
            match second_rev {
                Some(Ok(new)) => Ok((Some(old), Some(new), args[2..].to_vec())),
                Some(Err(e)) => Err(e),
                None => {
                    let new = Some(worktree_tree_filtered(store, snapshot, cwd)?);
                    Ok((Some(old), new, args[1..].to_vec()))
                }
            }
        }
    }
}

/// Resolve a revision spec to a tree hash, mapping a commit/remix to its
/// tree and accepting a bare tree hash as itself. `(message, code)` on
/// failure.
/// Snapshot the worktree, seeding the tracked set from the index (or HEAD
/// when no index file exists) so a tracked file matching an ignore rule is
/// not dropped from the snapshot and misreported as a deletion.
fn worktree_tree_filtered(
    store: &ObjectStore,
    snapshot: &EphemeralSink<'_>,
    cwd: &std::path::Path,
) -> Result<Hash, (String, u8)> {
    let idx =
        super::read_or_seed_index_from_head(cwd, store).map_err(|e| (e, exit::GENERAL_ERROR))?;
    worktree::build_tree_filtered(snapshot, cwd, Some(&idx))
        .map_err(|e| (format!("build tree: {e}"), exit::GENERAL_ERROR))
}

fn rev_to_tree(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    spec: &str,
) -> Result<Hash, (String, u8)> {
    let h = revspec::resolve_revision(store, mkit_dir, spec)
        .map_err(|e| (format!("bad revision '{spec}': {e}"), exit::DATAERR))?;
    object_to_tree(store, &h).map_err(|e| (e, exit::GENERAL_ERROR))
}

/// Like [`rev_to_tree`] but distinguishes "not a revision at all" (None)
/// from "looks like a revision but is broken" (`Some(Err(..))`).
fn try_rev_to_tree(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    spec: &str,
) -> Option<Result<Hash, (String, u8)>> {
    match revspec::resolve_revision(store, mkit_dir, spec) {
        Ok(h) => Some(object_to_tree(store, &h).map_err(|e| (e, exit::GENERAL_ERROR))),
        Err(revspec::RevError::Unknown(_)) => {
            // Not a known ref/object. If it still *looks* like a
            // revision request (ref-shaped or hash-shaped), surface the
            // failure; otherwise it is a pathspec.
            if looks_like_rev_request(spec) {
                Some(Err((
                    format!("bad revision '{spec}': not a known ref, commit, or short hash"),
                    exit::DATAERR,
                )))
            } else {
                None
            }
        }
        Err(e) => Some(Err((format!("bad revision '{spec}': {e}"), exit::DATAERR))),
    }
}

/// Follow `Object::Tag` targets to the first non-tag object, so an
/// annotated/signed tag resolves to the commit it points at (bounded against
/// a tag-of-tag cycle). A non-tag / unreadable object is returned unchanged.
fn peel_tags(store: &ObjectStore, mut h: Hash) -> Hash {
    for _ in 0..16 {
        match store.read_object(&h) {
            Ok(Object::Tag(t)) => h = t.target,
            _ => break,
        }
    }
    h
}

/// Map a resolved object hash to a tree hash: commit/remix → its tree,
/// a tree → itself.
pub(super) fn object_to_tree(store: &ObjectStore, h: &Hash) -> Result<Hash, String> {
    match store.read_object(h) {
        Ok(Object::Commit(c)) => Ok(c.tree_hash),
        Ok(Object::Remix(r)) => Ok(r.tree_hash),
        Ok(Object::Tree(_)) => Ok(*h),
        Ok(_) => Err(format!(
            "{} is not a commit, remix, or tree",
            mkit_core::hash::to_hex(h)
        )),
        Err(e) => Err(format!("read object: {e}")),
    }
}

/// Split an `A..B` range. Returns `None` if there is no `..`.
fn split_range(s: &str) -> Option<(&str, &str)> {
    let (a, b) = s.split_once("..")?;
    if a.is_empty() || b.is_empty() {
        return None;
    }
    Some((a, b))
}

/// Split a symmetric `A...B` range. An empty side defaults to `HEAD`
/// (`A...` = `A...HEAD`, `...B` = `HEAD...B`).
fn split_symmetric(s: &str) -> Option<(&str, &str)> {
    let (a, b) = s.split_once("...")?;
    Some((
        if a.is_empty() { "HEAD" } else { a },
        if b.is_empty() { "HEAD" } else { b },
    ))
}

/// The left-hand end of a possible range, used for the `--staged`
/// contradiction probe. Returns `(rev, is_range)`.
fn strip_range_end(s: &str) -> (&str, bool) {
    match s.split_once("..") {
        Some((a, _)) if !a.is_empty() => (a, true),
        _ => (s, false),
    }
}

/// Heuristic for #207: does this argument look like the user *intended*
/// a revision (so a resolve failure should be a hard error) rather than
/// a pathspec? True for hash-shaped tokens, `A..B` ranges, and the
/// literal `HEAD` (possibly with `~`/`^` navigation). A plain
/// filesystem-y token (`src/`, `./x`, `*.rs`) is treated as a pathspec.
fn looks_like_rev_request(s: &str) -> bool {
    if s.contains("..") {
        return true;
    }
    // A `~` or `^` navigation suffix is revision syntax, not a path.
    let base = s.split(['~', '^']).next().unwrap_or(s);
    if base == "HEAD" {
        return true;
    }
    // Hash-shaped: ≥ MIN_SHORT_HASH hex chars with no path separators.
    base.len() >= revspec::MIN_SHORT_HASH
        && !base.contains('/')
        && !base.contains('.')
        && base.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Is `arg` clearly a pathspec rather than a (typo'd) revision? True when it
/// names an existing worktree path or contains a `/` separator. Used by
/// `--merge-base` to keep a bad second revision from silently degrading into
/// an empty-output pathspec filter.
fn looks_like_pathspec(cwd: &std::path::Path, arg: &str) -> bool {
    arg.contains('/') || cwd.join(arg).symlink_metadata().is_ok()
}

fn head_tree(store: &ObjectStore, mkit_dir: &std::path::Path) -> Result<Option<Hash>, String> {
    let head = refs::resolve_head(mkit_dir).map_err(|e| format!("resolve HEAD: {e}"))?;
    match head {
        None => Ok(None),
        Some(h) => match store.read_object(&h) {
            Ok(Object::Commit(c)) => Ok(Some(c.tree_hash)),
            Ok(Object::Remix(r)) => Ok(Some(r.tree_hash)),
            Ok(_) => Ok(None),
            Err(e) => Err(format!("read HEAD: {e}")),
        },
    }
}

fn index_tree(
    root: &std::path::Path,
    store: &ObjectStore,
    snapshot: &EphemeralSink<'_>,
) -> Result<Option<Hash>, String> {
    let idx = super::read_or_seed_index_from_head(root, store)?;
    // Ephemeral diff snapshot — nothing durable is published, so skip the
    // re-hash; the read path verifies any object actually touched.
    let tree = worktree::build_tree_from_index_with(store, snapshot, &idx, false)
        .map_err(|e| format!("build index tree: {e}"))?;
    Ok(Some(tree))
}

/// Normalize a pathspec to the index/diff path form: strip a leading
/// `./`, collapse `\\` to `/`, drop a trailing `/`.
fn normalize_pathspec(spec: &str) -> String {
    let s = spec.replace('\\', "/");
    let s = s.strip_prefix("./").unwrap_or(&s);
    s.strip_suffix('/').unwrap_or(s).to_string()
}

fn path_matches_any(path: &str, specs: &[String]) -> bool {
    specs
        .iter()
        .any(|spec| super::index_path_matches_or_descends(path, spec))
}

/// Abbreviated all-zero blob id git prints for an absent side of `index`.
const ZERO_ABBREV: &str = "0000000";

/// git octal mode string for a [`DiffEntry`] side (`None` → regular file).
fn git_octal(mode: Option<EntryMode>) -> &'static str {
    match mode {
        Some(EntryMode::Executable) => "100755",
        Some(EntryMode::Symlink) => "120000",
        Some(EntryMode::Tree) => "040000",
        _ => "100644",
    }
}

/// Abbreviated blob id for an `index` line side (`None` → all-zero).
fn abbrev(h: Option<Hash>) -> String {
    h.map_or_else(|| ZERO_ABBREV.to_string(), |h| format::short_hash(&h, 7))
}

/// Emit a git-shaped `diff --git` header plus unified-diff hunks for one
/// changed entry. The `index <old>..<new>` ids are abbreviated BLAKE3
/// prefixes (longer than git's SHA-1 prefixes for the same `core.abbrev`),
/// the one inherent divergence; everything else matches `git diff`.
///
/// Shared with `mkit show`, so a commit's diff body is byte-identical to
/// `mkit diff <parent> <commit>`.
pub(super) fn emit_entry_patch<S: ObjectSource + ?Sized>(
    out: &mut impl Write,
    store: &S,
    e: &DiffEntry,
) -> Result<(), String> {
    // git C-style quotes special-byte paths in the header (core.quotePath),
    // quoting the whole `a/<path>` / `b/<path>` token as a unit.
    let a_path = quoted_side('a', &e.path);
    let b_path = quoted_side('b', &e.path);
    let _ = writeln!(out, "diff --git {a_path} {b_path}");

    match e.kind {
        DiffKind::ModeChanged => {
            // Identical content, mode flip — only the mode lines, no hunks.
            let _ = writeln!(out, "old mode {}", git_octal(e.old_mode));
            let _ = writeln!(out, "new mode {}", git_octal(e.new_mode));
            return Ok(());
        }
        DiffKind::Added => {
            let _ = writeln!(out, "new file mode {}", git_octal(e.new_mode));
            let _ = writeln!(out, "index {}..{}", ZERO_ABBREV, abbrev(e.new_hash));
        }
        DiffKind::Removed => {
            let _ = writeln!(out, "deleted file mode {}", git_octal(e.old_mode));
            let _ = writeln!(out, "index {}..{}", abbrev(e.old_hash), ZERO_ABBREV);
        }
        DiffKind::Modified if e.old_mode != e.new_mode => {
            // Content and mode both changed: mode lines, index without mode.
            let _ = writeln!(out, "old mode {}", git_octal(e.old_mode));
            let _ = writeln!(out, "new mode {}", git_octal(e.new_mode));
            let _ = writeln!(out, "index {}..{}", abbrev(e.old_hash), abbrev(e.new_hash));
        }
        DiffKind::Modified => {
            let _ = writeln!(
                out,
                "index {}..{} {}",
                abbrev(e.old_hash),
                abbrev(e.new_hash),
                git_octal(e.new_mode)
            );
        }
    }

    let old_bytes = match e.old_hash {
        Some(h) => read_blob(store, &h)?,
        None => Vec::new(),
    };
    let new_bytes = match e.new_hash {
        Some(h) => read_blob(store, &h)?,
        None => Vec::new(),
    };
    // `--- a/p` / `+++ b/p` (quoted), with `/dev/null` for the absent side.
    let (minus, plus) = match e.kind {
        DiffKind::Added => ("/dev/null".to_string(), b_path.clone()),
        DiffKind::Removed => (a_path.clone(), "/dev/null".to_string()),
        _ => (a_path.clone(), b_path.clone()),
    };
    match unified_hunks(&old_bytes, &new_bytes) {
        None => {
            let _ = writeln!(out, "Binary files {minus} and {plus} differ");
        }
        Some(hunks) if hunks.is_empty() => {}
        Some(hunks) => {
            let _ = writeln!(out, "--- {minus}");
            let _ = writeln!(out, "+++ {plus}");
            let _ = out.write_all(&hunks);
        }
    }
    Ok(())
}

/// The git-quoted `a/<path>` / `b/<path>` token for a patch header: C-style
/// quoted (with surrounding quotes) when the path has special bytes, else the
/// plain `<side>/<path>`.
fn quoted_side(side: char, path: &str) -> String {
    let s = format!("{side}/{path}");
    super::c_quote_path(&s).unwrap_or(s)
}

/// Read a blob's bytes from the store, reassembling chunked blobs via
/// the shared core helper so diff/cat/checkout agree (#203).
fn read_blob<S: ObjectSource + ?Sized>(store: &S, h: &Hash) -> Result<Vec<u8>, String> {
    worktree::read_blob(store, h).map_err(|e| format!("read object: {e}"))
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn de(path: &str, kind: DiffKind) -> DiffEntry {
        DiffEntry {
            path: path.to_string(),
            kind,
            old_hash: None,
            new_hash: None,
            old_mode: None,
            new_mode: None,
        }
    }

    fn render(e: &DiffEntry, name_status: bool, z: bool) -> String {
        let mut buf = Vec::new();
        emit_entry_name(&mut buf, e, name_status, z);
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn name_status_letters_cover_every_kind() {
        assert_eq!(name_status_letter(DiffKind::Added), 'A');
        assert_eq!(name_status_letter(DiffKind::Removed), 'D');
        assert_eq!(name_status_letter(DiffKind::Modified), 'M');
        assert_eq!(name_status_letter(DiffKind::ModeChanged), 'T');
    }

    #[test]
    fn decimal_width_counts_digits() {
        assert_eq!(decimal_width(0), 1);
        assert_eq!(decimal_width(9), 1);
        assert_eq!(decimal_width(10), 2);
        assert_eq!(decimal_width(201), 3);
    }

    #[test]
    fn scale_linear_matches_git_formula() {
        // it == 0 → 0; otherwise 1 + it*(width-1)/max_change.
        assert_eq!(scale_linear(0, 47, 201), 0);
        // The values verified against real git: a.txt total 13 → 3,
        // its single deletion → 1; the 201-change file fills the width.
        assert_eq!(scale_linear(13, 47, 201), 3);
        assert_eq!(scale_linear(1, 47, 201), 1);
        assert_eq!(scale_linear(201, 47, 201), 47);
    }

    #[test]
    fn stat_graph_unscaled_is_literal() {
        // When not scaling, the graph is `added` '+' then `deleted` '-'.
        assert_eq!(stat_graph(3, 0, 66, 4, false), "+++");
        assert_eq!(stat_graph(3, 1, 66, 4, false), "+++-");
        assert_eq!(stat_graph(0, 1, 66, 4, false), "-");
    }

    #[test]
    fn stat_graph_scaled_splits_like_git() {
        // a.txt: +12/-1 over graph_width 47, max_change 201 → "++-".
        assert_eq!(stat_graph(12, 1, 47, 201, true), "++-");
        // the max-change file fills the width: 46 '+' + 1 '-'.
        assert_eq!(
            stat_graph(200, 1, 47, 201, true),
            format!("{}-", "+".repeat(46))
        );
    }

    #[test]
    fn name_only_newline_plain_path() {
        assert_eq!(
            render(&de("a.txt", DiffKind::Modified), false, false),
            "a.txt\n"
        );
    }

    #[test]
    fn name_status_newline_is_letter_tab_path() {
        assert_eq!(
            render(&de("a.txt", DiffKind::Added), true, false),
            "A\ta.txt\n"
        );
    }

    #[test]
    fn name_only_quotes_special_path_in_newline_mode() {
        // A tab is C-style quoted like git core.quotePath.
        assert_eq!(
            render(&de("a\tb.txt", DiffKind::Modified), false, false),
            "\"a\\tb.txt\"\n"
        );
    }

    #[test]
    fn z_mode_is_raw_and_nul_terminated() {
        // name-only -z: `<path>\0`, path emitted raw (unquoted).
        assert_eq!(
            render(&de("a\tb.txt", DiffKind::Modified), false, true),
            "a\tb.txt\0"
        );
        // name-status -z: `<letter>\0<path>\0` — two NUL-terminated fields.
        assert_eq!(
            render(&de("del.txt", DiffKind::Removed), true, true),
            "D\0del.txt\0"
        );
    }
}
