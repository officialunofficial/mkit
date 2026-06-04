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
//! unified diff: a `diff --mkit a/<p> b/<p>` header per changed path
//! followed by the `text_patch` hunks (or `Binary files … differ`).
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
use mkit_core::object::Object;
use mkit_core::ops::{DiffEntry, DiffKind, diff_trees, text_patch};
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use mkit_core::worktree;

use super::revspec;
use crate::clap_shim;
use crate::exit;

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

    let (old_tree, new_tree, pathspecs) =
        match resolve_diff_endpoints(&store, &mkit_dir, &cwd, opts.staged, &opts.args) {
            Ok(v) => v,
            Err((msg, code)) => return emit_err(&msg, code),
        };

    let result = match diff_trees(&store, old_tree, new_tree) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("diff: {e}"), exit::GENERAL_ERROR),
    };

    let normalized: Vec<String> = pathspecs.iter().map(|p| normalize_pathspec(p)).collect();

    let mut stdout = std::io::stdout().lock();
    for e in &result.entries {
        if !normalized.is_empty() && !path_matches_any(&e.path, &normalized) {
            continue;
        }
        let res = if opts.name_only || opts.name_status {
            emit_entry_name(&mut stdout, e, opts.name_status, opts.z);
            Ok(())
        } else {
            emit_entry_patch(&mut stdout, &store, e)
        };
        if let Err(msg) = res {
            return emit_err(&msg, exit::GENERAL_ERROR);
        }
    }
    exit::OK
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
fn resolve_diff_endpoints(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    cwd: &std::path::Path,
    staged: bool,
    args: &[String],
) -> Result<DiffEndpoints, (String, u8)> {
    // #223: `--staged` with explicit revisions is contradictory —
    // `--staged` already pins HEAD vs the index. Pathspecs are fine, but
    // a leading revision is not. We only reject when the first arg
    // actually resolves as a revision (so `mkit diff --staged path/`
    // keeps working as a pathspec filter).
    if staged {
        if let Some(first) = args.first()
            && looks_like_rev_request(first)
            && revspec::resolve_revision(store, mkit_dir, strip_range_end(first).0).is_ok()
        {
            return Err((
                "`--staged` diffs HEAD vs the index; it cannot take an explicit revision"
                    .to_string(),
                exit::USAGE,
            ));
        }
        // No leading revision: HEAD vs index, all positionals = pathspecs.
        let head = head_tree(store, mkit_dir).map_err(|e| (e, exit::GENERAL_ERROR))?;
        let idx = index_tree(cwd, store).map_err(|e| (e, exit::GENERAL_ERROR))?;
        return Ok((head, idx, args.to_vec()));
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
            let new = worktree::build_tree(store, cwd)
                .map(Some)
                .map_err(|e| (format!("build tree: {e}"), exit::GENERAL_ERROR))?;
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
                    let new = worktree::build_tree(store, cwd)
                        .map(Some)
                        .map_err(|e| (format!("build tree: {e}"), exit::GENERAL_ERROR))?;
                    Ok((Some(old), new, args[1..].to_vec()))
                }
            }
        }
    }
}

/// Resolve a revision spec to a tree hash, mapping a commit/remix to its
/// tree and accepting a bare tree hash as itself. `(message, code)` on
/// failure.
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

/// Map a resolved object hash to a tree hash: commit/remix → its tree,
/// a tree → itself.
fn object_to_tree(store: &ObjectStore, h: &Hash) -> Result<Hash, String> {
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

fn index_tree(root: &std::path::Path, store: &ObjectStore) -> Result<Option<Hash>, String> {
    let idx = super::read_or_seed_index_from_head(root, store)?;
    let tree = worktree::build_tree_from_index(store, &idx)
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

/// Emit the `diff --mkit` header plus hunks for one changed entry.
fn emit_entry_patch(
    out: &mut impl Write,
    store: &ObjectStore,
    e: &DiffEntry,
) -> Result<(), String> {
    let _ = writeln!(out, "diff --mkit a/{} b/{}", e.path, e.path);
    match e.kind {
        DiffKind::ModeChanged => {
            // Same content, mode flip — no textual hunk to show.
            let _ = writeln!(out, "mode changed: {}", e.path);
            return Ok(());
        }
        DiffKind::Added => {
            let _ = writeln!(out, "new file: {}", e.path);
        }
        DiffKind::Removed => {
            let _ = writeln!(out, "deleted file: {}", e.path);
        }
        DiffKind::Modified => {}
    }

    let old_bytes = match e.old_hash {
        Some(h) => read_blob(store, &h)?,
        None => Vec::new(),
    };
    let new_bytes = match e.new_hash {
        Some(h) => read_blob(store, &h)?,
        None => Vec::new(),
    };
    let patch = text_patch(&old_bytes, &new_bytes, &e.path, &e.path);
    let _ = out.write_all(patch.as_bytes());
    Ok(())
}

/// Read a blob's bytes from the store, reassembling chunked blobs via
/// the shared core helper so diff/cat/checkout agree (#203).
fn read_blob(store: &ObjectStore, h: &Hash) -> Result<Vec<u8>, String> {
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
