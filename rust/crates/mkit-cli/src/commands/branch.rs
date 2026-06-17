//! `mkit branch` — list / create / delete branches.
//!
//! Output modes for the list form:
//!
//! - default — `<marker> <name>` per line, `*` marks current. Matches
//!   `git branch`: the commit id is **not** shown (it moved behind `-v`).
//! - `-v` / `--verbose` — `<marker> <name> <short> <subject>`, the name
//!   column padded to the longest branch name, like `git branch -v`. The
//!   abbreviated id is a BLAKE3 prefix (the documented hash-length
//!   divergence), not a 40-hex SHA-1 prefix.
//! - `--format=json` — JSONL: `{"name":"...","current":bool,"hash":"<64-hex>"}`.

use std::io::Write;

use clap::{Parser, ValueEnum};
use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::ops::merge::is_ancestor;
use mkit_core::refs::{self, Head};
use mkit_core::store::ObjectStore;

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;

/// Abbreviated-id length for `branch -v`, matching `log`'s default and
/// git's default `core.abbrev` (7) in shape (mkit's id is a BLAKE3 prefix).
const DEFAULT_ABBREV: usize = 7;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BranchFormat {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit branch",
    about = "List, create, rename, or delete branches."
)]
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
struct BranchOpts {
    /// Delete the named branch (safe — refuses the current branch and a
    /// non-existent branch).
    #[arg(short = 'd', long)]
    delete: bool,
    /// Force-delete the named branch. mkit tracks no per-branch merge
    /// state, so `-D` behaves like `-d`: it still refuses the branch HEAD
    /// points at (that would leave HEAD dangling) and, like git, errors on
    /// an absent branch rather than reporting a silent success.
    #[arg(short = 'D')]
    force_delete: bool,
    /// Rename a branch. `branch -m <old> <new>` renames `<old>`;
    /// `branch -m <new>` renames the current branch. Moves HEAD when the
    /// renamed branch is the checked-out one.
    #[arg(short = 'm', long)]
    rename: bool,
    /// Verbose list: also show each branch tip's abbreviated id and
    /// commit subject (like `git branch -v`).
    #[arg(short = 'v', long)]
    verbose: bool,
    /// List branches (explicit selector, like `git branch --list`). Listing
    /// is already the default when no create/delete/rename flag is given;
    /// `--list` additionally enables positional `<pattern>` glob filtering.
    #[arg(long)]
    list: bool,
    /// List only branches whose tip has `<commit>` as an ancestor (like
    /// `git branch --contains`).
    #[arg(long, value_name = "COMMIT")]
    contains: Option<String>,
    /// List only branches whose tip does NOT contain `<commit>`.
    #[arg(long = "no-contains", value_name = "COMMIT")]
    no_contains: Option<String>,
    /// List only branches already merged into `<commit>` (default HEAD) —
    /// the branch tip is an ancestor of it (like `git branch --merged`).
    #[arg(long, value_name = "COMMIT", num_args = 0..=1, default_missing_value = "HEAD")]
    merged: Option<String>,
    /// List only branches NOT merged into `<commit>` (default HEAD).
    #[arg(long = "no-merged", value_name = "COMMIT", num_args = 0..=1, default_missing_value = "HEAD")]
    no_merged: Option<String>,
    /// Output format for the list form. JSONL with `--format=json`.
    #[arg(long, value_enum, default_value = "default")]
    format: BranchFormat,
    /// Positional arguments. In create/delete/rename mode these are branch
    /// names; in list mode (`--list` or an ancestry filter) they are shell
    /// glob patterns that filter the listing (like `git branch --list`).
    #[arg(num_args = 0..)]
    names: Vec<String>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<BranchOpts>("mkit branch", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    // `-m` / `-d` / `-D` are mutually exclusive mode flags.
    let mode_flags = u8::from(opts.delete) + u8::from(opts.force_delete) + u8::from(opts.rename);
    if mode_flags > 1 {
        return super::usage_error("usage: mkit branch [-d|-D|-m] ...  (modes are exclusive)");
    }

    let specs = FilterSpecs {
        contains: opts.contains.as_deref(),
        no_contains: opts.no_contains.as_deref(),
        merged: opts.merged.as_deref(),
        no_merged: opts.no_merged.as_deref(),
    };
    let has_filter = opts.list || specs.any();

    if opts.rename || opts.delete || opts.force_delete {
        if has_filter {
            return super::usage_error(
                "usage: mkit branch [--list|--contains|--no-contains|--merged|--no-merged] only \
                 filter the listing — they cannot combine with -d/-D/-m",
            );
        }
        if opts.rename {
            return rename(&mkit_dir, &opts.names);
        }
        return delete(&mkit_dir, &opts.names, opts.force_delete);
    }

    let json = matches!(opts.format, BranchFormat::Json);

    // In list mode (`--list` or an ancestry filter present) the positionals
    // are glob patterns that filter the listing, like `git branch --list
    // <pattern>`. Otherwise the positional is a branch name to create.
    if has_filter {
        return list(&cwd, &mkit_dir, json, opts.verbose, &specs, &opts.names);
    }
    match opts.names.as_slice() {
        [] => list(&cwd, &mkit_dir, json, opts.verbose, &specs, &[]),
        [name] => create(&mkit_dir, name),
        _ => super::usage_error("usage: mkit branch <name>  (create takes one name)"),
    }
}

/// `mkit branch <name>` — create a new branch at HEAD.
fn create(mkit_dir: &std::path::Path, name: &str) -> u8 {
    let Ok(Some(h)) = refs::resolve_head(mkit_dir) else {
        return emit_err("no HEAD commit to branch from", exit::GENERAL_ERROR);
    };
    // `MustNotExist` (issue #206) refuses to silently clobber an
    // existing branch of the same name. Route through
    // `write_ref_recording_history` so the new branch picks up a
    // fresh history-MMR journal (the empty pre-leaf root + this
    // first append) on builds with `--features history-mmr`.
    match super::write_ref_recording_history(mkit_dir, name, refs::RefWriteCondition::Missing, &h) {
        Ok(()) => exit::OK,
        Err(refs::RefError::Conflict(_)) => {
            emit_err(&format!("branch '{name}' already exists"), exit::CANTCREAT)
        }
        Err(e) => emit_err(&format!("write {name}: {e}"), exit::CANTCREAT),
    }
}

/// `mkit branch -d/-D <name>` — delete a branch.
///
/// Both `-d` and `-D` route through `delete_ref_safe`, which refuses to
/// delete the branch HEAD currently points at (issue #206) — deleting
/// the current branch would leave HEAD dangling, and git refuses this
/// even under `-D`. mkit does not track per-branch merge status, so `-d`
/// and `-D` behave identically here. Like git, **both** error on a
/// missing branch (`error: branch '<name>' not found`); `-D` does not
/// silently no-op, so a typo'd name is surfaced rather than swallowed.
fn delete(mkit_dir: &std::path::Path, names: &[String], force: bool) -> u8 {
    let [name] = names else {
        let flag = if force { "-D" } else { "-d" };
        return super::usage_error(&format!("usage: mkit branch {flag} <name>"));
    };
    match refs::delete_ref_safe(mkit_dir, name) {
        Ok(()) => exit::OK,
        Err(refs::RefError::NotFound(_)) => {
            emit_err(&format!("branch '{name}' not found"), exit::GENERAL_ERROR)
        }
        Err(e) => emit_err(&format!("delete {name}: {e}"), exit::GENERAL_ERROR),
    }
}

/// `mkit branch -m [<old>] <new>` — rename a branch.
///
/// With two names renames `<old>` → `<new>`; with one name renames the
/// current branch → `<new>`. Implemented as a CAS-guarded create of the
/// destination (`RefWriteCondition::Missing` refuses to clobber) followed
/// by deletion of the source, then a HEAD update when the source was the
/// checked-out branch. The create routes through
/// `write_ref_recording_history` so the renamed branch seeds a fresh
/// history-MMR journal on `--features history-mmr` builds, exactly as a
/// freshly created branch would.
fn rename(mkit_dir: &std::path::Path, names: &[String]) -> u8 {
    let (old, new) = match names {
        [new] => {
            let Ok(refs::Head::Branch(cur)) = refs::read_head(mkit_dir) else {
                return emit_err(
                    "cannot rename: HEAD is detached (specify <old> <new>)",
                    exit::GENERAL_ERROR,
                );
            };
            (cur, new.clone())
        }
        [old, new] => (old.clone(), new.clone()),
        _ => return super::usage_error("usage: mkit branch -m [<old>] <new>"),
    };

    if old == new {
        return exit::OK;
    }

    let hash = match refs::read_ref(mkit_dir, &old) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err(&format!("branch '{old}' not found"), exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("read {old}: {e}"), exit::GENERAL_ERROR),
    };

    // Create the destination first under a CAS that refuses to clobber an
    // existing branch. Only after it lands do we drop the source, so a
    // mid-operation failure never loses the branch tip.
    match super::write_ref_recording_history(
        mkit_dir,
        &new,
        refs::RefWriteCondition::Missing,
        &hash,
    ) {
        Ok(()) => {}
        Err(refs::RefError::Conflict(_)) => {
            return emit_err(&format!("branch '{new}' already exists"), exit::CANTCREAT);
        }
        Err(e) => return emit_err(&format!("write {new}: {e}"), exit::CANTCREAT),
    }

    if let Err(e) = refs::delete_ref(mkit_dir, &old) {
        return emit_err(&format!("delete {old}: {e}"), exit::GENERAL_ERROR);
    }

    // Move HEAD if we renamed the checked-out branch.
    if let Ok(refs::Head::Branch(cur)) = refs::read_head(mkit_dir)
        && cur == old
        && let Err(e) = refs::write_head_branch(mkit_dir, &new)
    {
        return emit_err(&format!("update HEAD to {new}: {e}"), exit::GENERAL_ERROR);
    }
    exit::OK
}

/// The raw `--contains`/`--no-contains`/`--merged`/`--no-merged` specs as
/// typed, resolved to commits only when a listing actually runs.
struct FilterSpecs<'a> {
    contains: Option<&'a str>,
    no_contains: Option<&'a str>,
    merged: Option<&'a str>,
    no_merged: Option<&'a str>,
}

impl FilterSpecs<'_> {
    fn any(&self) -> bool {
        self.contains.is_some()
            || self.no_contains.is_some()
            || self.merged.is_some()
            || self.no_merged.is_some()
    }
}

/// The same specs after resolution to (tag-peeled) commit ids.
struct BranchFilter {
    contains: Option<Hash>,
    no_contains: Option<Hash>,
    merged: Option<Hash>,
    no_merged: Option<Hash>,
}

/// Resolve each present spec to a commit id, peeling annotated tags like
/// git. Returns `Err(message)` if a spec does not resolve.
fn resolve_filter(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    specs: &FilterSpecs<'_>,
) -> Result<BranchFilter, String> {
    let resolve = |spec: Option<&str>| -> Result<Option<Hash>, String> {
        match spec {
            None => Ok(None),
            Some(s) => {
                let h = revspec::resolve_revision(store, mkit_dir, s)
                    .map_err(|e| format!("bad revision '{s}': {e}"))?;
                Ok(Some(peel_tags(store, h)))
            }
        }
    };
    Ok(BranchFilter {
        contains: resolve(specs.contains)?,
        no_contains: resolve(specs.no_contains)?,
        merged: resolve(specs.merged)?,
        no_merged: resolve(specs.no_merged)?,
    })
}

/// Whether a branch tip satisfies every active filter (AND). `contains C`
/// keeps tips with C as an ancestor; `merged M` keeps tips that are
/// ancestors of M; the `no_*` forms are their complements.
fn tip_passes(store: &ObjectStore, filter: &BranchFilter, tip: &Hash) -> Result<bool, String> {
    let anc = |a: Hash, d: Hash| is_ancestor(store, a, d).map_err(|e| format!("ancestry: {e}"));
    if let Some(c) = filter.contains
        && !anc(c, *tip)?
    {
        return Ok(false);
    }
    if let Some(c) = filter.no_contains
        && anc(c, *tip)?
    {
        return Ok(false);
    }
    if let Some(m) = filter.merged
        && !anc(*tip, m)?
    {
        return Ok(false);
    }
    if let Some(m) = filter.no_merged
        && anc(*tip, m)?
    {
        return Ok(false);
    }
    Ok(true)
}

/// Bounded annotated-tag peel (mirrors `merge.rs`/`diff.rs`).
fn peel_tags(store: &ObjectStore, mut h: Hash) -> Hash {
    for _ in 0..16 {
        match store.read_object(&h) {
            Ok(Object::Tag(t)) => h = t.target,
            _ => break,
        }
    }
    h
}

/// Shell-glob match for `branch --list <pattern>`, mirroring git's
/// `wildmatch` without pathname mode: `*` matches any run (including `/`,
/// so `feature/*` works), `?` matches one character, and `[...]` is a
/// character class (`[a-z]`, leading `!`/`^` negates). A pattern with no
/// metacharacters must match the whole name (so `main` matches only
/// `main`). Backslash escapes the next metacharacter.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    // Backtrack point for the most recent `*`.
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        let advanced = if pi < p.len() {
            match p[pi] {
                '*' => {
                    star = Some((pi, ti));
                    pi += 1;
                    true
                }
                '?' => {
                    pi += 1;
                    ti += 1;
                    true
                }
                '[' => match match_class(&p, pi, t[ti]) {
                    Some((matched, next_pi)) if matched => {
                        pi = next_pi;
                        ti += 1;
                        true
                    }
                    Some(_) => false, // well-formed class, no match
                    None => {
                        // Malformed class — treat `[` literally.
                        if t[ti] == '[' {
                            pi += 1;
                            ti += 1;
                            true
                        } else {
                            false
                        }
                    }
                },
                '\\' if pi + 1 < p.len() => {
                    if p[pi + 1] == t[ti] {
                        pi += 2;
                        ti += 1;
                        true
                    } else {
                        false
                    }
                }
                c => {
                    if c == t[ti] {
                        pi += 1;
                        ti += 1;
                        true
                    } else {
                        false
                    }
                }
            }
        } else {
            false
        };
        if advanced {
            continue;
        }
        // Mismatch: backtrack to the last `*`, extending what it consumed.
        match star {
            Some((sp, st)) => {
                pi = sp + 1;
                ti = st + 1;
                star = Some((sp, st + 1));
            }
            None => return false,
        }
    }
    // Trailing `*`s match the empty remainder.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Match a bracket character class beginning at `p[start]` (the opening
/// bracket) against `ch`. Returns `Some((matched, next_index))` for a
/// well-formed class, where `next_index` is just past the closing bracket;
/// returns `None` when there is no closing bracket (the caller then treats
/// the opening bracket as a literal).
fn match_class(p: &[char], start: usize, ch: char) -> Option<(bool, usize)> {
    let mut i = start + 1;
    let mut negate = false;
    if i < p.len() && (p[i] == '!' || p[i] == '^') {
        negate = true;
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < p.len() {
        if p[i] == ']' && !first {
            return Some((matched ^ negate, i + 1));
        }
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if ch >= p[i] && ch <= p[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if p[i] == ch {
                matched = true;
            }
            i += 1;
        }
        first = false;
    }
    None
}

fn list(
    cwd: &std::path::Path,
    mkit_dir: &std::path::Path,
    json: bool,
    verbose: bool,
    specs: &FilterSpecs<'_>,
    patterns: &[String],
) -> u8 {
    let current = match refs::read_head(mkit_dir) {
        Ok(Head::Branch(n)) => Some(n),
        _ => None,
    };
    let mut refs = match refs::list_refs(mkit_dir) {
        Ok(r) => r,
        Err(e) => return emit_err(&format!("list refs: {e}"), exit::GENERAL_ERROR),
    };

    // Shell-glob name patterns (like `git branch --list <pattern>`): keep a
    // branch if it matches ANY pattern. Applied before the ancestry walk so
    // we don't resolve commits for branches the patterns already excluded.
    if !patterns.is_empty() {
        refs.retain(|r| patterns.iter().any(|pat| glob_match(pat, &r.name)));
    }

    // A filter or `-v` both need the object store; open it once.
    let store = if verbose || specs.any() {
        match ObjectStore::open(cwd) {
            Ok(s) => Some(s),
            Err(e) => return emit_err(&format!("open store: {e}"), exit::GENERAL_ERROR),
        }
    } else {
        None
    };

    // Apply listing filters (ancestry-based) before any rendering, so all
    // three output modes share the same filtered set.
    if specs.any() {
        let store = store.as_ref().expect("store opened when filtering");
        let filter = match resolve_filter(store, mkit_dir, specs) {
            Ok(f) => f,
            Err(e) => return emit_err(&e, exit::DATAERR),
        };
        let mut kept = Vec::with_capacity(refs.len());
        for r in refs {
            // A tip-less ref can't satisfy a commit filter, so skip it.
            if let Some(h) = &r.hash {
                match tip_passes(store, &filter, h) {
                    Ok(true) => kept.push(r),
                    Ok(false) => {}
                    Err(e) => return emit_err(&e, exit::GENERAL_ERROR),
                }
            }
        }
        refs = kept;
    }

    let mut stdout = std::io::stdout().lock();
    if json {
        for r in &refs {
            let is_current = current.as_deref() == Some(r.name.as_str());
            let _ = stdout.write_all(b"{");
            let _ = write!(stdout, "\"name\":\"{}\"", format::json_escape(&r.name));
            let _ = write!(stdout, ",\"current\":{is_current}");
            if let Some(h) = &r.hash {
                let _ = write!(stdout, ",\"hash\":\"{}\"", format::hex_hash(h));
            } else {
                let _ = stdout.write_all(b",\"hash\":null");
            }
            let _ = stdout.write_all(b"}\n");
        }
        return exit::OK;
    }

    let marker_for = |name: &str| {
        current
            .as_deref()
            .map_or(' ', |cur| if cur == name { '*' } else { ' ' })
    };

    if !verbose {
        // Default: `<marker> <name>` only — `git branch` omits the id.
        for r in &refs {
            let _ = writeln!(stdout, "{} {}", marker_for(&r.name), r.name);
        }
        return exit::OK;
    }

    // Verbose: `<marker> <name> <short> <subject>`, name column padded to
    // the longest branch name (like `git branch -v`). The tip subject is
    // the first line of the commit/remix message.
    let store = match ObjectStore::open(cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("open store: {e}"), exit::GENERAL_ERROR),
    };
    let width = refs.iter().map(|r| r.name.len()).max().unwrap_or(0);
    for r in &refs {
        let marker = marker_for(&r.name);
        match &r.hash {
            Some(h) => {
                let short = format::short_hash(h, DEFAULT_ABBREV);
                let subject = tip_subject(&store, h);
                let _ = writeln!(stdout, "{marker} {:<width$} {short} {subject}", r.name);
            }
            None => {
                let _ = writeln!(stdout, "{marker} {:<width$}", r.name);
            }
        }
    }
    exit::OK
}

/// First line of a branch tip's commit (or remix) message, for `-v`.
/// Returns an empty string if the tip can't be read or isn't a
/// commit/remix — `-v` is a display aid and must not fail the listing.
fn tip_subject(store: &ObjectStore, hash: &mkit_core::hash::Hash) -> String {
    let message = match store.read_object(hash) {
        Ok(Object::Commit(c)) => c.message,
        Ok(Object::Remix(r)) => r.message,
        _ => return String::new(),
    };
    String::from_utf8_lossy(&message)
        .lines()
        .next()
        .unwrap_or("")
        .to_owned()
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn literal_matches_whole_name() {
        assert!(glob_match("main", "main"));
        assert!(!glob_match("main", "maintenance"));
        assert!(!glob_match("main", " main"));
    }

    #[test]
    fn star_matches_any_run_including_slash() {
        assert!(glob_match("feat*", "feature"));
        assert!(glob_match("feature/*", "feature/login"));
        // `*` spans `/`, matching git's non-pathname wildmatch.
        assert!(glob_match("*", "any/branch/name"));
        assert!(glob_match("*login", "feature/login"));
        assert!(!glob_match("feature/*", "main"));
    }

    #[test]
    fn question_matches_single_char() {
        assert!(glob_match("v?", "v1"));
        assert!(!glob_match("v?", "v10"));
    }

    #[test]
    fn char_classes_and_negation() {
        assert!(glob_match("v[0-9]", "v3"));
        assert!(!glob_match("v[0-9]", "vx"));
        assert!(glob_match("v[!0-9]", "vx"));
        assert!(!glob_match("v[!0-9]", "v3"));
    }

    #[test]
    fn backslash_escapes_metacharacter() {
        assert!(glob_match(r"feat\*", "feat*"));
        assert!(!glob_match(r"feat\*", "feature"));
    }

    #[test]
    fn star_backtracks() {
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
    }
}
