//! `mkit log [<rev>] [<A>..<B>]` — walk commit history.
//!
//! With no argument the walk starts at `HEAD`. A single `<rev>` starts there
//! instead; a range `A..B` shows commits reachable from `B` but not `A`
//! (empty side = `HEAD`, so `A..` is `A..HEAD` and `..B` is `HEAD..B`).
//! Commits are ordered reverse-chronologically with a topological tie-break
//! (a parent never precedes a child) — git's `--date-order`. This is
//! identical to git's default for linear history and monotonic-timestamp
//! merges; it can differ only on merge DAGs with non-monotonic (skewed or
//! imported) timestamps. `A...B` symmetric ranges are a Phase-4 follow-up
//! (#252).
//!
//! Output modes:
//!
//! - default — human-oriented multi-line per commit on stdout. The
//!   full commit message body is printed indented (four spaces) and the
//!   timestamp is rendered as a stable UTC date
//!   (`YYYY-MM-DD HH:MM:SS +0000`), not the raw integer.
//! - `--oneline` — `<abbrev-hex> <title>` per commit on stdout. The
//!   abbreviation length defaults to 7 (`DEFAULT_ABBREV`) and is
//!   overridable with `--abbrev[=N]`.
//! - `--format=json` — JSONL, one self-contained JSON object per
//!   commit. Suitable for piping into `jq`.
//!
//! `--graph` is silently accepted as a no-op pending Phase 10.
//!
//! Argument parsing is delegated to clap-derive via
//! [`crate::clap_shim::parse`]; clap emits standard diagnostics on
//! errors and the shim maps them to mkit sysexits (`USAGE` for
//! unknown flags, `DATAERR` for malformed `-n` values, etc.).

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::io::Write;

use clap::{Parser, ValueEnum};
use mkit_core::Hash;
use mkit_core::object::{Commit, Object};
use mkit_core::ops::graph::collect_ancestor_set;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;
use crate::signal;

/// Default abbreviated-hash length, matching git's nominal `core.abbrev`
/// starting point. Overridable with `--abbrev[=N]`.
const DEFAULT_ABBREV: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Default,
    Oneline,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit log",
    about = "Show commit history.",
    disable_help_flag = false,
    disable_version_flag = true
)]
struct LogOpts {
    /// Compact one-line-per-commit output. Equivalent to
    /// `--format=oneline`; if both are given, `--format` wins.
    #[arg(long)]
    oneline: bool,

    /// Output format.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// Cap the number of commits printed.
    #[arg(short = 'n')]
    limit: Option<usize>,

    /// Abbreviate commit hashes in the default format (implied by
    /// `--oneline`).
    #[arg(long = "abbrev-commit")]
    abbrev_commit: bool,

    /// Minimum length of abbreviated hashes. Bare `--abbrev` uses the
    /// default (7); `--abbrev=N` sets the length.
    #[arg(long, value_name = "N", num_args = 0..=1, default_missing_value = "7")]
    abbrev: Option<usize>,

    /// Render an ASCII graph. Accepted for compatibility; Phase-10
    /// follow-up.
    #[arg(long)]
    graph: bool,

    /// Optional starting revision (`<rev>`) or range (`A..B`, `A..`, `..B`).
    /// Defaults to `HEAD`. An empty range side means `HEAD`.
    start: Option<String>,
}

impl LogOpts {
    /// Resolve `(oneline, format)` into the single `Format` the
    /// renderer consumes. Explicit `--format` wins over `--oneline`.
    fn render_format(&self) -> Format {
        match self.format {
            Some(f) => f,
            None if self.oneline => Format::Oneline,
            None => Format::Default,
        }
    }

    /// Abbreviation length for commit ids, or `None` to print the full
    /// 64-hex hash. `--abbrev=N` sets the length (and implies
    /// abbreviation); `--abbrev-commit` (or the `Oneline` format)
    /// abbreviates at `DEFAULT_ABBREV`. `short_hash` clamps the length
    /// to `[4, 64]`, so out-of-range `N` is harmless.
    fn abbrev_len(&self) -> Option<usize> {
        if let Some(n) = self.abbrev {
            return Some(n);
        }
        if self.abbrev_commit || self.render_format() == Format::Oneline {
            return Some(DEFAULT_ABBREV);
        }
        None
    }
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<LogOpts>("mkit log", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let fmt = opts.render_format();
    let abbrev = opts.abbrev_len();
    let _ = opts.graph; // accepted, currently no-op.

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    // Resolve the revision selection: default HEAD, a single `<rev>`, or a
    // `A..B` range (empty side = HEAD). `A...B` symmetric ranges are a
    // Phase-4 follow-up (#252).
    let selection = match parse_rev_arg(opts.start.as_deref()) {
        Ok(s) => s,
        Err(msg) => return emit_err(&msg, exit::USAGE),
    };
    let include = match resolve_tip(&store, &mkit_dir, selection.include.as_deref()) {
        Ok(Some(h)) => h,
        Ok(None) => {
            // No HEAD yet and no explicit include → nothing to show.
            if opts.start.is_none() && matches!(fmt, Format::Default | Format::Oneline) {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "no commits yet");
            }
            return exit::OK;
        }
        Err(msg) => return emit_err(&msg, exit::DATAERR),
    };

    // Excluded set: ancestors of the range's left side (`A` in `A..B`).
    let mut excluded: HashSet<Hash> = HashSet::new();
    if let Some(exclude_spec) = selection.exclude {
        match resolve_tip(&store, &mkit_dir, Some(&exclude_spec)) {
            Ok(Some(a)) => {
                if let Err(e) = collect_ancestor_set(&store, a, &mut excluded) {
                    return emit_err(&format!("walk range base: {e}"), exit::DATAERR);
                }
            }
            // An empty/HEAD-less left side excludes nothing.
            Ok(None) => {}
            Err(msg) => return emit_err(&msg, exit::DATAERR),
        }
    }

    let ordered = match ordered_commits(&store, include, &excluded) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let mut stdout = std::io::stdout().lock();
    let limit = opts.limit.unwrap_or(usize::MAX);
    for (hash, c) in ordered.iter().take(limit) {
        if signal::is_shutdown() {
            return exit::TEMPFAIL;
        }
        render_commit(&mut stdout, fmt, abbrev, hash, c);
    }
    exit::OK
}

/// A resolved revision selection for `log`.
struct RevSelection {
    /// The revision whose history to show (`None` = HEAD).
    include: Option<String>,
    /// For a range `A..B`, the left side `A` whose ancestors are excluded.
    exclude: Option<String>,
}

/// Parse the optional `<rev>` / `A..B` positional into a [`RevSelection`].
/// An empty range side resolves to `HEAD`. `A...B` is rejected (#252).
fn parse_rev_arg(arg: Option<&str>) -> Result<RevSelection, String> {
    let Some(s) = arg else {
        return Ok(RevSelection {
            include: None,
            exclude: None,
        });
    };
    if s.contains("...") {
        return Err(format!(
            "symmetric range '{s}' (A...B) is not supported yet (#252); use A..B"
        ));
    }
    if let Some((a, b)) = s.split_once("..") {
        let to_spec = |side: &str| {
            if side.is_empty() {
                "HEAD".to_string()
            } else {
                side.to_string()
            }
        };
        Ok(RevSelection {
            include: Some(to_spec(b)),
            exclude: Some(to_spec(a)),
        })
    } else {
        Ok(RevSelection {
            include: Some(s.to_string()),
            exclude: None,
        })
    }
}

/// Resolve a tip spec to a commit hash. `None` spec = HEAD (which may be
/// absent → `Ok(None)`). An explicit spec that fails to resolve is an error.
/// The resolved hash is peeled through annotated/signed tag objects so
/// `log <tag>` / `<tag>..HEAD` walk the tagged commit, like git.
fn resolve_tip(
    store: &ObjectStore,
    mkit_dir: &std::path::Path,
    spec: Option<&str>,
) -> Result<Option<Hash>, String> {
    let raw = match spec {
        None | Some("HEAD") => refs::resolve_head(mkit_dir).ok().flatten(),
        Some(s) => Some(
            revspec::resolve_revision(store, mkit_dir, s)
                .map_err(|e| format!("bad revision '{s}': {e}"))?,
        ),
    };
    Ok(raw.map(|h| peel_tags(store, h)))
}

/// Maximum tag-of-tag chain length to follow when peeling (cycle guard).
const MAX_TAG_DEPTH: usize = 16;

/// Follow `Object::Tag` targets to the first non-tag object, so an
/// annotated/signed tag resolves to the commit it points at. A non-tag (or
/// unreadable) object stops the peel and is returned as-is.
fn peel_tags(store: &ObjectStore, mut h: Hash) -> Hash {
    for _ in 0..MAX_TAG_DEPTH {
        match store.read_object(&h) {
            Ok(Object::Tag(t)) => h = t.target,
            _ => break,
        }
    }
    h
}

/// A commit ready to emit, ordered by timestamp (newest first) with the hash
/// as a deterministic tiebreak.
struct HeapItem {
    timestamp: u64,
    hash: Hash,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.hash.cmp(&other.hash))
    }
}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for HeapItem {}

/// Hard cap on commits collected for one `log` invocation.
const MAX_LOG_COMMITS: usize = 1_000_000;

/// Collect the commits reachable from `include` (minus `excluded`) in git's
/// `--date-order`: reverse-chronological by commit timestamp, with a parent
/// never shown before any of its children (topological tie-break). Uses an
/// in-degree + max-heap revwalk so equal-timestamp linear history keeps its
/// natural child→parent order. Matches git's *default* order for linear and
/// monotonic-timestamp history.
fn ordered_commits(
    store: &ObjectStore,
    include: Hash,
    excluded: &HashSet<Hash>,
) -> Result<Vec<(Hash, Commit)>, u8> {
    // 1. Collect the candidate commit set (DFS over parents, skip excluded).
    let mut commits: HashMap<Hash, Commit> = HashMap::new();
    let mut stack = vec![include];
    while let Some(h) = stack.pop() {
        if excluded.contains(&h) || commits.contains_key(&h) {
            continue;
        }
        if commits.len() >= MAX_LOG_COMMITS {
            break;
        }
        let c = match store.read_object(&h) {
            Ok(Object::Commit(c)) => c,
            Ok(_) => {
                return Err(emit_err(
                    &format!("not a commit: {}", format::hex_hash(&h)),
                    exit::DATAERR,
                ));
            }
            Err(e) => {
                return Err(emit_err(
                    &format!("read {}: {e}", format::hex_hash(&h)),
                    exit::DATAERR,
                ));
            }
        };
        for p in &c.parents {
            if !excluded.contains(p) {
                stack.push(*p);
            }
        }
        commits.insert(h, c);
    }

    // 2. In-degree = number of children within the candidate set.
    let mut indeg: HashMap<Hash, usize> = commits.keys().map(|h| (*h, 0usize)).collect();
    for c in commits.values() {
        for p in &c.parents {
            if let Some(d) = indeg.get_mut(p) {
                *d += 1;
            }
        }
    }

    // 3. Max-heap (by timestamp) over commits whose children are all emitted.
    let mut heap: BinaryHeap<HeapItem> = BinaryHeap::new();
    for (h, c) in &commits {
        if indeg[h] == 0 {
            heap.push(HeapItem {
                timestamp: c.timestamp,
                hash: *h,
            });
        }
    }
    let mut out: Vec<(Hash, Commit)> = Vec::with_capacity(commits.len());
    while let Some(item) = heap.pop() {
        let c = commits[&item.hash].clone();
        for p in &c.parents {
            if let Some(d) = indeg.get_mut(p) {
                *d -= 1;
                if *d == 0 {
                    heap.push(HeapItem {
                        timestamp: commits[p].timestamp,
                        hash: *p,
                    });
                }
            }
        }
        out.push((item.hash, c));
    }
    Ok(out)
}

/// Render one commit in the selected format.
fn render_commit(
    out: &mut impl Write,
    fmt: Format,
    abbrev: Option<usize>,
    hash: &Hash,
    c: &Commit,
) {
    let full_message: String = String::from_utf8_lossy(&c.message).into_owned();
    let title = full_message.lines().next().unwrap_or("");
    match fmt {
        Format::Oneline => {
            let id = format::short_hash(hash, abbrev.unwrap_or(DEFAULT_ABBREV));
            let _ = writeln!(out, "{id} {title}");
        }
        Format::Default => {
            let id = match abbrev {
                Some(n) => format::short_hash(hash, n),
                None => format::hex_hash(hash),
            };
            let _ = writeln!(out, "commit {id}");
            let _ = writeln!(out, "Author: {}", format::short_identity(&c.author));
            let _ = writeln!(out, "Date:   {}", format::human_date_utc(c.timestamp));
            let _ = writeln!(out);
            // Full message body, indented like git. Each line is prefixed
            // with four spaces; blank lines stay blank.
            for line in full_message.lines() {
                if line.is_empty() {
                    let _ = writeln!(out);
                } else {
                    let _ = writeln!(out, "    {line}");
                }
            }
            let _ = writeln!(out);
        }
        Format::Json => {
            emit_json_entry(out, hash, c, title, &full_message);
        }
    }
}

/// Emit one JSONL record for a commit. Schema:
///
/// ```json
/// {
///   "hash": "<64-hex>",
///   "parents": ["<64-hex>", ...],
///   "tree": "<64-hex>",
///   "author": "<identity-string>",
///   "timestamp": <unix-seconds>,
///   "title": "<first line of message>",
///   "message": "<full message, JSON-escaped>"
/// }
/// ```
///
/// Keys are written in a deterministic order so the output is
/// reproducible and easy to snapshot-test.
fn emit_json_entry(
    out: &mut impl Write,
    hash: &mkit_core::Hash,
    c: &mkit_core::object::Commit,
    title: &str,
    full_message: &str,
) {
    let _ = out.write_all(b"{");
    let _ = write!(out, "\"hash\":\"{}\"", format::hex_hash(hash));
    let _ = out.write_all(b",\"parents\":[");
    for (i, p) in c.parents.iter().enumerate() {
        if i > 0 {
            let _ = out.write_all(b",");
        }
        let _ = write!(out, "\"{}\"", format::hex_hash(p));
    }
    let _ = out.write_all(b"]");
    let _ = write!(out, ",\"tree\":\"{}\"", format::hex_hash(&c.tree_hash));
    let _ = write!(
        out,
        ",\"author\":\"{}\"",
        format::json_escape(&format::full_identity(&c.author))
    );
    let _ = write!(out, ",\"timestamp\":{}", c.timestamp);
    let _ = write!(out, ",\"title\":\"{}\"", format::json_escape(title));
    let _ = write!(
        out,
        ",\"message\":\"{}\"",
        format::json_escape(full_message)
    );
    let _ = out.write_all(b"}\n");
}

fn emit_err(msg: &str, code: u8) -> u8 {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "error: {msg}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_format_explicit_format_wins_over_oneline() {
        let opts = LogOpts {
            oneline: true,
            format: Some(Format::Default),
            limit: None,
            abbrev_commit: false,
            abbrev: None,
            graph: false,
            start: None,
        };
        assert_eq!(opts.render_format(), Format::Default);
    }

    #[test]
    fn render_format_oneline_alone_resolves_to_oneline() {
        let opts = LogOpts {
            oneline: true,
            format: None,
            limit: None,
            abbrev_commit: false,
            abbrev: None,
            graph: false,
            start: None,
        };
        assert_eq!(opts.render_format(), Format::Oneline);
    }

    #[test]
    fn render_format_default_when_no_flags() {
        let opts = LogOpts {
            oneline: false,
            format: None,
            limit: None,
            abbrev_commit: false,
            abbrev: None,
            graph: false,
            start: None,
        };
        assert_eq!(opts.render_format(), Format::Default);
    }

    #[test]
    fn render_format_json_via_format_flag() {
        let opts = LogOpts {
            oneline: false,
            format: Some(Format::Json),
            limit: None,
            abbrev_commit: false,
            abbrev: None,
            graph: false,
            start: None,
        };
        assert_eq!(opts.render_format(), Format::Json);
    }

    fn opts_for_abbrev(oneline: bool, abbrev_commit: bool, abbrev: Option<usize>) -> LogOpts {
        LogOpts {
            oneline,
            format: None,
            limit: None,
            abbrev_commit,
            abbrev,
            graph: false,
            start: None,
        }
    }

    #[test]
    fn abbrev_len_off_by_default() {
        assert_eq!(opts_for_abbrev(false, false, None).abbrev_len(), None);
    }

    #[test]
    fn abbrev_len_default_for_oneline_and_abbrev_commit() {
        assert_eq!(
            opts_for_abbrev(true, false, None).abbrev_len(),
            Some(DEFAULT_ABBREV)
        );
        assert_eq!(
            opts_for_abbrev(false, true, None).abbrev_len(),
            Some(DEFAULT_ABBREV)
        );
    }

    #[test]
    fn abbrev_len_explicit_value_wins() {
        assert_eq!(
            opts_for_abbrev(true, false, Some(12)).abbrev_len(),
            Some(12)
        );
    }
}
