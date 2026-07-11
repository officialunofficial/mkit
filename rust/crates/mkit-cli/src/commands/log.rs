//! `mkit log [<rev>] [<A>..<B> | <A>...<B>]` — walk commit history.
//!
//! With no argument the walk starts at `HEAD`. A single `<rev>` starts there
//! instead; a range `A..B` shows commits reachable from `B` but not `A`
//! (empty side = `HEAD`, so `A..` is `A..HEAD` and `..B` is `HEAD..B`).
//! An `A...B` symmetric range shows commits reachable from `A` or `B` but not
//! their common ancestors (the merge base). Commits are ordered
//! reverse-chronologically with a topological tie-break (a parent never
//! precedes a child) — git's `--date-order`. This is identical to git's
//! default for linear history and monotonic-timestamp merges; it can differ
//! only on merge DAGs with non-monotonic (skewed or imported) timestamps.
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
//! `--graph` is accepted for git compatibility but is a no-op: it is a
//! documented v1 non-goal (see `docs/CLI.md`). Full graph parity is not
//! achievable given mkit's content-addressed model; a limited
//! `--oneline --graph` renderer remains a possible post-v1 follow-up.
//!
//! History filters — `--author`/`--grep` (substring matches),
//! `--since`/`--until` (a small explicit date grammar, see the
//! `dateparse` submodule), and `--no-merges`/`--first-parent` — are
//! applied to the walk before `-n`'s limit, so the limit caps the
//! filtered result like git's does. `--first-parent` prunes the *walk*
//! itself (a merged side branch never enters the candidate set);
//! `--no-merges` only hides merge commits from the already-walked
//! output.
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
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, Object};
use mkit_core::ops::graph::collect_ancestor_set;
use mkit_core::ops::merge::find_merge_base;
use mkit_core::refs;
use mkit_core::store::ObjectStore;

use super::revspec;
use crate::clap_shim;
use crate::exit;
use crate::format;
use crate::signal;

mod dateparse;

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
#[allow(clippy::struct_excessive_bools)] // clap option flags, not a state machine
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

    /// Render an ASCII graph. Accepted for git compatibility but a
    /// no-op (documented v1 non-goal).
    #[arg(long)]
    graph: bool,

    /// Only show commits whose author identity contains `<pattern>`
    /// (substring match against both the short display form — `mkit
    /// log`'s `Author:` line — and the full `kind:hex`/`mid:N` form used
    /// by `--format=json`'s `author` field). Unlike git, mkit identities
    /// are opaque (Ed25519 keys, `mid:N` numbers, DID keys) rather than
    /// free-text `Name <email>`, so this is a plain substring match, not
    /// a regex.
    #[arg(long, value_name = "PATTERN")]
    author: Option<String>,

    /// Only show commits whose message (title + body) contains
    /// `<pattern>` (substring match, case-sensitive — like git's default
    /// `--grep`).
    #[arg(long, value_name = "PATTERN")]
    grep: Option<String>,

    /// Only show commits at or after this time. Accepts `@<unix-seconds>`,
    /// `now`/`today`/`yesterday`, `<N> <unit> ago`
    /// (second/minute/hour/day/week/month/year), `YYYY-MM-DD`, or
    /// `YYYY-MM-DD HH:MM:SS` (UTC).
    #[arg(long, value_name = "DATE")]
    since: Option<String>,

    /// Only show commits at or before this time. Same formats as
    /// `--since`.
    #[arg(long, value_name = "DATE")]
    until: Option<String>,

    /// Hide merge commits (more than one parent) from the output. The
    /// walk itself is unchanged — this only filters what gets printed —
    /// like `git log --no-merges`.
    #[arg(long = "no-merges")]
    no_merges: bool,

    /// Follow only the first parent at each merge, so a merged side
    /// branch never enters the walk at all (stronger than `--no-merges`,
    /// which still walks through merges but hides them from the
    /// output). Like `git log --first-parent`.
    #[arg(long = "first-parent")]
    first_parent: bool,

    /// Optional starting revision (`<rev>`), range (`A..B`, `A..`, `..B`), or
    /// symmetric range (`A...B`). Defaults to `HEAD`; an empty range side
    /// means `HEAD`.
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

    // `--since`/`--until` are validated up front (a bad date is a usage
    // error, not a silent no-match) before touching the repository.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let since = match opts.since.as_deref() {
        Some(s) => match dateparse::parse_date(s, now) {
            Ok(t) => Some(t),
            Err(msg) => return emit_err(&format!("--since: {msg}"), exit::USAGE),
        },
        None => None,
    };
    let until = match opts.until.as_deref() {
        Some(s) => match dateparse::parse_date(s, now) {
            Ok(t) => Some(t),
            Err(msg) => return emit_err(&format!("--until: {msg}"), exit::USAGE),
        },
        None => None,
    };

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    // Resolve the revision selection: default HEAD, a single `<rev>`, a
    // `A..B` range, or an `A...B` symmetric range (empty side = HEAD).
    let selection = parse_rev_arg(opts.start.as_deref());
    let (tips, excluded) = match resolve_selection(&store, &layout, &selection) {
        Ok(Some(v)) => v,
        Ok(None) => {
            // No HEAD yet and no explicit revision → nothing to show.
            if opts.start.is_none() && matches!(fmt, Format::Default | Format::Oneline) {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "no commits yet");
            }
            return exit::OK;
        }
        Err(msg) => return emit_err(&msg, exit::DATAERR),
    };

    let ordered = match ordered_commits_opts(&store, &tips, &excluded, opts.first_parent) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let mut stdout = std::io::stdout().lock();
    // `-n <limit>` caps the *filtered* set, not the raw walk, so it
    // composes with `--author`/`--grep`/`--since`/`--until`/`--no-merges`
    // the way git's does.
    let limit = opts.limit.unwrap_or(usize::MAX);
    let mut shown = 0usize;
    for (hash, c) in &ordered {
        if signal::is_shutdown() {
            return exit::TEMPFAIL;
        }
        if shown >= limit {
            break;
        }
        if !commit_matches(
            c,
            opts.author.as_deref(),
            opts.grep.as_deref(),
            since,
            until,
            opts.no_merges,
        ) {
            continue;
        }
        render_commit(&mut stdout, fmt, abbrev, hash, c);
        shown += 1;
    }
    exit::OK
}

/// Does `c` pass every active `log` filter? `since`/`until` are already
/// resolved Unix seconds; `author`/`grep` are substring patterns.
fn commit_matches(
    c: &Commit,
    author: Option<&str>,
    grep: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    no_merges: bool,
) -> bool {
    if no_merges && c.parents.len() > 1 {
        return false;
    }
    if since.is_some_and(|s| c.timestamp < s) {
        return false;
    }
    if until.is_some_and(|u| c.timestamp > u) {
        return false;
    }
    if let Some(pat) = author
        && !(format::short_identity(&c.author).contains(pat)
            || format::full_identity(&c.author).contains(pat))
    {
        return false;
    }
    if let Some(pat) = grep {
        let msg = String::from_utf8_lossy(&c.message);
        if !msg.contains(pat) {
            return false;
        }
    }
    true
}

/// The include tips to walk plus the excluded ancestor set, resolved from a
/// [`RevSelection`].
type WalkSet = (Vec<Hash>, HashSet<Hash>);

/// A parsed `log` revision selection.
enum RevSelection {
    /// No argument → walk `HEAD`.
    Default,
    /// A single `<rev>` → walk its history.
    Single(String),
    /// `A..B` → reachable from `B` but not `A`.
    Range { exclude: String, include: String },
    /// `A...B` → reachable from `A` or `B` but not their common ancestors.
    Symmetric { a: String, b: String },
}

/// Parse the optional `<rev>` / `A..B` / `A...B` positional. An empty range
/// side resolves to `HEAD`.
fn parse_rev_arg(arg: Option<&str>) -> RevSelection {
    let Some(s) = arg else {
        return RevSelection::Default;
    };
    let to_spec = |side: &str| {
        if side.is_empty() {
            "HEAD".to_string()
        } else {
            side.to_string()
        }
    };
    // Check `...` before `..` since the former contains the latter.
    if let Some((a, b)) = s.split_once("...") {
        return RevSelection::Symmetric {
            a: to_spec(a),
            b: to_spec(b),
        };
    }
    if let Some((a, b)) = s.split_once("..") {
        return RevSelection::Range {
            exclude: to_spec(a),
            include: to_spec(b),
        };
    }
    RevSelection::Single(s.to_string())
}

/// Resolve a [`RevSelection`] into the set of include tips to walk and the
/// excluded ancestor set. `Ok(None)` means there is nothing to show (e.g. a
/// HEAD-less repo with no explicit revision).
fn resolve_selection(
    store: &ObjectStore,
    layout: &RepoLayout,
    sel: &RevSelection,
) -> Result<Option<WalkSet>, String> {
    let mut excluded: HashSet<Hash> = HashSet::new();
    let tips: Vec<Hash> = match sel {
        RevSelection::Default => match resolve_tip(store, layout, None)? {
            Some(h) => vec![h],
            None => return Ok(None),
        },
        RevSelection::Single(spec) => match resolve_tip(store, layout, Some(spec))? {
            Some(h) => vec![h],
            None => return Ok(None),
        },
        RevSelection::Range { exclude, include } => {
            let Some(inc) = resolve_tip(store, layout, Some(include))? else {
                return Ok(None);
            };
            if let Some(a) = resolve_tip(store, layout, Some(exclude))? {
                collect_ancestor_set(store, a, &mut excluded)
                    .map_err(|e| format!("walk range base: {e}"))?;
            }
            vec![inc]
        }
        RevSelection::Symmetric { a, b } => {
            let ra = resolve_tip(store, layout, Some(a))?;
            let rb = resolve_tip(store, layout, Some(b))?;
            // Exclude the common ancestors (ancestors of the merge base).
            if let (Some(x), Some(y)) = (ra, rb)
                && let Some(mb) =
                    find_merge_base(store, x, y).map_err(|e| format!("merge base: {e}"))?
            {
                collect_ancestor_set(store, mb, &mut excluded)
                    .map_err(|e| format!("walk merge base: {e}"))?;
            }
            let tips: Vec<Hash> = ra.into_iter().chain(rb).collect();
            if tips.is_empty() {
                return Ok(None);
            }
            tips
        }
    };
    Ok(Some((tips, excluded)))
}

/// Resolve a tip spec to a commit hash. `None` spec = HEAD (which may be
/// absent → `Ok(None)`). An explicit spec that fails to resolve is an error.
/// The resolved hash is peeled through annotated/signed tag objects so
/// `log <tag>` / `<tag>..HEAD` walk the tagged commit, like git.
fn resolve_tip(
    store: &ObjectStore,
    layout: &RepoLayout,
    spec: Option<&str>,
) -> Result<Option<Hash>, String> {
    let raw = match spec {
        None | Some("HEAD") => refs::resolve_head(layout).ok().flatten(),
        Some(s) => Some(
            revspec::resolve_revision(store, layout, s)
                .map_err(|e| format!("bad revision '{s}': {e}"))?,
        ),
    };
    Ok(raw.map(|h| peel_tags(store, h)))
}

/// Maximum tag-of-tag chain length to follow when peeling (cycle guard).
const MAX_TAG_DEPTH: usize = 16;

/// Follow `Object::Tag` targets to the first non-tag object, so an
/// annotated/signed tag resolves to the commit it points at. A non-tag (or
/// unreadable) object stops the peel and is returned as-is. Shared with
/// `rev-list` / `merge-base`.
pub(super) fn peel_tags(store: &ObjectStore, mut h: Hash) -> Hash {
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

/// Collect the commits reachable from any of `tips` (minus `excluded`) in
/// git's `--date-order`: reverse-chronological by commit timestamp, with a
/// parent never shown before any of its children (topological tie-break). Uses
/// an in-degree + max-heap revwalk so equal-timestamp linear history keeps its
/// natural child→parent order. Matches git's *default* order for linear and
/// monotonic-timestamp history.
/// Topologically-ordered (reverse-chronological) commit walk from `tips`,
/// excluding `excluded` and their ancestors. Shared with `rev-list`.
/// Equivalent to [`ordered_commits_opts`] with `first_parent: false`.
pub(super) fn ordered_commits(
    store: &ObjectStore,
    tips: &[Hash],
    excluded: &HashSet<Hash>,
) -> Result<Vec<(Hash, Commit)>, u8> {
    ordered_commits_opts(store, tips, excluded, false)
}

/// Like [`ordered_commits`] but with `--first-parent` control: when
/// `first_parent` is set, the candidate-collection walk follows only each
/// commit's first parent, so a merge's later parents — and anything only
/// reachable through them — never enter the candidate set at all. Matches
/// git's `log --first-parent` (stronger than `--no-merges`, which still
/// walks through merges and only hides them from the printed list).
pub(super) fn ordered_commits_opts(
    store: &ObjectStore,
    tips: &[Hash],
    excluded: &HashSet<Hash>,
    first_parent: bool,
) -> Result<Vec<(Hash, Commit)>, u8> {
    // 1. Collect the candidate commit set (DFS over parents, skip excluded).
    let mut commits: HashMap<Hash, Commit> = HashMap::new();
    let mut stack: Vec<Hash> = tips.to_vec();
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
        let parents: &[Hash] = if first_parent {
            c.parents.get(..1).unwrap_or(&[])
        } else {
            &c.parents
        };
        for p in parents {
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

use super::error as emit_err;

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
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
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
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
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
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
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
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
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
            author: None,
            grep: None,
            since: None,
            until: None,
            no_merges: false,
            first_parent: false,
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

    fn commit_for(
        parents: Vec<Hash>,
        author: mkit_core::object::Identity,
        message: &str,
        timestamp: u64,
    ) -> Commit {
        Commit::new_unannotated(
            mkit_core::hash::ZERO,
            parents,
            author,
            [0u8; 32],
            message.as_bytes().to_vec(),
            timestamp,
            [0u8; 64],
        )
    }

    #[test]
    fn commit_matches_no_filters_passes_everything() {
        let c = commit_for(
            vec![],
            mkit_core::object::Identity::opaque(b"alice".to_vec()),
            "m",
            100,
        );
        assert!(commit_matches(&c, None, None, None, None, false));
    }

    #[test]
    fn commit_matches_author_is_substring_against_short_and_full_identity() {
        let c = commit_for(
            vec![],
            mkit_core::object::Identity::opaque(b"alice".to_vec()),
            "m",
            100,
        );
        assert!(commit_matches(&c, Some("alice"), None, None, None, false));
        assert!(!commit_matches(&c, Some("bob"), None, None, None, false));
    }

    #[test]
    fn commit_matches_grep_checks_message_substring() {
        let c = commit_for(
            vec![],
            mkit_core::object::Identity::opaque(b"alice".to_vec()),
            "fix: widget overflow",
            100,
        );
        assert!(commit_matches(&c, None, Some("widget"), None, None, false));
        assert!(!commit_matches(&c, None, Some("gadget"), None, None, false));
    }

    #[test]
    fn commit_matches_since_until_bound_the_timestamp() {
        let c = commit_for(
            vec![],
            mkit_core::object::Identity::opaque(b"a".to_vec()),
            "m",
            500,
        );
        assert!(commit_matches(&c, None, None, Some(500), Some(500), false));
        assert!(commit_matches(&c, None, None, Some(499), Some(501), false));
        assert!(!commit_matches(&c, None, None, Some(501), None, false));
        assert!(!commit_matches(&c, None, None, None, Some(499), false));
    }

    #[test]
    fn commit_matches_no_merges_excludes_multi_parent_commits() {
        let solo = commit_for(
            vec![],
            mkit_core::object::Identity::opaque(b"a".to_vec()),
            "m",
            1,
        );
        let merge = commit_for(
            vec![mkit_core::hash::ZERO, mkit_core::hash::ZERO],
            mkit_core::object::Identity::opaque(b"a".to_vec()),
            "m",
            1,
        );
        assert!(commit_matches(&solo, None, None, None, None, true));
        assert!(!commit_matches(&merge, None, None, None, None, true));
        // Without --no-merges, merges still pass.
        assert!(commit_matches(&merge, None, None, None, None, false));
    }
}
