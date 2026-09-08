//! `mkit git verify` / `status` / `format-patch` (feature
//! `git-bridge`): bridge-state inspection and audit.
//!
//! `verify` re-checks a state dir's staging mirror against the local
//! store: bridge-translated objects shallow-verify (SPEC-GIT-BRIDGE
//! §10) and must reconstruct to their mapped mkit twin; imported
//! objects must have retained raw bytes hashing to their sha1 and a
//! twin signed by the pinned importer key (SPEC-GIT-IMPORT §4).
//! `--fork-audit` adds §14.3 step 3: every tree/blob referenced by a
//! bridge commit re-derives from its mkit twin and must reproduce the
//! exact sha1.
//!
//! `format-patch` renders native commits as `git am`-able mbox
//! patches, so contributions can flow to a git upstream even without
//! a writable fork (the no-export collaboration path).

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Parser;
use mkit_core::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Commit, Object};
use mkit_core::store::ObjectStore;
use mkit_git_bridge::gitobj::{GitObject, GitType, Sha1Id, sha1_hex};
use mkit_git_bridge::gitsrc::{CatFileBatch, GitObjKind};
use mkit_git_bridge::{author, gitparse, map};

use super::revspec;
use crate::exit;

type CmdResult<T> = Result<T, (String, u8)>;

const ATTESTATIONS_REF: &str = "refs/mkit/attestations";

#[derive(Debug, Parser)]
pub(super) struct VerifyArgs {
    /// Bridge state name under `.mkit/git/`. Optional when exactly
    /// one state dir exists.
    #[arg(long = "remote-name", value_name = "NAME")]
    pub remote_name: Option<String>,
    /// Full fork audit (SPEC-GIT-BRIDGE §14.3): additionally
    /// re-derive every tree/blob referenced by bridge commits from
    /// its mkit twin and require the exact sha1.
    #[arg(long = "fork-audit")]
    pub fork_audit: bool,
    /// Verify only these refs (full names). Default: every ref
    /// recorded in the state dir.
    #[arg(long = "ref", value_name = "REF")]
    pub refs: Vec<String>,
}

#[derive(Debug, Parser)]
pub(super) struct StatusArgs {}

#[derive(Debug, Parser)]
pub(super) struct FormatPatchArgs {
    /// Commit range `A..B` (or a single rev, meaning `<rev>..HEAD`).
    pub range: String,
    /// Write patch files into this directory (default: current dir).
    #[arg(short = 'o', long = "output-directory", value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Print all patches to stdout instead of writing files.
    #[arg(long)]
    pub stdout: bool,
}

// ─── shared state-dir resolution ────────────────────────────────────

fn state_names(layout: &RepoLayout) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(rd) = std::fs::read_dir(layout.git_state_dir()) {
        for e in rd.flatten() {
            if e.path().is_dir()
                && let Some(name) = e.file_name().to_str()
                // Dot-leading entries are never valid bridge-state names
                // (mirrors `validate_ref_name`'s dot-leading-component
                // rejection): skips crash debris from a `remote rename`
                // move parked at a `.rename.tmp.<pid>.<seq>` temp dir
                // directly under this root, so it never fools zero-arg
                // state resolution into reporting "multiple bridge states".
                && !name.starts_with('.')
            {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    names
}

fn resolve_state(layout: &RepoLayout, remote_name: Option<&str>) -> CmdResult<(String, PathBuf)> {
    if let Some(name) = remote_name {
        let state = map::state_dir(layout, name).map_err(|e| (e.to_string(), exit::USAGE))?;
        if !state.is_dir() {
            return Err((format!("no bridge state for '{name}'"), exit::NOINPUT));
        }
        return Ok((name.to_owned(), state));
    }
    let names = state_names(layout);
    match names.as_slice() {
        [] => Err((
            "no git bridge state (run `mkit git import` or `mkit git export` first)".into(),
            exit::NOINPUT,
        )),
        [one] => Ok((one.clone(), layout.git_state_dir().join(one))),
        many => Err((
            format!(
                "multiple bridge states ({}); pick one with --remote-name",
                many.join(", ")
            ),
            exit::USAGE,
        )),
    }
}

fn open_repo(cwd: &Path) -> CmdResult<(RepoLayout, ObjectStore)> {
    let layout = mkit_core::layout::discover(cwd)
        .map_err(|e| (format!("worktree discovery: {e}"), exit::DATAERR))?;
    if !layout.common_dir().is_dir() {
        return Err(("not a mkit repository".into(), exit::USAGE));
    }
    let store =
        ObjectStore::open(&layout).map_err(|e| (format!("open store: {e}"), exit::NOINPUT))?;
    Ok((layout, store))
}

// ─── mkit git verify ────────────────────────────────────────────────

mod audit;

pub(super) fn verify(args: &VerifyArgs) -> CmdResult<()> {
    audit::run(args)
}

// ─── mkit git status ────────────────────────────────────────────────

pub(super) fn status(_args: &StatusArgs) -> CmdResult<()> {
    let cwd = std::env::current_dir().map_err(|e| (format!("cwd: {e}"), exit::NOINPUT))?;
    let (layout, _store) = open_repo(&cwd)?;
    let names = state_names(&layout);
    let mut out = std::io::stdout().lock();
    if names.is_empty() {
        let _ = writeln!(
            out,
            "no git bridge state (run `mkit git import` or `mkit git export` first)"
        );
        return Ok(());
    }
    for name in &names {
        let state = layout.git_state_dir().join(name);
        let direction = map::read_direction(&state)
            .ok()
            .flatten()
            .map_or("unknown", |d| d.as_str());
        let _ = writeln!(out, "{name}  direction={direction}");
        for (file, label) in [("source", "source"), ("dest", "dest")] {
            if let Ok(v) = std::fs::read_to_string(state.join(file)) {
                let _ = writeln!(out, "  {label}: {}", v.trim());
            }
        }
        if let Ok(Some(key)) = map::read_signer(&state) {
            let _ = writeln!(
                out,
                "  importer key: {}… (pinned)",
                &mkit_git_bridge::gitobj::bytes_hex(&key)[..16]
            );
        }
        for s in map::load_import_ref_state(&state).unwrap_or_default() {
            let _ = writeln!(
                out,
                "  tracking {} @ {} (import)",
                s.ref_name,
                &sha1_hex(&s.git_id)[..12]
            );
        }
        for s in map::load_ref_state(&state).unwrap_or_default() {
            if s.ref_name == ATTESTATIONS_REF {
                continue;
            }
            let _ = writeln!(
                out,
                "  exported {} @ {} (lease)",
                s.ref_name,
                &sha1_hex(&s.git_id)[..12]
            );
        }
        let staging = if state.join("repo.git/objects").is_dir() {
            "ok"
        } else {
            "missing"
        };
        let _ = writeln!(out, "  staging: {staging}");
    }
    Ok(())
}

// ─── mkit git format-patch ──────────────────────────────────────────

/// A patch series: oldest-first hashes, the commit set, and the
/// resolved `A`/`B` endpoint spellings (for messages).
type Series = (Vec<Hash>, HashMap<Hash, Commit>, String, String);

/// Resolve `A..B` (or `<rev>` = `<rev>..HEAD`) to the commit set and
/// its oldest-first topological order (parents before children,
/// timestamp as the tiebreak).
fn range_commits(store: &ObjectStore, layout: &RepoLayout, range: &str) -> CmdResult<Series> {
    let (a, b) = match range.split_once("..") {
        Some((a, b)) => (
            a.to_owned(),
            if b.is_empty() {
                "HEAD".to_owned()
            } else {
                b.to_owned()
            },
        ),
        None => (range.to_owned(), "HEAD".to_owned()),
    };
    let resolve = |spec: &str| -> CmdResult<Hash> {
        revspec::resolve_revision(store, layout, spec)
            .map_err(|e| (format!("{spec}: {e}"), exit::DATAERR))
    };
    let exclude_tip = peel(store, resolve(&a)?);
    let include_tip = peel(store, resolve(&b)?);
    for (spec, h) in [(&a, exclude_tip), (&b, include_tip)] {
        if !matches!(store.read_object(&h), Ok(Object::Commit(_))) {
            // A non-commit endpoint would silently exclude nothing
            // and render the entire history as the series.
            return Err((format!("{spec}: not a commit"), exit::DATAERR));
        }
    }

    // Ancestors of A drop out of the patch series.
    let mut excluded: HashSet<Hash> = HashSet::new();
    let mut stack = vec![exclude_tip];
    while let Some(h) = stack.pop() {
        if !excluded.insert(h) {
            continue;
        }
        if let Ok(Object::Commit(c)) = store.read_object(&h) {
            stack.extend(c.parents.iter().copied());
        }
    }
    let mut commits: HashMap<Hash, Commit> = HashMap::new();
    let mut stack = vec![include_tip];
    while let Some(h) = stack.pop() {
        if excluded.contains(&h) || commits.contains_key(&h) {
            continue;
        }
        let c = match store.read_object(&h) {
            Ok(Object::Commit(c)) => c,
            Ok(_) => {
                return Err((
                    format!("not a commit: {}", mkit_core::to_hex(&h)),
                    exit::DATAERR,
                ));
            }
            Err(e) => {
                return Err((
                    format!("read {}: {e}", mkit_core::to_hex(&h)),
                    exit::DATAERR,
                ));
            }
        };
        stack.extend(c.parents.iter().copied());
        commits.insert(h, c);
    }

    let mut remaining: Vec<Hash> = commits.keys().copied().collect();
    remaining.sort_by_key(|h| (commits[h].timestamp, *h));
    let mut ordered: Vec<Hash> = Vec::with_capacity(remaining.len());
    let mut placed: HashSet<Hash> = HashSet::new();
    while !remaining.is_empty() {
        let before = ordered.len();
        remaining.retain(|h| {
            let ready = commits[h]
                .parents
                .iter()
                .all(|p| placed.contains(p) || !commits.contains_key(p));
            if ready {
                ordered.push(*h);
                placed.insert(*h);
            }
            !ready
        });
        if ordered.len() == before {
            return Err(("commit graph cycle (corrupt store?)".into(), exit::DATAERR));
        }
    }
    Ok((ordered, commits, a, b))
}

pub(super) fn format_patch(args: &FormatPatchArgs) -> CmdResult<()> {
    let cwd = std::env::current_dir().map_err(|e| (format!("cwd: {e}"), exit::NOINPUT))?;
    let (layout, store) = open_repo(&cwd)?;
    let (ordered, commits, a, b) = range_commits(&store, &layout, &args.range)?;

    let mut skipped_merges = 0usize;
    let series: Vec<&Hash> = ordered
        .iter()
        .filter(|h| {
            let m = commits[*h].parents.len() > 1;
            if m {
                skipped_merges += 1;
            }
            !m
        })
        .collect();
    if skipped_merges > 0 {
        eprintln!("warning: {skipped_merges} merge commit(s) skipped (patches are linear)");
    }
    if series.is_empty() {
        eprintln!("no commits in range {a}..{b}");
        return Ok(());
    }

    let total = series.len();
    let outdir = args.output.clone().unwrap_or_else(|| cwd.clone());
    if !args.stdout {
        std::fs::create_dir_all(&outdir)
            .map_err(|e| (format!("create {}: {e}", outdir.display()), exit::CANTCREAT))?;
    }
    let mut stdout = std::io::stdout().lock();
    for (i, h) in series.iter().enumerate() {
        let c = &commits[*h];
        let text = render_patch(&store, h, c, i + 1, total)?;
        if args.stdout {
            stdout
                .write_all(text.as_bytes())
                .map_err(|e| (format!("write: {e}"), exit::GENERAL_ERROR))?;
        } else {
            let name = format!("{:04}-{}.patch", i + 1, slug(&subject_of(c)));
            let path = outdir.join(&name);
            std::fs::write(&path, &text)
                .map_err(|e| (format!("write {}: {e}", path.display()), exit::CANTCREAT))?;
            let _ = writeln!(stdout, "{name}");
        }
    }
    Ok(())
}

fn peel(store: &ObjectStore, mut h: Hash) -> Hash {
    while let Ok(Object::Tag(t)) = store.read_object(&h) {
        h = t.target;
    }
    h
}

fn subject_of(c: &Commit) -> String {
    let msg = String::from_utf8_lossy(&c.message);
    msg.lines().next().unwrap_or("").to_owned()
}

fn slug(subject: &str) -> String {
    let mut out = String::new();
    for ch in subject.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let trimmed = out.trim_end_matches('-');
    let cut = trimmed.chars().take(52).collect::<String>();
    if cut.is_empty() { "patch".into() } else { cut }
}

fn render_patch(
    store: &ObjectStore,
    hash: &Hash,
    c: &Commit,
    n: usize,
    total: usize,
) -> CmdResult<String> {
    let mut out = String::new();
    // mbox separator: git's fixed magic date; the id field is the
    // mkit commit hash (git only needs the "From " prefix).
    let _ = writeln!(
        out,
        "From {} Mon Sep 17 00:00:00 2001",
        mkit_core::to_hex(hash)
    );
    let _ = writeln!(out, "From: {}", from_header(c));
    let _ = writeln!(out, "Date: {}", rfc2822(c.timestamp));
    let msg = String::from_utf8_lossy(&c.message);
    let mut lines = msg.lines();
    let subject = lines.next().unwrap_or("");
    if total > 1 {
        let _ = write!(out, "Subject: [PATCH {n}/{total}] {subject}\n\n");
    } else {
        let _ = write!(out, "Subject: [PATCH] {subject}\n\n");
    }
    let body: Vec<&str> = lines.skip_while(|l| l.is_empty()).collect();
    for l in &body {
        // git mailsplit treats a date-shaped "From <x> <ctime>" body
        // line as a new-message separator and FAILS the apply — on
        // git's own format-patch output too. We do one better and
        // escape exactly that shape; `git am` applies cleanly and the
        // line round-trips with a leading '>' (the classic mboxrd
        // artifact), instead of a broken series.
        if is_mbox_from_line(l) {
            out.push('>');
        }
        out.push_str(l);
        out.push('\n');
    }
    out.push_str("---\n");

    let old_tree = match c.parents.first() {
        Some(p) => match store.read_object(p) {
            Ok(Object::Commit(pc)) => Some(pc.tree_hash),
            _ => None,
        },
        None => None,
    };
    let diff = mkit_core::ops::diff::diff_trees(store, old_tree, Some(c.tree_hash))
        .map_err(|e| (format!("diff: {e}"), exit::GENERAL_ERROR))?;
    let mut buf: Vec<u8> = Vec::new();
    for e in &diff.entries {
        let mut one: Vec<u8> = Vec::new();
        // Deliberately NOT wrapped in `DisplaySource` (#625): this patch
        // body is format-patch-style output that `git am` applies into new
        // commits elsewhere, not a render a human just glances at.
        // Corruption here must surface as a loud `HashMismatch`, not
        // propagate into someone's history — keep this read verified.
        super::diff::emit_entry_patch(
            &mut one,
            store,
            e,
            mkit_core::ops::DEFAULT_CONTEXT_LINES,
            mkit_core::ops::WhitespaceMode::Exact,
        )
        .map_err(|m| (m, exit::GENERAL_ERROR))?;
        // `git am` cannot apply the textual "Binary files differ"
        // notice (and we don't emit git's base85 binary literals), so
        // a series touching binary content would fail at the
        // MAINTAINER's end — refuse here instead.
        if one
            .split(|&b| b == b'\n')
            .any(|l| l.starts_with(b"Binary files "))
        {
            return Err((
                format!(
                    "{}: binary change in commit {} — format-patch emits text \
                     patches only; use `mkit git export` for binary content",
                    e.path,
                    &mkit_core::to_hex(hash)[..12]
                ),
                exit::DATAERR,
            ));
        }
        buf.extend_from_slice(&one);
    }
    out.push_str(&String::from_utf8_lossy(&buf));
    out.push_str("-- \nmkit git format-patch\n\n");
    Ok(out)
}

/// `From:` header. An opaque identity that already looks like a git
/// person ("Name <email>") passes through; anything else renders the
/// bridge's display name with its sentinel email (matching what
/// `mkit git export` would emit).
fn from_header(c: &Commit) -> String {
    if let Ok(s) = std::str::from_utf8(&c.author.bytes)
        && c.author.kind == mkit_core::object::IdentityKind::Opaque
        && s.contains('<')
        && s.ends_with('>')
        && !s.chars().any(char::is_control)
    {
        return s.to_owned();
    }
    format!(
        "{} <{}>",
        author::display_name(&c.author),
        author::BRIDGE_EMAIL
    )
}

/// The shape `git mailsplit` splits on: `From <token> … <ctime> …`
/// where ctime is `Www Mmm [D]D HH:MM:SS YYYY`. mailsplit accepts
/// trailing tokens after the date (verified: a `+0000` timezone
/// suffix still splits), so the ctime window is searched ANYWHERE
/// after the first token, not anchored at the line end. Looser lines
/// (a plain "From the start..." sentence) do NOT split and must not
/// be escaped.
fn is_mbox_from_line(line: &str) -> bool {
    const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let Some(rest) = line.strip_prefix("From ") else {
        return false;
    };
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    // At least one token (the "sender") before the date window.
    tokens.len() >= 6
        && tokens.windows(5).skip(1).any(|w| {
            let [wday, mon, day, time, year] = w else {
                return false;
            };
            WDAYS.contains(wday)
                && MONS.contains(mon)
                && (1..=2).contains(&day.len())
                && day.bytes().all(|b| b.is_ascii_digit())
                && time.len() == 8
                && time.as_bytes()[2] == b':'
                && time.as_bytes()[5] == b':'
                && year.len() == 4
                && year.bytes().all(|b| b.is_ascii_digit())
        })
}

/// RFC 2822 date from a unix timestamp (UTC).
fn rfc2822(ts: u64) -> String {
    const WDAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    #[allow(clippy::cast_possible_wrap)] // ts/86400 < i64::MAX
    let days = (ts / 86_400) as i64;
    let secs = ts % 86_400;
    let (y, m, d) = civil_from_days(days);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // rem_euclid(7) ∈ 0..7
    let wd = ((days + 4).rem_euclid(7)) as usize; // 1970-01-01 = Thu
    format!(
        "{}, {} {} {} {:02}:{:02}:{:02} +0000",
        WDAY[wd],
        d,
        MON[(m - 1) as usize],
        y,
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Days-since-epoch → (year, month, day). Howard Hinnant's
/// `civil_from_days`, exact over the proleptic Gregorian calendar.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // d ∈ 1..=31, m ∈ 1..=12
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc2822_known_dates() {
        assert_eq!(rfc2822(0), "Thu, 1 Jan 1970 00:00:00 +0000");
        // date -u -r 1700000000 → Tue Nov 14 22:13:20 UTC 2023
        assert_eq!(rfc2822(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 +0000");
        // Leap-day check: 2024-02-29 12:00:00 UTC = 1709208000
        assert_eq!(rfc2822(1_709_208_000), "Thu, 29 Feb 2024 12:00:00 +0000");
    }

    #[test]
    fn mbox_from_line_shapes() {
        assert!(is_mbox_from_line(
            "From 1234567890abcdef1234567890abcdef12345678 Mon Sep 17 00:00:00 2001"
        ));
        assert!(is_mbox_from_line("From x Thu Jan 1 00:00:00 1970"));
        // mailsplit also splits with trailing tokens after the date
        // (verified against native git) — a timezone suffix must not
        // defeat the escape.
        assert!(is_mbox_from_line(
            "From sender Fri Jun 12 12:00:00 2026 +0000"
        ));
        // The shapes mailsplit does NOT split on stay unescaped.
        assert!(!is_mbox_from_line("From the start, this was true."));
        assert!(!is_mbox_from_line("From: someone <a@b>"));
        assert!(!is_mbox_from_line("From abc Mon Sep 17 00:00 2001")); // bad time
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("Add foo, bar & baz!"), "Add-foo-bar-baz");
        assert_eq!(slug("???"), "patch");
    }

    /// PR #659 review, finding 1's missing test: a `.rename.tmp.<pid>.0`
    /// orphan under `.mkit/git/` — the crash debris `remote.rs`'s
    /// `rename_state_dir` can leave behind between its two renames —
    /// must not count as a second bridge state. Before the
    /// dot-leading-segment rejection in `validate_ref_name`, `state_names`
    /// had no filtering of its own and would have listed the orphan
    /// alongside the legitimate state, turning zero-arg resolution
    /// ("exactly one state dir") into a spurious "multiple bridge
    /// states" error. The companion assertion for `refs/remotes/` (the
    /// other state root) lives in
    /// `remote_tracking_native::orphaned_rename_temp_dir_is_inert_in_listings`,
    /// which exercises `show-ref`/`for-each-ref` directly since those
    /// don't require the `git-bridge` feature this module is gated on.
    #[test]
    fn state_names_and_resolve_state_skip_dot_leading_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(dir.path());
        let state_dir = layout.git_state_dir();
        std::fs::create_dir_all(state_dir.join("orig")).unwrap();
        std::fs::write(state_dir.join("orig").join("marker.txt"), b"real state\n").unwrap();
        // Crash debris: dot-leading, fully populated, directly under
        // the same root as the legitimate state dir.
        let orphan = state_dir.join(".rename.tmp.99999.0");
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join("marker.txt"), b"orphaned bridge state\n").unwrap();

        assert_eq!(
            state_names(&layout),
            vec!["orig".to_string()],
            "state_names must skip the dot-leading orphan"
        );
        let (name, path) = resolve_state(&layout, None).expect(
            "zero-arg resolution must pick the lone legitimate state \
             instead of erroring 'multiple bridge states' over the orphan",
        );
        assert_eq!(name, "orig");
        assert_eq!(path, state_dir.join("orig"));
    }
}
