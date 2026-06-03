//! `mkit reflog [<ref>]` — read-only view over the persisted
//! ref-history journal (issue #231).
//!
//! # What the journal actually records
//!
//! mkit's ref-history is the per-branch, append-only **commit-history
//! MMR** (`mkit_core::history::CommitHistory`, the `refs-history.lock`
//! journal written by `write_ref_recording_history`). On *every* branch
//! advance — commit, branch creation, merge, rebase, cherry-pick,
//! amend, fetch/pull tip update — the new tip hash is appended as one
//! leaf. The journal therefore stores:
//!
//! - the **count** of recorded advances (`len()`), and
//! - a tamper-evident **root** plus per-leaf inclusion proofs.
//!
//! It deliberately does **not** store what a Git reflog stores: there
//! is no op label, no old→new pair, no per-entry timestamp or message,
//! and — crucially — the leaf digests are BLAKE3 values with the leaf
//! position mixed in, so the original commit hashes **cannot be read
//! back out of the MMR**. The MMR can only *confirm* a hash you already
//! hold (via `verify_inclusion`).
//!
//! # What `mkit reflog` therefore surfaces
//!
//! Because the readable hashes can only come from the object store, not
//! the MMR, `reflog` walks the branch tip's **first-parent chain**
//! (newest → oldest) — the same reconstruction
//! `history::rebuild_from_chain` uses — and presents it as the branch's
//! movement history, addressed `<branch>@{N}` with `@{0}` = current
//! tip. On a build with `--features history-mmr` it additionally
//! **cross-checks each commit against the journaled MMR root**: it asks
//! the journal to confirm, via an inclusion proof, that the commit was
//! recorded as a branch advance at some leaf position. The
//! recorded-advance count is reported in the summary line. The check is
//! rewrite-robust — a reachable commit shows `[journaled]` as long as it
//! was journaled at some point, even after a later amend/reset shifted
//! the journal's leaf count past the reachable chain length.
//!
//! This is **not** a full Git reflog: `@{N}` indexes the reachable
//! first-parent chain (which drops superseded commits — e.g. after an
//! `--amend` or a reset the old tip is no longer listed), not the raw
//! append log of every movement. See the help text / `man mkit` for the
//! exact contract.
//!
//! Read-only: this command never mutates refs, the journal, or any
//! object.

use std::io::Write;

use clap::{Parser, ValueEnum};
use mkit_core::hash::Hash;
use mkit_core::object::Object;
use mkit_core::refs::{self, Head};
use mkit_core::store::ObjectStore;

use crate::clap_shim;
use crate::exit;
use crate::format;
use crate::signal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Default,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "mkit reflog",
    about = "Show a branch's recorded movement history (read-only).",
    disable_version_flag = true
)]
struct ReflogOpts {
    /// Branch whose history to show. Defaults to the branch HEAD points
    /// at. The journal is keyed per-branch, so a detached HEAD needs an
    /// explicit ref.
    #[arg(value_name = "REF")]
    reference: Option<String>,

    /// Output format. `json` emits one JSONL record per entry.
    #[arg(long, value_enum)]
    format: Option<Format>,

    /// Cap the number of entries printed.
    #[arg(short = 'n')]
    limit: Option<usize>,
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<ReflogOpts>("mkit reflog", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let fmt = opts.format.unwrap_or(Format::Default);

    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    // Resolve the target branch: explicit arg, else HEAD's branch.
    let branch = match resolve_branch(&mkit_dir, opts.reference.as_deref()) {
        Ok(b) => b,
        Err((m, c)) => return emit_err(&m, c),
    };

    let tip = match refs::read_ref(&mkit_dir, &branch) {
        Ok(Some(h)) => h,
        Ok(None) => {
            if matches!(fmt, Format::Default) {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "no history for '{branch}': no commits yet");
            }
            return exit::OK;
        }
        Err(e) => return emit_err(&format!("read ref '{branch}': {e}"), exit::DATAERR),
    };

    // Walk the first-parent chain newest → oldest. This is the readable
    // reconstruction of the branch's movement history; the MMR journal
    // itself stores opaque leaf digests that cannot be decoded back to
    // hashes (see module docs).
    let chain = match collect_chain(&store, tip) {
        Ok(c) => c,
        Err((m, c)) => return emit_err(&m, c),
    };

    // Optional journal cross-check (only meaningful on history-mmr
    // builds). `journal` carries `(recorded_advances, root)` and a
    // verifier closure that confirms a commit's inclusion at a position.
    let journal = open_journal(&mkit_dir, &branch);

    let mut stdout = std::io::stdout().lock();
    if let Format::Default = fmt
        && let Some(j) = &journal
        && let Some(summary) = j.summary_line(&branch)
    {
        let _ = writeln!(stdout, "{summary}");
    }

    for (i, &commit) in chain.iter().enumerate() {
        if signal::is_shutdown() {
            return exit::TEMPFAIL;
        }
        if let Some(lim) = opts.limit
            && i >= lim
        {
            break;
        }
        // `@{0}` is the current tip (chain[0]); `@{N}` walks back.
        let selector = i;
        // Journal cross-check: was this reachable commit ever recorded
        // as a journaled branch advance? We can't decode the opaque MMR
        // leaves, so we ask the journal to *confirm* the commit at some
        // leaf position via an inclusion proof. This is rewrite-robust:
        // a commit reachable today verifies as long as it was journaled
        // at some point (even if a later amend/reset shifted leaf
        // counts). `None` on a default build (no journal).
        let verified = journal.as_ref().map(|j| j.verify_present(&commit));

        let obj = match store.read_object(&commit) {
            Ok(o) => o,
            Err(e) => {
                return emit_err(
                    &format!("read {}: {e}", format::hex_hash(&commit)),
                    exit::DATAERR,
                );
            }
        };
        let title = match &obj {
            Object::Commit(c) => first_line(&c.message),
            Object::Remix(r) => first_line(&r.message),
            _ => {
                return emit_err(
                    &format!("not a commit: {}", format::hex_hash(&commit)),
                    exit::DATAERR,
                );
            }
        };

        match fmt {
            Format::Default => {
                let mark = match verified {
                    Some(true) => " [journaled]",
                    Some(false) => " [NOT in journal]",
                    None => "",
                };
                let _ = writeln!(
                    stdout,
                    "{} {}@{{{selector}}}: {title}{mark}",
                    format::short_hash(&commit, 8),
                    branch,
                );
            }
            Format::Json => {
                emit_json_entry(&mut stdout, &branch, selector, &commit, &title, verified);
            }
        }
    }
    exit::OK
}

/// JSONL record per entry. Schema:
///
/// ```json
/// {"ref":"main","selector":"main@{0}","index":0,
///  "hash":"<64-hex>","title":"...","journaled":true|false|null}
/// ```
///
/// `journaled` is `null` on a default build (no history-mmr feature, so
/// no journal to verify against).
fn emit_json_entry(
    out: &mut impl Write,
    branch: &str,
    index: usize,
    hash: &Hash,
    title: &str,
    verified: Option<bool>,
) {
    let _ = out.write_all(b"{");
    let _ = write!(out, "\"ref\":\"{}\"", format::json_escape(branch));
    let _ = write!(
        out,
        ",\"selector\":\"{}@{{{index}}}\"",
        format::json_escape(branch)
    );
    let _ = write!(out, ",\"index\":{index}");
    let _ = write!(out, ",\"hash\":\"{}\"", format::hex_hash(hash));
    let _ = write!(out, ",\"title\":\"{}\"", format::json_escape(title));
    match verified {
        Some(b) => {
            let _ = write!(out, ",\"journaled\":{b}");
        }
        None => {
            let _ = out.write_all(b",\"journaled\":null");
        }
    }
    let _ = out.write_all(b"}\n");
}

/// Resolve the branch whose history to show.
fn resolve_branch(
    mkit_dir: &std::path::Path,
    explicit: Option<&str>,
) -> Result<String, (String, u8)> {
    if let Some(name) = explicit {
        return Ok(name.to_owned());
    }
    match refs::read_head(mkit_dir) {
        Ok(Head::Branch(name)) => Ok(name),
        Ok(Head::Detached(_)) => Err((
            "HEAD is detached; pass an explicit <ref> (the ref-history journal is per-branch)"
                .to_owned(),
            exit::USAGE,
        )),
        Err(e) => Err((format!("read HEAD: {e}"), exit::DATAERR)),
    }
}

/// Walk the first-parent chain from `tip`, newest first.
fn collect_chain(store: &ObjectStore, tip: Hash) -> Result<Vec<Hash>, (String, u8)> {
    let mut chain = Vec::new();
    let mut cursor = Some(tip);
    while let Some(h) = cursor {
        chain.push(h);
        let parent = match store.read_object(&h) {
            Ok(Object::Commit(c)) => c.parents.first().copied(),
            Ok(Object::Remix(r)) => r.parents.first().copied(),
            Ok(_) => {
                return Err((
                    format!("not a commit: {}", format::hex_hash(&h)),
                    exit::DATAERR,
                ));
            }
            Err(e) => {
                return Err((format!("read {}: {e}", format::hex_hash(&h)), exit::DATAERR));
            }
        };
        cursor = parent;
    }
    Ok(chain)
}

fn first_line(message: &[u8]) -> String {
    String::from_utf8_lossy(message)
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

// ---------------------------------------------------------------------
// Journal cross-check (feature: history-mmr)
// ---------------------------------------------------------------------

/// A handle to the opened ref-history journal used to cross-check the
/// reconstructed chain. Carries the recorded-advance count and root for
/// display, plus the live `CommitHistory` to build inclusion proofs.
#[cfg(feature = "history-mmr")]
struct Journal {
    recorded_advances: u64,
    root: Hash,
    history: mkit_core::history::CommitHistory<mkit_core::history::TokioExecutor>,
}

#[cfg(feature = "history-mmr")]
impl Journal {
    /// One-line journal summary printed above the entries in the default
    /// format: the recorded-advance count and the journal root.
    ///
    /// Returns `Option` to share the signature with the default-build
    /// `Journal` (which has no journal and returns `None`).
    #[allow(clippy::unnecessary_wraps)]
    fn summary_line(&self, branch: &str) -> Option<String> {
        Some(format!(
            "# journal: {} recorded advance(s) on '{branch}', root {}",
            self.recorded_advances,
            format::short_hash(&self.root, 8)
        ))
    }

    /// `true` iff `commit` was recorded as a journaled branch advance —
    /// i.e. it verifies, against the current journal root, as the leaf
    /// at *some* position. Scans newest-leaf-first (the common case is
    /// the tip / a recent advance) and stops at the first match.
    ///
    /// O(advances) inclusion proofs in the worst case; reflog is a
    /// diagnostic command and callers cap it with `-n`. `false` for an
    /// empty journal or a commit that was never journaled.
    fn verify_present(&self, commit: &Hash) -> bool {
        let mut position = self.recorded_advances;
        while position > 0 {
            position -= 1;
            let pos = mkit_core::history::Position(position);
            let Ok(proof) = self.history.prove(pos) else {
                continue;
            };
            if mkit_core::history::verify_inclusion(commit, pos, &proof, &self.root) {
                return true;
            }
        }
        false
    }
}

/// Open the per-branch ref-history journal for cross-checking, if the
/// build has the `history-mmr` feature and the journal opens cleanly.
/// Read-only: opening does not append.
#[cfg(feature = "history-mmr")]
fn open_journal(mkit_dir: &std::path::Path, branch: &str) -> Option<Journal> {
    let exec = super::history_executor();
    let history = mkit_core::history::CommitHistory::open_at(exec, mkit_dir, branch).ok()?;
    Some(Journal {
        recorded_advances: history.len(),
        root: history.root(),
        history,
    })
}

/// Default build: no journal to verify against.
#[cfg(not(feature = "history-mmr"))]
struct Journal;

#[cfg(not(feature = "history-mmr"))]
impl Journal {
    #[allow(clippy::unused_self)]
    fn summary_line(&self, _branch: &str) -> Option<String> {
        None
    }

    #[allow(clippy::unused_self)]
    fn verify_present(&self, _commit: &Hash) -> bool {
        false
    }
}

#[cfg(not(feature = "history-mmr"))]
fn open_journal(_mkit_dir: &std::path::Path, _branch: &str) -> Option<Journal> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_line_takes_title_only() {
        assert_eq!(first_line(b"title\n\nbody"), "title");
        assert_eq!(first_line(b"only"), "only");
        assert_eq!(first_line(b""), "");
    }

    #[test]
    fn json_entry_shape_default_build_is_null_journaled() {
        let mut buf = Vec::new();
        emit_json_entry(&mut buf, "main", 0, &[0xab; 32], "hello", None);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"ref\":\"main\""));
        assert!(s.contains("\"selector\":\"main@{0}\""));
        assert!(s.contains("\"index\":0"));
        assert!(s.contains("\"journaled\":null"));
        assert!(s.ends_with("}\n"));
    }

    #[test]
    fn json_entry_journaled_true_renders_bool() {
        let mut buf = Vec::new();
        emit_json_entry(&mut buf, "dev", 3, &[0x01; 32], "t", Some(true));
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"selector\":\"dev@{3}\""));
        assert!(s.contains("\"journaled\":true"));
    }
}
