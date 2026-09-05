//! Read-only first-parent history. `@{0}` is the current tip, not a raw
//! ref-movement event. With history-mmr, cross-check against the versioned
//! local ancestry snapshot whose repository/ref/generation/tip context and
//! complete parent chain have been verified. Missing snapshots and pending
//! publications cannot produce a verified marker.
//! Detached replay intermediates are included when the final branch tip is
//! published; reset/amend start a new generation containing the new ancestry.
//! This command does not recover or rewrite snapshots.

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
    about = "Show a branch's first-parent ancestry (read-only).",
    disable_version_flag = true
)]
struct ReflogOpts {
    /// Branch whose history to show. Defaults to the branch HEAD points
    /// at. The ancestry is keyed per-branch, so a detached HEAD needs an
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
    let layout = match super::resolve_layout(&cwd) {
        Ok(layout) => layout,
        Err(code) => return code,
    };
    let store = match ObjectStore::open(&layout) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };

    // Resolve the target branch: explicit arg, else HEAD's branch.
    let branch = match resolve_branch(&layout, opts.reference.as_deref()) {
        Ok(b) => b,
        Err((m, c)) => return emit_err(&m, c),
    };

    let tip = match refs::read_ref(&layout, &branch) {
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

    // Walk verified first-parent commits newest to oldest for display.
    let chain = match collect_chain(&store, tip) {
        Ok(c) => c,
        Err((m, c)) => return emit_err(&m, c),
    };

    // Optional ancestry cross-check (only meaningful on history-mmr
    // builds). `ancestry` carries `(leaf_count, root)` and a
    // verifier closure that confirms a commit's inclusion at a position.
    let ancestry = open_ancestry(&layout, &branch);

    let mut stdout = std::io::stdout().lock();
    if let Format::Default = fmt
        && let Some(j) = &ancestry
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
        // Membership is in the trusted snapshot's exact first-parent chain.
        let verified = ancestry.as_ref().map(|j| j.verify_present(&commit));

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
                    Some(true) => " [ancestry verified]",
                    Some(false) => " [ancestry unverified]",
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
///  "hash":"<64-hex>","title":"...","ancestry_verified":true|false|null}
/// ```
///
/// `ancestry_verified` is `null` on a default build (no history-mmr feature, so
/// no ancestry to verify against).
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
            let _ = write!(out, ",\"ancestry_verified\":{b}");
        }
        None => {
            let _ = out.write_all(b",\"ancestry_verified\":null");
        }
    }
    let _ = out.write_all(b"}\n");
}

/// Resolve the branch whose history to show.
fn resolve_branch(
    layout: &mkit_core::layout::RepoLayout,
    explicit: Option<&str>,
) -> Result<String, (String, u8)> {
    if let Some(name) = explicit {
        return Ok(name.to_owned());
    }
    match refs::read_head(layout) {
        Ok(Head::Branch(name)) => Ok(name),
        Ok(Head::Detached(_)) => Err((
            "HEAD is detached; pass an explicit <ref> (the ref-history ancestry is per-branch)"
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

use super::error as emit_err;

// ---------------------------------------------------------------------
// Ancestry cross-check (feature: history-mmr)
// ---------------------------------------------------------------------

/// A handle to the opened ref-history ancestry used to cross-check the
/// reconstructed chain. Carries the verified leaf count and root for
/// display, plus the canonical snapshot used to build inclusion proofs.
#[cfg(feature = "history-mmr")]
struct Ancestry {
    leaf_count: u64,
    root: Hash,
    history: mkit_core::history::AncestrySnapshot,
}

#[cfg(feature = "history-mmr")]
impl Ancestry {
    /// One-line ancestry summary printed above the entries in the default
    /// format: the first-parent commit count and the ancestry root.
    ///
    /// Returns `Option` to share the signature with the default-build
    /// `Ancestry` (which has no ancestry and returns `None`).
    #[allow(clippy::unnecessary_wraps)]
    fn summary_line(&self, branch: &str) -> Option<String> {
        Some(format!(
            "# ancestry: {} first-parent commit(s) on '{branch}', root {}",
            self.leaf_count,
            format::short_hash(&self.root, 8)
        ))
    }

    /// Verify membership using the descriptor loaded from authoritative local
    /// state. Leaf lookup is exact; no ref-event/ancestry ambiguity remains.
    fn verify_present(&self, commit: &Hash) -> bool {
        let Some(position) = self.history.position_of(commit) else {
            return false;
        };
        let Ok(proof) = self.history.prove(position) else {
            return false;
        };
        let trusted = self.history.trusted_descriptor();
        mkit_core::history::verify_ancestry(
            commit,
            position,
            &proof,
            self.history.descriptor(),
            &trusted,
            self.history.descriptor(),
        )
    }
}

/// Open the per-branch ref-history ancestry for cross-checking, if the
/// build has the `history-mmr` feature and the ancestry opens cleanly.
/// Read-only: opening does not append.
#[cfg(feature = "history-mmr")]
fn open_ancestry(layout: &mkit_core::layout::RepoLayout, branch: &str) -> Option<Ancestry> {
    let history = mkit_core::history::AncestrySnapshot::load(layout, branch).ok()?;
    Some(Ancestry {
        leaf_count: history.len(),
        root: history.root(),
        history,
    })
}

/// Default build: no ancestry to verify against.
#[cfg(not(feature = "history-mmr"))]
struct Ancestry;

#[cfg(not(feature = "history-mmr"))]
impl Ancestry {
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
fn open_ancestry(_layout: &mkit_core::layout::RepoLayout, _branch: &str) -> Option<Ancestry> {
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
    fn json_entry_shape_default_build_is_null_ancestry_verified() {
        let mut buf = Vec::new();
        emit_json_entry(&mut buf, "main", 0, &[0xab; 32], "hello", None);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"ref\":\"main\""));
        assert!(s.contains("\"selector\":\"main@{0}\""));
        assert!(s.contains("\"index\":0"));
        assert!(s.contains("\"ancestry_verified\":null"));
        assert!(s.ends_with("}\n"));
    }

    #[test]
    fn json_entry_ancestry_verified_true_renders_bool() {
        let mut buf = Vec::new();
        emit_json_entry(&mut buf, "dev", 3, &[0x01; 32], "t", Some(true));
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("\"selector\":\"dev@{3}\""));
        assert!(s.contains("\"ancestry_verified\":true"));
    }
}
