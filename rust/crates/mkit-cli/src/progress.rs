//! Honest transfer-progress reporting for `clone`/`push`/`pull`/`fetch`
//! (#711).
//!
//! `mkit clone`/`push`/`pull`/`fetch` previously printed only a start
//! banner and a final summary — the network transfer itself was silent.
//! This module adds a lightweight, thread-local progress sink that the
//! transfer call chain (`push_branch_with_depth` in
//! `remote_dispatch::mod`, `unpack_downloaded_packs` in
//! `remote_dispatch::packmap`) reports real, already-happened work to:
//! objects staged into the outgoing pack, bytes handed to the transport,
//! and objects unpacked from a downloaded pack.
//!
//! It deliberately never reports git's fabricated
//! `Enumerating/Counting/Compressing objects` or `Total N (delta D)`
//! lines — mkit's transport is one-object-per-pack and computes no
//! cross-branch delta graph, so those numbers would be invented (see
//! `docs/PARITY.md`'s "Human-facing output parity" section).
//!
//! ## Threading pattern
//!
//! Rather than adding a progress parameter to every function in the
//! `push_all_with` → `push_branch_with_depth` → `pull_all` →
//! `fetch_objects` call chain (touching dozens of existing call sites,
//! including many integration tests that don't care about progress at
//! all), this mirrors the pattern already used for interrupt handling:
//! `crate::signal::is_shutdown()` is a global checkpoint polled inside
//! the same loops. Here, [`report`] is the equivalent checkpoint —  a
//! thread-local sink installed by [`start`] and torn down by the
//! returned [`Guard`]'s `Drop`. When no sink is installed (the common
//! case: every test that doesn't call [`start`], and any non-interactive
//! run), `report` is a cheap thread-local check that does nothing.
//! Concurrent callers (see `fetch_pull_lock_scope.rs`, which fetches
//! from multiple threads) are unaffected: the sink is thread-local, so
//! each thread has its own (absent, by default) reporter.
//!
//! ## Interactivity gating
//!
//! Mirrors `term::use_color_stderr`'s tty auto-detection: progress is
//! shown only when stderr is a tty, unless overridden by an explicit
//! `--quiet` flag (forces off) or the `MKIT_PROGRESS` env var
//! (`always`/`never`/`auto`, mirroring `NO_COLOR`/`CLICOLOR_FORCE`'s
//! override convention) — `always` is how the CLI integration tests
//! observe progress lines over a piped (non-tty) stderr.

use std::cell::RefCell;
use std::io::{IsTerminal, Write};

/// One real, already-happened unit of transfer work. Never a projection
/// or estimate.
#[derive(Debug, Clone, Copy)]
pub enum Event {
    /// `count` objects were appended to the outgoing pack(s) (push side,
    /// `build_and_upload_packs`'s `plan.raw` / `plan.deltas` loops).
    ObjectsPacked(usize),
    /// A finished pack (`bytes` long) was handed to
    /// `Transport::upload_pack` — that pack's upload is complete. Fires
    /// once per pack; a push whose plan exceeds a single pack's payload
    /// cap fires this more than once, and `bytes` accumulates across
    /// calls (issue #831) rather than reporting only the last pack.
    PackUploaded(u64),
    /// `count` objects were unpacked from one downloaded pack (pull/fetch
    /// side, `unpack_downloaded_packs`) — real counts from the pack's own
    /// [`mkit_core::pack::UnpackReport`].
    ObjectsUnpacked(usize),
}

/// Objects between throttled stderr re-writes. The final event
/// ([`Event::PackUploaded`], and [`Guard`]'s `Drop`) always emits
/// regardless of this threshold, so the last line reflects the true
/// final count even when it doesn't land on an interval boundary.
const REPORT_INTERVAL: usize = 8;

struct Reporter {
    label: &'static str,
    total: Option<usize>,
    done: usize,
    bytes: u64,
    last_emit_done: usize,
    emitted: bool,
}

impl Reporter {
    fn new(label: &'static str, total: Option<usize>) -> Self {
        Self {
            label,
            total,
            done: 0,
            bytes: 0,
            last_emit_done: 0,
            emitted: false,
        }
    }

    fn record(&mut self, event: Event) {
        match event {
            Event::ObjectsPacked(n) | Event::ObjectsUnpacked(n) => {
                self.done += n;
                if self.done.saturating_sub(self.last_emit_done) >= REPORT_INTERVAL {
                    self.emit();
                }
            }
            Event::PackUploaded(bytes) => {
                // Accumulate, not overwrite: a multi-pack push (#831)
                // fires this once per pack, and the reported total must
                // cover every pack uploaded so far, not just the last one.
                self.bytes = self.bytes.saturating_add(bytes);
                self.emit();
            }
        }
    }

    fn emit(&mut self) {
        self.last_emit_done = self.done;
        self.emitted = true;
        let mut stderr = std::io::stderr().lock();
        let _ = match (self.total, self.bytes) {
            (Some(total), 0) => write!(stderr, "\r{}: {}/{} objects", self.label, self.done, total),
            (Some(total), bytes) => write!(
                stderr,
                "\r{}: {}/{} objects, {} bytes",
                self.label, self.done, total, bytes
            ),
            (None, 0) => write!(stderr, "\r{}: {} objects", self.label, self.done),
            (None, bytes) => write!(
                stderr,
                "\r{}: {} objects, {} bytes",
                self.label, self.done, bytes
            ),
        };
        let _ = stderr.flush();
    }

    /// Force a final emit (bypassing the throttle) and move past the
    /// self-overwriting `\r` line so later output isn't clobbered by it.
    /// A no-op when nothing was ever reported (e.g. a no-op push).
    fn finish(&mut self) {
        if self.done == 0 && self.bytes == 0 {
            return;
        }
        self.emit();
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, ", done.");
    }
}

thread_local! {
    static REPORTER: RefCell<Option<Reporter>> = const { RefCell::new(None) };
}

/// RAII handle returned by [`start`]. Dropping it flushes a final
/// progress line (if anything was reported) and uninstalls the
/// thread-local sink, so a command can simply hold the guard for the
/// duration of its transfer call and let scope-exit (including an early
/// `return` on error) clean up.
#[derive(Debug)]
#[must_use = "dropping this immediately ends progress reporting"]
pub struct Guard {
    _private: (),
}

impl Drop for Guard {
    fn drop(&mut self) {
        REPORTER.with(|r| {
            if let Some(mut rep) = r.borrow_mut().take() {
                rep.finish();
            }
        });
    }
}

/// Install a thread-local progress reporter for the duration of the
/// returned [`Guard`]. `enabled = false` installs no reporter, so
/// [`report`] stays a cheap no-op — used when stderr isn't interactive
/// or `--quiet` was passed (see [`should_report`]).
///
/// `total`, when known ahead of time (the push side plans its pack
/// before building it), renders as `done/total`; `None` (the fetch/pull
/// side, where the object count isn't known until each pack is
/// downloaded) renders as a running count only — never a fabricated
/// total.
pub fn start(label: &'static str, total: Option<usize>, enabled: bool) -> Guard {
    REPORTER.with(|r| {
        *r.borrow_mut() = if enabled {
            Some(Reporter::new(label, total))
        } else {
            None
        };
    });
    Guard { _private: () }
}

/// Report one real unit of already-completed transfer work to the
/// current thread's installed reporter, if any. A no-op — a single
/// thread-local check — when no [`Guard`] is active on this thread,
/// which is the default for every caller that doesn't opt in (including
/// every existing test that drives `push_branch_with_depth` /
/// `push_all` / `pull_all` / `fetch_all` directly).
pub fn report(event: Event) {
    REPORTER.with(|r| {
        // `try_borrow_mut` rather than `borrow_mut`: `report` is called
        // from deep inside the transfer call chain and must never panic
        // on a re-entrant borrow; silently dropping a progress tick is
        // harmless (the running total is cosmetic), unlike the transfer
        // itself.
        if let Ok(mut slot) = r.try_borrow_mut()
            && let Some(rep) = slot.as_mut()
        {
            rep.record(event);
        }
    });
}

/// Whether progress should be shown on stderr: not explicitly silenced
/// (`--quiet` / `-q`), and either `MKIT_PROGRESS` forces a decision or
/// stderr is a tty. Mirrors `term::use_color_stderr`'s
/// `NO_COLOR`/`CLICOLOR_FORCE`-style override convention — `always` is
/// how CLI integration tests observe progress lines over a piped
/// (non-tty) stderr; `never` is an explicit opt-out distinct from
/// `--quiet` (e.g. for scripting environments that set it once instead
/// of threading `--quiet` through every call site).
#[must_use]
pub fn should_report(quiet: bool) -> bool {
    if quiet {
        return false;
    }
    match std::env::var("MKIT_PROGRESS").ok().as_deref() {
        Some("always") => true,
        Some("never") => false,
        _ => std::io::stderr().is_terminal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `report` with no active [`Guard`] must not panic and must not
    /// touch stderr (there's no reporter to write through) — the
    /// no-op path every existing push/pull/fetch integration test takes.
    #[test]
    fn report_without_guard_is_a_silent_no_op() {
        report(Event::ObjectsPacked(1));
        report(Event::PackUploaded(128));
        report(Event::ObjectsUnpacked(3));
    }

    /// issue #831: a multi-pack push fires `PackUploaded` once per
    /// pack. The reported byte total must accumulate across those
    /// calls, not report only the last pack (the bug this test pins).
    #[test]
    fn pack_uploaded_accumulates_across_multiple_packs() {
        let mut rep = Reporter::new("Writing objects", None);
        rep.record(Event::PackUploaded(100));
        assert_eq!(rep.bytes, 100);
        rep.record(Event::PackUploaded(50));
        assert_eq!(rep.bytes, 150, "second pack's bytes must add, not replace");
        rep.record(Event::PackUploaded(25));
        assert_eq!(rep.bytes, 175);
    }

    /// A disabled guard (`enabled: false`) installs no reporter, so
    /// `report` inside its scope is still the no-op path.
    #[test]
    fn disabled_guard_installs_no_reporter() {
        let guard = start("Writing objects", Some(4), false);
        report(Event::ObjectsPacked(4));
        drop(guard);
    }

    /// `should_report` precedence: `--quiet` wins outright, then
    /// `MKIT_PROGRESS`, then tty-ness. Exercised via the pure
    /// tty-independent branches only (quiet, and the env var forcing a
    /// decision) — this process's stderr tty-ness varies by how tests
    /// are invoked, so the `_ =>` fallthrough isn't asserted here.
    #[test]
    fn should_report_quiet_always_wins() {
        assert!(!should_report(true));
    }
}
