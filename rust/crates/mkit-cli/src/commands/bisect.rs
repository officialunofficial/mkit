//! `mkit bisect start|good|bad|reset|skip|run` — binary-search a history
//! for the commit that introduced a regression. Backing state + search
//! logic live in `mkit_core::ops::bisect`.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use mkit_core::hash::Hash;
use mkit_core::ops::bisect::{
    BisectState, BisectStep, cleanup_bisect, is_bisect_in_progress, next_step, read_state,
    write_state,
};
use mkit_core::refs::{self, Head};
use mkit_core::store::ObjectStore;

use clap::{Parser, Subcommand};

use crate::clap_shim;
use crate::exit;
use crate::format;

#[derive(Debug, Parser)]
#[command(
    name = "mkit bisect",
    about = "Binary-search for a regression-introducing commit."
)]
struct BisectOpts {
    #[command(subcommand)]
    sub: BisectCmd,
}

#[derive(Debug, Subcommand)]
enum BisectCmd {
    /// Begin a bisect session at HEAD.
    Start,
    /// Mark a commit (or HEAD) as good.
    Good { commit: Option<String> },
    /// Mark a commit (or HEAD) as bad.
    Bad { commit: Option<String> },
    /// Skip the current candidate.
    Skip,
    /// End the session and restore the original HEAD.
    Reset,
    /// Automatically bisect: run `<cmd> [args…]` at each candidate,
    /// classifying by exit status (0=good, 125=skip, 1–127 else=bad,
    /// ≥128=abort) until the first bad commit is found.
    Run {
        /// The command to run, followed by its arguments.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
}

#[must_use]
pub fn run(args: &[String]) -> u8 {
    let opts = match clap_shim::parse::<BisectOpts>("mkit bisect", args) {
        Ok(o) => o,
        Err(code) => return code,
    };
    let cwd = match std::env::current_dir() {
        Ok(p) => p,
        Err(e) => return emit_err(&format!("cwd: {e}"), exit::NOINPUT),
    };
    let store = match ObjectStore::open(&cwd) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("not a mkit repo: {e}"), exit::GENERAL_ERROR),
    };
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);

    match opts.sub {
        BisectCmd::Start => start(&mkit_dir),
        BisectCmd::Good { commit } => mark(&store, &mkit_dir, commit.as_deref(), true),
        BisectCmd::Bad { commit } => mark(&store, &mkit_dir, commit.as_deref(), false),
        BisectCmd::Skip => skip(&store, &mkit_dir),
        BisectCmd::Reset => reset(&mkit_dir),
        BisectCmd::Run { argv } => run_automated(&store, &cwd, &mkit_dir, &argv),
    }
}

fn start(mkit_dir: &std::path::Path) -> u8 {
    if is_bisect_in_progress(mkit_dir) {
        return emit_err(
            "a bisect is already in progress (use `mkit bisect reset` first)",
            exit::GENERAL_ERROR,
        );
    }
    let orig_head = match refs::resolve_head(mkit_dir) {
        Ok(Some(h)) => h,
        Ok(None) => return emit_err("no commits yet", exit::GENERAL_ERROR),
        Err(e) => return emit_err(&format!("resolve HEAD: {e}"), exit::GENERAL_ERROR),
    };
    let orig_branch = match refs::read_head(mkit_dir) {
        Ok(Head::Branch(name)) => Some(name),
        _ => None,
    };
    let state = BisectState {
        orig_head,
        orig_branch,
        bad_hash: None,
        good_hashes: Vec::new(),
        skipped: BTreeSet::default(),
    };
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("write state: {e}"), exit::CANTCREAT);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "bisect started; mark endpoints with `mkit bisect good <hash>` and `mkit bisect bad <hash>`"
    );
    exit::OK
}

fn mark(store: &ObjectStore, mkit_dir: &std::path::Path, arg: Option<&str>, good: bool) -> u8 {
    if !is_bisect_in_progress(mkit_dir) {
        return emit_err("no bisect in progress", exit::GENERAL_ERROR);
    }
    let mut state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    let hash_: Hash = match arg {
        Some(s) => match super::revspec::resolve_revision(store, mkit_dir, s) {
            Ok(h) => h,
            Err(e) => return emit_err(&format!("bad commit: {e}"), exit::DATAERR),
        },
        None => match refs::resolve_head(mkit_dir) {
            Ok(Some(h)) => h,
            _ => return emit_err("no HEAD; provide an explicit hash", exit::GENERAL_ERROR),
        },
    };
    if good {
        state.good_hashes.push(hash_);
    } else {
        state.bad_hash = Some(hash_);
    }
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("persist state: {e}"), exit::CANTCREAT);
    }
    report_step(store, &state)
}

fn skip(store: &ObjectStore, mkit_dir: &std::path::Path) -> u8 {
    if !is_bisect_in_progress(mkit_dir) {
        return emit_err("no bisect in progress", exit::GENERAL_ERROR);
    }
    let mut state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    // Determine the current midpoint to skip.
    let current_mid = match next_step(store, &state) {
        Ok(BisectStep::Testing { hash, .. }) => hash,
        Ok(_) => {
            // Nothing to skip: either already found or not enough data.
            // User error (skip invoked when bisect has no current
            // candidate); USAGE rather than OK so scripts see the
            // failure.
            return emit_err("bisect skip: no current candidate to skip", exit::USAGE);
        }
        Err(e) => return emit_err(&format!("bisect skip: {e}"), exit::GENERAL_ERROR),
    };
    // Add the current midpoint to the exclusion set, then advance.
    state.skipped.insert(current_mid);
    if let Err(e) = write_state(mkit_dir, &state) {
        return emit_err(&format!("persist state: {e}"), exit::CANTCREAT);
    }
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "skipped {}; advancing to next candidate",
        format::short_hash(&current_mid, 12)
    );
    drop(stderr);
    report_step(store, &state)
}

fn reset(mkit_dir: &std::path::Path) -> u8 {
    if !is_bisect_in_progress(mkit_dir) {
        return emit_err("no bisect in progress", exit::GENERAL_ERROR);
    }
    let state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };
    if let Some(branch) = state.orig_branch.as_deref() {
        let _ = refs::write_head_branch(mkit_dir, branch);
    } else {
        let _ = refs::write_head_detached(mkit_dir, &state.orig_head);
    }
    let _ = cleanup_bisect(mkit_dir);
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "bisect reset");
    exit::OK
}

/// How a `bisect run` command's exit status classifies the candidate.
enum Verdict {
    Good,
    Bad,
    Skip,
    Abort,
}

/// Map a child exit code to a verdict, following git's `bisect run`
/// contract: `0` good, `125` skip, `1`–`127` (except `125`) bad, `>=128`
/// or signal-killed (`code() == None`) abort.
fn classify(code: Option<i32>) -> Verdict {
    match code {
        Some(0) => Verdict::Good,
        Some(125) => Verdict::Skip,
        Some(c) if (1..=127).contains(&c) => Verdict::Bad,
        _ => Verdict::Abort,
    }
}

/// Drive the bisection automatically (git's `bisect run`): check out each
/// candidate, run `<program> [cmd_args…]`, classify by exit status, and
/// converge on the first bad commit.
///
/// mkit's bisect is otherwise print-candidate (no auto-checkout); `run`
/// checks out each candidate transiently so the command tests real code,
/// then restores the original HEAD once it converges — it *prints* the
/// first bad commit rather than parking the worktree there (the intentional
/// divergence that keeps bisect's overall model print-candidate). The
/// candidate is also exported as `MKIT_BISECT_COMMIT` for commands that
/// prefer it over the worktree.
fn run_automated(store: &ObjectStore, cwd: &Path, mkit_dir: &Path, argv: &[String]) -> u8 {
    if !is_bisect_in_progress(mkit_dir) {
        return emit_err("no bisect in progress", exit::GENERAL_ERROR);
    }
    // clap's `required = true` guarantees at least the program name.
    let Some((program, cmd_args)) = argv.split_first() else {
        return emit_err("bisect run: missing command", exit::USAGE);
    };
    let mut state = match read_state(mkit_dir) {
        Ok(s) => s,
        Err(e) => return emit_err(&format!("read state: {e}"), exit::GENERAL_ERROR),
    };

    // Each iteration records an endpoint (good/bad) or a skip, all of which
    // strictly shrink the candidate set, so the loop terminates; the guard
    // is a backstop against a misbehaving `next_step`.
    let mut guard = 0u32;
    loop {
        guard += 1;
        if guard > 1_000_000 {
            let _ = restore_head(cwd, &state);
            return emit_err("bisect run: did not converge", exit::GENERAL_ERROR);
        }

        let hash = match next_step(store, &state) {
            Ok(BisectStep::Testing { hash, remaining }) => {
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(
                    stderr,
                    "bisect run: testing {} ({remaining} candidates remaining)",
                    format::short_hash(&hash, 12)
                );
                hash
            }
            Ok(BisectStep::Found(h)) => {
                // Converged: restore the original HEAD, then report. The
                // hash goes to stdout (data), the prose to stderr.
                if let Err(code) = restore_head(cwd, &state) {
                    return code;
                }
                let mut stderr = std::io::stderr().lock();
                let _ = writeln!(stderr, "bisect found first bad commit:");
                drop(stderr);
                let mut stdout = std::io::stdout().lock();
                let _ = writeln!(stdout, "{}", format::short_hash(&h, 12));
                return exit::OK;
            }
            Ok(BisectStep::Ambiguous { bad, skipped }) => {
                // Only skipped commits remain: like git, report that the
                // first bad commit is ambiguous rather than guessing `bad`.
                let _ = restore_head(cwd, &state);
                report_ambiguous(bad, &skipped);
                return exit::GENERAL_ERROR;
            }
            Ok(BisectStep::NeedMore) => {
                return emit_err(
                    "bisect run: need at least one good and one bad commit first",
                    exit::USAGE,
                );
            }
            Err(e) => return emit_err(&format!("bisect run: {e}"), exit::GENERAL_ERROR),
        };

        // Check out the candidate so the command tests its actual tree.
        if let Err(code) = checkout(cwd, &format::hex_hash(&hash)) {
            let _ = restore_head(cwd, &state);
            return code;
        }

        let status = Command::new(program)
            .args(cmd_args)
            .current_dir(cwd)
            .env("MKIT_BISECT_COMMIT", format::hex_hash(&hash))
            .status();
        let code = match status {
            Ok(s) => s.code(),
            Err(e) => {
                let _ = restore_head(cwd, &state);
                return emit_err(
                    &format!("bisect run: failed to run `{program}`: {e}"),
                    exit::GENERAL_ERROR,
                );
            }
        };

        match classify(code) {
            Verdict::Good => state.good_hashes.push(hash),
            Verdict::Bad => state.bad_hash = Some(hash),
            Verdict::Skip => {
                state.skipped.insert(hash);
            }
            Verdict::Abort => {
                let _ = restore_head(cwd, &state);
                let shown = code.map_or_else(|| "signal".to_string(), |c| c.to_string());
                return emit_err(
                    &format!("bisect run: command aborted (exit {shown})"),
                    exit::GENERAL_ERROR,
                );
            }
        }
        if let Err(e) = write_state(mkit_dir, &state) {
            let _ = restore_head(cwd, &state);
            return emit_err(&format!("persist state: {e}"), exit::CANTCREAT);
        }
    }
}

/// Restore the worktree + HEAD to where bisect started, re-exec'ing
/// `mkit checkout` on the original branch (or detached original HEAD).
fn restore_head(cwd: &Path, state: &BisectState) -> Result<(), u8> {
    let target = match state.orig_branch.as_deref() {
        Some(branch) => branch.to_string(),
        None => format::hex_hash(&state.orig_head),
    };
    checkout(cwd, &target)
}

/// Re-exec this same binary as `mkit checkout --force <target>` to
/// materialize a commit into the worktree, reusing checkout's full
/// safety/index handling and discarding the test command's tracked-file
/// scribbles. On failure prints the child's diagnostics and returns a code.
///
/// This is deliberately its own small self-exec rather than reusing
/// `mcp::run_subprocess`: that helper wraps the result in an MCP
/// `CallOutcome`, whereas here we only need the raw exit status plus stderr
/// passthrough. Sparse caveat: the child checkout does not re-apply a
/// persisted sparse cone (checkout only honors an explicit `--sparse`), so
/// in a sparse repo each candidate materializes the full tree — a
/// pre-existing checkout limitation, documented on `bisect run` in
/// `docs/CLI.md`.
fn checkout(cwd: &Path, target: &str) -> Result<(), u8> {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return Err(emit_err(
                &format!("cannot locate mkit binary: {e}"),
                exit::GENERAL_ERROR,
            ));
        }
    };
    let out = Command::new(exe)
        // `--force`: discard the test command's scribbles on tracked files
        // so the next candidate materializes cleanly (git bisect resets the
        // worktree between candidates).
        .args(["checkout", "--force", target])
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let mut stderr = std::io::stderr().lock();
            let _ = stderr.write_all(&o.stderr);
            Err(exit::GENERAL_ERROR)
        }
        Err(e) => Err(emit_err(
            &format!("checkout {target}: {e}"),
            exit::GENERAL_ERROR,
        )),
    }
}

fn report_step(store: &ObjectStore, state: &BisectState) -> u8 {
    match next_step(store, state) {
        Ok(BisectStep::NeedMore) => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "need at least one good and a bad commit to start searching"
            );
            exit::OK
        }
        Ok(BisectStep::Testing { hash, remaining }) => {
            // Progress prose to stderr; the candidate hash itself to
            // stdout so `H=$(mkit bisect good)` keeps working.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "bisect: testing ({remaining} candidates remaining)");
            drop(stderr);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", format::short_hash(&hash, 12));
            exit::OK
        }
        Ok(BisectStep::Found(h)) => {
            // The "found" result is genuinely a data point — emit the
            // hash on stdout and the prose on stderr.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "bisect found first bad commit:");
            drop(stderr);
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{}", format::short_hash(&h, 12));
            exit::OK
        }
        Ok(BisectStep::Ambiguous { bad, skipped }) => {
            report_ambiguous(bad, &skipped);
            exit::GENERAL_ERROR
        }
        Err(e) => emit_err(&format!("bisect: {e}"), exit::GENERAL_ERROR),
    }
}

/// Report an ambiguous result (only skipped commits remain), like git's
/// "The first bad commit could be any of …". The suspect hashes go to
/// stdout (data), the prose to stderr.
fn report_ambiguous(bad: Hash, skipped: &[Hash]) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "there are only skipped commits left to test; the first bad commit could be any of:"
    );
    drop(stderr);
    let mut stdout = std::io::stdout().lock();
    for h in skipped {
        let _ = writeln!(stdout, "{}", format::short_hash(h, 12));
    }
    // `bad` is the known-bad endpoint and also a suspect.
    let _ = writeln!(stdout, "{}", format::short_hash(&bad, 12));
}

use super::error as emit_err;

#[cfg(test)]
mod tests {
    use super::{Verdict, classify};

    #[test]
    fn classify_matches_git_bisect_run_contract() {
        // git's contract: 0=good, 125=skip, 1-127 (except 125)=bad,
        // >=128 or signal-killed (None) = abort.
        assert!(matches!(classify(Some(0)), Verdict::Good));
        assert!(matches!(classify(Some(125)), Verdict::Skip));
        assert!(matches!(classify(Some(1)), Verdict::Bad));
        assert!(matches!(classify(Some(124)), Verdict::Bad));
        assert!(matches!(classify(Some(126)), Verdict::Bad));
        assert!(matches!(classify(Some(127)), Verdict::Bad));
        assert!(matches!(classify(Some(128)), Verdict::Abort));
        assert!(matches!(classify(Some(255)), Verdict::Abort));
        // Signal-killed children report no code.
        assert!(matches!(classify(None), Verdict::Abort));
    }
}
