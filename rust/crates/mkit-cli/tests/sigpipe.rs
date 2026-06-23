//! `mkit cat <large-blob> | head -1` must NOT be killed by SIGPIPE.
//!
//! ## What this actually guards
//!
//! Rust's runtime sets `SIGPIPE` to `SIG_IGN` at process start, so
//! today this test is green for free — `write(2)` on a closed pipe
//! returns `EPIPE` instead of terminating the process, and mkit's
//! `let _ = writeln!(stdout, …)` discipline absorbs that silently.
//! The test does not exercise `signal::install()` directly (see the
//! module docs there for why we deliberately don't register over
//! Rust's default).
//!
//! It is still load-bearing as a regression guard. Two ways the
//! pipeline-friendliness in `docs/CLI.md` §Signals could break:
//!
//! 1. Someone adds `#[unix_sigpipe = "sig_dfl"]` to `main`, opting
//!    mkit out of Rust's default. SIGPIPE then terminates the process
//!    with signal 13 and the test fails with exit 141.
//! 2. Someone replaces a write-loop with one that does its own
//!    `panic!()` on `BrokenPipe` instead of dropping the error.
//!
//! ## Provoking a deterministic SIGPIPE event
//!
//! `mkit log` against a small repo emits only a few hundred bytes —
//! those fit entirely in the pipe buffer in a single syscall, so
//! `head -1` reads the first line *after* mkit has already finished
//! writing. To force the issue we store a 256 KiB blob (well past
//! macOS's 16 KiB default pipe-buffer ceiling) and stream it back
//! through `mkit cat`, which calls `write_all` in a loop. The first
//! batch of writes fills the buffer, `head -1` reads `"x\n"` and
//! closes, and mkit's next write hits the closed pipe.
//!
//! Unix-only. Windows has no SIGPIPE; the CLI does not ship on Windows.

#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

/// Create a repo and store a 256 KiB blob built from `"x\n"` repeats.
/// Returns `(tempdir, hex-hash-of-blob)`. The blob is line-oriented
/// so `head -1` reads exactly 2 bytes and exits — leaving the rest
/// of the buffer's worth of content unread, which is what we need
/// to provoke SIGPIPE on the writer side.
fn repo_with_large_blob() -> (tempfile::TempDir, String) {
    let td = tempfile::tempdir().unwrap();
    let repo = td.path();
    assert!(run_in(repo, &["init"]).status.success(), "init");

    let payload: Vec<u8> = "x\n".repeat(128 * 1024).into_bytes(); // 256 KiB
    fs::write(repo.join("big.txt"), &payload).unwrap();

    let out = run_in(repo, &["hash", "big.txt"]);
    assert!(out.status.success(), "hash failed: {out:?}");
    let hex = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert_eq!(hex.len(), 64, "expected 64 hex chars, got {hex:?}");
    (td, hex)
}

#[test]
fn cat_piped_into_head_one_exits_cleanly() {
    let (td, hash) = repo_with_large_blob();
    let xdg = tempfile::tempdir().unwrap();

    // `bash -o pipefail` propagates the *left-hand* exit code if it
    // is non-zero, even though `head -1` succeeds. If anyone breaks
    // the pipeline contract (by opting out of Rust's SIGPIPE→SIG_IGN
    // default, or by panicking on BrokenPipe instead of dropping the
    // error), mkit dies with signal 13 → shell-visible exit 141 →
    // pipefail surfaces 141. In the working state, the post-pipe-close
    // write returns EPIPE (silently dropped by `let _ = stdout.write_all(…)`
    // in commands/cat.rs), the function returns OK, and the pipeline
    // exits 0.
    let status = Command::new("bash")
        .arg("-o")
        .arg("pipefail")
        .arg("-c")
        .arg(format!(
            r#""{}" cat {} | head -1 > /dev/null"#,
            mkit_bin(),
            hash
        ))
        .current_dir(td.path())
        .env("XDG_CONFIG_HOME", xdg.path())
        .status()
        .expect("spawn bash pipeline");

    assert!(
        status.success(),
        "`mkit cat <hash> | head -1` exited non-zero ({status:?}); \
         most likely killed by SIGPIPE — check for a recently-added \
         `#[unix_sigpipe = \"sig_dfl\"]` attribute on `main`, or a \
         write-loop that panics on BrokenPipe instead of dropping the \
         error. See signal.rs module docs."
    );
}
