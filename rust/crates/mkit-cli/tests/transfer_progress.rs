//! Honest transfer-progress reporting for `clone`/`push`/`pull`/`fetch`
//! (#711).
//!
//! Driven end-to-end through the real binary against a `mkit+file://`
//! bare-directory remote, mirroring `push_named_remote.rs`'s pattern.
//! `MKIT_PROGRESS=always` forces progress on despite the subprocess's
//! piped (non-tty) stderr — see `crate::progress`'s override
//! convention (mirrors `NO_COLOR`/`CLICOLOR_FORCE`). The default (no
//! override) is exercised by the suppression test below: a piped
//! stderr with no override must show no progress lines at all.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    run_in_with_env(cwd, args, &[])
}

fn run_in_with_env(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let mut cmd = Command::new(mkit_bin());
    cmd.args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn mkit");
    drop(xdg);
    out
}

fn file_url(dir: &Path) -> String {
    format!("mkit+file://{}", dir.display())
}

/// Init a repo with a signing key and a single commit containing `n`
/// distinct small files — enough objects (n blobs + n path-component
/// trees + 1 commit) to cross the progress reporter's throttling
/// interval (`progress::REPORT_INTERVAL`, currently 8) several times
/// over in one push.
fn repo_with_many_files(n: usize) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    for i in 0..n {
        fs::write(td.path().join(format!("f{i}.txt")), format!("file {i}")).unwrap();
    }
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "many files"])
            .status
            .success()
    );
    td
}

/// Push, forcing progress on via `MKIT_PROGRESS=always` (the
/// subprocess's stderr is piped, not a tty, so without the override
/// the reporter would auto-disable): must print multiple `Writing
/// objects:` lines with monotonically increasing, real object counts,
/// ending in a `, done.` line — never git's fabricated
/// Enumerating/Counting/Compressing/delta lines.
#[test]
fn push_reports_honest_monotonic_progress_when_forced_on() {
    let td = repo_with_many_files(40);
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    let out = run_in_with_env(
        td.path(),
        &["push", "origin"],
        &[("MKIT_PROGRESS", "always")],
    );
    assert!(out.status.success(), "push failed: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();

    let counts = extract_counts(&stderr, "Writing objects");
    assert!(
        counts.len() >= 2,
        "expected multiple progress updates crossing the report threshold, got stderr: {stderr}"
    );
    assert!(
        counts.windows(2).all(|w| w[0] <= w[1]),
        "counts must be monotonically non-decreasing: {counts:?} (stderr: {stderr})"
    );
    assert!(
        *counts.last().unwrap() > 0,
        "final count must reflect real objects sent: {counts:?}"
    );
    assert!(
        stderr.contains("done."),
        "expected a final ', done.' line: {stderr}"
    );
    // Never fabricate git's compression/delta-graph numbers — mkit's
    // transport is one-object-per-pack and computes no cross-branch
    // delta graph (docs/PARITY.md's "Human-facing output parity").
    assert!(!stderr.contains("Compressing objects"), "stderr: {stderr}");
    assert!(!stderr.contains("Enumerating objects"), "stderr: {stderr}");
    assert!(!stderr.contains("Total "), "stderr: {stderr}");
}

/// Without an explicit override, a non-tty stderr (the default for a
/// piped subprocess, as in every test here) must show NO progress
/// lines — exercising `should_report`'s tty auto-detection, not
/// `--quiet`.
#[test]
fn push_suppresses_progress_by_default_on_non_tty_stderr() {
    let td = repo_with_many_files(40);
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    let out = run_in(td.path(), &["push", "origin"]);
    assert!(out.status.success(), "push failed: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("Writing objects"),
        "progress must be suppressed on non-tty stderr by default: {stderr}"
    );
    // The ordinary git-shaped summary must still print.
    assert!(stderr.contains("To "), "stderr: {stderr}");
}

/// `--quiet` suppresses progress even when `MKIT_PROGRESS=always` would
/// otherwise force it on — the explicit flag wins.
#[test]
fn push_quiet_flag_wins_over_forced_progress() {
    let td = repo_with_many_files(10);
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    let out = run_in_with_env(
        td.path(),
        &["push", "origin", "--quiet"],
        &[("MKIT_PROGRESS", "always")],
    );
    assert!(out.status.success(), "push failed: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("Writing objects"),
        "--quiet must suppress progress even under MKIT_PROGRESS=always: {stderr}"
    );
}

/// Fetch/pull side: push several small commits separately (building a
/// multi-node packmap chain), then a fresh `clone` must unpack each
/// chain pack in turn and report real, monotonically increasing
/// `Unpacking objects:` counts across the packs it applies.
#[test]
fn clone_reports_honest_monotonic_progress_across_chain_packs_when_forced_on() {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    let remote = tempfile::tempdir().unwrap();
    let url = file_url(remote.path());
    assert!(
        run_in(td.path(), &["remote", "add", "origin", &url])
            .status
            .success()
    );

    // Several separate pushes chain multiple packmap nodes, so the
    // subsequent clone below applies more than one pack and reports
    // more than one real `ObjectsUnpacked` event.
    for i in 0..5 {
        fs::write(td.path().join(format!("g{i}.txt")), format!("gen {i}")).unwrap();
        assert!(run_in(td.path(), &["add", "."]).status.success());
        assert!(
            run_in(td.path(), &["commit", "-m", &format!("gen {i}")])
                .status
                .success()
        );
        assert!(
            run_in(td.path(), &["push", "origin"]).status.success(),
            "push gen {i}"
        );
    }

    let dst = tempfile::tempdir().unwrap();
    let clone_dir = dst.path().join("clone");
    let out = run_in_with_env(
        dst.path(),
        &["clone", &url, clone_dir.to_str().unwrap()],
        &[("MKIT_PROGRESS", "always")],
    );
    assert!(out.status.success(), "clone failed: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();

    let counts = extract_counts(&stderr, "Unpacking objects");
    assert!(
        counts.len() >= 2,
        "expected progress across multiple chain packs, got stderr: {stderr}"
    );
    assert!(
        counts.windows(2).all(|w| w[0] <= w[1]),
        "counts must be monotonically non-decreasing: {counts:?} (stderr: {stderr})"
    );
}

/// Parse every `"<label>: N ..."` occurrence out of a progress stream,
/// in order, returning just the `N` values. Progress lines
/// self-overwrite with `\r`, so this splits on `\r` as well as `\n`.
fn extract_counts(stderr: &str, label: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for line in stderr.split(['\r', '\n']) {
        let Some(rest) = line.strip_prefix(label) else {
            continue;
        };
        let rest = rest.trim_start_matches(':').trim_start();
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(n) = digits.parse::<u64>() {
            out.push(n);
        }
    }
    out
}
