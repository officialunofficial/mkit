//! `mkit log` revision arguments and ranges (#249 Phase 1) — the
//! mkit-specific paths the differential harness can't compare (the `A...B`
//! rejection, empty/reverse ranges, range + `-n`).

use std::fs;
use std::path::Path;
use std::process::Output;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn out_str(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// A repo with four commits c1..c4, each adding one file. Returns the dirs.
fn repo_with_four() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    for (f, m) in [
        ("a.txt", "c1"),
        ("b.txt", "c2"),
        ("c.txt", "c3"),
        ("d.txt", "c4"),
    ] {
        fs::write(root.join(f), b"x\n").unwrap();
        assert!(run_in(root, x, &["add", f]).status.success());
        assert!(run_in(root, x, &["commit", "-m", m]).status.success());
    }
    (td, xdg)
}

/// The `--oneline` subjects (titles), newest-first.
fn subjects(root: &Path, x: &Path, args: &[&str]) -> Vec<String> {
    let mut full = vec!["log", "--oneline"];
    full.extend_from_slice(args);
    out_str(&run_in(root, x, &full))
        .lines()
        .map(|l| {
            l.split_once(' ')
                .map_or(String::new(), |(_, t)| t.to_string())
        })
        .collect()
}

#[test]
fn log_default_shows_all_newest_first() {
    let (td, xdg) = repo_with_four();
    assert_eq!(
        subjects(td.path(), xdg.path(), &[]),
        ["c4", "c3", "c2", "c1"]
    );
}

#[test]
fn log_single_rev_starts_there() {
    let (td, xdg) = repo_with_four();
    // `log HEAD~1` shows HEAD~1 and its ancestors (c3, c2, c1).
    assert_eq!(
        subjects(td.path(), xdg.path(), &["HEAD~1"]),
        ["c3", "c2", "c1"]
    );
}

#[test]
fn log_range_excludes_left_side() {
    let (td, xdg) = repo_with_four();
    // `A..B` = reachable from B, not from A. HEAD~3 is c1.
    assert_eq!(
        subjects(td.path(), xdg.path(), &["HEAD~3..HEAD"]),
        ["c4", "c3", "c2"]
    );
    // Open-ended `A..` means `A..HEAD`.
    assert_eq!(subjects(td.path(), xdg.path(), &["HEAD~2.."]), ["c4", "c3"]);
    // Open-ended `..B` means `HEAD..B`; HEAD..HEAD is empty.
    assert!(
        subjects(td.path(), xdg.path(), &["..HEAD"])
            .iter()
            .all(String::is_empty)
    );
}

#[test]
fn log_reverse_range_is_empty() {
    let (td, xdg) = repo_with_four();
    // `HEAD..HEAD~2` excludes everything reachable from HEAD → empty.
    let out = run_in(td.path(), xdg.path(), &["log", "--oneline", "HEAD..HEAD~2"]);
    assert!(out.status.success());
    assert!(
        out_str(&out).is_empty(),
        "reverse range must be empty: {out:?}"
    );
}

#[test]
fn log_range_with_limit() {
    let (td, xdg) = repo_with_four();
    // Range c1..c4 = [c4,c3,c2]; `-n 2` caps to the two newest.
    assert_eq!(
        subjects(td.path(), xdg.path(), &["-n", "2", "HEAD~3..HEAD"]),
        ["c4", "c3"]
    );
}

#[test]
fn log_symmetric_range_is_rejected() {
    let (td, xdg) = repo_with_four();
    let out = run_in(td.path(), xdg.path(), &["log", "HEAD~2...HEAD"]);
    assert!(
        !out.status.success(),
        "A...B symmetric range is not supported yet: {out:?}"
    );
}

#[test]
fn log_bad_revision_errors() {
    let (td, xdg) = repo_with_four();
    let out = run_in(td.path(), xdg.path(), &["log", "no-such-ref"]);
    assert!(!out.status.success(), "bad rev must error: {out:?}");
}
