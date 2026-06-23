//! Exact rename detection, driven end-to-end through the binary.
//!
//! mkit is content-addressed, so a `mkit mv` (which stages the source as a
//! deletion and the destination with the same blob) is detected as an
//! exact rename: identical object id at two paths. `status` and `diff`
//! then render it git-shaped (`R`, `rename from`/`rename to`,
//! `similarity index 100%`), on by default, with `--no-renames` to opt out.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

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

/// Repo with a key and one commit containing the named files.
fn repo(files: &[(&str, &[u8])]) -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    for (name, content) in files {
        let p = root.join(name);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, content).unwrap();
    }
    assert!(run_in(root, x, &["add", "."]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "init"]).status.success());
    (td, xdg)
}

/// A repo with `a.txt` committed, then `mkit mv a.txt b.txt` staged.
fn renamed() -> (tempfile::TempDir, tempfile::TempDir) {
    let (td, xdg) = repo(&[("a.txt", b"hello world\nsecond line\n")]);
    assert!(
        run_in(td.path(), xdg.path(), &["mv", "a.txt", "b.txt"])
            .status
            .success()
    );
    (td, xdg)
}

#[test]
fn status_porcelain_v1_shows_rename() {
    let (td, x) = renamed();
    let out = run_in(td.path(), x.path(), &["status", "--porcelain"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert_eq!(s.trim_end(), "R  a.txt -> b.txt", "got: {s:?}");
}

#[test]
fn status_human_shows_renamed_old_to_new() {
    let (td, x) = renamed();
    let out = run_in(td.path(), x.path(), &["status"]);
    // Human output goes to stderr.
    let s = String::from_utf8_lossy(&out.stderr);
    assert!(
        s.contains("renamed:") && s.contains("a.txt -> b.txt"),
        "got: {s}"
    );
}

#[test]
fn status_porcelain_v2_emits_rename_record() {
    let (td, x) = renamed();
    let out = run_in(td.path(), x.path(), &["status", "--porcelain=v2"]);
    let s = String::from_utf8_lossy(&out.stdout);
    // `2 R. N... <mH> <mI> <mW> <hH> <hI> R100 <new>\t<old>`. Exact content
    // → hH == hI and a 100% score; the destination precedes the source.
    assert!(s.starts_with("2 R. N... "), "wrong record kind: {s:?}");
    assert!(s.contains(" R100 b.txt\ta.txt"), "wrong rename tail: {s:?}");
}

#[test]
fn status_porcelain_z_orders_new_then_old() {
    let (td, x) = renamed();
    let out = run_in(td.path(), x.path(), &["status", "--porcelain", "-z"]);
    // git's `-z` rename: `R  <new>\0<old>\0` (destination first).
    assert_eq!(out.stdout, b"R  b.txt\0a.txt\0", "got: {:?}", out.stdout);
}

#[test]
fn diff_cached_emits_rename_headers() {
    let (td, x) = renamed();
    let out = run_in(td.path(), x.path(), &["diff", "--cached"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("diff --git a/a.txt b/b.txt"), "header: {s}");
    assert!(s.contains("similarity index 100%"), "similarity: {s}");
    assert!(s.contains("rename from a.txt"), "from: {s}");
    assert!(s.contains("rename to b.txt"), "to: {s}");
    // An exact rename carries no hunk body.
    assert!(!s.contains("@@"), "exact rename must have no hunk: {s}");
}

#[test]
fn diff_cached_name_status_is_score_old_new() {
    let (td, x) = renamed();
    let out = run_in(td.path(), x.path(), &["diff", "--cached", "--name-status"]);
    let s = String::from_utf8_lossy(&out.stdout);
    // name-status orders source before destination (unlike porcelain -z).
    assert_eq!(s.trim_end(), "R100\ta.txt\tb.txt", "got: {s:?}");
}

#[test]
fn no_renames_flag_falls_back_to_delete_add() {
    let (td, x) = renamed();
    let out = run_in(
        td.path(),
        x.path(),
        &["status", "--porcelain", "--no-renames"],
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("D  a.txt"), "expected delete: {s}");
    assert!(s.contains("A  b.txt"), "expected add: {s}");
    assert!(!s.contains("->"), "must not pair into a rename: {s}");
}

#[test]
fn unrelated_delete_and_add_is_not_a_rename() {
    // Different content at the two paths → not a rename: a plain D + A.
    let (td, xdg) = repo(&[("a.txt", b"alpha\n")]);
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["rm", "a.txt"]).status.success());
    fs::write(root.join("c.txt"), b"totally different\n").unwrap();
    assert!(run_in(root, x, &["add", "c.txt"]).status.success());
    let out = run_in(root, x, &["status", "--porcelain"]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("D  a.txt") && s.contains("A  c.txt"), "got: {s}");
    assert!(!s.contains("->"), "distinct content is not a rename: {s}");
}
