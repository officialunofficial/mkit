//! `mkit log` / `mkit diff` revision arguments and ranges (#249, #252) — the
//! mkit-specific paths the differential harness can't compare deterministically
//! (empty/reverse ranges, range + `-n`, and the `A...B` symmetric range for
//! both `log` and `diff`).
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

/// A branched repo: base `c1`, then `c2` on `main` and `c3` on `feat`
/// (common ancestor `c1`). Leaves `HEAD` on `feat` (= c3).
fn branched_repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    fs::write(root.join("a.txt"), b"base\n").unwrap();
    assert!(run_in(root, x, &["add", "a.txt"]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "c1"]).status.success());
    assert!(run_in(root, x, &["branch", "feat"]).status.success());
    // c2 on main.
    fs::write(root.join("m.txt"), b"m\n").unwrap();
    assert!(run_in(root, x, &["add", "m.txt"]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "c2"]).status.success());
    // c3 on feat.
    assert!(run_in(root, x, &["checkout", "feat"]).status.success());
    fs::write(root.join("f.txt"), b"f\n").unwrap();
    assert!(run_in(root, x, &["add", "f.txt"]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "c3"]).status.success());
    (td, xdg)
}

#[test]
fn log_symmetric_range_shows_both_sides() {
    let (td, xdg) = branched_repo();
    let (root, x) = (td.path(), xdg.path());
    // `main...HEAD` = reachable from main OR feat, but not the common
    // ancestor c1 → {c2, c3} (order may vary, so compare as a set).
    let mut sym = subjects(root, x, &["main...HEAD"]);
    sym.sort();
    assert_eq!(sym, ["c2", "c3"], "symmetric range");
    // The asymmetric `main..HEAD` excludes everything reachable from main
    // (c2 and the shared c1) → only c3.
    assert_eq!(
        subjects(root, x, &["main..HEAD"]),
        ["c3"],
        "asymmetric range"
    );
    // Empty left side: `...HEAD` = `HEAD...HEAD` → empty.
    assert!(
        subjects(root, x, &["...HEAD"]).iter().all(String::is_empty),
        "HEAD...HEAD is empty"
    );
}

#[test]
fn diff_symmetric_range_is_merge_base_vs_b() {
    let (td, xdg) = branched_repo();
    let (root, x) = (td.path(), xdg.path());
    // `diff main...HEAD` = diff merge-base(main, feat)=c1 against feat=c3,
    // so it shows f.txt added and does NOT show m.txt (which is on main).
    let out = run_in(root, x, &["diff", "main...HEAD"]);
    assert!(out.status.success(), "diff failed: {out:?}");
    let s = out_str(&out);
    assert!(
        s.contains("diff --git a/f.txt b/f.txt"),
        "f.txt added: {s:?}"
    );
    assert!(s.contains("new file mode"), "new file header: {s:?}");
    assert!(!s.contains("m.txt"), "m.txt must not appear: {s:?}");
}

#[test]
fn diff_symmetric_range_peels_annotated_tag() {
    // An annotated tag on the `A...B` side must be peeled to its commit
    // before merge-base resolution — otherwise the tag object errors / has
    // no merge base.
    let (td, xdg) = branched_repo();
    let (root, x) = (td.path(), xdg.path());
    // Tag `main` (= c2) annotated; HEAD is feat (= c3).
    assert!(
        run_in(root, x, &["tag", "-a", "v1", "main", "-m", "tag main"])
            .status
            .success()
    );
    let out = run_in(root, x, &["diff", "v1...HEAD"]);
    assert!(
        out.status.success(),
        "tagged symmetric diff failed: {out:?}"
    );
    let s = out_str(&out);
    // merge-base(c2, c3) = c1, diff c1 vs c3 → f.txt added.
    assert!(
        s.contains("diff --git a/f.txt b/f.txt"),
        "f.txt added: {s:?}"
    );
}

#[test]
fn log_peels_annotated_tag_on_include_and_exclude() {
    // An annotated/signed tag must be peeled to its commit for both the
    // include side (`log <tag>`) and the exclude side (`<tag>..HEAD`), like
    // git — otherwise the tag object is rejected / excludes nothing.
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["init"]).status.success());
    assert!(run_in(root, x, &["keygen"]).status.success());
    fs::write(root.join("a.txt"), b"1\n").unwrap();
    assert!(run_in(root, x, &["add", "a.txt"]).status.success());
    assert!(run_in(root, x, &["commit", "-m", "c1"]).status.success());
    // Annotated tag at c1 (HEAD), then two more commits.
    assert!(
        run_in(root, x, &["tag", "-a", "v1", "-m", "tag c1"])
            .status
            .success()
    );
    for (f, m) in [("b.txt", "c2"), ("c.txt", "c3")] {
        fs::write(root.join(f), b"x\n").unwrap();
        assert!(run_in(root, x, &["add", f]).status.success());
        assert!(run_in(root, x, &["commit", "-m", m]).status.success());
    }
    // include side: `log v1` peels to c1 and walks its ancestors (just c1).
    assert_eq!(subjects(root, x, &["v1"]), ["c1"]);
    // exclude side: `v1..HEAD` excludes c1 and its ancestors → c3, c2.
    assert_eq!(subjects(root, x, &["v1..HEAD"]), ["c3", "c2"]);
}

#[test]
fn log_bad_revision_errors() {
    let (td, xdg) = repo_with_four();
    let out = run_in(td.path(), xdg.path(), &["log", "no-such-ref"]);
    assert!(!out.status.success(), "bad rev must error: {out:?}");
}
