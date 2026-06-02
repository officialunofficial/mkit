//! Integration tests for PR5 local-command Git parity (#188):
//! `rm` worktree removal + `--cached`/`-r`/`-f` + dirty/untracked
//! guards, `diff` unified hunks + `--staged` + pathspecs, and
//! `add -A`/`-u`/multi-pathspec. Spawns the real binary.

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

/// Init a repo with a keypair and an initial commit of `files`.
fn init_with_commit(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    for (name, content) in files {
        let full = td.path().join(name);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&full, content).unwrap();
    }
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "initial"])
            .status
            .success(),
        "commit failed"
    );
    td
}

fn porcelain(cwd: &std::path::Path) -> String {
    let out = run_in(cwd, &["status", "--porcelain"]);
    assert!(out.status.success(), "status failed: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

// =====================================================================
// rm
// =====================================================================

#[test]
fn rm_removes_worktree_file_and_stages_deletion() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    let out = run_in(td.path(), &["rm", "a.txt"]);
    assert!(out.status.success(), "rm failed: {out:?}");
    assert!(
        !td.path().join("a.txt").exists(),
        "rm should delete the worktree file"
    );
    // Deletion is staged.
    let p = porcelain(td.path());
    assert!(
        p.lines().any(|l| l == "D  a.txt"),
        "expected staged deletion `D `, got: {p:?}"
    );
}

#[test]
fn rm_cached_keeps_worktree_file() {
    let td = init_with_commit(&[("a.txt", b"hello")]);
    let out = run_in(td.path(), &["rm", "--cached", "a.txt"]);
    assert!(out.status.success(), "rm --cached failed: {out:?}");
    assert!(
        td.path().join("a.txt").exists(),
        "rm --cached must keep the worktree file"
    );
}

#[test]
fn rm_cached_keeps_dirty_worktree_file_untouched() {
    // --cached skips the dirty guard (it never touches the worktree),
    // but it must NOT modify or delete the locally-modified file.
    let td = init_with_commit(&[("a.txt", b"clean")]);
    fs::write(td.path().join("a.txt"), b"locally modified").unwrap();
    let out = run_in(td.path(), &["rm", "--cached", "a.txt"]);
    assert!(out.status.success(), "rm --cached failed: {out:?}");
    assert!(
        td.path().join("a.txt").exists(),
        "rm --cached must keep the dirty worktree file"
    );
    assert_eq!(
        fs::read(td.path().join("a.txt")).unwrap(),
        b"locally modified",
        "rm --cached must not alter the worktree file's content"
    );
}

#[test]
fn rm_refuses_dirty_file_without_force() {
    let td = init_with_commit(&[("a.txt", b"clean")]);
    fs::write(td.path().join("a.txt"), b"locally modified").unwrap();
    let out = run_in(td.path(), &["rm", "a.txt"]);
    assert!(
        !out.status.success(),
        "rm of a modified file must fail without --force"
    );
    assert!(
        td.path().join("a.txt").exists(),
        "dirty file must NOT be destroyed without --force"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("local modifications"),
        "expected dirty-guard message, got: {stderr}"
    );
}

#[test]
fn rm_force_discards_dirty_file() {
    let td = init_with_commit(&[("a.txt", b"clean")]);
    fs::write(td.path().join("a.txt"), b"locally modified").unwrap();
    let out = run_in(td.path(), &["rm", "--force", "a.txt"]);
    assert!(out.status.success(), "rm --force failed: {out:?}");
    assert!(
        !td.path().join("a.txt").exists(),
        "rm --force should delete the modified file"
    );
}

#[test]
fn rm_directory_requires_recursive() {
    let td = init_with_commit(&[("dir/x.txt", b"x"), ("dir/y.txt", b"y")]);
    let out = run_in(td.path(), &["rm", "dir"]);
    assert!(
        !out.status.success(),
        "removing a directory without -r must fail"
    );
    assert!(td.path().join("dir/x.txt").exists());
}

#[test]
fn rm_recursive_removes_directory_tree() {
    let td = init_with_commit(&[("dir/x.txt", b"x"), ("dir/y.txt", b"y"), ("keep.txt", b"k")]);
    let out = run_in(td.path(), &["rm", "-r", "dir"]);
    assert!(out.status.success(), "rm -r failed: {out:?}");
    assert!(!td.path().join("dir/x.txt").exists());
    assert!(!td.path().join("dir/y.txt").exists());
    // Empty parent dir pruned.
    assert!(
        !td.path().join("dir").exists(),
        "empty dir should be pruned"
    );
    // Unrelated file untouched.
    assert!(td.path().join("keep.txt").exists());
}

#[test]
fn rm_multiple_pathspecs() {
    let td = init_with_commit(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let out = run_in(td.path(), &["rm", "a.txt", "b.txt"]);
    assert!(out.status.success(), "multi rm failed: {out:?}");
    assert!(!td.path().join("a.txt").exists());
    assert!(!td.path().join("b.txt").exists());
    assert!(td.path().join("c.txt").exists());
}

#[test]
fn rm_unmatched_pathspec_errors() {
    let td = init_with_commit(&[("a.txt", b"a")]);
    let out = run_in(td.path(), &["rm", "nope.txt"]);
    assert!(!out.status.success(), "rm of untracked path should error");
    assert!(td.path().join("a.txt").exists());
}

// =====================================================================
// diff
// =====================================================================

#[test]
fn diff_emits_unified_hunks_for_modified_file() {
    let td = init_with_commit(&[("f.txt", b"line1\nline2\nline3\n")]);
    fs::write(td.path().join("f.txt"), b"line1\nCHANGED\nline3\n").unwrap();
    let out = run_in(td.path(), &["diff"]);
    assert!(out.status.success(), "diff failed: {out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("diff --mkit a/f.txt b/f.txt"), "{stdout}");
    assert!(stdout.contains("@@ "), "expected a hunk header: {stdout}");
    assert!(stdout.contains("-line2"), "{stdout}");
    assert!(stdout.contains("+CHANGED"), "{stdout}");
}

#[test]
fn diff_staged_shows_index_vs_head() {
    let td = init_with_commit(&[("f.txt", b"original\n")]);
    fs::write(td.path().join("f.txt"), b"staged change\n").unwrap();
    assert!(run_in(td.path(), &["add", "f.txt"]).status.success());
    // After staging, --staged shows HEAD->index, and since the worktree
    // matches the index there is no unstaged delta beyond it. Revert the
    // worktree to HEAD so plain diff (HEAD vs worktree) is empty while
    // --staged (HEAD vs index) still reports the staged change.
    fs::write(td.path().join("f.txt"), b"original\n").unwrap();
    let plain = run_in(td.path(), &["diff"]);
    let plain_out = String::from_utf8(plain.stdout).unwrap();
    assert!(
        plain_out.trim().is_empty(),
        "plain diff should be empty after reverting worktree, got: {plain_out}"
    );
    let staged = run_in(td.path(), &["diff", "--staged"]);
    assert!(staged.status.success());
    let staged_out = String::from_utf8(staged.stdout).unwrap();
    assert!(
        staged_out.contains("+staged change"),
        "--staged should show the staged delta: {staged_out}"
    );
}

#[test]
fn diff_pathspec_filters_output() {
    let td = init_with_commit(&[("a.txt", b"a\n"), ("b.txt", b"b\n")]);
    fs::write(td.path().join("a.txt"), b"a-changed\n").unwrap();
    fs::write(td.path().join("b.txt"), b"b-changed\n").unwrap();
    let out = run_in(td.path(), &["diff", "a.txt"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("a/a.txt"), "{stdout}");
    assert!(
        !stdout.contains("b.txt"),
        "pathspec must exclude b.txt: {stdout}"
    );
}

#[test]
fn diff_binary_reports_differ() {
    let td = init_with_commit(&[("bin", &[0x00, 0x01, 0xff])]);
    fs::write(td.path().join("bin"), [0x00, 0x02, 0xfe]).unwrap();
    let out = run_in(td.path(), &["diff"]);
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("Binary files a/bin and b/bin differ"),
        "{stdout}"
    );
}

// =====================================================================
// add
// =====================================================================

#[test]
fn add_all_stages_new_and_deleted() {
    let td = init_with_commit(&[("a.txt", b"a"), ("b.txt", b"b")]);
    // New file + delete a tracked one.
    fs::write(td.path().join("c.txt"), b"c").unwrap();
    fs::remove_file(td.path().join("b.txt")).unwrap();
    let out = run_in(td.path(), &["add", "-A"]);
    assert!(out.status.success(), "add -A failed: {out:?}");
    let p = porcelain(td.path());
    assert!(
        p.lines().any(|l| l == "A  c.txt"),
        "c.txt should be staged-added: {p}"
    );
    assert!(
        p.lines().any(|l| l == "D  b.txt"),
        "b.txt deletion should be staged: {p}"
    );
}

#[test]
fn add_update_stages_only_tracked() {
    let td = init_with_commit(&[("a.txt", b"a")]);
    // Modify tracked a.txt and create untracked u.txt.
    fs::write(td.path().join("a.txt"), b"a-modified").unwrap();
    fs::write(td.path().join("u.txt"), b"untracked").unwrap();
    let out = run_in(td.path(), &["add", "-u"]);
    assert!(out.status.success(), "add -u failed: {out:?}");
    let p = porcelain(td.path());
    assert!(
        p.lines().any(|l| l == "M  a.txt"),
        "a.txt mod should be staged: {p}"
    );
    // u.txt must remain untracked (not staged).
    assert!(
        p.lines().any(|l| l == "?? u.txt"),
        "u.txt must remain untracked under -u: {p}"
    );
}

#[test]
fn add_multiple_pathspecs() {
    let td = init_with_commit(&[("seed.txt", b"seed")]);
    fs::write(td.path().join("a.txt"), b"a").unwrap();
    fs::write(td.path().join("b.txt"), b"b").unwrap();
    fs::write(td.path().join("c.txt"), b"c").unwrap();
    let out = run_in(td.path(), &["add", "a.txt", "b.txt"]);
    assert!(out.status.success(), "multi add failed: {out:?}");
    let p = porcelain(td.path());
    assert!(p.lines().any(|l| l == "A  a.txt"), "{p}");
    assert!(p.lines().any(|l| l == "A  b.txt"), "{p}");
    // c.txt not added.
    assert!(p.lines().any(|l| l == "?? c.txt"), "{p}");
}

#[test]
fn add_rejects_all_with_paths() {
    let td = init_with_commit(&[("a.txt", b"a")]);
    let out = run_in(td.path(), &["add", "-A", "a.txt"]);
    assert!(!out.status.success(), "-A with a path must error");
}

#[test]
fn add_rejects_update_with_paths() {
    let td = init_with_commit(&[("a.txt", b"a")]);
    let out = run_in(td.path(), &["add", "-u", "a.txt"]);
    assert!(!out.status.success(), "-u with a path must error");
}

#[test]
fn add_rejects_all_and_update_together() {
    let td = init_with_commit(&[("a.txt", b"a")]);
    let out = run_in(td.path(), &["add", "-A", "-u"]);
    assert!(!out.status.success(), "-A and -u together must error");
}
