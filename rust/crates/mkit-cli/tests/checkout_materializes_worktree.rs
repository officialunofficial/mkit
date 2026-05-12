//! `mkit checkout` must rematerialise the branch tip's tree on disk,
//! not just flip HEAD. Integration test: commit files, delete them
//! from the worktree, run checkout, assert they reappear.

use std::fs;
use std::process::Command;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    // Each invocation gets an empty XDG_CONFIG_HOME so the developer's
    // real `~/.config/mkit/config` does not leak into tests (e.g. by
    // overriding `signing_key`).
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

#[test]
fn checkout_restores_files_that_were_removed_from_worktree() {
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    // we removed auto-keygen on commit.
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"alpha\n").unwrap();
    fs::write(td.path().join("b.txt"), b"bravo\n").unwrap();
    fs::create_dir_all(td.path().join("sub")).unwrap();
    fs::write(td.path().join("sub/c.txt"), b"charlie\n").unwrap();

    assert!(run_in(td.path(), &["add", "."]).status.success());
    let out = run_in(td.path(), &["commit", "-m", "initial"]);
    assert!(out.status.success(), "commit failed: {out:?}");

    // Nuke the worktree files (but keep .mkit/).
    fs::remove_file(td.path().join("a.txt")).unwrap();
    fs::remove_file(td.path().join("b.txt")).unwrap();
    fs::remove_dir_all(td.path().join("sub")).unwrap();
    assert!(!td.path().join("a.txt").exists());
    assert!(!td.path().join("sub/c.txt").exists());

    // Run checkout on the main branch and assert all three files are back.
    let out = run_in(td.path(), &["checkout", "main"]);
    assert!(out.status.success(), "checkout failed: {out:?}");
    assert_eq!(fs::read(td.path().join("a.txt")).unwrap(), b"alpha\n");
    assert_eq!(fs::read(td.path().join("b.txt")).unwrap(), b"bravo\n");
    assert_eq!(fs::read(td.path().join("sub/c.txt")).unwrap(), b"charlie\n");
}

#[test]
fn checkout_respects_mkitignore() {
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    // Commit a file we will later locally-ignore.
    fs::write(td.path().join("tracked.txt"), b"v1").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(run_in(td.path(), &["commit", "-m", "v1"]).status.success());

    // Now add a local-only file + an ignore rule that covers it, and
    // perform a checkout. The local file must survive.
    fs::write(td.path().join(".mkitignore"), "local.txt\n").unwrap();
    fs::write(td.path().join("local.txt"), b"untracked").unwrap();

    let out = run_in(td.path(), &["checkout", "main"]);
    assert!(out.status.success(), "checkout failed: {out:?}");
    assert_eq!(fs::read(td.path().join("local.txt")).unwrap(), b"untracked");
    assert_eq!(fs::read(td.path().join("tracked.txt")).unwrap(), b"v1");
}

fn head_commit(cwd: &std::path::Path) -> String {
    fs::read_to_string(cwd.join(".mkit/refs/heads/main"))
        .unwrap()
        .trim()
        .to_string()
}

fn tree_of_commit(cwd: &std::path::Path, commit: &str) -> String {
    let out = run_in(cwd, &["cat", commit]);
    assert!(out.status.success(), "cat commit failed: {out:?}");
    let body = String::from_utf8(out.stdout).unwrap();
    body.lines()
        .find_map(|line| line.strip_prefix("tree "))
        .expect("commit has tree")
        .trim()
        .to_string()
}

#[test]
fn checkout_resets_index_to_checked_out_tree() {
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("main.txt"), b"main").unwrap();
    assert!(run_in(td.path(), &["add", "main.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "main"])
            .status
            .success()
    );

    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("feature.txt"), b"feature").unwrap();
    assert!(run_in(td.path(), &["add", "feature.txt"]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "feature"])
            .status
            .success()
    );

    assert!(run_in(td.path(), &["checkout", "main"]).status.success());
    assert!(!td.path().join("feature.txt").exists());

    // Default-mode prose lives on stderr; use --porcelain for the
    // machine-readable contract. Empty stdout means clean.
    let status = run_in(td.path(), &["status", "--porcelain"]);
    assert!(status.status.success());
    let stdout = String::from_utf8(status.stdout).unwrap();
    assert!(
        stdout.is_empty(),
        "checkout should leave index aligned with main: {stdout:?}"
    );

    assert!(
        run_in(td.path(), &["commit", "-m", "after checkout"])
            .status
            .success()
    );
    let commit = head_commit(td.path());
    let tree = tree_of_commit(td.path(), &commit);
    let cat = run_in(td.path(), &["cat", &tree]);
    assert!(cat.status.success());
    let body = String::from_utf8(cat.stdout).unwrap();
    assert!(body.contains("main.txt"));
    assert!(
        !body.contains("feature.txt"),
        "stale feature index leaked into main commit: {body}"
    );
}
