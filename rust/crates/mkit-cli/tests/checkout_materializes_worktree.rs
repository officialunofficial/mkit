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
