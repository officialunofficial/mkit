//! `mkit checkout` must protect dirty work before rematerialising a
//! branch tip's tree on disk.

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
fn checkout_refuses_removed_tracked_files() {
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

    // Checkout must not silently recreate tracked paths the user removed.
    let out = run_in(td.path(), &["checkout", "main"]);
    assert!(!out.status.success(), "dirty checkout should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("restore would overwrite local changes"),
        "stderr should explain dirty worktree refusal: {stderr}"
    );
    assert!(!td.path().join("a.txt").exists());
    assert!(!td.path().join("sub/c.txt").exists());
}

#[test]
fn checkout_refuses_dirty_tracked_file() {
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"v1\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "main"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("a.txt"), b"feature\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "feature"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());

    fs::write(td.path().join("a.txt"), b"local edit\n").unwrap();
    let out = run_in(td.path(), &["checkout", "feature"]);
    assert!(!out.status.success(), "dirty checkout should fail: {out:?}");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("restore would overwrite local changes"));
    assert_eq!(fs::read(td.path().join("a.txt")).unwrap(), b"local edit\n");
}

#[test]
fn checkout_refuses_staged_change() {
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"v1\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "main"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("feature.txt"), b"feature\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "feature"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());

    fs::write(td.path().join("a.txt"), b"staged\n").unwrap();
    assert!(run_in(td.path(), &["add", "a.txt"]).status.success());
    let out = run_in(td.path(), &["checkout", "feature"]);
    assert!(
        !out.status.success(),
        "staged checkout should fail: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("restore would overwrite staged changes"));
}

#[test]
fn checkout_refuses_untracked_collision() {
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("base.txt"), b"base\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "main"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("collision.txt"), b"tracked on feature\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "feature"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());

    fs::write(td.path().join("collision.txt"), b"local only\n").unwrap();
    let out = run_in(td.path(), &["checkout", "feature"]);
    assert!(
        !out.status.success(),
        "untracked collision should fail: {out:?}"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("restore would overwrite untracked path"));
    assert_eq!(
        fs::read(td.path().join("collision.txt")).unwrap(),
        b"local only\n"
    );
}

#[test]
fn checkout_preserves_noncolliding_untracked_file() {
    // Branch switching PRESERVES untracked files (git semantics): an
    // untracked path that does not exist in the target tree must neither
    // block the checkout nor be deleted by it.
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("base.txt"), b"base\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "main"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("feature.txt"), b"feature\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "feature"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["checkout", "main"]).status.success());

    fs::write(td.path().join("notes.txt"), b"local notes\n").unwrap();
    let out = run_in(td.path(), &["checkout", "feature"]);

    assert!(
        out.status.success(),
        "checkout with a non-colliding untracked file should succeed: {out:?}"
    );
    assert_eq!(
        fs::read(td.path().join("notes.txt")).unwrap(),
        b"local notes\n",
        "untracked file must survive the branch switch"
    );
    assert_eq!(
        fs::read(td.path().join("feature.txt")).unwrap(),
        b"feature\n"
    );
}

#[test]
fn checkout_same_tree_succeeds_with_untracked_file() {
    // Re-checking-out the current branch with an untracked file present
    // is a no-op for the untracked file: the checkout succeeds and the
    // file survives (it used to be refused with "restore would remove
    // untracked path").
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("tracked.txt"), b"tracked\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "main"])
            .status
            .success()
    );

    fs::write(td.path().join("notes.txt"), b"local notes\n").unwrap();
    let out = run_in(td.path(), &["checkout", "main"]);

    assert!(
        out.status.success(),
        "same-tree checkout with an untracked file should succeed: {out:?}"
    );
    assert_eq!(
        fs::read(td.path().join("notes.txt")).unwrap(),
        b"local notes\n",
        "untracked file must survive a same-tree checkout"
    );
    assert_eq!(
        fs::read(td.path().join("tracked.txt")).unwrap(),
        b"tracked\n"
    );
}

#[test]
fn checkout_removes_dropped_tracked_files_but_keeps_untracked() {
    // Tracked files that exist on the current branch but not in the
    // target tree are removed (with now-empty directories pruned), while
    // untracked files — including one inside a directory the target
    // drops — are preserved.
    let td = tempfile::tempdir().unwrap();

    assert!(run_in(td.path(), &["init"]).status.success());
    assert!(run_in(td.path(), &["keygen"]).status.success());
    fs::write(td.path().join("base.txt"), b"base\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "main"])
            .status
            .success()
    );
    assert!(run_in(td.path(), &["branch", "feature"]).status.success());
    assert!(run_in(td.path(), &["checkout", "feature"]).status.success());
    fs::write(td.path().join("feature.txt"), b"feature\n").unwrap();
    fs::create_dir_all(td.path().join("sub")).unwrap();
    fs::write(td.path().join("sub/nested.txt"), b"nested\n").unwrap();
    fs::create_dir_all(td.path().join("gone")).unwrap();
    fs::write(td.path().join("gone/only.txt"), b"only\n").unwrap();
    assert!(run_in(td.path(), &["add", "."]).status.success());
    assert!(
        run_in(td.path(), &["commit", "-m", "feature"])
            .status
            .success()
    );

    // Untracked survivors: one at the root, one under a dir whose
    // tracked content the target drops.
    fs::write(td.path().join("notes.txt"), b"local notes\n").unwrap();
    fs::write(td.path().join("sub/keep-me.txt"), b"keep\n").unwrap();

    let out = run_in(td.path(), &["checkout", "main"]);
    assert!(out.status.success(), "checkout main failed: {out:?}");

    // Tracked-on-feature, absent-on-main files are gone.
    assert!(!td.path().join("feature.txt").exists());
    assert!(!td.path().join("sub/nested.txt").exists());
    assert!(!td.path().join("gone/only.txt").exists());
    // A directory emptied by the switch is pruned...
    assert!(!td.path().join("gone").exists(), "emptied dir not pruned");
    // ...but one still holding an untracked file survives, with the file.
    assert_eq!(
        fs::read(td.path().join("sub/keep-me.txt")).unwrap(),
        b"keep\n",
        "untracked file under a dropped dir must survive"
    );
    assert_eq!(
        fs::read(td.path().join("notes.txt")).unwrap(),
        b"local notes\n"
    );
    assert_eq!(fs::read(td.path().join("base.txt")).unwrap(), b"base\n");
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
    assert_eq!(
        fs::read_to_string(td.path().join(".mkitignore")).unwrap(),
        "local.txt\n"
    );
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
