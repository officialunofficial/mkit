//! PR-H1 (#228): branch/remote/stash completeness driven end-to-end
//! through the real binary.
//!
//! Covers:
//! - `branch -m` rename (moves the ref; moves HEAD when current).
//! - `branch -D` force-delete (incl. absent = error like git, current = refused).
//! - `remote remove` / `remote rename` (named-remote config mutations,
//!   trust boundary preserved).
//! - `stash apply` (keeps the entry, guarded) and `stash clear`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::Output;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// Run `mkit` in `cwd` with a fresh per-invocation XDG home so user
/// config (keys / trusted endpoints) does not leak between tests.
fn run_in(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    std::process::Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

/// Init a repo with a key and one commit on the default branch.
fn repo() -> (tempfile::TempDir, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let xdg = tempfile::tempdir().unwrap();
    let x = xdg.path();
    assert!(run_in(td.path(), x, &["init"]).status.success());
    assert!(run_in(td.path(), x, &["keygen"]).status.success());
    fs::write(td.path().join("a.txt"), b"hello\n").unwrap();
    assert!(run_in(td.path(), x, &["add", "."]).status.success());
    assert!(
        run_in(td.path(), x, &["commit", "-m", "initial"])
            .status
            .success()
    );
    (td, xdg)
}

fn head_branch(mkit_dir: &Path) -> String {
    let head = fs::read_to_string(mkit_dir.join("HEAD")).unwrap();
    head.trim()
        .strip_prefix("ref: refs/heads/")
        .expect("symbolic HEAD")
        .to_string()
}

// ---------------------------------------------------------------------------
// branch -m / -D
// ---------------------------------------------------------------------------

#[test]
fn branch_default_list_omits_id_verbose_shows_id_and_subject() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["branch", "feature"]).status.success());

    // Default list: `<marker> <name>` only — no id appended (git parity).
    // The marker field is the first two bytes (`* ` or `  `); the rest is
    // exactly the branch name, so it must contain no further whitespace.
    let plain = run_in(root, x, &["branch"]);
    assert!(plain.status.success(), "branch failed: {plain:?}");
    let plain_out = String::from_utf8_lossy(&plain.stdout);
    for line in plain_out.lines() {
        let rest = &line[2..];
        assert!(
            !rest.contains(' '),
            "default list must be `<marker> <name>` only (no id), got: {line:?}"
        );
    }

    // `-v`: `<marker> <name> <short-id> <subject>` — id + subject present.
    let verbose = run_in(root, x, &["branch", "-v"]);
    assert!(verbose.status.success(), "branch -v failed: {verbose:?}");
    let v_out = String::from_utf8_lossy(&verbose.stdout);
    let current_line = v_out
        .lines()
        .find(|l| l.trim_start().starts_with('*'))
        .expect("a current-branch line");
    let cols: Vec<&str> = current_line.split_whitespace().collect();
    // ["*", "<name>", "<short>", "initial"]
    assert!(
        cols.len() >= 4,
        "verbose line missing fields: {current_line:?}"
    );
    let short = cols[2];
    assert!(
        short.len() >= 7 && short.chars().all(|c| c.is_ascii_hexdigit()),
        "expected an abbreviated hex id, got: {short:?}"
    );
    assert!(
        v_out.contains("initial"),
        "verbose output must include the commit subject: {v_out:?}"
    );
}

#[test]
fn branch_rename_two_args_moves_ref() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let mkit = root.join(".mkit");

    // Create a non-current branch and rename it.
    assert!(run_in(root, x, &["branch", "feature"]).status.success());
    let old_hash = fs::read(mkit.join("refs/heads/feature")).unwrap();

    let out = run_in(root, x, &["branch", "-m", "feature", "topic"]);
    assert!(out.status.success(), "rename failed: {out:?}");

    assert!(
        !mkit.join("refs/heads/feature").exists(),
        "old ref must be gone"
    );
    let new_hash = fs::read(mkit.join("refs/heads/topic")).unwrap();
    assert_eq!(old_hash, new_hash, "renamed ref must keep the same tip");
    // HEAD untracked branch was not touched.
    assert_ne!(head_branch(&mkit), "topic");
}

#[test]
fn branch_rename_current_moves_head() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let mkit = root.join(".mkit");
    let current = head_branch(&mkit);

    let out = run_in(root, x, &["branch", "-m", "renamed-main"]);
    assert!(out.status.success(), "rename current failed: {out:?}");

    assert!(!mkit.join(format!("refs/heads/{current}")).exists());
    assert!(mkit.join("refs/heads/renamed-main").exists());
    assert_eq!(
        head_branch(&mkit),
        "renamed-main",
        "HEAD must follow rename"
    );
}

#[test]
fn branch_rename_refuses_existing_destination() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["branch", "feature"]).status.success());
    assert!(run_in(root, x, &["branch", "other"]).status.success());

    let out = run_in(root, x, &["branch", "-m", "feature", "other"]);
    assert!(!out.status.success(), "must refuse clobbering 'other'");
    assert!(root.join(".mkit/refs/heads/feature").exists());
    assert!(root.join(".mkit/refs/heads/other").exists());
}

#[test]
fn branch_force_delete_removes_branch() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(run_in(root, x, &["branch", "feature"]).status.success());
    assert!(root.join(".mkit/refs/heads/feature").exists());

    let out = run_in(root, x, &["branch", "-D", "feature"]);
    assert!(out.status.success(), "-D failed: {out:?}");
    assert!(!root.join(".mkit/refs/heads/feature").exists());
}

#[test]
fn branch_delete_absent_errors_for_both_d_and_force() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    // Parity reconciliation (#249): like `git branch -D <missing>`, both
    // `-d` and `-D` error on an absent branch — `-D` no longer silently
    // no-ops, so a typo'd name is surfaced rather than swallowed.
    let safe = run_in(root, x, &["branch", "-d", "ghost"]);
    assert!(!safe.status.success(), "-d on missing branch must error");
    let forced = run_in(root, x, &["branch", "-D", "ghost"]);
    assert!(
        !forced.status.success(),
        "-D on a missing branch must error like git, not no-op: {forced:?}"
    );
    let stderr = String::from_utf8_lossy(&forced.stderr);
    assert!(
        stderr.contains("not found"),
        "expected a 'not found' message, got: {stderr:?}"
    );
}

#[test]
fn branch_force_delete_refuses_current() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let current = head_branch(&root.join(".mkit"));
    let out = run_in(root, x, &["branch", "-D", &current]);
    assert!(
        !out.status.success(),
        "even -D must refuse the checked-out branch"
    );
    assert!(root.join(".mkit/refs/heads").join(&current).exists());
}

// ---------------------------------------------------------------------------
// remote remove / rename
// ---------------------------------------------------------------------------

fn read_config(root: &Path) -> String {
    fs::read_to_string(root.join(".mkit/config")).unwrap_or_default()
}

#[test]
fn remote_remove_drops_named_remote() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(
        run_in(root, x, &["remote", "add", "origin", "mkit+file:///tmp/r"])
            .status
            .success()
    );
    assert!(read_config(root).contains("remote.origin.url"));

    let out = run_in(root, x, &["remote", "remove", "origin"]);
    assert!(out.status.success(), "remove failed: {out:?}");
    assert!(!read_config(root).contains("remote.origin"));

    // Removing a missing remote errors.
    assert!(
        !run_in(root, x, &["remote", "remove", "origin"])
            .status
            .success()
    );
}

#[test]
fn remote_rename_updates_config_and_upstream() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(
        run_in(root, x, &["remote", "add", "origin", "mkit+file:///tmp/r"])
            .status
            .success()
    );
    // Hand-wire a branch upstream pointing at `origin` so we can prove
    // rename repoints it.
    let cfg_path = root.join(".mkit/config");
    let mut cfg = read_config(root);
    cfg.push_str("branch.main.remote = origin\nbranch.main.merge = main\n");
    fs::write(&cfg_path, cfg).unwrap();

    let out = run_in(root, x, &["remote", "rename", "origin", "upstream"]);
    assert!(out.status.success(), "rename failed: {out:?}");

    let after = read_config(root);
    assert!(after.contains("remote.upstream.url"));
    assert!(!after.contains("remote.origin.url"));
    assert!(
        after.contains("branch.main.remote = upstream"),
        "upstream tracking must be repointed: {after}"
    );
}

#[test]
fn remote_rename_refuses_existing_destination() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    assert!(
        run_in(root, x, &["remote", "add", "a", "mkit+file:///tmp/a"])
            .status
            .success()
    );
    assert!(
        run_in(root, x, &["remote", "add", "b", "mkit+file:///tmp/b"])
            .status
            .success()
    );
    let out = run_in(root, x, &["remote", "rename", "a", "b"]);
    assert!(!out.status.success(), "must refuse clobbering existing 'b'");
    let cfg = read_config(root);
    assert!(cfg.contains("remote.a.url"), "source must survive: {cfg}");
    assert!(cfg.contains("remote.b.url"));
}

#[test]
fn remote_remove_preserves_trusted_endpoint() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());
    let url = "mkit+https://example.test/r";
    assert!(
        run_in(root, x, &["remote", "add", "origin", url])
            .status
            .success()
    );
    // Trust the exact endpoint (user-scoped; keyed by URL, not name).
    assert!(
        run_in(root, x, &["config", "trusted_remote_endpoint", url])
            .status
            .success()
    );
    let user_cfg = xdg.path().join("mkit/config");
    let before = fs::read_to_string(&user_cfg).unwrap();
    assert!(before.contains(url));

    assert!(
        run_in(root, x, &["remote", "remove", "origin"])
            .status
            .success()
    );

    // The user-scoped trust record is untouched by repo-config rewrites.
    let after = fs::read_to_string(&user_cfg).unwrap();
    assert!(
        after.contains(url),
        "trusted endpoint must survive remote remove: {after}"
    );
    // ...and it was never written into the repo config.
    assert!(!read_config(root).contains("trusted_remote_endpoint"));
}

// ---------------------------------------------------------------------------
// stash apply / clear
// ---------------------------------------------------------------------------

#[test]
fn stash_apply_keeps_entry() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());

    fs::write(root.join("a.txt"), b"work-in-progress\n").unwrap();
    assert!(run_in(root, x, &["stash"]).status.success());
    // Worktree was reset to HEAD by the stash save.
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"hello\n");

    let out = run_in(root, x, &["stash", "apply"]);
    assert!(out.status.success(), "apply failed: {out:?}");
    // The stashed change is back in the worktree...
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"work-in-progress\n");
    // ...and the entry is still listed (apply does not drop).
    let list = run_in(root, x, &["stash", "list"]);
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("stash@{0}"),
        "apply must keep the entry on the stack"
    );
}

#[test]
fn stash_apply_is_guarded_against_clobber() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());

    fs::write(root.join("a.txt"), b"stashed edit\n").unwrap();
    assert!(run_in(root, x, &["stash"]).status.success());

    // Dirty the same path with different uncommitted work, then apply.
    fs::write(root.join("a.txt"), b"conflicting local work\n").unwrap();
    let out = run_in(root, x, &["stash", "apply"]);
    assert!(
        !out.status.success(),
        "apply must refuse to clobber uncommitted edits"
    );
    // The local work is intact and the entry is still present.
    assert_eq!(
        fs::read(root.join("a.txt")).unwrap(),
        b"conflicting local work\n"
    );
    let list = run_in(root, x, &["stash", "list"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains("stash@{0}"));
}

#[test]
fn stash_clear_empties_the_stack() {
    let (td, xdg) = repo();
    let (root, x) = (td.path(), xdg.path());

    fs::write(root.join("a.txt"), b"v1\n").unwrap();
    assert!(run_in(root, x, &["stash"]).status.success());
    fs::write(root.join("a.txt"), b"v2\n").unwrap();
    assert!(run_in(root, x, &["stash"]).status.success());

    let before = run_in(root, x, &["stash", "list"]);
    assert!(String::from_utf8_lossy(&before.stdout).contains("stash@{1}"));

    let out = run_in(root, x, &["stash", "clear"]);
    assert!(out.status.success(), "clear failed: {out:?}");

    let after = run_in(root, x, &["stash", "list"]);
    assert!(
        after.stdout.is_empty(),
        "stash list must be empty after clear: {:?}",
        String::from_utf8_lossy(&after.stdout)
    );
}
