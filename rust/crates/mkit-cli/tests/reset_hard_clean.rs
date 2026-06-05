//! `mkit reset --hard` and `mkit clean` — guarded destructive worktree
//! commands (#250, Phase 2), driven end-to-end through the binary.
//!
//! Both refuse to destroy without an explicit `-f` (the mkit safety
//! divergence): `reset --hard` discards tracked changes silently in git
//! but refuses dirty content here unless `-f`; `clean` mirrors git's
//! `clean.requireForce`.

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

// ---------------------------------------------------------------------------
// reset --hard
// ---------------------------------------------------------------------------

#[test]
fn reset_hard_refuses_dirty_without_force_then_force_discards() {
    let (td, xdg) = repo(&[("tracked.txt", b"v1\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("tracked.txt"), b"v2-dirty\n").unwrap();

    // Without -f, the dirty tracked file is protected.
    let refused = run_in(root, x, &["reset", "--hard", "HEAD"]);
    assert!(
        !refused.status.success(),
        "reset --hard must refuse to discard a dirty file without -f: {refused:?}"
    );
    assert_eq!(fs::read(root.join("tracked.txt")).unwrap(), b"v2-dirty\n");

    // With -f, the change is discarded back to the committed content.
    let forced = run_in(root, x, &["reset", "--hard", "-f", "HEAD"]);
    assert!(
        forced.status.success(),
        "reset --hard -f failed: {forced:?}"
    );
    assert_eq!(fs::read(root.join("tracked.txt")).unwrap(), b"v1\n");
}

#[test]
fn reset_hard_keeps_untracked_files() {
    let (td, xdg) = repo(&[("tracked.txt", b"v1\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("untracked.txt"), b"keep me\n").unwrap();

    // A clean worktree (only an untracked file) — reset --hard succeeds and,
    // like git, leaves the untracked file in place.
    let out = run_in(root, x, &["reset", "--hard", "HEAD"]);
    assert!(out.status.success(), "reset --hard failed: {out:?}");
    assert!(
        root.join("untracked.txt").exists(),
        "reset --hard must keep untracked files (like git)"
    );
}

#[test]
fn reset_hard_to_earlier_commit_restores_tracked_tree() {
    let (td, xdg) = repo(&[("f.txt", b"one\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("f.txt"), b"two\n").unwrap();
    assert!(run_in(root, x, &["add", "."]).status.success());
    assert!(
        run_in(root, x, &["commit", "-m", "second"])
            .status
            .success()
    );

    // Reset --hard back one commit restores the worktree file to "one".
    let out = run_in(root, x, &["reset", "--hard", "HEAD~1"]);
    assert!(out.status.success(), "reset --hard HEAD~1 failed: {out:?}");
    assert_eq!(fs::read(root.join("f.txt")).unwrap(), b"one\n");
}

#[test]
fn reset_hard_removes_tracked_file_absent_from_target_keeps_untracked() {
    let (td, xdg) = repo(&[("base.txt", b"base\n")]);
    let (root, x) = (td.path(), xdg.path());
    // Commit adds a second tracked file.
    fs::write(root.join("added.txt"), b"added\n").unwrap();
    assert!(run_in(root, x, &["add", "."]).status.success());
    assert!(
        run_in(root, x, &["commit", "-m", "add file"])
            .status
            .success()
    );
    // An untracked file that must survive.
    fs::write(root.join("untracked.txt"), b"keep\n").unwrap();

    // reset --hard back one commit: added.txt was tracked but is absent
    // from the target, so it is removed; untracked.txt is kept.
    let out = run_in(root, x, &["reset", "--hard", "HEAD~1"]);
    assert!(out.status.success(), "reset --hard HEAD~1 failed: {out:?}");
    assert!(root.join("base.txt").exists(), "base file kept");
    assert!(
        !root.join("added.txt").exists(),
        "dropped tracked file removed"
    );
    assert!(root.join("untracked.txt").exists(), "untracked file kept");
}

// ---------------------------------------------------------------------------
// clean
// ---------------------------------------------------------------------------

#[test]
fn clean_refuses_without_force_or_dry_run() {
    let (td, xdg) = repo(&[("tracked.txt", b"t\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("untracked.txt"), b"u\n").unwrap();

    let out = run_in(root, x, &["clean"]);
    assert!(
        !out.status.success(),
        "clean must refuse without -f/-n: {out:?}"
    );
    assert!(
        root.join("untracked.txt").exists(),
        "nothing should be removed"
    );
}

#[test]
fn clean_dry_run_previews_without_deleting() {
    let (td, xdg) = repo(&[("tracked.txt", b"t\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("untracked.txt"), b"u\n").unwrap();

    let out = run_in(root, x, &["clean", "-n"]);
    assert!(out.status.success(), "clean -n failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Would remove untracked.txt"),
        "preview: {stdout:?}"
    );
    assert!(root.join("untracked.txt").exists(), "-n must not delete");
}

#[test]
fn clean_force_removes_untracked_files_but_keeps_tracked_and_dirs() {
    let (td, xdg) = repo(&[("tracked.txt", b"t\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("untracked.txt"), b"u\n").unwrap();
    fs::create_dir(root.join("untrackeddir")).unwrap();
    fs::write(root.join("untrackeddir/f.txt"), b"d\n").unwrap();

    let out = run_in(root, x, &["clean", "-f"]);
    assert!(out.status.success(), "clean -f failed: {out:?}");
    assert!(
        !root.join("untracked.txt").exists(),
        "untracked file removed"
    );
    assert!(root.join("tracked.txt").exists(), "tracked file kept");
    // Without -d, the untracked directory is left alone.
    assert!(
        root.join("untrackeddir/f.txt").exists(),
        "untracked dir must survive without -d"
    );
}

#[test]
fn clean_force_d_removes_untracked_directories() {
    let (td, xdg) = repo(&[("tracked.txt", b"t\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir(root.join("untrackeddir")).unwrap();
    fs::write(root.join("untrackeddir/f.txt"), b"d\n").unwrap();

    let out = run_in(root, x, &["clean", "-f", "-d"]);
    assert!(out.status.success(), "clean -fd failed: {out:?}");
    assert!(
        !root.join("untrackeddir").exists(),
        "untracked dir removed with -d"
    );
}

#[test]
fn clean_respects_ignore_unless_x() {
    let (td, xdg) = repo(&[("tracked.txt", b"t\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join(".mkitignore"), b"*.log\n").unwrap();
    fs::write(root.join("debug.log"), b"ignored\n").unwrap();
    fs::write(root.join("untracked.txt"), b"u\n").unwrap();

    // Default: ignored file is kept; the plain untracked file is listed.
    let preview = run_in(root, x, &["clean", "-n"]);
    let s = String::from_utf8_lossy(&preview.stdout);
    assert!(s.contains("untracked.txt"), "preview: {s:?}");
    assert!(
        !s.contains("debug.log"),
        "ignored file must be kept by default: {s:?}"
    );

    // -X removes ONLY ignored files.
    let only_ign = run_in(root, x, &["clean", "-n", "-X"]);
    let s = String::from_utf8_lossy(&only_ign.stdout);
    assert!(s.contains("debug.log"), "-X must list ignored: {s:?}");
    assert!(
        !s.contains("untracked.txt"),
        "-X must skip non-ignored: {s:?}"
    );
}
