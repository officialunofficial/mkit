//! `mkit mv` — guarded move/rename, driven end-to-end through the binary
//! (#250, Phase 2). mkit has no rename detection, so `status` shows the
//! move as a delete + add rather than git's `R`; these tests assert the
//! worktree move and the staged/committed result instead.

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

#[test]
fn mv_renames_file_and_stages_the_move() {
    let (td, xdg) = repo(&[("a.txt", b"hello\n")]);
    let (root, x) = (td.path(), xdg.path());

    let out = run_in(root, x, &["mv", "a.txt", "b.txt"]);
    assert!(out.status.success(), "mv failed: {out:?}");

    // Worktree: source gone, destination has the original content.
    assert!(!root.join("a.txt").exists(), "source must be moved away");
    assert_eq!(fs::read(root.join("b.txt")).unwrap(), b"hello\n");

    // The move is staged: committing it leaves a clean tree with b.txt
    // tracked and a.txt gone.
    assert!(run_in(root, x, &["commit", "-m", "move"]).status.success());
    let st = run_in(root, x, &["status", "--porcelain"]);
    assert!(
        String::from_utf8_lossy(&st.stdout).trim().is_empty(),
        "tree should be clean after committing the move: {st:?}"
    );
    // b.txt is tracked at the moved content (a fresh checkout-equivalent
    // read still shows it); a.txt is not present.
    assert!(root.join("b.txt").exists());
}

#[test]
fn mv_refuses_to_clobber_existing_destination() {
    let (td, xdg) = repo(&[("a.txt", b"aaa\n"), ("b.txt", b"bbb\n")]);
    let (root, x) = (td.path(), xdg.path());

    let out = run_in(root, x, &["mv", "a.txt", "b.txt"]);
    assert!(
        !out.status.success(),
        "mv onto an existing path must be refused without -f: {out:?}"
    );
    // Nothing moved: both files keep their original content.
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"aaa\n");
    assert_eq!(fs::read(root.join("b.txt")).unwrap(), b"bbb\n");
}

#[test]
fn mv_force_overwrites_existing_destination() {
    let (td, xdg) = repo(&[("a.txt", b"aaa\n"), ("b.txt", b"bbb\n")]);
    let (root, x) = (td.path(), xdg.path());

    let out = run_in(root, x, &["mv", "-f", "a.txt", "b.txt"]);
    assert!(out.status.success(), "mv -f failed: {out:?}");
    assert!(!root.join("a.txt").exists());
    assert_eq!(fs::read(root.join("b.txt")).unwrap(), b"aaa\n");
}

#[test]
fn mv_into_existing_directory_keeps_basename() {
    let (td, xdg) = repo(&[("a.txt", b"hi\n"), ("sub/keep.txt", b"k\n")]);
    let (root, x) = (td.path(), xdg.path());

    let out = run_in(root, x, &["mv", "a.txt", "sub"]);
    assert!(out.status.success(), "mv into dir failed: {out:?}");
    assert!(!root.join("a.txt").exists());
    assert_eq!(fs::read(root.join("sub/a.txt")).unwrap(), b"hi\n");
}

#[test]
fn mv_untracked_source_is_refused() {
    let (td, xdg) = repo(&[("tracked.txt", b"t\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("untracked.txt"), b"u\n").unwrap();

    let out = run_in(root, x, &["mv", "untracked.txt", "dest.txt"]);
    assert!(
        !out.status.success(),
        "mv of an untracked source must be refused: {out:?}"
    );
    assert!(root.join("untracked.txt").exists(), "source untouched");
    assert!(!root.join("dest.txt").exists());
}

#[test]
fn mv_missing_source_is_refused() {
    let (td, xdg) = repo(&[("a.txt", b"a\n")]);
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["mv", "ghost.txt", "dest.txt"]);
    assert!(
        !out.status.success(),
        "mv of a missing source must fail: {out:?}"
    );
}

#[test]
fn mv_directory_source_is_refused_clearly() {
    let (td, xdg) = repo(&[("dir/file.txt", b"x\n")]);
    let (root, x) = (td.path(), xdg.path());
    // Directory moves are not yet supported — must fail with a clear
    // message, not silently or with a confusing error.
    let out = run_in(root, x, &["mv", "dir", "newdir"]);
    assert!(
        !out.status.success(),
        "mv of a directory must be refused: {out:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("directories"),
        "expected a directory-not-supported message, got: {stderr:?}"
    );
    // Nothing moved.
    assert!(root.join("dir/file.txt").exists());
    assert!(!root.join("newdir").exists());
}

#[test]
fn mv_multi_source_is_atomic_on_a_bad_source() {
    // The KEY guard: a later bad source must not leave earlier files moved.
    let (td, xdg) = repo(&[("a.txt", b"a\n"), ("dst/keep.txt", b"k\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("untracked.txt"), b"u\n").unwrap();

    // a.txt is valid, untracked.txt is not; dst/ is an existing dir.
    let out = run_in(root, x, &["mv", "a.txt", "untracked.txt", "dst"]);
    assert!(
        !out.status.success(),
        "batch with a bad source must fail: {out:?}"
    );
    // a.txt must NOT have been moved (validation happens before any move).
    assert!(
        root.join("a.txt").exists(),
        "valid source moved despite batch failure"
    );
    assert!(
        !root.join("dst/a.txt").exists(),
        "a.txt was partially moved"
    );
}

#[cfg(unix)]
#[test]
fn mv_refuses_dangling_symlink_destination_without_force() {
    use std::os::unix::fs::symlink;
    let (td, xdg) = repo(&[("a.txt", b"a\n")]);
    let (root, x) = (td.path(), xdg.path());
    // A dangling symlink "exists" for clobber purposes (git refuses too);
    // `Path::exists()` would wrongly report false.
    symlink("/nonexistent/target", root.join("danglink")).unwrap();

    let out = run_in(root, x, &["mv", "a.txt", "danglink"]);
    assert!(
        !out.status.success(),
        "mv onto a dangling symlink must be refused without -f: {out:?}"
    );
    assert!(root.join("a.txt").exists(), "source must be untouched");
}

#[cfg(unix)]
#[test]
fn mv_refuses_destination_escaping_repo_via_symlinked_dir() {
    use std::os::unix::fs::symlink;
    let (td, xdg) = repo(&[("a.txt", b"a\n")]);
    let (root, x) = (td.path(), xdg.path());
    // A repo-local symlink pointing outside the repo must not become a
    // write path: mkit keeps moves inside the repository.
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.join("link_out")).unwrap();

    let out = run_in(root, x, &["mv", "a.txt", "link_out/moved.txt"]);
    assert!(
        !out.status.success(),
        "mv to a path escaping the repo must be refused: {out:?}"
    );
    assert!(root.join("a.txt").exists(), "source must be untouched");
    assert!(
        !outside.path().join("moved.txt").exists(),
        "nothing should be written outside the repository"
    );
}
