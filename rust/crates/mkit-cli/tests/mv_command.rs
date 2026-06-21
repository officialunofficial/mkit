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
fn mv_directory_renames_tracked_subtree() {
    let (td, xdg) = repo(&[("dir/file.txt", b"x\n"), ("dir/sub/n.txt", b"n\n")]);
    let (root, x) = (td.path(), xdg.path());
    // An untracked file inside the directory must travel with it (git mv
    // renames the whole directory on disk).
    fs::write(root.join("dir/untracked.txt"), b"u\n").unwrap();

    let out = run_in(root, x, &["mv", "dir", "newdir"]);
    assert!(
        out.status.success(),
        "directory rename must succeed: {out:?}"
    );

    // The whole subtree moved, including the nested and untracked files.
    assert!(!root.join("dir").exists(), "source directory must be gone");
    assert!(root.join("newdir/file.txt").exists());
    assert!(root.join("newdir/sub/n.txt").exists());
    assert!(
        root.join("newdir/untracked.txt").exists(),
        "untracked file should be carried along, like git mv"
    );

    // Each tracked file is staged as a delete at the old path + add at the
    // new one (mkit has no rename detection).
    let status = run_in(root, x, &["status", "--porcelain"]);
    let s = String::from_utf8_lossy(&status.stdout);
    assert!(s.contains("D  dir/file.txt"), "missing delete: {s}");
    assert!(s.contains("A  newdir/file.txt"), "missing add: {s}");
    assert!(
        s.contains("D  dir/sub/n.txt") && s.contains("A  newdir/sub/n.txt"),
        "{s}"
    );
}

#[test]
fn mv_directory_into_existing_dir_nests_under_it() {
    let (td, xdg) = repo(&[("dir/file.txt", b"x\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir_all(root.join("target")).unwrap();

    let out = run_in(root, x, &["mv", "dir", "target"]);
    assert!(out.status.success(), "move into existing dir: {out:?}");
    // git moves `dir` INTO `target`, becoming `target/dir/...`.
    assert!(root.join("target/dir/file.txt").exists());
    assert!(!root.join("dir").exists());
}

#[test]
fn mv_directory_into_itself_is_refused() {
    let (td, xdg) = repo(&[("dir/file.txt", b"x\n")]);
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["mv", "dir", "dir/inner"]);
    assert!(!out.status.success(), "moving a dir into itself must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("into itself"),
        "expected an into-itself message: {out:?}"
    );
    assert!(
        root.join("dir/file.txt").exists(),
        "nothing should have moved"
    );
}

#[test]
fn mv_directory_refuses_existing_destination_even_with_force() {
    // `mv -f src dst` where `dst/src` already exists (into-dir collision):
    // -f must NOT recursively delete the existing `dst/src` — that would
    // strand its tracked files in the index and destroy untracked files. A
    // pre-existing destination directory is refused, even with -f.
    let (td, xdg) = repo(&[("src/a.txt", b"a\n"), ("dst/src/old.txt", b"o\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("dst/src/untracked.txt"), b"u\n").unwrap();

    let out = run_in(root, x, &["mv", "-f", "src", "dst"]);
    assert!(
        !out.status.success(),
        "mv -f onto an existing dst/src must be refused: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already exists"),
        "expected an already-exists message: {out:?}"
    );
    // Nothing was destroyed: both the source and the pre-existing destination
    // (tracked AND untracked) are intact.
    assert!(root.join("src/a.txt").exists(), "source must be intact");
    assert!(
        root.join("dst/src/old.txt").exists(),
        "dst tracked file intact"
    );
    assert!(
        root.join("dst/src/untracked.txt").exists(),
        "dst untracked file must not be destroyed"
    );
}

#[test]
fn mv_overlapping_sources_are_refused_up_front() {
    // `mv dir dir/file <dest>` — moving `dir` first would invalidate
    // `dir/file`; git rejects this up front, so must mkit (no partial move).
    let (td, xdg) = repo(&[("dir/file.txt", b"x\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir_all(root.join("dst")).unwrap();
    let out = run_in(root, x, &["mv", "dir", "dir/file.txt", "dst"]);
    assert!(
        !out.status.success(),
        "overlapping sources must be refused: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("overlapping"),
        "expected an overlapping-sources message: {out:?}"
    );
    // Validation happens before any move, so nothing was touched.
    assert!(root.join("dir/file.txt").exists(), "no partial move");
    assert!(!root.join("dst/dir").exists());
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

#[test]
fn mv_file_refuses_directory_destination_even_with_force() {
    // A file source whose into-dir target is an existing DIRECTORY must be
    // refused even with -f (removing it would recursively delete tracked +
    // untracked contents and leave a file/dir index conflict).
    let (td, xdg) = repo(&[("src", b"file\n"), ("dst/src/old.txt", b"o\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::write(root.join("dst/src/u.txt"), b"u\n").unwrap();
    // `mv src dst` → into-dir → target is `dst/src`, which already exists as
    // a directory.
    let out = run_in(root, x, &["mv", "-f", "src", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("directory"),
        "expected a directory message: {out:?}"
    );
    assert!(root.join("src").exists(), "source intact");
    assert!(root.join("dst/src/old.txt").exists(), "tracked dest intact");
    assert!(root.join("dst/src/u.txt").exists(), "untracked dest intact");
}

#[test]
fn mv_refuses_ancestor_destination_collision() {
    // Targets `dst/x` (file) and `dst/x/file.txt` (dir) nest into each other.
    let (td, xdg) = repo(&[("a/x", b"f\n"), ("b/x/file.txt", b"g\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir_all(root.join("dst")).unwrap();
    let out = run_in(root, x, &["mv", "a/x", "b/x", "dst"]);
    assert!(
        !out.status.success(),
        "must refuse colliding targets: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("conflicting destinations"),
        "expected a conflicting-destinations message: {out:?}"
    );
    // No partial move.
    assert!(root.join("a/x").exists() && root.join("b/x/file.txt").exists());
}

#[test]
fn mv_dir_refuses_destination_tracked_but_deleted_from_disk() {
    // `dst` is a tracked FILE deleted from disk; moving a dir to `dst` would
    // create both `dst` (file) and `dst/<child>` index entries.
    let (td, xdg) = repo(&[("src/a.txt", b"a\n"), ("dst", b"d\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::remove_file(root.join("dst")).unwrap(); // still tracked in the index
    let out = run_in(root, x, &["mv", "src", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("tracked"),
        "expected a tracked-path conflict message: {out:?}"
    );
}

#[cfg(unix)]
#[test]
fn mv_refuses_symlinked_directory_source() {
    // A tracked directory replaced by a symlink-to-a-directory must not be
    // "moved" as a directory (which would bypass repo-containment).
    let (td, xdg) = repo(&[("dir/file.txt", b"x\n")]);
    let (root, x) = (td.path(), xdg.path());
    let external = tempfile::tempdir().unwrap();
    fs::remove_dir_all(root.join("dir")).unwrap();
    std::os::unix::fs::symlink(external.path(), root.join("dir")).unwrap();
    let out = run_in(root, x, &["mv", "dir", "newdir"]);
    assert!(
        !out.status.success(),
        "symlink dir source must be refused: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not a directory"),
        "expected a not-a-directory message: {out:?}"
    );
}

#[cfg(unix)]
#[test]
fn mv_refuses_source_through_a_symlinked_ancestor() {
    // A tracked `link/dir/file` whose `link` ANCESTOR is replaced by a
    // symlink to an external directory must not be moved — that would operate
    // on content outside the repo. `symlink_metadata` only declines the final
    // component, so the ancestor walk is what catches this.
    let (td, xdg) = repo(&[("link/dir/file.txt", b"x\n")]);
    let (root, x) = (td.path(), xdg.path());
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("file.txt"), b"external\n").unwrap();
    fs::remove_dir_all(root.join("link")).unwrap();
    std::os::unix::fs::symlink(external.path(), root.join("link")).unwrap();

    let out = run_in(root, x, &["mv", "link/dir", "newdir"]);
    assert!(
        !out.status.success(),
        "must refuse a symlinked-ancestor source: {out:?}"
    );
    assert!(
        external.path().join("file.txt").exists(),
        "external content must be untouched"
    );
}

#[test]
fn mv_dir_refuses_destination_nested_under_a_tracked_ancestor_file() {
    // `dst` is a tracked FILE, deleted from disk and recreated as a directory.
    // `mv src dst` would stage `dst/src/...` while the index still tracks the
    // file `dst` — a file/dir conflict. Refuse it.
    let (td, xdg) = repo(&[("src/a.txt", b"a\n"), ("dst", b"file\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::remove_file(root.join("dst")).unwrap(); // still tracked as a file
    fs::create_dir(root.join("dst")).unwrap(); // recreated as a directory on disk
    let out = run_in(root, x, &["mv", "src", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("tracked"),
        "expected a tracked-path conflict message: {out:?}"
    );
}

#[test]
fn mv_case_only_rename_preserves_the_file() {
    // `mv -f Foo foo` must not delete the source. On a case-insensitive FS the
    // destination IS the source; on a case-sensitive FS it is a plain rename.
    // Either way the content survives and the new name exists.
    let (td, xdg) = repo(&[("Foo", b"data\n")]);
    let (root, x) = (td.path(), xdg.path());
    let out = run_in(root, x, &["mv", "-f", "Foo", "foo"]);
    assert!(
        out.status.success(),
        "case-only rename should succeed: {out:?}"
    );
    assert_eq!(
        fs::read(root.join("foo")).unwrap(),
        b"data\n",
        "content must be preserved at the new name"
    );
}

#[test]
fn mv_file_refuses_destination_with_tracked_descendants() {
    // `dst/child` is tracked; `dst` deleted from disk. `mv src dst` (a file
    // move) would leave both `dst` (file) and `dst/child` in the index.
    let (td, xdg) = repo(&[("src", b"s\n"), ("dst/child", b"c\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::remove_dir_all(root.join("dst")).unwrap(); // dst/child still tracked
    let out = run_in(root, x, &["mv", "src", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("tracked descendants"),
        "expected a tracked-descendants message: {out:?}"
    );
}

#[test]
fn mv_dir_refuses_when_a_tracked_child_is_missing_from_the_worktree() {
    // `src/missing.txt` is tracked but deleted from disk; moving the directory
    // must not resurrect its old blob at the destination.
    let (td, xdg) = repo(&[("src/a.txt", b"a\n"), ("src/missing.txt", b"m\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::remove_file(root.join("src/missing.txt")).unwrap();
    let out = run_in(root, x, &["mv", "src", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("missing from the worktree"),
        "expected a missing-source message: {out:?}"
    );
}

#[test]
fn mv_file_refuses_source_replaced_by_a_directory() {
    // Tracked file `src` replaced on disk by a directory: a "file move" would
    // rename the directory but stage the destination with the old file blob.
    let (td, xdg) = repo(&[("src", b"x\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::remove_file(root.join("src")).unwrap();
    fs::create_dir(root.join("src")).unwrap();
    fs::write(root.join("src/inner"), b"y\n").unwrap();
    let out = run_in(root, x, &["mv", "src", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("now a directory"),
        "expected a tracked-as-file-but-now-directory message: {out:?}"
    );
}

#[test]
fn mv_dir_refuses_child_replaced_by_a_directory() {
    // A tracked child `src/file` replaced on disk by a directory must be
    // refused — moving the parent would restage the stale blob at the dest.
    let (td, xdg) = repo(&[("src/file", b"x\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::remove_file(root.join("src/file")).unwrap();
    fs::create_dir(root.join("src/file")).unwrap();
    fs::write(root.join("src/file/inner"), b"y\n").unwrap();
    let out = run_in(root, x, &["mv", "src", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("now a directory"),
        "expected a type-changed-child message: {out:?}"
    );
}

#[cfg(unix)]
#[test]
fn mv_dir_refuses_child_through_a_symlinked_ancestor() {
    // A tracked `src/link/file` whose `link` ancestor (inside the moved tree)
    // is a symlink to an external dir must be refused — the single directory
    // rename would otherwise carry the symlink and escape the repo.
    let (td, xdg) = repo(&[("src/link/file", b"f\n")]);
    let (root, x) = (td.path(), xdg.path());
    let external = tempfile::tempdir().unwrap();
    fs::write(external.path().join("file"), b"external\n").unwrap();
    fs::remove_dir_all(root.join("src/link")).unwrap();
    std::os::unix::fs::symlink(external.path(), root.join("src/link")).unwrap();
    let out = run_in(root, x, &["mv", "src", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("traverses a symlink"),
        "expected a symlink-traversal message: {out:?}"
    );
    assert!(
        external.path().join("file").exists(),
        "external content untouched"
    );
}

#[cfg(unix)]
#[test]
fn mv_refuses_symlink_destination_pointing_at_source() {
    // An untracked symlink `b -> a` is still an existing destination; mv must
    // refuse it without -f (it is NOT a case-only rename). same_file alone
    // would have wrongly bypassed the guard.
    let (td, xdg) = repo(&[("a", b"data\n")]);
    let (root, x) = (td.path(), xdg.path());
    std::os::unix::fs::symlink("a", root.join("b")).unwrap();
    let out = run_in(root, x, &["mv", "a", "b"]);
    assert!(
        !out.status.success(),
        "must refuse a symlink destination: {out:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("destination exists"),
        "expected a destination-exists message: {out:?}"
    );
    assert_eq!(
        fs::read(root.join("a")).unwrap(),
        b"data\n",
        "source untouched"
    );
}

#[cfg(unix)]
#[test]
fn mv_refuses_destination_through_in_repo_symlinked_parent() {
    // `link -> real` is an in-repo symlink; `mv src link/src` would write
    // through it to real/src while staging the lexical path link/src — a
    // worktree/index divergence. Refuse it (symmetric with the source guard).
    let (td, xdg) = repo(&[("src", b"s\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir(root.join("real")).unwrap();
    std::os::unix::fs::symlink("real", root.join("link")).unwrap();
    let out = run_in(root, x, &["mv", "src", "link/src"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("traverses a symlink"),
        "expected a symlink-traversal message: {out:?}"
    );
    assert!(
        !root.join("real/src").exists(),
        "nothing written through the symlink"
    );
}

#[test]
fn mv_refuses_two_directory_sources_to_same_destination_root() {
    // `mv x/dir y/dir dst` lands both at dst/dir — the per-file collision
    // check misses it (dst/dir/a vs dst/dir/b don't collide), but the bare
    // fs::rename of the second onto the now-existing dest would fail mid-batch.
    // Reject up front (no partial move).
    let (td, xdg) = repo(&[("x/dir/a", b"a\n"), ("y/dir/b", b"b\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir_all(root.join("dst")).unwrap();
    let out = run_in(root, x, &["mv", "x/dir", "y/dir", "dst"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("same destination"),
        "expected a same-destination message: {out:?}"
    );
    assert!(
        root.join("x/dir/a").exists() && root.join("y/dir/b").exists(),
        "nothing should have moved"
    );
}

#[cfg(unix)]
#[test]
fn mv_dir_refuses_destination_through_in_repo_symlinked_parent() {
    // Directory-source variant of the file-source guard: `link -> real` is an
    // in-repo symlink; `mv dir link/dir` would rename the subtree to real/dir
    // while staging the lexical path link/dir — a worktree/index divergence.
    let (td, xdg) = repo(&[("dir/a.txt", b"a\n")]);
    let (root, x) = (td.path(), xdg.path());
    fs::create_dir(root.join("real")).unwrap();
    std::os::unix::fs::symlink("real", root.join("link")).unwrap();
    let out = run_in(root, x, &["mv", "dir", "link/dir"]);
    assert!(!out.status.success(), "must refuse: {out:?}");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("traverses a symlink"),
        "expected a symlink-traversal message: {out:?}"
    );
    assert!(
        !root.join("real/dir").exists(),
        "nothing written through the symlink"
    );
}
