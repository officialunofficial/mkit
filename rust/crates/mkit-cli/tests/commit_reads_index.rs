//! Verifies that `mkit commit` builds its tree from the staging index
//! (`.mkit/index`), NOT from a recursive walk of the working tree.
//!
//! Resolves issue #102 — pre-Option-B, `mkit add` wrote to the index
//! but `mkit commit` ignored it and snapshotted the entire worktree.
//! These tests pin the new contract:
//!
//! 1. A file present in the worktree but NOT in the index is excluded
//!    from the commit's tree.
//! 2. `mkit add <path>` followed by `mkit commit` produces a tree that
//!    contains exactly the staged paths.
//! 3. Committing with an empty index is a hard error (no silent
//!    "commit nothing" mode).
//! 4. `mkit add .` followed by `mkit commit` produces a tree
//!    byte-equivalent to what the pre-#102 behaviour produced (the
//!    snapshot use-case still works with one extra command).

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run(cwd: &Path, args: &[&str]) -> Output {
    let xdg = tempfile::tempdir().expect("xdg");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

fn ok(cwd: &Path, args: &[&str]) -> Output {
    let out = run(cwd, args);
    assert!(
        out.status.success(),
        "mkit {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    ok(td.path(), &["init"]);
    ok(td.path(), &["keygen"]);
    td
}

/// Pull the tree hash that `<commit-hash>` points at by parsing
/// `mkit cat <commit-hash>`. We don't bind to a parser surface — the
/// commit body is line-delimited "field value" pairs, the first being
/// `tree <64-hex>`.
fn tree_of_commit(cwd: &Path, commit: &str) -> String {
    let out = ok(cwd, &["cat", commit]);
    let body = String::from_utf8(out.stdout).unwrap();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("tree ") {
            return rest.trim().to_string();
        }
    }
    panic!("no `tree` line in commit body: {body}");
}

/// Read the current branch HEAD as the most recent commit hash.
fn head_commit(cwd: &Path) -> String {
    // refs/heads/<branch> contains the commit hash. Default branch
    // after `mkit init` is `main`.
    let head_path = cwd.join(".mkit/refs/heads/main");
    fs::read_to_string(&head_path).unwrap().trim().to_string()
}

fn head_tree_body(cwd: &Path) -> String {
    let commit = head_commit(cwd);
    let tree = tree_of_commit(cwd, &commit);
    let cat = ok(cwd, &["cat", &tree]);
    String::from_utf8(cat.stdout).unwrap()
}

fn head_blob_body(cwd: &Path, file: &str) -> String {
    let body = head_tree_body(cwd);
    let hash = body
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let _mode = parts.next()?;
            let hash = parts.next()?;
            let name = parts.next()?;
            (name == file).then_some(hash.to_string())
        })
        .unwrap_or_else(|| panic!("missing {file} in tree: {body}"));
    let cat = ok(cwd, &["cat", &hash]);
    String::from_utf8(cat.stdout).unwrap()
}

fn head_tree_line(cwd: &Path, file: &str) -> String {
    let body = head_tree_body(cwd);
    body.lines()
        .find(|line| line.ends_with(&format!(" {file}")))
        .unwrap_or_else(|| panic!("missing {file} in tree: {body}"))
        .to_string()
}

#[test]
fn unstaged_files_are_excluded_from_commit_tree() {
    let td = init_repo();
    let p = td.path();

    // Two files on disk; only one is staged.
    fs::write(p.join("staged.txt"), b"in the index").unwrap();
    fs::write(p.join("unstaged.txt"), b"NOT in the index").unwrap();
    ok(p, &["add", "staged.txt"]);

    ok(p, &["commit", "-m", "only staged"]);
    let commit = head_commit(p);
    let tree = tree_of_commit(p, &commit);

    let cat = ok(p, &["cat", &tree]);
    let body = String::from_utf8(cat.stdout).unwrap();

    assert!(
        body.contains("staged.txt"),
        "commit tree missing staged file. body=\n{body}"
    );
    assert!(
        !body.contains("unstaged.txt"),
        "commit tree contains unstaged file — issue #102 regression. body=\n{body}"
    );
}

#[test]
fn commit_with_empty_index_is_an_error() {
    let td = init_repo();
    let p = td.path();
    // Files exist on disk but nothing was added — pre-#102 this
    // silently committed the whole worktree. Post-#102, this is a
    // hard error so the failure surfaces loudly instead of producing
    // a "ghost commit" the user didn't intend.
    fs::write(p.join("orphan.txt"), b"on disk, not staged").unwrap();
    let out = run(p, &["commit", "-m", "should fail"]);
    assert!(
        !out.status.success(),
        "commit with empty index must fail; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("index") || stderr.contains("staged") || stderr.contains("nothing"),
        "stderr should hint at the empty index. got: {stderr}"
    );
}

#[test]
fn add_dot_then_commit_reproduces_full_worktree_snapshot() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    fs::write(p.join("b.txt"), b"beta").unwrap();
    fs::create_dir(p.join("sub")).unwrap();
    fs::write(p.join("sub/c.txt"), b"gamma").unwrap();

    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "snapshot all"]);
    let commit = head_commit(p);
    let tree = tree_of_commit(p, &commit);

    // Tree should mention all three paths. Walking the full tree to
    // verify byte-equivalence is overkill for this test — that
    // invariant is pinned in mkit-core's
    // `from_index_matches_build_tree_for_equivalent_worktree`.
    let cat = ok(p, &["cat", &tree]);
    let body = String::from_utf8(cat.stdout).unwrap();
    assert!(body.contains("a.txt"));
    assert!(body.contains("b.txt"));
    assert!(body.contains("sub"));
}

#[cfg(unix)]
#[test]
fn add_one_preserves_executable_mode() {
    use std::os::unix::fs::PermissionsExt;

    let td = init_repo();
    let p = td.path();
    let script = p.join("run.sh");

    fs::write(&script, b"#!/bin/sh\n").unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(perms.mode() | 0o111);
    fs::set_permissions(&script, perms).unwrap();

    ok(p, &["add", "run.sh"]);
    ok(p, &["commit", "-m", "add executable"]);

    let line = head_tree_line(p, "run.sh");
    assert!(
        line.starts_with("04 "),
        "run.sh should be executable: {line}"
    );
}

#[cfg(unix)]
#[test]
fn add_dot_preserves_executable_mode() {
    use std::os::unix::fs::PermissionsExt;

    let td = init_repo();
    let p = td.path();
    let script = p.join("run.sh");

    fs::write(&script, b"#!/bin/sh\n").unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(perms.mode() | 0o111);
    fs::set_permissions(&script, perms).unwrap();

    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "snapshot executable"]);

    let line = head_tree_line(p, "run.sh");
    assert!(
        line.starts_with("04 "),
        "run.sh should be executable: {line}"
    );
}

#[test]
fn commit_all_stages_modified_tracked_file() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    fs::write(p.join("a.txt"), b"alpha v2").unwrap();
    ok(p, &["commit", "-a", "-m", "update tracked"]);

    assert_eq!(head_blob_body(p, "a.txt"), "alpha v2");
}

#[test]
fn commit_dash_am_stages_modified_tracked_file() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    fs::write(p.join("a.txt"), b"alpha v2").unwrap();
    let out = ok(p, &["commit", "-am", "update tracked"]);

    assert_eq!(head_blob_body(p, "a.txt"), "alpha v2");
    // Confirmation prose lives on stderr.
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("update tracked"),
        "-am message was not used: {stderr}"
    );
}

#[test]
fn commit_all_stages_tracked_deletion() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    fs::write(p.join("b.txt"), b"beta").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    fs::remove_file(p.join("b.txt")).unwrap();
    ok(p, &["commit", "--all", "-m", "drop tracked"]);

    let body = head_tree_body(p);
    assert!(body.contains("a.txt"));
    assert!(
        !body.contains("b.txt"),
        "commit -a did not stage tracked deletion: {body}"
    );
}

#[test]
fn commit_all_does_not_add_untracked_files() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("tracked.txt"), b"tracked").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    fs::write(p.join("tracked.txt"), b"tracked v2").unwrap();
    fs::write(p.join("untracked.txt"), b"do not add").unwrap();
    ok(p, &["commit", "-a", "-m", "tracked only"]);

    let body = head_tree_body(p);
    assert!(body.contains("tracked.txt"));
    assert!(
        !body.contains("untracked.txt"),
        "commit -a added an untracked file: {body}"
    );
}

#[cfg(unix)]
#[test]
fn commit_all_tracks_executable_bit_changes() {
    use std::os::unix::fs::PermissionsExt;

    let td = init_repo();
    let p = td.path();
    let script = p.join("run.sh");

    fs::write(&script, b"#!/bin/sh\n").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(perms.mode() | 0o111);
    fs::set_permissions(&script, perms).unwrap();
    ok(p, &["commit", "-a", "-m", "make executable"]);
    let executable_line = head_tree_line(p, "run.sh");
    assert!(
        executable_line.starts_with("04 "),
        "commit -a did not stage executable mode: {executable_line}"
    );

    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(perms.mode() & !0o111);
    fs::set_permissions(&script, perms).unwrap();
    ok(p, &["commit", "-a", "-m", "make regular"]);
    let blob_line = head_tree_line(p, "run.sh");
    assert!(
        blob_line.starts_with("01 "),
        "commit -a did not stage removal of executable mode: {blob_line}"
    );
}

#[cfg(not(unix))]
#[test]
fn commit_all_preserves_existing_executable_mode_on_non_unix() {
    use mkit_core::index::{self, EntryStatus, Index, IndexEntry};
    use mkit_core::object::{Blob, Object};
    use mkit_core::serialize;
    use mkit_core::store::ObjectStore;

    let td = init_repo();
    let p = td.path();
    let script = p.join("run.sh");

    fs::write(&script, b"v1").unwrap();
    let store = ObjectStore::open(p).unwrap();
    let blob = Object::Blob(Blob {
        data: b"v1".to_vec(),
    });
    let bytes = serialize::serialize(&blob).unwrap();
    let hash = store.write(&bytes).unwrap();
    let mut idx = Index::new();
    idx.entries.push(IndexEntry {
        path: "run.sh".into(),
        status: EntryStatus::Executable,
        object_hash: hash,
    });
    index::write_index(p, &idx).unwrap();
    ok(p, &["commit", "-m", "first"]);

    fs::write(&script, b"v2").unwrap();
    ok(p, &["commit", "-a", "-m", "update executable"]);

    let line = head_tree_line(p, "run.sh");
    assert!(
        line.starts_with("04 "),
        "non-Unix commit -a should preserve executable mode: {line}"
    );
    assert_eq!(head_blob_body(p, "run.sh"), "v2");
}

#[cfg(not(unix))]
#[test]
fn add_one_preserves_existing_executable_mode_on_non_unix() {
    use mkit_core::index::{self, EntryStatus, Index, IndexEntry};
    use mkit_core::object::{Blob, Object};
    use mkit_core::serialize;
    use mkit_core::store::ObjectStore;

    let td = init_repo();
    let p = td.path();
    let script = p.join("run.sh");

    fs::write(&script, b"v1").unwrap();
    let store = ObjectStore::open(p).unwrap();
    let blob = Object::Blob(Blob {
        data: b"v1".to_vec(),
    });
    let bytes = serialize::serialize(&blob).unwrap();
    let hash = store.write(&bytes).unwrap();
    let mut idx = Index::new();
    idx.entries.push(IndexEntry {
        path: "run.sh".into(),
        status: EntryStatus::Executable,
        object_hash: hash,
    });
    index::write_index(p, &idx).unwrap();

    fs::write(&script, b"v2").unwrap();
    ok(p, &["add", "run.sh"]);
    ok(p, &["commit", "-m", "update executable"]);

    let line = head_tree_line(p, "run.sh");
    assert!(
        line.starts_with("04 "),
        "non-Unix add should preserve executable mode: {line}"
    );
    assert_eq!(head_blob_body(p, "run.sh"), "v2");
}

#[test]
fn commit_all_rejects_invalid_index_path_before_refreshing() {
    use mkit_core::hash::ZERO;
    use mkit_core::index::{self, EntryStatus, Index, IndexEntry};

    let td = init_repo();
    let p = td.path();
    let mut idx = Index::new();
    idx.entries.push(IndexEntry {
        path: "../outside.txt".into(),
        status: EntryStatus::Blob,
        object_hash: ZERO,
    });
    index::write_index(p, &idx).unwrap();

    let out = run(p, &["commit", "-a", "-m", "should fail"]);
    assert!(
        !out.status.success(),
        "commit -a with invalid index path must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid index path"),
        "error should report invalid index path before refreshing, got: {stderr}"
    );
}

#[test]
fn commit_all_with_only_untracked_files_is_an_error() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("orphan.txt"), b"not tracked").unwrap();
    let out = run(p, &["commit", "-a", "-m", "should fail"]);

    assert!(
        !out.status.success(),
        "commit -a with only untracked files must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("index") || stderr.contains("staged") || stderr.contains("nothing"),
        "stderr should hint at the empty index. got: {stderr}"
    );
}

#[test]
fn add_dot_stages_tracked_deletions() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    fs::write(p.join("b.txt"), b"beta").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    fs::remove_file(p.join("b.txt")).unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "drop b"]);

    let body = head_tree_body(p);
    assert!(body.contains("a.txt"));
    assert!(
        !body.contains("b.txt"),
        "add . failed to stage tracked deletion: {body}"
    );
}

#[test]
fn add_dot_respects_mkitignore_before_commit() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join(".mkitignore"), b"secret.txt\n").unwrap();
    fs::write(p.join("public.txt"), b"safe").unwrap();
    fs::write(p.join("secret.txt"), b"do not commit").unwrap();

    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "respect ignore"]);

    let body = head_tree_body(p);
    assert!(body.contains("public.txt"));
    assert!(body.contains(".mkitignore"));
    assert!(
        !body.contains("secret.txt"),
        "ignored file was committed by add .: {body}"
    );
}

#[test]
fn add_dot_keeps_existing_tracked_file_that_is_now_ignored() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("public.txt"), b"safe").unwrap();
    fs::write(p.join("secret.txt"), b"already tracked").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "track secret"]);

    fs::write(p.join(".mkitignore"), b"secret.txt\n").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "ignore future secrets"]);

    let body = head_tree_body(p);
    assert!(body.contains("public.txt"));
    assert!(body.contains(".mkitignore"));
    assert!(
        body.contains("secret.txt"),
        "add . staged deletion for an existing tracked ignored file: {body}"
    );
}

#[test]
fn add_dot_removes_tracked_ignored_file_when_it_is_missing() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("secret.txt"), b"already tracked").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "track secret"]);

    fs::write(p.join(".mkitignore"), b"secret.txt\n").unwrap();
    fs::remove_file(p.join("secret.txt")).unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "drop secret"]);

    let body = head_tree_body(p);
    assert!(body.contains(".mkitignore"));
    assert!(
        !body.contains("secret.txt"),
        "add . failed to stage an actual tracked deletion: {body}"
    );
}

#[test]
fn add_dot_stages_file_replacing_tracked_directory() {
    let td = init_repo();
    let p = td.path();

    fs::create_dir(p.join("a")).unwrap();
    fs::write(p.join("a/b.txt"), b"nested").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "track directory"]);

    fs::remove_dir_all(p.join("a")).unwrap();
    fs::write(p.join("a"), b"now a file").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "replace directory"]);

    let body = head_tree_body(p);
    let a_line = body
        .lines()
        .find(|line| line.ends_with(" a"))
        .unwrap_or_else(|| panic!("missing replacement file entry: {body}"));
    assert!(
        a_line.starts_with("01 "),
        "replacement should be a blob entry, got: {a_line}"
    );
}

#[test]
fn add_one_stages_file_replacing_tracked_directory() {
    let td = init_repo();
    let p = td.path();

    fs::create_dir(p.join("a")).unwrap();
    fs::write(p.join("a/b.txt"), b"nested").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "track directory"]);

    fs::remove_dir_all(p.join("a")).unwrap();
    fs::write(p.join("a"), b"now a file").unwrap();
    ok(p, &["add", "a"]);
    ok(p, &["commit", "-m", "replace directory"]);

    let body = head_tree_body(p);
    let a_line = body
        .lines()
        .find(|line| line.ends_with(" a"))
        .unwrap_or_else(|| panic!("missing replacement file entry: {body}"));
    assert!(
        a_line.starts_with("01 "),
        "replacement should be a blob entry, got: {a_line}"
    );
}

#[test]
fn add_one_stages_nested_file_replacing_tracked_file() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a"), b"was a file").unwrap();
    ok(p, &["add", "a"]);
    ok(p, &["commit", "-m", "track file"]);

    fs::remove_file(p.join("a")).unwrap();
    fs::create_dir(p.join("a")).unwrap();
    fs::write(p.join("a/b.txt"), b"now nested").unwrap();
    ok(p, &["add", "a/b.txt"]);
    ok(p, &["commit", "-m", "replace file"]);

    let body = head_tree_body(p);
    let a_line = body
        .lines()
        .find(|line| line.ends_with(" a"))
        .unwrap_or_else(|| panic!("missing replacement directory entry: {body}"));
    assert!(
        a_line.starts_with("02 "),
        "replacement should be a tree entry, got: {a_line}"
    );
    let a_tree = a_line.split_whitespace().nth(1).unwrap();
    let nested = ok(p, &["cat", a_tree]);
    let nested_body = String::from_utf8(nested.stdout).unwrap();
    assert!(nested_body.contains("b.txt"));
}

#[test]
fn add_dot_stages_directory_replacing_tracked_file() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a"), b"was a file").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "track file"]);

    fs::remove_file(p.join("a")).unwrap();
    fs::create_dir(p.join("a")).unwrap();
    fs::write(p.join("a/b.txt"), b"now nested").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "replace file"]);

    let body = head_tree_body(p);
    let a_line = body
        .lines()
        .find(|line| line.ends_with(" a"))
        .unwrap_or_else(|| panic!("missing replacement directory entry: {body}"));
    assert!(
        a_line.starts_with("02 "),
        "replacement should be a tree entry, got: {a_line}"
    );
}

#[cfg(unix)]
#[test]
fn add_dot_rejects_absolute_symlink_instead_of_staging_target_bytes() {
    use std::os::unix::fs::symlink;

    let td = init_repo();
    let p = td.path();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(outside.path(), b"outside secret").unwrap();
    symlink(outside.path(), p.join("secret-link")).unwrap();

    let out = run(p, &["add", "."]);
    assert!(
        !out.status.success(),
        "add . must reject absolute symlink targets"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("symlink") || stderr.contains("target"),
        "error should explain the symlink rejection, got: {stderr}"
    );

    let commit = run(p, &["commit", "-m", "should fail"]);
    assert!(
        !commit.status.success(),
        "failed add . must not leave staged target bytes behind"
    );
}

#[cfg(unix)]
#[test]
fn add_one_preserves_safe_symlink_mode() {
    use std::os::unix::fs::symlink;

    let td = init_repo();
    let p = td.path();
    fs::write(p.join("target.txt"), b"target contents").unwrap();
    symlink("target.txt", p.join("link")).unwrap();

    ok(p, &["add", "link"]);
    ok(p, &["commit", "-m", "stage symlink"]);

    let body = head_tree_body(p);
    let line = body
        .lines()
        .find(|line| line.ends_with(" link"))
        .unwrap_or_else(|| panic!("missing symlink entry: {body}"));
    assert!(
        line.starts_with("03 "),
        "link should be committed as symlink mode, got: {line}"
    );
    let target_hash = line.split_whitespace().nth(1).unwrap();
    let target = ok(p, &["cat", target_hash]);
    assert_eq!(String::from_utf8(target.stdout).unwrap(), "target.txt");
}

#[cfg(unix)]
#[test]
fn add_dot_stages_symlinked_directory_without_recursing() {
    use std::os::unix::fs::symlink;

    let td = init_repo();
    let p = td.path();
    fs::create_dir(p.join("real-dir")).unwrap();
    fs::write(p.join("real-dir/inside.txt"), b"inside").unwrap();
    symlink("real-dir", p.join("dirlink")).unwrap();

    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "stage dir symlink"]);

    let body = head_tree_body(p);
    assert!(body.contains("dirlink"));
    let line = body
        .lines()
        .find(|line| line.ends_with(" dirlink"))
        .unwrap_or_else(|| panic!("missing dirlink entry: {body}"));
    assert!(
        line.starts_with("03 "),
        "dirlink should be committed as symlink mode, got: {line}"
    );
}

/// Reviewer finding 1 (PR #103): an index whose only entries are
/// `Removed` is a meaningful changeset — the user is committing
/// removals — and must produce an empty-tree commit, not an error.
/// Pre-fix, `commit.rs` checked `staged_count() == 0` (which excludes
/// Removed) and rejected the operation with "nothing staged".
#[test]
fn rm_only_index_commits_an_empty_tree() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    ok(p, &["add", "a.txt"]);
    ok(p, &["commit", "-m", "first"]);

    // Remove the only file, leaving an all-Removed index.
    ok(p, &["rm", "a.txt"]);
    let out = run(p, &["commit", "-m", "drop everything"]);
    assert!(
        out.status.success(),
        "all-Removed commit must succeed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let commit = head_commit(p);
    let tree = tree_of_commit(p, &commit);
    let cat = ok(p, &["cat", &tree]);
    let body = String::from_utf8(cat.stdout).unwrap();
    // Empty tree has no entries.
    assert!(
        !body.contains("a.txt"),
        "empty-tree commit unexpectedly references the removed file: {body}"
    );
}

#[test]
fn rm_then_commit_excludes_the_removed_path() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    fs::write(p.join("b.txt"), b"beta").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    // Stage a removal of b.txt; the file may or may not still be on
    // disk — index is the source of truth post-#102.
    ok(p, &["rm", "b.txt"]);
    ok(p, &["commit", "-m", "drop b"]);
    let commit = head_commit(p);
    let tree = tree_of_commit(p, &commit);
    let cat = ok(p, &["cat", &tree]);
    let body = String::from_utf8(cat.stdout).unwrap();
    assert!(body.contains("a.txt"));
    assert!(
        !body.contains("b.txt"),
        "removed file still present in tree: {body}"
    );
}

#[test]
fn rm_directory_stages_tracked_descendants() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("keep.txt"), b"keep").unwrap();
    fs::create_dir(p.join("sub")).unwrap();
    fs::write(p.join("sub/file.txt"), b"drop").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    ok(p, &["rm", "sub"]);
    ok(p, &["commit", "-m", "drop sub"]);

    let body = head_tree_body(p);
    assert!(body.contains("keep.txt"));
    assert!(
        !body.contains("sub"),
        "rm sub left tracked descendants in the tree: {body}"
    );
}

#[test]
fn rm_normalizes_path_before_replacing_index_entry() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    fs::write(p.join("b.txt"), b"beta").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    ok(p, &["rm", "./b.txt"]);
    ok(p, &["commit", "-m", "drop b"]);

    let body = head_tree_body(p);
    assert!(body.contains("a.txt"));
    assert!(
        !body.contains("b.txt"),
        "rm ./b.txt wrote a non-matching tombstone: {body}"
    );
}

#[test]
fn rm_accepts_absolute_in_repo_path() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    fs::write(p.join("b.txt"), b"beta").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    let b_path = p.join("b.txt");
    let b_arg = b_path.to_str().unwrap();
    ok(p, &["rm", b_arg]);
    ok(p, &["commit", "-m", "drop b"]);

    let body = head_tree_body(p);
    assert!(body.contains("a.txt"));
    assert!(
        !body.contains("b.txt"),
        "rm absolute path wrote a non-matching tombstone: {body}"
    );
}

#[test]
fn rm_accepts_absolute_path_after_parent_directory_was_deleted() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("keep.txt"), b"keep").unwrap();
    fs::create_dir(p.join("sub")).unwrap();
    fs::write(p.join("sub/file.txt"), b"drop").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    let removed_path = p.join("sub/file.txt");
    let removed_arg = removed_path.to_str().unwrap();
    fs::remove_dir_all(p.join("sub")).unwrap();

    ok(p, &["rm", removed_arg]);
    ok(p, &["commit", "-m", "drop sub file"]);

    let body = head_tree_body(p);
    assert!(body.contains("keep.txt"));
    assert!(
        !body.contains("sub"),
        "rm absolute path with missing parent left subtree behind: {body}"
    );
}

#[test]
fn add_with_missing_index_seeds_from_head_before_commit() {
    let td = init_repo();
    let p = td.path();

    fs::write(p.join("a.txt"), b"alpha").unwrap();
    fs::write(p.join("b.txt"), b"beta").unwrap();
    ok(p, &["add", "."]);
    ok(p, &["commit", "-m", "first"]);

    fs::remove_file(p.join(".mkit/index")).unwrap();
    fs::write(p.join("a.txt"), b"alpha v2").unwrap();
    ok(p, &["add", "a.txt"]);
    ok(p, &["commit", "-m", "update a"]);

    let commit = head_commit(p);
    let tree = tree_of_commit(p, &commit);
    let cat = ok(p, &["cat", &tree]);
    let body = String::from_utf8(cat.stdout).unwrap();
    assert!(body.contains("a.txt"));
    assert!(
        body.contains("b.txt"),
        "missing-index add dropped unchanged tracked file: {body}"
    );
}
