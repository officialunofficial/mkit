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
