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
