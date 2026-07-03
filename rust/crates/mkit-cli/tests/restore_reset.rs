//! PR-C integration tests (#212): `mkit restore` and `mkit reset`.
//!
//! Covered behaviours:
//! - `restore --staged <path>` unstages (the index entry reverts to HEAD)
//!   while the worktree file is left as-is.
//! - `restore <path>` discards an un-staged worktree edit by restoring
//!   from the index, but refuses (without `--force`) when that would
//!   clobber an un-staged change; `--force` overrides.
//! - `reset --soft` moves HEAD/branch only (index/worktree untouched).
//! - `reset --mixed` (default) moves HEAD and resets the index to the
//!   target tree, leaving the worktree.
//! - `reset` resolves `<commit>` as a short hash, branch name, and
//!   `HEAD~1` via the shared revspec resolver.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("spawn mkit")
}

fn ok(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    let out = run(cwd, xdg, args);
    assert!(
        out.status.success(),
        "expected `mkit {}` to succeed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn fail(cwd: &Path, xdg: &Path, args: &[&str]) -> Output {
    let out = run(cwd, xdg, args);
    assert!(
        !out.status.success(),
        "expected `mkit {}` to fail but it succeeded",
        args.join(" ")
    );
    out
}

struct Repo {
    dir: tempfile::TempDir,
    xdg: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let xdg = tempfile::tempdir().unwrap();
        ok(dir.path(), xdg.path(), &["init"]);
        ok(dir.path(), xdg.path(), &["keygen"]);
        Repo { dir, xdg }
    }
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn xdg(&self) -> &Path {
        self.xdg.path()
    }
    fn write(&self, rel: &str, body: &[u8]) {
        let p = self.path().join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, body).unwrap();
    }
    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path().join(rel)).unwrap()
    }
    fn add(&self, rel: &str) {
        ok(self.path(), self.xdg(), &["add", rel]);
    }
    fn commit(&self, msg: &str) {
        ok(self.path(), self.xdg(), &["commit", "-m", msg]);
    }
    fn commit_file(&self, rel: &str, body: &[u8], msg: &str) {
        self.write(rel, body);
        self.add(rel);
        self.commit(msg);
    }
    /// The current HEAD commit hash (full hex) via `log --format=json`.
    /// The first JSONL record's leading field is `"hash":"<64-hex>"`.
    fn head_hash(&self) -> String {
        let out = ok(
            self.path(),
            self.xdg(),
            &["log", "--format=json", "-n", "1"],
        );
        let line = String::from_utf8(out.stdout).unwrap();
        let first = line.lines().next().expect("log produced no output");
        let needle = "\"hash\":\"";
        let start = first.find(needle).expect("log json has hash field") + needle.len();
        first[start..start + 64].to_string()
    }
    /// Whether `status --porcelain` reports a staged change for `path`.
    fn status_porcelain(&self) -> String {
        let out = ok(self.path(), self.xdg(), &["status", "--porcelain"]);
        String::from_utf8(out.stdout).unwrap()
    }
}

/// `restore --staged <path>` reverts the index entry to HEAD while the
/// worktree file keeps its new content.
#[test]
fn restore_staged_unstages_leaving_worktree() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"v1\n", "base");

    // Stage a change.
    repo.write("a.txt", b"v2-staged\n");
    repo.add("a.txt");
    // Sanity: the change is staged (X column = 'M').
    let before = repo.status_porcelain();
    assert!(
        before.contains("M  a.txt"),
        "expected a.txt to be staged-modified before restore: {before:?}"
    );

    // Unstage it.
    ok(repo.path(), repo.xdg(), &["restore", "--staged", "a.txt"]);

    // The worktree file is unchanged (the edit survives).
    assert_eq!(
        repo.read("a.txt"),
        "v2-staged\n",
        "restore --staged must not touch the worktree file"
    );

    // The index entry reverted to HEAD: the edit is now an UN-staged
    // worktree modification (Y column = 'M'), not a staged one.
    let porcelain = repo.status_porcelain();
    assert!(
        porcelain.contains(" M a.txt"),
        "after unstage, a.txt must be reported as unstaged-modified: {porcelain:?}"
    );
    assert!(
        !porcelain.contains("M  a.txt"),
        "after unstage, a.txt must NOT be staged-modified: {porcelain:?}"
    );
}

/// `restore <path>` discards an un-staged worktree edit by restoring the
/// file from the staged (index) content.
#[test]
fn restore_worktree_discards_unstaged_edit_from_index() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"committed\n", "base");

    // Stage a new version, then make a *further* un-staged worktree edit.
    repo.write("a.txt", b"staged\n");
    repo.add("a.txt");
    repo.write("a.txt", b"dirty-unstaged\n");

    // restore (no --staged) must refuse: it would clobber the un-staged
    // edit (worktree differs from the index).
    let out = fail(repo.path(), repo.xdg(), &["restore", "a.txt"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unstaged") || stderr.contains("force"),
        "expected restore to refuse clobbering an un-staged edit: {stderr}"
    );
    assert_eq!(repo.read("a.txt"), "dirty-unstaged\n", "file untouched");

    // --force discards the un-staged edit, restoring the staged content.
    ok(repo.path(), repo.xdg(), &["restore", "--force", "a.txt"]);
    assert_eq!(
        repo.read("a.txt"),
        "staged\n",
        "restore --force must restore the staged content"
    );
}

/// `restore <path>` refuses to clobber an unstaged worktree edit even
/// when the index is clean (== HEAD): the worktree differs from the
/// index, so restore demands `--force`; with it, the committed content
/// comes back.
#[test]
fn restore_unstaged_edit_requires_force_even_with_clean_index() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"committed\n", "base");

    // Edit the worktree but do NOT stage it. The index still matches HEAD,
    // so the worktree differs from the index — restore needs --force.
    repo.write("a.txt", b"local-edit\n");
    let refused = fail(repo.path(), repo.xdg(), &["restore", "a.txt"]);
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("force"),
        "an un-staged worktree edit is refused without --force"
    );
    ok(repo.path(), repo.xdg(), &["restore", "--force", "a.txt"]);
    assert_eq!(
        repo.read("a.txt"),
        "committed\n",
        "restore --force brings back the committed content"
    );
}

/// `reset --soft` moves the branch tip but leaves the index and worktree
/// untouched — the difference shows up as a staged change.
#[test]
fn reset_soft_moves_head_only() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "c1");
    let c1 = repo.head_hash();
    repo.commit_file("a.txt", b"two\n", "c2");

    // Soft-reset back to c1.
    ok(repo.path(), repo.xdg(), &["reset", "--soft", &c1]);

    // HEAD moved.
    assert_eq!(repo.head_hash(), c1, "reset --soft must move HEAD to c1");
    // Worktree is untouched (still the c2 content).
    assert_eq!(repo.read("a.txt"), "two\n", "worktree untouched by --soft");
    // The index still holds c2's tree, so a.txt shows as a STAGED change
    // (X column = 'M') relative to the now-current HEAD (c1).
    let porcelain = repo.status_porcelain();
    assert!(
        porcelain.contains("M  a.txt"),
        "soft reset leaves c2's content staged vs c1: {porcelain:?}"
    );
}

/// `reset --mixed` (and the bare default) moves HEAD and resets the index
/// to the target tree, leaving the worktree.
#[test]
fn reset_mixed_moves_head_and_index() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "c1");
    let c1 = repo.head_hash();
    repo.commit_file("a.txt", b"two\n", "c2");

    // Mixed-reset back to c1.
    ok(repo.path(), repo.xdg(), &["reset", "--mixed", &c1]);
    assert_eq!(repo.head_hash(), c1, "reset --mixed must move HEAD to c1");

    // Worktree untouched (still c2).
    assert_eq!(repo.read("a.txt"), "two\n", "worktree untouched by --mixed");

    // Index was reset to c1's tree, so the c2 content now shows as an
    // UN-staged worktree modification (Y column = 'M'), NOT staged.
    let porcelain = repo.status_porcelain();
    assert!(
        porcelain.contains(" M a.txt"),
        "mixed reset leaves a.txt as an unstaged worktree change: {porcelain:?}"
    );
    assert!(
        !porcelain.contains("M  a.txt"),
        "mixed reset must clear the staged entry for a.txt: {porcelain:?}"
    );
}

/// `reset` (bare, default mixed) targeting `HEAD` re-syncs the index to
/// HEAD's tree without moving the branch.
#[test]
fn reset_default_target_is_head() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"one\n", "c1");
    let head = repo.head_hash();

    // Stage an extra change, then `reset` with no target — index reverts
    // to HEAD's tree, HEAD stays put.
    repo.write("b.txt", b"new\n");
    repo.add("b.txt");
    ok(repo.path(), repo.xdg(), &["reset"]);
    assert_eq!(repo.head_hash(), head, "bare reset must not move HEAD");
    // b.txt is no longer staged (index == HEAD tree), so it is untracked
    // ('??') in the worktree, not staged-added ('A ').
    let porcelain = repo.status_porcelain();
    assert!(
        porcelain.contains("?? b.txt"),
        "b.txt should now be untracked after reset: {porcelain:?}"
    );
    assert!(
        !porcelain.contains("A  b.txt"),
        "reset must clear the staged-add of b.txt: {porcelain:?}"
    );
}

/// `reset` resolves the target through the shared revspec resolver:
/// short-hash, branch name, and `HEAD~1` all work.
#[test]
fn reset_resolves_short_hash_branch_and_relative() {
    // Short hash.
    {
        let repo = Repo::new();
        repo.commit_file("a.txt", b"one\n", "c1");
        let c1 = repo.head_hash();
        repo.commit_file("a.txt", b"two\n", "c2");
        let short = &c1[..12];
        ok(repo.path(), repo.xdg(), &["reset", "--soft", short]);
        assert_eq!(repo.head_hash(), c1, "short-hash target must resolve");
    }
    // Branch name.
    {
        let repo = Repo::new();
        repo.commit_file("a.txt", b"one\n", "c1");
        let c1 = repo.head_hash();
        ok(repo.path(), repo.xdg(), &["branch", "saved"]);
        repo.commit_file("a.txt", b"two\n", "c2");
        ok(repo.path(), repo.xdg(), &["reset", "--soft", "saved"]);
        assert_eq!(repo.head_hash(), c1, "branch-name target must resolve");
    }
    // HEAD~1.
    {
        let repo = Repo::new();
        repo.commit_file("a.txt", b"one\n", "c1");
        let c1 = repo.head_hash();
        repo.commit_file("a.txt", b"two\n", "c2");
        ok(repo.path(), repo.xdg(), &["reset", "--soft", "HEAD~1"]);
        assert_eq!(repo.head_hash(), c1, "HEAD~1 target must resolve");
    }
}
