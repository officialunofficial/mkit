//! PR-A integration tests.
//!
//! - #205: `stash pop` runs the #176 destructive-restore guard before
//!   restoring, so a dirty unrelated file is never clobbered and the
//!   stash entry survives a refused pop.
//! - #222: the `worktree.lock` serialises mutating commands — a second
//!   mutator blocks on the held lock and ultimately fails rather than
//!   racing the worktree/index.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

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
    fn mkit_dir(&self) -> std::path::PathBuf {
        self.path().join(".mkit")
    }
}

/// #205: `stash pop` must run the destructive-restore guard before it
/// touches the worktree. A dirty UNRELATED tracked file must block the
/// pop, the file must be left untouched, and the stash entry must remain
/// so the user can retry after cleaning up.
#[test]
fn stash_pop_refuses_and_preserves_entry_when_unrelated_file_dirty() {
    let repo = Repo::new();
    // Two tracked files committed.
    repo.commit_file("tracked.txt", b"v1\n", "base tracked");
    repo.commit_file("other.txt", b"orig\n", "base other");

    // Modify tracked.txt and stash it (worktree resets to committed v1).
    repo.write("tracked.txt", b"stashed-change\n");
    repo.add("tracked.txt");
    ok(repo.path(), repo.xdg(), &["stash", "-m", "wip"]);

    // The stash entry exists.
    let listed = ok(repo.path(), repo.xdg(), &["stash", "list"]);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("stash@{0}"),
        "stash entry must exist after save"
    );

    // Dirty an UNRELATED tracked file with uncommitted edits.
    repo.write("other.txt", b"precious-uncommitted\n");

    // Pop must be refused by the #176 guard.
    let out = fail(repo.path(), repo.xdg(), &["stash", "pop"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("overwrite") || stderr.contains("local changes"),
        "expected stash pop to be refused on dirty unrelated file, got: {stderr}"
    );

    // The dirty unrelated file is untouched...
    assert_eq!(
        fs::read_to_string(repo.path().join("other.txt")).unwrap(),
        "precious-uncommitted\n",
        "refused pop must not clobber the dirty unrelated file (#205)"
    );
    // ...and the stash entry survives for a retry.
    let listed = ok(repo.path(), repo.xdg(), &["stash", "list"]);
    assert!(
        String::from_utf8_lossy(&listed.stdout).contains("stash@{0}"),
        "stash entry must survive a refused pop (#205)"
    );
}

/// #205 happy path: with a clean worktree, `stash pop` restores the
/// stashed content and drops the entry.
#[test]
fn stash_pop_succeeds_on_clean_worktree() {
    let repo = Repo::new();
    repo.commit_file("tracked.txt", b"v1\n", "base");
    repo.write("tracked.txt", b"stashed-change\n");
    repo.add("tracked.txt");
    ok(repo.path(), repo.xdg(), &["stash", "-m", "wip"]);

    // Worktree was reset to v1 by the stash save.
    assert_eq!(
        fs::read_to_string(repo.path().join("tracked.txt")).unwrap(),
        "v1\n"
    );

    ok(repo.path(), repo.xdg(), &["stash", "pop"]);
    assert_eq!(
        fs::read_to_string(repo.path().join("tracked.txt")).unwrap(),
        "stashed-change\n",
        "pop must restore the stashed content"
    );
    // Entry dropped.
    let listed = ok(repo.path(), repo.xdg(), &["stash", "list"]);
    assert!(
        !String::from_utf8_lossy(&listed.stdout).contains("stash@{0}"),
        "stash entry must be dropped after a successful pop"
    );
}

/// #222: while the worktree lock is held, a second mutating command must
/// block on it and then fail (TEMPFAIL) rather than racing the
/// worktree/index. We acquire the lock directly (the same helper the CLI
/// uses) and assert a concurrent `mkit add` blocks for roughly the lock
/// timeout before failing.
// #505 PR 5/5: blocks the full ~5s default lock timeout every run —
// quarantined to the serial `--ignored` CI lane (cloudbuild/ci.yaml,
// .github/workflows/rust.yml) instead of paying that wait on every
// `cargo test`.
#[test]
#[ignore = "blocks the full ~5s worktree-lock timeout; run via the serial --ignored CI lane"]
fn second_mutating_command_blocks_on_worktree_lock() {
    let repo = Repo::new();
    repo.commit_file("a.txt", b"a\n", "base");
    repo.write("b.txt", b"b\n");

    let mkit_dir = repo.mkit_dir();
    // Hold the worktree lock for the duration of the command attempt.
    let held =
        mkit_core::repo_lock::acquire_default(&mkit_dir, "worktree.lock").expect("acquire lock");

    let start = Instant::now();
    let out = run(repo.path(), repo.xdg(), &["add", "b.txt"]);
    let elapsed = start.elapsed();

    assert!(
        !out.status.success(),
        "a mutating command must fail while the worktree lock is held"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("repo lock") || stderr.contains("busy"),
        "expected a lock-contention error, got: {stderr}"
    );
    // It should have waited (blocked) for a non-trivial slice of the
    // default ~5s timeout rather than failing instantly.
    assert!(
        elapsed >= Duration::from_secs(1),
        "expected the second mutator to block on the lock, waited only {elapsed:?}"
    );

    drop(held);
    // After release, the same command succeeds.
    ok(repo.path(), repo.xdg(), &["add", "b.txt"]);
}
