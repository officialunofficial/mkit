//! Fault injection — multi-process lock contention.
//!
//! mkit serialises worktree mutations under a `flock`-backed lock file
//! (`.mkit/worktree.lock`, 5s acquire timeout → exit `TEMPFAIL`/75). Per
//! #635/INV-16, the lock's sentinel file is never unlinked and carries no
//! meaning by itself — only the kernel lock does — so a lockfile left behind
//! by a killed process does not block later commands (the kernel already
//! released its lock when the dead process's descriptor closed). These tests
//! assert that under concurrency the repo never corrupts, never deadlocks,
//! and never leaves a *held* lock behind — and pin that a merely-present,
//! unlocked sentinel does not wedge future acquires.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::fs;
use std::process::Output;
use std::thread;

use common::{Repo, check_invariants};

const TEMPFAIL: i32 = 75;

/// A repo with one commit (so HEAD exists for tag/update-ref) and N worker
/// files pre-created so `add file{i}` has something to stage.
fn repo_with_workers(n: usize) -> Repo {
    let repo = Repo::new();
    repo.commit_file("base.txt", b"base\n", "base");
    for i in 0..n {
        repo.write(&format!("file{i}.txt"), format!("w{i}\n").as_bytes());
    }
    repo
}

/// Every concurrent worker must end either applied (0) or lock-busy (75) — no
/// other exit code, no panic, no signal.
fn assert_lock_outcome(out: &Output, who: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked") && !stderr.contains("RUST_BACKTRACE"),
        "{who}: panic in stderr: {stderr}"
    );
    match out.status.code() {
        Some(0 | TEMPFAIL) => {}
        other => panic!("{who}: unexpected exit {other:?}; stderr: {stderr}"),
    }
}

#[test]
fn concurrent_independent_mutators_serialize_cleanly() {
    let n = 8;
    let repo = repo_with_workers(n);

    // Each worker runs ONE semantically-independent command, so the only
    // possible contention is the lock (→ outcome is strictly 0 or 75).
    thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let repo = &repo;
                s.spawn(move || {
                    let owned: Vec<String> = match i % 4 {
                        0 => vec!["tag".into(), format!("v{i}")],
                        1 => vec![
                            "update-ref".into(),
                            format!("refs/heads/worker{i}"),
                            "HEAD".into(),
                        ],
                        2 => vec!["add".into(), format!("file{i}.txt")],
                        _ => vec!["gc".into()],
                    };
                    let args: Vec<&str> = owned.iter().map(String::as_str).collect();
                    (i, repo.run(&args))
                })
            })
            .collect();
        for h in handles {
            let (i, out) = h.join().expect("worker thread panicked");
            assert_lock_outcome(&out, &format!("worker{i}"));
        }
    });

    // No corruption, and the lock was released by every holder (the sentinel
    // file itself is allowed to persist — see module doc — `check_invariants`
    // asserts nobody still holds it).
    check_invariants(repo.path(), "post-contention").unwrap();
}

#[test]
fn unlocked_stale_lockfile_does_not_block() {
    // #635/INV-16: a lockfile left behind by a crashed holder must not
    // permanently wedge future commands. The sentinel's mere on-disk
    // presence is not the mutual-exclusion signal — the kernel `flock` is
    // — so an inert leftover file (present, but nobody holds its lock, as
    // a SIGKILL'd process's lock would be released by the kernel) must
    // not block. Simulate the crashed-holder aftermath deterministically
    // by creating the file directly, with no lock ever taken on it — no
    // SIGKILL needed.
    let repo = repo_with_workers(0);
    let lock = repo.mkit_dir().join("worktree.lock");
    fs::write(&lock, b"").unwrap();

    repo.ok(&["tag", "blocked"]);
    check_invariants(repo.path(), "post-stale-lock").unwrap();
}

#[test]
fn publisher_vs_gc_never_corrupts() {
    // Root-publisher race (#267): a `tag -a` writes its object then publishes a
    // ref; a concurrent `gc --grace-secs 0` must not prune the just-written
    // object out from under it. They share the worktree lock, so each iteration
    // must leave the repo consistent and any created tag resolvable.
    let repo = repo_with_workers(0);
    let iters = 20;
    for k in 0..iters {
        let name = format!("rel{k}");
        thread::scope(|s| {
            let t_tag = {
                let repo = &repo;
                let name = name.clone();
                s.spawn(move || repo.run(&["tag", "-a", &name, "-m", "release"]))
            };
            let t_gc = {
                let repo = &repo;
                s.spawn(move || repo.run(&["gc", "--grace-secs", "0"]))
            };
            assert_lock_outcome(&t_tag.join().unwrap(), &format!("tag-a/{k}"));
            assert_lock_outcome(&t_gc.join().unwrap(), &format!("gc/{k}"));
        });
        // The repo stays consistent every iteration (the live-set check would
        // catch a tag object pruned out from under the publisher).
        check_invariants(repo.path(), &format!("publisher-vs-gc/{k}")).unwrap();
    }
}
