//! Integration test for the history-recording fix in the fault-injection rollup: every CLI
//! ref-writing path must funnel through `commands::write_ref_recording_history`,
//! which on `--features history-mmr` builds opens a journaled
//! `CommitHistory` for the current branch and appends each new tip
//! to its on-disk MMR.
//!
//! This file is compiled only with `--features history-mmr` (a default
//! build has no history journal to inspect).

#![cfg(feature = "history-mmr")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use mkit_core::hash::Hash;
use mkit_core::history::{CommitHistory, TokioExecutor};
use mkit_core::refs;

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
        "mkit {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    out
}

fn init_repo() -> tempfile::TempDir {
    let td = tempfile::tempdir().unwrap();
    ok(td.path(), &["init"]);
    ok(td.path(), &["keygen"]);
    td
}

fn write_file(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, body).unwrap();
}

fn mkit_dir(root: &Path) -> PathBuf {
    root.join(mkit_core::MKIT_DIR)
}

/// Walk the branch's first-parent chain from the current tip back to the
/// root commit, returning the hashes in append order (oldest first).
fn branch_commit_chain(root: &Path, branch: &str) -> Vec<Hash> {
    use mkit_core::object::Object;
    use mkit_core::store::ObjectStore;
    let mkit_dir = mkit_dir(root);
    let store = ObjectStore::open(root).expect("open store");
    let tip = refs::read_ref(&mkit_dir, branch)
        .expect("read ref")
        .expect("ref present");
    let mut chain = Vec::new();
    let mut cursor = Some(tip);
    while let Some(h) = cursor {
        chain.push(h);
        let parent = match store.read_object(&h).expect("read object") {
            Object::Commit(c) => c.parents.first().copied(),
            Object::Remix(r) => r.parents.first().copied(),
            _ => panic!("expected Commit/Remix at {h:?}"),
        };
        cursor = parent;
    }
    chain.reverse();
    chain
}

#[test]
fn two_commits_land_in_branch_history_journal() {
    let td = init_repo();
    let root = td.path();

    // First commit.
    write_file(root, "alpha.txt", "alpha\n");
    ok(root, &["add", "alpha.txt"]);
    ok(root, &["commit", "-m", "alpha"]);

    // Second commit.
    write_file(root, "beta.txt", "beta\n");
    ok(root, &["add", "beta.txt"]);
    ok(root, &["commit", "-m", "beta"]);

    let mkit = mkit_dir(root);

    // The journal blob directory must exist under the documented
    // sanitized-partition layout (branch "main" → "main__journal-blobs").
    let journal_dir = mkit.join("history").join("main__journal-blobs");
    assert!(
        journal_dir.is_dir(),
        "journal blob dir absent at {} — write_ref_recording_history did not fire",
        journal_dir.display()
    );

    // Reopen the on-disk history journal and assert it carries
    // exactly two leaves, in the same order the CLI wrote the commits.
    let exec = Arc::new(TokioExecutor::new().expect("tokio runtime"));
    let live = CommitHistory::open_at(exec.clone(), &mkit, "main").expect("reopen live history");
    assert_eq!(
        live.len(),
        2,
        "two commits must produce exactly two leaves in main's MMR"
    );

    // Cross-check: a fresh, in-memory MMR built by replaying the same
    // commit chain (in append order) MUST produce the same root as
    // the on-disk journal. If `write_ref_recording_history` ever
    // silently degrades to a `refs::write_ref` call, the journal will
    // be empty / desynced and this equality breaks.
    let chain = branch_commit_chain(root, "main");
    assert_eq!(chain.len(), 2, "branch chain length sanity check");

    let mut mem = CommitHistory::open();
    for h in &chain {
        mem.append(h).expect("append to mem MMR");
    }
    assert_eq!(
        live.root(),
        mem.root(),
        "live journaled MMR root must equal a fresh manual append over the same chain"
    );
}
