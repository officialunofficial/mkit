//! push + pull must transfer the full object closure, not just ref
//! pointers. Integration test: repo A commits two files and pushes;
//! repo B pulls; all commit/tree/blob objects end up in repo B.

use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::sync::Arc;

use mkit_cli::remote_dispatch::{fetch_all, pull_all, push_all};
use mkit_core::ops::reachable_objects;
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use mkit_transport_memory::MemoryTransport;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn mkit")
}

#[test]
fn push_pull_transfers_full_object_closure_via_memory_transport() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());

    fs::write(alice.path().join("README.md"), b"# project\n").unwrap();
    fs::create_dir_all(alice.path().join("src")).unwrap();
    fs::write(alice.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "alice-1"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());

    // Push alice → remote.
    let pushed = push_all(alice.path(), tx.as_ref()).expect("push");
    assert!(pushed >= 1);

    // Pull remote → bob.
    let pulled = pull_all(bob.path(), tx.as_ref()).expect("pull");
    assert_eq!(pulled, pushed);

    // Alice and Bob now hold exactly the same object set reachable
    // from their shared `refs/heads/main` tip.
    let alice_mkit = alice.path().join(".mkit");
    let bob_mkit = bob.path().join(".mkit");
    let alice_tip = refs::read_ref(&alice_mkit, "main").unwrap().unwrap();
    let bob_tip = refs::read_ref(&bob_mkit, "main").unwrap().unwrap();
    assert_eq!(alice_tip, bob_tip);

    let alice_store = ObjectStore::open(alice.path()).unwrap();
    let bob_store = ObjectStore::open(bob.path()).unwrap();
    let alice_set: HashSet<_> = reachable_objects(&alice_store, &alice_tip)
        .unwrap()
        .into_iter()
        .collect();
    let bob_set: HashSet<_> = reachable_objects(&bob_store, &bob_tip)
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(alice_set, bob_set, "object closures must match after pull");
    assert!(
        alice_set.len() >= 4,
        "closure must include ≥ commit+tree+2 blobs"
    );
}

#[test]
fn fetch_all_does_not_move_bob_head() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());

    fs::write(alice.path().join("a.txt"), b"alpha").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "alice-1"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();

    // Read bob's HEAD before fetch.
    let bob_mkit = bob.path().join(".mkit");
    let head_before = fs::read_to_string(bob_mkit.join("HEAD")).unwrap_or_default();

    let n = fetch_all(bob.path(), tx.as_ref()).expect("fetch");
    assert!(n >= 1);

    // HEAD unchanged by fetch.
    let head_after = fs::read_to_string(bob_mkit.join("HEAD")).unwrap_or_default();
    assert_eq!(head_before, head_after, "fetch MUST NOT rewrite HEAD");

    // But refs/heads/main is set.
    assert!(bob_mkit.join("refs/heads/main").exists());
}
