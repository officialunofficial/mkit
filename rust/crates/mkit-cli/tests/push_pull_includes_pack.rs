//! push + pull must transfer the full object closure, not just ref
//! pointers. Integration test: repo A commits two files and pushes;
//! repo B pulls; all commit/tree/blob objects end up in repo B.

use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::sync::Arc;

use mkit_cli::remote_dispatch::{DispatchError, fetch_all, pull_all, push_all};
use mkit_core::ops::reachable_objects;
use mkit_core::refs;
use mkit_core::store::ObjectStore;
use mkit_transport_memory::MemoryTransport;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    out
}

#[test]
fn push_pull_transfers_full_object_closure_via_memory_transport() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

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
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

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

    // Fetch records the remote tip without clobbering local heads.
    assert!(!bob_mkit.join("refs/heads/main").exists());
    assert!(bob_mkit.join("refs/remotes/default/main").exists());
}

#[test]
fn fetch_all_does_not_overwrite_local_branch() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

    fs::write(alice.path().join("a.txt"), b"alice").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "alice"])
            .status
            .success()
    );

    fs::write(bob.path().join("b.txt"), b"bob").unwrap();
    assert!(run_in(bob.path(), &["add", "."]).status.success());
    assert!(
        run_in(bob.path(), &["commit", "-m", "bob"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();
    let bob_mkit = bob.path().join(".mkit");
    let bob_before = refs::read_ref(&bob_mkit, "main").unwrap().unwrap();

    let n = fetch_all(bob.path(), tx.as_ref()).expect("fetch");
    assert!(n >= 1);

    let bob_after = refs::read_ref(&bob_mkit, "main").unwrap().unwrap();
    let remote_main = refs::read_remote_ref(&bob_mkit, "default", "main")
        .unwrap()
        .unwrap();
    assert_eq!(bob_before, bob_after, "fetch must not move local main");
    assert_ne!(bob_after, remote_main, "remote-tracking ref should differ");
}

#[test]
fn pull_all_fast_forwards_current_branch() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v1"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();
    pull_all(bob.path(), tx.as_ref()).expect("initial pull");

    fs::write(alice.path().join("a.txt"), b"v2").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v2"])
            .status
            .success()
    );
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();

    pull_all(bob.path(), tx.as_ref()).expect("fast-forward pull");

    let alice_tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let bob_tip = refs::read_ref(&bob.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    assert_eq!(alice_tip, bob_tip);
    assert_eq!(fs::read(bob.path().join("a.txt")).unwrap(), b"v2");
}

#[test]
fn pull_all_refuses_divergent_current_branch() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v1"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();
    pull_all(bob.path(), tx.as_ref()).expect("initial pull");

    fs::write(alice.path().join("a.txt"), b"alice v2").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "alice-v2"])
            .status
            .success()
    );
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();

    fs::write(bob.path().join("a.txt"), b"bob v2").unwrap();
    assert!(run_in(bob.path(), &["add", "."]).status.success());
    assert!(
        run_in(bob.path(), &["commit", "-m", "bob-v2"])
            .status
            .success()
    );
    let bob_tip = refs::read_ref(&bob.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();

    let err = pull_all(bob.path(), tx.as_ref()).unwrap_err();
    assert!(matches!(err, DispatchError::NonFastForwardPull { .. }));
    assert_eq!(
        refs::read_ref(&bob.path().join(".mkit"), "main")
            .unwrap()
            .unwrap(),
        bob_tip
    );
}

#[test]
fn pull_all_refuses_dirty_worktree_before_fast_forward() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v1"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();
    pull_all(bob.path(), tx.as_ref()).expect("initial pull");

    fs::write(alice.path().join("a.txt"), b"v2").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v2"])
            .status
            .success()
    );
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();

    fs::write(bob.path().join("a.txt"), b"local dirty").unwrap();
    let bob_tip = refs::read_ref(&bob.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();

    let err = pull_all(bob.path(), tx.as_ref()).unwrap_err();
    assert!(matches!(err, DispatchError::RestoreSafety(_)));
    assert_eq!(fs::read(bob.path().join("a.txt")).unwrap(), b"local dirty");
    assert_eq!(
        refs::read_ref(&bob.path().join(".mkit"), "main")
            .unwrap()
            .unwrap(),
        bob_tip
    );
}

#[cfg(unix)]
#[test]
fn pull_all_ref_update_failure_does_not_restore_worktree() {
    use std::os::unix::fs::PermissionsExt;

    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v1"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();
    pull_all(bob.path(), tx.as_ref()).expect("initial pull");

    fs::write(alice.path().join("a.txt"), b"v2").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v2"])
            .status
            .success()
    );
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();

    let bob_mkit = bob.path().join(".mkit");
    let bob_tip = refs::read_ref(&bob_mkit, "main").unwrap().unwrap();
    let heads_dir = bob_mkit.join("refs/heads");
    let original_perms = fs::metadata(&heads_dir).unwrap().permissions();
    let mut readonly = original_perms.clone();
    readonly.set_mode(0o555);
    fs::set_permissions(&heads_dir, readonly).unwrap();

    let err = pull_all(bob.path(), tx.as_ref()).unwrap_err();

    fs::set_permissions(&heads_dir, original_perms).unwrap();

    assert!(
        matches!(err, DispatchError::Refs(_)),
        "unexpected error: {err}"
    );
    assert_eq!(fs::read(bob.path().join("a.txt")).unwrap(), b"v1");
    assert_eq!(refs::read_ref(&bob_mkit, "main").unwrap().unwrap(), bob_tip);
}

#[test]
fn pull_all_preserves_ignored_untracked_files() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();

    assert!(run_in(alice.path(), &["init"]).status.success());
    assert!(run_in(alice.path(), &["keygen"]).status.success());
    assert!(run_in(bob.path(), &["init"]).status.success());
    assert!(run_in(bob.path(), &["keygen"]).status.success());

    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v1"])
            .status
            .success()
    );

    let tx: Arc<MemoryTransport> = Arc::new(MemoryTransport::new());
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();
    pull_all(bob.path(), tx.as_ref()).expect("initial pull");

    fs::write(alice.path().join("a.txt"), b"v2").unwrap();
    assert!(run_in(alice.path(), &["add", "."]).status.success());
    assert!(
        run_in(alice.path(), &["commit", "-m", "v2"])
            .status
            .success()
    );
    let _ = push_all(alice.path(), tx.as_ref()).unwrap();

    fs::write(bob.path().join(".mkitignore"), "local.txt\n").unwrap();
    fs::write(bob.path().join("local.txt"), b"local only\n").unwrap();

    pull_all(bob.path(), tx.as_ref()).expect("fast-forward pull");

    assert_eq!(fs::read(bob.path().join("a.txt")).unwrap(), b"v2");
    assert_eq!(
        fs::read(bob.path().join("local.txt")).unwrap(),
        b"local only\n"
    );
    assert_eq!(
        fs::read_to_string(bob.path().join(".mkitignore")).unwrap(),
        "local.txt\n"
    );
}
