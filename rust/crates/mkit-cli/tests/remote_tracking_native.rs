//! Native remote-tracking prerequisites: remote-tracking refs are
//! first-class citizens of revspec/merge/show-ref/for-each-ref,
//! printable opaque identities render as text, replays preserve
//! authorship, and `remote rename/remove` cleans tracking refs.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use common::Repo;
use mkit_core::object::{Identity, Object};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

/// Simulate a fetched tracking ref pointing at a commit ahead of HEAD.
fn plant_tracking_ref(r: &Repo, remote: &str, branch: &str) -> mkit_core::Hash {
    // Advance main, record the tip as the "remote" position, then move
    // main back so the tracking ref is strictly ahead.
    let mkit_dir = r.mkit_dir();
    let before = refs::read_ref(&mkit_dir, "main").unwrap().unwrap();
    r.commit_file("ahead.txt", b"ahead\n", "remote is ahead");
    let ahead = refs::read_ref(&mkit_dir, "main").unwrap().unwrap();
    refs::write_remote_ref(&mkit_dir, remote, branch, &ahead).unwrap();
    // Rewind main (guarded reset path not needed for test setup).
    refs::write_ref(&mkit_dir, "main", &before).unwrap();
    let store = ObjectStore::open(r.path()).unwrap();
    let Object::Commit(c) = store.read_object(&before).unwrap() else {
        panic!("not a commit")
    };
    let tree = c.tree_hash;
    drop(store);
    // Restore worktree to match the rewound HEAD so merge sees clean state.
    let out = r.run(&["reset", "--hard", "-f", &mkit_core::to_hex(&before)]);
    assert!(out.status.success(), "reset: {out:?}");
    let _ = tree;
    ahead
}

#[test]
fn merge_fast_forwards_from_tracking_ref() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let ahead = plant_tracking_ref(&r, "up", "main");

    // Short form `<remote>/<branch>` resolves and fast-forwards.
    let out = r.ok(&["merge", "up/main"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("fast-forward"),
        "stderr: {stderr}"
    );
    assert_eq!(
        refs::read_ref(&r.mkit_dir(), "main").unwrap().unwrap(),
        ahead
    );
}

#[test]
fn revspec_resolves_remote_tracking_forms() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let ahead = plant_tracking_ref(&r, "up", "main");
    let hex = mkit_core::to_hex(&ahead);

    for spec in ["up/main", "refs/remotes/up/main"] {
        let out = r.ok(&["rev-parse", spec]);
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            hex,
            "spec {spec}"
        );
    }
    // Suffix navigation works on tracking refs too.
    let out = r.ok(&["rev-parse", "up/main~1"]);
    assert_ne!(String::from_utf8_lossy(&out.stdout).trim(), hex);
}

#[test]
fn show_ref_and_for_each_ref_list_tracking_refs() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    plant_tracking_ref(&r, "up", "main");

    let out = r.ok(&["show-ref"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("refs/remotes/up/main"),
        "show-ref: {stdout}"
    );
    // --heads keeps its narrow meaning.
    let out = r.ok(&["show-ref", "--heads"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("refs/remotes/"), "--heads: {stdout}");

    let out = r.ok(&["for-each-ref"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("refs/remotes/up/main"),
        "for-each-ref: {stdout}"
    );
}

#[test]
fn printable_opaque_author_renders_as_text() {
    let r = Repo::new();
    r.write("a.txt", b"a\n");
    r.ok(&["add", "a.txt"]);
    r.ok(&[
        "commit",
        "-m",
        "imported-style author",
        "--author",
        "opaque:Alice Example <alice@example.com>",
    ]);
    let out = r.ok(&["log", "-n", "1"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Author: Alice Example <alice@example.com>"),
        "log: {stdout}"
    );
}

#[test]
fn cherry_pick_preserves_author_and_timestamp() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    r.ok(&["branch", "side"]);
    r.ok(&["checkout", "side"]);
    r.write("b.txt", b"b\n");
    r.ok(&["add", "b.txt"]);
    r.ok(&[
        "commit",
        "-m",
        "side work",
        "--author",
        "opaque:Original Author <orig@example.com>",
    ]);
    let mkit_dir = r.mkit_dir();
    let picked = refs::read_ref(&mkit_dir, "side").unwrap().unwrap();
    let store = ObjectStore::open(r.path()).unwrap();
    let Object::Commit(orig) = store.read_object(&picked).unwrap() else {
        panic!("not a commit")
    };

    r.ok(&["checkout", "main"]);
    // Advance main so the replay gets a different parent (with an
    // identical parent, deterministic signing + preserved authorship
    // reproduce the byte-identical commit — content addressing dedupes).
    r.commit_file("main2.txt", b"m\n", "main advances");
    r.ok(&["cherry-pick", &mkit_core::to_hex(&picked)]);

    let tip = refs::resolve_head(&mkit_dir).unwrap().unwrap();
    let Object::Commit(replayed) = store.read_object(&tip).unwrap() else {
        panic!("not a commit")
    };
    assert_eq!(
        replayed.author,
        Identity::opaque(b"Original Author <orig@example.com>".to_vec())
    );
    assert_eq!(replayed.timestamp, orig.timestamp);
    assert_ne!(tip, picked, "replay must be a new commit");
}

#[test]
fn remote_rename_moves_and_remove_deletes_tracking_refs() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let mkit_dir = r.mkit_dir();
    let tip = refs::read_ref(&mkit_dir, "main").unwrap().unwrap();
    refs::write_remote_ref(&mkit_dir, "old", "main", &tip).unwrap();

    // Named remote in config so rename/remove operate on it.
    r.ok(&["remote", "add", "old", "mkit+file:///tmp/nowhere"]);
    r.ok(&["remote", "rename", "old", "new"]);
    assert!(
        refs::read_remote_ref(&mkit_dir, "new", "main")
            .unwrap()
            .is_some(),
        "rename must move tracking refs"
    );
    assert!(
        refs::read_remote_ref(&mkit_dir, "old", "main")
            .unwrap()
            .is_none()
    );

    r.ok(&["remote", "remove", "new"]);
    assert!(
        refs::read_remote_ref(&mkit_dir, "new", "main")
            .unwrap()
            .is_none(),
        "remove must delete tracking refs"
    );
}

#[test]
fn named_remote_fetch_and_pull_use_their_namespace() {
    // Origin repo with one commit, exposed over mkit+file://.
    let origin = Repo::new();
    origin.commit_file("a.txt", b"a\n", "origin base");
    let origin_store = origin.path().join("store");
    std::fs::create_dir_all(&origin_store).unwrap();
    let url = format!("mkit+file://{}", origin_store.display());
    origin.ok(&["remote", "add", &url]);
    origin.ok(&["push", "--all"]);

    // Consumer adds it as a NAMED remote and fetches.
    let consumer = Repo::new();
    consumer.commit_file("local.txt", b"l\n", "local base");
    consumer.ok(&["remote", "add", "origin", &url]);
    let out = consumer.ok(&["fetch", "origin"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // git-shaped: `From <url>` + a per-ref summary line for the new branch.
    assert!(stderr.contains("From "), "fetch: {stderr}");
    assert!(stderr.contains("origin/main"), "fetch summary: {stderr}");
    assert!(
        refs::read_remote_ref(&consumer.mkit_dir(), "origin", "main")
            .unwrap()
            .is_some(),
        "named fetch must write refs/remotes/origin/*"
    );
    // Unknown name errors cleanly.
    let out = consumer.run(&["fetch", "nope"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown remote 'nope'"));
}
