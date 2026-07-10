//! Native remote-tracking prerequisites: remote-tracking refs are
//! first-class citizens of revspec/merge/show-ref/for-each-ref,
//! printable opaque identities render as text, replays preserve
//! authorship, and `remote rename/remove` cleans tracking refs.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use common::Repo;
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Identity, Object};
use mkit_core::refs;
use mkit_core::store::ObjectStore;

/// Simulate a fetched tracking ref pointing at a commit ahead of HEAD.
fn plant_tracking_ref(r: &Repo, remote: &str, branch: &str) -> mkit_core::Hash {
    // Advance main, record the tip as the "remote" position, then move
    // main back so the tracking ref is strictly ahead.
    let layout = RepoLayout::single(r.path());
    let before = refs::read_ref(&layout, "main").unwrap().unwrap();
    r.commit_file("ahead.txt", b"ahead\n", "remote is ahead");
    let ahead = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, remote, branch, &ahead).unwrap();
    // Rewind main (guarded reset path not needed for test setup).
    refs::write_ref(&layout, "main", &before).unwrap();
    let store = ObjectStore::open(&layout).unwrap();
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
        refs::read_ref(&RepoLayout::single(r.path()), "main")
            .unwrap()
            .unwrap(),
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
    let layout = RepoLayout::single(r.path());
    let picked = refs::read_ref(&layout, "side").unwrap().unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    let Object::Commit(orig) = store.read_object(&picked).unwrap() else {
        panic!("not a commit")
    };

    r.ok(&["checkout", "main"]);
    // Advance main so the replay gets a different parent (with an
    // identical parent, deterministic signing + preserved authorship
    // reproduce the byte-identical commit — content addressing dedupes).
    r.commit_file("main2.txt", b"m\n", "main advances");
    r.ok(&["cherry-pick", &mkit_core::to_hex(&picked)]);

    let tip = refs::resolve_head(&layout).unwrap().unwrap();
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
    let layout = RepoLayout::single(r.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, "old", "main", &tip).unwrap();

    // Named remote in config so rename/remove operate on it.
    r.ok(&["remote", "add", "old", "mkit+file:///tmp/nowhere"]);
    r.ok(&["remote", "rename", "old", "new"]);
    assert!(
        refs::read_remote_ref(&layout, "new", "main")
            .unwrap()
            .is_some(),
        "rename must move tracking refs"
    );
    assert!(
        refs::read_remote_ref(&layout, "old", "main")
            .unwrap()
            .is_none()
    );

    r.ok(&["remote", "remove", "new"]);
    assert!(
        refs::read_remote_ref(&layout, "new", "main")
            .unwrap()
            .is_none(),
        "remove must delete tracking refs"
    );
}

/// Plant a marker file under `.mkit/git/<name>/` to stand in for
/// bridge state (leases/maps/staging mirror) without needing a real
/// git-bridge remote wired up.
fn plant_bridge_state(layout: &RepoLayout, name: &str) -> std::path::PathBuf {
    let dir = layout.git_state_dir().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("marker.txt");
    std::fs::write(&marker, b"bridge state\n").unwrap();
    marker
}

#[test]
fn remote_rename_single_to_multi_segment_moves_refs_and_bridge_state() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let layout = RepoLayout::single(r.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, "a", "main", &tip).unwrap();
    plant_bridge_state(&layout, "a");

    r.ok(&["remote", "add", "a", "mkit+file:///tmp/nowhere"]);
    let out = r.ok(&["remote", "rename", "a", "team/upstream"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("could not move"),
        "single->multi-segment rename must not degrade: {stderr}"
    );

    assert!(
        refs::read_remote_ref(&layout, "team/upstream", "main")
            .unwrap()
            .is_some(),
        "rename must move tracking refs into the nested destination"
    );
    assert!(
        refs::read_remote_ref(&layout, "a", "main")
            .unwrap()
            .is_none()
    );

    let moved_marker = layout.git_state_dir().join("team/upstream/marker.txt");
    assert!(
        moved_marker.exists(),
        "bridge state must move into the nested destination"
    );
    assert_eq!(
        std::fs::read(&moved_marker).unwrap(),
        b"bridge state\n",
        "marker contents must survive the move"
    );
    assert!(!layout.git_state_dir().join("a").exists());
}

#[test]
fn remote_rename_multi_to_single_segment_moves_refs_and_prunes_empty_parent() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let layout = RepoLayout::single(r.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, "team/upstream", "main", &tip).unwrap();
    plant_bridge_state(&layout, "team/upstream");

    r.ok(&["remote", "add", "team/upstream", "mkit+file:///tmp/nowhere"]);
    r.ok(&["remote", "rename", "team/upstream", "b"]);

    assert!(
        refs::read_remote_ref(&layout, "b", "main")
            .unwrap()
            .is_some(),
        "rename must move tracking refs to the flat destination"
    );
    assert!(
        refs::read_remote_ref(&layout, "team/upstream", "main")
            .unwrap()
            .is_none()
    );
    // No orphaned content left behind under the old multi-segment path.
    assert!(!layout.remotes_dir().join("team").exists());

    let moved_marker = layout.git_state_dir().join("b/marker.txt");
    assert!(moved_marker.exists(), "bridge state must move to 'b'");
    // The now-empty `team/` parent under git state must be pruned too.
    assert!(!layout.git_state_dir().join("team").exists());
}

#[test]
fn remote_rename_multi_to_multi_segment_moves_refs_and_bridge_state() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let layout = RepoLayout::single(r.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, "team/upstream", "main", &tip).unwrap();
    plant_bridge_state(&layout, "team/upstream");

    r.ok(&["remote", "add", "team/upstream", "mkit+file:///tmp/nowhere"]);
    let out = r.ok(&["remote", "rename", "team/upstream", "archive/upstream"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("could not move"),
        "multi->multi-segment rename must not degrade: {stderr}"
    );

    assert!(
        refs::read_remote_ref(&layout, "archive/upstream", "main")
            .unwrap()
            .is_some(),
        "rename must move tracking refs to the new nested destination"
    );
    assert!(
        refs::read_remote_ref(&layout, "team/upstream", "main")
            .unwrap()
            .is_none()
    );

    let moved_marker = layout.git_state_dir().join("archive/upstream/marker.txt");
    assert!(
        moved_marker.exists(),
        "bridge state must move to archive/upstream"
    );
    assert!(!layout.remotes_dir().join("team").exists());
    assert!(!layout.git_state_dir().join("team").exists());
}

#[test]
fn rename_into_own_subtree_moves_state() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let layout = RepoLayout::single(r.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, "a", "main", &tip).unwrap();
    plant_bridge_state(&layout, "a");

    r.ok(&["remote", "add", "a", "mkit+file:///tmp/nowhere"]);
    let out = r.ok(&["remote", "rename", "a", "a/sub"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("could not move"),
        "rename into own subtree must not degrade: {stderr}"
    );

    assert!(
        refs::read_remote_ref(&layout, "a/sub", "main")
            .unwrap()
            .is_some(),
        "rename must move tracking refs into the subtree destination"
    );

    let moved_marker = layout.git_state_dir().join("a/sub/marker.txt");
    assert!(
        moved_marker.exists(),
        "bridge state must move into the subtree destination"
    );
    assert_eq!(std::fs::read(&moved_marker).unwrap(), b"bridge state\n");

    // The `a` level now contains only `sub/` — no stray files directly
    // under the old locations.
    let refs_a_entries: Vec<_> = std::fs::read_dir(layout.remotes_dir().join("a"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(refs_a_entries, vec![std::ffi::OsString::from("sub")]);
    let state_a_entries: Vec<_> = std::fs::read_dir(layout.git_state_dir().join("a"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(state_a_entries, vec![std::ffi::OsString::from("sub")]);
}

#[test]
fn rename_out_of_own_subtree_moves_state() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let layout = RepoLayout::single(r.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, "a/sub", "main", &tip).unwrap();
    plant_bridge_state(&layout, "a/sub");

    r.ok(&["remote", "add", "a/sub", "mkit+file:///tmp/nowhere"]);
    let out = r.ok(&["remote", "rename", "a/sub", "a"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("could not move"),
        "rename out of own subtree must not degrade: {stderr}"
    );

    assert!(
        refs::read_remote_ref(&layout, "a", "main")
            .unwrap()
            .is_some(),
        "rename must move tracking refs to the flat destination"
    );
    // No remnant of the old nesting under either state root.
    assert!(!layout.remotes_dir().join("a/sub").exists());
    assert!(!layout.git_state_dir().join("a/sub").exists());

    let moved_marker = layout.git_state_dir().join("a/marker.txt");
    assert!(moved_marker.exists(), "bridge state must move to 'a'");
    assert_eq!(std::fs::read(&moved_marker).unwrap(), b"bridge state\n");
}

#[test]
fn rename_out_of_deep_nesting_prunes_parents() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let layout = RepoLayout::single(r.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, "x/y/z", "main", &tip).unwrap();
    plant_bridge_state(&layout, "x/y/z");

    r.ok(&["remote", "add", "x/y/z", "mkit+file:///tmp/nowhere"]);
    r.ok(&["remote", "rename", "x/y/z", "flat"]);

    assert!(
        refs::read_remote_ref(&layout, "flat", "main")
            .unwrap()
            .is_some(),
        "rename must move tracking refs to the flat destination"
    );
    // The whole emptied `x/y/z` chain must be pruned, including the
    // top-level `x` directory.
    assert!(!layout.remotes_dir().join("x").exists());
    assert!(!layout.git_state_dir().join("x").exists());

    let moved_marker = layout.git_state_dir().join("flat/marker.txt");
    assert!(moved_marker.exists(), "bridge state must move to 'flat'");
}

#[test]
fn failed_rename_restores_source_state() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");
    let layout = RepoLayout::single(r.path());
    let tip = refs::read_ref(&layout, "main").unwrap().unwrap();
    refs::write_remote_ref(&layout, "orig", "main", &tip).unwrap();
    plant_bridge_state(&layout, "orig");
    r.ok(&["remote", "add", "orig", "mkit+file:///tmp/nowhere"]);

    // A non-empty orphaned state dir at the destination, with no config
    // entry — exactly what `remote remove` leaves behind for bridge
    // state (see `warn_orphaned_bridge_state`). Its non-emptiness makes
    // the final rename into it fail (ENOTEMPTY-ish).
    let taken_state = layout.git_state_dir().join("taken");
    std::fs::create_dir_all(&taken_state).unwrap();
    std::fs::write(taken_state.join("occupied.txt"), b"pre-existing\n").unwrap();

    let out = r.ok(&["remote", "rename", "orig", "taken"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("could not move git-bridge state"),
        "expected a warning for the failed bridge-state move: {stderr}"
    );

    // Restore contract: orig's bridge state is back/intact at its
    // original location, not stranded in a temp dir.
    let restored_marker = layout.git_state_dir().join("orig/marker.txt");
    assert!(
        restored_marker.exists(),
        "bridge state must be restored to 'orig' after a failed move"
    );
    assert_eq!(std::fs::read(&restored_marker).unwrap(), b"bridge state\n");
    // The pre-existing occupant at the destination is untouched.
    assert!(taken_state.join("occupied.txt").exists());
    // No `.rename-*` temp dir left under the state root.
    let stray_temp = std::fs::read_dir(layout.git_state_dir())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .any(|e| e.file_name().to_string_lossy().starts_with(".rename-"));
    assert!(!stray_temp, "no temp dir should remain after a failed move");
}

#[test]
fn prefix_nested_remotes_coexist() {
    let r = Repo::new();
    r.commit_file("a.txt", b"a\n", "base");

    r.ok(&["remote", "add", "a", "mkit+file:///tmp/nowhere"]);
    r.ok(&["remote", "add", "a/b", "mkit+file:///tmp/nowhere-b"]);

    let out = r.ok(&["remote"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains('a'), "listing: {stdout}");
    assert!(stdout.contains("a/b"), "listing: {stdout}");

    r.ok(&["remote", "remove", "a"]);

    let out = r.ok(&["remote"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("a/b"),
        "a/b must survive removal of unrelated remote 'a': {stdout}"
    );
    let out = r.ok(&["remote", "get-url", "a/b"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "mkit+file:///tmp/nowhere-b",
        "a/b's config entry must remain intact"
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
        refs::read_remote_ref(&RepoLayout::single(consumer.path()), "origin", "main")
            .unwrap()
            .is_some(),
        "named fetch must write refs/remotes/origin/*"
    );
    // Unknown name errors cleanly.
    let out = consumer.run(&["fetch", "nope"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown remote 'nope'"));
}
