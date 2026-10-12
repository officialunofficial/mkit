//! End-to-end behaviour of `clone`, `fetch` and `pull` over the
//! `Transport`-backed remote source, against an in-memory remote that is
//! populated the way a push populates a real one (packs, a packmap chain, a
//! branch ref).
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::cell::{Cell, RefCell};
use std::path::Path;

use mkit_core::hash::{self, Hash};
use mkit_core::layout::RepoLayout;
use mkit_core::object::{Blob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::{self, PackWriter};
use mkit_core::protocol::{PackKey, Transport};
use mkit_core::refs::{self, RefWriteCondition};
use mkit_core::sign::{self, KeyPair};
use mkit_core::transfer;
use mkit_sync::{
    CloneRemote, NoopObserver, PullOutcome, RemoteSource, SyncError, SyncEvent, SyncObserver,
    SyncOptions, TransportSource, clone, fetch, init_clone_dir, pull,
};
use mkit_transport_memory::MemoryTransport;

/// A remote repository: objects arrive in packs, each push appends a node to
/// the branch's packmap chain, then moves the branch ref.
struct Remote {
    tx: MemoryTransport,
    packmap_head: RefCell<Option<Hash>>,
    key: KeyPair,
}

impl Remote {
    fn new() -> Self {
        Self {
            tx: MemoryTransport::new(),
            packmap_head: RefCell::new(None),
            key: KeyPair::generate().unwrap(),
        }
    }

    /// Publish one commit on `main` carrying `files`, parented on `parent`.
    /// `signed = false` leaves the signature zeroed, as a hostile remote's
    /// forged history would.
    fn publish(&self, parent: Option<Hash>, files: &[(&str, &[u8])], signed: bool) -> Hash {
        let mut objects = Vec::new();
        let mut entries = Vec::new();
        for (name, data) in files {
            let blob = Object::Blob(Blob {
                data: data.to_vec(),
            });
            entries.push(TreeEntry {
                name: name.as_bytes().to_vec(),
                mode: EntryMode::Blob,
                object_hash: blob.id().unwrap(),
            });
            objects.push(blob);
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let tree = Object::Tree(Tree { entries });
        let tree_hash = tree.id().unwrap();
        objects.push(tree);
        let mut commit = Commit::new_unannotated(
            tree_hash,
            parent.into_iter().collect(),
            Identity::ed25519(self.key.public.0),
            self.key.public.0,
            format!("commit {}", files.len()).into_bytes(),
            1_700_000_000 + u64::from(parent.is_some()),
            [0u8; 64],
        );
        if signed {
            commit.signature = sign::sign_commit(&commit, &self.key).unwrap().0;
        }
        let commit = Object::Commit(commit);
        let tip = commit.id().unwrap();
        objects.push(commit);
        self.publish_objects(&objects, tip);
        tip
    }

    fn publish_objects(&self, objects: &[Object], tip: Hash) {
        let mut writer = PackWriter::new();
        for object in objects {
            writer
                .push_raw(
                    object.id().unwrap(),
                    &mkit_core::serialize::serialize(object).unwrap(),
                )
                .unwrap();
        }
        let pack = writer.finish().unwrap();
        let pack_key = pack::pack_key(&pack);
        self.tx
            .upload_pack(&pack, &PackKey::from_hash(pack_key))
            .unwrap();
        let prev = *self.packmap_head.borrow();
        let node = transfer::encode_packlist(prev, &[pack_key]).unwrap();
        let node_key = hash::hash(&node);
        self.tx
            .upload_blob(&node, &PackKey::from_hash(node_key))
            .unwrap();
        let condition = prev.map_or(RefWriteCondition::Missing, RefWriteCondition::Match);
        self.tx
            .update_ref("refs/mkit/packmap/main", condition, &node_key)
            .unwrap();
        *self.packmap_head.borrow_mut() = Some(node_key);
        let head = self.tx.read_ref("refs/heads/main").unwrap();
        self.tx
            .update_ref(
                "refs/heads/main",
                head.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
                &tip,
            )
            .unwrap();
    }

    fn source(&self) -> TransportSource<'_> {
        TransportSource::new(&self.tx)
    }
}

#[derive(Default)]
struct Recorder {
    events: RefCell<Vec<SyncEvent>>,
    cancel: Cell<bool>,
}

impl SyncObserver for Recorder {
    fn event(&self, event: &SyncEvent) {
        self.events.borrow_mut().push(event.clone());
    }
    fn cancelled(&self) -> bool {
        self.cancel.get()
    }
}

fn default_remote(url: &str) -> CloneRemote {
    CloneRemote {
        name: "default".to_owned(),
        url: url.to_owned(),
        kind: "memory".to_owned(),
    }
}

fn clone_into(remote: &Remote, dir: &Path) -> mkit_sync::CloneReport {
    clone(
        dir,
        &remote.source(),
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap()
}

#[test]
fn clone_materialises_the_branch_worktree_and_tracking_ref() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"hello\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");

    let report = clone_into(&remote, &target);

    assert_eq!(report.pull.fetch.branches_fetched, 1);
    assert_eq!(report.pull.fetch.packs_downloaded, 1);
    assert_eq!(report.pull.fetch.packs_already_applied, 0);
    assert!(report.pull.fetch.objects_unpacked >= 3);
    assert_eq!(
        report.pull.outcome,
        PullOutcome::FastForwarded {
            branch: "main".to_owned(),
            old: None,
            new: tip
        }
    );
    let layout = RepoLayout::single(&target);
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(tip));
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(tip)
    );
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"hello\n");
}

#[test]
fn clone_writes_the_flat_and_named_remote_config() {
    let dir = tempfile::tempdir().unwrap();
    let flat = dir.path().join("flat");
    let layout = init_clone_dir(&flat, &default_remote("mkit+memory://x")).unwrap();
    assert_eq!(
        std::fs::read_to_string(layout.config_file()).unwrap(),
        "default_branch = main\nremote_endpoint = mkit+memory://x\nremote_type = memory\n"
    );

    let named = dir.path().join("named");
    let remote = CloneRemote {
        name: "upstream".to_owned(),
        url: "mkit+file:///srv/r".to_owned(),
        kind: "file".to_owned(),
    };
    let layout = init_clone_dir(&named, &remote).unwrap();
    assert_eq!(
        std::fs::read_to_string(layout.config_file()).unwrap(),
        "default_branch = main\nremote.upstream.url = mkit+file:///srv/r\nremote.upstream.type = file\n"
    );
}

#[test]
fn pull_fast_forwards_and_a_second_pull_is_a_no_op() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);

    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let report = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        report.outcome,
        PullOutcome::FastForwarded {
            branch: "main".to_owned(),
            old: Some(first),
            new: second
        }
    );
    // Only the new pack is downloaded; the first is recorded as applied.
    assert_eq!(report.fetch.packs_downloaded, 1);
    assert_eq!(report.fetch.packs_already_applied, 1);
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"two\n");

    let again = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        again.outcome,
        PullOutcome::UpToDate {
            branch: "main".to_owned()
        }
    );
    assert_eq!(again.fetch.packs_downloaded, 0);
    assert_eq!(again.fetch.packs_already_applied, 2);
}

#[test]
fn fetch_moves_only_the_tracking_ref() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    let second = remote.publish(Some(first), &[("a.txt", b"two\n")], true);

    let report = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"one\n");
}

#[test]
fn pull_refuses_anything_that_is_not_a_fast_forward() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);

    // The remote branch is replaced by an unrelated history.
    let unrelated = remote.publish(None, &[("b.txt", b"other\n")], true);
    assert_ne!(first, unrelated);

    let err = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(
        matches!(err, SyncError::NonFastForwardPull { ref branch } if branch == "main"),
        "{err:?}"
    );
    let layout = RepoLayout::single(&target);
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(std::fs::read(target.join("a.txt")).unwrap(), b"one\n");
}

#[test]
fn an_unsigned_commit_is_rejected_by_default_and_publishes_nothing() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"forged\n")], false);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");

    let err = clone(
        &target,
        &remote.source(),
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();
    let mkit_sync::CloneError::Sync(SyncError::UnsignedOrInvalidObject { hash, .. }) = err else {
        panic!("expected UnsignedOrInvalidObject");
    };
    assert_eq!(hash, hash::to_hex(&tip));
    let layout = RepoLayout::single(&target);
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), None);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        None
    );
    assert!(!target.join("a.txt").exists());
}

#[test]
fn the_explicit_opt_out_accepts_an_unsigned_commit() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"unsigned\n")], false);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let options = SyncOptions {
        verify_signatures: false,
        ..SyncOptions::default()
    };

    let report = clone(
        &target,
        &remote.source(),
        &default_remote("mkit+memory://x"),
        &options,
        &NoopObserver,
    )
    .unwrap();

    assert!(matches!(
        report.pull.outcome,
        PullOutcome::FastForwarded { new, .. } if new == tip
    ));
}

#[test]
fn a_missing_target_branch_is_an_error_not_a_fallback() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let options = SyncOptions {
        target_branch: Some("release".to_owned()),
        ..SyncOptions::default()
    };

    let err = clone(
        &target,
        &remote.source(),
        &default_remote("mkit+memory://x"),
        &options,
        &NoopObserver,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        mkit_sync::CloneError::Sync(SyncError::RemoteBranchMissing(ref b)) if b == "release"
    ));
}

#[test]
fn cancellation_is_polled_and_reported_as_interrupted() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let observer = Recorder::default();
    observer.cancel.set(true);

    let err = clone(
        &target,
        &remote.source(),
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &observer,
    )
    .unwrap_err();

    assert!(matches!(
        err,
        mkit_sync::CloneError::Sync(SyncError::Interrupted)
    ));
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        None
    );
}

#[test]
fn progress_arrives_as_events_not_output() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let observer = Recorder::default();

    clone(
        &dir.path().join("work"),
        &remote.source(),
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    let events = observer.events.borrow();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SyncEvent::ObjectsUnpacked { count } if *count >= 3)),
        "{events:?}"
    );
}

#[test]
fn a_stale_applied_packs_record_self_heals_with_a_visible_event() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);

    // Wipe the object store but keep the applied-packs record.
    let layout = RepoLayout::single(&target);
    let objects = layout.common_dir().join("objects");
    std::fs::remove_dir_all(&objects).unwrap();
    std::fs::create_dir_all(&objects).unwrap();
    let observer = Recorder::default();

    let report = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    assert_eq!(report.packs_downloaded, 1);
    assert!(
        observer
            .events
            .borrow()
            .iter()
            .any(|e| matches!(e, SyncEvent::AppliedPacksStale { .. }))
    );
}

#[test]
fn the_source_trait_is_object_safe() {
    let remote = Remote::new();
    let source: &dyn RemoteSource = &remote.source();
    assert!(source.list_branches().unwrap().is_empty());
}
