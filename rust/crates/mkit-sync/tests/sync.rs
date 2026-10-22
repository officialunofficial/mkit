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
        let (objects, tip) = self.build(parent, files, signed);
        self.publish_objects(&objects, tip, false);
        tip
    }

    /// Replace the branch with `files` as a fresh single-node chain, the way
    /// a re-baselining push resets a packmap.
    fn publish_reset(&self, files: &[(&str, &[u8])]) -> Hash {
        let (objects, tip) = self.build(None, files, true);
        self.publish_objects(&objects, tip, true);
        tip
    }

    fn build(
        &self,
        parent: Option<Hash>,
        files: &[(&str, &[u8])],
        signed: bool,
    ) -> (Vec<Object>, Hash) {
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
        (objects, tip)
    }

    fn publish_objects(&self, objects: &[Object], tip: Hash, reset: bool) {
        let mut writer = PackWriter::new();
        for object in objects {
            writer
                .push_raw(
                    object.id().unwrap(),
                    &mkit_core::serialize::serialize(object).unwrap(),
                )
                .unwrap();
        }
        self.publish_pack(&writer.finish().unwrap(), tip, reset);
    }

    fn publish_pack(&self, pack: &[u8], tip: Hash, reset: bool) {
        let pack_key = pack::pack_key(pack);
        self.tx
            .upload_pack(pack, &PackKey::from_hash(pack_key))
            .unwrap();
        let prev = if reset {
            None
        } else {
            *self.packmap_head.borrow()
        };
        let node = transfer::encode_packlist(prev, &[pack_key]).unwrap();
        let node_key = hash::hash(&node);
        self.tx
            .upload_blob(&node, &PackKey::from_hash(node_key))
            .unwrap();
        let condition = if reset {
            RefWriteCondition::Any
        } else {
            prev.map_or(RefWriteCondition::Missing, RefWriteCondition::Match)
        };
        self.tx
            .update_ref("refs/mkit/packmap/main", condition, &node_key)
            .unwrap();
        *self.packmap_head.borrow_mut() = Some(node_key);
        let head = self.tx.read_ref("refs/heads/main").unwrap();
        let condition = match (reset, head) {
            (true, _) => RefWriteCondition::Any,
            (false, None) => RefWriteCondition::Missing,
            (false, Some(head)) => RefWriteCondition::Match(head),
        };
        self.tx
            .update_ref("refs/heads/main", condition, &tip)
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
    /// Cancel once this many checkpoints have been polled.
    cancel_after: Cell<Option<usize>>,
    polls: Cell<usize>,
}

impl SyncObserver for Recorder {
    fn event(&self, event: &SyncEvent) {
        self.events.borrow_mut().push(event.clone());
    }
    fn cancelled(&self) -> bool {
        self.polls.set(self.polls.get() + 1);
        self.cancel.get()
            || self
                .cancel_after
                .get()
                .is_some_and(|n| self.polls.get() > n)
    }
}

/// A source that serves a stale branch listing and otherwise delegates.
struct StaleListing<'a> {
    inner: TransportSource<'a>,
    listing: Vec<mkit_core::refs::Ref>,
}

impl RemoteSource for StaleListing<'_> {
    fn list_branches(&self) -> Result<Vec<mkit_core::refs::Ref>, mkit_sync::SourceError> {
        Ok(self.listing.clone())
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, mkit_sync::SourceError> {
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, mkit_sync::SourceError> {
        self.inner.download_blob_via_ref(key, ref_name)
    }
    fn download_pack_via_ref(
        &self,
        key: &PackKey,
        ref_name: &str,
    ) -> Result<Vec<u8>, mkit_sync::SourceError> {
        self.inner.download_pack_via_ref(key, ref_name)
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
fn clone_refuses_values_that_would_inject_config_lines() {
    let dir = tempfile::tempdir().unwrap();
    for remote in [
        CloneRemote {
            name: "default".to_owned(),
            url: "mkit+file:///x\nremote.evil.url = y".to_owned(),
            kind: "file".to_owned(),
        },
        CloneRemote {
            name: "up\nstream".to_owned(),
            url: "mkit+file:///x".to_owned(),
            kind: "file".to_owned(),
        },
        CloneRemote {
            name: "dotted.name".to_owned(),
            url: "mkit+file:///x".to_owned(),
            kind: "file".to_owned(),
        },
        CloneRemote {
            name: "default".to_owned(),
            url: "mkit+file:///x".to_owned(),
            kind: "fi\rle".to_owned(),
        },
    ] {
        let target = dir.path().join("work");
        let err = init_clone_dir(&target, &remote).unwrap_err();
        assert!(
            matches!(err, mkit_sync::CloneInitError::InvalidRemote(_)),
            "{err:?}"
        );
        assert!(!target.exists(), "nothing is created for a rejected remote");
    }
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
    let options = SyncOptions::default().with_verify_signatures(false);

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
    let options = SyncOptions::default().with_target_branch(Some("release".to_owned()));

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
    assert_eq!(source.list_branches().unwrap(), [] as [mkit_core::Ref; 0]);
}

#[test]
fn a_listed_branch_deleted_since_the_listing_is_skipped_not_fetched() {
    let remote = Remote::new();
    let tip = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    init_clone_dir(&target, &default_remote("mkit+memory://x")).unwrap();
    let mut listing = remote.tx.list_refs("refs/heads/").unwrap();
    listing.push(mkit_core::refs::Ref {
        name: "ghost".to_owned(),
        hash: Some(tip),
    });
    let source = StaleListing {
        inner: remote.source(),
        listing,
    };
    let observer = Recorder::default();

    let report = fetch(
        &target,
        &source,
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    assert_eq!(report.branches_skipped, vec!["ghost".to_owned()]);
    assert!(
        observer
            .events
            .borrow()
            .iter()
            .any(|e| matches!(e, SyncEvent::BranchSkippedStale { branch } if branch == "ghost"))
    );
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "ghost").unwrap(),
        None
    );
}

#[test]
fn a_concurrent_rebaseline_is_retried_once_with_the_fresh_tip() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    // The listing was taken before another pusher reset the packmap to a
    // single node covering only the new tip.
    let stale = remote.tx.list_refs("refs/heads/").unwrap();
    let fresh_tip = remote.publish_reset(&[("b.txt", b"rebaselined\n")]);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    init_clone_dir(&target, &default_remote("mkit+memory://x")).unwrap();
    let source = StaleListing {
        inner: remote.source(),
        listing: stale,
    };

    let report = fetch(
        &target,
        &source,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();

    assert_eq!(report.branches_fetched, 1);
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(fresh_tip)
    );
}

#[test]
fn pull_refuses_to_overwrite_local_work_and_leaves_the_branch_alone() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    std::fs::write(target.join("a.txt"), b"local edit\n").unwrap();

    let err = pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();

    assert!(matches!(err, SyncError::RestoreSafety(_)), "{err:?}");
    let layout = RepoLayout::single(&target);
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(
        std::fs::read(target.join("a.txt")).unwrap(),
        b"local edit\n"
    );
}

#[cfg(unix)]
#[test]
fn a_failed_worktree_restore_rolls_the_branch_and_head_back() {
    use std::os::unix::fs::PermissionsExt;

    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    // HEAD sits on `dev`, so landing on `main` moves HEAD as well.
    let layout = RepoLayout::single(&target);
    refs::write_ref(&layout, "dev", &first).unwrap();
    refs::write_head_branch(&layout, "dev").unwrap();
    remote.publish(
        Some(first),
        &[("a.txt", b"two\n"), ("c.txt", b"new\n")],
        true,
    );
    // A read-only worktree root makes writing the new file fail after the
    // branch ref and HEAD have moved.
    let mut perms = std::fs::metadata(&target).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&target, perms.clone()).unwrap();
    if std::fs::write(target.join("probe"), b"x").is_ok() {
        // Running with privileges that ignore directory permissions.
        perms.set_mode(0o755);
        std::fs::set_permissions(&target, perms).unwrap();
        return;
    }
    let options = SyncOptions::default().with_target_branch(Some("main".to_owned()));

    let result = pull(
        &target,
        &remote.source(),
        "default",
        &options,
        &NoopObserver,
    );

    perms.set_mode(0o755);
    std::fs::set_permissions(&target, perms).unwrap();
    // The failure is the worktree write itself, after the ref and HEAD moved.
    assert!(
        matches!(&result, Err(SyncError::RestoreSafety(m)) if m.contains("restore worktree")),
        "{result:?}"
    );
    assert_eq!(refs::read_ref(&layout, "main").unwrap(), Some(first));
    assert_eq!(
        refs::read_head(&layout).unwrap(),
        refs::Head::Branch("dev".to_owned())
    );
}

#[test]
fn cancellation_after_the_first_checkpoint_stops_before_publishing() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    init_clone_dir(&target, &default_remote("mkit+memory://x")).unwrap();
    let observer = Recorder::default();
    observer.cancel_after.set(Some(1));

    let err = fetch(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap_err();

    assert!(matches!(err, SyncError::Interrupted), "{err:?}");
    let layout = RepoLayout::single(&target);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        None
    );
}

#[test]
fn a_live_server_is_reported_as_an_event() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone_into(&remote, &target);
    remote.publish(Some(first), &[("a.txt", b"two\n")], true);
    let layout = RepoLayout::single(&target);
    let _serving =
        mkit_core::repo_lock::acquire_default(layout.common_dir(), mkit_sync::SERVE_LOCK).unwrap();
    let observer = Recorder::default();

    pull(
        &target,
        &remote.source(),
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();

    assert!(
        observer
            .events
            .borrow()
            .iter()
            .any(|e| matches!(e, SyncEvent::RepositoryServed { .. }))
    );
}

#[test]
fn staging_honours_the_configured_directory() {
    let remote = Remote::new();
    remote.publish(None, &[("a.txt", b"one\n")], true);
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("stage");
    std::fs::create_dir(&staging).unwrap();
    let options = SyncOptions::default().with_staging_dir(Some(staging.clone()));

    clone(
        &dir.path().join("work"),
        &remote.source(),
        &default_remote("mkit+memory://x"),
        &options,
        &NoopObserver,
    )
    .unwrap();

    // Staging directories are removed on success; the directory itself stays.
    assert_eq!(std::fs::read_dir(&staging).unwrap().count(), 0);
    let missing = SyncOptions::default().with_staging_dir(Some(dir.path().join("nope")));
    let err = clone(
        &dir.path().join("work2"),
        &remote.source(),
        &default_remote("mkit+memory://x"),
        &missing,
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(err, mkit_sync::CloneError::Sync(SyncError::Io(_))));
}

/// A signed one-commit history whose pack carries a zstd entry
/// (`examples/gen_zstd_fixture.rs` regenerates it).
const ZSTD_PACK: &[u8] = include_bytes!("fixtures/zstd.pack");
const ZSTD_TIP: &str = "8c6b7803b11c2e4325369f93927a180c80cb97bdec7708cf30c0f541d2ae8787";

fn remote_with_zstd_pack() -> Remote {
    // The blob alone is about 9.7 KB; the pack is far smaller only because an
    // entry is zstd-compressed.
    assert!(
        ZSTD_PACK.len() < 1024,
        "the fixture must carry a compressed entry"
    );
    let remote = Remote::new();
    let pack_key = pack::pack_key(ZSTD_PACK);
    remote
        .tx
        .upload_pack(ZSTD_PACK, &PackKey::from_hash(pack_key))
        .unwrap();
    let node = transfer::encode_packlist(None, &[pack_key]).unwrap();
    let node_key = hash::hash(&node);
    remote
        .tx
        .upload_blob(&node, &PackKey::from_hash(node_key))
        .unwrap();
    remote
        .tx
        .update_ref(
            "refs/mkit/packmap/main",
            RefWriteCondition::Missing,
            &node_key,
        )
        .unwrap();
    remote
        .tx
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &hash::from_hex(ZSTD_TIP).unwrap(),
        )
        .unwrap();
    remote
}

// Test builds unify mkit-core's features across the dev-dependencies, so this
// runs with the C decoder available whichever of the two features is selected;
// the pure-Rust-only build is held by `scripts/check-sync-native-deps.sh`
// (the normal graph has `ruzstd` and no `zstd`).
#[test]
fn a_zstd_compressed_pack_is_cloned() {
    let remote = remote_with_zstd_pack();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");

    clone_into(&remote, &target);

    let text = std::fs::read_to_string(target.join("big.txt")).unwrap();
    assert_eq!(text, "mkit compresses repetitive text well. ".repeat(256));
}

include!("support/counting.rs");

fn identified(source: &dyn RemoteSource) -> CountingSource<'_> {
    let mut counted = CountingSource::new(source);
    counted.address = Some(("repository".into(), "https://example.invalid".into()));
    counted
}

fn checkpoint_file(target: &Path) -> std::path::PathBuf {
    std::fs::read_dir(
        RepoLayout::single(target)
            .applied_packs_dir()
            .join(".heads"),
    )
    .unwrap()
    .next()
    .unwrap()
    .unwrap()
    .path()
}

#[test]
fn incremental_pull_counts_and_rebaseline_fallback() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let second = remote.publish(Some(first), &[("a", b"2")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let calls = counted.take();
    assert_eq!(calls.len(), 6); // listing, packmap, two nodes, two packs
    let report = pull(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        counted.take(),
        ["ListRefs", "ReadRef refs/mkit/packmap/main"]
    );
    assert_eq!(report.fetch.objects_unpacked, 0);
    assert_eq!(report.fetch.packs_already_applied, 2);
    // A checkpoint established with verification also remains safe for an
    // explicit verification opt-out; the option does not discard prior trust.
    pull(
        &target,
        &counted,
        "default",
        &SyncOptions::default().with_verify_signatures(false),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        counted.take(),
        ["ListRefs", "ReadRef refs/mkit/packmap/main"]
    );

    let third = remote.publish(Some(second), &[("a", b"3")], true);
    let new_head = remote.packmap_head.borrow().unwrap();
    let report = pull(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let calls = counted.take();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[2], format!("Node {}", hash::to_hex(&new_head)));
    assert!(calls[3].starts_with("Pack "));
    assert_eq!(report.fetch.packs_downloaded, 1);
    assert_eq!(report.fetch.packs_already_applied, 2);
    assert!(matches!(report.outcome, PullOutcome::FastForwarded { new, .. } if new == third));

    let reset = remote.publish_reset(&[("reset", b"new root")]);
    let reset_tip = remote.publish(Some(reset), &[("reset", b"new tip")], true);
    let report = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 6); // unrelated two-node chain, walked to root
    assert_eq!(report.packs_downloaded, 2);
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(reset_tip)
    );
}

#[test]
fn checkpoint_corruption_absence_and_identity_changes_walk_the_full_chain() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    remote.publish(Some(first), &[("a", b"2")], true);
    let source = remote.source();
    let mut counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    counted.take();
    let path = checkpoint_file(&target);
    for bytes in [Some(b"corrupt".as_slice()), None] {
        if let Some(bytes) = bytes {
            std::fs::write(&path, bytes).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        fetch(
            &target,
            &counted,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(counted.take().len(), 4);
    }
    for address in [
        ("repository", "https://other.invalid"),
        ("other-repository", "https://example.invalid"),
    ] {
        counted.address = Some((address.0.into(), address.1.into()));
        fetch(
            &target,
            &counted,
            "default",
            &SyncOptions::default(),
            &NoopObserver,
        )
        .unwrap();
        assert_eq!(counted.take().len(), 4);
    }
}

#[test]
fn checkpoint_self_heals_a_missing_prefix_and_verifies_new_signatures() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let path = checkpoint_file(&target);
    let before = std::fs::read(&path).unwrap();
    let layout = RepoLayout::single(&target);
    std::fs::remove_dir_all(layout.objects_dir()).unwrap();
    std::fs::create_dir_all(layout.objects_dir()).unwrap();
    let observer = Recorder::default();
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();
    assert!(
        observer
            .events
            .borrow()
            .iter()
            .any(|e| matches!(e, SyncEvent::AppliedPacksStale { .. }))
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    // Recovery also resolves an omitted prefix after a new suffix was applied.
    let second = remote.publish(Some(first), &[("a", b"2")], true);
    std::fs::remove_dir_all(layout.objects_dir()).unwrap();
    std::fs::create_dir_all(layout.objects_dir()).unwrap();
    let recovered = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(recovered.packs_downloaded, 2);
    let before = std::fs::read(&path).unwrap();
    remote.publish(Some(second), &[("a", b"unsigned")], false);
    let error = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(error, SyncError::UnsignedOrInvalidObject { .. }));
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
}

#[test]
fn omitted_prefix_restores_delta_bases_when_applied_record_is_missing() {
    let remote = Remote::new();
    let base = Object::Blob(Blob {
        data: vec![b'a'; 1024],
    });
    let first = remote.publish(None, &[("a", &vec![b'a'; 1024])], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let checkpoint = checkpoint_file(&target);
    let before = std::fs::read(&checkpoint).unwrap();
    let (objects, second) = remote.build(Some(first), &[("a", &vec![b'b'; 1024])], true);
    let mut writer = PackWriter::new();
    let base_bytes = mkit_core::serialize::serialize(&base).unwrap();
    let target_bytes = mkit_core::serialize::serialize(&objects[0]).unwrap();
    let delta = mkit_core::delta::encode(&base_bytes, &target_bytes).unwrap();
    writer.push_delta(&base.id().unwrap(), &delta).unwrap();
    for object in &objects[1..] {
        writer
            .push_raw(
                object.id().unwrap(),
                &mkit_core::serialize::serialize(object).unwrap(),
            )
            .unwrap();
    }
    remote.publish_pack(&writer.finish().unwrap(), second, false);
    let layout = RepoLayout::single(&target);
    std::fs::remove_dir_all(layout.objects_dir()).unwrap();
    std::fs::create_dir_all(layout.objects_dir()).unwrap();
    // A stale applied-pack record already failed this way before checkpoints.
    // Falling back must retain those skips rather than broaden that recovery.
    let error = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        SyncError::Pack(pack::PackError::DeltaBaseMissing(_))
    ));
    assert_eq!(std::fs::read(&checkpoint).unwrap(), before);
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(first)
    );
    // With no pack record, the original full walk restores the raw prefix
    // before decoding its delta. An omitted prefix must preserve that behavior.
    std::fs::remove_file(layout.applied_packs_dir().join("default")).unwrap();
    counted.take();
    let report = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(report.packs_downloaded, 2);
    assert_eq!(counted.take().len(), 8); // suffix attempt, then one full walk
    assert_eq!(
        refs::read_remote_ref(&layout, "default", "main").unwrap(),
        Some(second)
    );
    assert_ne!(std::fs::read(checkpoint).unwrap(), before);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        counted.take(),
        ["ListRefs", "ReadRef refs/mkit/packmap/main"]
    );
}

#[test]
fn crash_between_tracking_publication_and_checkpoint_rewalks_safely() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let path = checkpoint_file(&target);
    let old_record = std::fs::read(&path).unwrap();
    let applied_path = RepoLayout::single(&target)
        .applied_packs_dir()
        .join("default");
    let old_applied = std::fs::read(&applied_path).unwrap();
    remote.publish(Some(first), &[("a", b"2")], true);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    // Reconstruct exactly the durable crash boundary: objects and tracking ref
    // published, but neither the checkpoint rename nor the final applied-pack
    // persist has occurred.
    std::fs::write(&path, old_record).unwrap();
    std::fs::write(&applied_path, old_applied).unwrap();
    counted.take();
    let report = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 4); // missed suffix plus the not-yet-recorded new pack
    assert_eq!(report.packs_downloaded, 1);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 2);
}

#[test]
fn concurrent_pulls_publish_consistent_checkpoints_under_the_lock() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let second = remote.publish(Some(first), &[("a", b"2")], true);
    let barrier = std::sync::Barrier::new(2);
    let tx = &remote.tx;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let target = &target;
                let barrier = &barrier;
                scope.spawn(move || {
                    let source = TransportSource::new(tx);
                    let mut counted = identified(&source);
                    // Both transfers rendezvous before either can publish.
                    counted.before_pack = Some(barrier);
                    barrier.wait();
                    pull(
                        target,
                        &counted,
                        "default",
                        &SyncOptions::default(),
                        &NoopObserver,
                    )
                    .unwrap()
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    });
    assert_eq!(
        refs::read_ref(&RepoLayout::single(&target), "main").unwrap(),
        Some(second)
    );
    counted.take();
    pull(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 2);
}

#[test]
fn checkpoints_are_per_branch_and_unchanged_heads_still_publish_listed_tips() {
    let remote = Remote::new();
    let first = remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    clone(
        &target,
        &counted,
        &default_remote("mkit+memory://x"),
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let second = remote.publish(Some(first), &[("a", b"2")], true);
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    // The listed tip and tracking tip can agree while the checkpoint records
    // a different historical tip under the same immutable packmap head.
    refs::write_remote_ref(&RepoLayout::single(&target), "default", "main", &first).unwrap();
    let stale = StaleListing {
        inner: remote.source(),
        listing: vec![refs::Ref {
            name: "main".into(),
            hash: Some(first),
        }],
    };
    let stale_counted = identified(&stale);
    pull(
        &target,
        &stale_counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(stale_counted.take().len(), 2); // no-op conditions hold despite the different recorded tip

    remote
        .tx
        .update_ref("refs/heads/topic", RefWriteCondition::Missing, &second)
        .unwrap();
    remote
        .tx
        .update_ref(
            "refs/mkit/packmap/topic",
            RefWriteCondition::Missing,
            &remote.packmap_head.borrow().unwrap(),
        )
        .unwrap();
    fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(&target), "default", "main").unwrap(),
        Some(second)
    );
    counted.take();
    let report = fetch(
        &target,
        &counted,
        "default",
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 3); // one listing, two packmap reads
    assert_eq!(report.branches_fetched, 2);
    assert_eq!(report.objects_unpacked, 0);
}

#[test]
fn checkpoint_directory_does_not_collide_with_a_remote_named_heads() {
    let remote = Remote::new();
    remote.publish(None, &[("a", b"1")], true);
    let source = remote.source();
    let counted = identified(&source);
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("work");
    let mut named = default_remote("mkit+memory://x");
    named.name = "heads".into();
    clone(
        &target,
        &counted,
        &named,
        &SyncOptions::default(),
        &NoopObserver,
    )
    .unwrap();
    let records = RepoLayout::single(&target).applied_packs_dir();
    assert!(records.join("heads").is_file());
    assert!(records.join(".heads").is_dir());
    assert!(!refs::validate_ref_name(".heads"));
    counted.take();
    let observer = Recorder::default();
    pull(
        &target,
        &counted,
        "heads",
        &SyncOptions::default(),
        &observer,
    )
    .unwrap();
    assert_eq!(counted.take().len(), 2);
    assert!(
        !observer
            .events
            .borrow()
            .iter()
            .any(|event| matches!(event, SyncEvent::AppliedPacksPersistFailed { .. }))
    );
}
