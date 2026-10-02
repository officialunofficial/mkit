//! Push over a transport whose retry ladder re-issues a landed head write
//! (MKIT-58, SPEC-TRANSPORT §7).
//!
//! `update_ref` with `Missing`/`Match` is not idempotent across retries: when
//! the first attempt lands and its response is lost, the ladder's re-issue
//! reports `RefConflict` for the caller's own write. The push path must read
//! the head back before reporting a non-fast-forward. A genuine
//! non-fast-forward (another writer's commit on the head) is still rejected.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};

use common::Repo;
use mkit_cli::remote_dispatch::{DispatchError, pull_all, push_all};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use mkit_core::refs::{self, Ref};
use mkit_transport_file::FileTransport;

/// A [`FileTransport`] whose `update_ref` on a `refs/heads/` name applies
/// the write, loses the response, and re-issues it: the caller sees only
/// the second attempt's result, as it would after the SPEC-TRANSPORT §7
/// ladder retried a timed-out write. `advance_refs` keeps the trait's
/// ordered default (packmap, then head), so a push reaches the head write
/// through this `update_ref` and sees `HeadConflict` for its own write.
struct LostHeadResponse {
    inner: FileTransport,
    reissued: AtomicUsize,
}

impl Transport for LostHeadResponse {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }
    fn upload_blob(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_blob(bytes, key)
    }
    fn download_blob(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_blob(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if name.starts_with("refs/heads/") && self.inner.update_ref(name, condition, hash).is_ok() {
            self.reissued.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.update_ref(name, condition, hash)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
}

fn head(repo: &Repo) -> Hash {
    refs::read_ref(&RepoLayout::single(repo.path()), "main")
        .unwrap()
        .unwrap()
}

#[test]
fn push_whose_head_write_is_reissued_after_landing_succeeds() {
    let remote = tempfile::tempdir().unwrap();
    let tx = LostHeadResponse {
        inner: FileTransport::new(remote.path()),
        reissued: AtomicUsize::new(0),
    };
    let alice = Repo::new();

    // First push: `Missing` head write, re-issued after it landed.
    alice.commit_file("f.txt", b"one", "one");
    push_all(alice.path(), &tx).expect("first push landed");
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(head(&alice)));

    // Second push: `Match(previous tip)` head write, re-issued after it landed.
    alice.commit_file("f.txt", b"two", "two");
    push_all(alice.path(), &tx).expect("second push landed");
    let tip = head(&alice);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(tip));
    assert_eq!(
        tx.reissued.load(Ordering::SeqCst),
        2,
        "both head writes landed on their first attempt and were re-issued"
    );

    // The success path advanced alice's remote-tracking ref, and the remote
    // still reconstructs the tip.
    assert_eq!(
        refs::read_remote_ref(&RepoLayout::single(alice.path()), "default", "main").unwrap(),
        Some(tip)
    );
    let bob = Repo::new();
    pull_all(bob.path(), &tx, "default", None).expect("bob clones");
    assert_eq!(head(&bob), tip);
}

#[test]
fn genuine_non_fast_forward_is_still_rejected() {
    let remote = tempfile::tempdir().unwrap();
    let tx = LostHeadResponse {
        inner: FileTransport::new(remote.path()),
        reissued: AtomicUsize::new(0),
    };
    // Set up through a plain transport on the same remote, so only bob's
    // push goes through the re-issuing one.
    let plain = FileTransport::new(remote.path());
    let alice = Repo::new();
    let bob = Repo::new();
    alice.commit_file("f.txt", b"base", "base");
    push_all(alice.path(), &plain).unwrap();
    pull_all(bob.path(), &plain, "default", None).unwrap();

    alice.commit_file("f.txt", b"alice", "alice");
    push_all(alice.path(), &plain).unwrap();
    let alice_tip = head(&alice);

    // bob's lease is the stale base: a real conflict, not our own write.
    bob.commit_file("f.txt", b"bob", "bob");
    let err = push_all(bob.path(), &tx).unwrap_err();
    assert!(
        matches!(err, DispatchError::NonFastForwardPush { ref branch } if branch == "main"),
        "expected NonFastForwardPush, got {err:?}"
    );
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(alice_tip));
}
