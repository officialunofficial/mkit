//! Issue #545: the applied-packs record's lifecycle follows its remote's.
//!
//! `mkit remote remove` must delete the per-remote applied-packs record
//! (#409/#520) and `mkit remote rename` must move it, so that:
//!
//! * remove → gc → re-add of the same name fetches cleanly, with no
//!   spurious stale-record self-heal (asserted via the fetch's stderr, not
//!   just file absence);
//! * a renamed remote reuses its record on the next fetch (asserted by
//!   counting pack downloads through an instrumented transport) and leaves
//!   no orphan record under the old name.
//!
//! Both operations must be non-fatal when the record is missing.
//!
//! A positive control (ported from PR #573) re-plants the record into the
//! remove → gc → re-add sequence and asserts the self-heal note DOES fire,
//! so the no-self-heal assertion can never go vacuously green.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

use mkit_cli::remote_dispatch::{fetch_all, push_all};
use mkit_core::hash::Hash;
use mkit_core::layout::RepoLayout;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use mkit_core::refs::{self, Ref};
use mkit_core::store::ObjectStore;
use mkit_transport_memory::MemoryTransport;

mod common;
use common::Repo;

/// Counts calls to `download_pack` specifically (NOT `download_blob`, which
/// the packlist chain-node walk uses and which stays unconditional per the
/// #409 spec) so tests can assert exactly how many *pack* bodies were pulled
/// over the wire on a given fetch. Everything else delegates to an inner
/// [`MemoryTransport`]. A sibling copy lives in `applied_packs_fetch.rs`;
/// integration-test binaries can't share non-`common` helpers, and folding
/// a transport wrapper into `common/mod.rs` would tax every other binary
/// that compiles it, so the duplication is deliberate.
struct CountingTransport {
    inner: MemoryTransport,
    pack_downloads: AtomicUsize,
}

impl CountingTransport {
    fn new() -> Self {
        Self {
            inner: MemoryTransport::new(),
            pack_downloads: AtomicUsize::new(0),
        }
    }

    /// Read-and-reset the pack-download counter.
    fn take_pack_downloads(&self) -> usize {
        self.pack_downloads.swap(0, Ordering::SeqCst)
    }
}

impl Transport for CountingTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.pack_downloads.fetch_add(1, Ordering::SeqCst);
        self.inner.download_pack(key)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }

    // Explicitly delegated (rather than left to the trait's default, which
    // would route through `Self::download_pack`/`Self::upload_pack` and
    // inflate the pack counter with chain-node blob traffic).
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
        self.inner.update_ref(name, condition, hash)
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
}

/// remove → gc → re-add of the same name: with the record deleted at remove
/// time, the re-added remote's first fetch is a clean full fetch — it must
/// NOT trip the stale-record self-heal (whose "looks stale ... clearing it"
/// note plus retry is the spurious-path marker #545 eliminates).
#[test]
fn remove_deletes_record_and_readd_fetch_has_no_self_heal() {
    // Origin publishes a two-pack chain over mkit+file://.
    let origin = Repo::new();
    let store_dir = origin.path().join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let url = format!("mkit+file://{}", store_dir.display());
    origin.ok(&["remote", "add", &url]);
    origin.commit_file("a.txt", b"v1\n", "c1");
    origin.ok(&["push", "--all"]);
    origin.commit_file("a.txt", b"v2\n", "c2");
    origin.ok(&["push", "--all"]);
    let origin_tip = refs::read_ref(&RepoLayout::single(origin.path()), "main")
        .unwrap()
        .unwrap();

    // Consumer (with its own unrelated history) fetches the named remote,
    // which creates its applied-packs record.
    let consumer = Repo::new();
    consumer.commit_file("local.txt", b"l\n", "local base");
    consumer.ok(&["remote", "add", "up", &url]);
    consumer.ok(&["fetch", "up"]);
    let record = consumer.mkit_dir().join("applied-packs").join("up");
    assert!(
        record.is_file(),
        "fetch must create the applied-packs record"
    );

    // Remove the remote: the record's lifecycle follows the remote's.
    consumer.ok(&["remote", "remove", "up"]);
    assert!(
        !record.exists(),
        "remote remove must delete the applied-packs record"
    );

    // gc reclaims origin's objects (their tracking refs are gone). This is
    // the setup that made the stale record harmful: it claimed packs were
    // applied whose objects the store no longer holds.
    consumer.ok(&["gc", "--grace-secs", "0"]);
    let consumer_layout = RepoLayout::single(consumer.path());
    let consumer_store = ObjectStore::open(&consumer_layout).unwrap();
    assert!(
        consumer_store.read(&origin_tip).is_err(),
        "precondition: gc must have pruned the removed remote's objects, \
         or the no-self-heal assertion below is vacuous"
    );

    // Re-add the same name and fetch: a clean first fetch, no self-heal.
    consumer.ok(&["remote", "add", "up", &url]);
    let out = consumer.ok(&["fetch", "up"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("looks stale"),
        "re-add after remove must not trip the stale-record self-heal: {stderr}"
    );
    let tracked = refs::read_remote_ref(&consumer_layout, "up", "main")
        .unwrap()
        .unwrap();
    assert_eq!(tracked, origin_tip, "re-fetch must land on origin's tip");
    assert!(
        record.is_file() && !fs::read(&record).unwrap().is_empty(),
        "the re-fetch must rebuild a fresh record"
    );
}

/// Positive control for the test above, ported from PR #573: restore the
/// pre-remove record into the same remove → gc → re-add sequence, simulating
/// pre-#545 behavior where `remote remove` left the file behind. The stale
/// record claims packs are applied whose objects the gc'd store no longer
/// holds, so the fetch MUST emit the "looks stale" self-heal note — and
/// still succeed via the full re-download retry. Without this control, a
/// rewording of the note would turn the negative assertion above vacuously
/// green forever.
#[test]
fn stale_record_surviving_remove_trips_self_heal_note() {
    let origin = Repo::new();
    let store_dir = origin.path().join("store");
    fs::create_dir_all(&store_dir).unwrap();
    let url = format!("mkit+file://{}", store_dir.display());
    origin.ok(&["remote", "add", &url]);
    origin.commit_file("a.txt", b"v1\n", "c1");
    origin.ok(&["push", "--all"]);
    origin.commit_file("a.txt", b"v2\n", "c2");
    origin.ok(&["push", "--all"]);
    let origin_tip = refs::read_ref(&RepoLayout::single(origin.path()), "main")
        .unwrap()
        .unwrap();

    let consumer = Repo::new();
    consumer.commit_file("local.txt", b"l\n", "local base");
    consumer.ok(&["remote", "add", "up", &url]);
    consumer.ok(&["fetch", "up"]);
    let record = consumer.mkit_dir().join("applied-packs").join("up");
    let record_bytes = fs::read(&record).unwrap();
    assert!(
        !record_bytes.is_empty(),
        "precondition: record must list applied packs"
    );

    consumer.ok(&["remote", "remove", "up"]);
    consumer.ok(&["gc", "--grace-secs", "0"]);
    let consumer_layout = RepoLayout::single(consumer.path());
    let consumer_store = ObjectStore::open(&consumer_layout).unwrap();
    assert!(
        consumer_store.read(&origin_tip).is_err(),
        "precondition: gc must have pruned the removed remote's objects, \
         or the self-heal assertion below is vacuous"
    );
    consumer.ok(&["remote", "add", "up", &url]);

    // Simulate pre-#545 behavior: the record survives the remove.
    fs::create_dir_all(record.parent().unwrap()).unwrap();
    fs::write(&record, &record_bytes).unwrap();

    let out = consumer.ok(&["fetch", "up"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("looks stale"),
        "a stale record over a pruned store must trip the self-heal note: {stderr}"
    );
    let tracked = refs::read_remote_ref(&consumer_layout, "up", "main")
        .unwrap()
        .unwrap();
    assert_eq!(
        tracked, origin_tip,
        "self-heal must recover the fetch to origin's tip"
    );
}

/// rename old → new moves the record (no orphan under the old name), and the
/// renamed remote's next steady-state fetch downloads ZERO packs — the
/// record is reused, not rebuilt via a full re-download. Uses multi-segment
/// names on both sides so the shared percent-encoding path is exercised
/// end-to-end (`team/upstream` ↔ `team%2Fupstream` on disk).
#[test]
fn rename_moves_record_and_next_fetch_reuses_it() {
    let alice = Repo::new();
    let bob = Repo::new();
    let tx = CountingTransport::new();

    // Two pushes before bob's first fetch → a two-pack chain.
    alice.commit_file("a.txt", b"v1", "c1");
    push_all(alice.path(), &tx).expect("push 1");
    alice.commit_file("a.txt", b"v2", "c2");
    push_all(alice.path(), &tx).expect("push 2");

    fetch_all(bob.path(), &tx, "team/upstream").expect("fetch 1");
    assert!(tx.take_pack_downloads() >= 1);
    // Steady state under the old name.
    fetch_all(bob.path(), &tx, "team/upstream").expect("fetch 2 (steady state)");
    assert_eq!(tx.take_pack_downloads(), 0);

    // Rename via the real binary (the remote must exist in config for the
    // command to operate on it; the URL itself is never dialed here).
    bob.ok(&["remote", "add", "team/upstream", "mkit+memory://unused"]);
    bob.ok(&["remote", "rename", "team/upstream", "archive/upstream"]);

    // The record moved: exactly one flat, percent-encoded file, no orphan.
    let dir = bob.mkit_dir().join("applied-packs");
    let names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        vec!["archive%2Fupstream".to_owned()],
        "rename must move the record and leave no orphan"
    );

    // The renamed remote reuses the record: steady-state fetch, zero packs.
    fetch_all(bob.path(), &tx, "archive/upstream").expect("fetch under new name");
    assert_eq!(
        tx.take_pack_downloads(),
        0,
        "a steady-state fetch under the renamed remote must reuse the moved \
         record and download zero packs"
    );

    // And it stays incremental: one new pack costs exactly one download.
    alice.commit_file("a.txt", b"v3", "c3");
    push_all(alice.path(), &tx).expect("push 3");
    fetch_all(bob.path(), &tx, "archive/upstream").expect("incremental fetch");
    assert_eq!(tx.take_pack_downloads(), 1);
}

/// `remote remove default` (the flat default remote) also deletes the
/// `default` record the default-remote fetch path writes.
#[test]
fn remove_default_remote_deletes_its_record() {
    let alice = Repo::new();
    let bob = Repo::new();
    let tx = CountingTransport::new();

    alice.commit_file("a.txt", b"v1", "c1");
    push_all(alice.path(), &tx).expect("push");
    fetch_all(bob.path(), &tx, "default").expect("fetch");
    let record = bob.mkit_dir().join("applied-packs").join("default");
    assert!(record.is_file(), "precondition: default record exists");

    bob.ok(&["remote", "add", "mkit+memory://unused"]); // flat default
    bob.ok(&["remote", "remove", "default"]);
    assert!(
        !record.exists(),
        "removing the default remote must delete its applied-packs record"
    );
}

/// A remote that was never fetched has no record; remove and rename must
/// both succeed silently — no failure, no applied-packs warning.
#[test]
fn remove_and_rename_are_non_fatal_when_record_missing() {
    let r = Repo::new();
    r.ok(&["remote", "add", "up", "mkit+file:///tmp/nowhere"]);
    let out = r.ok(&["remote", "remove", "up"]);
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("applied-packs"),
        "missing record must not warn on remove"
    );

    r.ok(&["remote", "add", "old", "mkit+file:///tmp/nowhere"]);
    let out = r.ok(&["remote", "rename", "old", "new"]);
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("applied-packs"),
        "missing record must not warn on rename"
    );
}
