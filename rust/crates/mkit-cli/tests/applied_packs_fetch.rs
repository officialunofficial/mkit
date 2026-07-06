//! Issue #409: fetch-side applied-pack record.
//!
//! Verifies, via a counting transport wrapper around the in-process
//! `MemoryTransport`, that a steady-state fetch skips packs already
//! recorded as applied (downloading zero packs when the remote chain
//! hasn't grown, and exactly the new pack when it has), and that the
//! self-heal path recovers if the local object store is wiped out-of-band
//! while the applied-packs record survives.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use mkit_cli::remote_dispatch::{fetch_all, push_all};
use mkit_core::hash::Hash;
use mkit_core::ops::reachable_objects;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use mkit_core::refs::{self, Ref};
use mkit_core::store::ObjectStore;
use mkit_transport_memory::MemoryTransport;

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &Path, args: &[&str]) -> std::process::Output {
    let xdg = tempfile::tempdir().expect("xdg tempdir");
    let out = Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg.path())
        .output()
        .expect("spawn mkit");
    drop(xdg);
    assert!(
        out.status.success(),
        "mkit {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn init_repo(dir: &Path) {
    run_in(dir, &["init"]);
    run_in(dir, &["keygen"]);
}

fn commit_all(dir: &Path, msg: &str) {
    run_in(dir, &["add", "."]);
    run_in(dir, &["commit", "-m", msg]);
}

/// Counts calls to `download_pack` specifically (NOT `download_blob`, which
/// the packlist chain-node walk uses and which stays unconditional per the
/// #409 spec) so tests can assert exactly how many *pack* bodies were
/// pulled over the wire on a given fetch. Everything else delegates to an
/// inner [`MemoryTransport`].
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
    // inflate the pack counter with chain-node blob traffic): the packlist
    // chain walk is unconditional by design (#409) and must never count
    // against the pack-download assertions below.
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

#[test]
fn steady_state_fetch_skips_already_applied_packs() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    let tx = CountingTransport::new();

    // Two pushes from alice BEFORE bob ever fetches, so bob's first fetch
    // walks a two-pack chain.
    fs::write(alice.path().join("a.txt"), b"v1").unwrap();
    commit_all(alice.path(), "c1");
    push_all(alice.path(), &tx).expect("push 1");

    fs::write(alice.path().join("a.txt"), b"v2").unwrap();
    commit_all(alice.path(), "c2");
    push_all(alice.path(), &tx).expect("push 2");

    // Fetch 1: pulls the whole (two-pack) chain. Reset the counter — this
    // test only asserts about the *steady-state* fetches that follow.
    fetch_all(bob.path(), &tx, "default").expect("fetch 1");
    let first_fetch_downloads = tx.take_pack_downloads();
    assert!(
        first_fetch_downloads >= 1,
        "first fetch must download at least one pack, got {first_fetch_downloads}"
    );

    // Fetch 2: nothing changed on the remote since fetch 1 — every pack in
    // the chain is already recorded as applied, so this must download ZERO
    // packs (the whole point of #409).
    fetch_all(bob.path(), &tx, "default").expect("fetch 2 (steady state)");
    assert_eq!(
        tx.take_pack_downloads(),
        0,
        "a fetch with no new remote packs must download zero packs"
    );

    // Push a third time from alice: exactly one new pack enters the chain.
    fs::write(alice.path().join("a.txt"), b"v3").unwrap();
    commit_all(alice.path(), "c3");
    push_all(alice.path(), &tx).expect("push 3");

    // Fetch 3: must download exactly the one new pack, skipping every
    // earlier pack in the chain.
    fetch_all(bob.path(), &tx, "default").expect("fetch 3");
    assert_eq!(
        tx.take_pack_downloads(),
        1,
        "a fetch with exactly one new remote pack must download exactly one pack"
    );

    // Sanity: bob's remote-tracking ref actually landed on alice's latest
    // tip (fetch never checks out the working tree, so we assert via the
    // ref rather than reading a working-tree file).
    let alice_tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let bob_tracking_tip = refs::read_remote_ref(&bob.path().join(".mkit"), "default", "main")
        .unwrap()
        .unwrap();
    assert_eq!(alice_tip, bob_tracking_tip);
}

#[test]
fn self_heal_recovers_when_object_store_is_wiped_but_record_survives() {
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    let tx = CountingTransport::new();

    fs::write(alice.path().join("a.txt"), b"alpha").unwrap();
    fs::create_dir_all(alice.path().join("src")).unwrap();
    fs::write(alice.path().join("src/main.rs"), b"fn main() {}\n").unwrap();
    commit_all(alice.path(), "c1");
    push_all(alice.path(), &tx).expect("push");

    // Populates bob's object store AND the applied-packs record.
    fetch_all(bob.path(), &tx, "default").expect("initial fetch");
    assert!(tx.take_pack_downloads() >= 1);

    // Wipe bob's object store contents out-of-band, but keep the
    // applied-packs record — exactly the staleness scenario the self-heal
    // path exists for.
    let bob_mkit = bob.path().join(".mkit");
    let objects_dir = bob_mkit.join("objects");
    assert!(objects_dir.is_dir(), "precondition: objects dir exists");
    fs::remove_dir_all(&objects_dir).unwrap();
    fs::create_dir_all(&objects_dir).unwrap();
    assert!(
        bob_mkit.join("applied-packs").join("default").exists(),
        "precondition: applied-packs record must survive the wipe"
    );

    // Fetch again: without self-heal this would skip every pack (they're
    // all still "recorded applied") yet find no objects, and blow up
    // downstream. With self-heal it must succeed by clearing the stale
    // record and re-downloading everything.
    fetch_all(bob.path(), &tx, "default").expect("fetch must self-heal, not fail");
    assert!(
        tx.take_pack_downloads() >= 1,
        "the self-heal retry must re-download the pack(s)"
    );

    // Every object reachable from bob's remote-tracking tip must be back.
    let bob_store = ObjectStore::open(bob.path()).unwrap();
    let remote_tip = refs::read_remote_ref(&bob_mkit, "default", "main")
        .unwrap()
        .unwrap();
    let closure: HashSet<_> = reachable_objects(&bob_store, &remote_tip)
        .unwrap()
        .into_iter()
        .collect();
    assert!(
        closure.len() >= 4,
        "closure must include >= commit+tree+2 blobs after self-heal, got {}",
        closure.len()
    );

    // A subsequent steady-state fetch is back to normal: zero downloads.
    fetch_all(bob.path(), &tx, "default").expect("post-heal fetch");
    assert_eq!(
        tx.take_pack_downloads(),
        0,
        "after self-heal, the record must be accurate again"
    );
}
