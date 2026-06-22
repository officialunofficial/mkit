//! Delta-on-the-wire integration tests.
//!
//! Exercises the full push/fetch path through a memory transport:
//!
//! 1. A small edit to a large (>1 MiB) FastCDC-chunked file produces a
//!    second push that transfers delta-sized bytes for the changed region,
//!    not whole chunks (acceptance #1).
//! 2. A fresh clone after a delta push reconstructs the file byte-for-byte
//!    with every object hash verifying (acceptance #2).
//! 3. Re-pushing identical content transfers nothing — identical-object
//!    dedup is preferred over delta (acceptance #3).

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mkit_cli::remote_dispatch::{DispatchError, pull_all, push_all, push_branch};
use mkit_core::hash;
use mkit_core::ops::reachable_objects;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportError, TransportResult};
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

/// A transport that counts the bytes handed to `upload_pack`, so a test can
/// measure exactly how much a push transferred. Everything else delegates
/// to an inner [`MemoryTransport`].
struct CountingTransport {
    inner: Arc<MemoryTransport>,
    uploaded: AtomicU64,
}

impl CountingTransport {
    fn new() -> Self {
        Self {
            inner: Arc::new(MemoryTransport::new()),
            uploaded: AtomicU64::new(0),
        }
    }
    fn take_uploaded(&self) -> u64 {
        self.uploaded.swap(0, Ordering::SeqCst)
    }
}

impl Transport for CountingTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.uploaded
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &hash::Hash,
    ) -> TransportResult<()> {
        self.inner.update_ref(name, condition, hash)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<hash::Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
}

/// Deterministic >1 MiB buffer that `FastCDC` splits into many chunks.
/// Splitmix64 keeps it dependency-free and reproducible.
fn big_buffer() -> Vec<u8> {
    let mut data = vec![0u8; 2 * 1024 * 1024];
    let mut state: u64 = 0x0123_4567_89ab_cdef;
    for chunk in data.chunks_mut(8) {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        let n = chunk.len();
        chunk.copy_from_slice(&bytes[..n]);
    }
    data
}

fn init_repo(dir: &Path) {
    run_in(dir, &["init"]);
    run_in(dir, &["keygen"]);
}

fn commit_all(dir: &Path, msg: &str) {
    run_in(dir, &["add", "."]);
    run_in(dir, &["commit", "-m", msg]);
}

#[test]
fn small_edit_to_large_file_pushes_delta_sized_bytes() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());

    // v1: a >1 MiB file (lands as a ChunkedBlob of FastCDC blob chunks).
    let v1 = big_buffer();
    fs::write(alice.path().join("big.bin"), &v1).unwrap();
    commit_all(alice.path(), "v1");

    let tx = CountingTransport::new();
    push_all(alice.path(), &tx).expect("push v1");
    let first = tx.take_uploaded();
    assert!(
        first > v1.len() as u64,
        "first push must transfer at least the whole file ({} bytes), got {first}",
        v1.len()
    );

    // v2: flip 16 bytes in the middle, same length → FastCDC boundaries
    // stay stable, so only the chunk covering the edit changes.
    let mut v2 = v1.clone();
    for k in 0..16 {
        v2[1_000_000 + k] ^= 0xFF;
    }
    fs::write(alice.path().join("big.bin"), &v2).unwrap();
    commit_all(alice.path(), "v2");

    push_all(alice.path(), &tx).expect("push v2");
    let second = tx.take_uploaded();

    // The whole point: the second push must NOT re-upload whole chunks. A
    // single FastCDC chunk is >= 16 KiB (MIN_SIZE); the delta + small
    // manifest/tree/commit objects must come in well under that.
    assert!(
        second < 16 * 1024,
        "second push should be delta-sized (< 16 KiB), got {second} bytes \
         (first push was {first})"
    );
    assert!(
        second * 20 < first,
        "second push ({second}) should be a tiny fraction of the first ({first})"
    );
}

#[test]
fn clone_after_delta_push_reconstructs_byte_identical() {
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());

    let v1 = big_buffer();
    fs::write(alice.path().join("big.bin"), &v1).unwrap();
    fs::write(alice.path().join("README.md"), b"hello\n").unwrap();
    commit_all(alice.path(), "v1");

    let tx = CountingTransport::new();
    push_all(alice.path(), &tx).expect("push v1");

    // Edit and push again so the remote holds a delta chain.
    let mut v2 = v1.clone();
    for k in 0..32 {
        v2[1_500_000 + k] = v2[1_500_000 + k].wrapping_add(1);
    }
    fs::write(alice.path().join("big.bin"), &v2).unwrap();
    commit_all(alice.path(), "v2");
    push_all(alice.path(), &tx).expect("push v2");

    // Fresh clone: a brand-new repo that holds nothing must reconstruct the
    // whole closure (base chunks + delta chunks) from the advertised packs.
    let bob = tempfile::tempdir().unwrap();
    init_repo(bob.path());
    pull_all(bob.path(), &tx, "default").expect("pull into fresh repo");

    // The working file must be byte-for-byte identical to v2.
    assert_eq!(fs::read(bob.path().join("big.bin")).unwrap(), v2);
    assert_eq!(fs::read(bob.path().join("README.md")).unwrap(), b"hello\n");

    // Every object in the closure must read back hash-verified (ObjectStore
    // ::read re-hashes and rejects mismatches), proving the delta chain
    // reconstructed to the correct ids.
    let alice_mkit = alice.path().join(".mkit");
    let bob_mkit = bob.path().join(".mkit");
    let alice_tip = refs::read_ref(&alice_mkit, "main").unwrap().unwrap();
    let bob_tip = refs::read_ref(&bob_mkit, "main").unwrap().unwrap();
    assert_eq!(alice_tip, bob_tip, "clone must land on the same tip");

    let bob_store = ObjectStore::open(bob.path()).unwrap();
    let closure = reachable_objects(&bob_store, &bob_tip).unwrap();
    assert!(closure.len() > 4, "closure should include several chunks");
    for h in &closure {
        let bytes = bob_store.read(h).expect("object present and hash-verified");
        // `read` already re-verifies the dispatched id (merkle root for
        // Tree/ChunkedBlob, BLAKE3 otherwise); assert it explicitly.
        assert_eq!(
            mkit_core::serialize::deserialize(&bytes)
                .unwrap()
                .id()
                .unwrap(),
            *h,
            "reconstructed object must address to its id"
        );
    }
}

#[test]
fn clone_reconstructs_multi_commit_delta_chain() {
    // Several sequential edits to the same region build a delta chain on the
    // remote (chunk_vN deltas against chunk_v(N-1)). A fresh clone must walk
    // the chain — unpacking the listed packs in order so each delta's base
    // is already present — and land byte-for-byte on the latest version.
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    let tx = CountingTransport::new();

    let mut data = big_buffer();
    let mut latest = data.clone();
    for rev in 0..4u8 {
        for k in 0..24usize {
            data[700_000 + k] = data[700_000 + k].wrapping_add(rev.wrapping_add(1));
        }
        latest = data.clone();
        fs::write(alice.path().join("big.bin"), &data).unwrap();
        commit_all(alice.path(), &format!("rev{rev}"));
        push_all(alice.path(), &tx).unwrap_or_else(|e| panic!("push rev{rev}: {e}"));
    }

    let bob = tempfile::tempdir().unwrap();
    init_repo(bob.path());
    pull_all(bob.path(), &tx, "default").expect("clone the delta chain");
    assert_eq!(fs::read(bob.path().join("big.bin")).unwrap(), latest);

    // Hash-verify the whole reconstructed closure.
    let bob_tip = refs::read_ref(&bob.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let bob_store = ObjectStore::open(bob.path()).unwrap();
    for h in reachable_objects(&bob_store, &bob_tip).unwrap() {
        let bytes = bob_store
            .read(&h)
            .expect("object present and hash-verified");
        assert_eq!(
            mkit_core::serialize::deserialize(&bytes)
                .unwrap()
                .id()
                .unwrap(),
            h
        );
    }
}

#[test]
fn identical_repush_transfers_nothing() {
    // Identical-object dedup is preferred over delta: when nothing changed,
    // the second push sends zero pack bytes (empty plan → no pack uploaded).
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());

    let v1 = big_buffer();
    fs::write(alice.path().join("big.bin"), &v1).unwrap();
    commit_all(alice.path(), "v1");

    let tx = CountingTransport::new();
    push_all(alice.path(), &tx).expect("push v1");
    assert!(tx.take_uploaded() > 0, "first push transfers the closure");

    // Re-push the very same tip — remote already holds everything.
    push_all(alice.path(), &tx).expect("re-push");
    assert_eq!(
        tx.take_uploaded(),
        0,
        "identical re-push must transfer no bytes"
    );
}

/// A transport that fails every CAS write to the `refs/mkit/` (packmap)
/// namespace, simulating sustained contention on the packmap pointer.
/// Everything else delegates to an inner [`MemoryTransport`].
struct PackmapBlockingTransport {
    inner: MemoryTransport,
}

impl PackmapBlockingTransport {
    fn new() -> Self {
        Self {
            inner: MemoryTransport::new(),
        }
    }
}

impl Transport for PackmapBlockingTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &hash::Hash,
    ) -> TransportResult<()> {
        if name.starts_with("refs/mkit/") {
            return Err(TransportError::RefConflict); // always contended
        }
        self.inner.update_ref(name, condition, hash)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<hash::Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
}

#[test]
fn head_not_moved_when_packmap_cannot_be_established() {
    // The atomicity invariant: if the packmap can't be durably advanced,
    // the branch head must NOT move — otherwise a clone would see a tip the
    // packmap can't reconstruct.
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    fs::write(alice.path().join("big.bin"), big_buffer()).unwrap();
    commit_all(alice.path(), "v1");

    let tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let store = ObjectStore::open(alice.path()).unwrap();
    let tx = PackmapBlockingTransport::new();

    let err = push_branch(&tx, &store, "main", tip, RefWriteCondition::Missing).unwrap_err();
    assert!(
        matches!(err, DispatchError::PackmapContended { .. }),
        "expected PackmapContended, got {err:?}"
    );
    // The head ref must never have been written.
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        None,
        "head must not advance past an unestablished packmap"
    );
}

#[test]
fn divergent_concurrent_push_leaves_cloneable_remote() {
    // alice and bob both branch from a shared base and push divergent edits.
    // alice wins the head CAS; bob loses it (non-fast-forward). The remote
    // must still clone byte-identically to alice's tip — bob's losing push
    // must not have left the packmap unable to reconstruct the head.
    let alice = tempfile::tempdir().unwrap();
    let bob = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    init_repo(bob.path());

    let base = big_buffer();
    fs::write(alice.path().join("big.bin"), &base).unwrap();
    commit_all(alice.path(), "v0");

    let tx = CountingTransport::new();
    push_all(alice.path(), &tx).expect("alice base push");
    pull_all(bob.path(), &tx, "default").expect("bob clones base");

    let shared_tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();

    // alice edits → A1, bob edits the same region → B1 (divergent).
    let mut av = base.clone();
    for k in 0..32 {
        av[800_000 + k] ^= 0xAA;
    }
    fs::write(alice.path().join("big.bin"), &av).unwrap();
    commit_all(alice.path(), "A1");
    let mut bv = base;
    for k in 0..32 {
        bv[800_000 + k] ^= 0x55;
    }
    fs::write(bob.path().join("big.bin"), &bv).unwrap();
    commit_all(bob.path(), "B1");

    let alice_tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let bob_tip = refs::read_ref(&bob.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let alice_store = ObjectStore::open(alice.path()).unwrap();
    let bob_store = ObjectStore::open(bob.path()).unwrap();

    // alice wins the head CAS off the shared base.
    push_branch(
        &tx,
        &alice_store,
        "main",
        alice_tip,
        RefWriteCondition::Match(shared_tip),
    )
    .expect("alice push wins");

    // bob races with the same expected base → non-fast-forward.
    let bob_err = push_branch(
        &tx,
        &bob_store,
        "main",
        bob_tip,
        RefWriteCondition::Match(shared_tip),
    )
    .unwrap_err();
    assert!(
        matches!(bob_err, DispatchError::NonFastForwardPush { .. }),
        "expected NonFastForwardPush, got {bob_err:?}"
    );

    // The remote head is alice's tip, and a fresh clone reconstructs it
    // byte-for-byte despite bob's losing push having advanced the packmap.
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(alice_tip));
    let carol = tempfile::tempdir().unwrap();
    init_repo(carol.path());
    pull_all(carol.path(), &tx, "default").expect("carol clones");
    assert_eq!(fs::read(carol.path().join("big.bin")).unwrap(), av);

    let carol_tip = refs::read_ref(&carol.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    assert_eq!(carol_tip, alice_tip);
    let carol_store = ObjectStore::open(carol.path()).unwrap();
    for h in reachable_objects(&carol_store, &carol_tip).unwrap() {
        let b = carol_store.read(&h).expect("hash-verified");
        assert_eq!(
            mkit_core::serialize::deserialize(&b).unwrap().id().unwrap(),
            h
        );
    }
}

/// Wraps a [`MemoryTransport`] and makes `download_pack` report
/// `PackNotFound` for a configurable set of keys — simulating a pack that
/// the remote advertised but no longer holds (pruned / corrupt R2).
struct DropPackTransport {
    inner: MemoryTransport,
    dropped: std::sync::Mutex<std::collections::HashSet<PackKey>>,
}

impl DropPackTransport {
    fn new() -> Self {
        Self {
            inner: MemoryTransport::new(),
            dropped: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
    fn drop_pack(&self, key: PackKey) {
        self.dropped.lock().unwrap().insert(key);
    }
}

impl Transport for DropPackTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.inner.upload_pack(bytes, key)
    }
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        if self.dropped.lock().unwrap().contains(key) {
            return Err(TransportError::PackNotFound);
        }
        self.inner.download_pack(key)
    }
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }
    fn update_ref(&self, name: &str, c: RefWriteCondition, h: &hash::Hash) -> TransportResult<()> {
        self.inner.update_ref(name, c, h)
    }
    fn read_ref(&self, name: &str) -> TransportResult<Option<hash::Hash>> {
        self.inner.read_ref(name)
    }
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
}

fn packmap_head_pack(tx: &dyn Transport, branch: &str) -> PackKey {
    // Read the branch's packmap head node and return the pack it lists.
    let pm = tx
        .read_ref(&format!("refs/mkit/packmap/{branch}"))
        .unwrap()
        .unwrap();
    let node_bytes = tx.download_blob(&PackKey::from_hash(pm)).unwrap();
    let node = mkit_core::transfer::decode_packlist(&node_bytes).unwrap();
    PackKey::from_hash(node.packs[0])
}

#[test]
fn fetch_fails_loudly_when_advertised_pack_is_missing() {
    // The packmap promises a pack; if the remote can't deliver it, a fresh
    // clone must error — NOT silently publish a ref to an unreconstructable
    // history (those objects live only inside the pack).
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    fs::write(alice.path().join("big.bin"), big_buffer()).unwrap();
    commit_all(alice.path(), "v1");

    let tx = DropPackTransport::new();
    push_all(alice.path(), &tx).expect("push v1");
    // Drop the pack the packmap advertises.
    tx.drop_pack(packmap_head_pack(&tx, "main"));

    let bob = tempfile::tempdir().unwrap();
    init_repo(bob.path());
    let err = pull_all(bob.path(), &tx, "default").unwrap_err();
    assert!(
        matches!(err, DispatchError::AdvertisedPackMissing { .. }),
        "expected AdvertisedPackMissing, got {err:?}"
    );
    // Bob must NOT have recorded a remote-tracking ref for the broken branch.
    assert!(
        refs::read_remote_ref(&bob.path().join(".mkit"), "default", "main")
            .unwrap()
            .is_none(),
        "no ref should be published for an incompletely-fetched branch"
    );
}

#[test]
fn push_blocks_on_a_corrupt_prior_packmap_without_moving_head() {
    // A non-self-contained push cannot safely append onto a chain whose tail
    // is unreadable (its delta bases live there) — it must block before the
    // head moves.
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    fs::write(alice.path().join("big.bin"), big_buffer()).unwrap();
    commit_all(alice.path(), "v1");

    let tx = MemoryTransport::new();
    push_all(alice.path(), &tx).expect("push v1");
    let v1_tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();

    // Corrupt the packmap: point it at a node that does not exist.
    tx.update_ref(
        "refs/mkit/packmap/main",
        RefWriteCondition::Any,
        &[0xEE; 32],
    )
    .unwrap();

    // Edit + commit v2, then push the branch (fast-forward off v1).
    let mut v2 = big_buffer();
    v2[500_000] ^= 0xFF;
    fs::write(alice.path().join("big.bin"), &v2).unwrap();
    commit_all(alice.path(), "v2");
    let v2_tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let store = ObjectStore::open(alice.path()).unwrap();

    let err = push_branch(
        &tx,
        &store,
        "main",
        v2_tip,
        RefWriteCondition::Match(v1_tip),
    )
    .unwrap_err();
    assert!(
        matches!(err, DispatchError::PackChainInvalid { .. }),
        "expected PackChainInvalid, got {err:?}"
    );
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(v1_tip),
        "head must not move past a corrupt packmap"
    );
}

#[test]
fn self_contained_push_resets_a_corrupt_packmap_chain() {
    // A full-closure (self-contained) push CAN escape a broken chain by
    // resetting to a fresh one, then a clone reconstructs from it.
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    fs::write(alice.path().join("a.bin"), big_buffer()).unwrap();
    commit_all(alice.path(), "alice-v1");

    let tx = MemoryTransport::new();
    push_all(alice.path(), &tx).expect("push alice v1");
    // Corrupt the packmap chain head.
    tx.update_ref(
        "refs/mkit/packmap/main",
        RefWriteCondition::Any,
        &[0xEE; 32],
    )
    .unwrap();

    // carol: a *fresh root* commit (no parents, complete local closure) that
    // does not share alice's objects → the push diffs against a remote tip it
    // lacks, so the plan is self-contained.
    let carol = tempfile::tempdir().unwrap();
    init_repo(carol.path());
    let carol_data = {
        let mut d = big_buffer();
        d[0] ^= 0xAA; // make it distinct content
        d
    };
    fs::write(carol.path().join("c.bin"), &carol_data).unwrap();
    commit_all(carol.path(), "carol-root");
    let carol_tip = refs::read_ref(&carol.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let carol_store = ObjectStore::open(carol.path()).unwrap();

    // Force-push over the divergent head; the self-contained plan resets the
    // broken chain instead of blocking.
    push_branch(&tx, &carol_store, "main", carol_tip, RefWriteCondition::Any)
        .expect("self-contained push should reset and succeed");
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(carol_tip));

    // The packmap is healthy again — a fresh clone reconstructs carol's tree.
    let dave = tempfile::tempdir().unwrap();
    init_repo(dave.path());
    pull_all(dave.path(), &tx, "default").expect("clone after reset");
    assert_eq!(fs::read(dave.path().join("c.bin")).unwrap(), carol_data);
}

#[test]
fn push_blocks_on_a_corrupt_deeper_packmap_node() {
    // The packmap HEAD node decodes fine, but a DEEPER node it chains to is
    // missing. A non-self-contained push must walk the whole chain, detect
    // the break, and block — never moving the head onto a chain fetch can't
    // walk. (The shallow case corrupts the ref itself; this covers depth.)
    let alice = tempfile::tempdir().unwrap();
    init_repo(alice.path());
    let tx = DropPackTransport::new();

    // v1 → chain node N1 (the soon-to-be-deeper node).
    let mut data = big_buffer();
    fs::write(alice.path().join("big.bin"), &data).unwrap();
    commit_all(alice.path(), "v1");
    push_all(alice.path(), &tx).expect("push v1");
    let n1 = tx.read_ref("refs/mkit/packmap/main").unwrap().unwrap();

    // v2 → head node N2 (prev = N1).
    data[400_000] ^= 0xFF;
    fs::write(alice.path().join("big.bin"), &data).unwrap();
    commit_all(alice.path(), "v2");
    push_all(alice.path(), &tx).expect("push v2");
    let n2 = tx.read_ref("refs/mkit/packmap/main").unwrap().unwrap();
    assert_ne!(n1, n2, "v2 must chain a new head node");
    let v2_tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();

    // Drop the DEEPER node N1; the head node N2 still decodes.
    tx.drop_pack(PackKey::from_hash(n1));

    // v3 → a non-self-contained push (diffs against v2, which alice holds).
    data[400_000] ^= 0xFF; // back to v1 byte; still a fresh chunk vs v2
    data[1_200_000] ^= 0xAA;
    fs::write(alice.path().join("big.bin"), &data).unwrap();
    commit_all(alice.path(), "v3");
    let v3_tip = refs::read_ref(&alice.path().join(".mkit"), "main")
        .unwrap()
        .unwrap();
    let store = ObjectStore::open(alice.path()).unwrap();

    let err = push_branch(
        &tx,
        &store,
        "main",
        v3_tip,
        RefWriteCondition::Match(v2_tip),
    )
    .unwrap_err();
    assert!(
        matches!(err, DispatchError::PackChainInvalid { .. }),
        "a deeper broken node must block the push, got {err:?}"
    );
    assert_eq!(
        tx.read_ref("refs/heads/main").unwrap(),
        Some(v2_tip),
        "head must not move onto a chain with a broken deeper node"
    );
}

#[test]
fn advance_refs_default_distinguishes_packmap_and_head_conflicts() {
    // The #408 atomic-advance primitive: even the non-transactional default
    // impl must report WHICH precondition failed, so the push loop can retry
    // a packmap conflict but fail a head conflict.
    use mkit_core::protocol::AdvanceOutcome;
    let tx = MemoryTransport::new();
    let head = "refs/heads/main";
    let pm = "refs/mkit/packmap/main";
    let (a, b, c, d, wrong) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [9u8; 32]);

    // Both fresh → Committed; both refs land.
    assert_eq!(
        tx.advance_refs(
            head,
            RefWriteCondition::Missing,
            &a,
            pm,
            RefWriteCondition::Missing,
            &b
        )
        .unwrap(),
        AdvanceOutcome::Committed
    );
    assert_eq!(tx.read_ref(head).unwrap(), Some(a));
    assert_eq!(tx.read_ref(pm).unwrap(), Some(b));

    // Packmap precondition wrong → PackmapConflict; NOTHING moves (packmap is
    // attempted first and fails before the head is touched).
    assert_eq!(
        tx.advance_refs(
            head,
            RefWriteCondition::Match(a),
            &c,
            pm,
            RefWriteCondition::Match(wrong),
            &d
        )
        .unwrap(),
        AdvanceOutcome::PackmapConflict
    );
    assert_eq!(
        tx.read_ref(head).unwrap(),
        Some(a),
        "head unchanged on packmap conflict"
    );
    assert_eq!(
        tx.read_ref(pm).unwrap(),
        Some(b),
        "packmap unchanged on packmap conflict"
    );

    // Head precondition wrong → HeadConflict; the head stays put. The default
    // impl commits the packmap first (documented), so it advances to d — a
    // superset, still safe; an atomic transport would leave it at b.
    assert_eq!(
        tx.advance_refs(
            head,
            RefWriteCondition::Match(wrong),
            &c,
            pm,
            RefWriteCondition::Match(b),
            &d
        )
        .unwrap(),
        AdvanceOutcome::HeadConflict
    );
    assert_eq!(
        tx.read_ref(head).unwrap(),
        Some(a),
        "head unchanged on head conflict"
    );
    assert_eq!(
        tx.read_ref(pm).unwrap(),
        Some(d),
        "default impl commits packmap before head"
    );
}
