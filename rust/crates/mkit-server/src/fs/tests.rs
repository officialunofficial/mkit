//! Backend tests the black-box storage suite cannot see: the on-disk
//! layout (interop with `FileTransport` both ways), temp-file hygiene, the
//! path-escape guard, the lock file, streaming reads, and rule 8's
//! clock-under-the-lock ordering.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use futures_executor::block_on;
use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport as _};
use mkit_transport_file::FileTransport;
use tempfile::TempDir;

use super::blob::READ_BLOCK;
use super::{FsBlobStore, FsLayoutStore};
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::Clock;
use crate::store::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobStore, ByteRange, CommitOutcome, Key,
    NamespaceStore, PackSink, Partition, Precondition, StoreError, Value, codec, keys, read,
};

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new("room-a").unwrap(),
    }
}

fn part() -> Partition {
    Partition::Namespace(NamespaceKey::deployment_default())
}

fn ref_key(name: &str) -> Key {
    keys::ref_key(&repo().name, name)
}

fn id(seed: &[u8]) -> [u8; 32] {
    hash(seed)
}

fn layout(root: &Path) -> FsLayoutStore {
    FsLayoutStore::new(root, &repo())
}

fn apply(store: &FsLayoutStore, batch: Batch) -> Result<BatchOutcome, StoreError> {
    block_on(store.apply(&part(), batch))
}

fn put_blob(
    store: &FsBlobStore,
    key: BlobKey,
    len: u64,
    chunks: &[&[u8]],
) -> Result<CommitOutcome, StoreError> {
    block_on(async {
        let mut sink = store.begin(key, len).await?;
        for chunk in chunks {
            sink.write(Bytes::copy_from_slice(chunk)).await?;
        }
        sink.commit().await
    })
}

/// Every path under `root`, relative to it.
fn listing(root: &Path) -> BTreeSet<PathBuf> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeSet<PathBuf>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            out.insert(path.strip_prefix(root).unwrap().to_path_buf());
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn layout_interop_filetransport_reads_what_fsstores_wrote() {
    let dir = TempDir::new().unwrap();
    let data = b"pack bytes from the blob store";
    let key = PackKey::new(hash(data));
    let blobs = FsBlobStore::new(dir.path());
    assert_eq!(
        put_blob(&blobs, key, data.len() as u64, &[&data[..9], &data[9..]]).unwrap(),
        CommitOutcome::Created
    );
    let refs = layout(dir.path());
    let main = id(b"main");
    let put = Batch::new()
        .require(Precondition::Absent(ref_key("refs/heads/main")))
        .put(ref_key("refs/heads/main"), codec::encode_ref_id(&main));
    assert_eq!(apply(&refs, put).unwrap(), BatchOutcome::Committed);

    let tx = FileTransport::new(dir.path());
    assert_eq!(tx.download_pack(&key).unwrap(), data);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(main));
    // The same bytes FileTransport writes: 64 lowercase hex and a newline.
    let wire = fs::read(dir.path().join("refs/heads/main")).unwrap();
    assert_eq!(
        wire,
        format!("{}\n", mkit_core::hash::to_hex(&main)).as_bytes()
    );
    let listed = tx.list_refs("").unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "refs/heads/main");
}

#[test]
fn layout_interop_fsstores_read_what_filetransport_wrote() {
    let dir = TempDir::new().unwrap();
    let tx = FileTransport::new(dir.path());
    let data = vec![7_u8; 3000];
    let key = PackKey::new(hash(&data));
    tx.upload_pack(&data, &key).unwrap();
    let (a, b) = (id(b"a"), id(b"b"));
    tx.update_ref("refs/heads/main", RefWriteCondition::Missing, &a)
        .unwrap();
    tx.update_ref("refs/tags/v1", RefWriteCondition::Missing, &b)
        .unwrap();

    let blobs = FsBlobStore::new(dir.path());
    let Some(BlobBody::Bytes(got)) = block_on(blobs.get(&key, None)).unwrap() else {
        panic!("a small pack is one buffer");
    };
    assert_eq!(got, data);
    assert_eq!(
        block_on(blobs.head(&key)).unwrap().map(|m| m.len),
        Some(3000)
    );

    let refs = layout(dir.path());
    let name = &repo().name;
    assert_eq!(
        block_on(read::read_ref(&refs, &part(), name, "refs/heads/main")).unwrap(),
        Some(a)
    );
    // `list_refs` returns names relative to the listed directory; the store
    // turns them back into full `refs/...` names.
    let page = block_on(read::list_refs(&refs, &part(), name, "refs/", None, 10)).unwrap();
    assert_eq!(
        page.refs,
        vec![
            ("refs/heads/main".to_owned(), a),
            ("refs/tags/v1".to_owned(), b)
        ]
    );
    assert_eq!(page.next, None);
    // A guarded update through the store is FileTransport's CAS.
    let stale = Batch::new()
        .require(Precondition::Equals(
            ref_key("refs/heads/main"),
            codec::encode_ref_id(&b),
        ))
        .put(ref_key("refs/heads/main"), codec::encode_ref_id(&b));
    assert_eq!(
        apply(&refs, stale).unwrap(),
        BatchOutcome::PreconditionFailed {
            index: 0,
            observed: Some(codec::encode_ref_id(&a)),
        }
    );
    let advance = Batch::new()
        .require(Precondition::Equals(
            ref_key("refs/heads/main"),
            codec::encode_ref_id(&a),
        ))
        .put(ref_key("refs/heads/main"), codec::encode_ref_id(&b));
    assert_eq!(apply(&refs, advance).unwrap(), BatchOutcome::Committed);
    assert_eq!(tx.read_ref("refs/heads/main").unwrap(), Some(b));
}

#[test]
fn layout_non_ref_names_live_outside_the_ref_directory() {
    let dir = TempDir::new().unwrap();
    let refs = layout(dir.path());
    let odd = keys::ref_key(&repo().name, "not-under-refs");
    let put = Batch::new().put(odd.clone(), Value::new(&b"any bytes"[..]));
    assert_eq!(apply(&refs, put).unwrap(), BatchOutcome::Committed);
    assert_eq!(
        block_on(refs.get(&part(), &odd)).unwrap(),
        Some(Value::new(&b"any bytes"[..]))
    );
    // FileTransport never sees it, and the ref directory stays empty.
    let tx = FileTransport::new(dir.path());
    assert_eq!(tx.list_refs("").unwrap(), vec![]);
    assert!(!dir.path().join("refs").exists());
    assert!(!dir.path().join("not-under-refs").exists());
    // A ref's value is its 32-byte id.
    let bad = Batch::new().put(ref_key("refs/heads/x"), Value::new(&b"short"[..]));
    assert!(matches!(apply(&refs, bad), Err(StoreError::Invalid(_))));
    assert_eq!(tx.read_ref("refs/heads/x").unwrap(), None);
}

#[test]
fn layout_rejects_other_partitions_and_repos() {
    let dir = TempDir::new().unwrap();
    let refs = layout(dir.path());
    let other_part = Partition::Coordinator(NamespaceKey::deployment_default());
    let key = ref_key("refs/heads/main");
    assert!(matches!(
        block_on(refs.get(&other_part, &key)),
        Err(StoreError::Unsupported(_))
    ));
    let put = Batch::new().put(key, codec::encode_ref_id(&id(b"x")));
    assert!(matches!(
        block_on(refs.apply(&other_part, put)),
        Err(StoreError::Unsupported(_))
    ));
    let other_repo = keys::ref_key(&RepoName::new("room-b").unwrap(), "refs/heads/main");
    let put = Batch::new().put(other_repo, codec::encode_ref_id(&id(b"x")));
    assert!(matches!(apply(&refs, put), Err(StoreError::Unsupported(_))));
    assert!(!dir.path().join("refs").exists());
}

#[test]
fn blob_rejected_commit_leaves_no_file_and_no_temp() {
    let dir = TempDir::new().unwrap();
    let blobs = FsBlobStore::new(dir.path());
    let seed = b"seed";
    put_blob(&blobs, PackKey::new(hash(seed)), 4, &[seed]).unwrap();
    let before = listing(dir.path());
    let key = PackKey::new(hash(b"hello"));
    for (key, len, chunks) in [
        (PackKey::new(hash(b"other")), 5, &[&b"hello"[..]][..]),
        (key, 6, &[&b"hello"[..]][..]),
        (key, 4, &[&b"hel"[..], b"lo"][..]),
    ] {
        assert!(matches!(
            put_blob(&blobs, key, len, chunks),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(listing(dir.path()), before);
    }
    // Aborted and dropped uploads leave nothing either.
    block_on(async {
        let mut sink = blobs.begin(key, 5).await.unwrap();
        sink.write(Bytes::from_static(b"hel")).await.unwrap();
        assert_ne!(
            listing(dir.path()),
            before,
            "the temp file exists mid-upload"
        );
        sink.abort().await;
        let mut sink = blobs.begin(key, 5).await.unwrap();
        sink.write(Bytes::from_static(b"hel")).await.unwrap();
        drop(sink);
    });
    assert_eq!(listing(dir.path()), before);
}

#[test]
fn blob_rejected_commit_never_overwrites_existing() {
    let dir = TempDir::new().unwrap();
    let blobs = FsBlobStore::new(dir.path());
    let data = b"the real pack";
    let key = PackKey::new(hash(data));
    put_blob(&blobs, key, data.len() as u64, &[data]).unwrap();
    // Same key, same length, wrong bytes: rejected, and the stored blob is
    // untouched (SPEC-TRANSPORT-CONNECT §11).
    let forged = b"a forged pack";
    assert_eq!(forged.len(), data.len());
    assert!(matches!(
        put_blob(&blobs, key, data.len() as u64, &[forged]),
        Err(StoreError::Invalid(_))
    ));
    let path = dir.path().join("packs").join(key.to_hex());
    assert_eq!(fs::read(&path).unwrap(), data);
    // A verified re-upload reports the blob as already there.
    assert_eq!(
        put_blob(&blobs, key, data.len() as u64, &[data]).unwrap(),
        CommitOutcome::AlreadyPresent
    );
    assert_eq!(fs::read(&path).unwrap(), data);
}

#[test]
fn blob_get_range_streams_without_reading_whole_file() {
    let dir = TempDir::new().unwrap();
    let blobs = FsBlobStore::new(dir.path());
    let data: Vec<u8> = (0..=250_u8).cycle().take(5 * 1024 * 1024).collect();
    let key = PackKey::new(hash(&data));
    let pieces: Vec<&[u8]> = data.chunks(300_000).collect();
    put_blob(&blobs, key, data.len() as u64, &pieces).unwrap();
    let read_all = |range| {
        let body = block_on(blobs.get(&key, range)).unwrap().unwrap();
        let BlobBody::Stream { len, mut stream } = body else {
            panic!("a body over 1 MiB is streamed");
        };
        let (mut out, mut blocks) = (Vec::new(), 0);
        while let Some(piece) = block_on(core::future::poll_fn(|cx| stream.as_mut().poll_next(cx)))
        {
            let piece = piece.unwrap();
            assert!(piece.len() <= READ_BLOCK);
            out.extend_from_slice(&piece);
            blocks += 1;
        }
        assert_eq!(out.len() as u64, len);
        (out, blocks)
    };
    let (whole, blocks) = read_all(None);
    assert_eq!(whole, data);
    assert_eq!(blocks, data.len() / READ_BLOCK);
    let range = ByteRange {
        start: 1,
        end_inclusive: 3 * 1024 * 1024,
    };
    let (part, blocks) = read_all(Some(range));
    assert_eq!(part, &data[1..=3 * 1024 * 1024]);
    assert_eq!(blocks, (3 * 1024 * 1024_usize).div_ceil(READ_BLOCK));
    // A small range is one buffer, read from its offset.
    let small = ByteRange {
        start: 4 * 1024 * 1024,
        end_inclusive: 4 * 1024 * 1024 + 9,
    };
    let Some(BlobBody::Bytes(got)) = block_on(blobs.get(&key, Some(small))).unwrap() else {
        panic!("a small range is one buffer");
    };
    assert_eq!(got, &data[4 * 1024 * 1024..=4 * 1024 * 1024 + 9]);
}

#[cfg(unix)]
#[test]
fn layout_symlink_escape_rejected() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let target = outside.path().join("secret");
    fs::write(
        &target,
        format!("{}\n", mkit_core::hash::to_hex(&id(b"secret"))),
    )
    .unwrap();
    fs::create_dir_all(dir.path().join("refs/heads")).unwrap();
    symlink(&target, dir.path().join("refs/heads/evil")).unwrap();

    let refs = layout(dir.path());
    let key = ref_key("refs/heads/evil");
    assert!(matches!(
        block_on(refs.get(&part(), &key)),
        Err(StoreError::Unavailable(_))
    ));
    let before = fs::read(&target).unwrap();
    let put = Batch::new().put(key, codec::encode_ref_id(&id(b"new")));
    assert!(matches!(apply(&refs, put), Err(StoreError::Unavailable(_))));
    assert_eq!(fs::read(&target).unwrap(), before);
}

#[test]
fn layout_cas_lock_file_path_is_dot_mkit_refs_lock() {
    let dir = TempDir::new().unwrap();
    let refs = layout(dir.path());
    let lock = dir.path().join(".mkit").join("refs").join(".lock");
    assert!(!lock.exists());
    let put = Batch::new().put(ref_key("refs/heads/main"), codec::encode_ref_id(&id(b"a")));
    assert_eq!(apply(&refs, put).unwrap(), BatchOutcome::Committed);
    assert!(lock.is_file());
}

/// A clock that records, each time it is read, whether the ref lock file
/// is held by someone else (this store) at that moment.
struct LockProbe {
    lock: PathBuf,
    now_ms: i64,
    reads: AtomicUsize,
    held: AtomicBool,
}

impl Clock for LockProbe {
    fn now_ms(&self) -> i64 {
        self.reads.fetch_add(1, Ordering::SeqCst);
        // flock(2) conflicts across open file descriptions, even within
        // one process: a second handle cannot take a lock the store holds.
        let held = match fs::File::open(&self.lock) {
            Ok(file) => file.try_lock().is_err(),
            Err(_) => false,
        };
        self.held.store(held, Ordering::SeqCst);
        self.now_ms
    }
}

#[test]
fn layout_not_after_reads_the_clock_under_the_ref_lock() {
    let dir = TempDir::new().unwrap();
    let probe = Arc::new(LockProbe {
        lock: dir.path().join(".mkit").join("refs").join(".lock"),
        now_ms: 2_000,
        reads: AtomicUsize::new(0),
        held: AtomicBool::new(false),
    });
    let refs = layout(dir.path()).with_clock(probe.clone());
    let key = ref_key("refs/heads/main");
    let batch = |deadline| {
        Batch::new()
            .require(Precondition::NotAfter(deadline))
            .require(Precondition::Absent(key.clone()))
            .put(key.clone(), codec::encode_ref_id(&id(b"a")))
    };
    // Late: the reading happens under the lock, and nothing is written.
    assert_eq!(
        apply(&refs, batch(1_999)).unwrap(),
        BatchOutcome::DeadlinePassed { backend_now: 2_000 }
    );
    assert_eq!(probe.reads.load(Ordering::SeqCst), 1);
    assert!(
        probe.held.load(Ordering::SeqCst),
        "clock read before the lock"
    );
    assert_eq!(block_on(refs.get(&part(), &key)).unwrap(), None);
    // On time: read once more, under the lock again, and committed.
    probe.held.store(false, Ordering::SeqCst);
    assert_eq!(apply(&refs, batch(2_000)).unwrap(), BatchOutcome::Committed);
    assert_eq!(probe.reads.load(Ordering::SeqCst), 2);
    assert!(
        probe.held.load(Ordering::SeqCst),
        "clock read before the lock"
    );
    // A batch without a deadline never reads the clock.
    let plain = Batch::new().put(key, codec::encode_ref_id(&id(b"b")));
    assert_eq!(apply(&refs, plain).unwrap(), BatchOutcome::Committed);
    assert_eq!(probe.reads.load(Ordering::SeqCst), 2);
}
