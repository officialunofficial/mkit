//! Backend tests the black-box storage suite cannot see: the on-disk
//! layout (interop with `FileTransport` both ways), temp-file hygiene, the
//! path-escape guard, the lock file, streaming reads, and rule 8's
//! clock-under-the-lock ordering, the `refs/` side against a model, file
//! name limits, ref clashes, corrupt ref files and I/O error mapping.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use futures_executor::block_on;
use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport as _};
use mkit_transport_file::FileTransport;
use tempfile::TempDir;

use proptest::prelude::*;

use super::blob::READ_BLOCK;
use super::io_error;
use super::layout::{MAX_SHORT_ROW, NAME_MAX, max_temp_name};
use super::{FsBlobStore, FsLayoutStore};
use crate::MemoryKv;
use crate::repo::{NamespaceKey, RepoId, RepoName};
use crate::rt::{Clock, ManualClock};
use crate::store::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobStore, ByteRange, CommitOutcome, Cursor, Key,
    NamespaceStore, PackSink, Partition, Precondition, ScanPage, StoreCapabilities, StoreError,
    Value, codec, keys, read,
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

// ---------------------------------------------------------------------
// Row file names: the 255-byte file-name limit
// ---------------------------------------------------------------------

#[test]
fn row_file_and_temp_names_fit_name_max_at_the_limits() {
    let dir = TempDir::new().unwrap();
    let refs = layout(dir.path());
    let rows = dir.path().join(".mkit/server/rows");
    // The longest short row file name, and the longest temp name
    // FileTransport can derive from it: pid u32::MAX, seq u64::MAX.
    let longest = format!("n{}", "ab".repeat(MAX_SHORT_ROW));
    let temp = format!(".{longest}.tmp.{}.{}", u32::MAX, u64::MAX);
    assert_eq!(temp.len(), max_temp_name(longest.len()));
    assert!(temp.len() <= NAME_MAX, "{}", temp.len());
    // The filesystem takes it (the case that used to fail: a 120-byte name
    // plus a long seq went past 255).
    fs::create_dir_all(&rows).unwrap();
    fs::write(rows.join(&temp), b"x").unwrap();
    fs::remove_file(rows.join(&temp)).unwrap();
    // Round trips at, just past and far past the short-name limit.
    for len in [MAX_SHORT_ROW, MAX_SHORT_ROW + 1, 1000] {
        let key = keys::ref_key(&repo().name, &"x".repeat(len));
        let value = Value::new(vec![7; len]);
        let put = Batch::new()
            .require(Precondition::Absent(key.clone()))
            .put(key.clone(), value.clone());
        assert_eq!(apply(&refs, put).unwrap(), BatchOutcome::Committed, "{len}");
        assert_eq!(block_on(refs.get(&part(), &key)).unwrap(), Some(value));
    }
    for entry in fs::read_dir(&rows).unwrap() {
        let name = entry.unwrap().file_name();
        assert!(name.len() <= 1 + 2 * MAX_SHORT_ROW, "{name:?}");
    }
}

// ---------------------------------------------------------------------
// Ref clashes, pruning, corrupt ref files
// ---------------------------------------------------------------------

#[test]
fn layout_ref_directory_file_clash_is_invalid_and_delete_prunes() {
    let dir = TempDir::new().unwrap();
    let refs = layout(dir.path());
    let put = |name: &str| Batch::new().put(ref_key(name), codec::encode_ref_id(&id(b"v")));
    assert_eq!(
        apply(&refs, put("refs/heads/a/b")).unwrap(),
        BatchOutcome::Committed
    );
    // `refs/heads/a` would be a file where a directory is.
    assert!(matches!(
        apply(&refs, put("refs/heads/a")),
        Err(StoreError::Invalid(_))
    ));
    // `refs/heads/a/b/c` would be a directory where a file is.
    assert!(matches!(
        apply(&refs, put("refs/heads/a/b/c")),
        Err(StoreError::Invalid(_))
    ));
    // The directory reads as no ref, and deleting it deletes nothing.
    assert_eq!(
        block_on(refs.get(&part(), &ref_key("refs/heads/a"))).unwrap(),
        None
    );
    let del = |name: &str| Batch::new().delete(ref_key(name));
    assert_eq!(
        apply(&refs, del("refs/heads/a")).unwrap(),
        BatchOutcome::Committed
    );
    assert!(dir.path().join("refs/heads/a/b").is_file());
    // Deleting the ref removes the directories it emptied, so the name
    // is free again.
    assert_eq!(
        apply(&refs, del("refs/heads/a/b")).unwrap(),
        BatchOutcome::Committed
    );
    assert!(!dir.path().join("refs/heads").exists());
    assert!(dir.path().join("refs").is_dir());
    assert_eq!(
        apply(&refs, put("refs/heads/a")).unwrap(),
        BatchOutcome::Committed
    );
}

/// A ref file that does not decode is `Corrupt` for a read of its name
/// and for a precondition on it, but a scan skips it (with a warning), as
/// `FileTransport::list_refs` does: one stray file (`refs/heads/README`)
/// must not fail every listing, in its range or out of it.
#[test]
fn layout_corrupt_ref_file_is_corrupt_for_reads_and_preconditions_skipped_by_scans() {
    let dir = TempDir::new().unwrap();
    let refs = layout(dir.path());
    fs::create_dir_all(dir.path().join("refs/heads")).unwrap();
    fs::create_dir_all(dir.path().join("refs/tags")).unwrap();
    fs::write(dir.path().join("refs/heads/bad"), b"garbage\n").unwrap();
    fs::write(dir.path().join("refs/tags/README"), b"not a ref\n").unwrap();
    let good = id(b"good");
    let put = Batch::new().put(ref_key("refs/heads/good"), codec::encode_ref_id(&good));
    assert_eq!(apply(&refs, put).unwrap(), BatchOutcome::Committed);
    let key = ref_key("refs/heads/bad");
    assert!(matches!(
        block_on(refs.get(&part(), &key)),
        Err(StoreError::Corrupt(_))
    ));
    for prefix in ["refs/", "refs/heads/"] {
        let (start, end) = keys::ref_prefix_range(&repo().name, prefix);
        let page = block_on(refs.scan(&part(), &start, &end, None, 10)).unwrap();
        let listed: Vec<_> = page.entries.iter().map(|(k, _)| k.clone()).collect();
        assert_eq!(listed, [ref_key("refs/heads/good")], "{prefix}");
    }
    let new = codec::encode_ref_id(&id(b"new"));
    for pre in [
        Precondition::Absent(key.clone()),
        Precondition::Present(key.clone()),
        Precondition::Equals(key.clone(), new.clone()),
    ] {
        let batch = Batch::new().require(pre).put(key.clone(), new.clone());
        assert!(matches!(apply(&refs, batch), Err(StoreError::Corrupt(_))));
    }
    assert_eq!(
        fs::read(dir.path().join("refs/heads/bad")).unwrap(),
        b"garbage\n"
    );
}

/// Plant a ref file the way a server did before SPEC-REFS §3 bounded
/// names (`FileTransport` now refuses to write one).
fn plant_legacy_ref(root: &Path, name: &str, id: &[u8; 32]) {
    let path = name.split('/').fold(root.to_path_buf(), |p, s| p.join(s));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, mkit_core::refs::encode_ref_wire(id)).unwrap();
}

/// A ref file whose name is over the 512-byte limit (SPEC-REFS §3),
/// written by an older server, is skipped by scans with a warning; the
/// pipeline refuses the name before it reaches the store.
#[test]
fn layout_scan_skips_over_long_legacy_ref_files() {
    let dir = TempDir::new().unwrap();
    let long = format!("refs/heads/{}", vec!["a".repeat(200); 3].join("/"));
    assert!(long.len() > crate::refs::MAX_REF_NAME_BYTES);
    let tx = FileTransport::new(dir.path());
    plant_legacy_ref(dir.path(), &long, &id(b"long"));
    tx.update_ref("refs/heads/main", RefWriteCondition::Any, &id(b"main"))
        .unwrap();
    let refs = layout(dir.path());
    let (start, end) = keys::ref_prefix_range(&repo().name, "refs/");
    let page = block_on(refs.scan(&part(), &start, &end, None, 10)).unwrap();
    let listed: Vec<_> = page.entries.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(listed, [ref_key("refs/heads/main")]);
}

#[test]
fn io_errors_map_full_clash_and_outage() {
    let kind = |k: io::ErrorKind| io_error(io::Error::from(k));
    assert!(matches!(kind(io::ErrorKind::StorageFull), StoreError::Full));
    assert!(matches!(
        kind(io::ErrorKind::QuotaExceeded),
        StoreError::Full
    ));
    assert!(matches!(
        kind(io::ErrorKind::IsADirectory),
        StoreError::Invalid(_)
    ));
    assert!(matches!(
        kind(io::ErrorKind::NotADirectory),
        StoreError::Invalid(_)
    ));
    for other in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Interrupted,
        io::ErrorKind::Other,
    ] {
        assert!(
            matches!(kind(other), StoreError::Unavailable(_)),
            "{other:?}"
        );
    }
    // ENOSPC and EDQUOT from the OS map the same way.
    #[cfg(unix)]
    for errno in [28, if cfg!(target_os = "linux") { 122 } else { 69 }] {
        let e = io::Error::from_raw_os_error(errno);
        assert!(matches!(io_error(e), StoreError::Full), "errno {errno}");
    }
}

// ---------------------------------------------------------------------
// The `refs/` side against the reference model
// ---------------------------------------------------------------------

/// Ref names with no directory/file clash among them.
const NAMES: [&str; 5] = [
    "refs/heads/a",
    "refs/heads/b",
    "refs/heads/c-d",
    "refs/tags/v1",
    "refs/x",
];

fn model_id(i: u8) -> Value {
    codec::encode_ref_id(&[i; 32])
}

/// A batch's write.
#[derive(Debug, Clone)]
enum W {
    None,
    Delete,
    Put(u8),
}

#[derive(Debug, Clone)]
enum Guard {
    None,
    Absent,
    Present,
    Equals(u8),
}

#[derive(Debug, Clone)]
enum Op {
    /// One single-key batch: an optional deadline (relative to now), a
    /// guard on the key, and a write.
    Apply {
        name: usize,
        deadline: Option<i64>,
        guard: Guard,
        write: W,
    },
    Get(usize),
    GetMany(Vec<usize>),
    /// Page through the refs from `NAMES[from]` on, `limit` at a time.
    Scan {
        from: usize,
        limit: u32,
    },
    /// Drop the store and open the root again.
    Reopen,
    Tick(i64),
}

fn op() -> impl Strategy<Value = Op> {
    let name = 0..NAMES.len();
    let guard = prop_oneof![
        Just(Guard::None),
        Just(Guard::Absent),
        Just(Guard::Present),
        (0_u8..3).prop_map(Guard::Equals),
    ];
    let write = prop_oneof![Just(W::None), Just(W::Delete), (0_u8..3).prop_map(W::Put)];
    prop_oneof![
        6 => (name.clone(), proptest::option::of(-2_i64..=2), guard, write).prop_map(
            |(name, deadline, guard, write)| Op::Apply { name, deadline, guard, write }
        ),
        2 => name.clone().prop_map(Op::Get),
        1 => proptest::collection::vec(name.clone(), 0..4).prop_map(Op::GetMany),
        2 => (name, 1_u32..4).prop_map(|(from, limit)| Op::Scan { from, limit }),
        1 => Just(Op::Reopen),
        1 => (-3_i64..=3).prop_map(Op::Tick),
    ]
}

fn batch_of(name: usize, deadline: Option<i64>, guard: &Guard, write: &W, now: i64) -> Batch {
    let key = ref_key(NAMES[name]);
    let mut batch = Batch::new();
    if let Some(delta) = deadline {
        batch = batch.require(Precondition::NotAfter(u64::try_from(now + delta).unwrap()));
    }
    batch = match guard {
        Guard::None => batch,
        Guard::Absent => batch.require(Precondition::Absent(key.clone())),
        Guard::Present => batch.require(Precondition::Present(key.clone())),
        Guard::Equals(v) => batch.require(Precondition::Equals(key.clone(), model_id(*v))),
    };
    match write {
        W::None => batch,
        W::Delete => batch.delete(key),
        W::Put(v) => batch.put(key, model_id(*v)),
    }
}

/// Every page of a scan from `start`, `limit` at a time.
fn pages<S: NamespaceStore>(s: &S, start: &Key, end: &Key, limit: u32) -> Vec<ScanPage> {
    let (mut out, mut after): (Vec<ScanPage>, Option<Cursor>) = (Vec::new(), None);
    loop {
        let page = block_on(s.scan(&part(), start, end, after.as_ref(), limit)).unwrap();
        after.clone_from(&page.next);
        out.push(page);
        if after.is_none() || out.len() > 16 {
            return out;
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 12,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Random single-key batches, reads, paged scans, deadlines and reopens
    /// on `refs/` names with 32-byte ids: `FsLayoutStore` answers exactly
    /// as the refs-only `MemoryKv`.
    #[test]
    fn layout_refs_match_the_memory_model(ops in proptest::collection::vec(op(), 1..24)) {
        let dir = TempDir::new().unwrap();
        let clock = Arc::new(ManualClock::new(1_000));
        let open = || layout(dir.path()).with_clock(clock.clone());
        let model = MemoryKv::with_clock(clock.clone())
            .with_capabilities(StoreCapabilities::refs_only());
        let mut fs_store = open();
        let p = part();
        let (_, end) = keys::ref_prefix_range(&repo().name, "refs/");
        for op in ops {
            match op {
                Op::Apply { name, deadline, guard, write } => {
                    let batch = batch_of(name, deadline, &guard, &write, clock.now_ms());
                    let want = block_on(model.apply(&p, batch.clone())).unwrap();
                    let got = block_on(fs_store.apply(&p, batch.clone())).unwrap();
                    prop_assert_eq!(got, want, "{:?}", batch);
                }
                Op::Get(name) => {
                    let key = ref_key(NAMES[name]);
                    let want = block_on(model.get(&p, &key)).unwrap();
                    prop_assert_eq!(block_on(fs_store.get(&p, &key)).unwrap(), want.clone());
                    prop_assert_eq!(block_on(fs_store.has(&p, &key)).unwrap(), want.is_some());
                }
                Op::GetMany(names) => {
                    let keys: Vec<Key> = names.iter().map(|n| ref_key(NAMES[*n])).collect();
                    let want = block_on(model.get_many(&p, &keys)).unwrap();
                    prop_assert_eq!(block_on(fs_store.get_many(&p, &keys)).unwrap(), want);
                }
                Op::Scan { from, limit } => {
                    let start = ref_key(NAMES[from]);
                    let want = pages(&model, &start, &end, limit);
                    prop_assert_eq!(pages(&fs_store, &start, &end, limit), want);
                }
                Op::Reopen => fs_store = open(),
                Op::Tick(delta) => clock.advance(delta),
            }
        }
        // Everything the model holds is on disk as FileTransport ref files.
        drop(fs_store);
        let tx = FileTransport::new(dir.path());
        let all = pages(&model, &ref_key("refs/"), &end, 100);
        let on_disk: Vec<(String, [u8; 32])> = tx
            .list_refs("refs/")
            .unwrap()
            .into_iter()
            .map(|r| (format!("refs/{}", r.name), r.hash.unwrap()))
            .collect();
        let modeled: Vec<(String, [u8; 32])> = all
            .iter()
            .flat_map(|page| page.entries.iter())
            .map(|(k, v)| {
                let name = String::from_utf8(k.as_bytes()[2 + repo().name.as_str().len() + 1..].to_vec()).unwrap();
                (name, codec::decode_ref_id(v).unwrap())
            })
            .collect();
        prop_assert_eq!(on_disk, modeled);
    }
}

#[test]
fn open_refuses_a_root_marked_for_sqlite_meta() {
    let dir = TempDir::new().unwrap();
    // Unmarked: opens, and serves the same files as `new`.
    let store = FsLayoutStore::open(dir.path(), &repo()).unwrap();
    let put = Batch::new().put(ref_key("refs/heads/main"), Value::new(id(b"a").to_vec()));
    assert_eq!(apply(&store, put).unwrap(), BatchOutcome::Committed);

    fs::create_dir_all(dir.path().join(".mkit")).unwrap();
    fs::write(dir.path().join(super::META_MARKER), b"sqlite").unwrap();
    let err = FsLayoutStore::open(dir.path(), &repo()).unwrap_err();
    let StoreError::Unsupported(message) = err else {
        panic!("{err:?}");
    };
    assert!(message.contains("--meta sqlite"), "{message}");
    assert!(message.contains("server-meta"), "{message}");
}

// ------------------------------------------------ crashed uploads, R-86

/// Set `path`'s modification time `age` in the past.
fn age_file(path: &Path, age: std::time::Duration) {
    let when = std::time::SystemTime::now() - age;
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

#[test]
fn upload_temp_names_match_exactly() {
    use super::blob::is_upload_temp_name;
    let hex = "ab".repeat(32);
    assert!(is_upload_temp_name(&format!(".{hex}.tmp.123.0")));
    assert!(is_upload_temp_name(&format!(
        ".{hex}.tmp.4294967295.18446744073709551615"
    )));
    for bad in [
        hex.clone(),
        format!("{hex}.tmp.1.2"),
        format!(".{}.tmp.1.2", "AB".repeat(32)),
        format!(".{}.tmp.1.2", "ab".repeat(31)),
        format!(".{hex}a.tmp.1.2"),
        format!(".{hex}.tmp.1"),
        format!(".{hex}.tmp..2"),
        format!(".{hex}.tmp.1.2.3"),
        format!(".{hex}.tmp.1.x"),
        format!(".{hex}.tmp.12345678901.2"),
        format!(".{hex}.lock"),
        ".lock".to_owned(),
    ] {
        assert!(!is_upload_temp_name(&bad), "{bad}");
    }
}

#[test]
fn sweep_removes_only_old_upload_temp_files() {
    let td = TempDir::new().unwrap();
    let store = FsBlobStore::new(td.path());
    // A missing keyspace directory sweeps nothing.
    let hour = std::time::Duration::from_hours(1);
    assert_eq!(store.sweep_stale_uploads(hour).unwrap(), 0);

    let tx = FileTransport::new(td.path());
    let pack = b"a published pack".to_vec();
    let key = PackKey::new(hash(&pack));
    tx.upload_pack(&pack, &key).unwrap();
    let packs = td.path().join("packs");
    let hex = key.to_hex();
    let old_tmp = packs.join(format!(".{hex}.tmp.77.0"));
    let fresh_tmp = packs.join(format!(".{hex}.tmp.77.1"));
    let old_other = packs.join(format!(".{hex}.lock"));
    let old_link = packs.join(format!(".{hex}.tmp.77.2"));
    for p in [&old_tmp, &fresh_tmp, &old_other] {
        fs::write(p, b"partial").unwrap();
    }
    let two_hours = std::time::Duration::from_hours(2);
    for p in [&old_tmp, &old_other, &packs.join(&hex)] {
        age_file(p, two_hours);
    }
    std::os::unix::fs::symlink(&old_other, &old_link).unwrap();

    assert_eq!(store.sweep_stale_uploads(hour).unwrap(), 1);
    assert!(!old_tmp.exists(), "the old temp file is swept");
    assert!(fresh_tmp.exists(), "a fresh temp file may be a live upload");
    assert!(old_other.exists(), "another name is never touched");
    assert!(
        old_link.symlink_metadata().is_ok(),
        "a symlink is never touched"
    );
    assert_eq!(
        tx.download_pack(&key).unwrap(),
        pack,
        "blobs are never touched"
    );
}

#[test]
fn legacy_ref_files_finds_refs_outside_refs_dir() {
    let td = TempDir::new().unwrap();
    let root = td.path();
    let tx = FileTransport::new(root);
    tx.update_ref("refs/heads/main", RefWriteCondition::Any, &id(b"m"))
        .unwrap();
    let pack = b"pack".to_vec();
    tx.upload_pack(&pack, &PackKey::new(hash(&pack))).unwrap();
    fs::create_dir_all(root.join(".mkit")).unwrap();
    let wire = mkit_core::refs::encode_ref_wire(&id(b"legacy"));
    // What an older `mkit serve` wrote for `main` and `heads/dev`.
    fs::write(root.join("main"), wire).unwrap();
    fs::create_dir_all(root.join("heads")).unwrap();
    fs::write(root.join("heads/dev"), wire).unwrap();
    // Not legacy refs: another file, a hidden one, one under `.mkit`, and
    // a ref-wire file whose name fails the grammar.
    fs::write(root.join("README"), b"hello\n").unwrap();
    fs::write(root.join(".hidden"), wire).unwrap();
    fs::write(root.join(".mkit/stray"), wire).unwrap();
    fs::write(root.join("bad name"), wire).unwrap();

    let store = layout(root);
    assert_eq!(
        store.legacy_ref_files(10_000).unwrap(),
        ["heads/dev", "main"]
    );
    // The walk is bounded.
    assert!(store.legacy_ref_files(1).unwrap().len() <= 1);
    // A root without legacy refs reports none.
    let clean = TempDir::new().unwrap();
    FileTransport::new(clean.path())
        .update_ref("refs/heads/main", RefWriteCondition::Any, &id(b"m"))
        .unwrap();
    let clean = layout(clean.path());
    assert!(clean.legacy_ref_files(10_000).unwrap().is_empty());
}
