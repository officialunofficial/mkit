//! Batched-durability object writes.
//!
//! [`WriteBatch`] amortises the cost of crash durability across every
//! object written by one logical command (an `add`, a `commit`, a pack
//! unpack): objects are staged as barrier-synced temp files and become
//! durable *and visible together* at [`WriteBatch::commit`], with **one**
//! full flush per batch instead of two per object.
//!
//! # Durability contract
//!
//! The invariant the store actually needs is not "every object is
//! durable the moment it is written" — it is:
//!
//! > A ref or index file is only ever written after every object it
//! > references is durable, and a crash never produces a visible object
//! > that fails the read-time hash check.
//!
//! `WriteBatch` preserves both halves:
//!
//! * Staged objects are **invisible** until `commit()` — renames are
//!   deferred until after the batch's full flush, so another process's
//!   `contains()` dedup can never observe (and then reference) an
//!   object whose bytes are not yet durable.
//! * `commit()` returns only after one full flush, every rename, and a
//!   deduplicated flush of each touched shard directory. Callers MUST
//!   order their ref/index writes after `commit()`.
//! * A dropped (never committed) batch unlinks its temp files and
//!   leaves the store untouched — aborting is free.
//!
//! # How the single flush is enough
//!
//! This is git's `core.fsyncMethod=batch` design (bulk-checkin) and
//! `SQLite`'s macOS sync strategy:
//!
//! Every staged file gets a real per-file writeback at commit time —
//! Apple `fcntl(F_BARRIERFSYNC)`, Linux `fdatasync`, Windows
//! `FlushFileBuffers` — issued **concurrently** from a scoped-thread
//! pool so the cost is device latency at queue depth, not
//! latency×objects. The trailing constant-count full flushes
//! (`F_FULLFSYNC` on Apple) cover ordering and the dirent updates.
//! This holds on every filesystem; it does not depend on ext4
//! ordered-data journaling.
//!
//! Workloads that prefer the historical schedule can select
//! [`SyncPolicy::PerObject`] (config key `durability.objects =
//! per-object`), which reproduces the old write path exactly.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tempfile::TempPath;

use crate::hash::Hash;
use crate::store::{
    MAX_RAW_OBJECT_SIZE, ObjectSink, ObjectStore, StoreError, StoreResult, sync_parent_dir,
    temp_file_in,
};

/// When object writes become durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncPolicy {
    /// Historical behaviour: full flush + dir flush per object, object
    /// visible immediately. O(objects) full flushes.
    PerObject,
    /// Stage now, make durable + visible together at
    /// [`WriteBatch::commit`]. O(1) full flushes per batch. Default.
    ///
    /// (There is deliberately no "no flushes" policy: a visible object
    /// MUST be durable — SPEC-OBJECTS §10.1 — because every writer's
    /// content-addressed dedup trusts visibility. Ephemeral snapshots
    /// belong in [`crate::store::EphemeralSink`], which never touches
    /// the store.)
    #[default]
    Batch,
}

/// Flush/rename primitive seam between the store and the OS.
///
/// Production code uses [`RealSyncer`]; unit tests inject a recording
/// double to assert flush *ordering* and *counts* — the tests in this
/// module are the proof (and CI regression guard) of the O(1) full
/// flushes per batch claim. Distinct from [`SyncPolicy`], which is a
/// production knob deciding *whether* to flush; the syncer decides
/// *how*.
pub(crate) trait Syncer: Send + Sync + fmt::Debug {
    /// Writeback + ordering barrier for one staged file. Must guarantee
    /// the file's bytes reach the device before any later
    /// [`Syncer::full`] completes, without forcing a device cache
    /// flush.
    fn barrier(&self, file: &File, path: &Path) -> io::Result<()>;
    /// Full durable flush (device cache included) of `file`.
    fn full(&self, file: &File, path: &Path) -> io::Result<()>;
    /// Atomically rename a staged temp file into its final path,
    /// replacing any existing file.
    fn rename(&self, tmp: TempPath, final_path: &Path) -> io::Result<()>;
    /// Durably flush the directory entry updates of `dir` — the legacy
    /// per-object schedule ([`SyncPolicy::PerObject`] and
    /// `ObjectStore::write`).
    fn dir_sync(&self, dir: &Path) -> io::Result<()>;
    /// Writeback + ordering barrier for the dirent updates of `dir`,
    /// without forcing a device cache flush. Must guarantee the dirents
    /// reach the device before a later [`Syncer::device_flush`]
    /// completes. Batched schedule only; needs the trailing
    /// `device_flush` to be durable.
    fn dir_barrier(&self, dir: &Path) -> io::Result<()>;
    /// Terminal full flush of the device write cache, anchored at the
    /// store's `objects/` root. Makes everything previously
    /// barrier-ordered (file data and dirents alike) durable.
    fn device_flush(&self, objects_root: &Path) -> io::Result<()>;
}

/// Production [`Syncer`].
#[derive(Debug)]
pub(crate) struct RealSyncer;

impl RealSyncer {
    /// Per-file write barrier: order this file's writeback ahead of the
    /// batch's terminal device flush, as cheaply as the platform allows.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn file_barrier(file: &File) -> io::Result<()> {
        use std::os::unix::io::AsRawFd;
        // Apple: `File::sync_data()`/`sync_all()` both map to
        // `fcntl(F_FULLFSYNC)` — a full device-cache flush. F_BARRIERFSYNC
        // is the cheaper primitive the module docs assume: it forces this
        // file's writeback and orders it ahead of later writes WITHOUT a
        // device flush. The single terminal `device_flush` (one
        // F_FULLFSYNC) still makes the whole batch durable, so the per-
        // file step stays a true barrier rather than N full flushes.
        //
        // SAFETY: `fcntl(2)` with `F_BARRIERFSYNC` takes only the fd and
        // the command — it reads/writes no user memory, and the fd is
        // valid for the borrow of `file`.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_BARRIERFSYNC) };
        if rc == -1 {
            // Some filesystems reject the fcntl — fall back to the full
            // flush rather than weaken durability.
            return file.sync_data();
        }
        Ok(())
    }

    /// Linux: `fdatasync`. Windows: `FlushFileBuffers` (requires the
    /// write-capable handle the commit path now opens).
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fn file_barrier(file: &File) -> io::Result<()> {
        file.sync_data()
    }
}

impl Syncer for RealSyncer {
    fn barrier(&self, file: &File, _path: &Path) -> io::Result<()> {
        // Per-file writeback on EVERY platform — Apple: fcntl
        // F_BARRIERFSYNC (writeback + ordering barrier, no device-cache
        // flush); Linux: fdatasync; Windows: FlushFileBuffers. This is
        // what makes a committed batch durable on all filesystems, not
        // just metadata-journaling ones in ordered-data mode — XFS,
        // btrfs, ext4 data=writeback, and NTFS get the same guarantee.
        // The cost is bounded: barriers are issued concurrently from a
        // thread pool at commit, so wall-clock is latency/queue-depth,
        // not latency×objects.
        Self::file_barrier(file)
    }

    fn full(&self, file: &File, _path: &Path) -> io::Result<()> {
        file.sync_all()
    }

    fn rename(&self, tmp: TempPath, final_path: &Path) -> io::Result<()> {
        // Cross-platform atomic replace: rename(2) on Unix, MoveFileExW
        // with MOVEFILE_REPLACE_EXISTING on Windows.
        tmp.persist(final_path).map_err(|e| e.error)?;
        Ok(())
    }

    fn dir_sync(&self, dir: &Path) -> io::Result<()> {
        sync_parent_dir(dir)
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn dir_barrier(&self, dir: &Path) -> io::Result<()> {
        // F_BARRIERFSYNC on the directory fd: pushes the dirent
        // updates toward the device and orders them ahead of the
        // batch's terminal F_FULLFSYNC, at a fraction of its cost.
        // Some filesystems reject the fcntl on directories — fall back
        // to the full dir fsync rather than weaken durability.
        match File::open(dir) {
            Ok(d) => d.sync_data().or_else(|_| d.sync_all()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fn dir_barrier(&self, dir: &Path) -> io::Result<()> {
        // Linux: the directory fsync IS the durability mechanism (the
        // journal commit orders ordered-mode file data ahead of the
        // dirents), so the "barrier" must stay a real fsync. Windows:
        // no directory flush primitive — no-op, the device_flush
        // covers what the OS exposes.
        sync_parent_dir(dir)
    }

    #[cfg(unix)]
    fn device_flush(&self, objects_root: &Path) -> io::Result<()> {
        // macOS: sync_all on any fd is F_FULLFSYNC — flushes the whole
        // device write cache, making every prior barrier durable.
        // Linux: fsync of the objects root; cheap insurance on top of
        // the per-dir fsyncs above.
        match File::open(objects_root) {
            Ok(d) => d.sync_all(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[cfg(not(unix))]
    #[allow(clippy::unnecessary_wraps)]
    fn device_flush(&self, _objects_root: &Path) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct BatchState {
    /// hash → staged-but-invisible temp file, insertion-deduped. The
    /// final path is derived from the hash at commit (`path_for`) — a
    /// single source of truth for the layout. Handles are closed
    /// (`TempPath`) so a large batch does not exhaust the fd limit;
    /// deletion-on-drop is retained for abort cleanup.
    staged: HashMap<Hash, TempPath>,
    /// Shard directories whose dirents this batch must flush at commit.
    /// Includes dedup hits: an object made visible by another process
    /// may not have a durable dirent yet, and our commit is about to
    /// reference it.
    touched_shards: HashSet<PathBuf>,
    /// Shard directories this batch has already `create_dir_all`'d —
    /// at most 256 exist, so memoizing saves ~one mkdir syscall per
    /// object on large ingests.
    created_shards: HashSet<PathBuf>,
}

/// A set of object writes that become durable and visible together.
/// Created by [`ObjectStore::batch`]. See the module docs for the
/// durability contract.
#[derive(Debug)]
pub struct WriteBatch<'s> {
    store: &'s ObjectStore,
    policy: SyncPolicy,
    // Interior mutability so `&self` writes work and a future parallel
    // ingest can share one batch across worker threads.
    inner: Mutex<BatchState>,
}

impl<'s> WriteBatch<'s> {
    pub(crate) fn new(store: &'s ObjectStore, policy: SyncPolicy) -> Self {
        Self {
            store,
            policy,
            inner: Mutex::new(BatchState::default()),
        }
    }

    /// Hash `bytes`, dedup against staged and on-disk objects, and
    /// stage (policy `Batch`/`None`) or durably write (policy
    /// `PerObject`) the object. Returns the BLAKE3 hash either way.
    pub fn write(&self, bytes: &[u8]) -> StoreResult<Hash> {
        self.write_parts(&[bytes])
    }

    /// [`Self::write`] for an object whose bytes are the concatenation
    /// of `parts`, hashed and written streaming — no concatenated
    /// buffer is materialised.
    ///
    /// # Panics
    ///
    /// Panics only if the internal hash-to-path mapping produces a path
    /// without a parent directory (impossible by construction) or if a
    /// previous write panicked while holding the batch mutex.
    pub fn write_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        let mut total: usize = 0;
        for p in parts {
            total = total
                .checked_add(p.len())
                .ok_or(StoreError::ObjectTooLarge)?;
        }
        if total > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        // One id dispatch shared by every part-wise sink: a merkle type
        // buffers + uses its BMT root, a byte-hashed type streams.
        self.write_prehashed(crate::object::object_id_from_parts(parts), parts)
    }

    /// Stage `parts` under the caller-supplied content hash, skipping
    /// the BLAKE3 pass. `pub(crate)` and reserved for callers that have
    /// PROVABLY just hashed the same bytes (pack unpack hashes every
    /// entry to build its report; re-hashing in the batch doubled the
    /// CPU of every clone/fetch). A wrong hash here would corrupt the
    /// content addressing — never expose this publicly.
    pub(crate) fn write_prehashed(&self, h: Hash, parts: &[&[u8]]) -> StoreResult<Hash> {
        let final_path = self.store.path_for(&h);
        let shard_dir = final_path
            .parent()
            .expect("object path always has a 2-hex parent")
            .to_path_buf();

        // Short lock: staged-dedup check + mkdir memoization decision.
        // The file I/O below runs OUTSIDE the lock so concurrent
        // writers sharing one batch don't convoy on each other's
        // write_all calls.
        let need_mkdir = {
            let st = self.inner.lock().expect("batch state mutex poisoned");
            if st.staged.contains_key(&h) {
                return Ok(h);
            }
            !st.created_shards.contains(&shard_dir)
        };
        if final_path.exists() {
            // Dedup hit: the object is visible, but if another process
            // renamed it and has not yet flushed the dirent, it may not
            // be durable. We are about to reference it, so flush its
            // shard dir at commit.
            self.inner
                .lock()
                .expect("batch state mutex poisoned")
                .touched_shards
                .insert(shard_dir);
            return Ok(h);
        }
        if need_mkdir {
            fs::create_dir_all(&shard_dir)?;
        }
        let file_name = final_path
            .file_name()
            .expect("object path has file name")
            .to_string_lossy();
        let mut tmp = temp_file_in(&shard_dir, &file_name)?;
        for p in parts {
            tmp.as_file_mut().write_all(p)?;
        }
        let syncer = self.store.syncer();
        match self.policy {
            SyncPolicy::PerObject => {
                // Historical write path, immediately durable + visible.
                syncer.full(tmp.as_file(), tmp.path())?;
                syncer.rename(tmp.into_temp_path(), &final_path)?;
                syncer.dir_sync(&shard_dir)?;
                let mut st = self.inner.lock().expect("batch state mutex poisoned");
                st.created_shards.insert(shard_dir);
            }
            SyncPolicy::Batch => {
                // No flush here: barriers for every staged file are
                // issued concurrently at commit() — sequential
                // per-file barriers would re-serialise the batch on
                // device latency (measured ~4.6ms per F_BARRIERFSYNC
                // on Apple SSDs, ~8s for a 100 MiB ingest).
                let mut st = self.inner.lock().expect("batch state mutex poisoned");
                // Lost race against a concurrent writer of the same
                // object within this batch: keep theirs, drop our tmp
                // (content-addressed — byte-identical by construction).
                st.staged.entry(h).or_insert_with(|| tmp.into_temp_path());
                st.touched_shards.insert(shard_dir.clone());
                st.created_shards.insert(shard_dir);
            }
        }
        Ok(h)
    }

    /// True when `h` is staged in this batch or already in the store.
    ///
    /// # Panics
    ///
    /// Panics only if a previous write panicked while holding the batch
    /// mutex.
    #[must_use]
    pub fn contains(&self, h: &Hash) -> bool {
        self.inner
            .lock()
            .expect("batch state mutex poisoned")
            .staged
            .contains_key(h)
            || self.store.contains(h)
    }

    /// Make every staged object durable and visible: one full flush,
    /// then all renames, then deduplicated shard-directory flushes.
    ///
    /// After `commit()` returns `Ok`, every hash returned by
    /// [`Self::write`]/[`Self::write_parts`] is durable AND visible.
    /// Callers MUST call this before reading any object written by this
    /// batch and before writing any ref/index that references one.
    ///
    /// If `commit()` fails partway, already-renamed objects remain
    /// visible (content-addressing makes re-running the command
    /// idempotent) and not-yet-renamed temp files are unlinked on drop.
    ///
    /// # Panics
    ///
    /// Panics only if a previous write panicked while holding the batch
    /// mutex.
    pub fn commit(self) -> StoreResult<()> {
        let st = self.inner.into_inner().expect("batch state mutex poisoned");
        let syncer = self.store.syncer();
        match self.policy {
            // Every write was already made durable and visible.
            SyncPolicy::PerObject => Ok(()),
            SyncPolicy::Batch => {
                let staged: Vec<(Hash, TempPath)> = st.staged.into_iter().collect();
                // 1. Barrier every staged file, concurrently. Each
                //    barrier initiates writeback for its file and
                //    orders it ahead of the full flush below; issuing
                //    them from worker threads overlaps their device
                //    latency (queue depth) instead of paying it
                //    serially per file. All barriers complete (joined)
                //    before the flush is issued.
                parallel_io(staged.len(), |i| {
                    // Write-capable handle: the barrier maps to
                    // `FlushFileBuffers` on Windows, which rejects a
                    // read-only handle. `write(true)` opens the existing
                    // temp without truncating it.
                    let f = OpenOptions::new().write(true).open(&staged[i].1)?;
                    syncer.barrier(&f, &staged[i].1)
                })?;
                // 2. One full flush — any staged file serves as the
                //    anchor; the barriers ordered every staged write
                //    ahead of it (see module docs). Pure-dedup batches
                //    (nothing staged) skip it: the objects were made
                //    durable by whoever renamed them into visibility.
                if let Some((_, tmp)) = staged.first() {
                    // Write-capable handle for the same Windows reason as
                    // the barrier above (`sync_all` → `FlushFileBuffers`).
                    let f = OpenOptions::new().write(true).open(tmp)?;
                    syncer.full(&f, tmp)?;
                }
                // 3. Renames: objects become visible only now, after
                //    their bytes are durable — another process's dedup
                //    can never reference a non-durable object. Final
                //    paths derive from the hashes (single layout rule).
                for (h, tmp) in staged {
                    syncer.rename(tmp, &self.store.path_for(&h))?;
                }
                // 4. Dirent barriers, once per touched shard dir,
                //    concurrently (sorted first so the work list is
                //    deterministic).
                let mut shards: Vec<PathBuf> = st.touched_shards.into_iter().collect();
                shards.sort();
                if !shards.is_empty() {
                    parallel_io(shards.len(), |i| syncer.dir_barrier(&shards[i]))?;
                    // 5. Terminal device flush: makes the dirent
                    //    barriers (and, on platforms where step 2 was
                    //    a barrier-anchored flush, everything) durable.
                    syncer.device_flush(self.store.objects_root())?;
                }
                Ok(())
            }
        }
    }
}

/// Run `op(0..count)` across a small pool of scoped threads, joining
/// them all before returning. Concurrency overlaps per-item device
/// latency (~ms per flush primitive on Apple SSDs) that would otherwise
/// serialise a batch; correctness only needs *all* items complete
/// before the caller proceeds, which the join guarantees. Returns the
/// first error observed, if any.
fn parallel_io(count: usize, op: impl Fn(usize) -> io::Result<()> + Sync) -> io::Result<()> {
    if count == 0 {
        return Ok(());
    }
    let workers = std::thread::available_parallelism()
        .map_or(4, std::num::NonZeroUsize::get)
        .min(16)
        .min(count);
    if workers == 1 {
        return (0..count).try_for_each(op);
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut results: Vec<io::Result<()>> = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                let next = &next;
                let op = &op;
                scope.spawn(move || -> io::Result<()> {
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= count {
                            return Ok(());
                        }
                        op(i)?;
                    }
                })
            })
            .collect();
        for h in handles {
            results.push(h.join().expect("parallel io worker panicked"));
        }
    });
    results.into_iter().collect()
}

impl ObjectSink for WriteBatch<'_> {
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash> {
        self.write(bytes)
    }

    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        self.write_parts(parts)
    }

    fn has(&self, h: &Hash) -> bool {
        self.contains(h)
    }
}

/// Test doubles shared with other modules' sync-behaviour tests
/// (`pack.rs` asserts unpack costs one flush; later, `worktree.rs` and
/// `ops/diff.rs` assert their flush budgets).
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// Every Syncer call, in order. `Rename` records the temp path so
    /// tests can pair a rename with the `Barrier` that staged it. The
    /// terminal device flush is recorded as `Full` so "full flush
    /// count" stays the single number the O(1) tests bound.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Ev {
        Barrier(PathBuf),
        Full(PathBuf),
        Rename { tmp: PathBuf, dst: PathBuf },
        DirSync(PathBuf),
        DirBarrier(PathBuf),
    }

    /// Recording double: logs ordering, performs renames for real (so
    /// the store stays functional under test), skips actual flushes
    /// (they have no observable filesystem effect).
    #[derive(Debug, Default)]
    pub(crate) struct RecordingSyncer {
        events: Mutex<Vec<Ev>>,
    }

    impl RecordingSyncer {
        pub(crate) fn events(&self) -> Vec<Ev> {
            self.events.lock().unwrap().clone()
        }
    }

    impl Syncer for RecordingSyncer {
        fn barrier(&self, _file: &File, path: &Path) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(Ev::Barrier(path.to_path_buf()));
            Ok(())
        }

        fn full(&self, _file: &File, path: &Path) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(Ev::Full(path.to_path_buf()));
            Ok(())
        }

        fn rename(&self, tmp: TempPath, final_path: &Path) -> io::Result<()> {
            self.events.lock().unwrap().push(Ev::Rename {
                tmp: tmp.to_path_buf(),
                dst: final_path.to_path_buf(),
            });
            tmp.persist(final_path).map_err(|e| e.error)?;
            Ok(())
        }

        fn dir_sync(&self, dir: &Path) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(Ev::DirSync(dir.to_path_buf()));
            Ok(())
        }

        fn dir_barrier(&self, dir: &Path) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(Ev::DirBarrier(dir.to_path_buf()));
            Ok(())
        }

        fn device_flush(&self, objects_root: &Path) -> io::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(Ev::Full(objects_root.to_path_buf()));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Ev, RecordingSyncer};
    use super::*;
    use crate::hash;
    use proptest::prelude::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().expect("tempdir");
        let store = ObjectStore::init(dir.path()).expect("init");
        (dir, store)
    }

    /// Store with a shared `RecordingSyncer` injected.
    fn recording_store() -> (TempDir, ObjectStore, Arc<RecordingSyncer>) {
        let (dir, mut store) = fresh_store();
        let rec = Arc::new(RecordingSyncer::default());
        store.set_syncer(rec.clone());
        (dir, store, rec)
    }

    /// Count object files (62-hex names) under `objects/`, recursively.
    fn object_file_count(store: &ObjectStore) -> usize {
        store.iter_object_hashes().unwrap().len()
    }

    /// Count ALL files under `objects/` including temp files.
    fn any_file_count(store: &ObjectStore) -> usize {
        fn walk(dir: &Path, n: &mut usize) {
            if let Ok(rd) = fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, n);
                    } else {
                        *n += 1;
                    }
                }
            }
        }
        let mut n = 0;
        walk(store.objects_root(), &mut n);
        n
    }

    // ---- Cycle 1: staging invisibility --------------------------------

    #[test]
    fn staged_object_is_invisible_until_commit() {
        let (dir, store) = fresh_store();
        let batch = store.batch();
        let h = batch.write(b"staged bytes").unwrap();

        // A second, independent handle must not see the object yet.
        let other = ObjectStore::open(dir.path()).unwrap();
        assert!(
            !other.contains(&h),
            "staged object must be invisible before commit"
        );
        assert!(other.read(&h).is_err());

        batch.commit().unwrap();
        assert!(other.contains(&h), "committed object must be visible");
        assert_eq!(other.read(&h).unwrap(), b"staged bytes");
    }

    #[test]
    fn batch_contains_sees_staged_and_disk() {
        let (_dir, store) = fresh_store();
        let on_disk = store.write(b"already stored").unwrap();
        let batch = store.batch();
        let staged = batch.write(b"only staged").unwrap();

        assert!(batch.contains(&on_disk), "must see on-disk objects");
        assert!(batch.contains(&staged), "must see its own staged objects");
        let phony = hash::hash(b"never written");
        assert!(!batch.contains(&phony));
    }

    #[test]
    fn dropped_batch_leaves_no_tmp_files_and_no_objects() {
        let (_dir, store) = fresh_store();
        {
            let batch = store.batch();
            batch.write(b"abort me 1").unwrap();
            batch.write(b"abort me 2").unwrap();
            batch.write(b"abort me 3").unwrap();
            // dropped without commit
        }
        assert_eq!(object_file_count(&store), 0, "no objects may be visible");
        assert_eq!(
            any_file_count(&store),
            0,
            "no temp files may leak from an aborted batch"
        );
    }

    // ---- Cycle 2: flush ordering (the O(1) proof) ----------------------

    fn fifty_distinct_objects() -> Vec<Vec<u8>> {
        (0u32..50)
            .map(|i| format!("object #{i}").into_bytes())
            .collect()
    }

    #[test]
    fn batch_commit_full_flush_count_is_constant() {
        // The O(1) proof: a committed batch costs exactly TWO full
        // flushes — one covering staged file data (pre-rename), one
        // terminal device flush covering the dirent updates —
        // regardless of how many objects it stages.
        for count in [3usize, 50] {
            let (_dir, store, rec) = recording_store();
            let batch = store.batch();
            for bytes in fifty_distinct_objects().into_iter().take(count) {
                batch.write(&bytes).unwrap();
            }
            // Duplicates must not add flushes either.
            batch.write(b"object #0").unwrap();
            batch.commit().unwrap();

            let fulls = rec
                .events()
                .iter()
                .filter(|e| matches!(e, Ev::Full(_)))
                .count();
            assert_eq!(
                fulls, 2,
                "a {count}-object batch must cost exactly two full flushes"
            );
        }
    }

    #[test]
    fn every_rename_is_preceded_by_its_barrier_and_the_full_flush() {
        let (_dir, store, rec) = recording_store();
        let batch = store.batch();
        for bytes in fifty_distinct_objects() {
            batch.write(&bytes).unwrap();
        }
        batch.commit().unwrap();

        let evs = rec.events();
        let full_pos = evs
            .iter()
            .position(|e| matches!(e, Ev::Full(_)))
            .expect("one full flush");
        // Every barrier must complete before the full flush is issued —
        // the flush only covers writes the barriers pushed ahead of it.
        let last_barrier = evs
            .iter()
            .rposition(|e| matches!(e, Ev::Barrier(_)))
            .expect("barriers recorded");
        assert!(
            last_barrier < full_pos,
            "all barriers (last at {last_barrier}) must precede the full flush at {full_pos}"
        );
        for (i, ev) in evs.iter().enumerate() {
            if let Ev::Rename { tmp, .. } = ev {
                assert!(
                    i > full_pos,
                    "rename at {i} must come after the full flush at {full_pos}"
                );
                let barrier_pos = evs
                    .iter()
                    .position(|e| matches!(e, Ev::Barrier(p) if p == tmp))
                    .unwrap_or_else(|| panic!("no barrier recorded for {}", tmp.display()));
                assert!(
                    barrier_pos < i,
                    "barrier for {} must precede its rename",
                    tmp.display()
                );
            }
        }
    }

    #[test]
    fn dir_syncs_come_after_all_renames_and_are_deduped() {
        let (_dir, store, rec) = recording_store();
        let batch = store.batch();
        let mut shards = HashSet::new();
        for bytes in fifty_distinct_objects() {
            let h = batch.write(&bytes).unwrap();
            shards.insert(store.path_for(&h).parent().unwrap().to_path_buf());
        }
        batch.commit().unwrap();

        let evs = rec.events();
        let last_rename = evs
            .iter()
            .rposition(|e| matches!(e, Ev::Rename { .. }))
            .expect("renames recorded");
        let dir_barriers: Vec<(usize, &PathBuf)> = evs
            .iter()
            .enumerate()
            .filter_map(|(i, e)| match e {
                Ev::DirBarrier(p) => Some((i, p)),
                _ => None,
            })
            .collect();

        let synced: HashSet<PathBuf> = dir_barriers.iter().map(|(_, p)| (*p).clone()).collect();
        assert_eq!(
            dir_barriers.len(),
            synced.len(),
            "each shard dir must be flushed exactly once"
        );
        assert_eq!(synced, shards, "exactly the touched shards are flushed");
        for (i, p) in &dir_barriers {
            assert!(
                *i > last_rename,
                "dir barrier of {} at {i} must come after the last rename at {last_rename}",
                p.display()
            );
        }
        // The terminal device flush makes the dirent barriers durable —
        // it must be the last sync event of the batch.
        let last_full = evs
            .iter()
            .rposition(|e| matches!(e, Ev::Full(_)))
            .expect("device flush recorded");
        let last_dir_barrier = dir_barriers.last().expect("dir barriers recorded").0;
        assert!(
            last_full > last_dir_barrier,
            "device flush at {last_full} must follow the last dir barrier at {last_dir_barrier}"
        );
    }

    #[test]
    fn dedup_hit_still_dir_syncs_at_commit() {
        let (_dir, store, rec) = recording_store();
        // Pre-store the object (e.g. another process raced us there).
        let h = store.write(b"already present").unwrap();
        let shard = store.path_for(&h).parent().unwrap().to_path_buf();

        let batch = store.batch();
        let h2 = batch.write(b"already present").unwrap();
        assert_eq!(h, h2);
        let before = rec.events().len();
        batch.commit().unwrap();

        let evs = rec.events()[before..].to_vec();
        assert!(
            !evs.iter().any(|e| matches!(e, Ev::Rename { .. })),
            "dedup hit must not stage or rename anything"
        );
        assert!(
            evs.contains(&Ev::DirBarrier(shard)),
            "commit must still flush the dedup-hit shard dir: its dirent \
             may not be durable yet and we are about to reference it"
        );
        assert!(
            matches!(evs.last(), Some(Ev::Full(_))),
            "the dir barrier needs a trailing device flush to be durable"
        );
    }

    #[test]
    fn sync_policy_per_object_matches_legacy_event_pattern() {
        // Legacy pattern = ObjectStore::write: Full(tmp), Rename, DirSync
        // per object, in that order, objects visible immediately.
        let (_dir, store, rec) = recording_store();
        let legacy_h = store.write(b"legacy path").unwrap();
        let legacy: Vec<Ev> = rec.events();

        let batch = store.batch_with_policy(SyncPolicy::PerObject);
        let h = batch.write(b"per object path").unwrap();
        assert!(
            store.contains(&h),
            "PerObject writes must be visible immediately, pre-commit"
        );
        let per_object: Vec<Ev> = rec.events()[legacy.len()..].to_vec();

        let kinds = |evs: &[Ev]| -> Vec<u8> {
            evs.iter()
                .map(|e| match e {
                    Ev::Barrier(_) => 0u8,
                    Ev::Full(_) => 1,
                    Ev::Rename { .. } => 2,
                    Ev::DirSync(_) => 3,
                    Ev::DirBarrier(_) => 4,
                })
                .collect()
        };
        assert_eq!(
            kinds(&per_object),
            kinds(&legacy),
            "PerObject batch must reproduce the legacy per-write sync pattern"
        );
        // commit() of a PerObject batch is a no-op.
        let before = rec.events().len();
        batch.commit().unwrap();
        assert_eq!(rec.events().len(), before);
        let _ = legacy_h;
    }

    // ---- Cycle 3: equivalence & limits ---------------------------------

    #[test]
    fn idempotent_duplicate_writes_in_one_batch_stage_once() {
        let (_dir, store, rec) = recording_store();
        let batch = store.batch();
        let h1 = batch.write(b"twice staged").unwrap();
        let h2 = batch.write(b"twice staged").unwrap();
        assert_eq!(h1, h2);
        batch.commit().unwrap();

        let evs = rec.events();
        let barriers = evs.iter().filter(|e| matches!(e, Ev::Barrier(_))).count();
        let renames = evs
            .iter()
            .filter(|e| matches!(e, Ev::Rename { .. }))
            .count();
        assert_eq!(barriers, 1, "duplicate must not re-stage");
        assert_eq!(renames, 1, "duplicate must not re-rename");
    }

    #[test]
    fn batch_write_rejects_oversize() {
        // Mirrors store::tests::write_rejects_oversize: the 1 GiB cap
        // cannot be allocated in a unit test; assert the guard constant
        // is wired and a realistic write succeeds. The checked-sum
        // logic is exercised by write_parts proptests.
        let (_dir, store) = fresh_store();
        let _ = MAX_RAW_OBJECT_SIZE;
        let batch = store.batch();
        let h = batch.write(&[0u8; 16]).unwrap();
        batch.commit().unwrap();
        assert!(store.contains(&h));
    }

    proptest! {
        #[test]
        fn batch_write_hash_equals_store_write_hash(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let (_dir, store) = fresh_store();
            let batch = store.batch();
            let h_batch = batch.write(&bytes).unwrap();
            batch.commit().unwrap();
            let on_disk_via_batch = store.read(&h_batch).unwrap();

            let (_dir2, store2) = fresh_store();
            let h_store = store2.write(&bytes).unwrap();
            prop_assert_eq!(h_batch, h_store, "batch and store writes must agree on the hash");
            prop_assert_eq!(on_disk_via_batch, bytes, "on-disk bytes must round-trip");
        }

        #[test]
        fn write_parts_equals_concatenated_write(
            parts in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..512), 0..8)
        ) {
            let (_dir, store) = fresh_store();
            let concatenated: Vec<u8> = parts.iter().flatten().copied().collect();

            let batch = store.batch();
            let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
            let h_parts = batch.write_parts(&slices).unwrap();
            let h_whole = batch.write(&concatenated).unwrap();
            batch.commit().unwrap();

            prop_assert_eq!(h_parts, h_whole, "parts and whole must hash identically");
            prop_assert_eq!(store.read(&h_parts).unwrap(), concatenated);
        }
    }
}
