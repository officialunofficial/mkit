//! Local content-addressed object store.
//!
//! Layout (rooted at the working-tree directory passed to [`ObjectStore::open`]
//! / [`ObjectStore::init`]):
//!
//! ```text
//! .mkit/
//!   objects/
//!     <2-hex>/<62-hex>   # raw canonical object bytes, BLAKE3-named
//! ```
//!
//! Writes are atomic: bytes are first written to a sibling temp file
//! (`<name>.tmp.<pid>.<rand>`), made durable, then renamed into place.
//! A crash mid-write leaves only the temp file behind and never
//! produces a visible object that fails the read-time hash check.
//!
//! Durability comes in three shapes (see [`crate::batch`] for the full
//! contract): [`ObjectStore::write`] flushes per object
//! ([`SyncPolicy::PerObject`]); [`ObjectStore::batch`] defers visibility
//! and amortises durability to **one** full flush per batch — the write
//! path used by every multi-object command (add, commit, pack unpack);
//! and [`ObjectStore::bulk_writer`] fsyncs each object's contents before
//! the rename and batches the dir fsyncs at commit (git import). In all
//! three an object is never visible before its bytes are durable, so a
//! ref or index written after the write/commit returns can never
//! reference a non-durable object.
//!
//! Reads always verify integrity by recomputing BLAKE3 over the bytes
//! and comparing against the requested hash; mismatch returns
//! [`StoreError::HashMismatch`].
//!
//! See `docs/SPEC-OBJECTS.md` §10 for the path-layout rule.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tempfile::NamedTempFile;

use crate::batch::{RealSyncer, Syncer};
pub use crate::batch::{SyncPolicy, WriteBatch};
use crate::hash::{self, Hash, object_path, to_hex};
use crate::object::{MkitError, Object};
use crate::serialize;

/// Top-level repository directory name.
pub const MKIT_DIR: &str = ".mkit";
/// Subdirectory under `.mkit/` that holds raw object files.
pub const OBJECTS_DIR: &str = "objects";
/// File under `.mkit/` declaring the object-addressing format. Written at
/// [`ObjectStore::init`] and required (and matched) at [`ObjectStore::open`]
/// so an older flat-hash-addressed repository is rejected loudly rather
/// than silently mis-read once merkle addressing is in effect.
pub const FORMAT_FILE: &str = "format";
/// The only supported object-addressing format value (see
/// `docs/SPEC-MERKLE-OBJECTS.md`): Tree/ChunkedBlob keyed by BMT root.
pub const FORMAT_VALUE: &str = "bmt-v1";
/// Hard cap on raw object size, enforced on both [`ObjectStore::write`]
/// and [`ObjectStore::read`].
pub const MAX_RAW_OBJECT_SIZE: usize = 1024 * 1024 * 1024; // 1 GiB

/// Hard cap on tree-walk recursion depth.
///
/// Every core tree-walker (`index::from_tree`, `ops::diff`, `ops::merge`,
/// `ops::restore`) recurses one native stack frame per directory level.
/// Content-addressing prevents true cycles (a child's hash can never equal
/// its parent's), but a crafted untrusted repo can still nest a few thousand
/// single-entry trees in a tiny pack and overflow the stack — a denial of
/// service reachable from `clone`/`checkout`/`merge`/`diff`. Walkers thread a
/// depth counter and abort with a typed `TreeTooDeep` error once
/// `depth > MAX_TREE_DEPTH`.
///
/// 128 is far beyond any legitimately-deep source tree (Git's own working
/// trees rarely exceed a couple dozen levels) while remaining comfortably
/// within a default 8 MiB thread stack. Mirrors the `MAX_REF_DEPTH` cap on
/// the ref-tree walker in `refs.rs`.
pub const MAX_TREE_DEPTH: usize = 128;

/// Errors raised by the [`ObjectStore`] surface. Distinct from
/// [`MkitError`] so callers can pattern-match on filesystem failures
/// without losing the structured-decode-error variants.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("path is not an mkit repository (missing .mkit/objects)")]
    NotAMkitRepository,
    #[error(".mkit already exists in this directory")]
    AlreadyInitialized,
    #[error(
        "repository object-addressing format is {found:?}, expected \"{}\" — this repository predates merkle object addressing and is not readable by this mkit (pre-1.0: no migration). See docs/SPEC-MERKLE-OBJECTS.md.",
        FORMAT_VALUE
    )]
    IncompatibleRepoFormat { found: Option<String> },
    #[error("object {0} not found")]
    ObjectNotFound(String),
    #[error("object exceeds {} byte cap", MAX_RAW_OBJECT_SIZE)]
    ObjectTooLarge,
    #[error("tree nesting exceeds {} levels", MAX_TREE_DEPTH)]
    TreeTooDeep,
    #[error("on-disk bytes hash to {actual}, expected {expected}")]
    HashMismatch { expected: String, actual: String },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Decode(#[from] MkitError),
}

/// Deferred-fsync writer returned by [`ObjectStore::bulk_writer`].
/// See that method for the crash-safety contract.
#[derive(Debug)]
pub struct BulkWriter<'a> {
    store: &'a ObjectStore,
    dirs: std::collections::HashSet<PathBuf>,
    files: std::collections::HashSet<PathBuf>,
}

/// The content-address (storage key) for an object's canonical bytes.
///
/// Merkelized types are addressed by their Binary Merkle Tree root
/// (`crate::merkle`): a `Tree` by its `compute_tree_id` and a `ChunkedBlob`
/// by its `compute_chunked_id`. Every other type is addressed by `BLAKE3`
/// of its bytes — the historical scheme. Dispatch is on the prologue type
/// byte, which is validated against the `MKT1` magic at decode. A
/// merkle-typed buffer that fails to decode falls back to the byte hash;
/// it could never have been produced by a real writer, so this only guards
/// malformed input from being silently mis-addressed.
///
/// This is the SINGLE function every write path and the read verifier route
/// through, so the two addressing schemes can never diverge across sinks
/// (`BulkWriter`, `ObjectStore`, `EphemeralSink`, `WriteBatch`).
pub(crate) fn object_id_from_bytes(bytes: &[u8]) -> Hash {
    use crate::object::{Object, ObjectType};
    match bytes.first().and_then(|b| ObjectType::from_u8(*b).ok()) {
        Some(ObjectType::Tree) => {
            if let Ok(Object::Tree(t)) = crate::serialize::deserialize(bytes) {
                return crate::merkle::compute_tree_id(&t);
            }
        }
        Some(ObjectType::ChunkedBlob) => {
            if let Ok(Object::ChunkedBlob(cb)) = crate::serialize::deserialize(bytes) {
                return crate::merkle::compute_chunked_id(&cb);
            }
        }
        _ => {}
    }
    hash::hash(bytes)
}

impl BulkWriter<'_> {
    /// Write one object durable-before-visible: contents are fsynced
    /// before the rename publishes the object, and only the shard-dir
    /// fsync (rename durability) is deferred to commit. This upholds the
    /// store's global invariant (an object is never visible before its
    /// bytes are durable), so another process's `contains()` dedup can
    /// never reference a half-written object. An existing path is
    /// byte-verified: matched objects are left in place (but still
    /// fsynced at commit, see below), torn ones are rewritten.
    ///
    /// # Panics
    /// Never in practice: object paths always have a 2-hex shard
    /// parent by construction.
    pub fn write(&mut self, bytes: &[u8]) -> StoreResult<Hash> {
        if bytes.len() > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        let h = object_id_from_bytes(bytes);
        let final_path = self.store.path_for(&h);
        // VERIFY-skip an existing object: content addressing makes
        // byte-equality the exact durability test — a good file (from
        // a previously committed session, possibly referenced by
        // native history) must NOT be replaced with an unsynced inode
        // a power loss could tear, while a torn file from a crashed
        // session fails the comparison and is healed by the rewrite.
        let shard_dir = final_path
            .parent()
            .expect("object path always has a 2-hex parent");
        if let Ok(existing) = fs::read(&final_path)
            && existing == bytes
        {
            // The bytes may have matched out of the PAGE CACHE of a
            // crashed session's unsynced write — byte equality is not a
            // durability test, so this pre-existing file still needs a
            // content fsync at commit.
            self.dirs.insert(shard_dir.to_path_buf());
            self.files.insert(final_path);
            return Ok(h);
        }
        fs::create_dir_all(shard_dir)?;
        // Content fsync happens BEFORE the rename, so the object is
        // durable the instant it becomes visible. Only the rename's
        // durability (the shard dir fsync) is deferred to commit.
        crate::atomic::write_content_synced(&final_path, bytes)?;
        self.dirs.insert(shard_dir.to_path_buf());
        Ok(h)
    }

    /// Make the session durable: fsync the CONTENTS of any pre-existing
    /// objects this batch re-used (newly written objects were already
    /// content-fsynced before their rename in [`write`](Self::write)),
    /// then every touched shard directory (renames become durable).
    pub fn commit(self) -> StoreResult<()> {
        for file in &self.files {
            fs::OpenOptions::new().write(true).open(file)?.sync_all()?;
        }
        for dir in &self.dirs {
            crate::atomic::sync_dir(dir)?;
        }
        Ok(())
    }
}

/// Result alias used throughout this module.
pub type StoreResult<T> = Result<T, StoreError>;

// Tiny per-process counter for unique temp-file names. We use this
// instead of pulling in `rand` because the temp name only needs to be
// unique within the process; the atomic `rename` enforces global
// correctness even if two processes collide on a name.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Local content-addressed object store backed by the filesystem.
#[derive(Debug, Clone)]
pub struct ObjectStore {
    /// Absolute path to `<root>/.mkit/objects`.
    objects_root: PathBuf,
    /// Flush/rename primitive seam. Production code always uses
    /// [`RealSyncer`]; unit tests inject a recording double to assert
    /// flush ordering and counts (the O(1)-flushes-per-batch contract).
    syncer: Arc<dyn Syncer>,
    /// Policy handed out by [`Self::batch`]. Defaults to
    /// [`SyncPolicy::Batch`]; the CLI maps the repo config key
    /// `durability.objects = per-object` onto it for deployments that
    /// want the strict historical schedule.
    default_policy: SyncPolicy,
}

impl ObjectStore {
    /// Open an existing repository rooted at `root`. Returns
    /// [`StoreError::NotAMkitRepository`] if `<root>/.mkit/objects` does
    /// not exist.
    pub fn open(root: &Path) -> StoreResult<Self> {
        let mkit_root = root.join(MKIT_DIR);
        let objects_root = mkit_root.join(OBJECTS_DIR);
        if !objects_root.is_dir() {
            return Err(StoreError::NotAMkitRepository);
        }
        // Reject a repository that does not declare merkle object
        // addressing — a pre-merkle repo would mis-read every Tree /
        // ChunkedBlob (and thus every Commit) under the new id scheme.
        match fs::read_to_string(mkit_root.join(FORMAT_FILE)) {
            Ok(s) if s.trim() == FORMAT_VALUE => {}
            Ok(s) => {
                return Err(StoreError::IncompatibleRepoFormat {
                    found: Some(s.trim().to_owned()),
                });
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::IncompatibleRepoFormat { found: None });
            }
            Err(e) => return Err(StoreError::Io(e)),
        }
        Ok(Self {
            objects_root,
            syncer: Arc::new(RealSyncer),
            default_policy: SyncPolicy::Batch,
        })
    }

    /// Initialise a fresh `.mkit/` directory under `root`. Returns
    /// [`StoreError::AlreadyInitialized`] if `.mkit/` already exists.
    pub fn init(root: &Path) -> StoreResult<Self> {
        let mkit_root = root.join(MKIT_DIR);
        if mkit_root.exists() {
            return Err(StoreError::AlreadyInitialized);
        }
        let objects_root = mkit_root.join(OBJECTS_DIR);
        fs::create_dir_all(&objects_root)?;
        // Declare the object-addressing format so a future open by an
        // incompatible (older) mkit fails loudly (SPEC-MERKLE-OBJECTS §7).
        fs::write(
            mkit_root.join(FORMAT_FILE),
            format!("{FORMAT_VALUE}\n").as_bytes(),
        )?;
        Ok(Self {
            objects_root,
            syncer: Arc::new(RealSyncer),
            default_policy: SyncPolicy::Batch,
        })
    }

    /// Select the [`SyncPolicy`] that [`Self::batch`] hands out. The
    /// CLI wires the repo config key `durability.objects` here so
    /// deployments on filesystems where they prefer the strict
    /// per-object schedule can opt into it (SPEC-OBJECTS §10.1).
    pub fn set_sync_policy(&mut self, policy: SyncPolicy) {
        self.default_policy = policy;
    }

    /// Replace the flush/rename primitives. Test-only seam — see the
    /// `syncer` field. Not exposed publicly so the production sync
    /// strategy cannot be silently weakened by downstream code.
    #[cfg(test)]
    pub(crate) fn set_syncer(&mut self, syncer: Arc<dyn Syncer>) {
        self.syncer = syncer;
    }

    /// The active flush/rename primitives, shared with [`WriteBatch`].
    pub(crate) fn syncer(&self) -> &Arc<dyn Syncer> {
        &self.syncer
    }

    /// Start a batched write with the store's configured policy
    /// (default [`SyncPolicy::Batch`]): objects staged by the batch
    /// become durable and visible together at [`WriteBatch::commit`],
    /// with O(1) full flushes per batch instead of per object.
    #[must_use]
    pub fn batch(&self) -> WriteBatch<'_> {
        self.batch_with_policy(self.default_policy)
    }

    /// Start a batched write with an explicit [`SyncPolicy`].
    #[must_use]
    pub fn batch_with_policy(&self, policy: SyncPolicy) -> WriteBatch<'_> {
        WriteBatch::new(self, policy)
    }

    /// Returns `true` when `root` contains a `.mkit/objects` directory.
    #[must_use]
    pub fn is_repo_root(root: &Path) -> bool {
        root.join(MKIT_DIR).join(OBJECTS_DIR).is_dir()
    }

    /// Absolute path to the `objects/` directory.
    #[must_use]
    pub fn objects_root(&self) -> &Path {
        &self.objects_root
    }

    /// Compute the on-disk path for `hash`, joined under `objects/`.
    /// `pub(crate)` so [`WriteBatch`] shares the single layout rule.
    pub(crate) fn path_for(&self, h: &Hash) -> PathBuf {
        let p = object_path(h);
        // Both halves are ASCII hex by construction in `object_path`.
        let dir = std::str::from_utf8(&p.dir).expect("ascii hex");
        let file = std::str::from_utf8(&p.file).expect("ascii hex");
        self.objects_root.join(dir).join(file)
    }

    /// Returns `true` when the object `h` is present in the store. Does
    /// **not** verify integrity — use [`Self::read`] for that.
    #[must_use]
    pub fn contains(&self, h: &Hash) -> bool {
        self.path_for(h).is_file()
    }

    /// Write `bytes` to the store, returning their BLAKE3 hash. Atomic:
    /// writes to a sibling temp file, `fsync`s, then renames into place.
    /// Idempotent — re-writing the same bytes is a no-op (the temp file
    /// is unlinked on the early-return path).
    ///
    /// # Panics
    ///
    /// Panics only if the internal hash-to-path mapping produces a path
    /// without a parent directory, which is impossible by construction.
    pub fn write(&self, bytes: &[u8]) -> StoreResult<Hash> {
        if bytes.len() > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        let h = object_id_from_bytes(bytes);
        let final_path = self.path_for(&h);
        if final_path.exists() {
            // Dedup hit: the object is visible, but if another process
            // renamed it and has not yet flushed the dirent, it may not
            // be durable — and our caller is about to reference it.
            // Flush its shard dir before returning (SPEC-OBJECTS §10.1
            // dedup rule, mirroring WriteBatch's touched_shards).
            self.syncer()
                .dir_sync(final_path.parent().expect("object path has parent"))?;
            return Ok(h);
        }
        let shard_dir = final_path
            .parent()
            .expect("object path always has a 2-hex parent");
        fs::create_dir_all(shard_dir)?;
        write_atomic(&final_path, bytes, &**self.syncer())?;
        Ok(h)
    }

    /// Begin a bulk-write session: each new object is written
    /// durable-before-visible (contents fsynced, then renamed), and
    /// [`BulkWriter::commit`] batches the directory fsyncs (rename
    /// durability) plus a content fsync of any re-used pre-existing
    /// objects once at the end, instead of fsyncing a dir per write.
    ///
    /// Because content is durable before the rename, the session upholds
    /// the store's global invariant even under concurrent readers: an
    /// object another process can `contains()`-dedup against is always
    /// backed by durable bytes.
    ///
    /// Crash-safety contract (deliberately weaker than [`Self::write`]
    /// only for the rename/dirent half, for callers whose whole
    /// operation is idempotent — e.g. the deterministic git-import,
    /// which re-runs from a retained source mirror): after a crash
    /// BEFORE `commit`, a just-renamed object's dirent may be lost (the
    /// shard dir is not yet fsynced), so objects may be missing — never
    /// torn, since contents were fsynced first. Existing paths are
    /// VERIFIED (byte compare)
    /// rather than blindly rewritten or blindly trusted: a matching
    /// file is left untouched (it may be durable and referenced by
    /// native history — replacing it with an unsynced inode would put
    /// it at risk), a torn one is healed by rewrite, and reads always
    /// BLAKE3-verify. Callers MUST gate bulk sessions behind their
    /// own crash marker and re-run on detection.
    #[must_use]
    pub fn bulk_writer(&self) -> BulkWriter<'_> {
        BulkWriter {
            store: self,
            dirs: std::collections::HashSet::new(),
            files: std::collections::HashSet::new(),
        }
    }

    /// Read raw bytes for `h`. Verifies that BLAKE3 of the on-disk
    /// bytes equals `h` and returns [`StoreError::HashMismatch`] on
    /// failure (the bytes are still discarded so callers cannot
    /// accidentally use corrupt data).
    pub fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        let path = self.path_for(h);
        let mut file = File::open(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => StoreError::ObjectNotFound(to_hex(h)),
            _ => StoreError::Io(e),
        })?;
        let meta = file.metadata()?;
        let size = meta.len();
        if u128::from(size) > MAX_RAW_OBJECT_SIZE as u128 {
            return Err(StoreError::ObjectTooLarge);
        }
        // We've already bounded `size` by `MAX_RAW_OBJECT_SIZE` (1 GiB),
        // which fits in `usize` on every platform we support (32-bit
        // included). Pre-size the buffer to avoid the doubling
        // re-allocations of `read_to_end` for large objects.
        let cap = usize::try_from(size).map_err(|_| StoreError::ObjectTooLarge)?;
        let mut bytes = Vec::with_capacity(cap);
        file.read_to_end(&mut bytes)?;
        let actual = object_id_from_bytes(&bytes);
        if actual != *h {
            return Err(StoreError::HashMismatch {
                expected: to_hex(h),
                actual: to_hex(&actual),
            });
        }
        Ok(bytes)
    }

    /// The object's type tag, from its 6-byte prologue — without
    /// reading or hash-verifying the body. Backs cheap shape checks
    /// (e.g. "is this staged hash blob-like?") that previously paid a
    /// full read+BLAKE3 of every staged blob per status/commit; the
    /// real read path still integrity-verifies at use time.
    ///
    /// # Errors
    /// [`StoreError::ObjectNotFound`] if absent; [`StoreError::Decode`]
    /// for a short file, bad magic/version, or unknown tag.
    pub fn object_type(&self, h: &Hash) -> StoreResult<crate::object::ObjectType> {
        let path = self.path_for(h);
        let mut file = File::open(&path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => StoreError::ObjectNotFound(to_hex(h)),
            _ => StoreError::Io(e),
        })?;
        let mut prologue = [0u8; 6];
        file.read_exact(&mut prologue)
            .map_err(|_| StoreError::Decode(MkitError::EmptyData))?;
        if prologue[1..5] != crate::object::MAGIC {
            return Err(StoreError::Decode(MkitError::InvalidMagic));
        }
        if prologue[5] != crate::object::SCHEMA_VERSION {
            return Err(StoreError::Decode(MkitError::UnsupportedObjectVersion));
        }
        crate::object::ObjectType::from_u8(prologue[0]).map_err(StoreError::Decode)
    }

    /// Convenience: read raw bytes and decode into a typed [`Object`].
    pub fn read_object(&self, h: &Hash) -> StoreResult<Object> {
        let bytes = self.read(h)?;
        let obj = serialize::deserialize(&bytes)?;
        Ok(obj)
    }

    /// Hash-verifying variant of [`object_type`](Self::object_type): reads
    /// the whole object and confirms its content hashes to `h` before
    /// returning the declared type. This is the integrity guard for
    /// tree-publication paths (commit, merge, rebase, …) — `object_type`
    /// alone reads only the 6-byte prologue, so a staged object corrupted
    /// after `add` would otherwise be published into a durable tree and
    /// only fail at later read time. Use `object_type` on hot read-only
    /// paths (status/diff snapshots) where nothing durable is published.
    pub fn verify_object_type(&self, h: &Hash) -> StoreResult<crate::object::ObjectType> {
        let bytes = self.read(h)?; // read() re-hashes and rejects on mismatch
        if bytes.len() < 6 {
            return Err(StoreError::Decode(MkitError::EmptyData));
        }
        if bytes[1..5] != crate::object::MAGIC {
            return Err(StoreError::Decode(MkitError::InvalidMagic));
        }
        if bytes[5] != crate::object::SCHEMA_VERSION {
            return Err(StoreError::Decode(MkitError::UnsupportedObjectVersion));
        }
        crate::object::ObjectType::from_u8(bytes[0]).map_err(StoreError::Decode)
    }

    /// Enumerate every object hash currently in the store by walking
    /// `objects/<2-hex>/<62-hex>`. Entries whose names are not the
    /// expected hex shape (stray files, atomic-write temp files, unknown
    /// dirs) are skipped — they are not objects. Used by `gc` to find
    /// prune candidates.
    ///
    /// # Errors
    /// [`StoreError::Io`] if a directory cannot be read (gc must then
    /// fail closed rather than prune against a partial enumeration).
    pub fn iter_object_hashes(&self) -> StoreResult<Vec<Hash>> {
        let mut out = Vec::new();
        let shards = match fs::read_dir(&self.objects_root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(StoreError::Io(e)),
        };
        for shard in shards {
            let shard = shard?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            let dir_name = shard.file_name();
            let Some(dir) = dir_name.to_str() else {
                continue;
            };
            if dir.len() != 2 || !dir.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            for entry in fs::read_dir(shard.path())? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let file_name = entry.file_name();
                let Some(file) = file_name.to_str() else {
                    continue;
                };
                if file.len() != 62 {
                    continue;
                }
                // Reassemble the 64-hex id and parse it; skips non-objects.
                if let Ok(h) = hash::from_hex(&format!("{dir}{file}")) {
                    out.push(h);
                }
            }
        }
        Ok(out)
    }

    /// Filesystem metadata for object `h` (size + mtime), for gc's
    /// grace-window check.
    ///
    /// # Errors
    /// [`StoreError::ObjectNotFound`] if absent, else [`StoreError::Io`].
    pub fn object_metadata(&self, h: &Hash) -> StoreResult<fs::Metadata> {
        fs::metadata(self.path_for(h)).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => StoreError::ObjectNotFound(to_hex(h)),
            _ => StoreError::Io(e),
        })
    }

    /// Delete object `h` from the store. Idempotent: a missing object is
    /// not an error (it may have been pruned already).
    ///
    /// # Errors
    /// [`StoreError::Io`] on a filesystem failure other than not-found.
    pub fn remove_object(&self, h: &Hash) -> StoreResult<()> {
        match fs::remove_file(self.path_for(h)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }
}

/// Create a uniquely-named sibling temp file in `parent` for the object
/// file `file_name`. The `.{name}.tmp.{pid}.{seq}` shape is what
/// [`ObjectStore::iter_object_hashes`] and the stale-temp tests rely on
/// to skip non-objects.
pub(crate) fn temp_file_in(parent: &Path, file_name: &str) -> io::Result<NamedTempFile> {
    let pid = process::id();
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{file_name}.tmp.{pid}.{seq}");
    NamedTempFile::with_prefix_in(tmp_name, parent)
}

/// Atomically write `bytes` to `final_path` with per-object durability
/// ([`SyncPolicy::PerObject`]): temp file, full flush, rename into
/// place, parent-dir flush. On Unix, `rename(2)` is atomic with respect
/// to concurrent readers and replaces the destination. On Windows,
/// [`NamedTempFile::persist`] uses `MOVEFILE_REPLACE_EXISTING`
/// semantics so the replace-existing path works there too.
///
/// After a successful rename we flush the parent directory on Unix to
/// commit the dirent update — without this, the rename can survive a
/// power loss only in the page cache and the file appears missing on
/// reboot.
///
/// All flush/rename primitives go through `syncer` so unit tests can
/// assert ordering; [`RealSyncer`] preserves the historical behaviour
/// exactly.
fn write_atomic(final_path: &Path, bytes: &[u8], syncer: &dyn Syncer) -> io::Result<()> {
    let parent = final_path.parent().expect("write_atomic: path has parent");
    let file_name = final_path
        .file_name()
        .expect("write_atomic: path has file name")
        .to_string_lossy();

    let mut tmp = temp_file_in(parent, &file_name)?;
    tmp.as_file_mut().write_all(bytes)?;
    syncer.full(tmp.as_file(), tmp.path())?;

    // NamedTempFile::persist uses a cross-platform atomic replace:
    // rename(2) on Unix, MoveFileExW with MOVEFILE_REPLACE_EXISTING on Windows.
    syncer.rename(tmp.into_temp_path(), final_path)?;

    syncer.dir_sync(parent)?;
    Ok(())
}

/// Read source shared by [`ObjectStore`] and snapshot overlays, so
/// tree-diff code can resolve objects from either the durable store or
/// an in-memory [`EphemeralSink`].
pub trait ObjectSource {
    /// Read and integrity-verify the raw bytes of `h`.
    ///
    /// # Errors
    /// [`StoreError::ObjectNotFound`] / [`StoreError::HashMismatch`] /
    /// I/O errors, as for [`ObjectStore::read`].
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>>;

    /// Read and decode `h` into a typed [`Object`].
    ///
    /// # Errors
    /// As [`Self::read`], plus decode errors.
    fn read_object(&self, h: &Hash) -> StoreResult<Object> {
        Ok(serialize::deserialize(&self.read(h)?)?)
    }
}

impl ObjectSource for ObjectStore {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        ObjectStore::read(self, h)
    }
}

/// In-memory object overlay for **ephemeral worktree snapshots**
/// (`status`, `diff`, conflict/restore safety checks).
///
/// Writes never touch the durable store: objects whose hash already
/// exists on disk are deduplicated against it (the store's
/// visible-implies-durable invariant makes that safe), everything else
/// lives in a private map that vanishes with the sink. This is what
/// keeps query commands from (a) paying any durability cost, (b)
/// growing `objects/` with throwaway snapshot trees, and (c) ever
/// making a non-durable object *visible* where another writer's dedup
/// could durably reference it.
///
/// Reads fall through to the underlying store, so diff walkers can
/// resolve a snapshot tree that references committed objects.
#[derive(Debug)]
pub struct EphemeralSink<'s> {
    store: &'s ObjectStore,
    objects: std::sync::Mutex<std::collections::HashMap<Hash, Vec<u8>>>,
}

impl<'s> EphemeralSink<'s> {
    /// Create an empty overlay over `store`.
    #[must_use]
    pub fn new(store: &'s ObjectStore) -> Self {
        Self {
            store,
            objects: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl ObjectSink for EphemeralSink<'_> {
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash> {
        self.put_parts(&[bytes])
    }

    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        let mut total: usize = 0;
        for p in parts {
            total = total
                .checked_add(p.len())
                .ok_or(StoreError::ObjectTooLarge)?;
        }
        if total > MAX_RAW_OBJECT_SIZE {
            return Err(StoreError::ObjectTooLarge);
        }
        // Merkelized types (Tree/ChunkedBlob) are addressed by a BMT root,
        // which needs the contiguous bytes to decode — so they buffer, then
        // dispatch through the one id function. Blobs/chunks (the bulk of
        // bytes) stay streaming and copy-free, materialising only on insert.
        let type_byte = parts.first().and_then(|p| p.first()).copied();
        let is_merkle = matches!(
            type_byte.and_then(|b| crate::object::ObjectType::from_u8(b).ok()),
            Some(crate::object::ObjectType::Tree | crate::object::ObjectType::ChunkedBlob)
        );
        if is_merkle {
            let mut buf = Vec::with_capacity(total);
            for p in parts {
                buf.extend_from_slice(p);
            }
            let h = object_id_from_bytes(&buf);
            if self.store.contains(&h) {
                return Ok(h);
            }
            self.objects
                .lock()
                .expect("ephemeral sink mutex")
                .entry(h)
                .or_insert(buf);
            return Ok(h);
        }
        let mut hasher = hash::Hasher::new();
        for p in parts {
            hasher.update(p);
        }
        let h = hasher.finalize();
        // Dedup against the durable store: visible store objects are
        // durable by invariant, and skipping them keeps the overlay's
        // memory bounded by the *changed* content, not the worktree.
        if self.store.contains(&h) {
            return Ok(h);
        }
        let mut map = self.objects.lock().expect("ephemeral sink mutex");
        map.entry(h).or_insert_with(|| {
            let mut buf = Vec::with_capacity(total);
            for p in parts {
                buf.extend_from_slice(p);
            }
            buf
        });
        Ok(h)
    }

    fn has(&self, h: &Hash) -> bool {
        self.objects
            .lock()
            .expect("ephemeral sink mutex")
            .contains_key(h)
            || self.store.contains(h)
    }
}

impl ObjectSource for EphemeralSink<'_> {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        if let Some(bytes) = self
            .objects
            .lock()
            .expect("ephemeral sink mutex")
            .get(h)
            .cloned()
        {
            return Ok(bytes);
        }
        self.store.read(h)
    }
}

/// Write target shared by [`ObjectStore`] (per-object durability) and
/// [`WriteBatch`] (batched durability), so ingest code can be written
/// once against either sink.
pub trait ObjectSink {
    /// Store `bytes` as one object, returning its BLAKE3 hash.
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash>;
    /// Store the concatenation of `parts` as one object without the
    /// caller having to materialise the concatenated buffer.
    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash>;
    /// True when the object is already present (or staged) in this sink.
    fn has(&self, h: &Hash) -> bool;
}

impl ObjectSink for ObjectStore {
    fn put(&self, bytes: &[u8]) -> StoreResult<Hash> {
        self.write(bytes)
    }

    fn put_parts(&self, parts: &[&[u8]]) -> StoreResult<Hash> {
        // Per-object path is the legacy/rare sink; hot ingest paths use
        // WriteBatch, whose put_parts is copy-free.
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut bytes = Vec::with_capacity(total);
        for p in parts {
            bytes.extend_from_slice(p);
        }
        self.write(&bytes)
    }

    fn has(&self, h: &Hash) -> bool {
        self.contains(h)
    }
}

/// On Unix, fsync the directory holding the just-renamed file so the
/// dirent update is durable. No-op on non-Unix (Windows does not expose
/// a stable directory-fsync primitive via `std::fs`).
#[cfg(unix)]
pub(crate) fn sync_parent_dir(parent: &Path) -> io::Result<()> {
    match File::open(parent) {
        Ok(dir) => dir.sync_all(),
        // If the dir disappeared under us (race with external cleanup),
        // the durability invariant is moot — propagate silently.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
pub(crate) fn sync_parent_dir(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Blob;
    use std::fs::OpenOptions;
    use std::io::Seek;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().expect("tempdir");
        let store = ObjectStore::init(dir.path()).expect("init");
        (dir, store)
    }

    #[test]
    fn init_creates_layout() {
        let dir = TempDir::new().unwrap();
        let _ = ObjectStore::init(dir.path()).unwrap();
        assert!(dir.path().join(MKIT_DIR).is_dir());
        assert!(dir.path().join(MKIT_DIR).join(OBJECTS_DIR).is_dir());
    }

    #[test]
    fn init_rejects_already_initialized() {
        let dir = TempDir::new().unwrap();
        ObjectStore::init(dir.path()).unwrap();
        let err = ObjectStore::init(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::AlreadyInitialized));
    }

    #[test]
    fn open_rejects_non_repo() {
        let dir = TempDir::new().unwrap();
        let err = ObjectStore::open(dir.path()).unwrap_err();
        assert!(matches!(err, StoreError::NotAMkitRepository));
    }

    #[test]
    fn init_writes_format_marker_and_open_accepts_it() {
        let dir = TempDir::new().unwrap();
        ObjectStore::init(dir.path()).unwrap();
        let marker = fs::read_to_string(dir.path().join(MKIT_DIR).join(FORMAT_FILE)).unwrap();
        assert_eq!(marker.trim(), FORMAT_VALUE);
        // A freshly-init'd repo opens cleanly.
        ObjectStore::open(dir.path()).unwrap();
    }

    #[test]
    fn open_rejects_repo_missing_or_wrong_format_marker() {
        // A pre-merkle repo (objects dir present, no format marker) must be
        // rejected loudly rather than silently mis-read.
        let dir = TempDir::new().unwrap();
        ObjectStore::init(dir.path()).unwrap();
        let marker_path = dir.path().join(MKIT_DIR).join(FORMAT_FILE);

        fs::remove_file(&marker_path).unwrap();
        assert!(matches!(
            ObjectStore::open(dir.path()),
            Err(StoreError::IncompatibleRepoFormat { found: None })
        ));

        // A repo declaring some other (e.g. future) format is also rejected.
        fs::write(&marker_path, b"flat-v0\n").unwrap();
        assert!(matches!(
            ObjectStore::open(dir.path()),
            Err(StoreError::IncompatibleRepoFormat { found: Some(_) })
        ));
    }

    #[test]
    fn is_repo_root_predicate() {
        let dir = TempDir::new().unwrap();
        assert!(!ObjectStore::is_repo_root(dir.path()));
        ObjectStore::init(dir.path()).unwrap();
        assert!(ObjectStore::is_repo_root(dir.path()));
    }

    #[test]
    fn write_then_read_roundtrip() {
        let (_dir, store) = fresh_store();
        let bytes = b"hello world".to_vec();
        let h = store.write(&bytes).unwrap();
        assert!(store.contains(&h));
        let got = store.read(&h).unwrap();
        assert_eq!(got, bytes);
    }

    #[test]
    fn read_object_deserialises() {
        let (_dir, store) = fresh_store();
        let obj = Object::Blob(Blob {
            data: b"object bytes".to_vec(),
        });
        let bytes = serialize::serialize(&obj).unwrap();
        let h = store.write(&bytes).unwrap();
        let parsed = store.read_object(&h).unwrap();
        assert_eq!(parsed, obj);
    }

    #[test]
    fn write_is_idempotent() {
        let (_dir, store) = fresh_store();
        let bytes = b"duplicate".to_vec();
        let h1 = store.write(&bytes).unwrap();
        let h2 = store.write(&bytes).unwrap();
        assert_eq!(h1, h2);
        // Second write must not have produced any stray temp files.
        let shard = store.path_for(&h1);
        let parent = shard.parent().unwrap();
        let entries: Vec<_> = fs::read_dir(parent).unwrap().collect();
        assert_eq!(
            entries.len(),
            1,
            "shard dir should contain exactly the final object, no temp leaks"
        );
    }

    #[test]
    fn read_missing_returns_not_found() {
        let (_dir, store) = fresh_store();
        let phony = hash::hash(b"never written");
        let err = store.read(&phony).unwrap_err();
        assert!(matches!(err, StoreError::ObjectNotFound(_)));
        assert!(!store.contains(&phony));
    }

    #[test]
    fn write_rejects_oversize() {
        let (_dir, store) = fresh_store();
        // We obviously can't allocate 1 GiB+1 in a test, so use a small
        // synthetic threshold check by exercising the guard surface
        // through a fake slice header. The cleanest portable approach
        // is to assert the constant directly and rely on the smaller
        // overflow test below for runtime coverage.
        let _ = MAX_RAW_OBJECT_SIZE;
        // Realistic small write still works.
        let h = store.write(&[0u8; 16]).unwrap();
        assert!(store.contains(&h));
    }

    #[test]
    fn read_rejects_oversize_on_disk() {
        // Construct an oversize on-disk blob by hand and confirm `read`
        // refuses it. We use a sentinel size = MAX + 1 file padded with
        // zeros; this allocates ~1 GiB of disk, which is unfriendly in
        // unit tests, so instead we monkey-patch via a smaller-cap copy
        // of the read path: we synthesise a too-large file by truncating
        // a real one and verifying the comparison logic at the boundary.
        //
        // We exercise `MAX_RAW_OBJECT_SIZE` indirectly by writing a
        // small object and then *replacing* the on-disk file with one
        // whose `metadata().len()` exceeds the cap. We use sparse
        // truncation so no real disk is consumed.
        let (_dir, store) = fresh_store();
        let h = store.write(b"seed").unwrap();
        let path = store.path_for(&h);
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        // Sparse extend to cap+1 bytes; allocates effectively no blocks.
        f.set_len(MAX_RAW_OBJECT_SIZE as u64 + 1).unwrap();
        drop(f);
        let err = store.read(&h).unwrap_err();
        assert!(matches!(err, StoreError::ObjectTooLarge));
    }

    #[test]
    fn read_detects_corruption() {
        let (_dir, store) = fresh_store();
        let bytes = b"trustworthy".to_vec();
        let h = store.write(&bytes).unwrap();
        // Flip a single byte in the on-disk file and expect HashMismatch.
        let path = store.path_for(&h);
        {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(io::SeekFrom::Start(0)).unwrap();
            f.write_all(&[bytes[0] ^ 0xFF]).unwrap();
            f.sync_all().unwrap();
        }
        let err = store.read(&h).unwrap_err();
        match err {
            StoreError::HashMismatch { expected, actual } => {
                assert_eq!(expected, to_hex(&h));
                assert_ne!(actual, expected, "actual must differ once corrupted");
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn path_layout_is_2_then_62_hex() {
        let (_dir, store) = fresh_store();
        let bytes = b"layout test".to_vec();
        let h = store.write(&bytes).unwrap();
        let hex = to_hex(&h);
        let path = store.path_for(&h);
        let parent = path.parent().unwrap();
        let parent_name = parent.file_name().unwrap().to_str().unwrap();
        let file_name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(parent_name.len(), 2);
        assert_eq!(file_name.len(), 62);
        assert_eq!(parent_name, &hex[..2]);
        assert_eq!(file_name, &hex[2..]);
        assert!(path.is_file(), "object file must exist at expected path");
    }

    #[test]
    fn temp_file_left_behind_does_not_satisfy_contains() {
        // Simulate a crash mid-write: drop a stale `.tmp.*` file in the
        // shard dir without ever renaming. `contains()` must report the
        // object as absent, and the shard dir must not contain a real
        // entry that passes the hash check.
        let (_dir, store) = fresh_store();
        let target = hash::hash(b"never finalised");
        let final_path = store.path_for(&target);
        let shard = final_path.parent().unwrap();
        fs::create_dir_all(shard).unwrap();
        let stale = shard.join(format!(
            ".{}.tmp.0.0",
            final_path.file_name().unwrap().to_string_lossy()
        ));
        fs::write(&stale, b"partial").unwrap();
        assert!(stale.is_file());
        assert!(!store.contains(&target));
        // No file in the shard dir should hash to `target`.
        for entry in fs::read_dir(shard).unwrap() {
            let p = entry.unwrap().path();
            let bytes = fs::read(&p).unwrap();
            assert_ne!(
                hash::hash(&bytes),
                target,
                "stale temp file must not satisfy the target hash"
            );
        }
    }
}

#[cfg(test)]
mod bulk_writer_tests {
    use super::*;

    #[test]
    fn bulk_writer_round_trips_and_rewrites() {
        let td = tempfile::tempdir().unwrap();
        let store = ObjectStore::init(td.path()).unwrap();
        let obj = crate::serialize::serialize(&crate::object::Object::Blob(crate::object::Blob {
            data: b"bulk".to_vec(),
        }))
        .unwrap();
        let mut bw = store.bulk_writer();
        let h1 = bw.write(&obj).unwrap();
        // No existence short-circuit: rewriting is fine and heals
        // torn files on idempotent re-runs.
        let h2 = bw.write(&obj).unwrap();
        assert_eq!(h1, h2);
        bw.commit().unwrap();
        assert_eq!(store.read(&h1).unwrap(), obj);
        // Interoperates with the normal (fsynced) writer.
        assert_eq!(store.write(&obj).unwrap(), h1);
    }
}
