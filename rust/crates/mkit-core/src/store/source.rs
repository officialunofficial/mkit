//! Read-side object sources and adapters over the durable [`ObjectStore`].
//!
//! [`ObjectSource`] is the read trait shared by the store and its overlays;
//! [`EphemeralSink`] is the in-memory snapshot overlay for query commands;
//! [`DisplaySource`] is the display-only adapter that opts a render path out of
//! per-read hash verification (#625). Extracted from `store.rs` (#633): these are
//! consumers of the store's read API, distinct from its on-disk write/fsync
//! machinery.

use crate::hash::Hash;
use crate::object::{Object, object_id_from_parts};
use crate::serialize;

use super::{MAX_RAW_OBJECT_SIZE, ObjectSink, ObjectStore, StoreError, StoreResult};

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

    /// Read `h` without integrity verification, for display-only
    /// rendering — see [`ObjectStore::read_unverified`] for the full
    /// policy (#625). Defaults to the fully-verifying [`Self::read`], so
    /// every existing and third-party [`ObjectSource`] stays verifying
    /// unless it explicitly opts in by overriding this method.
    ///
    /// # Errors
    /// As [`Self::read`] (an opting-in override may narrow this to never
    /// return [`StoreError::HashMismatch`]).
    fn read_unverified(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        self.read(h)
    }
}

impl ObjectSource for ObjectStore {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        ObjectStore::read(self, h)
    }

    fn read_unverified(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        ObjectStore::read_unverified(self, h)
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
        let h = object_id_from_parts(parts);
        // Dedup against the durable store: visible store objects are durable
        // by invariant, and skipping them keeps the overlay's memory bounded
        // by the *changed* content, not the worktree. The overlay only ever
        // materialises the bytes on a dedup miss.
        if self.store.contains(&h) {
            return Ok(h);
        }
        self.objects
            .lock()
            .expect("ephemeral sink mutex")
            .entry(h)
            .or_insert_with(|| {
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

impl EphemeralSink<'_> {
    /// The private-map half of a read: bytes this process already built
    /// (via `put`/`put_parts`) and never persisted anywhere else to be
    /// corrupted, shared by both [`ObjectSource::read`] and
    /// [`ObjectSource::read_unverified`] below — the two differ only in
    /// what they do on a miss.
    fn overlay_get(&self, h: &Hash) -> Option<Vec<u8>> {
        self.objects
            .lock()
            .expect("ephemeral sink mutex")
            .get(h)
            .cloned()
    }
}

impl ObjectSource for EphemeralSink<'_> {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        match self.overlay_get(h) {
            Some(bytes) => Ok(bytes),
            None => self.store.read(h),
        }
    }

    fn read_unverified(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        // Private-map hits are already trusted, same as the verifying
        // `read` path above. Only the store fall-through actually skips a
        // hash check.
        match self.overlay_get(h) {
            Some(bytes) => Ok(bytes),
            None => self.store.read_unverified(h),
        }
    }
}

/// Adapter that makes any [`ObjectSource`] read without BLAKE3
/// verification, for display-only rendering (`diff`, `show`, and the
/// commit/merge/pull post-op summaries). Wrap the source once at the
/// render call site — `DisplaySource::new(&store)` — and pass the
/// wrapper wherever a generic `S: ObjectSource` render function expects
/// its source. Every existing render function (`render_stat`,
/// `emit_entry_patch`, `LoadedBlob::load`/`prefix`/`into_content`) works
/// unchanged: the verify/no-verify policy lives entirely in which source
/// gets passed in, never in a flag threaded through render code.
///
/// # When to use
/// mkit never feeds unverified bytes into state that mkit itself writes,
/// or into output that mkit's own tooling round-trips (format-patch →
/// `git am`) — a diffstat or patch preview that only a human reads and
/// discards is neither, so it's fair game. NEVER wrap a source feeding
/// publication (commit/merge/rebase tree writes), dedup, fetch/apply, or
/// any path whose output becomes durable state or gets applied elsewhere
/// (e.g. the format-patch body in `git_tools.rs`, which is deliberately
/// NOT wrapped because `git am` applies it into new commits). See
/// [`ObjectStore::read_unverified`] for the full policy this wrapper
/// exists to apply consistently (#625).
pub struct DisplaySource<'a, S: ObjectSource + ?Sized> {
    inner: &'a S,
}

impl<'a, S: ObjectSource + ?Sized> DisplaySource<'a, S> {
    /// Wrap `inner` so reads through this adapter skip verification.
    #[must_use]
    pub fn new(inner: &'a S) -> Self {
        Self { inner }
    }
}

// Manual `Debug` (rather than `derive`) so this doesn't force an
// unnecessary `S: Debug` bound on every generic render fn that only
// needs `S: ObjectSource`.
impl<S: ObjectSource + ?Sized> std::fmt::Debug for DisplaySource<'_, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisplaySource").finish_non_exhaustive()
    }
}

impl<S: ObjectSource + ?Sized> ObjectSource for DisplaySource<'_, S> {
    fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
        self.inner.read_unverified(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::RepoLayout;
    use std::fs::OpenOptions;
    use std::io::{self, Seek, Write};
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, ObjectStore) {
        let dir = TempDir::new().expect("tempdir");
        let store = ObjectStore::init(&RepoLayout::single(dir.path())).expect("init");
        (dir, store)
    }

    /// Flip the first byte of the on-disk object file for `h`, in place.
    /// Shared by the `read_unverified`/`DisplaySource` corruption tests
    /// below, which all need the same "the bytes on disk no longer match
    /// `h`" setup that `read_detects_corruption` uses inline.
    fn corrupt_first_byte(store: &ObjectStore, h: &Hash, first_byte: u8) {
        let path = store.path_for(h);
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(io::SeekFrom::Start(0)).unwrap();
        f.write_all(&[first_byte ^ 0xFF]).unwrap();
        f.sync_all().unwrap();
    }

    #[test]
    fn display_source_delegates_to_unverified() {
        // `DisplaySource` is the intended call-site adapter: wrapping the
        // store must make `ObjectSource::read` succeed on an object that
        // `ObjectStore::read` itself would reject.
        let (_dir, store) = fresh_store();
        let bytes = b"trustworthy".to_vec();
        let h = store.write(&bytes).unwrap();
        corrupt_first_byte(&store, &h, bytes[0]);
        assert!(matches!(
            store.read(&h).unwrap_err(),
            StoreError::HashMismatch { .. }
        ));

        let display = DisplaySource::new(&store);
        let mut corrupted = bytes.clone();
        corrupted[0] ^= 0xFF;
        assert_eq!(
            display.read(&h).unwrap(),
            corrupted,
            "DisplaySource::read must delegate to the store's unverified read"
        );
    }

    #[test]
    fn ephemeral_sink_unverified_falls_through() {
        // Two shapes an `EphemeralSink` reader can hit: a private-map
        // object built by this snapshot (never touches disk, so nothing to
        // corrupt) and a store-backed object corrupted on disk. Both must
        // read fine through `DisplaySource<EphemeralSink>`.
        let (_dir, store) = fresh_store();
        let durable_bytes = b"trustworthy".to_vec();
        let durable_h = store.write(&durable_bytes).unwrap();
        corrupt_first_byte(&store, &durable_h, durable_bytes[0]);

        let sink = EphemeralSink::new(&store);
        let private_h = sink.put(b"snapshot-only").unwrap();

        let display = DisplaySource::new(&sink);
        assert_eq!(display.read(&private_h).unwrap(), b"snapshot-only");

        let mut corrupted = durable_bytes.clone();
        corrupted[0] ^= 0xFF;
        assert_eq!(display.read(&durable_h).unwrap(), corrupted);
    }

    #[test]
    fn read_unverified_default_is_verifying_read() {
        // A minimal `ObjectSource` impl that only defines `read` must get
        // fully-verifying behaviour from `read_unverified`'s default body
        // — the whole safety net for third-party/future implementors that
        // haven't opted in to the unverified path.
        struct OnlyReadImpl<'s>(&'s ObjectStore);
        impl ObjectSource for OnlyReadImpl<'_> {
            fn read(&self, h: &Hash) -> StoreResult<Vec<u8>> {
                self.0.read(h)
            }
        }

        let (_dir, store) = fresh_store();
        let bytes = b"trustworthy".to_vec();
        let h = store.write(&bytes).unwrap();
        corrupt_first_byte(&store, &h, bytes[0]);

        let only_read = OnlyReadImpl(&store);
        assert!(matches!(
            only_read.read_unverified(&h).unwrap_err(),
            StoreError::HashMismatch { .. }
        ));
    }
}
