//! `FsBlobStore`: content-addressed blobs as files, `<root>/packs/<64-hex>`
//! by default, the layout `FileTransport::upload_pack` writes.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use mkit_core::hash::Hasher;
use mkit_transport_file::{create_dir_all_durably, sync_dir, temp_path};

use super::{io_error, unavailable};
use crate::store::{
    BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, CommitOutcome, MAX_BLOB_PIECE_BYTES,
    PackSink, StoreError,
};

/// The size of each piece of a streamed body.
pub(super) const READ_BLOCK: usize = 64 * 1024;

/// A [`BlobStore`] over one keyspace directory, `<root>/<keyspace>/<64-hex>`
/// (`packs` by default). An upload streams into a temp file in that
/// directory (named like `FileTransport`'s own, `.<hex>.tmp.<pid>.<seq>`)
/// while hashing it, and becomes visible only once its BLAKE3 and length
/// verify: fsync, rename over the destination, fsync the directory. A
/// failed, aborted or dropped upload removes its temp file and never
/// touches an existing blob. A new directory's entry is fsynced into its
/// parent before anything is published in it. A full disk or quota is
/// [`StoreError::Full`].
///
/// A process that crashes mid-upload leaves its temp file,
/// `<keyspace>/.<64-hex>.tmp.<pid>.<seq>`, behind. It is never visible as
/// a blob; [`FsBlobStore::sweep_stale_uploads`] removes old ones.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    root: PathBuf,
    keyspace: &'static str,
}

impl FsBlobStore {
    /// The `packs` keyspace under `root`, the directory `FileTransport`
    /// uploads to.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_keyspace(root, "packs")
    }

    /// The `keyspace` directory under `root` (e.g. `objects` for the global
    /// object store). `keyspace` is one plain path component.
    ///
    /// # Panics
    /// If `keyspace` is empty, starts with `.` or holds a path separator.
    #[must_use]
    pub fn with_keyspace(root: impl Into<PathBuf>, keyspace: &'static str) -> Self {
        assert!(
            !keyspace.is_empty() && !keyspace.starts_with('.') && !keyspace.contains(['/', '\\']),
            "a keyspace is one plain path component: {keyspace:?}"
        );
        Self {
            root: root.into(),
            keyspace,
        }
    }

    /// The root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The keyspace this store serves.
    #[must_use]
    pub fn keyspace(&self) -> &'static str {
        self.keyspace
    }

    fn dir(&self) -> PathBuf {
        self.root.join(self.keyspace)
    }

    fn path(&self, key: &BlobKey) -> PathBuf {
        self.dir().join(key.to_hex())
    }

    /// Remove the temp files crashed uploads left in the keyspace
    /// directory: regular files named exactly `.<64-hex>.tmp.<pid>.<seq>`
    /// (the names [`temp_path`] gives an upload, from this store or
    /// `FileTransport::upload_pack`) last modified at least `min_age` ago.
    /// Nothing else is touched: no blob, no symlink, no other name, no file
    /// modified in the future. Returns how many were removed; a file that
    /// cannot be inspected or removed is skipped.
    ///
    /// A live upload keeps its temp file's modification time fresh as it
    /// writes, so a `min_age` well above any pause between two writes of
    /// one upload is safe against `FileTransport` writers, which take no
    /// lock. The caller must also rule out a live writer that can pause for
    /// longer, a stalled streaming upload: `mkit serve` sweeps only while
    /// it holds `serve.lock` exclusively, which no other `mkit serve` or
    /// `mkit-server` (each holds it shared) can then hold.
    ///
    /// # Errors
    /// I/O listing the directory; a missing directory sweeps nothing.
    pub fn sweep_stale_uploads(&self, min_age: Duration) -> io::Result<usize> {
        let entries = match fs::read_dir(self.dir()) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e),
        };
        let now = SystemTime::now();
        let mut removed = 0;
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            if !name.to_str().is_some_and(is_upload_temp_name) {
                continue;
            }
            // `DirEntry::metadata` does not follow a symlink.
            let Ok(meta) = entry.metadata() else { continue };
            let stale = meta.is_file()
                && meta
                    .modified()
                    .ok()
                    .and_then(|m| now.duration_since(m).ok())
                    .is_some_and(|age| age >= min_age);
            if stale && fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Whether `name` is an upload's temp file name, `.<64 lowercase
/// hex>.tmp.<pid>.<seq>`, with a decimal `u32` pid and `u64` sequence.
pub(super) fn is_upload_temp_name(name: &str) -> bool {
    let decimal = |s: &str, max: usize| {
        !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_digit())
    };
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some((hex, rest)) = rest.split_at_checked(64) else {
        return false;
    };
    let Some((pid, seq)) = rest.strip_prefix(".tmp.").and_then(|r| r.split_once('.')) else {
        return false;
    };
    hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && decimal(pid, 10)
        && decimal(seq, 20)
}

/// The upload handle of [`FsBlobStore`]: a temp file and a running hash.
/// Memory is one chunk, never the blob.
pub struct FsPackSink {
    /// The open temp file; `None` once closed for the rename.
    file: Option<File>,
    /// The temp file's path; `None` once it was renamed or removed.
    tmp: Option<PathBuf>,
    dest: PathBuf,
    key: BlobKey,
    declared: u64,
    written: u64,
    hasher: Hasher,
}

impl fmt::Debug for FsPackSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsPackSink")
            .field("tmp", &self.tmp)
            .field("dest", &self.dest)
            .field("declared", &self.declared)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

impl FsPackSink {
    /// Verify the upload and move it into place; `Ok(true)` if the
    /// destination already existed.
    fn publish(&mut self) -> Result<bool, StoreError> {
        if self.written != self.declared {
            return Err(StoreError::Invalid("blob length does not match".into()));
        }
        if self.hasher.finalize() != self.key.0 {
            return Err(StoreError::Invalid(
                "blob hash does not match its key".into(),
            ));
        }
        let file = self.file.take().ok_or_else(closed)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        let tmp = self.tmp.as_ref().ok_or_else(closed)?;
        let existed = self.dest.exists();
        // Identical bytes by construction, so replacing a present blob is
        // harmless, and it repairs one a pre-atomic writer left short.
        fs::rename(tmp, &self.dest).map_err(io_error)?;
        self.tmp = None;
        if let Some(dir) = self.dest.parent() {
            sync_dir(dir).map_err(io_error)?;
        }
        Ok(existed)
    }
}

/// The error for a sink used after it was closed (unreachable: `commit`
/// and `abort` consume it).
fn closed() -> StoreError {
    StoreError::unavailable(io::Error::other("blob upload already closed"))
}

impl Drop for FsPackSink {
    fn drop(&mut self) {
        self.file = None;
        if let Some(tmp) = self.tmp.take() {
            let _ = fs::remove_file(tmp);
        }
    }
}

impl PackSink for FsPackSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        let total = self.written.checked_add(chunk.len() as u64);
        let Some(total) = total.filter(|t| *t <= self.declared) else {
            return Err(StoreError::Invalid("blob is longer than declared".into()));
        };
        let file = self.file.as_mut().ok_or_else(closed)?;
        file.write_all(&chunk).map_err(io_error)?;
        self.hasher.update(&chunk);
        self.written = total;
        Ok(())
    }

    async fn commit(mut self) -> Result<CommitOutcome, StoreError> {
        // On any error, dropping `self` removes the temp file.
        Ok(if self.publish()? {
            CommitOutcome::AlreadyPresent
        } else {
            CommitOutcome::Created
        })
    }

    async fn abort(self) {}
}

/// The remaining bytes of a streamed body, read [`READ_BLOCK`] at a time.
struct Blocks {
    file: File,
    remaining: u64,
}

impl Stream for Blocks {
    type Item = Result<Bytes, StoreError>;

    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let n = usize::try_from(this.remaining).map_or(READ_BLOCK, |r| r.min(READ_BLOCK));
        let mut piece = BytesMut::zeroed(n);
        match this.file.read_exact(&mut piece) {
            Ok(()) => {
                this.remaining -= n as u64;
                Poll::Ready(Some(Ok(piece.freeze())))
            }
            Err(e) => {
                this.remaining = 0;
                Poll::Ready(Some(Err(io_error(e))))
            }
        }
    }
}

// The piece size a streamed body must respect.
const _: () = assert!(READ_BLOCK <= MAX_BLOB_PIECE_BYTES);

impl BlobStore for FsBlobStore {
    type Sink = FsPackSink;

    async fn begin(&self, key: BlobKey, len: u64) -> Result<FsPackSink, StoreError> {
        let dir = self.dir();
        create_dir_all_durably(&dir).map_err(io_error)?;
        let dest = self.path(&key);
        let tmp = temp_path(&dest).map_err(io_error)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(io_error)?;
        Ok(FsPackSink {
            file: Some(file),
            tmp: Some(tmp),
            dest,
            key,
            declared: len,
            written: 0,
            hasher: Hasher::new(),
        })
    }

    async fn get(
        &self,
        key: &BlobKey,
        range: Option<ByteRange>,
    ) -> Result<Option<BlobBody>, StoreError> {
        let mut file = match File::open(self.path(key)) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_error(e)),
        };
        let len = file.metadata().map_err(io_error)?.len();
        let span = match range {
            Some(range) => range.resolve(len)?,
            None => 0..len,
        };
        if span.start > 0 {
            file.seek(SeekFrom::Start(span.start)).map_err(io_error)?;
        }
        let n = span.end - span.start;
        if let Ok(whole) = usize::try_from(n)
            && whole <= MAX_BLOB_PIECE_BYTES
        {
            let mut buf = vec![0; whole];
            file.read_exact(&mut buf).map_err(io_error)?;
            return Ok(Some(BlobBody::Bytes(Bytes::from(buf))));
        }
        Ok(Some(BlobBody::Stream {
            len: n,
            stream: Box::pin(Blocks { file, remaining: n }),
        }))
    }

    async fn head(&self, key: &BlobKey) -> Result<Option<BlobMeta>, StoreError> {
        match fs::metadata(self.path(key)) {
            Ok(meta) => Ok(Some(BlobMeta { len: meta.len() })),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(e)),
        }
    }

    async fn probe(&self) -> Result<(), StoreError> {
        let meta = fs::metadata(&self.root).map_err(io_error)?;
        if meta.is_dir() {
            Ok(())
        } else {
            Err(unavailable(io::Error::other(
                "blob root is not a directory",
            )))
        }
    }

    async fn delete(&self, key: &BlobKey) -> Result<bool, StoreError> {
        match fs::remove_file(self.path(key)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io_error(e)),
        }
        sync_dir(&self.dir()).map_err(io_error)?;
        Ok(true)
    }
}
