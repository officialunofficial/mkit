//! The upload side of [`S3BlobStore`]: the local spool, its disk budget, and
//! [`S3PackSink`].

use std::fmt;
use std::fs::File;
use std::io::{self, ErrorKind, Write as _};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use futures_util::Stream;
use mkit_core::hash::{Hasher, to_hex_bytes};
use mkit_server::storage_error::StorageOp;
use mkit_server::{BlobKey, CommitOutcome, PackSink, StoreError};
use sha2::{Digest as _, Sha256};

use super::put::Progress;
use super::{S3BlobStore, fail};
use crate::blocking::on_pool;

/// The piece size a `PUT` body is read from the spool in.
const SPOOL_READ_BYTES: usize = 256 * 1024;

/// The prefix of every spool file's (short-lived) name.
pub(super) const SPOOL_FILE_PREFIX: &str = ".tmp";

/// A spool I/O failure: a full disk or an exhausted quota (`ENOSPC`,
/// `EDQUOT`) is [`StoreError::Full`], as for the FS store; anything else
/// is [`StoreError::Unavailable`].
pub(super) fn spool_error(what: &str, e: &io::Error) -> StoreError {
    match e.kind() {
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded => {
            tracing::warn!(error = %e, "S3 upload spool: {what}: disk full");
            StoreError::Full
        }
        _ => fail(StorageOp::FsIo, format!("S3 upload spool: {what}: {e}")),
    }
}

/// The spool's disk budget: the bytes every open upload has declared.
#[derive(Debug)]
pub(super) struct SpoolBudget {
    max: u64,
    reserved: AtomicU64,
}

impl SpoolBudget {
    pub(super) fn new(max: u64) -> Self {
        Self {
            max,
            reserved: AtomicU64::new(0),
        }
    }

    pub(super) fn max(&self) -> u64 {
        self.max
    }

    pub(super) fn reserved(&self) -> u64 {
        self.reserved.load(Ordering::SeqCst)
    }

    /// Reserve `n` bytes, before any arrive: [`StoreError::Full`] when the
    /// spool has no room for them now, [`StoreError::Invalid`] when it never
    /// will.
    fn reserve(self: &Arc<Self>, n: u64) -> Result<Reservation, StoreError> {
        if n > self.max {
            return Err(StoreError::Invalid(
                "blob exceeds the upload spool's size".into(),
            ));
        }
        self.reserved
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(n).filter(|total| *total <= self.max)
            })
            .map_err(|_| {
                tracing::warn!(
                    declared = n,
                    max = self.max,
                    "S3 upload spool budget exhausted"
                );
                StoreError::Full
            })?;
        Ok(Reservation {
            budget: Arc::clone(self),
            bytes: n,
        })
    }
}

/// Bytes of the spool budget one upload holds until it commits, aborts or
/// is dropped.
#[derive(Debug)]
struct Reservation {
    budget: Arc<SpoolBudget>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.reserved.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

/// An upload's spool file and its two running hashes.
struct Spool {
    /// Unnamed: unlinked at creation (see the module docs).
    file: File,
    blake3: Hasher,
    sha256: Sha256,
}

impl Spool {
    fn append(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.file.write_all(chunk)?;
        self.blake3.update(chunk);
        self.sha256.update(chunk);
        Ok(())
    }
}

/// Start an upload of `len` bytes: reserve the spool budget (failing fast,
/// before any byte arrives), then create the spool file. `tempfile` makes
/// it unnamed: `O_TMPFILE` on Linux; elsewhere a `.tmp*` file unlinked
/// right after it is created, so only a crash in between leaves a name
/// behind, which [`sweep_spool_dir`] removes at startup.
pub(super) async fn begin(
    store: &S3BlobStore,
    key: BlobKey,
    len: u64,
) -> Result<S3PackSink, StoreError> {
    let reservation = store.spool.reserve(len)?;
    let dir = store.spool_dir.clone();
    let file = on_pool(move || {
        match dir {
            Some(dir) => tempfile::tempfile_in(dir),
            None => tempfile::tempfile(),
        }
        .map_err(|e| spool_error("creating a file", &e))
    })
    .await?;
    Ok(S3PackSink {
        store: store.clone(),
        key,
        declared: len,
        written: 0,
        spool: Some(Spool {
            file,
            blake3: Hasher::new(),
            sha256: Sha256::new(),
        }),
        failed: false,
        _reservation: reservation,
    })
}

/// Remove the `.tmp*` files a crashed server left in the spool directory
/// `dir` (they never hold anything visible). Only safe while no upload is
/// spooling there: the binary runs it under the root's exclusive
/// `server.lock`, before serving. Returns how many it removed.
///
/// # Errors
/// If `dir` cannot be listed or a leftover cannot be removed.
pub fn sweep_spool_dir(dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let leftover = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(SPOOL_FILE_PREFIX));
        if leftover && entry.file_type()?.is_file() {
            std::fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Read `buf.len()` bytes of `file` at `offset`, leaving its cursor alone
/// (a retried `PUT` must not race an abandoned one's reads).
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        let mut done = 0;
        while done < buf.len() {
            let n = std::os::windows::fs::FileExt::seek_read(
                file,
                &mut buf[done..],
                offset + done as u64,
            )?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
        Ok(())
    }
}

/// The spool's first `len` bytes, [`SPOOL_READ_BYTES`] at a time, each
/// read on the blocking pool; every piece handed over counts as progress.
pub(super) fn spool_stream(
    spool: Arc<File>,
    len: u64,
    progress: Arc<Progress>,
) -> impl Stream<Item = Result<Bytes, StoreError>> + Send + 'static {
    futures_util::stream::unfold(0_u64, move |offset| {
        let spool = Arc::clone(&spool);
        let progress = Arc::clone(&progress);
        async move {
            if offset >= len {
                return None;
            }
            let n =
                usize::try_from(len - offset).map_or(SPOOL_READ_BYTES, |r| r.min(SPOOL_READ_BYTES));
            let piece = on_pool(move || {
                let mut buf = vec![0; n];
                read_at(&spool, &mut buf, offset).map_err(|e| spool_error("reading", &e))?;
                Ok(Bytes::from(buf))
            })
            .await;
            progress.touch();
            // After an error the stream ends: the offset jumps past `len`.
            let next = if piece.is_ok() {
                offset + n as u64
            } else {
                len
            };
            Some((piece, next))
        }
    })
}

/// The upload handle of [`S3BlobStore`]: bytes go to a local spool file,
/// never to the bucket, until [`PackSink::commit`] has verified them.
/// Memory is one chunk, never the blob; the declared length is reserved
/// from the spool budget until the sink is committed, aborted or dropped.
pub struct S3PackSink {
    store: S3BlobStore,
    key: BlobKey,
    declared: u64,
    written: u64,
    /// `None` once failed, or lost to a cancelled write.
    spool: Option<Spool>,
    failed: bool,
    _reservation: Reservation,
}

impl fmt::Debug for S3PackSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3PackSink")
            .field("key", &self.key.to_hex())
            .field("declared", &self.declared)
            .field("written", &self.written)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl S3PackSink {
    /// The spool file's size: the upload's bytes are on disk, not in
    /// memory. For tests.
    #[doc(hidden)]
    #[must_use]
    pub fn spooled_bytes(&self) -> Option<u64> {
        let spool = self.spool.as_ref()?;
        spool.file.metadata().ok().map(|m| m.len())
    }

    fn fail(&mut self) {
        self.failed = true;
        self.spool = None;
    }
}

fn sink_gone() -> StoreError {
    StoreError::unavailable("upload spool lost to a cancelled write")
}

impl PackSink for S3PackSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        if self.failed {
            return Err(StoreError::Invalid("write after a failed write".into()));
        }
        let total = self.written.checked_add(chunk.len() as u64);
        let Some(total) = total.filter(|t| *t <= self.declared) else {
            self.fail();
            return Err(StoreError::Invalid("blob is longer than declared".into()));
        };
        if chunk.is_empty() {
            return Ok(());
        }
        let Some(mut spool) = self.spool.take() else {
            self.failed = true;
            return Err(sink_gone());
        };
        // If this future is dropped mid-write, the spool goes with the
        // blocking task, and later calls fail.
        let appended = on_pool(move || {
            let result = spool.append(&chunk);
            Ok((spool, result))
        })
        .await;
        match appended {
            Ok((spool, Ok(()))) => {
                self.spool = Some(spool);
                self.written = total;
                Ok(())
            }
            Ok((_, Err(e))) => {
                self.fail();
                Err(spool_error("writing", &e))
            }
            Err(e) => {
                self.fail();
                Err(e)
            }
        }
    }

    async fn commit(mut self) -> Result<CommitOutcome, StoreError> {
        if self.failed {
            return Err(StoreError::Invalid("commit after a failed write".into()));
        }
        if self.written != self.declared {
            return Err(StoreError::Invalid("blob length does not match".into()));
        }
        let spool = self.spool.take().ok_or_else(sink_gone)?;
        // Verify first: nothing is sent for bytes that do not match.
        if spool.blake3.finalize() != self.key.0 {
            return Err(StoreError::Invalid(
                "blob hash does not match its key".into(),
            ));
        }
        let sha256 = to_hex_bytes(&spool.sha256.finalize());
        // The reservation is released when `self` drops, after the PUT.
        self.store
            .put_verified(&self.key, Arc::new(spool.file), self.declared, &sha256)
            .await
    }

    /// Nothing was sent: dropping the spool discards the upload and its
    /// reservation.
    async fn abort(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_disk_or_quota_is_full() {
        for kind in [ErrorKind::StorageFull, ErrorKind::QuotaExceeded] {
            let e = io::Error::from(kind);
            assert!(matches!(spool_error("writing", &e), StoreError::Full));
        }
        let e = io::Error::from(ErrorKind::PermissionDenied);
        assert!(matches!(
            spool_error("writing", &e),
            StoreError::Unavailable(_)
        ));
        #[cfg(unix)]
        for errno in [libc::ENOSPC, libc::EDQUOT] {
            let e = io::Error::from_raw_os_error(errno);
            assert!(matches!(spool_error("writing", &e), StoreError::Full));
        }
    }
}
