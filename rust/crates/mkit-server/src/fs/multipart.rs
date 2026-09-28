//! Durable multipart staging below `server-uploads/<ticket-id-hex>`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use mkit_core::hash::{hash, to_hex_bytes};
use mkit_core::upload_parts::{PartHasher, PartPlan, merge_to_root};
use mkit_transport_file::{create_dir_all_durably, sync_dir, temp_path};

use super::blob::{FsBlobStore, READ_BLOCK};
use super::io_error;
use crate::store::{
    BlobKey, BlobNamespace, BlobStore, CommitOutcome, MultipartBlobStore, PackSink, PartRef,
    PartSink, StoreError,
};

const UPLOADS_DIR: &str = "server-uploads";
const META: &str = "meta";
const META_MAGIC: &[u8; 5] = b"MKUP1";
const SESSION_AGE: Duration = Duration::from_hours(169);
static NEXT_SESSION: AtomicU64 = AtomicU64::new(0);

fn session_lock(
    store: &FsBlobStore,
    session: &[u8],
) -> Result<std::sync::Arc<tokio::sync::Mutex<()>>, StoreError> {
    let id: [u8; 32] = session.try_into().map_err(|_| StoreError::SessionGone)?;
    let mut locks = store
        .multipart_locks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if locks.len() >= 1024 {
        locks.retain(|_, weak| weak.strong_count() > 0);
    }
    if let Some(lock) = locks.get(&id).and_then(std::sync::Weak::upgrade) {
        return Ok(lock);
    }
    let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(id, std::sync::Arc::downgrade(&lock));
    Ok(lock)
}

fn uploads(root: &Path) -> PathBuf {
    root.join(UPLOADS_DIR)
}

fn session_dir(store: &FsBlobStore, session: &[u8]) -> Result<PathBuf, StoreError> {
    if session.len() != 32 {
        return Err(StoreError::SessionGone);
    }
    Ok(uploads(&store.root).join(to_hex_bytes(session)))
}

fn session_meta(key: BlobKey, len: u64, part_size: u64) -> Result<Vec<u8>, StoreError> {
    if key.namespace() != BlobNamespace::Pack {
        return Err(StoreError::Invalid("multipart requires a pack key".into()));
    }
    let mut value = Vec::with_capacity(53);
    value.extend_from_slice(META_MAGIC);
    value.extend_from_slice(key.hash());
    value.extend_from_slice(&len.to_be_bytes());
    value.extend_from_slice(&part_size.to_be_bytes());
    Ok(value)
}

fn verify_session(dir: &Path, expected: &[u8]) -> Result<(), StoreError> {
    match fs::read(dir.join(META)) {
        Ok(actual) if actual == expected => Ok(()),
        Ok(_) => Err(StoreError::SessionGone),
        Err(e) if e.kind() == ErrorKind::NotFound => Err(StoreError::SessionGone),
        Err(e) => Err(io_error(e)),
    }
}

async fn create_session(
    store: &FsBlobStore,
    key: BlobKey,
    len: u64,
    part_size: u64,
    session: &[u8],
) -> Result<Vec<u8>, StoreError> {
    PartPlan::new(len, part_size, u32::MAX)
        .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
    let expected = session_meta(key, len, part_size)?;
    let dir = session_dir(store, session)?;
    let parent = uploads(&store.root);
    let lock = session_lock(store, session)?;
    let _guard = lock.lock().await;
    create_dir_all_durably(&parent).map_err(io_error)?;
    match fs::symlink_metadata(&dir) {
        Ok(info) if !info.is_dir() => return Err(StoreError::SessionGone),
        Ok(_) => match fs::read(dir.join(META)) {
            Ok(actual) if actual == expected => return Ok(session.to_vec()),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(e)),
    }
    if dir.exists() {
        // An attempt that never issued a ticket may leave an incomplete or
        // mismatched directory, including after a part-size configuration
        // change. This open reservation replaces that orphan.
        fs::remove_dir_all(&dir).map_err(io_error)?;
        sync_dir(&parent).map_err(io_error)?;
    }
    fs::create_dir(&dir).map_err(io_error)?;
    let dest = dir.join(META);
    let tmp = temp_path(&dest).map_err(io_error)?;
    let result = (|| {
        sync_dir(&parent)?;
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(&expected)?;
        file.sync_all()?;
        fs::rename(&tmp, &dest)?;
        sync_dir(&dir)?;
        Ok::<(), io::Error>(())
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_dir_all(&dir);
        let _ = sync_dir(&parent);
        return Err(io_error(e));
    }
    Ok(session.to_vec())
}

fn fresh_session(key: BlobKey) -> [u8; 32] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut material = Vec::with_capacity(64);
    material.extend_from_slice(key.hash());
    material.extend_from_slice(&now.as_nanos().to_be_bytes());
    material.extend_from_slice(&std::process::id().to_be_bytes());
    material.extend_from_slice(&NEXT_SESSION.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    hash(&material)
}

fn part_name(index: u32, cv: &[u8; 32]) -> String {
    format!("{index}-{}", to_hex_bytes(cv))
}

fn current_path(dir: &Path, index: u32) -> PathBuf {
    dir.join(format!("{index}.current"))
}

fn publish_current(dir: &Path, index: u32, name: &str) -> Result<(), StoreError> {
    let dest = current_path(dir, index);
    let tmp = temp_path(&dest).map_err(io_error)?;
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(name.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, &dest)?;
        sync_dir(dir)?;
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(io_error)
}

fn is_part_name(name: &str, index: u32) -> bool {
    name.strip_prefix(&format!("{index}-")).is_some_and(|cv| {
        cv.len() == 64
            && cv
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// A staged file and incremental subtree hasher. Dropping it removes only
/// this attempt's temp file; the prior verified part remains intact.
pub struct FsPartSink {
    session_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
    file: Option<File>,
    tmp: PathBuf,
    dir: PathBuf,
    name: String,
    meta: Vec<u8>,
    index: u32,
    expected_cv: [u8; 32],
    hasher: Option<PartHasher>,
}

impl std::fmt::Debug for FsPartSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsPartSink")
            .field("tmp", &self.tmp)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl Drop for FsPartSink {
    fn drop(&mut self) {
        self.file = None;
        let _ = fs::remove_file(&self.tmp);
    }
}

impl PartSink for FsPartSink {
    async fn write(&mut self, chunk: Bytes) -> Result<(), StoreError> {
        if chunk.is_empty() {
            return Err(StoreError::Invalid("empty part chunk".into()));
        }
        let hasher = self.hasher.as_mut().ok_or(StoreError::SessionGone)?;
        hasher
            .update(&chunk)
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        if let Err(e) = self
            .file
            .as_mut()
            .ok_or(StoreError::SessionGone)?
            .write_all(&chunk)
        {
            self.file = None;
            return Err(io_error(e));
        }
        Ok(())
    }

    async fn commit(mut self) -> Result<Vec<u8>, StoreError> {
        let cv = self
            .hasher
            .take()
            .ok_or(StoreError::SessionGone)?
            .finalize()
            .map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        if cv != self.expected_cv {
            return Err(StoreError::PartSubtreeMismatch);
        }
        let file = self.file.take().ok_or(StoreError::SessionGone)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        let _guard = self.session_lock.lock().await;
        verify_session(&self.dir, &self.meta)?;
        // The new file is durable before the pointer changes. A crash before
        // that change leaves the old receipt valid; a crash after it leaves
        // the new receipt valid, even if old files remain for cleanup.
        fs::rename(&self.tmp, self.dir.join(&self.name)).map_err(io_error)?;
        sync_dir(&self.dir).map_err(io_error)?;
        publish_current(&self.dir, self.index, &self.name)?;
        for entry in fs::read_dir(&self.dir).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if entry.file_type().map_err(io_error)?.is_file()
                && entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name != self.name && is_part_name(name, self.index))
                && let Err(e) = fs::remove_file(entry.path())
            {
                tracing::warn!(error = %e, "old multipart part cleanup failed");
            }
        }
        sync_dir(&self.dir).map_err(io_error)?;
        Ok(self.name.as_bytes().to_vec())
    }

    async fn abort(self) {}
}

impl MultipartBlobStore for FsBlobStore {
    type PartSink = FsPartSink;
    const MAX_PARTS: u32 = u32::MAX;

    fn supports_multipart(&self) -> bool {
        true
    }

    async fn begin_multipart(
        &self,
        key: BlobKey,
        len: u64,
        part_size: u64,
    ) -> Result<Vec<u8>, StoreError> {
        for _ in 0..8 {
            let session = fresh_session(key);
            if !session_dir(self, &session)?.exists() {
                return create_session(self, key, len, part_size, &session).await;
            }
        }
        Err(StoreError::unavailable(io::Error::other(
            "could not allocate a multipart session",
        )))
    }

    async fn begin_multipart_for_ticket(
        &self,
        key: BlobKey,
        len: u64,
        part_size: u64,
        ticket_id: [u8; 32],
    ) -> Result<Vec<u8>, StoreError> {
        create_session(self, key, len, part_size, &ticket_id).await
    }

    async fn begin_part(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        index: u32,
        expected_cv: [u8; 32],
    ) -> Result<FsPartSink, StoreError> {
        let meta = session_meta(key, plan.total(), plan.part_size())?;
        let dir = session_dir(self, session)?;
        let hasher =
            PartHasher::new(plan, index).map_err(|e| StoreError::Invalid(e.to_string().into()))?;
        let name = part_name(index, &expected_cv);
        let session_lock = session_lock(self, session)?;
        let _guard = session_lock.lock().await;
        verify_session(&dir, &meta)?;
        let tmp = temp_path(&dir.join(&name)).map_err(io_error)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(io_error)?;
        Ok(FsPartSink {
            session_lock: session_lock.clone(),
            file: Some(file),
            tmp,
            dir,
            name,
            meta,
            index,
            expected_cv,
            hasher: Some(hasher),
        })
    }

    async fn complete(
        &self,
        key: BlobKey,
        session: &[u8],
        plan: &PartPlan,
        parts: &[PartRef],
    ) -> Result<CommitOutcome, StoreError> {
        let meta = session_meta(key, plan.total(), plan.part_size())?;
        let dir = session_dir(self, session)?;
        let session_lock = session_lock(self, session)?;
        let _guard = session_lock.lock().await;
        verify_session(&dir, &meta)?;
        if parts.len() != plan.count() as usize {
            return Err(StoreError::Invalid("wrong number of parts".into()));
        }
        let mut cvs = Vec::with_capacity(parts.len());
        for (position, part) in parts.iter().enumerate() {
            let index = u32::try_from(position)
                .map_err(|_| StoreError::Invalid("part index overflow".into()))?;
            let prefix = format!("{index}-");
            let tag = std::str::from_utf8(&part.tag)
                .map_err(|_| StoreError::Invalid("invalid part tag".into()))?;
            let cv_hex = tag
                .strip_prefix(&prefix)
                .filter(|_| is_part_name(tag, index))
                .ok_or_else(|| StoreError::Invalid("invalid part tag".into()))?;
            let cv = mkit_core::hash::from_hex(cv_hex)
                .map_err(|_| StoreError::Invalid("invalid part tag".into()))?;
            if part.index != index
                || part.len
                    != plan
                        .expected_len(index)
                        .map_err(|e| StoreError::Invalid(e.to_string().into()))?
            {
                return Err(StoreError::Invalid("part geometry mismatch".into()));
            }
            cvs.push(cv);
        }
        if merge_to_root(plan, &cvs).map_err(|e| StoreError::Invalid(e.to_string().into()))?
            != *key.hash()
        {
            return Err(StoreError::Invalid("merged part root mismatch".into()));
        }
        let mut sink = self.begin(key, plan.total()).await?;
        let mut buf = BytesMut::with_capacity(READ_BLOCK);
        for part in parts {
            let tag = std::str::from_utf8(&part.tag)
                .map_err(|_| StoreError::Invalid("invalid part tag".into()))?;
            let active = match fs::read(current_path(&dir, part.index)) {
                Ok(active) => active,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    verify_session(&dir, &meta)?;
                    return Err(StoreError::Invalid("part tag is not current".into()));
                }
                Err(e) => return Err(io_error(e)),
            };
            if active != part.tag {
                return Err(StoreError::Invalid("part tag is not current".into()));
            }
            let mut file = match File::open(dir.join(tag)) {
                Ok(file) => file,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    verify_session(&dir, &meta)?;
                    // The session exists, but this receipt's tag no longer
                    // names its selected part (for example after replacement).
                    return Err(StoreError::Invalid("part tag has no stored file".into()));
                }
                Err(e) => return Err(io_error(e)),
            };
            if file.metadata().map_err(io_error)?.len() != part.len {
                return Err(StoreError::Invalid("stored part length mismatch".into()));
            }
            let mut remaining = part.len;
            while remaining > 0 {
                let n = usize::try_from(remaining).map_or(READ_BLOCK, |n| n.min(READ_BLOCK));
                buf.resize(n, 0);
                file.read_exact(&mut buf[..n]).map_err(io_error)?;
                sink.write(buf.split().freeze()).await?;
                remaining -= n as u64;
            }
        }
        let outcome = sink.commit().await?;
        // The pack is durable. Cleanup failure is harmless; startup sweep
        // reclaims the directory after the ticket lifetime.
        if let Err(e) = fs::remove_dir_all(&dir).and_then(|()| sync_dir(&uploads(&self.root))) {
            tracing::warn!(error = %e, "completed multipart session cleanup failed");
        }
        Ok(outcome)
    }

    async fn abort(&self, key: BlobKey, session: &[u8]) -> Result<(), StoreError> {
        let dir = session_dir(self, session)?;
        let session_lock = session_lock(self, session)?;
        let _guard = session_lock.lock().await;
        let meta = match fs::read(dir.join(META)) {
            Ok(meta) => meta,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io_error(e)),
        };
        if meta.get(5..37) != Some(key.hash().as_slice()) {
            return Ok(());
        }
        fs::remove_dir_all(&dir).map_err(io_error)?;
        sync_dir(&uploads(&self.root)).map_err(io_error)
    }
}

pub(super) fn sweep_sessions(root: &Path, now: SystemTime) -> io::Result<usize> {
    let parent = uploads(root);
    let entries = match fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0;
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.len() != 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        // The immutable metadata file records session creation. Directory
        // mtime changes as parts arrive, but cannot extend a ticket's life.
        let created = fs::symlink_metadata(entry.path().join(META))
            .ok()
            .filter(fs::Metadata::is_file)
            .unwrap_or(meta);
        if created
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_none_or(|age| age < SESSION_AGE)
        {
            continue;
        }
        if fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        sync_dir(&parent)?;
    }
    Ok(removed)
}
