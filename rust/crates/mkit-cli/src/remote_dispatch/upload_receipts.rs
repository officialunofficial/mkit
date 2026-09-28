//! Atomic, deletable receipt cache under the repository common directory.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use mkit_core::hash::to_hex;
use mkit_core::protocol::{TransportError, TransportResult};
use mkit_core::upload_parts::PartPlan;
use mkit_transport_connect::{PartReceiptStore, StoredPart, TicketMetadata};
use serde::{Deserialize, Serialize};
use tempfile::Builder;

const VERSION: u8 = 1;
const MAX_RECORD_BYTES: u64 = 32 * 1024;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct TicketRecord {
    version: u8,
    ticket_id: String,
    audience: String,
    repository: String,
    head_ref: String,
    pack_id: String,
    bytes: u64,
    part_size: u64,
    expires_unix_ms: i64,
}

impl From<&TicketMetadata> for TicketRecord {
    fn from(ticket: &TicketMetadata) -> Self {
        Self {
            version: VERSION,
            ticket_id: to_hex(&ticket.ticket_id),
            audience: ticket.audience.clone(),
            repository: ticket.repository.clone(),
            head_ref: ticket.head_ref.clone(),
            pack_id: ticket.pack_key.to_hex(),
            bytes: ticket.bytes,
            part_size: ticket.part_size,
            expires_unix_ms: ticket.expires_unix_ms,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PartRecord {
    version: u8,
    index: u32,
    len: u64,
    receipt: Vec<u8>,
}

/// One repository's file-backed upload receipt cache.
pub(super) struct FilePartReceiptStore {
    root: PathBuf,
}

impl FilePartReceiptStore {
    pub(super) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn ticket_dir(&self, id: &[u8; 32]) -> PathBuf {
        self.root.join(to_hex(id))
    }

    fn ensure_dir(path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)?;
        if !fs::symlink_metadata(path)?.file_type().is_dir() {
            return Err(io::Error::other("upload receipt path is not a directory"));
        }
        Ok(())
    }

    fn read_record<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
        if !fs::symlink_metadata(path).ok()?.file_type().is_file() {
            return None;
        }
        let mut bytes = Vec::new();
        File::open(path)
            .ok()?
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return None;
        }
        serde_json::from_slice(&bytes).ok()
    }

    fn write_record<T: Serialize>(path: &Path, record: &T) -> TransportResult<()> {
        let bytes = serde_json::to_vec(record).map_err(|_| TransportError::ProtocolError)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(TransportError::ProtocolError);
        }
        let parent = path.parent().ok_or(TransportError::ProtocolError)?;
        Self::ensure_dir(parent).map_err(io_error)?;
        let mut tmp = Builder::new()
            .prefix("receipt-")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(io_error)?;
        tmp.as_file_mut().write_all(&bytes).map_err(io_error)?;
        tmp.as_file_mut().sync_all().map_err(io_error)?;
        tmp.persist(path).map_err(|err| io_error(err.error))?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(io_error)
    }

    fn remove_stale_same_pack(&self, ticket: &TicketMetadata) -> TransportResult<()> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(());
        };
        let current = TicketRecord::from(ticket);
        for entry in entries {
            let entry = entry.map_err(io_error)?;
            if entry.file_type().map_err(io_error)?.is_dir()
                && entry.path() != self.ticket_dir(&ticket.ticket_id)
                && let Some(other) = Self::read_record::<TicketRecord>(&entry.path().join("ticket"))
                && other.audience == current.audience
                && other.repository == current.repository
                && other.head_ref == current.head_ref
                && other.pack_id == current.pack_id
            {
                fs::remove_dir_all(entry.path()).map_err(io_error)?;
            }
        }
        Ok(())
    }
}

fn io_error(err: io::Error) -> TransportError {
    TransportError::RemoteError(format!("upload receipt cache: {err}"))
}

impl PartReceiptStore for FilePartReceiptStore {
    fn load(&self, ticket: &TicketMetadata, plan: &PartPlan) -> TransportResult<Vec<StoredPart>> {
        let dir = self.ticket_dir(&ticket.ticket_id);
        if Self::read_record::<TicketRecord>(&dir.join("ticket")) != Some(ticket.into()) {
            return Ok(Vec::new());
        }
        let mut parts = Vec::new();
        for index in 0..plan.count() {
            let Some(record) = Self::read_record::<PartRecord>(&dir.join(format!("{index}.part")))
            else {
                continue;
            };
            if record.version == VERSION
                && record.index == index
                && plan.expected_len(index).is_ok_and(|len| len == record.len)
                && !record.receipt.is_empty()
            {
                parts.push(StoredPart {
                    index,
                    len: record.len,
                    receipt: record.receipt,
                    from_disk: true,
                });
            }
        }
        Ok(parts)
    }

    fn put(&self, ticket: &TicketMetadata, part: &StoredPart) -> TransportResult<()> {
        if part.receipt.is_empty() {
            return Err(TransportError::ProtocolError);
        }
        Self::ensure_dir(&self.root).map_err(io_error)?;
        self.remove_stale_same_pack(ticket)?;
        let dir = self.ticket_dir(&ticket.ticket_id);
        Self::ensure_dir(&dir).map_err(io_error)?;
        Self::write_record(&dir.join("ticket"), &TicketRecord::from(ticket))?;
        Self::write_record(
            &dir.join(format!("{}.part", part.index)),
            &PartRecord {
                version: VERSION,
                index: part.index,
                len: part.len,
                receipt: part.receipt.clone(),
            },
        )
    }

    fn forget(&self, ticket_id: &[u8; 32]) -> TransportResult<()> {
        match fs::remove_dir_all(self.ticket_dir(ticket_id)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(io_error(err)),
        }
    }

    fn sweep(&self, now_ms: i64) -> TransportResult<()> {
        static SWEPT: OnceLock<Mutex<std::collections::HashSet<PathBuf>>> = OnceLock::new();
        let swept = SWEPT.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
        let mut swept = swept.lock().map_err(|_| TransportError::ProtocolError)?;
        if swept.contains(&self.root) {
            return Ok(());
        }
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(());
        };
        for entry in entries {
            let entry = entry.map_err(io_error)?;
            let path = entry.path();
            if entry.file_type().map_err(io_error)?.is_dir() {
                let meta_path = path.join("ticket");
                let remove = match Self::read_record::<TicketRecord>(&meta_path) {
                    Some(record) => record.version != VERSION || record.expires_unix_ms <= now_ms,
                    None => fs::metadata(&path)
                        .and_then(|meta| meta.modified())
                        .ok()
                        .and_then(|time| SystemTime::now().duration_since(time).ok())
                        .is_some_and(|age| age >= Duration::from_secs(7 * 24 * 60 * 60)),
                };
                if remove {
                    fs::remove_dir_all(&path).map_err(io_error)?;
                } else if let Ok(files) = fs::read_dir(&path) {
                    for file in files {
                        let file = file.map_err(io_error)?;
                        if file.file_name().to_string_lossy().ends_with(".tmp") {
                            fs::remove_file(file.path()).map_err(io_error)?;
                        }
                    }
                }
            } else if path.extension().is_some_and(|ext| ext == "tmp") {
                fs::remove_file(path).map_err(io_error)?;
            }
        }
        swept.insert(self.root.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::protocol::PackKey;
    use mkit_core::upload_parts::MIN_PART_SIZE;

    fn ticket() -> TicketMetadata {
        TicketMetadata {
            ticket_id: [7; 32],
            audience: "https://example.test".into(),
            repository: "repo".into(),
            head_ref: "refs/heads/main".into(),
            pack_key: PackKey::new([9; 32]),
            bytes: MIN_PART_SIZE + 1,
            part_size: MIN_PART_SIZE,
            expires_unix_ms: i64::MAX,
        }
    }

    #[test]
    fn persists_receipts_atomically_and_ignores_bad_records() {
        let temp = tempfile::tempdir().unwrap();
        let store = FilePartReceiptStore::new(temp.path().join("upload-parts"));
        let meta = ticket();
        let plan = PartPlan::new(meta.bytes, meta.part_size, 2).unwrap();
        let part = StoredPart {
            index: 0,
            len: MIN_PART_SIZE,
            receipt: vec![1, 2, 3],
            from_disk: false,
        };
        store.put(&meta, &part).unwrap();
        let loaded = store.load(&meta, &plan).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].from_disk);
        assert!(store.ticket_dir(&meta.ticket_id).join("ticket").exists());
        assert!(
            !fs::read_dir(store.ticket_dir(&meta.ticket_id))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|ext| ext == "tmp"))
        );

        fs::write(
            store.ticket_dir(&meta.ticket_id).join("1.part.tmp"),
            b"torn",
        )
        .unwrap();
        assert_eq!(store.load(&meta, &plan).unwrap().len(), 1);
        let mut changed = meta.clone();
        changed.pack_key = PackKey::new([8; 32]);
        assert!(store.load(&changed, &plan).unwrap().is_empty());
        store.sweep(0).unwrap();
        assert!(
            !store
                .ticket_dir(&meta.ticket_id)
                .join("1.part.tmp")
                .exists()
        );
    }

    #[test]
    fn expired_ticket_and_concurrent_writers() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(FilePartReceiptStore::new(temp.path().join("upload-parts")));
        let mut meta = ticket();
        meta.expires_unix_ms = 10;
        let part = StoredPart {
            index: 0,
            len: MIN_PART_SIZE,
            receipt: vec![4],
            from_disk: false,
        };
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let store = std::sync::Arc::clone(&store);
                let meta = meta.clone();
                let part = part.clone();
                scope.spawn(move || store.put(&meta, &part).unwrap());
            }
        });
        let plan = PartPlan::new(meta.bytes, meta.part_size, 2).unwrap();
        assert_eq!(store.load(&meta, &plan).unwrap().len(), 1);
        store.sweep(10).unwrap();
        assert!(store.load(&meta, &plan).unwrap().is_empty());
    }
}
