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
    signer: String,
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
            signer: ticket.signer.clone(),
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

    fn remove_replaced_ticket(&self, ticket: &TicketMetadata) {
        match fs::symlink_metadata(&self.root) {
            Ok(meta) if !meta.file_type().is_dir() => {
                eprintln!("upload receipt cache cleanup: root is not a directory");
                return;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => {
                eprintln!("upload receipt cache cleanup: {err}");
                return;
            }
            Ok(_) => {}
        }
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => {
                eprintln!("upload receipt cache cleanup: {err}");
                return;
            }
        };
        let current = TicketRecord::from(ticket);
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    eprintln!("upload receipt cache cleanup: {err}");
                    continue;
                }
            };
            let is_dir = match entry.file_type() {
                Ok(kind) => kind.is_dir(),
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    eprintln!("upload receipt cache cleanup: {err}");
                    continue;
                }
            };
            if is_dir
                && entry.path() != self.ticket_dir(&ticket.ticket_id)
                && let Some(other) = Self::read_record::<TicketRecord>(&entry.path().join("ticket"))
                && other.audience == current.audience
                && other.repository == current.repository
                && other.signer == current.signer
                && other.head_ref == current.head_ref
                && other.pack_id == current.pack_id
            {
                if let Err(err) = fs::remove_dir_all(entry.path())
                    && err.kind() != io::ErrorKind::NotFound
                {
                    eprintln!("upload receipt cache cleanup: {err}");
                }
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // Accepts the owned error directly from map_err.
fn io_error(err: io::Error) -> TransportError {
    TransportError::RemoteError(format!("upload receipt cache: {err}"))
}

fn stale_tmp(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age >= Duration::from_hours(1))
}

impl PartReceiptStore for FilePartReceiptStore {
    fn load(&self, ticket: &TicketMetadata, plan: &PartPlan) -> TransportResult<Vec<StoredPart>> {
        self.remove_replaced_ticket(ticket);
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
                && record.receipt.len() <= 512
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
        self.remove_replaced_ticket(ticket);
        let dir = self.ticket_dir(&ticket.ticket_id);
        Self::ensure_dir(&dir).map_err(io_error)?;
        // Persist the new ticket directory entry before its metadata and
        // parts; a crash must not leave durable files under a lost name.
        File::open(&self.root)
            .and_then(|root| root.sync_all())
            .map_err(io_error)?;
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
        {
            let mut swept = swept
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !swept.insert(self.root.clone()) {
                return Ok(());
            }
        }
        let entries = match fs::symlink_metadata(&self.root) {
            Ok(meta) if meta.file_type().is_dir() => match fs::read_dir(&self.root) {
                Ok(entries) => entries,
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(err) => {
                    eprintln!("upload receipt cache cleanup: {err}");
                    return Ok(());
                }
            },
            Ok(_) => {
                eprintln!("upload receipt cache cleanup: root is not a directory");
                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                eprintln!("upload receipt cache cleanup: {err}");
                return Ok(());
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    eprintln!("upload receipt cache cleanup: {err}");
                    continue;
                }
            };
            let path = entry.path();
            let is_dir = match entry.file_type() {
                Ok(kind) => kind.is_dir(),
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    eprintln!("upload receipt cache cleanup: {err}");
                    continue;
                }
            };
            if is_dir {
                let meta_path = path.join("ticket");
                let remove = match Self::read_record::<TicketRecord>(&meta_path) {
                    // A newer writer may share this cache. Keep records whose
                    // format this version cannot judge.
                    Some(record) if record.version > VERSION => false,
                    Some(record) => record.version != VERSION || record.expires_unix_ms <= now_ms,
                    None => fs::metadata(&path)
                        .and_then(|meta| meta.modified())
                        .ok()
                        .and_then(|time| SystemTime::now().duration_since(time).ok())
                        .is_some_and(|age| age >= Duration::from_hours(168)),
                };
                if remove {
                    if let Err(err) = fs::remove_dir_all(&path)
                        && err.kind() != io::ErrorKind::NotFound
                    {
                        eprintln!("upload receipt cache cleanup: {err}");
                    }
                } else {
                    let files = match fs::read_dir(&path) {
                        Ok(files) => files,
                        Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                        Err(err) => {
                            eprintln!("upload receipt cache cleanup: {err}");
                            continue;
                        }
                    };
                    for file in files {
                        let file = match file {
                            Ok(file) => file,
                            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                            Err(err) => {
                                eprintln!("upload receipt cache cleanup: {err}");
                                continue;
                            }
                        };
                        if file.file_name().to_string_lossy().ends_with(".tmp")
                            && stale_tmp(&file.path())
                        {
                            if let Err(err) = fs::remove_file(file.path())
                                && err.kind() != io::ErrorKind::NotFound
                            {
                                eprintln!("upload receipt cache cleanup: {err}");
                            }
                        }
                    }
                }
            } else if path.extension().is_some_and(|ext| ext == "tmp") && stale_tmp(&path) {
                if let Err(err) = fs::remove_file(path)
                    && err.kind() != io::ErrorKind::NotFound
                {
                    eprintln!("upload receipt cache cleanup: {err}");
                }
            }
        }
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
            signer: "signer".into(),
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
        let restarted = FilePartReceiptStore::new(store.root.clone());
        assert_eq!(
            restarted.load(&meta, &plan).unwrap()[0].receipt,
            part.receipt
        );
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

        let torn = store.ticket_dir(&meta.ticket_id).join("1.part.tmp");
        fs::write(&torn, b"torn").unwrap();
        assert_eq!(store.load(&meta, &plan).unwrap().len(), 1);
        let mut changed = meta.clone();
        changed.pack_key = PackKey::new([8; 32]);
        assert!(store.load(&changed, &plan).unwrap().is_empty());
        File::open(&torn)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_hours(2)),
            )
            .unwrap();
        store.sweep(0).unwrap();
        assert!(!torn.exists());
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

    #[test]
    fn replacement_ticket_forgets_old_receipts_but_other_signer_is_independent() {
        let temp = tempfile::tempdir().unwrap();
        let store = FilePartReceiptStore::new(temp.path().join("upload-parts"));
        let first = ticket();
        let plan = PartPlan::new(first.bytes, first.part_size, 2).unwrap();
        let part = StoredPart {
            index: 0,
            len: MIN_PART_SIZE,
            receipt: vec![4],
            from_disk: false,
        };
        store.put(&first, &part).unwrap();
        let mut other_signer = first.clone();
        other_signer.ticket_id = [8; 32];
        other_signer.signer = "other".into();
        store.put(&other_signer, &part).unwrap();
        let mut replacement = first.clone();
        replacement.ticket_id = [9; 32];
        assert!(store.load(&replacement, &plan).unwrap().is_empty());
        assert!(!store.ticket_dir(&first.ticket_id).exists());
        assert!(store.ticket_dir(&other_signer.ticket_id).exists());
    }

    #[test]
    fn sweeping_does_not_remove_an_active_writer_temp_file() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(FilePartReceiptStore::new(temp.path().join("upload-parts")));
        let meta = ticket();
        let part = StoredPart {
            index: 0,
            len: MIN_PART_SIZE,
            receipt: vec![4],
            from_disk: false,
        };
        std::thread::scope(|scope| {
            let writer = store.clone();
            let meta = meta.clone();
            let part = part.clone();
            scope.spawn(move || {
                for _ in 0..20 {
                    writer.put(&meta, &part).unwrap();
                }
            });
            let sweeper = store.clone();
            scope.spawn(move || sweeper.sweep(0).unwrap());
        });
        let plan = PartPlan::new(meta.bytes, meta.part_size, 2).unwrap();
        assert_eq!(store.load(&meta, &plan).unwrap().len(), 1);
    }

    #[test]
    fn concurrent_sweeps_of_an_expired_ticket_are_both_successful() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(FilePartReceiptStore::new(temp.path().join("upload-parts")));
        let mut expired = ticket();
        expired.expires_unix_ms = 10;
        let part = StoredPart {
            index: 0,
            len: MIN_PART_SIZE,
            receipt: vec![4],
            from_disk: false,
        };
        store.put(&expired, &part).unwrap();
        let barrier = std::sync::Barrier::new(3);
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let store = store.clone();
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    store.sweep(10).unwrap();
                });
            }
            barrier.wait();
        });
        assert!(!store.ticket_dir(&expired.ticket_id).exists());
    }

    #[test]
    fn sweep_discards_old_unreadable_metadata_and_preserves_newer_format() {
        let temp = tempfile::tempdir().unwrap();
        let store = FilePartReceiptStore::new(temp.path().join("upload-parts"));
        let unreadable = store.ticket_dir(&[1; 32]);
        FilePartReceiptStore::ensure_dir(&unreadable).unwrap();
        fs::write(unreadable.join("ticket"), b"not JSON").unwrap();
        File::open(&unreadable)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(SystemTime::now() - Duration::from_hours(8 * 24)),
            )
            .unwrap();

        let mut newer = ticket();
        newer.ticket_id = [2; 32];
        newer.expires_unix_ms = 10;
        let part = StoredPart {
            index: 0,
            len: MIN_PART_SIZE,
            receipt: vec![4],
            from_disk: false,
        };
        store.put(&newer, &part).unwrap();
        let newer_path = store.ticket_dir(&newer.ticket_id).join("ticket");
        let mut record: TicketRecord = FilePartReceiptStore::read_record(&newer_path).unwrap();
        record.version = VERSION + 1;
        FilePartReceiptStore::write_record(&newer_path, &record).unwrap();

        store.sweep(10).unwrap();
        assert!(!unreadable.exists());
        assert!(newer_path.exists());
    }

    #[test]
    fn concurrent_sweep_and_replacement_preserve_new_receipts() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            std::sync::Arc::new(FilePartReceiptStore::new(temp.path().join("upload-parts")));
        let mut old = ticket();
        old.expires_unix_ms = 10;
        let part = StoredPart {
            index: 0,
            len: MIN_PART_SIZE,
            receipt: vec![4],
            from_disk: false,
        };
        store.put(&old, &part).unwrap();
        let mut replacement = old.clone();
        replacement.ticket_id = [8; 32];
        replacement.expires_unix_ms = i64::MAX;
        let barrier = std::sync::Barrier::new(3);
        std::thread::scope(|scope| {
            let sweeper = store.clone();
            let barrier_ref = &barrier;
            scope.spawn(move || {
                barrier_ref.wait();
                sweeper.sweep(10).unwrap();
            });
            let writer = store.clone();
            let barrier_ref = &barrier;
            let replacement_ref = &replacement;
            let part_ref = &part;
            scope.spawn(move || {
                barrier_ref.wait();
                writer.put(replacement_ref, part_ref).unwrap();
            });
            barrier.wait();
        });
        let plan = PartPlan::new(replacement.bytes, replacement.part_size, 2).unwrap();
        assert_eq!(store.load(&replacement, &plan).unwrap().len(), 1);
        assert!(!store.ticket_dir(&old.ticket_id).exists());
    }
}
