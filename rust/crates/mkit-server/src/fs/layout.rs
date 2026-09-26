//! `FsLayoutStore`: the ref class of one repo as files, delegating to
//! `FileTransport`.

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mkit_core::hash::{Hash, hash, to_hex, to_hex_bytes};
use mkit_core::protocol::RefWriteCondition;
use mkit_transport_file::{FileTransport, LockedRefs, RefFileError};

use super::{io_error, ref_file_error, unavailable};
use crate::refs;
use crate::repo::{RepoId, RepoName};
use crate::rt::{Clock, SystemClock};
use crate::store::{
    Batch, BatchOutcome, Cursor, Key, NamespaceStore, Partition, PartitionStats, Precondition,
    ScanPage, StoreCapabilities, StoreError, Value, Write, keys,
};

/// The directory `FileTransport` keeps refs in, as a ref-name prefix.
const REFS_PREFIX: &str = "refs/";

/// Where the ref-class rows whose name is not a `refs/` ref name live,
/// relative to the root: out of reach of every ref name (a ref name
/// component never starts with `.`) and of `FileTransport::list_refs`.
const ROWS_DIR: &str = ".mkit/server/rows";

/// Where one key lives.
enum Slot<'k> {
    /// A valid ref name under `refs/`: `FileTransport`'s ref file
    /// `<root>/<name>`, holding a 32-byte id as `<64-hex>\n`.
    Ref(&'k str),
    /// Any other name bytes the ref class allows (`store::keys`): a row
    /// file in `ROWS_DIR` (see `row_file_name`), holding
    /// `be16(len(name)) ‖ name ‖ value`.
    Row(&'k [u8]),
}

/// A [`NamespaceStore`] holding the ref class (`r 00 <repo> 00 <name>`) of
/// one repo, in one partition, as files under the served root. Its
/// capabilities are [`StoreCapabilities::refs_only`]: one key per batch,
/// no layout-version row (the `.mkit` on-disk format is layout version 1).
///
/// A ref (a `refs/` name) is exactly `FileTransport`'s ref file: reads are
/// [`FileTransport`]'s strict reads, and every write is its CAS (`Missing`
/// for an `Absent` guard, `Match` for an `Equals` guard, `Any` otherwise)
/// and its atomic write, under its ref lock (`<root>/.mkit/refs/.lock`), so
/// local `mkit` commands, `mkit+file://` remotes and this store see the
/// same files and serialize on the same lock. A ref's value is its 32-byte
/// id. A ref file that does not decode is [`StoreError::Corrupt`] on a
/// read or a precondition, never absent; a scan skips it with a warning,
/// like a ref file whose name is over [`refs::MAX_REF_NAME_BYTES`] (written
/// before SPEC-REFS §3 capped names), as `FileTransport::list_refs` skips
/// both. A ref whose file would clash with
/// another ref's directory, or the reverse, is [`StoreError::Invalid`]; a
/// delete removes the directories it leaves empty.
///
/// The ref class also allows names that are not `refs/` ref names, with
/// any value. The pipeline never writes one; they live in row files under
/// `.mkit/server/rows/`, written under the same lock and invisible to the
/// CLI and `FileTransport` (so a name like `packs/<hex>` can never
/// overwrite a pack).
///
/// `apply` takes the ref lock, reads the store clock (for a
/// [`Precondition::NotAfter`]), checks every precondition and writes, all
/// in one synchronous step (normative rules 4 and 8). Reads take no lock:
/// every write is one atomic rename. A full disk or quota is
/// [`StoreError::Full`], except for a delete-only batch (rule 7).
///
/// TODO(M0-13): a process that crashes mid-write leaves its temp file
/// (`.<file>.tmp.<pid>.<seq>`, next to the ref or row file) behind;
/// nothing sweeps them yet. Scans skip them.
///
/// It is the permanent metadata store of the server-free ssh path
/// (reconciliation R-13), with `SinglePartition` routing.
pub struct FsLayoutStore {
    tx: FileTransport,
    partition: Partition,
    repo: RepoName,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for FsLayoutStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FsLayoutStore")
            .field("root", &self.tx.root())
            .field("partition", &self.partition)
            .field("repo", &self.repo)
            .finish_non_exhaustive()
    }
}

impl FsLayoutStore {
    /// `repo`'s refs, served from `root`, in the partition `SinglePartition`
    /// routes them to (`Partition::Namespace(repo.namespace)`).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, repo: &RepoId) -> Self {
        let partition = Partition::Namespace(repo.namespace.clone());
        Self::in_partition(root, partition, repo.name.clone())
    }

    /// `repo`'s refs in `partition`, served from `root`: for a deployment
    /// that maps each partition to its own directory. Any other partition
    /// or repo is [`StoreError::Unsupported`].
    #[must_use]
    pub fn in_partition(root: impl Into<PathBuf>, partition: Partition, repo: RepoName) -> Self {
        Self {
            tx: FileTransport::new(root),
            partition,
            repo,
            clock: Arc::new(SystemClock),
        }
    }

    /// Use `clock` for [`Precondition::NotAfter`] instead of the host
    /// clock.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// The served root.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.tx.root()
    }

    fn check_partition(&self, p: &Partition) -> Result<(), StoreError> {
        if *p == self.partition {
            Ok(())
        } else {
            Err(StoreError::Unsupported(
                "this store holds a single partition".into(),
            ))
        }
    }

    /// Where `key` lives, if this store can hold it.
    fn slot<'k>(&self, key: &'k Key) -> Result<Slot<'k>, StoreError> {
        let Some(rest) = key.as_bytes().strip_prefix(b"r\0") else {
            return Err(StoreError::Unsupported(
                "this store holds only ref keys".into(),
            ));
        };
        let name = rest
            .strip_prefix(self.repo.as_str().as_bytes())
            .and_then(|r| r.strip_prefix(b"\0"))
            .ok_or_else(|| StoreError::Unsupported("this store holds one repo's refs".into()))?;
        Ok(match core::str::from_utf8(name) {
            Ok(name) if is_ref_name(name) => Slot::Ref(name),
            _ => Slot::Row(name),
        })
    }

    /// The value at `key`.
    fn read(&self, key: &Key) -> Result<Option<Value>, StoreError> {
        match self.slot(key)? {
            Slot::Ref(name) => {
                // Strict: a ref file that does not decode is `Corrupt`,
                // never absent, so no precondition passes over it.
                let id = self.tx.read_ref_strict(name).map_err(ref_file_error)?;
                Ok(id.map(|id| Value::new(id.to_vec())))
            }
            Slot::Row(name) => {
                let path = self.tx.server_path(&row_path(name));
                match fs::read(path.map_err(ref_file_error)?) {
                    Ok(bytes) => {
                        let (stored, value) = decode_row(&bytes)?;
                        if stored != name {
                            return Err(StoreError::Corrupt("row file holds another key".into()));
                        }
                        Ok(Some(value))
                    }
                    Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(io_error(e)),
                }
            }
        }
    }

    /// Every row whose key `keep` accepts, unordered.
    fn rows(&self, keep: impl Fn(&Key) -> bool) -> Result<Vec<(Key, Value)>, StoreError> {
        let mut rows = Vec::new();
        // Listing `refs/` (not the whole root) never reads a pack. Unlike
        // `read`, a listing skips a file it cannot serve, loudly, as
        // `FileTransport::list_refs` (today's `mkit serve`) skips it: one
        // stray file must not fail every listing of its directory.
        let listed = self.tx.list_ref_files(REFS_PREFIX);
        for (name, id) in listed.map_err(ref_file_error)? {
            let key = keys::ref_key(&self.repo, &name);
            if !keep(&key) {
                continue;
            }
            if name.len() > refs::MAX_REF_NAME_BYTES {
                // Written before SPEC-REFS §3 capped ref names.
                tracing::warn!(
                    len = name.len(),
                    max = refs::MAX_REF_NAME_BYTES,
                    "skipping a ref file whose name is over the ref-name limit"
                );
                continue;
            }
            match id {
                Some(id) if is_ref_name(&name) => rows.push((key, Value::new(id.to_vec()))),
                Some(_) => {}
                None => tracing::warn!(file = %name, "skipping a ref file that holds no ref id"),
            }
        }
        let rows_dir = self.tx.server_path(Path::new(ROWS_DIR));
        let dir = match fs::read_dir(rows_dir.map_err(ref_file_error)?) {
            Ok(dir) => dir,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(rows),
            Err(e) => return Err(io_error(e)),
        };
        for entry in dir {
            let entry = entry.map_err(io_error)?;
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if file_name.starts_with('.') {
                continue; // an in-flight or abandoned temp file
            }
            // A short name is in the file name: skip rows out of range
            // without reading them.
            if let Some(hex) = file_name.strip_prefix(SHORT_ROW) {
                let name = from_hex(hex).ok_or_else(|| corrupt_row_name(&file_name))?;
                if !keep(&self.key(&name)) {
                    continue;
                }
            }
            let bytes = fs::read(entry.path()).map_err(io_error)?;
            let (name, value) = decode_row(&bytes)?;
            if row_file_name(name) != file_name {
                return Err(corrupt_row_name(&file_name));
            }
            let key = self.key(name);
            if keep(&key) {
                rows.push((key, value));
            }
        }
        Ok(rows)
    }

    /// `r 00 <repo> 00 <name>` for any name bytes.
    fn key(&self, name: &[u8]) -> Key {
        let repo = self.repo.as_str().as_bytes();
        Key::new([b"r\0", repo, b"\0", name].concat())
    }

    /// The locked step of [`NamespaceStore::apply`]: read the clock, check
    /// the preconditions in order, then write. [`Batch::validate`] allowed
    /// at most one write and at most one key precondition, on its key.
    fn check_and_write(
        &self,
        refs: &LockedRefs<'_>,
        batch: &Batch,
    ) -> Result<BatchOutcome, StoreError> {
        // Rule 8: the store's clock, read once, under the lock. A reading
        // before the epoch fails every deadline (fail closed).
        let now = batch
            .preconditions
            .iter()
            .any(|pre| matches!(pre, Precondition::NotAfter(_)))
            .then(|| u64::try_from(self.clock.now_ms()).unwrap_or(u64::MAX));
        // The guard FileTransport re-checks on a ref write, and the index
        // of the key precondition it stands for.
        let mut guard = (0, RefWriteCondition::Any);
        for (index, pre) in batch.preconditions.iter().enumerate() {
            let (holds, observed) = match pre {
                Precondition::NotAfter(deadline) => {
                    let backend_now = now.unwrap_or(u64::MAX);
                    if backend_now > *deadline {
                        return Ok(BatchOutcome::DeadlinePassed { backend_now });
                    }
                    continue;
                }
                Precondition::Absent(key) => {
                    guard = (index, RefWriteCondition::Missing);
                    let current = self.read(key)?;
                    (current.is_none(), current)
                }
                Precondition::Present(key) => (self.read(key)?.is_some(), None),
                Precondition::Equals(key, want) => {
                    if let Ok(id) = Hash::try_from(want.as_bytes()) {
                        guard = (index, RefWriteCondition::Match(id));
                    }
                    let current = self.read(key)?;
                    (current.as_ref() == Some(want), current)
                }
            };
            if !holds {
                return Ok(BatchOutcome::PreconditionFailed { index, observed });
            }
        }
        for write in &batch.writes {
            match write {
                Write::Put(key, value) => match self.slot(key)? {
                    Slot::Ref(name) => {
                        let id = ref_id(value)?;
                        match refs.update_ref(name, guard.1, &id) {
                            Ok(()) => {}
                            // FileTransport's own re-check under the same
                            // lock failed (unreachable unless a writer
                            // bypassed the lock): report what a read sees,
                            // as `mkit serve` does on a conflict.
                            Err(RefFileError::Conflict) => {
                                return Ok(BatchOutcome::PreconditionFailed {
                                    index: guard.0,
                                    observed: self.read(key)?,
                                });
                            }
                            Err(e) => return Err(ref_file_error(e)),
                        }
                    }
                    Slot::Row(name) => refs
                        .write_file(&row_path(name), &encode_row(name, value))
                        .map_err(ref_file_error)?,
                },
                Write::Delete(key) => {
                    match self.slot(key)? {
                        Slot::Ref(name) => refs.delete_ref(name),
                        Slot::Row(name) => refs.remove_file(&row_path(name)),
                    }
                    .map_err(ref_file_error)?;
                }
            }
        }
        Ok(BatchOutcome::Committed)
    }
}

/// Whether `name` is a ref this store keeps as a `FileTransport` ref file.
fn is_ref_name(name: &str) -> bool {
    name.starts_with(REFS_PREFIX) && refs::validate_ref_name(name)
}

/// A ref's value: its 32-byte id.
fn ref_id(value: &Value) -> Result<Hash, StoreError> {
    Hash::try_from(value.as_bytes())
        .map_err(|_| StoreError::Invalid("a ref's value is its 32-byte id".into()))
}

/// The row file of `name`, relative to the root.
fn row_path(name: &[u8]) -> PathBuf {
    Path::new(ROWS_DIR).join(row_file_name(name))
}

/// A row file named after its name: `n<hex(name)>`, for names up to
/// [`MAX_SHORT_ROW`] bytes (a scan decodes the key from the file name and
/// reads only the rows in range).
const SHORT_ROW: &str = "n";
/// A row file named after its name's hash: `h<hex(BLAKE3(name))>`, for
/// longer names (a file name holds at most 255 bytes).
const HASHED_ROW: &str = "h";
/// The longest name kept in a file name (`1 + 2 × 100` bytes).
pub(super) const MAX_SHORT_ROW: usize = 100;

/// The longest temp file name `FileTransport` writes next to a row file
/// `<file>`: `.<file>.tmp.<pid: u32>.<seq: u64>`.
pub(super) const fn max_temp_name(file_name_len: usize) -> usize {
    1 + file_name_len + ".tmp.".len() + 10 + 1 + 20
}

/// Every row file, and every temp file written to publish one, fits the
/// 255-byte file-name limit of common filesystems (APFS, ext4, NTFS), for
/// any pid and any value of the process-wide temp counter.
pub(super) const NAME_MAX: usize = 255;
const _: () = assert!(max_temp_name(SHORT_ROW.len() + 2 * MAX_SHORT_ROW) <= NAME_MAX);
const _: () = assert!(max_temp_name(HASHED_ROW.len() + 64) <= NAME_MAX);

fn row_file_name(name: &[u8]) -> String {
    if name.len() <= MAX_SHORT_ROW {
        format!("{SHORT_ROW}{}", to_hex_bytes(name))
    } else {
        format!("{HASHED_ROW}{}", to_hex(&hash(name)))
    }
}

fn corrupt_row_name(file_name: &str) -> StoreError {
    StoreError::Corrupt(format!("row file {file_name} does not hold its key").into())
}

/// Lowercase hex to bytes.
fn from_hex(hex: &str) -> Option<Vec<u8>> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let (pairs, []) = hex.as_bytes().as_chunks::<2>() else {
        return None;
    };
    pairs
        .iter()
        .map(|[hi, lo]| Some(digit(*hi)? << 4 | digit(*lo)?))
        .collect()
}

fn encode_row(name: &[u8], value: &Value) -> Vec<u8> {
    // A key is at most MAX_KEY_BYTES (1024), so its name fits a be16.
    let len = u16::try_from(name.len()).unwrap_or(u16::MAX);
    [&len.to_be_bytes()[..], name, value.as_bytes()].concat()
}

/// A row file's name and value.
fn decode_row(bytes: &[u8]) -> Result<(&[u8], Value), StoreError> {
    let corrupt = || StoreError::Corrupt("truncated row file".into());
    let (len, rest) = bytes.split_first_chunk::<2>().ok_or_else(corrupt)?;
    let len = usize::from(u16::from_be_bytes(*len));
    let (name, value) = rest.split_at_checked(len).ok_or_else(corrupt)?;
    Ok((name, Value::new(value.to_vec())))
}

impl NamespaceStore for FsLayoutStore {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities::refs_only()
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.check_partition(p)?;
        self.read(key)
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        if limit == 0 {
            return Err(StoreError::Invalid("scan limit must be at least 1".into()));
        }
        self.check_partition(p)?;
        // Every cursor this range returns is one of its keys.
        let after = after.map(|c| Key::new(c.clone().into_bytes()));
        if after.as_ref().is_some_and(|c| c < start || c >= end) {
            return Err(StoreError::Invalid(
                "scan cursor outside the scanned range".into(),
            ));
        }
        let mut entries =
            self.rows(|k| start <= k && k < end && after.as_ref().is_none_or(|c| k > c))?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let want = usize::try_from(limit).unwrap_or(usize::MAX);
        let next = (entries.len() > want).then(|| {
            entries.truncate(want);
            Cursor::new(entries[want - 1].0.clone().into_bytes())
        });
        Ok(ScanPage { entries, next })
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        batch.validate(&self.capabilities())?;
        self.check_partition(p)?;
        // Every key resolves, and a ref write carries an id, before the
        // lock is taken: a batch this store cannot hold writes nothing.
        for pre in &batch.preconditions {
            match pre {
                Precondition::Absent(key)
                | Precondition::Present(key)
                | Precondition::Equals(key, _) => {
                    self.slot(key)?;
                }
                Precondition::NotAfter(_) => {}
            }
        }
        for write in &batch.writes {
            match write {
                Write::Put(key, value) => {
                    if let Slot::Ref(_) = self.slot(key)? {
                        ref_id(value)?;
                    }
                }
                Write::Delete(key) => {
                    self.slot(key)?;
                }
            }
        }
        let result = self
            .tx
            .with_ref_lock(|refs| self.check_and_write(refs, &batch))
            .map_err(ref_file_error)
            .and_then(|outcome| outcome);
        match result {
            // Rule 7: a delete-only batch never reports `Full` (a delete
            // frees space; a full disk while syncing it is an outage).
            Err(StoreError::Full) if !batch.has_put() => Err(unavailable(std::io::Error::other(
                "storage full while deleting",
            ))),
            other => other,
        }
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.check_partition(p)?;
        let rows = self.rows(|_| true)?;
        let bytes = rows
            .iter()
            .map(|(k, v)| (k.as_bytes().len() + v.as_bytes().len()) as u64)
            .sum();
        Ok(PartitionStats {
            bytes,
            keys: Some(rows.len() as u64),
        })
    }

    async fn probe(&self) -> Result<(), StoreError> {
        let meta = fs::metadata(self.root()).map_err(io_error)?;
        if meta.is_dir() {
            Ok(())
        } else {
            Err(unavailable(std::io::Error::other(
                "ref root is not a directory",
            )))
        }
    }
}
