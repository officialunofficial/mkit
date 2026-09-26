//! Backup and restore (PRD §5.3: "a backup and restore procedure and
//! versioned schema migrations are required for every backend") and the
//! optional backend hooks.
//!
//! **Portable logical export** (R-20) works on every [`NamespaceStore`]: a
//! full ordered scan of one partition as [`ExportRecord`]s under an
//! [`ExportHeader`], written in the byte format of [`encode_export_header`]
//! and [`encode_export_record`] and read back by [`ExportReader`]. A store
//! never lists its partitions: a full backup exports each partition the
//! `Partition` enumeration names (namespaces from configuration and the
//! `nl` list, repos from each coordinator's `rr` registry, index and
//! content shards by construction, see [`super::content_shards`], ref
//! shards from the ref-name index). There is no registry of all shards.
//!
//! [`StoreMaintenance`] (R-19) and [`StateCommitment`] (R-21) are optional:
//! nothing in the pipeline requires them.

use core::future::{Future, poll_fn};
use core::pin::{Pin, pin};
use core::task::{Context, Poll, ready};
use std::collections::VecDeque;

use bytes::{BufMut, Bytes, BytesMut};
use futures_core::Stream;
use mkit_core::hash::Hash;

use super::codec;
use super::error::StoreError;
use super::keys;
use super::kv::{
    Batch, BatchOutcome, Cursor, Key, KeyClasses, MAX_BATCH_BYTES, MAX_BATCH_OPS, MAX_KEY_BYTES,
    MAX_VALUE_BYTES, NamespaceStore, Precondition, Value,
};
use super::partition::Partition;
use crate::rt::{BoxFuture, MaybeSend, MaybeSync};

/// First bytes of every export.
pub const EXPORT_MAGIC: [u8; 8] = *b"mkitexp\0";
/// The export byte format this binary writes and reads.
pub const EXPORT_FORMAT_V1: u8 = 1;
/// End marker: a record whose partition length is 0. A reader requires it,
/// so a truncated export never imports as a shorter one.
pub const EXPORT_END: [u8; 2] = [0, 0];

const HEADER_LEN: usize = EXPORT_MAGIC.len() + 1 + 4 + 8;
/// Records per scan while exporting.
const EXPORT_PAGE: u32 = 256;

/// What an export was taken from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportHeader {
    /// The partition's key-layout version: its `v` row, a `RefsOnly`
    /// store's `implicit_layout_version`, or this binary's version for an
    /// unversioned partition. A dump of several partitions carries the
    /// highest.
    pub layout_version: u32,
    /// When the export started, Unix ms.
    pub exported_at_ms: u64,
}

impl ExportHeader {
    /// A header.
    #[must_use]
    pub fn new(layout_version: u32, exported_at_ms: u64) -> Self {
        Self {
            layout_version,
            exported_at_ms,
        }
    }
}

/// One exported row.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportRecord {
    /// The row's partition.
    pub partition: Partition,
    /// Key.
    pub key: Key,
    /// Value.
    pub value: Value,
}

impl ExportRecord {
    /// A record.
    #[must_use]
    pub fn new(partition: Partition, key: Key, value: Value) -> Self {
        Self {
            partition,
            key,
            value,
        }
    }
}

/// One page of [`export_page`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ExportPage {
    /// Records in key order.
    pub records: Vec<ExportRecord>,
    /// Resume point, if more records may follow.
    pub next: Option<Cursor>,
}

/// The key range an export scans: every key of the store's classes. Every
/// key starts with an ASCII class tag, so `[0xff]` bounds them all.
fn export_range<S: NamespaceStore>(store: &S) -> (Key, Key) {
    if store.capabilities().key_classes == KeyClasses::RefsOnly {
        keys::class_range(keys::TAG_REF)
    } else {
        (Key::default(), Key::new(vec![0xff]))
    }
}

/// The header of an export of `p` taken at `now_ms`.
pub async fn export_header<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    now_ms: u64,
) -> Result<ExportHeader, StoreError> {
    let layout_version = match store.capabilities().implicit_layout_version {
        Some(version) => version,
        None => match store.get(p, &keys::layout_version()).await? {
            Some(value) => codec::decode_u32(&value)?,
            None => keys::LAYOUT_VERSION,
        },
    };
    Ok(ExportHeader {
        layout_version,
        exported_at_ms: now_ms,
    })
}

/// Up to `limit` rows of `p` after `after`, in key order: one stateless
/// step of an export (a Durable Object serves it per call).
pub async fn export_page<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    after: Option<&Cursor>,
    limit: u32,
) -> Result<ExportPage, StoreError> {
    let (start, end) = export_range(store);
    let page = store.scan(p, &start, &end, after, limit).await?;
    Ok(ExportPage {
        records: page
            .entries
            .into_iter()
            .map(|(key, value)| ExportRecord {
                partition: p.clone(),
                key,
                value,
            })
            .collect(),
        next: page.next,
    })
}

async fn owned_page<S: NamespaceStore>(
    store: &S,
    p: Partition,
    after: Option<Cursor>,
) -> Result<ExportPage, StoreError> {
    export_page(store, &p, after.as_ref(), EXPORT_PAGE).await
}

/// Portable logical backup of one partition: its header and a stream of
/// every row in key order. The stream is not a snapshot: rows written while
/// it runs may or may not appear, so export a quiesced partition.
pub async fn export_partition<'a, S: NamespaceStore>(
    store: &'a S,
    p: &Partition,
    now_ms: u64,
) -> Result<(ExportHeader, ExportStream<'a, S>), StoreError> {
    let header = export_header(store, p, now_ms).await?;
    let stream = ExportStream {
        store,
        partition: p.clone(),
        pending: Some(Box::pin(owned_page(store, p.clone(), None))),
        buffered: VecDeque::new(),
    };
    Ok((header, stream))
}

/// The record stream of [`export_partition`].
pub struct ExportStream<'a, S> {
    store: &'a S,
    partition: Partition,
    pending: Option<BoxFuture<'a, Result<ExportPage, StoreError>>>,
    buffered: VecDeque<ExportRecord>,
}

impl<S> core::fmt::Debug for ExportStream<'_, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExportStream")
            .field("partition", &self.partition)
            .field("buffered", &self.buffered.len())
            .finish_non_exhaustive()
    }
}

impl<S: NamespaceStore> Stream for ExportStream<'_, S> {
    type Item = Result<ExportRecord, StoreError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(record) = this.buffered.pop_front() {
                return Poll::Ready(Some(Ok(record)));
            }
            let Some(pending) = this.pending.as_mut() else {
                return Poll::Ready(None);
            };
            let page = ready!(pending.as_mut().poll(cx));
            this.pending = None;
            let page = match page {
                Ok(page) => page,
                Err(e) => return Poll::Ready(Some(Err(e))),
            };
            this.buffered.extend(page.records);
            if let Some(next) = page.next {
                let fut = owned_page(this.store, this.partition.clone(), Some(next));
                this.pending = Some(Box::pin(fut));
            }
        }
    }
}

/// The export header bytes: [`EXPORT_MAGIC`], [`EXPORT_FORMAT_V1`], the
/// layout version (be32) and the export time (be64).
#[must_use]
pub fn encode_export_header(header: &ExportHeader) -> Bytes {
    let mut buf = BytesMut::with_capacity(HEADER_LEN);
    buf.put_slice(&EXPORT_MAGIC);
    buf.put_u8(EXPORT_FORMAT_V1);
    buf.put_u32(header.layout_version);
    buf.put_u64(header.exported_at_ms);
    buf.freeze()
}

/// One record's bytes: partition length (be16, never 0) and
/// [`Partition::encode`] bytes, key length (be16) and key, value length
/// (be32) and value. An export is the header, its records, then
/// [`EXPORT_END`].
///
/// # Errors
/// [`StoreError::Invalid`] for an unencodable partition or a key or value
/// over the contract limits.
pub fn encode_export_record(record: &ExportRecord) -> Result<Bytes, StoreError> {
    let partition = record.partition.encode()?;
    let (key, value) = (record.key.as_bytes(), record.value.as_bytes());
    let too_long = || StoreError::Invalid("export record exceeds limits".into());
    if key.len() > MAX_KEY_BYTES || value.len() > MAX_VALUE_BYTES {
        return Err(too_long());
    }
    let mut buf = BytesMut::with_capacity(8 + partition.len() + key.len() + value.len());
    buf.put_u16(u16::try_from(partition.len()).map_err(|_| too_long())?);
    buf.put_slice(&partition);
    buf.put_u16(u16::try_from(key.len()).map_err(|_| too_long())?);
    buf.put_slice(key);
    buf.put_u32(u32::try_from(value.len()).map_err(|_| too_long())?);
    buf.put_slice(value);
    Ok(buf.freeze())
}

/// Reads an export's records from its bytes; see [`encode_export_record`].
#[derive(Debug)]
pub struct ExportReader<'a> {
    rest: &'a [u8],
    done: bool,
}

fn corrupt(what: &'static str) -> StoreError {
    StoreError::Corrupt(what.into())
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8], StoreError> {
    if rest.len() < n {
        return Err(corrupt("truncated export"));
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn take_len(rest: &mut &[u8], width: usize, max: usize) -> Result<usize, StoreError> {
    let len = take(rest, width)?
        .iter()
        .fold(0_usize, |n, &b| (n << 8) | usize::from(b));
    if len > max {
        return Err(corrupt("export record exceeds limits"));
    }
    Ok(len)
}

impl<'a> ExportReader<'a> {
    /// Check the header of `bytes` and return it with a reader over the
    /// records.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for a missing magic, an unknown format or a
    /// short header.
    pub fn new(bytes: &'a [u8]) -> Result<(ExportHeader, Self), StoreError> {
        let (head, rest) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or_else(|| corrupt("truncated export"))?;
        let (magic, fields) = head.split_at(EXPORT_MAGIC.len());
        if magic != EXPORT_MAGIC {
            return Err(corrupt("not an mkit export"));
        }
        if fields[0] != EXPORT_FORMAT_V1 {
            return Err(corrupt("unknown export format"));
        }
        let mut version = [0; 4];
        version.copy_from_slice(&fields[1..5]);
        let mut at = [0; 8];
        at.copy_from_slice(&fields[5..]);
        let header = ExportHeader {
            layout_version: u32::from_be_bytes(version),
            exported_at_ms: u64::from_be_bytes(at),
        };
        Ok((header, Self { rest, done: false }))
    }

    fn record(&mut self) -> Result<Option<ExportRecord>, StoreError> {
        let partition_len = take_len(&mut self.rest, 2, usize::from(u16::MAX))?;
        if partition_len == 0 {
            if !self.rest.is_empty() {
                return Err(corrupt("bytes after the export end marker"));
            }
            return Ok(None);
        }
        let partition = Partition::decode(take(&mut self.rest, partition_len)?)?;
        let key_len = take_len(&mut self.rest, 2, MAX_KEY_BYTES)?;
        let key = Key::new(take(&mut self.rest, key_len)?.to_vec());
        let value_len = take_len(&mut self.rest, 4, MAX_VALUE_BYTES)?;
        let value = Value::new(take(&mut self.rest, value_len)?.to_vec());
        Ok(Some(ExportRecord {
            partition,
            key,
            value,
        }))
    }
}

impl Iterator for ExportReader<'_> {
    type Item = Result<ExportRecord, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let record = self.record();
        self.done = !matches!(record, Ok(Some(_)));
        record.transpose()
    }
}

/// How an [`Importer`] treats a partition that already holds rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportMode {
    /// Refuse it: a restore goes into empty partitions.
    #[default]
    Fresh,
    /// Write over it: imported rows replace same-key rows, other rows stay.
    Merge,
}

/// Restores exported records into a store, in batches within
/// [`MAX_BATCH_OPS`] and [`MAX_BATCH_BYTES`] (so they fit Durable Object
/// limits), one partition per batch; one write per batch on a store without
/// `atomic_multi_key`. A partition's records must be contiguous, as an
/// export writes them.
///
/// On the first record of each partition, [`ImportMode::Fresh`] checks the
/// partition is empty. After a partition's last record, a store that holds
/// the `v` class gets `v` = the header's layout version if the export had
/// no `v` row (a `RefsOnly` export), written only if absent. Records are
/// plain puts, so an interrupted import can be rerun with
/// [`ImportMode::Merge`].
#[derive(Debug)]
pub struct Importer<'a, S> {
    store: &'a S,
    mode: ImportMode,
    layout_version: u32,
    holds_v: bool,
    max_ops: usize,
    partition: Option<Partition>,
    saw_v: bool,
    batch: Batch,
    bytes: usize,
    imported: u64,
}

fn check_layout(version: u32) -> Result<(), StoreError> {
    if version > keys::LAYOUT_VERSION {
        return Err(StoreError::Unsupported(
            "export has a newer layout version than this binary".into(),
        ));
    }
    Ok(())
}

impl<'a, S: NamespaceStore> Importer<'a, S> {
    /// An importer for an export with `header`.
    ///
    /// # Errors
    /// [`StoreError::Unsupported`] if the export's layout version is newer
    /// than [`keys::LAYOUT_VERSION`].
    pub fn new(store: &'a S, header: &ExportHeader, mode: ImportMode) -> Result<Self, StoreError> {
        check_layout(header.layout_version)?;
        let caps = store.capabilities();
        Ok(Self {
            store,
            mode,
            layout_version: header.layout_version,
            holds_v: caps.key_classes == KeyClasses::All,
            max_ops: if caps.atomic_multi_key {
                MAX_BATCH_OPS
            } else {
                1
            },
            partition: None,
            saw_v: false,
            batch: Batch::new(),
            bytes: 0,
            imported: 0,
        })
    }

    /// Queue `record`, committing the pending batch first if the record
    /// changes partition or would overflow it.
    ///
    /// # Errors
    /// [`StoreError::Unsupported`] for a `v` row newer than this binary's
    /// layout; [`StoreError::Invalid`] for a non-empty partition under
    /// [`ImportMode::Fresh`]; any error of the store's `apply`.
    pub async fn push(&mut self, record: ExportRecord) -> Result<(), StoreError> {
        let is_v = record.key == keys::layout_version();
        if is_v {
            check_layout(codec::decode_u32(&record.value)?)?;
        }
        let size = record.key.as_bytes().len() + record.value.as_bytes().len();
        if self.partition.as_ref() != Some(&record.partition) {
            self.end_partition().await?;
            if self.mode == ImportMode::Fresh {
                let (start, end) = export_range(self.store);
                let page = self
                    .store
                    .scan(&record.partition, &start, &end, None, 1)
                    .await?;
                if !page.entries.is_empty() {
                    return Err(StoreError::Invalid(
                        "import target partition is not empty".into(),
                    ));
                }
            }
            self.partition = Some(record.partition);
            self.saw_v = false;
        } else if self.batch.writes.len() >= self.max_ops || self.bytes + size > MAX_BATCH_BYTES {
            self.flush().await?;
        }
        self.saw_v |= is_v;
        self.batch = core::mem::take(&mut self.batch).put(record.key, record.value);
        self.bytes += size;
        self.imported += 1;
        Ok(())
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<(), StoreError> {
        match self.store.apply(p, batch).await? {
            BatchOutcome::Committed => Ok(()),
            _ => Err(StoreError::unavailable("import batch did not commit")),
        }
    }

    async fn flush(&mut self) -> Result<(), StoreError> {
        let batch = core::mem::take(&mut self.batch);
        self.bytes = 0;
        match &self.partition {
            Some(p) if !batch.writes.is_empty() => self.apply(p, batch).await,
            _ => Ok(()),
        }
    }

    /// Commit the current partition's last batch, then its `v` row if it
    /// needs one.
    async fn end_partition(&mut self) -> Result<(), StoreError> {
        self.flush().await?;
        let Some(p) = self.partition.take() else {
            return Ok(());
        };
        if !self.holds_v || self.saw_v {
            return Ok(());
        }
        let key = keys::layout_version();
        let batch = Batch::new()
            .require(Precondition::Absent(key.clone()))
            .put(key, codec::encode_u32(self.layout_version));
        match self.store.apply(&p, batch).await? {
            BatchOutcome::Committed | BatchOutcome::PreconditionFailed { .. } => Ok(()),
            BatchOutcome::DeadlinePassed { .. } => {
                Err(StoreError::unavailable("import batch did not commit"))
            }
        }
    }

    /// Commit the pending batches; the number of records imported.
    pub async fn finish(mut self) -> Result<u64, StoreError> {
        self.end_partition().await?;
        Ok(self.imported)
    }
}

/// Import a record stream (such as an [`ExportStream`]) taken under
/// `header`; the number of records imported. Records carry their
/// partition, so one stream may restore several partitions.
pub async fn import_stream<S, R>(
    store: &S,
    header: &ExportHeader,
    mode: ImportMode,
    records: R,
) -> Result<u64, StoreError>
where
    S: NamespaceStore,
    R: Stream<Item = Result<ExportRecord, StoreError>>,
{
    let mut importer = Importer::new(store, header, mode)?;
    let mut records = pin!(records);
    while let Some(record) = poll_fn(|cx| records.as_mut().poll_next(cx)).await {
        importer.push(record?).await?;
    }
    importer.finish().await
}

/// Backend-defined maintenance (R-19). Optional: the pipeline never calls
/// it. `SQLite` implements it with versioned physical migrations and
/// `VACUUM INTO` (M0-09); another backend may implement it however it
/// likes, and every backend still has the portable export above.
pub trait StoreMaintenance: MaybeSend + MaybeSync {
    /// The backend's physical layout version (its schema, e.g. `SQLite`'s
    /// `user_version`); independent of [`keys::LAYOUT_VERSION`].
    fn layout_version(&self) -> u32;

    /// Migrate the physical layout to the version this binary expects;
    /// returns the version reached. Idempotent.
    fn migrate(&self) -> impl Future<Output = Result<u32, StoreError>> + MaybeSend;

    /// Write a consistent backend-native backup to `dest`, a location the
    /// backend defines (a file path, a bucket URL).
    fn backup_to(&self, dest: &str) -> impl Future<Output = Result<(), StoreError>> + MaybeSend;
}

/// A future verifiable state root over a partition (R-21). Optional and
/// unimplemented in the epic; the pipeline never requires it.
pub trait StateCommitment: NamespaceStore {
    /// The partition's current root, with the name of its commitment
    /// scheme; `None` if the backend keeps no root for it.
    fn root(
        &self,
        p: &Partition,
    ) -> impl Future<Output = Result<Option<(String, Hash)>, StoreError>> + MaybeSend;

    /// A proof of `key`'s value (or absence) against [`Self::root`], in the
    /// scheme's encoding; `None` if the backend cannot prove it.
    fn prove(
        &self,
        p: &Partition,
        key: &Key,
    ) -> impl Future<Output = Result<Option<Bytes>, StoreError>> + MaybeSend;
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use futures_executor::block_on;

    use super::*;
    use crate::memory::MemoryKv;
    use crate::repo::{NamespaceKey, RepoName};
    use crate::store::content_index::{
        BlockEntry, ContentIndex, HoldOutcome, Holder, content_shard,
    };
    use crate::store::{PartitionStats, ScanPage, StoreCapabilities};

    fn ns() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }

    fn repo() -> RepoName {
        RepoName::new("r").unwrap()
    }

    /// Every row of `p`, in pages of 2.
    fn scan_all<S: NamespaceStore>(store: &S, p: &Partition) -> Vec<ExportRecord> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let page = block_on(export_page(store, p, after.as_ref(), 2)).unwrap();
            out.extend(page.records);
            match page.next {
                Some(next) => after = Some(next),
                None => return out,
            }
        }
    }

    /// `export_partition` of `p`, encoded.
    fn export_bytes<S: NamespaceStore>(store: &S, p: &Partition) -> Vec<u8> {
        block_on(async {
            let (header, stream) = export_partition(store, p, 42).await.unwrap();
            let mut stream = pin!(stream);
            let mut out = encode_export_header(&header).to_vec();
            while let Some(record) = poll_fn(|cx| stream.as_mut().poll_next(cx)).await {
                out.extend_from_slice(&encode_export_record(&record.unwrap()).unwrap());
            }
            out.extend_from_slice(&EXPORT_END);
            out
        })
    }

    fn import_bytes<S: NamespaceStore>(
        store: &S,
        bytes: &[u8],
        mode: ImportMode,
    ) -> Result<u64, StoreError> {
        let (header, reader) = ExportReader::new(bytes)?;
        block_on(async {
            let mut importer = Importer::new(store, &header, mode)?;
            for record in reader {
                importer.push(record?).await?;
            }
            importer.finish().await
        })
    }

    #[test]
    fn export_import_roundtrip_is_identical() {
        let (a, b) = ([0x10; 32], [0xf0; 32]);
        let idx = ContentIndex::new(MemoryKv::default());
        let holder = Holder::new(NamespaceKey::deployment_default(), repo());
        block_on(async {
            idx.add_holder(&a, &holder, None, 1).await.unwrap();
            let held = idx.add_hold(&b, &[1; 32], 99, 2).await.unwrap();
            assert_eq!(held, HoldOutcome::Held);
            let entry = BlockEntry::new("r", 3);
            idx.block(&b, &entry, 3).await.unwrap();
            let mut batch = Batch::new()
                .put(keys::layout_version(), codec::encode_u32(1))
                .put(keys::grant_epoch(), codec::encode_u64(4));
            for i in 0..7_u8 {
                let name = format!("refs/heads/b{i}");
                let id = codec::encode_ref_id(&[i; 32]);
                batch = batch.put(keys::ref_key(&repo(), &name), id);
            }
            idx.store().apply(&ns(), batch).await.unwrap();
        });
        let src = idx.store();
        let dst = MemoryKv::default();
        let parts = [ns(), content_shard(&a), content_shard(&b)];
        for p in &parts {
            let bytes = export_bytes(src, p);
            let rows = u64::try_from(scan_all(src, p).len()).unwrap();
            assert!(rows >= 3);
            assert_eq!(import_bytes(&dst, &bytes, ImportMode::Fresh).unwrap(), rows);
            assert_eq!(scan_all(&dst, p), scan_all(src, p), "{p:?}");
            assert_eq!(export_bytes(&dst, p), bytes, "byte-for-byte {p:?}");
        }
        // The stream form imports directly, several partitions at once.
        let dst = MemoryKv::default();
        block_on(async {
            for p in &parts {
                let (header, stream) = export_partition(src, p, 42).await.unwrap();
                import_stream(&dst, &header, ImportMode::Fresh, stream)
                    .await
                    .unwrap();
            }
        });
        for p in &parts {
            assert_eq!(scan_all(&dst, p), scan_all(src, p));
        }
    }

    #[test]
    fn export_format_golden_bytes() {
        let header = ExportHeader {
            layout_version: 1,
            exported_at_ms: 0x0102_0304_0506_0708,
        };
        let record = ExportRecord {
            partition: Partition::ContentShard(7),
            key: Key::new(&b"b\0"[..]),
            value: Value::new(&b"v"[..]),
        };
        let bytes = [
            &encode_export_header(&header)[..],
            &encode_export_record(&record).unwrap(),
            &EXPORT_END,
        ]
        .concat();
        let golden: &[u8] = b"mkitexp\0\x01\0\0\0\x01\x01\x02\x03\x04\x05\x06\x07\x08\
            \0\x03s7\0\0\x02b\0\0\0\0\x01v\0\0";
        assert_eq!(bytes, golden);
        let (read, reader) = ExportReader::new(golden).unwrap();
        assert_eq!(read, header);
        assert_eq!(
            reader.collect::<Result<Vec<_>, _>>().unwrap(),
            vec![record.clone()]
        );
        let mut trailing = golden.to_vec();
        trailing.push(0);
        let mut bad_magic = golden.to_vec();
        bad_magic[0] = b'M';
        let mut newer_format = golden.to_vec();
        newer_format[8] = 2;
        let mut long_key = golden[..HEADER_LEN + 5].to_vec();
        long_key.extend_from_slice(&[0x04, 0x01]);
        for bad in [
            &golden[..golden.len() - 1],
            &golden[..HEADER_LEN],
            &golden[..5],
            trailing.as_slice(),
            bad_magic.as_slice(),
            newer_format.as_slice(),
            long_key.as_slice(),
        ] {
            let result = ExportReader::new(bad)
                .and_then(|(_, reader)| reader.collect::<Result<Vec<_>, _>>());
            assert!(matches!(result, Err(StoreError::Corrupt(_))), "{bad:?}");
        }
        let huge = ExportRecord {
            value: Value::new(vec![0; MAX_VALUE_BYTES + 1]),
            ..record
        };
        assert!(matches!(
            encode_export_record(&huge),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn import_refuses_newer_layout_version() {
        let kv = MemoryKv::default();
        let newer = ExportHeader {
            layout_version: keys::LAYOUT_VERSION + 1,
            exported_at_ms: 0,
        };
        assert!(matches!(
            Importer::new(&kv, &newer, ImportMode::Fresh),
            Err(StoreError::Unsupported(_))
        ));
        let bytes = [&encode_export_header(&newer)[..], &EXPORT_END].concat();
        assert!(matches!(
            import_bytes(&kv, &bytes, ImportMode::Fresh),
            Err(StoreError::Unsupported(_))
        ));
        // A `v` row newer than the header claims is refused too.
        let current = ExportHeader {
            layout_version: keys::LAYOUT_VERSION,
            exported_at_ms: 0,
        };
        let row = ExportRecord {
            partition: ns(),
            key: keys::layout_version(),
            value: codec::encode_u32(keys::LAYOUT_VERSION + 1),
        };
        let mut importer = Importer::new(&kv, &current, ImportMode::Fresh).unwrap();
        assert!(matches!(
            block_on(importer.push(row)),
            Err(StoreError::Unsupported(_))
        ));
        assert!(scan_all(&kv, &ns()).is_empty(), "nothing was written");
    }

    /// A store that records the size of every batch it applies.
    struct Recording {
        inner: MemoryKv,
        batches: Mutex<Vec<(usize, usize)>>,
    }

    impl NamespaceStore for Recording {
        fn capabilities(&self) -> StoreCapabilities {
            self.inner.capabilities()
        }
        async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
            self.inner.get(p, key).await
        }
        async fn scan(
            &self,
            p: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&Cursor>,
            limit: u32,
        ) -> Result<ScanPage, StoreError> {
            self.inner.scan(p, start, end, after, limit).await
        }
        async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
            let bytes = batch
                .writes
                .iter()
                .map(|w| match w {
                    crate::store::Write::Put(k, v) => k.as_bytes().len() + v.as_bytes().len(),
                    crate::store::Write::Delete(k) => k.as_bytes().len(),
                })
                .sum();
            self.batches
                .lock()
                .unwrap()
                .push((batch.writes.len(), bytes));
            self.inner.apply(p, batch).await
        }
        async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
            self.inner.stats(p).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn import_batches_stay_within_do_limits() {
        let header = ExportHeader {
            layout_version: keys::LAYOUT_VERSION,
            exported_at_ms: 0,
        };
        let records: Vec<_> = (0..250_u32)
            .map(|i| {
                let big = i % 50 < 7;
                ExportRecord {
                    partition: if i < 200 {
                        ns()
                    } else {
                        content_shard(&[0; 32])
                    },
                    key: keys::ref_key(&repo(), &format!("refs/heads/{i:04}")),
                    value: Value::new(vec![1; if big { 300 * 1024 } else { 32 }]),
                }
            })
            .collect();
        for caps in [StoreCapabilities::full(), StoreCapabilities::refs_only()] {
            let store = Recording {
                inner: MemoryKv::new(caps),
                batches: Mutex::default(),
            };
            let imported = block_on(async {
                let mut importer = Importer::new(&store, &header, ImportMode::Fresh).unwrap();
                for record in records.clone() {
                    importer.push(record).await.unwrap();
                }
                importer.finish().await.unwrap()
            });
            assert_eq!(imported, 250);
            let batches = store.batches.into_inner().unwrap();
            let max_ops = if caps.atomic_multi_key {
                MAX_BATCH_OPS
            } else {
                1
            };
            for &(ops, bytes) in &batches {
                assert!(
                    ops <= max_ops && bytes <= MAX_BATCH_BYTES,
                    "{ops} ops, {bytes} B"
                );
            }
            // A full store also gets one `v` batch per partition: the
            // export had no `v` row.
            let v_rows = if caps.atomic_multi_key { 2 } else { 0 };
            assert_eq!(batches.iter().map(|b| b.0).sum::<usize>(), 250 + v_rows);
            if caps.atomic_multi_key {
                // Split by bytes (3 big values per batch), by ops and by
                // partition, never needlessly.
                assert!(batches.len() > 3 && batches.len() < 30, "{batches:?}");
            }
            for p in [ns(), content_shard(&[0; 32])] {
                let want: Vec<_> = records.iter().filter(|r| r.partition == p).collect();
                let got = scan_all(&store.inner, &p);
                let got: Vec<_> = got
                    .iter()
                    .filter(|r| r.key != keys::layout_version())
                    .collect();
                assert_eq!(got, want);
            }
        }
    }

    #[test]
    fn refs_only_export_is_the_ref_class_with_the_implicit_version() {
        let kv = MemoryKv::new(StoreCapabilities::refs_only());
        let key = keys::ref_key(&repo(), "refs/heads/main");
        block_on(kv.apply(
            &ns(),
            Batch::new().put(key.clone(), codec::encode_ref_id(&[5; 32])),
        ))
        .unwrap();
        let header = block_on(export_header(&kv, &ns(), 7)).unwrap();
        assert_eq!(header.layout_version, keys::LAYOUT_VERSION);
        let records = scan_all(&kv, &ns());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].key, key);
        assert_eq!(keys::class_range(keys::TAG_REF), export_range(&kv));
        // Into a full store it gains the header's layout version as `v`.
        let full = MemoryKv::default();
        let bytes = export_bytes(&kv, &ns());
        assert_eq!(import_bytes(&full, &bytes, ImportMode::Fresh).unwrap(), 1);
        let v = block_on(full.get(&ns(), &keys::layout_version())).unwrap();
        assert_eq!(v, Some(codec::encode_u32(header.layout_version)));
        assert_eq!(scan_all(&full, &ns()).len(), 2);
    }

    #[test]
    fn import_refuses_a_non_empty_target_unless_merging() {
        let src = MemoryKv::default();
        let rows = Batch::new()
            .put(keys::layout_version(), codec::encode_u32(1))
            .put(keys::grant_epoch(), codec::encode_u64(9));
        block_on(src.apply(&ns(), rows)).unwrap();
        let bytes = export_bytes(&src, &ns());
        let dst = MemoryKv::default();
        let other = keys::ref_key(&repo(), "refs/heads/keep");
        let existing = Batch::new()
            .put(keys::grant_epoch(), codec::encode_u64(1))
            .put(other.clone(), codec::encode_ref_id(&[1; 32]));
        block_on(dst.apply(&ns(), existing)).unwrap();
        let before = scan_all(&dst, &ns());
        assert!(matches!(
            import_bytes(&dst, &bytes, ImportMode::Fresh),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(scan_all(&dst, &ns()), before, "nothing was written");
        assert_eq!(import_bytes(&dst, &bytes, ImportMode::Merge).unwrap(), 2);
        let epoch = block_on(dst.get(&ns(), &keys::grant_epoch())).unwrap();
        assert_eq!(epoch, Some(codec::encode_u64(9)), "imported rows win");
        let kept = block_on(dst.get(&ns(), &other)).unwrap();
        assert!(kept.is_some(), "other rows stay");
    }
}
