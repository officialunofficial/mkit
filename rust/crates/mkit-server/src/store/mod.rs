//! The storage contract (PRD §5.3): the key-level [`NamespaceStore`], the
//! content-addressed [`BlobStore`], and the key layouts, value codecs and
//! typed readers every backend shares. Nothing here needs SQL: a
//! single-writer key-value store implements the whole contract.
//!
//! Layers over the contract that work on any backend: the global
//! [`ContentIndex`], the portable logical export and import, and the
//! optional [`StoreMaintenance`] and [`StateCommitment`] hooks.
//!
//! The contract types are also re-exported at the crate root; [`keys`],
//! [`codec`] and [`read`] stay namespaced.

mod blob;
pub mod codec;
mod content_index;
mod error;
pub mod keys;
mod kv;
mod maintenance;
mod partition;
pub mod read;

pub use blob::{BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, CommitOutcome, PackSink};
pub use content_index::{
    BlockEntry, ContentIndex, Holder, HolderPage, INDEX_FANOUT, MAX_BLOCK_REASON_BYTES,
    ObjectState, content_shard, content_shards,
};
pub use error::{BoxError, StoreError};
pub use kv::{
    Batch, BatchOutcome, Cursor, Key, KeyClasses, MAX_BATCH_BYTES, MAX_BATCH_OPS, MAX_KEY_BYTES,
    MAX_VALUE_BYTES, MembershipMode, NamespaceStore, PartitionStats, Precondition, ScanPage,
    StoreCapabilities, Value, Write,
};
pub use maintenance::{
    EXPORT_END, EXPORT_FORMAT_V1, EXPORT_MAGIC, ExportHeader, ExportPage, ExportReader,
    ExportRecord, ExportStream, Importer, StateCommitment, StoreMaintenance, encode_export_header,
    encode_export_record, export_header, export_page, export_partition, import_stream,
};
pub use partition::Partition;
