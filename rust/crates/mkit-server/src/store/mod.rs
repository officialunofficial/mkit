//! The storage contract (PRD §5.3): the key-level [`NamespaceStore`], the
//! content-addressed [`BlobStore`], and the key layouts, value codecs and
//! typed readers every backend shares. Nothing here needs SQL: a
//! single-writer key-value store implements the whole contract.
//!
//! Layers over the contract that work on any backend: the global
//! [`ContentIndex`], the portable logical export and import, and the
//! optional [`StoreMaintenance`] and [`StateCommitment`] hooks.
//!
//! The contract types are also re-exported at the crate root;
//! storage layouts and codecs live in the doc-hidden [`adapter_spi`].

/// Storage layout and maintenance hooks for adapters; not the embedder contract.
#[doc(hidden)]
pub mod adapter_spi;
mod blob;
pub(crate) use adapter_spi::{codec, index, keys, outbox, publication, tickets, watermark};
pub use codec::{AbortReason, OutcomeRef, PendingOp, ReservationV1, StoredProcedure};
pub use tickets::TicketCaps;

mod content_index;
mod pending_holder;
pub use pending_holder::PendingHolderV1;
mod error;

#[cfg(test)]
pub(crate) mod inspection_flags;
#[cfg(test)]
pub(crate) mod inspection_holds;
#[cfg(test)]
pub(crate) mod inspection_mode;
#[cfg(test)]
#[path = "tests/inspection_mode.rs"]
mod inspection_mode_tests;

mod kv;
pub(crate) mod read_io;
#[cfg(test)]
pub(crate) mod read_probe;
#[doc(hidden)]
pub use read_io::ReadReservation;
mod maintenance;

mod partition;

pub(crate) mod read;
pub(crate) mod repo_storage;
pub(crate) mod restore;

pub(crate) mod view;

pub use blob::{
    BlobBody, BlobKey, BlobMeta, BlobNamespace, BlobStore, ByteRange, CommitOutcome,
    MAX_BLOB_PIECE_BYTES, MultipartBlobStore, PackSink, PartRef, PartSink, UnsupportedPartSink,
    is_reserved_pack_keyspace,
};
pub(crate) use content_index::BorrowedStore;
pub use content_index::{
    BlockEntry, CONTENT_APPLY_WINDOW_MS, ContentIndex, GcPlan, HoldOutcome, Holder, HolderOutcome,
    HolderPage, HolderRecord, INDEX_FANOUT, MAX_BLOCK_REASON_BYTES, MAX_HOLD_TTL_MS, ObjectState,
    REF_INDEX_FANOUT, content_shard, content_shards,
};
pub use error::{BoxError, StoreError};
pub use kv::{
    Batch, BatchOutcome, Cursor, Key, KeyClasses, MAX_BATCH_BYTES, MAX_BATCH_OPS, MAX_KEY_BYTES,
    MAX_SCAN_RANGES, MAX_VALUE_BYTES, MembershipMode, NamespaceStore, PartitionStats, Precondition,
    RangeScan, ScanPage, StoreCapabilities, Value, Write,
};
pub use maintenance::{
    EXPORT_END, EXPORT_FORMAT_V1, EXPORT_MAGIC, ExportHeader, ExportPage, ExportReader,
    ExportRecord, ExportStream, ImportMode, Importer, StateCommitment, StoreMaintenance,
    encode_export_header, encode_export_record, export_header, export_page, export_partition,
    import_stream,
};
pub use partition::Partition;
