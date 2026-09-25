//! The storage contract (PRD §5.3): the key-level [`NamespaceStore`], the
//! content-addressed [`BlobStore`], and the key layouts, value codecs and
//! typed readers every backend shares. Nothing here needs SQL: a
//! single-writer key-value store implements the whole contract.
//!
//! The contract types are also re-exported at the crate root; [`keys`],
//! [`codec`] and [`read`] stay namespaced.

mod blob;
pub mod codec;
mod error;
pub mod keys;
mod kv;
mod partition;
pub mod read;

pub use blob::{BlobBody, BlobKey, BlobMeta, BlobStore, ByteRange, CommitOutcome, PackSink};
pub use error::{BoxError, StoreError};
pub use kv::{
    Batch, BatchOutcome, Cursor, Key, KeyClasses, MAX_BATCH_BYTES, MAX_BATCH_OPS, MAX_KEY_BYTES,
    MAX_VALUE_BYTES, MembershipMode, NamespaceStore, PartitionStats, Precondition, ScanPage,
    StoreCapabilities, Value, Write,
};
pub use partition::Partition;
