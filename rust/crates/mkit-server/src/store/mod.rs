//! The storage contract (PRD §5.3): the key-level [`NamespaceStore`] and
//! the key layouts every backend shares. Nothing here needs SQL: a
//! single-writer key-value store implements the whole contract.
//!
//! The contract types are also re-exported at the crate root; [`keys`]
//! stays namespaced.

mod error;
pub mod keys;
mod kv;

pub use error::{BoxError, StoreError};
pub use kv::{
    Batch, BatchOutcome, Cursor, Key, KeyClasses, MAX_KEY_BYTES, MAX_VALUE_BYTES, MembershipMode,
    NamespaceStore, Partition, PartitionStats, Precondition, ScanPage, StoreCapabilities, Value,
    Write,
};
