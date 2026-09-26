#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! This crate is runtime-agnostic: it compiles for the host and for
//! `wasm32-unknown-unknown`, never reads the wall clock directly (see
//! [`Clock`]) and never spawns on a concrete executor (see [`Spawner`]).
//! The shared vocabulary is re-exported at the crate root from private
//! modules. The protocol logic lives in public modules, so call sites name
//! the protocol they apply (`refs::evaluate_cas`, `quota::evaluate_quota`).
//! The storage contract lives in [`store`]: its contract types are also
//! re-exported at the root, its key layouts, value codecs and typed
//! readers stay namespaced (`store::keys`, `store::codec`, `store::read`),
//! as do the export/import helpers and the `ContentIndex` row types
//! (`store::export_partition`, `store::Holder`).
//! The `memory` feature adds the in-memory reference backends.

pub mod auth_v2;
pub mod download;
mod error;
#[cfg(any(test, feature = "memory"))]
mod memory;
mod op;
mod principal;
pub mod quota;
pub mod refs;
mod replay;
mod repo;
mod rt;
pub mod storage_error;
pub mod store;
mod telemetry;
pub mod upload;

pub use error::{
    ADMISSION_CHALLENGE_TYPE, Code, ErrorDetail, InvalidHeader, Redacted, ServerError,
};
#[cfg(any(test, feature = "memory"))]
pub use memory::{MemoryBlobStore, MemoryFault, MemoryKv, MemoryPackSink};
pub use op::{
    AuthzFacts, Commitment, GrantRef, OpKind, Operation, Procedure, RefUpdate, VerifiedAuth,
};
pub use principal::Principal;
pub use replay::{
    ReplayDecision, ReplayKey, ReplayRecord, ReplayState, StoredRejection, StoredResult,
    UpdateRefResult, classify,
};
pub use repo::{Addressing, NamespaceKey, RepoId, RepoName};
#[cfg(not(target_arch = "wasm32"))]
pub use rt::SystemClock;
pub use rt::{BoxFuture, BoxStream, Clock, ManualClock, MaybeSend, MaybeSync, Spawner, send_wrap};
pub use store::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobMeta, BlobStore, BoxError, ByteRange,
    CommitOutcome, ContentIndex, Cursor, Key, KeyClasses, MAX_BATCH_BYTES, MAX_BATCH_OPS,
    MAX_KEY_BYTES, MAX_VALUE_BYTES, MembershipMode, NamespaceStore, PackSink, Partition,
    PartitionStats, Precondition, ScanPage, StateCommitment, StoreCapabilities, StoreError,
    StoreMaintenance, Value, Write,
};
pub use telemetry::{
    METRIC_LATENCY, METRIC_REQUESTS, METRIC_UPLOAD_BYTES, Metrics, NEVER_ECHO, NEVER_LOG,
    NoopMetrics, REDACTED_VALUE, Redactor, is_never_echo, is_never_log,
};
