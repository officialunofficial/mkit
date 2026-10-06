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
//! re-exported at the root. Key layouts and value codecs live in the
//! doc-hidden `store::adapter_spi`; typed readers remain crate-private.
//! Portable maintenance and content-index contracts remain in `store`
//! (`store::export_partition`, `store::Holder`).
//! The `memory` feature adds the in-memory reference backends; the native
//! `fs` feature adds the `fs` module, the stores over the `.mkit` on-disk
//! layout; the `ssh` feature adds the `ssh` module, the
//! `mkit.rpc.v1.ssh` session over the pipeline. The `connect` feature
//! (default) adds the `mkit.transport.v1` Connect binding over the pipeline
//! ([`connect::service`]); the `remote-hooks` feature adds the `hooks` module,
//! the `mkit.server.hooks.v1` adapter over a transport-agnostic channel; the
//! `http-objects` feature adds the `http_objects` module and
//! `Pipeline::serve_http_object` (explicit indexed HTTP opt-in).

pub mod admin;
pub mod auth_v2;
pub mod authority;
pub mod budget;
#[cfg(feature = "connect")]
pub mod connect;
pub(crate) mod download;
mod error;
#[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
pub mod fs;
pub mod history_token;
#[cfg(feature = "remote-hooks")]
pub mod hooks;
#[cfg(feature = "http-objects")]
pub mod http_objects;
pub mod indexed;
pub mod limits;
#[cfg(any(test, feature = "memory"))]
mod memory;
mod op;
pub mod pipeline;
pub mod policy;
mod principal;
pub mod purge;
pub mod quota;
pub mod refs;
pub mod relay;
mod replay;
mod repo;
mod rt;
pub mod scanner_retrieval;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod storage_error;
pub mod store;
pub mod takedown;
pub mod telemetry;
pub mod timers;
pub mod upload;
pub mod url_token;

pub use error::{
    ADMISSION_CHALLENGE_TYPE, Code, ErrorDetail, InvalidHeader, Redacted, ServerError,
};
#[cfg(any(test, feature = "memory"))]
pub use memory::{MemoryBlobStore, MemoryFault, MemoryKv, MemoryPackSink};
pub use op::{
    AuthzFacts, Commitment, Creation, GrantRef, OpKind, Operation, PresenceRequirement, Procedure,
    RefUpdate, VerifiedAuth,
};
pub use policy::GrantConfig;
pub use principal::Principal;
pub use replay::{
    BeginUploadResult, ReplayDecision, ReplayKey, ReplayRecord, ReplayState, StoredRejection,
    StoredResult, UpdateRefResult, classify,
};
pub use repo::{Addressing, MultiAddressing, NamespaceKey, RepoId, RepoName, ResolvedRepo};
#[cfg(not(target_arch = "wasm32"))]
pub use rt::SystemClock;
pub use rt::{
    BoxFuture, BoxStream, Clock, Elapsed, ManualClock, ManualSleep, MaybeSend, MaybeSync, Sleep,
    Spawner, send_wrap, with_timeout,
};
pub use store::{
    Batch, BatchOutcome, BlobBody, BlobKey, BlobMeta, BlobNamespace, BlobStore, BoxError,
    ByteRange, CommitOutcome, ContentIndex, Cursor, Key, KeyClasses, MAX_BATCH_BYTES,
    MAX_BATCH_OPS, MAX_KEY_BYTES, MAX_SCAN_RANGES, MAX_VALUE_BYTES, MembershipMode,
    MultipartBlobStore, NamespaceStore, PackSink, PartRef, PartSink, Partition, PartitionStats,
    Precondition, RangeScan, ScanPage, StateCommitment, StoreCapabilities, StoreError,
    StoreMaintenance, UnsupportedPartSink, Value, Write, is_reserved_pack_keyspace,
};
pub use telemetry::{
    METRIC_LATENCY, METRIC_REQUESTS, METRIC_UPLOAD_BYTES, Metrics, NEVER_ECHO, NEVER_LOG,
    NoopMetrics, REDACTED_VALUE, Redactor, is_never_echo, is_never_log,
};
