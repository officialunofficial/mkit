#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! This crate is runtime-agnostic: it compiles for the host and for
//! `wasm32-unknown-unknown`, never reads the wall clock directly (see
//! [`Clock`]) and never spawns on a concrete executor (see [`Spawner`]).
//! The shared vocabulary is re-exported at the crate root from private
//! modules. The protocol logic lives in public modules, so call sites name
//! the protocol they apply (`refs::evaluate_cas`, `quota::evaluate_quota`);
//! the quota value types are also at the root.

pub mod download;
mod error;
mod op;
mod principal;
pub mod quota;
pub mod refs;
mod repo;
mod rt;
pub mod storage_error;
mod telemetry;

pub use error::{
    ADMISSION_CHALLENGE_TYPE, Code, ErrorDetail, InvalidHeader, Redacted, ServerError,
};
pub use op::{
    AuthzFacts, Commitment, GrantRef, OpKind, Operation, Procedure, RefUpdate, VerifiedAuth,
};
pub use principal::Principal;
pub use quota::{QuotaLimits, QuotaScope, QuotaState};
pub use repo::{Addressing, NamespaceKey, RepoId, RepoName};
#[cfg(not(target_arch = "wasm32"))]
pub use rt::SystemClock;
pub use rt::{BoxFuture, BoxStream, Clock, ManualClock, MaybeSend, MaybeSync, Spawner, send_wrap};
pub use telemetry::{
    METRIC_LATENCY, METRIC_REQUESTS, METRIC_UPLOAD_BYTES, Metrics, NEVER_ECHO, NEVER_LOG,
    NoopMetrics, REDACTED_VALUE, Redactor, is_never_echo, is_never_log,
};
