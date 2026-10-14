#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! [`ConnectTransport`] preserves synchronous Transport APIs and native host
//! configuration over `mkit-client`'s canonical Connect RPC implementation.
//! Repository operations borrow `mkit-sync::ClientSource`; the host supplies
//! credential selection, admission recovery, scheduling and durable receipts.
//!
//! Generated messages and Connect bindings remain compatibility reexports
//! from `mkit-rpc`, owned by the canonical transport schema.
//!
//! See [`docs/specs/SPEC-TRANSPORT-CONNECT.md`][spec] for the full wire
//! contract (verb mapping, CAS semantics, error-code mapping, streaming
//! design).
//!
//! [spec]: https://github.com/officialunofficial/mkit/blob/main/docs/specs/SPEC-TRANSPORT-CONNECT.md

pub mod admission;
mod client;
pub mod envelope;
mod error;
pub mod grant;
mod host;
mod part_receipts;
pub mod pooled_http;
mod receipt;
mod status;
pub mod tls;

/// Shared generated `mkit.transport.v1` messages and Connect service types.
pub mod proto {
    pub use mkit_rpc::transport::mkit;
}

pub use client::{
    Completion, ConnectTransport, PACK_TRANSFER_TIMEOUT, PENDING_INTERRUPTED_MESSAGE, PendingEvent,
    ServerInfoView, TOKEN_ENV, UNARY_TIMEOUT, UploadEvent, UrlIdentityError, VisibilityChoice,
    VisibilityRequest, audience_from_url, remote_identity_from_url, repository_identity_from_url,
};
pub use envelope::EnvelopeSigner;
pub use grant::{GrantCondition, GrantOperation, GrantRef, GrantRequest, GrantSource};
pub use part_receipts::{MemoryPartReceiptStore, PartReceiptStore, StoredPart, TicketMetadata};
pub use receipt::{AdmissionReceipt, ReceiptValue};

// Re-exported so integration tests (and in-tree servers and conformance
// suites) can build request/response messages and register the generated
// `TransportService` trait without reaching into this crate's private
// `proto` module.
#[doc(hidden)]
pub mod generated {
    pub use crate::proto::mkit::transport::v1::*;
}
