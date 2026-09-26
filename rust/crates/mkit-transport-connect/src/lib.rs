#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::print_stdout, clippy::print_stderr))]
#![doc = include_str!("../README.md")]
//!
//! `mkit.transport.v1.TransportService` (SPEC-TRANSPORT-CONNECT) client:
//! [`ConnectTransport`], a non-wasm ConnectRPC client implementing
//! [`mkit_core::protocol::Transport`] itself, used by `mkit-cli`'s
//! `remote_dispatch` for `mkit+https://` / loopback `mkit+http://`.
//!
//! The server is not in this crate: `mkit-server` (`mkit-server-native`,
//! over `mkit-server`'s pipeline) serves `mkit.transport.v1`. The `server`
//! feature and its `router`/`serve`/`TransportServer`/`map_transport_error`
//! API were removed with `mkit serve --http`.
//!
//! The client is generated from the canonical
//! `<repo-root>/proto/mkit/transport/v1/transport.proto` (see `build.rs` —
//! no duplicated proto, matching `mkit-repo-client`'s pattern for
//! `mkit.repo.v1`).
//!
//! See [`docs/specs/SPEC-TRANSPORT-CONNECT.md`][spec] for the full wire
//! contract (verb mapping, CAS semantics, error-code mapping, streaming
//! design).
//!
//! [spec]: https://github.com/officialunofficial/mkit/blob/main/docs/specs/SPEC-TRANSPORT-CONNECT.md

mod client;
pub mod envelope;
mod error;
mod executor;

/// Generated `mkit.transport.v1` message + Connect service types, compiled
/// directly from the canonical `<repo-root>/proto/mkit/transport/v1/transport.proto`
/// (see `build.rs` — no duplicated proto, matching `mkit-repo-client`'s
/// pattern for `mkit.repo.v1`).
pub mod proto {
    // `::connectrpc` required: the generated file declares `pub mod
    // connectrpc` inside this module, which would shadow the crate name if
    // relative.
    ::connectrpc::include_generated!();
}

pub use client::{ConnectTransport, PACK_TRANSFER_TIMEOUT, TOKEN_ENV, UNARY_TIMEOUT};
pub use envelope::EnvelopeSigner;

// Re-exported so integration tests (and in-tree servers and conformance
// suites) can build request/response messages and register the generated
// `TransportService` trait without reaching into this crate's private
// `proto` module.
#[doc(hidden)]
pub mod generated {
    pub use crate::proto::mkit::transport::v1::*;
}
