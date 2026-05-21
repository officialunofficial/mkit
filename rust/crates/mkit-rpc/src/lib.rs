// SPDX-License-Identifier: MIT OR Apache-2.0

//! Versioned wire protocols for mkit cross-system speech.
//!
//! mkit-rpc owns the schemas mkit uses to talk to processes outside
//! its address space:
//!
//! - **External signers** (`signer.proto`): mkit-cli ↔ a subprocess
//!   signer (file, FIDO2, TPM, future hardware backends).
//! - **SSH transport** (`ssh.proto`): mkit-cli ↔ a remote
//!   `mkit-server` over an `ssh(1)` child process.
//!
//! Shared vocabulary (`common.proto`) — algorithms, key forms, error
//! codes, protocol-version negotiation — is re-exported at the crate
//! root for convenience.
//!
//! ## Wire framing
//!
//! Both protocols use the same length-prefixed framing:
//!
//! ```text
//! [u32 LE length][N bytes protobuf-encoded Frame]
//! ```
//!
//! [`MAX_FRAME_BYTES`] caps the length at 1 MiB. Larger frames are
//! a protocol error and the connection MUST be closed.
//!
//! ## Stability
//!
//! The schemas are frozen for the v0.1.x line at protocol version 1.
//! Wire-compatible additions (new enum values, new optional fields,
//! new oneof variants) ship as patches. Breaking changes bump the
//! protocol-version integer in `common.proto` and introduce sibling
//! `signer2.proto` / `ssh2.proto` files rather than mutating v1.

#![cfg_attr(docsrs, feature(doc_cfg))]

// Generated protobuf modules. `_includes.rs` is emitted by
// buffa-build; it sets up the module tree for common.proto,
// signer.proto, ssh.proto under `mkit::rpc::v1`.
include!(concat!(env!("OUT_DIR"), "/_includes.rs"));

/// Maximum length of a single framed protobuf message in bytes.
/// Both directions of both protocols enforce this cap; receivers
/// MUST close the connection on a longer frame.
pub const MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// The protocol version mkit v0.1.x speaks. Aliased here so callers
/// don't need to chase the generated module path.
pub const PROTOCOL_VERSION: i32 = crate::mkit::rpc::v1::ProtocolVersion::PROTOCOL_VERSION_1 as i32;

mod framing;
mod helpers;
pub use framing::{FrameError, read_frame, write_frame};
pub use helpers::{signer_error_frame, ssh_error_frame};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_constant_is_one() {
        // Wire-load-bearing. v0.1.0 ships PROTOCOL_VERSION = 1.
        // If this assert fails, common.proto was edited in a way
        // that breaks the protocol contract — bump the integer
        // explicitly rather than letting codegen drift.
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn max_frame_bytes_is_one_mib() {
        assert_eq!(MAX_FRAME_BYTES, 1024 * 1024);
    }
}
