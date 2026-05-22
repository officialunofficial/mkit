// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small frame-construction helpers shared by signer subprocesses and
//! transports (SSH + encrypted-stream). These are pure builders — no
//! I/O — so callers can still choose how / whether to write them. Use
//! [`super::write_frame`] to put them on the wire.
//!
//! Two groups live here:
//!
//! * Error-frame builders (`signer_error_frame`, `ssh_error_frame`):
//!   used by signer subprocesses and the SSH server to construct
//!   per-request `Error` responses.
//!
//! * Transport-side frame helpers (`cond_to_wire`,
//!   `rpc_error_to_transport`, `unexpected_frame`, `body_name`,
//!   `ref_entry_to_ref`, plus the `MAX_REF_NAME` and `CHUNK_DATA_MAX`
//!   limits): shared between `mkit-transport-ssh` and
//!   `mkit-transport-enc`. Both transports speak the same
//!   `SshFrame` wire, so the response-parsing helpers are
//!   transport-independent; the only thing that differs is the
//!   advisory string baked into a `RemoteError`, which is parameterised
//!   via a `&str` label (e.g. `"ssh"` / `"enc"`).

use crate::mkit::rpc::v1::Error as RpcError;
use crate::mkit::rpc::v1::ErrorCode;
use crate::mkit::rpc::v1::signer::{SignerFrame, signer_frame};
use crate::mkit::rpc::v1::ssh::{
    RefExpectation, SshFrame, list_refs_response::RefEntry, ssh_frame,
};

use mkit_core::hash::Hash;
use mkit_core::protocol::{TransportError, TransportResult};
use mkit_core::refs::{Ref, RefWriteCondition, validate_ref_name};

// ---------------------------------------------------------------------------
// Error-frame builders (used by signer subprocesses + SSH server)
// ---------------------------------------------------------------------------

/// Build a [`SignerFrame`] carrying a per-request `Error`. All three
/// reference signers (file / tpm / ctap) share this shape; factored
/// here so it stays in lockstep with the proto schema.
#[inline]
pub fn signer_error_frame(code: ErrorCode, message: impl Into<String>) -> SignerFrame {
    SignerFrame {
        body: Some(signer_frame::Body::Error(Box::new(
            RpcError::default()
                .with_code(code)
                .with_message(message)
                .with_details(Vec::new()),
        ))),
        ..Default::default()
    }
}

/// Build an [`SshFrame`] carrying a server-side `Error`. Mirror of
/// [`signer_error_frame`] for the SSH wire.
#[inline]
pub fn ssh_error_frame(code: ErrorCode, message: impl Into<String>) -> SshFrame {
    SshFrame {
        body: Some(ssh_frame::Body::Error(Box::new(
            RpcError::default()
                .with_code(code)
                .with_message(message)
                .with_details(Vec::new()),
        ))),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Transport-side limits + frame helpers (shared by transport-ssh / -enc)
// ---------------------------------------------------------------------------

/// Maximum combined ref / prefix name length accepted by client-side
/// validation before sending a frame. The 4 KiB bound matches the
/// server-side cap so the client can fail fast without a round-trip.
pub const MAX_REF_NAME: usize = 4096;

/// Per-frame pack-data segment cap. Pack uploads chunk the body into
/// frames this size so the framing layer's 1 MiB length cap
/// accommodates protobuf overhead on top of the data segment.
pub const CHUNK_DATA_MAX: usize = 800 * 1024;

/// Encode a [`RefWriteCondition`] into the two on-wire fields the
/// `UpdateRef` message carries: the (often empty) `expected_id` bytes
/// and the `RefExpectation` enum. Production and test paths share this
/// so the test cannot drift from the production encoding. See
/// SPEC-TRANSPORT §4.2.1.
#[must_use]
pub fn cond_to_wire(c: RefWriteCondition) -> (Vec<u8>, RefExpectation) {
    match c {
        RefWriteCondition::Any => (Vec::new(), RefExpectation::REF_EXPECTATION_ANY),
        RefWriteCondition::Missing => (Vec::new(), RefExpectation::REF_EXPECTATION_MISSING),
        RefWriteCondition::Match(h) => (h.to_vec(), RefExpectation::REF_EXPECTATION_MATCH),
    }
}

/// Map a wire-level [`RpcError`] into a [`TransportError`]. `transport`
/// is a short tag (`"ssh"` / `"enc"`) baked into the catch-all
/// `RemoteError` message so logs say which transport surfaced the
/// failure.
#[must_use]
pub fn rpc_error_to_transport(e: RpcError, transport: &str) -> TransportError {
    let code = e.code.as_ref().map_or(0, buffa::EnumValue::to_i32);
    let msg = e.message.unwrap_or_default();
    if code == ErrorCode::ERROR_CODE_KEY_NOT_FOUND as i32 {
        TransportError::PackNotFound
    } else if code == ErrorCode::ERROR_CODE_USER_DECLINED as i32 {
        TransportError::AccessDenied
    } else if msg.is_empty() {
        TransportError::RemoteError(format!("{transport} server returned an unspecified error"))
    } else {
        TransportError::RemoteError(msg)
    }
}

/// Build a [`TransportError::RemoteError`] reporting an unexpected
/// frame variant. `want` is the human-readable body name the caller
/// expected, `got` is whatever it actually received.
#[must_use]
pub fn unexpected_frame(
    transport: &str,
    want: &str,
    got: Option<ssh_frame::Body>,
) -> TransportError {
    TransportError::RemoteError(format!(
        "{transport} server returned {} when {want} was expected",
        body_name(&got),
    ))
}

/// Stringify an `SshFrame` body variant. Used for diagnostic messages
/// in [`unexpected_frame`] and from transport tests that assert on the
/// rejected body.
#[must_use]
pub fn body_name(b: &Option<ssh_frame::Body>) -> &'static str {
    use ssh_frame::Body;
    match b {
        Some(Body::Hello(_)) => "hello",
        Some(Body::HelloResponse(_)) => "hello_response",
        Some(Body::Error(_)) => "error",
        Some(Body::Close(_)) => "close",
        Some(Body::ListRefs(_)) => "list_refs",
        Some(Body::ListRefsResponse(_)) => "list_refs_response",
        Some(Body::ReadRef(_)) => "read_ref",
        Some(Body::ReadRefResponse(_)) => "read_ref_response",
        Some(Body::UpdateRef(_)) => "update_ref",
        Some(Body::UpdateRefResponse(_)) => "update_ref_response",
        Some(Body::PackExists(_)) => "pack_exists",
        Some(Body::PackExistsResponse(_)) => "pack_exists_response",
        Some(Body::UploadPack(_)) => "upload_pack",
        Some(Body::UploadPackResponse(_)) => "upload_pack_response",
        Some(Body::DownloadPack(_)) => "download_pack",
        Some(Body::DownloadPackHeader(_)) => "download_pack_header",
        Some(Body::PackChunk(_)) => "pack_chunk",
        None => "(empty body)",
    }
}

/// Validate + convert a wire-level [`RefEntry`] into a [`Ref`]. Fails
/// the response if the name violates SPEC-REFS §3 or the object id
/// isn't exactly 32 bytes.
///
/// # Errors
///
/// * [`TransportError::InvalidRef`] — name is empty or fails the
///   ref-name grammar.
/// * [`TransportError::InvalidResponse`] — object id is not 32 bytes.
pub fn ref_entry_to_ref(e: RefEntry) -> TransportResult<Ref> {
    let name = e.name.unwrap_or_default();
    if !validate_ref_name(&name) {
        return Err(TransportError::InvalidRef(name));
    }
    let oid = e.object_id.unwrap_or_default();
    if oid.len() != 32 {
        return Err(TransportError::InvalidResponse);
    }
    let mut h: Hash = [0u8; 32];
    h.copy_from_slice(&oid);
    Ok(Ref {
        name,
        hash: Some(h),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message;

    #[test]
    fn signer_error_frame_round_trips() {
        let frame = signer_error_frame(ErrorCode::ERROR_CODE_INVALID_REQUEST, "bad");
        let bytes = frame.encode_to_vec();
        let decoded = SignerFrame::decode(&mut &bytes[..]).expect("decode");
        let Some(signer_frame::Body::Error(e)) = decoded.body else {
            panic!("expected Error body");
        };
        assert_eq!(
            e.code.as_ref().map(buffa::EnumValue::to_i32),
            Some(ErrorCode::ERROR_CODE_INVALID_REQUEST as i32),
        );
        assert_eq!(e.message.as_deref(), Some("bad"));
        assert_eq!(e.details.as_deref(), Some(&[][..]));
    }

    #[test]
    fn ssh_error_frame_round_trips() {
        let frame = ssh_error_frame(ErrorCode::ERROR_CODE_KEY_NOT_FOUND, "missing");
        let bytes = frame.encode_to_vec();
        let decoded = SshFrame::decode(&mut &bytes[..]).expect("decode");
        let Some(ssh_frame::Body::Error(e)) = decoded.body else {
            panic!("expected Error body");
        };
        assert_eq!(
            e.code.as_ref().map(buffa::EnumValue::to_i32),
            Some(ErrorCode::ERROR_CODE_KEY_NOT_FOUND as i32),
        );
        assert_eq!(e.message.as_deref(), Some("missing"));
    }

    #[test]
    fn cond_to_wire_encodes_any() {
        let (id, exp) = cond_to_wire(RefWriteCondition::Any);
        assert!(id.is_empty());
        assert_eq!(exp, RefExpectation::REF_EXPECTATION_ANY);
    }

    #[test]
    fn cond_to_wire_encodes_missing() {
        let (id, exp) = cond_to_wire(RefWriteCondition::Missing);
        assert!(id.is_empty());
        assert_eq!(exp, RefExpectation::REF_EXPECTATION_MISSING);
    }

    #[test]
    fn cond_to_wire_encodes_match() {
        let h: Hash = [7u8; 32];
        let (id, exp) = cond_to_wire(RefWriteCondition::Match(h));
        assert_eq!(id, h.to_vec());
        assert_eq!(exp, RefExpectation::REF_EXPECTATION_MATCH);
    }

    #[test]
    fn rpc_error_to_transport_maps_known_codes() {
        let not_found = RpcError::default()
            .with_code(ErrorCode::ERROR_CODE_KEY_NOT_FOUND)
            .with_message("missing pack");
        assert!(matches!(
            rpc_error_to_transport(not_found, "ssh"),
            TransportError::PackNotFound
        ));

        let declined = RpcError::default().with_code(ErrorCode::ERROR_CODE_USER_DECLINED);
        assert!(matches!(
            rpc_error_to_transport(declined, "ssh"),
            TransportError::AccessDenied
        ));
    }

    #[test]
    fn rpc_error_to_transport_falls_back_with_label() {
        let empty = RpcError::default().with_code(ErrorCode::ERROR_CODE_INVALID_REQUEST);
        match rpc_error_to_transport(empty, "enc") {
            TransportError::RemoteError(msg) => assert!(msg.contains("enc server")),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn unexpected_frame_includes_labels() {
        let err = unexpected_frame("ssh", "UpdateRefResponse", None);
        match err {
            TransportError::RemoteError(msg) => {
                assert!(msg.contains("ssh server"));
                assert!(msg.contains("UpdateRefResponse"));
                assert!(msg.contains("(empty body)"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn ref_entry_to_ref_rejects_bad_oid_length() {
        let bad = RefEntry::default()
            .with_name("refs/heads/main")
            .with_object_id(vec![1, 2, 3]);
        assert!(matches!(
            ref_entry_to_ref(bad),
            Err(TransportError::InvalidResponse)
        ));
    }

    #[test]
    fn ref_entry_to_ref_rejects_invalid_name() {
        let bad = RefEntry::default()
            .with_name("not a ref")
            .with_object_id(vec![0u8; 32]);
        assert!(matches!(
            ref_entry_to_ref(bad),
            Err(TransportError::InvalidRef(_))
        ));
    }

    #[test]
    fn ref_entry_to_ref_accepts_valid() {
        let oid = vec![9u8; 32];
        let ok = RefEntry::default()
            .with_name("refs/heads/main")
            .with_object_id(oid.clone());
        let r = ref_entry_to_ref(ok).expect("valid");
        assert_eq!(r.name, "refs/heads/main");
        assert_eq!(r.hash.unwrap().to_vec(), oid);
    }
}
