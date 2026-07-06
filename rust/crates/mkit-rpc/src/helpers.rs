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
//!   `rpc_error_to_transport`, `map_update_ref_error`,
//!   `unexpected_frame`, `body_name`,
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
        RefWriteCondition::Any => (Vec::new(), RefExpectation::Any),
        RefWriteCondition::Missing => (Vec::new(), RefExpectation::Missing),
        RefWriteCondition::Match(h) => (h.to_vec(), RefExpectation::Match),
    }
}

/// Map a server `Error` reply to an `update_ref` request into a
/// [`TransportError`]. Shared by `mkit-transport-ssh` and
/// `mkit-transport-enc` so the two clients classify CAS conflicts
/// identically and cannot drift.
///
/// Per SPEC-TRANSPORT §4.2.1, the server signals a compare-and-swap
/// mismatch as `ERROR_CODE_INVALID_REQUEST` carrying the *current* ref
/// id in `details`. We treat that as [`TransportError::RefConflict`].
///
/// The bare `ERROR_CODE_INVALID_REQUEST` code alone is ambiguous: the
/// server reuses it for genuine bad requests (malformed ref, backend
/// failure) as well as CAS mismatches. To avoid masking a real error as
/// a conflict we only treat it as `RefConflict` when:
///   - the write carried a CAS precondition (`condition != Any`), and
///   - the error carries non-empty `details` (the documented current-id
///     payload that disambiguates a true CAS mismatch).
///
/// When `details` is absent we fall back to [`rpc_error_to_transport`]
/// so a genuine invalid-request surfaces its real message instead of a
/// misleading `RefConflict`. That fallback also covers the rare
/// conflict-then-ref-absent case (a `MATCH` expectation against a ref
/// that does not exist): the server has no current value to put in
/// `details`, so the failure surfaces as a `RemoteError` carrying the
/// server's descriptive message.
#[must_use]
pub fn map_update_ref_error(
    e: RpcError,
    condition: RefWriteCondition,
    transport: &str,
) -> TransportError {
    let is_invalid_request = e.code.is_some_and(|c| c == ErrorCode::InvalidRequest);
    let has_cas_details = e.details.as_deref().is_some_and(|d| !d.is_empty());
    if is_invalid_request && !matches!(condition, RefWriteCondition::Any) && has_cas_details {
        TransportError::RefConflict
    } else {
        rpc_error_to_transport(e, transport)
    }
}

/// Map a wire-level [`RpcError`] into a [`TransportError`]. `transport`
/// is a short tag (`"ssh"` / `"enc"`) baked into the catch-all
/// `RemoteError` message so logs say which transport surfaced the
/// failure.
///
/// Per SPEC-RPC §3.3 / §4, every `Error` frame MUST carry a known
/// non-zero `ErrorCode` — `code = 0` (`ERROR_CODE_UNSPECIFIED`) or an
/// absent `code` field is itself a protocol violation, not a
/// well-formed-but-uninteresting error. Receivers MUST treat it as
/// such rather than collapsing it into the generic `RemoteError` a
/// legitimate-but-unmapped code (e.g. `ERROR_CODE_INTERNAL`) would
/// produce, so a server that stops setting `code` is distinguishable
/// from one returning ordinary application errors.
#[must_use]
pub fn rpc_error_to_transport(e: RpcError, transport: &str) -> TransportError {
    if e.code.is_some_and(|c| c == ErrorCode::KeyNotFound) {
        return TransportError::PackNotFound;
    }
    if e.code.is_some_and(|c| c == ErrorCode::UserDeclined) {
        return TransportError::AccessDenied;
    }
    if e.code.is_none_or(|c| c == ErrorCode::Unspecified) {
        return TransportError::ProtocolError;
    }
    let msg = e.message.unwrap_or_default();
    if msg.is_empty() {
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
        let frame = signer_error_frame(ErrorCode::InvalidRequest, "bad");
        let bytes = frame.encode_to_vec();
        let decoded = SignerFrame::decode(&mut &bytes[..]).expect("decode");
        let Some(signer_frame::Body::Error(e)) = decoded.body else {
            panic!("expected Error body");
        };
        assert_eq!(e.code, Some(ErrorCode::InvalidRequest.into()));
        assert_eq!(e.message.as_deref(), Some("bad"));
        assert_eq!(e.details.as_deref(), Some(&[][..]));
    }

    #[test]
    fn ssh_error_frame_round_trips() {
        let frame = ssh_error_frame(ErrorCode::KeyNotFound, "missing");
        let bytes = frame.encode_to_vec();
        let decoded = SshFrame::decode(&mut &bytes[..]).expect("decode");
        let Some(ssh_frame::Body::Error(e)) = decoded.body else {
            panic!("expected Error body");
        };
        assert_eq!(e.code, Some(ErrorCode::KeyNotFound.into()));
        assert_eq!(e.message.as_deref(), Some("missing"));
    }

    #[test]
    fn cond_to_wire_encodes_any() {
        let (id, exp) = cond_to_wire(RefWriteCondition::Any);
        assert!(id.is_empty());
        assert_eq!(exp, RefExpectation::Any);
    }

    #[test]
    fn cond_to_wire_encodes_missing() {
        let (id, exp) = cond_to_wire(RefWriteCondition::Missing);
        assert!(id.is_empty());
        assert_eq!(exp, RefExpectation::Missing);
    }

    #[test]
    fn cond_to_wire_encodes_match() {
        let h: Hash = [7u8; 32];
        let (id, exp) = cond_to_wire(RefWriteCondition::Match(h));
        assert_eq!(id, h.to_vec());
        assert_eq!(exp, RefExpectation::Match);
    }

    #[test]
    fn rpc_error_to_transport_maps_known_codes() {
        let not_found = RpcError::default()
            .with_code(ErrorCode::KeyNotFound)
            .with_message("missing pack");
        assert!(matches!(
            rpc_error_to_transport(not_found, "ssh"),
            TransportError::PackNotFound
        ));

        let declined = RpcError::default().with_code(ErrorCode::UserDeclined);
        assert!(matches!(
            rpc_error_to_transport(declined, "ssh"),
            TransportError::AccessDenied
        ));
    }

    #[test]
    fn rpc_error_to_transport_falls_back_with_label() {
        let empty = RpcError::default().with_code(ErrorCode::InvalidRequest);
        match rpc_error_to_transport(empty, "enc") {
            TransportError::RemoteError(msg) => assert!(msg.contains("enc server")),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn rpc_error_to_transport_treats_zero_code_as_protocol_error() {
        // SPEC-RPC §3.3/§4: ERROR_CODE_UNSPECIFIED (wire 0) is itself a
        // protocol violation, not a well-formed-but-generic error — it
        // must be distinguishable from a legitimate unmapped code like
        // ERROR_CODE_INTERNAL, even when a message is present.
        let zero_with_message = RpcError::default()
            .with_code(ErrorCode::Unspecified)
            .with_message("something went wrong");
        assert!(matches!(
            rpc_error_to_transport(zero_with_message, "ssh"),
            TransportError::ProtocolError
        ));
    }

    #[test]
    fn rpc_error_to_transport_treats_absent_code_as_protocol_error() {
        // A completely absent `code` field (never set by a conforming
        // producer) must classify the same as the explicit zero value —
        // both mean "no known non-zero ErrorCode was carried".
        let absent = RpcError::default().with_message("no code at all");
        assert_eq!(absent.code, None);
        assert!(matches!(
            rpc_error_to_transport(absent, "enc"),
            TransportError::ProtocolError
        ));
    }

    #[test]
    fn rpc_error_to_transport_distinguishes_unspecified_from_mapped_internal_error() {
        // A legitimate, mapped-but-uninteresting code (INTERNAL = 99)
        // must still fall through to the generic RemoteError path — only
        // the zero/absent case gets the stricter ProtocolError treatment.
        let internal = RpcError::default()
            .with_code(ErrorCode::Internal)
            .with_message("boom");
        match rpc_error_to_transport(internal, "ssh") {
            TransportError::RemoteError(msg) => assert_eq!(msg, "boom"),
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
