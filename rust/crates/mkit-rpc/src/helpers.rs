// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small frame-construction helpers shared by signer subprocesses and
//! the SSH server. These are pure builders — no I/O — so callers can
//! still choose how / whether to write them. Use [`super::write_frame`]
//! to put them on the wire.

use crate::mkit::rpc::v1::Error as RpcError;
use crate::mkit::rpc::v1::ErrorCode;
use crate::mkit::rpc::v1::signer::{SignerFrame, signer_frame};
use crate::mkit::rpc::v1::ssh::{SshFrame, ssh_frame};

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
}
