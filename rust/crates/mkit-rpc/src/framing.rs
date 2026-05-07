// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Length-prefixed protobuf framing for signer + SSH protocols.

use buffa::Message;

use crate::MAX_FRAME_BYTES;

/// Errors emitted by the framing layer. Wire-protocol errors (a frame
/// longer than [`MAX_FRAME_BYTES`], a truncated read) are distinct
/// from decode errors so callers can decide whether to close the
/// connection or just surface a parse failure.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The 4-byte length prefix could not be read in full.
    #[error("frame length prefix truncated")]
    LengthTruncated,

    /// The advertised length exceeded [`MAX_FRAME_BYTES`]. Receivers
    /// MUST close the connection rather than continue reading.
    #[error("frame length {0} exceeds MAX_FRAME_BYTES")]
    LengthTooLarge(u32),

    /// The frame body could not be read in full (peer closed, IO
    /// error, etc.).
    #[error("frame body truncated: expected {expected} bytes, got {actual}")]
    BodyTruncated { expected: u32, actual: usize },

    /// The frame body did not decode as the expected message type.
    #[error("frame decode failed")]
    DecodeFailed,

    /// Underlying IO error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Writes a single framed protobuf message to `w`. The encoded length
/// is prepended as a little-endian u32; if it exceeds
/// [`MAX_FRAME_BYTES`] the call returns [`FrameError::LengthTooLarge`]
/// without writing anything.
pub fn write_frame<W, M>(w: &mut W, msg: &M) -> Result<(), FrameError>
where
    W: std::io::Write,
    M: Message,
{
    let body = msg.encode_to_vec();
    let len: u32 = body
        .len()
        .try_into()
        .map_err(|_| FrameError::LengthTooLarge(u32::MAX))?;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::LengthTooLarge(len));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&body)?;
    w.flush()?;
    Ok(())
}

/// Reads a single framed protobuf message from `r`. Enforces the
/// [`MAX_FRAME_BYTES`] cap; receivers MUST close the connection on
/// any [`FrameError::LengthTooLarge`].
pub fn read_frame<R, M>(r: &mut R) -> Result<M, FrameError>
where
    R: std::io::Read,
    M: Message + Default,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::LengthTruncated
        } else {
            FrameError::Io(e)
        }
    })?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::LengthTooLarge(len));
    }

    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::BodyTruncated {
                expected: len,
                actual: 0,
            }
        } else {
            FrameError::Io(e)
        }
    })?;

    M::decode_from_slice(&body).map_err(|_| FrameError::DecodeFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mkit::rpc::v1::signer::{SignerFrame, signer_frame};
    use crate::mkit::rpc::v1::{Error, ErrorCode};
    use std::io::Cursor;

    fn err_frame(code: ErrorCode, msg: &str) -> SignerFrame {
        SignerFrame {
            body: Some(signer_frame::Body::Error(Box::new(Error {
                code: Some(code.into()),
                message: Some(msg.into()),
                details: Some(Vec::new()),
                ..Default::default()
            }))),
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_signer_error_frame() {
        let in_msg = err_frame(ErrorCode::ERROR_CODE_USER_DECLINED, "user said no");
        let mut buf = Vec::new();
        write_frame(&mut buf, &in_msg).expect("write");

        // Frame layout: 4-byte LE length + protobuf body.
        let advertised = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(advertised as usize, buf.len() - 4);

        let mut cur = Cursor::new(buf);
        let out: SignerFrame = read_frame(&mut cur).expect("read");
        assert_eq!(in_msg, out);
    }

    #[test]
    fn read_rejects_oversized_frame() {
        // Hand-craft a length prefix > MAX_FRAME_BYTES with no body.
        let mut buf = Vec::with_capacity(4);
        buf.extend_from_slice(&(MAX_FRAME_BYTES + 1).to_le_bytes());
        let mut cur = Cursor::new(buf);
        match read_frame::<_, SignerFrame>(&mut cur) {
            Err(FrameError::LengthTooLarge(n)) => assert_eq!(n, MAX_FRAME_BYTES + 1),
            other => panic!("expected LengthTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn read_rejects_truncated_length_prefix() {
        let buf = vec![0x01, 0x00];
        let mut cur = Cursor::new(buf);
        match read_frame::<_, SignerFrame>(&mut cur) {
            Err(FrameError::LengthTruncated) => {}
            other => panic!("expected LengthTruncated, got {other:?}"),
        }
    }
}
