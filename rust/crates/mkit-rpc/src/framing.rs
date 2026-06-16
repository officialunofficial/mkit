// Length-prefixed protobuf framing for signer + SSH protocols.

use buffa::{DecodeOptions, Message};

use crate::MAX_FRAME_BYTES;

/// Recursion limit applied when decoding frame bodies. The deepest
/// message in signer.proto / ssh.proto nests four levels (frame →
/// oneof body → response → repeated entry); 16 leaves generous
/// headroom for schema evolution while staying far below buffa's
/// default of 100.
pub const FRAME_RECURSION_LIMIT: u32 = 16;

/// Decode options for a single frame body: recursion capped at
/// [`FRAME_RECURSION_LIMIT`] and size capped at [`MAX_FRAME_BYTES`].
///
/// [`read_frame`] already bounds the input buffer to
/// [`MAX_FRAME_BYTES`] before decoding; stating the cap here as well
/// keeps the bound attached to the decode itself, so paths that
/// receive frame bodies through other channels (e.g. the encrypted
/// transport, where the cipher layer does the framing) enforce the
/// same limits.
#[must_use]
pub fn frame_decode_options() -> DecodeOptions {
    DecodeOptions::new()
        .with_recursion_limit(FRAME_RECURSION_LIMIT)
        .with_max_message_size(MAX_FRAME_BYTES as usize)
}

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

    // Read the body with a manual fill loop (rather than `read_exact`) so
    // a short read reports the TRUE number of bytes received in
    // `BodyTruncated.actual` instead of a hardcoded 0.
    let mut body = vec![0u8; len as usize];
    let mut filled = 0usize;
    while filled < body.len() {
        match r.read(&mut body[filled..]) {
            Ok(0) => {
                return Err(FrameError::BodyTruncated {
                    expected: len,
                    actual: filled,
                });
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FrameError::Io(e)),
        }
    }

    frame_decode_options()
        .decode_from_slice(&body)
        .map_err(|_| FrameError::DecodeFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mkit::rpc::v1::signer::{SignerFrame, signer_frame};
    use crate::mkit::rpc::v1::{Error, ErrorCode};
    use std::io::Cursor;

    fn err_frame(code: ErrorCode, msg: &str) -> SignerFrame {
        SignerFrame {
            body: Some(signer_frame::Body::Error(Box::new(
                Error::default()
                    .with_code(code)
                    .with_message(msg)
                    .with_details(Vec::new()),
            ))),
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip_signer_error_frame() {
        let in_msg = err_frame(ErrorCode::UserDeclined, "user said no");
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

    #[test]
    fn decode_options_reject_oversized_body_even_without_framing() {
        use crate::mkit::rpc::v1::signer::SignRequest;

        // A frame whose encoding exceeds MAX_FRAME_BYTES. read_frame
        // never sees one (the length prefix is checked first), but
        // decode paths that receive bodies through other channels —
        // e.g. the encrypted transport, where the cipher layer does
        // the framing — rely on frame_decode_options for the bound.
        // The bare decoder accepts it; the capped decoder must not.
        let frame = SignerFrame {
            body: Some(signer_frame::Body::SignRequest(Box::new(
                SignRequest::default().with_payload(vec![0u8; MAX_FRAME_BYTES as usize + 1]),
            ))),
            ..Default::default()
        };
        let bytes = frame.encode_to_vec();
        assert!(SignerFrame::decode_from_slice(&bytes).is_ok());
        assert!(
            frame_decode_options()
                .decode_from_slice::<SignerFrame>(&bytes)
                .is_err(),
            "decode cap must reject a body over MAX_FRAME_BYTES"
        );
    }

    #[test]
    fn body_truncated_reports_true_actual_count() {
        // Advertise a 10-byte body but supply only 3 bytes. The error
        // must report the actual count (3), not a hardcoded 0.
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_le_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // 3 body bytes only
        let mut cur = Cursor::new(buf);
        match read_frame::<_, SignerFrame>(&mut cur) {
            Err(FrameError::BodyTruncated { expected, actual }) => {
                assert_eq!(expected, 10);
                assert_eq!(actual, 3, "actual byte count must reflect bytes read");
            }
            other => panic!("expected BodyTruncated, got {other:?}"),
        }
    }
}
