//! mkit transport protocol — the 7-verb abstract interface, error
//! taxonomy, SSH wire framing, and retry/backoff policy.
//!
//! Wire-format authority: `docs/SPEC-TRANSPORT.md` — change the spec
//! and this module in the same PR.
//!
//! The trait is object-safe: method signatures do not introduce
//! generics, so callers can hold a `Box<dyn Transport>` and swap
//! implementations at runtime.

// SPEC-TRANSPORT §8 calls out the exponential ladder in seconds
// (1, 2, 4, …, 300). Expressing those values with `Duration::from_secs`
// is deliberate — switching to `from_mins` loses the one-to-one match
// with the spec text.
#![allow(clippy::duration_suboptimal_units)]

use core::fmt;
use core::time::Duration;

use crate::hash::{FromHexError, Hash, to_hex};
use crate::refs::Ref;
pub use crate::refs::RefWriteCondition;

// ---------------------------------------------------------------------------
// SSH wire framing constants — SPEC-TRANSPORT §7
// ---------------------------------------------------------------------------

/// Maximum SSH payload length in a single frame (16 MiB).
///
/// Frames larger than this are rejected both on encode and on decode.
/// SPEC-TRANSPORT §7.1: "Larger payloads (e.g. packs > 16 MiB) use
/// repeated frames — SSH transport does NOT fragment". v1 treats this
/// as a hard error rather than silently truncating.
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Header size for every SSH frame: opcode/status (1) + `payload_len` u32 LE (4).
pub const FRAME_HEADER_LEN: usize = 1 + 4;

// -- Client → server opcodes -------------------------------------------------

/// `0x00` — mandatory first frame on every connection; carries the
/// protocol version handshake (SPEC-TRANSPORT §7.4).
pub const OP_HELLO: u8 = 0x00;
/// `0x01` — upload a packfile. Payload = `[32 digest][pack bytes]`.
pub const OP_UPLOAD_PACK: u8 = 0x01;
/// `0x02` — download a packfile by digest. Payload = `[32 digest]`.
pub const OP_DOWNLOAD_PACK: u8 = 0x02;
/// `0x03` — HEAD-check a pack by digest. Payload = `[32 digest]`.
pub const OP_PACK_EXISTS: u8 = 0x03;
/// `0x04` — unconditional ref write. Payload = `[u16 LE name_len][name][32 hash]`.
pub const OP_WRITE_REF: u8 = 0x04;
/// `0x05` — CAS ref write. Payload = `[condition byte][u16 LE name_len][name][32 hash]`
/// with `condition ∈ {0x00 ANY, 0x01 MISSING, 0x02 MATCH}` and an
/// additional 32-byte expected-hash suffix when `MATCH`.
pub const OP_UPDATE_REF: u8 = 0x05;
/// `0x06` — read a ref. Payload = `[u16 LE name_len][name]`.
pub const OP_READ_REF: u8 = 0x06;
/// `0x07` — list refs under a prefix. Payload = `[u16 LE prefix_len][prefix]`.
pub const OP_LIST_REFS: u8 = 0x07;
/// `0xFF` — graceful shutdown. Payload empty.
pub const OP_CLOSE: u8 = 0xFF;

// -- OP_UPDATE_REF condition byte values -------------------------------------

/// `.any` — clobber, no precondition.
pub const COND_ANY: u8 = 0x00;
/// `.missing` — write only if the ref is absent.
pub const COND_MISSING: u8 = 0x01;
/// `.match(H)` — write only if the ref currently contains `H`.
pub const COND_MATCH: u8 = 0x02;

// -- Server → client status bytes --------------------------------------------

/// `0x00` — request succeeded.
pub const STATUS_OK: u8 = 0x00;
/// `0x01` — request failed; payload is advisory UTF-8.
pub const STATUS_ERROR: u8 = 0x01;
/// `0x02` — "absent" (e.g. `read_ref` on a missing ref, or `download_pack`
/// on a missing pack). Payload empty.
pub const STATUS_NULL: u8 = 0x02;
/// `0x03` — server does not speak the client's `proto_version`.
pub const STATUS_UNSUPPORTED: u8 = 0x03;

// -- HELLO handshake constants ----------------------------------------------

/// Current SSH wire protocol version emitted in `OP_HELLO`.
pub const SSH_PROTO_VERSION: u8 = 0x01;
/// ASCII binary name every `mkit` client advertises in `OP_HELLO`.
pub const SSH_BINARY_NAME: &str = "mkit";
/// Cap on the `binary_name_len` byte (SPEC-TRANSPORT §7.4).
pub const HELLO_NAME_MAX: usize = 32;
/// Cap on the `client_version_len` / `server_version_len` byte.
pub const HELLO_VERSION_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// Errors that any transport may surface across the [`Transport`]
/// boundary. Implementations MAY wrap transport-specific errors
/// internally but MUST map them to one of these variants before
/// returning.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// `download_pack` called on a digest the remote does not hold.
    #[error("pack not found on remote")]
    PackNotFound,
    /// Authentication or ACL failure (HTTP 401/403, SSH auth refusal,
    /// S3 `SignatureDoesNotMatch`, …).
    #[error("access denied by remote")]
    AccessDenied,
    /// Catch-all remote-side failure carrying an advisory message. The
    /// message is for operators; programs MUST NOT pattern-match on its
    /// contents.
    #[error("remote error: {0}")]
    RemoteError(String),
    /// `update_ref` CAS precondition was not satisfied. Per
    /// SPEC-TRANSPORT §8, callers MUST treat this as
    /// "possibly-success on retry" for `.missing` / `.match` and
    /// confirm with `read_ref`.
    #[error("ref CAS precondition failed")]
    RefConflict,
    /// Caller passed a ref name failing SPEC-REFS §3.
    #[error("invalid ref name: {0}")]
    InvalidRef(String),
    /// Network-level failure: DNS, TCP connect, TLS handshake, SSH
    /// subprocess spawn. Retryable (see [`is_retryable`]).
    #[error("connection to remote failed")]
    ConnectionFailed,
    /// Unexpected HTTP status or SSH protocol error. 5xx and 429 are
    /// retryable; 4xx (except 401/403/404/409/412) is not.
    #[error("server error (status {status})")]
    ServerError {
        /// Numeric status code. HTTP uses its native codes; SSH uses
        /// `0` when the failure is not an HTTP exchange.
        status: u16,
    },
    /// Server response did not match the wire contract (truncated
    /// frame, unknown opcode, bad JSON, …).
    #[error("invalid response from remote")]
    InvalidResponse,
    /// Generic protocol-level failure — malformed frame, unexpected
    /// opcode order, or failed HELLO handshake.
    #[error("protocol error")]
    ProtocolError,
    /// Payload exceeds `MAX_PAYLOAD_LEN`; emitted by frame encoders /
    /// decoders. Distinguished from [`Self::InvalidResponse`] so
    /// transports can log an actionable message.
    #[error("payload exceeds {MAX_PAYLOAD_LEN}-byte cap: got {0} bytes")]
    PayloadTooLarge(usize),
    /// Frame truncated at the wire level — fewer bytes on the stream
    /// than `payload_len` advertised.
    #[error("frame truncated: expected {expected} payload bytes, got {actual}")]
    TruncatedFrame {
        /// `payload_len` from the frame header.
        expected: usize,
        /// Bytes actually available after the header.
        actual: usize,
    },
}

/// Result alias used throughout this module.
pub type TransportResult<T> = Result<T, TransportError>;

// ---------------------------------------------------------------------------
// PackKey — 32-byte digest wrapper
// ---------------------------------------------------------------------------

/// A 32-byte pack digest used as the content-address for an uploaded
/// pack. This is the same 32 bytes as [`Hash`] but wrapped so pack
/// digests and object hashes do not silently cross purposes at API
/// boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackKey(pub [u8; 32]);

impl PackKey {
    /// Build a [`PackKey`] from a raw 32-byte digest.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase 64-char hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    /// Build a [`PackKey`] from a [`Hash`] (alias for [`From`]).
    #[must_use]
    pub const fn from_hash(h: Hash) -> Self {
        Self(h)
    }

    /// Convert back to a plain [`Hash`].
    #[must_use]
    pub const fn into_hash(self) -> Hash {
        self.0
    }
}

impl From<Hash> for PackKey {
    fn from(h: Hash) -> Self {
        Self(h)
    }
}

impl From<PackKey> for Hash {
    fn from(k: PackKey) -> Hash {
        k.0
    }
}

impl fmt::Display for PackKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Parse a [`PackKey`] from a 64-char lowercase hex string.
///
/// Accepts uppercase too (matches the permissive [`crate::hash::from_hex`]
/// semantics); callers that require lowercase MUST validate the input
/// independently.
pub fn pack_key_from_hex(s: &str) -> Result<PackKey, FromHexError> {
    let h = crate::hash::from_hex(s)?;
    Ok(PackKey(h))
}

// ---------------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------------

/// Encode a single SSH frame: `[u8 opcode_or_status][u32 LE payload_len][payload]`.
///
/// Returns [`TransportError::PayloadTooLarge`] if `payload.len() >
/// MAX_PAYLOAD_LEN`. All opcode / status bytes are valid encoder inputs
/// — the encoder does not validate `op` against the known-opcode list
/// because the caller (SSH transport) is authoritative for which
/// direction a given byte is legal in.
pub fn encode_frame(op: u8, payload: &[u8]) -> TransportResult<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(TransportError::PayloadTooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    out.push(op);
    // The cap-check above guarantees payload.len() ≤ MAX_PAYLOAD_LEN
    // (16 MiB), well inside u32::MAX; map a theoretical overflow to a
    // `PayloadTooLarge` rather than panicking via `.expect`.
    let len_u32 =
        u32::try_from(payload.len()).map_err(|_| TransportError::PayloadTooLarge(payload.len()))?;
    out.extend_from_slice(&len_u32.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode a single SSH frame, returning `(opcode_or_status, payload_slice)`.
///
/// The returned payload borrows from `bytes`. Extra bytes past the
/// advertised payload length are *not* consumed — the caller is
/// responsible for advancing the stream cursor by
/// `FRAME_HEADER_LEN + payload.len()`. This lets the SSH transport
/// reuse the decoder on a pipelined read buffer without copying.
///
/// Errors:
/// - [`TransportError::TruncatedFrame`] if `bytes` is shorter than the
///   header or shorter than the advertised payload.
/// - [`TransportError::PayloadTooLarge`] if `payload_len > MAX_PAYLOAD_LEN`.
pub fn decode_frame(bytes: &[u8]) -> TransportResult<(u8, &[u8])> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(TransportError::TruncatedFrame {
            expected: FRAME_HEADER_LEN,
            actual: bytes.len(),
        });
    }
    let op = bytes[0];
    let len_bytes = [bytes[1], bytes[2], bytes[3], bytes[4]];
    let payload_len = u32::from_le_bytes(len_bytes) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(TransportError::PayloadTooLarge(payload_len));
    }
    let rest = &bytes[FRAME_HEADER_LEN..];
    if rest.len() < payload_len {
        return Err(TransportError::TruncatedFrame {
            expected: payload_len,
            actual: rest.len(),
        });
    }
    Ok((op, &rest[..payload_len]))
}

/// Build the payload for a client-sent `OP_HELLO` frame per
/// SPEC-TRANSPORT §7.4.
///
/// `binary_name` MUST satisfy `binary_name.len() ≤ HELLO_NAME_MAX` and
/// `client_version.len() ≤ HELLO_VERSION_MAX`. Oversize inputs return
/// [`TransportError::ProtocolError`] so callers cannot silently produce
/// an un-decodable frame.
pub fn encode_hello_payload(
    proto_version: u8,
    binary_name: &str,
    client_version: &str,
) -> TransportResult<Vec<u8>> {
    if binary_name.len() > HELLO_NAME_MAX || client_version.len() > HELLO_VERSION_MAX {
        return Err(TransportError::ProtocolError);
    }
    let mut out = Vec::with_capacity(1 + 1 + binary_name.len() + 1 + client_version.len());
    out.push(proto_version);
    // The length-caps above (≤ 32 and ≤ 64) fit in u8; map a
    // theoretical overflow to `ProtocolError` rather than panicking.
    let name_len = u8::try_from(binary_name.len()).map_err(|_| TransportError::ProtocolError)?;
    let version_len =
        u8::try_from(client_version.len()).map_err(|_| TransportError::ProtocolError)?;
    out.push(name_len);
    out.extend_from_slice(binary_name.as_bytes());
    out.push(version_len);
    out.extend_from_slice(client_version.as_bytes());
    Ok(out)
}

// ---------------------------------------------------------------------------
// Retry / backoff
// ---------------------------------------------------------------------------

/// Return `true` if a transport should retry after seeing `err`.
///
/// Retryable per SPEC-TRANSPORT §8:
/// - [`TransportError::ConnectionFailed`]
/// - [`TransportError::ServerError`] with a 5xx status OR HTTP 429.
///
/// Explicitly non-retryable:
/// - [`TransportError::PackNotFound`]
/// - [`TransportError::AccessDenied`]
/// - [`TransportError::RefConflict`] (CAS retry is a caller-level policy)
/// - [`TransportError::InvalidRef`]
/// - [`TransportError::InvalidResponse`] / [`TransportError::ProtocolError`]
/// - [`TransportError::PayloadTooLarge`] / [`TransportError::TruncatedFrame`]
/// - [`TransportError::RemoteError`] — the remote chose not to be specific;
///   we do not guess.
/// - [`TransportError::ServerError`] with any 4xx status.
#[must_use]
pub fn is_retryable(err: &TransportError) -> bool {
    match err {
        TransportError::ConnectionFailed => true,
        TransportError::ServerError { status } => *status >= 500 || *status == 429,
        _ => false,
    }
}

/// Max attempts for the default backoff ladder.
///
/// SPEC-TRANSPORT §8: `attempt = 1; while attempt ≤ 5`.
pub const BACKOFF_MAX_ATTEMPTS: u32 = 5;

/// Initial sleep between attempts.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Upper bound on any individual sleep.
pub const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// Exponential-backoff iterator used by all transports.
///
/// Yields `[1s, 2s, 4s, 8s, 16s]` (5 attempts) for the default ladder,
/// doubling each step and capping at 300s. This is the ladder mandated
/// by SPEC-TRANSPORT §8 for `ConnectionFailed`, 5xx, and HTTP 429.
///
/// The iterator is self-contained — it holds no reference to a clock,
/// so it can be constructed in tests and exhaustively enumerated.
#[derive(Debug, Clone)]
pub struct BackoffIterator {
    next_delay: Duration,
    attempts_remaining: u32,
    cap: Duration,
}

impl BackoffIterator {
    /// Default ladder: 5 attempts, starting at 1s, doubling, capped at 300s.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_delay: BACKOFF_INITIAL,
            attempts_remaining: BACKOFF_MAX_ATTEMPTS,
            cap: BACKOFF_CAP,
        }
    }

    /// Custom ladder for tests.
    #[must_use]
    pub const fn with(initial: Duration, cap: Duration, attempts: u32) -> Self {
        Self {
            next_delay: initial,
            attempts_remaining: attempts,
            cap,
        }
    }
}

impl Default for BackoffIterator {
    fn default() -> Self {
        Self::new()
    }
}

impl Iterator for BackoffIterator {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        if self.attempts_remaining == 0 {
            return None;
        }
        self.attempts_remaining -= 1;
        let current = self.next_delay;
        // Double, saturating at cap. Use saturating multiplication to
        // avoid overflow on absurd custom ladders.
        let doubled = current.saturating_mul(2);
        self.next_delay = if doubled > self.cap {
            self.cap
        } else {
            doubled
        };
        Some(current)
    }
}

// ---------------------------------------------------------------------------
// Transport trait
// ---------------------------------------------------------------------------

/// The mkit transport vtable.
///
/// Every transport (memory, file, HTTP, S3, SSH) implements this trait.
/// Methods are synchronous and take `&self`; transports that need
/// interior mutability (e.g. connection pools) MUST use a `Mutex` /
/// `RwLock` internally. This keeps the trait object-safe.
///
/// All implementations MUST honour the retry policy in
/// SPEC-TRANSPORT §8 internally OR document that the caller is
/// responsible — the abstract trait takes no position. The
/// [`is_retryable`] and [`BackoffIterator`] helpers are provided for
/// implementations that embed the policy.
pub trait Transport: Send + Sync {
    /// Upload a pack. The digest is computed by the caller (BLAKE3 of
    /// the full pack bytes) and used as the object key — servers MAY
    /// dedupe on this key.
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()>;

    /// Download a pack by its digest.
    ///
    /// Returns [`TransportError::PackNotFound`] if the remote does not
    /// hold this digest.
    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>>;

    /// HEAD-check a pack. Cheaper than [`Self::download_pack`] on
    /// network transports.
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool>;

    /// Unconditional ref write — equivalent to
    /// `update_ref(name, RefWriteCondition::Any, hash)`.
    ///
    /// Default impl delegates to [`Self::update_ref`] so transports only
    /// implement one entry point.
    fn write_ref(&self, name: &str, hash: &Hash) -> TransportResult<()> {
        self.update_ref(name, RefWriteCondition::Any, hash)
    }

    /// CAS ref write. See [`RefWriteCondition`].
    ///
    /// On `.missing` / `.match` CAS failure, returns
    /// [`TransportError::RefConflict`]. Callers retrying after a
    /// timeout MUST follow up with [`Self::read_ref`] to confirm
    /// whether the first attempt actually landed (SPEC-TRANSPORT §8).
    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()>;

    /// Read the current value of a ref, or `None` if it does not exist.
    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>>;

    /// List refs whose full name starts with `prefix`. Returned names
    /// have `prefix` stripped per SPEC-REFS §4. An empty prefix lists
    /// every ref.
    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Frame encode / decode roundtrips for every opcode ------------------

    fn roundtrip_empty(op: u8) {
        let bytes = encode_frame(op, &[]).unwrap();
        assert_eq!(bytes.len(), FRAME_HEADER_LEN);
        let (decoded_op, payload) = decode_frame(&bytes).unwrap();
        assert_eq!(decoded_op, op);
        assert_eq!(payload, &[] as &[u8]);
    }

    #[test]
    fn frame_roundtrip_hello() {
        let payload = encode_hello_payload(SSH_PROTO_VERSION, "mkit", "mkit 0.1.0").unwrap();
        let bytes = encode_frame(OP_HELLO, &payload).unwrap();
        let (op, got) = decode_frame(&bytes).unwrap();
        assert_eq!(op, OP_HELLO);
        assert_eq!(got, payload.as_slice());
    }

    #[test]
    fn frame_roundtrip_upload_pack() {
        let payload = vec![0x42u8; 33]; // 32 digest + 1 pack byte
        let bytes = encode_frame(OP_UPLOAD_PACK, &payload).unwrap();
        let (op, got) = decode_frame(&bytes).unwrap();
        assert_eq!(op, OP_UPLOAD_PACK);
        assert_eq!(got, payload.as_slice());
    }

    #[test]
    fn frame_roundtrip_download_pack() {
        roundtrip_empty(OP_DOWNLOAD_PACK);
    }

    #[test]
    fn frame_roundtrip_pack_exists() {
        roundtrip_empty(OP_PACK_EXISTS);
    }

    #[test]
    fn frame_roundtrip_write_ref() {
        roundtrip_empty(OP_WRITE_REF);
    }

    #[test]
    fn frame_roundtrip_update_ref() {
        roundtrip_empty(OP_UPDATE_REF);
    }

    #[test]
    fn frame_roundtrip_read_ref() {
        roundtrip_empty(OP_READ_REF);
    }

    #[test]
    fn frame_roundtrip_list_refs() {
        roundtrip_empty(OP_LIST_REFS);
    }

    #[test]
    fn frame_roundtrip_close() {
        roundtrip_empty(OP_CLOSE);
    }

    #[test]
    fn frame_roundtrip_status_ok() {
        roundtrip_empty(STATUS_OK);
    }

    #[test]
    fn frame_roundtrip_status_null() {
        roundtrip_empty(STATUS_NULL);
    }

    #[test]
    fn frame_roundtrip_status_error_with_message() {
        let msg = b"binary name mismatch";
        let bytes = encode_frame(STATUS_ERROR, msg).unwrap();
        let (op, got) = decode_frame(&bytes).unwrap();
        assert_eq!(op, STATUS_ERROR);
        assert_eq!(got, msg);
    }

    // -- Frame size boundaries ---------------------------------------------

    #[test]
    fn frame_rejects_encode_oversize_payload() {
        let oversize = vec![0u8; MAX_PAYLOAD_LEN + 1];
        match encode_frame(OP_UPLOAD_PACK, &oversize) {
            Err(TransportError::PayloadTooLarge(n)) => assert_eq!(n, MAX_PAYLOAD_LEN + 1),
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn frame_accepts_empty_payload() {
        let bytes = encode_frame(OP_CLOSE, &[]).unwrap();
        assert_eq!(bytes, vec![OP_CLOSE, 0, 0, 0, 0]);
        let (op, payload) = decode_frame(&bytes).unwrap();
        assert_eq!(op, OP_CLOSE);
        assert!(payload.is_empty());
    }

    #[test]
    fn frame_accepts_max_payload_exactly() {
        // MAX_PAYLOAD_LEN is 16 MiB — encoding one is heavy but fine in tests.
        let payload = vec![0xA5u8; MAX_PAYLOAD_LEN];
        let bytes = encode_frame(OP_UPLOAD_PACK, &payload).unwrap();
        let (op, got) = decode_frame(&bytes).unwrap();
        assert_eq!(op, OP_UPLOAD_PACK);
        assert_eq!(got.len(), MAX_PAYLOAD_LEN);
    }

    #[test]
    fn frame_decode_rejects_oversize_len_field() {
        // Hand-craft a frame whose advertised payload_len exceeds the cap.
        let advertised = u32::try_from(MAX_PAYLOAD_LEN).unwrap() + 1;
        let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN);
        bytes.push(OP_UPLOAD_PACK);
        bytes.extend_from_slice(&advertised.to_le_bytes());
        match decode_frame(&bytes) {
            Err(TransportError::PayloadTooLarge(n)) => {
                assert_eq!(n, MAX_PAYLOAD_LEN + 1);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn frame_decode_rejects_truncated_header() {
        let err = decode_frame(&[0x00, 0x00]).unwrap_err();
        match err {
            TransportError::TruncatedFrame { expected, actual } => {
                assert_eq!(expected, FRAME_HEADER_LEN);
                assert_eq!(actual, 2);
            }
            other => panic!("expected TruncatedFrame, got {other:?}"),
        }
    }

    #[test]
    fn frame_decode_rejects_truncated_payload() {
        // Header says 8 bytes of payload, supply only 3.
        let mut bytes = vec![OP_WRITE_REF];
        bytes.extend_from_slice(&8u32.to_le_bytes());
        bytes.extend_from_slice(b"abc");
        match decode_frame(&bytes) {
            Err(TransportError::TruncatedFrame { expected, actual }) => {
                assert_eq!(expected, 8);
                assert_eq!(actual, 3);
            }
            other => panic!("expected TruncatedFrame, got {other:?}"),
        }
    }

    #[test]
    fn frame_decode_ignores_trailing_bytes() {
        // An SSH read buffer may have pipelined frames. Decoder MUST
        // return only the advertised payload length and leave the rest
        // alone.
        let inner = encode_frame(OP_CLOSE, b"hello").unwrap();
        let mut buf = inner.clone();
        buf.extend_from_slice(b"trailing garbage");
        let (op, payload) = decode_frame(&buf).unwrap();
        assert_eq!(op, OP_CLOSE);
        assert_eq!(payload, b"hello");
    }

    // -- HELLO payload encoder ---------------------------------------------

    #[test]
    fn hello_payload_matches_spec_example() {
        // SPEC-TRANSPORT §7.4 example: proto=0x01, "mkit", "mkit 0.2.0".
        let payload = encode_hello_payload(SSH_PROTO_VERSION, "mkit", "mkit 0.2.0").unwrap();
        assert_eq!(payload.len(), 1 + 1 + 4 + 1 + 10);
        assert_eq!(payload[0], 0x01);
        assert_eq!(payload[1], 4);
        assert_eq!(&payload[2..6], b"mkit");
        assert_eq!(payload[6], 10);
        assert_eq!(&payload[7..], b"mkit 0.2.0");
    }

    #[test]
    fn hello_payload_rejects_oversize_binary_name() {
        let too_long = "a".repeat(HELLO_NAME_MAX + 1);
        let err = encode_hello_payload(SSH_PROTO_VERSION, &too_long, "v").unwrap_err();
        assert!(matches!(err, TransportError::ProtocolError));
    }

    #[test]
    fn hello_payload_rejects_oversize_version() {
        let too_long = "a".repeat(HELLO_VERSION_MAX + 1);
        let err = encode_hello_payload(SSH_PROTO_VERSION, "mkit", &too_long).unwrap_err();
        assert!(matches!(err, TransportError::ProtocolError));
    }

    // -- PackKey -----------------------------------------------------------

    #[test]
    fn pack_key_hex_roundtrip() {
        let raw: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let key = PackKey::new(raw);
        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed = pack_key_from_hex(&hex).unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn pack_key_display_matches_hex() {
        let raw: [u8; 32] = [0xABu8; 32];
        let key = PackKey::new(raw);
        assert_eq!(format!("{key}"), key.to_hex());
    }

    #[test]
    fn pack_key_from_hex_rejects_short_input() {
        assert!(pack_key_from_hex("abcd").is_err());
    }

    // -- Backoff ladder ----------------------------------------------------

    #[test]
    fn backoff_default_ladder_is_spec_sequence() {
        let got: Vec<Duration> = BackoffIterator::new().collect();
        assert_eq!(
            got,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
            ]
        );
    }

    #[test]
    fn backoff_saturates_at_cap() {
        // 10 attempts starting at 60s with a 120s cap: 60, 120, 120, 120, …
        let got: Vec<Duration> =
            BackoffIterator::with(Duration::from_secs(60), Duration::from_secs(120), 10).collect();
        assert_eq!(got.len(), 10);
        assert_eq!(got[0], Duration::from_secs(60));
        assert_eq!(got[1], Duration::from_secs(120));
        for d in &got[2..] {
            assert_eq!(*d, Duration::from_secs(120));
        }
    }

    #[test]
    fn backoff_zero_attempts_is_empty() {
        let got: Vec<Duration> =
            BackoffIterator::with(Duration::from_secs(1), Duration::from_secs(300), 0).collect();
        assert!(got.is_empty());
    }

    // -- is_retryable classifier -------------------------------------------

    #[test]
    fn retryable_connection_failed() {
        assert!(is_retryable(&TransportError::ConnectionFailed));
    }

    #[test]
    fn retryable_5xx_server_errors() {
        assert!(is_retryable(&TransportError::ServerError { status: 500 }));
        assert!(is_retryable(&TransportError::ServerError { status: 502 }));
        assert!(is_retryable(&TransportError::ServerError { status: 503 }));
        assert!(is_retryable(&TransportError::ServerError { status: 599 }));
    }

    #[test]
    fn retryable_429_too_many_requests() {
        assert!(is_retryable(&TransportError::ServerError { status: 429 }));
    }

    #[test]
    fn non_retryable_4xx_other_than_429() {
        for status in [400u16, 401, 403, 404, 409, 412, 418, 422] {
            assert!(
                !is_retryable(&TransportError::ServerError { status }),
                "status {status} unexpectedly classified as retryable"
            );
        }
    }

    #[test]
    fn non_retryable_domain_errors() {
        assert!(!is_retryable(&TransportError::PackNotFound));
        assert!(!is_retryable(&TransportError::AccessDenied));
        assert!(!is_retryable(&TransportError::RefConflict));
        assert!(!is_retryable(&TransportError::InvalidRef("x".into())));
        assert!(!is_retryable(&TransportError::InvalidResponse));
        assert!(!is_retryable(&TransportError::ProtocolError));
        assert!(!is_retryable(&TransportError::RemoteError(
            "something".into()
        )));
        assert!(!is_retryable(&TransportError::PayloadTooLarge(0)));
        assert!(!is_retryable(&TransportError::TruncatedFrame {
            expected: 1,
            actual: 0
        }));
    }

    // -- Object-safety smoke test ------------------------------------------

    #[test]
    fn transport_is_object_safe() {
        // If this compiles, `dyn Transport` is object-safe — the point
        // of the entire phase.
        fn _takes_dyn(_t: &dyn Transport) {}
    }
}
