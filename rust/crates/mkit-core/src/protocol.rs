//! Cross-transport types: error taxonomy, the [`Transport`] trait, the
//! [`PackKey`] digest wrapper, and the retry/backoff helpers used by
//! every transport implementation (memory, file, HTTP, S3, SSH).
//!
//! The SSH wire format is defined in `mkit-rpc`'s `ssh.proto` and
//! lives in `mkit_rpc::mkit::rpc::v1::ssh`; transport-ssh consumes
//! the schema directly. The hand-rolled `OP_HELLO` byte format that
//! used to live in this module has been retired.

// SPEC-TRANSPORT §7 calls out the exponential ladder in seconds
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
    /// SPEC-TRANSPORT §7, callers MUST treat this as
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
    /// Unexpected HTTP status or transport-protocol error. 5xx and 429
    /// are retryable; 4xx (except 401/403/404/409/412) is not.
    #[error("server error (status {status})")]
    ServerError {
        /// Numeric status code. HTTP uses its native codes; transports
        /// without a status integer use `0`.
        status: u16,
    },
    /// Server response did not match the wire contract (truncated
    /// frame, unknown opcode, bad JSON, …).
    #[error("invalid response from remote")]
    InvalidResponse,
    /// Generic protocol-level failure — malformed frame, unexpected
    /// opcode order, or failed handshake.
    #[error("protocol error")]
    ProtocolError,
    /// Payload exceeded a transport-specific cap.
    #[error("payload too large: {0} bytes")]
    PayloadTooLarge(usize),
    /// An insecure URL scheme (plain `http://`) was supplied for a
    /// non-loopback host. Plain HTTP is restricted to loopback addresses
    /// (`127.0.0.1`, `::1`, `localhost`) so production traffic is never
    /// transported in the clear.
    #[error("insecure scheme: plain http:// is allowed only for loopback hosts")]
    InsecureScheme,
}

/// Result alias used throughout this module.
pub type TransportResult<T> = Result<T, TransportError>;

// ---------------------------------------------------------------------------
// PackKey — 32-byte digest wrapper
// ---------------------------------------------------------------------------

/// A 32-byte pack digest used as the content-address for an uploaded
/// pack. This is the same 32 bytes as [`Hash`](tyalias@Hash) but wrapped so pack
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

    /// Build a [`PackKey`] from a [`Hash`](tyalias@Hash) (alias for [`From`]).
    #[must_use]
    pub const fn from_hash(h: Hash) -> Self {
        Self(h)
    }

    /// Convert back to a plain [`Hash`](tyalias@Hash).
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
// Retry / backoff
// ---------------------------------------------------------------------------

/// Return `true` if a transport should retry after seeing `err`.
///
/// Retryable per SPEC-TRANSPORT §7:
/// - [`TransportError::ConnectionFailed`]
/// - [`TransportError::ServerError`] with a 5xx status OR HTTP 429.
///
/// Explicitly non-retryable:
/// - [`TransportError::PackNotFound`]
/// - [`TransportError::AccessDenied`]
/// - [`TransportError::RefConflict`] (CAS retry is a caller-level policy)
/// - [`TransportError::InvalidRef`]
/// - [`TransportError::InvalidResponse`] / [`TransportError::ProtocolError`]
/// - [`TransportError::PayloadTooLarge`]
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
/// SPEC-TRANSPORT §7: `attempt = 1; while attempt ≤ 5`.
pub const BACKOFF_MAX_ATTEMPTS: u32 = 5;

/// Initial sleep between attempts.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Upper bound on any individual sleep.
pub const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// Per-pack body size ceiling enforced by every transport that ingests
/// pack bytes (HTTP `Content-Length`, S3 `GetObject`, SSH
/// `DownloadPackHeader.total_bytes`). On 64-bit targets, 4 GiB matches
/// the pack-format addressable range; pointer-width-limited targets cap
/// at their maximum addressable buffer size instead of failing to compile.
#[cfg(target_pointer_width = "64")]
pub const PACK_BODY_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
#[cfg(not(target_pointer_width = "64"))]
pub const PACK_BODY_LIMIT: u64 = usize::MAX as u64;

/// `usize`-typed mirror of [`PACK_BODY_LIMIT`] for `Vec`-shaped buffer
/// caps. The assertion below prevents silent truncation on any target.
#[allow(clippy::cast_possible_truncation)]
pub const PACK_BODY_LIMIT_USIZE: usize = PACK_BODY_LIMIT as usize;
const _: () = assert!(
    (PACK_BODY_LIMIT_USIZE as u64) == PACK_BODY_LIMIT,
    "PACK_BODY_LIMIT does not fit in usize on this target",
);

/// Exponential-backoff iterator used by all transports.
///
/// Yields `[1s, 2s, 4s, 8s, 16s]` (5 attempts) for the default ladder,
/// doubling each step and capping at 300s. This is the ladder mandated
/// by SPEC-TRANSPORT §7 for `ConnectionFailed`, 5xx, and HTTP 429.
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
// PackChunk — transport-agnostic streaming segment
// ---------------------------------------------------------------------------

/// One bounded-size segment of a streamed pack transfer.
///
/// Mirrors the wire-level `PackChunk` shape shared by the SSH and enc
/// transports (`offset`, `data`, `last` — see `mkit-rpc/proto/ssh.proto`)
/// and the `mkit.transport.v1` Connect proto being designed for the HTTP
/// reference worker, without this crate depending on any
/// protobuf-generated type: `mkit-core` is the dependency root that
/// `mkit-rpc` builds on, not the reverse (see this module's header
/// comment), so the canonical protobuf `PackChunk` cannot be named here.
/// Transports convert 1:1 between this type and their own wire
/// representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackChunk {
    /// Byte offset of `data` within the pack. Consecutive chunks in one
    /// transfer MUST have ascending, contiguous offsets starting at 0 —
    /// i.e. chunk *n*'s `offset` equals the sum of every prior chunk's
    /// `data.len()`.
    pub offset: u64,
    /// Chunk payload. Transports typically bound this to a fixed
    /// per-frame maximum (e.g. `mkit_rpc::CHUNK_DATA_MAX`, 800 KiB for
    /// SSH/enc) so no single chunk forces a large allocation.
    pub data: Vec<u8>,
    /// `true` on the final chunk of the stream. An empty pack is still
    /// represented as exactly one chunk with `last = true` and empty
    /// `data` — a stream MUST NOT end silently without a `last = true`
    /// chunk.
    pub last: bool,
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
/// SPEC-TRANSPORT §7 internally OR document that the caller is
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

    /// Upload a pack by streaming bounded-size [`PackChunk`]s instead of
    /// requiring the whole pack materialized as one `&[u8]` up front.
    ///
    /// `total_bytes` is the caller-declared pack length — the wire
    /// header most streaming transports send before the first chunk.
    /// `chunks` MUST yield its segments in ascending contiguous `offset`
    /// order and end with exactly one item whose `last` field is `true`
    /// (an empty pack still yields one `last = true` chunk with empty
    /// `data`); the accumulated `data` length across every yielded chunk
    /// MUST equal `total_bytes`. The digest (`key`) is still computed by
    /// the caller up front, exactly as for [`Self::upload_pack`] — this
    /// method does not hash the stream itself.
    ///
    /// This is an additive, opt-in entry point: no existing transport is
    /// forced to implement real streaming. The default impl buffers
    /// `chunks` into one `Vec` (bounded by [`PACK_BODY_LIMIT_USIZE`]) and
    /// delegates to [`Self::upload_pack`], so every transport gets a
    /// working implementation with zero code — callers may always use
    /// this entry point, even against a transport that has not opted
    /// into streaming. Transports that can forward chunks directly to
    /// their own wire (SSH, enc — see `mkit-transport-ssh`'s existing
    /// `PackChunk` frame loop) SHOULD override this to avoid the buffer
    /// and stay in bounded memory regardless of pack size.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::ProtocolError`] if `chunks` never
    /// yields a `last = true` item, or if the accumulated byte count
    /// does not equal `total_bytes`. Returns
    /// [`TransportError::PayloadTooLarge`] if `total_bytes` (or the
    /// accumulated count) would exceed [`PACK_BODY_LIMIT`]. Propagates
    /// any error yielded by `chunks` itself (e.g. the caller's own I/O
    /// error while reading a pack off disk).
    fn upload_pack_streaming(
        &self,
        key: &PackKey,
        total_bytes: u64,
        chunks: &mut dyn Iterator<Item = TransportResult<PackChunk>>,
    ) -> TransportResult<()> {
        if total_bytes > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(PACK_BODY_LIMIT_USIZE));
        }
        // `total_bytes <= PACK_BODY_LIMIT` was just checked, and
        // `PACK_BODY_LIMIT_USIZE as u64 == PACK_BODY_LIMIT` is asserted
        // at the constant's definition, so this conversion never
        // truncates — `try_from` (rather than `as`) makes that provable
        // to clippy instead of asserted in a comment.
        let initial = usize::try_from(total_bytes).unwrap_or(PACK_BODY_LIMIT_USIZE);
        let mut buf = Vec::with_capacity(initial);
        let mut saw_last = false;
        for chunk in chunks {
            let c = chunk?;
            if buf.len().saturating_add(c.data.len()) > PACK_BODY_LIMIT_USIZE {
                return Err(TransportError::PayloadTooLarge(PACK_BODY_LIMIT_USIZE));
            }
            buf.extend_from_slice(&c.data);
            if c.last {
                saw_last = true;
                break;
            }
        }
        if !saw_last || buf.len() as u64 != total_bytes {
            return Err(TransportError::ProtocolError);
        }
        self.upload_pack(&buf, key)
    }

    /// Download a pack as a lazy stream of bounded-size [`PackChunk`]s
    /// instead of one big `Vec<u8>`.
    ///
    /// This is an additive, opt-in entry point mirroring
    /// [`Self::upload_pack_streaming`]. The default impl calls
    /// [`Self::download_pack`] eagerly (so it does not save memory by
    /// itself) and wraps the whole result as a single `last = true`
    /// chunk — every transport gets a working implementation with zero
    /// code. Transports that can read their own wire incrementally (SSH,
    /// enc) SHOULD override this to yield each wire chunk as it arrives,
    /// keeping memory bounded to roughly one chunk at a time regardless
    /// of total pack size.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::PackNotFound`] immediately if the
    /// remote does not hold `key` — a conforming implementation never
    /// returns a stream that then fails its first item with
    /// `PackNotFound`. Errors surfacing mid-stream (a malformed frame, a
    /// connection drop) are yielded as `Err` items from the returned
    /// iterator rather than failing this call itself, since an
    /// overridden implementation may not know the transfer will fail
    /// until partway through.
    fn download_pack_streaming(
        &self,
        key: &PackKey,
    ) -> TransportResult<Box<dyn Iterator<Item = TransportResult<PackChunk>> + '_>> {
        let bytes = self.download_pack(key)?;
        Ok(Box::new(core::iter::once(Ok(PackChunk {
            offset: 0,
            data: bytes,
            last: true,
        }))))
    }

    /// HEAD-check a pack. Cheaper than [`Self::download_pack`] on
    /// network transports.
    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool>;

    /// Upload a content-addressed **auxiliary blob** — transfer metadata
    /// that is NOT a packfile (e.g. a packlist chain node, SPEC-PACKFILE is
    /// silent on these). The key is BLAKE3 of `bytes`, exactly like a pack.
    ///
    /// Auxiliary blobs share the digest-keyed content-addressed store with
    /// packs (the store is a general blob store; "pack" is just the primary
    /// content kind), so the default impl delegates to [`Self::upload_pack`].
    /// The distinct verb keeps the *kind* explicit at the call site so a
    /// caller never has to infer "is this blob a packfile or metadata?".
    fn upload_blob(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.upload_pack(bytes, key)
    }

    /// Download an auxiliary blob by digest. Counterpart to
    /// [`Self::upload_blob`]; default impl delegates to
    /// [`Self::download_pack`]. Returns [`TransportError::PackNotFound`] if
    /// the remote does not hold this digest.
    fn download_blob(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        self.download_pack(key)
    }

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
    /// whether the first attempt actually landed (SPEC-TRANSPORT §7).
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

    /// Advance a branch by updating its **head ref and its packmap ref
    /// together**, each under its own CAS precondition.
    ///
    /// This exists so the delta-transfer invariant — "if `head_ref` resolves
    /// to T, the packmap reconstructs `closure(T)`" — can be upheld without a
    /// window where the two refs disagree. A transport backed by a
    /// transactional ref store SHOULD override this to apply both writes in
    /// ONE transaction: then a failed advance changes nothing, and the head
    /// is never observed past a packmap that can't yet reconstruct it.
    ///
    /// The default impl is the safe non-transactional approximation used by
    /// stores without multi-ref transactions: it writes the **packmap first**
    /// (durable before the head moves) then the head. A crash in between
    /// leaves the head at its prior value and the packmap a superset — still
    /// consistent for fetch. The [`AdvanceOutcome`] distinguishes a packmap
    /// precondition failure (caller re-reads and retries the chain) from a
    /// head precondition failure (caller treats it as non-fast-forward),
    /// which a single `RefConflict` could not.
    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        match self.update_ref(packmap_ref, packmap_condition, packmap_value) {
            Ok(()) => {}
            Err(TransportError::RefConflict) => return Ok(AdvanceOutcome::PackmapConflict),
            Err(e) => return Err(e),
        }
        match self.update_ref(head_ref, head_condition, head_value) {
            Ok(()) => Ok(AdvanceOutcome::Committed),
            Err(TransportError::RefConflict) => Ok(AdvanceOutcome::HeadConflict),
            Err(e) => Err(e),
        }
    }

    /// Whether [`Self::advance_refs`] commits the head + packmap advance as
    /// one indivisible transaction, rather than the default's ordered
    /// packmap-then-head writes.
    ///
    /// The default (non-transactional) `advance_refs` is safe for an
    /// **appending** packmap write: per its doc comment, a crash or lost
    /// head-CAS race between the two writes leaves the packmap a strict
    /// superset of what the (unmoved) head needs — still reconstructable.
    /// That safety argument does NOT extend to a packmap **reset** (a fresh
    /// node with `prev = None`, produced by the pack-chain re-baseline,
    /// mkit #406): a reset is not a superset of the prior chain, so a
    /// packmap write that commits while the paired head write loses its CAS
    /// would strand the (still-unmoved) head pointing at a commit whose
    /// closure the reset packmap can no longer reconstruct (mkit #521).
    ///
    /// Callers MUST treat `false` (the default) as "never request a
    /// packmap reset against this transport" — see
    /// `remote_dispatch::push_branch`'s re-baseline gate. Override to
    /// `true` ONLY when [`Self::advance_refs`] is overridden with a
    /// genuinely transactional implementation (e.g. the HTTP transport's
    /// single-request `/refs/advance` endpoint, mkit #408).
    fn supports_atomic_advance(&self) -> bool {
        false
    }
}

/// Result of [`Transport::advance_refs`] — a two-ref branch advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceOutcome {
    /// Both refs were updated.
    Committed,
    /// The head precondition did not hold (the branch moved under us). An
    /// atomic transport leaves nothing changed; callers treat this as a
    /// non-fast-forward.
    HeadConflict,
    /// The packmap precondition did not hold (a concurrent pusher advanced
    /// the chain). Callers re-read the packmap and retry.
    PackmapConflict,
}

// ---------------------------------------------------------------------------
// async_shim — sync/async bridge for transports that wrap an async cipher
// ---------------------------------------------------------------------------

/// Sync-over-async shim for transports whose underlying cipher / I/O is
/// async (e.g. `commonware-stream::encrypted`) but whose
/// [`Transport`] trait surface is intentionally sync.
///
/// Lives in `mkit-core` (the trait crate) because it is generic
/// infrastructure — multiple transports and sparse-checkout's transport
/// layer will reuse the same plug-in point. It does **not** depend on
/// `tokio`, `commonware-runtime`, or any concrete executor; callers
/// pick the runner.
///
/// # Why a trait
///
/// `mkit-transport-enc` and (once its transport layer lands) `mkit-core::sparse` need to
/// drive `async fn` bodies from a sync method. Hard-coding
/// `tokio::runtime::Handle::block_on` would bleed tokio across the
/// workspace; hard-coding `commonware_runtime::deterministic` would
/// mean production = tests. A pluggable `Executor` keeps the
/// runtime-choice at the consumer crate.
pub mod async_shim {
    /// Drives an async future to completion synchronously. Pluggable so
    /// callers can choose between `tokio`, `commonware-runtime`'s
    /// deterministic runner (tests), or the planned production tokio
    /// runner without `mkit-core` having to compile-time depend on a
    /// specific runtime crate.
    ///
    /// Implementations MUST be re-entrancy-safe in the sense expected
    /// by the chosen runtime — calling `block_on` from inside an
    /// already-running task on the same runtime will typically panic
    /// or deadlock. The shim's contract is "synchronous external API
    /// wraps async internals", not "arbitrary async-from-sync
    /// recursion".
    pub trait Executor: Send + Sync {
        /// Block the current thread until `fut` resolves.
        fn block_on<F, T>(&self, fut: F) -> T
        where
            F: core::future::Future<Output = T> + Send,
            T: Send;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_key_hex_roundtrip() {
        let bytes = [0x42u8; 32];
        let pk = PackKey::new(bytes);
        let hex = pk.to_hex();
        assert_eq!(hex.len(), 64);
        let pk2 = pack_key_from_hex(&hex).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn is_retryable_matches_spec() {
        assert!(is_retryable(&TransportError::ConnectionFailed));
        assert!(is_retryable(&TransportError::ServerError { status: 500 }));
        assert!(is_retryable(&TransportError::ServerError { status: 503 }));
        assert!(is_retryable(&TransportError::ServerError { status: 429 }));
        assert!(!is_retryable(&TransportError::ServerError { status: 404 }));
        assert!(!is_retryable(&TransportError::ServerError { status: 401 }));
        assert!(!is_retryable(&TransportError::PackNotFound));
        assert!(!is_retryable(&TransportError::AccessDenied));
        assert!(!is_retryable(&TransportError::RefConflict));
    }

    #[test]
    fn backoff_default_ladder_is_1_2_4_8_16() {
        let delays: Vec<Duration> = BackoffIterator::new().collect();
        assert_eq!(
            delays,
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
    fn backoff_caps_at_max() {
        let cap = Duration::from_secs(10);
        let delays: Vec<Duration> = BackoffIterator::with(Duration::from_secs(8), cap, 5).collect();
        // 8s, then cap (16s would exceed 10s cap; clamped to 10s)
        assert_eq!(delays[0], Duration::from_secs(8));
        for d in &delays[1..] {
            assert!(*d <= cap);
        }
    }

    // -----------------------------------------------------------------
    // upload_pack_streaming / download_pack_streaming default impls
    // -----------------------------------------------------------------

    /// Minimal in-memory [`Transport`] that only implements the
    /// required whole-buffer methods, so its `*_streaming` behavior is
    /// entirely the trait's default impl under test.
    #[derive(Default)]
    struct RecordingTransport {
        uploaded: std::sync::Mutex<Option<(Vec<u8>, PackKey)>>,
        stored: std::sync::Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>,
    }

    impl Transport for RecordingTransport {
        fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
            *self.uploaded.lock().unwrap() = Some((bytes.to_vec(), *key));
            self.stored
                .lock()
                .unwrap()
                .insert(*key.as_bytes(), bytes.to_vec());
            Ok(())
        }

        fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
            self.stored
                .lock()
                .unwrap()
                .get(key.as_bytes())
                .cloned()
                .ok_or(TransportError::PackNotFound)
        }

        fn pack_exists(&self, _key: &PackKey) -> TransportResult<bool> {
            unimplemented!("not exercised by these tests")
        }

        fn update_ref(
            &self,
            _name: &str,
            _condition: RefWriteCondition,
            _hash: &Hash,
        ) -> TransportResult<()> {
            unimplemented!("not exercised by these tests")
        }

        fn read_ref(&self, _name: &str) -> TransportResult<Option<Hash>> {
            unimplemented!("not exercised by these tests")
        }

        fn list_refs(&self, _prefix: &str) -> TransportResult<Vec<Ref>> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn chunks_of(data: &[u8], chunk_len: usize) -> Vec<PackChunk> {
        if data.is_empty() {
            return vec![PackChunk {
                offset: 0,
                data: Vec::new(),
                last: true,
            }];
        }
        let mut out = Vec::new();
        let mut offset = 0usize;
        while offset < data.len() {
            let end = core::cmp::min(offset + chunk_len, data.len());
            out.push(PackChunk {
                offset: offset as u64,
                data: data[offset..end].to_vec(),
                last: end == data.len(),
            });
            offset = end;
        }
        out
    }

    #[test]
    fn upload_pack_streaming_default_delegates_to_upload_pack() {
        let t = RecordingTransport::default();
        let payload = b"hello mkit pack bytes".repeat(100);
        let key = PackKey::new([0x11; 32]);
        let mut it = chunks_of(&payload, 7).into_iter().map(Ok);

        t.upload_pack_streaming(&key, payload.len() as u64, &mut it)
            .expect("streaming upload via default impl");

        let (got_bytes, got_key) = t.uploaded.lock().unwrap().clone().expect("upload recorded");
        assert_eq!(got_bytes, payload);
        assert_eq!(got_key, key);
    }

    #[test]
    fn upload_pack_streaming_default_rejects_missing_last_chunk() {
        let t = RecordingTransport::default();
        let key = PackKey::new([0x22; 32]);
        // No chunk at all — total_bytes = 0 still requires one `last =
        // true` chunk per the trait contract.
        let mut it = core::iter::empty();

        let err = t
            .upload_pack_streaming(&key, 0, &mut it)
            .expect_err("must reject a stream with no last=true chunk");
        assert!(matches!(err, TransportError::ProtocolError));
    }

    #[test]
    fn upload_pack_streaming_default_rejects_total_bytes_mismatch() {
        let t = RecordingTransport::default();
        let key = PackKey::new([0x33; 32]);
        let mut it = core::iter::once(Ok(PackChunk {
            offset: 0,
            data: vec![1, 2, 3],
            last: true,
        }));

        // Declared total (10) does not match the 3 bytes actually
        // streamed.
        let err = t
            .upload_pack_streaming(&key, 10, &mut it)
            .expect_err("must reject a total_bytes/accumulated-length mismatch");
        assert!(matches!(err, TransportError::ProtocolError));
    }

    #[test]
    fn upload_pack_streaming_default_propagates_chunk_error() {
        let t = RecordingTransport::default();
        let key = PackKey::new([0x44; 32]);
        let mut it = core::iter::once(Err(TransportError::ConnectionFailed));

        let err = t
            .upload_pack_streaming(&key, 0, &mut it)
            .expect_err("must propagate an error yielded mid-stream");
        assert!(matches!(err, TransportError::ConnectionFailed));
    }

    #[test]
    fn upload_pack_streaming_default_rejects_oversize_total() {
        let t = RecordingTransport::default();
        let key = PackKey::new([0x55; 32]);
        let mut it = core::iter::empty();

        let err = t
            .upload_pack_streaming(&key, PACK_BODY_LIMIT + 1, &mut it)
            .expect_err("must reject total_bytes above PACK_BODY_LIMIT");
        assert!(matches!(err, TransportError::PayloadTooLarge(_)));
    }

    #[test]
    fn download_pack_streaming_default_wraps_whole_pack() {
        let t = RecordingTransport::default();
        let key = PackKey::new([0x66; 32]);
        let payload = vec![9u8; 4096];
        t.upload_pack(&payload, &key).unwrap();

        let mut stream = t.download_pack_streaming(&key).expect("stream opens");
        let first = stream.next().expect("one chunk").expect("no error");
        assert_eq!(first.data, payload);
        assert!(first.last);
        assert!(
            stream.next().is_none(),
            "default impl yields exactly one chunk"
        );
    }

    #[test]
    fn download_pack_streaming_default_propagates_not_found() {
        let t = RecordingTransport::default();
        let key = PackKey::new([0x77; 32]);
        // `Box<dyn Iterator<..>>`'s `Ok` type isn't `Debug`, so match
        // instead of `expect_err`.
        match t.download_pack_streaming(&key) {
            Err(TransportError::PackNotFound) => {}
            Err(other) => panic!("expected PackNotFound, got {other:?}"),
            Ok(_) => panic!("missing pack must fail before any chunk is produced"),
        }
    }
}
