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
}
