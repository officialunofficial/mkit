//! Storage errors, shared by the key-value and blob contracts.

use std::borrow::Cow;

/// A boxed backend error: `Send + Sync` on native targets only, because
/// Workers errors are `!Send`.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// A boxed backend error: `Send + Sync` on native targets only, because
/// Workers errors are `!Send`.
#[cfg(target_arch = "wasm32")]
pub type BoxError = Box<dyn std::error::Error>;

/// Why a storage call failed. A failed precondition is not an error: it is
/// [`crate::BatchOutcome::PreconditionFailed`].
///
/// The pipeline maps these to a [`crate::ServerError`]; storage text never
/// reaches a client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The request breaks the contract: an oversize key, value or batch, a
    /// scan `limit` of 0, a malformed byte range, or a blob whose bytes do
    /// not match its key or declared length. Nothing was written.
    #[error("invalid storage request: {0}")]
    Invalid(Cow<'static, str>),
    /// A byte range starts at or past the end of a blob of `len` bytes
    /// (HTTP 416 on the serving path).
    #[error("byte range not satisfiable for a {len}-byte blob")]
    RangeNotSatisfiable {
        /// The blob's length.
        len: u64,
    },
    /// The store's [`crate::StoreCapabilities`] exclude the request, e.g. a
    /// non-ref key on a `RefsOnly` store or a multi-write batch on a store
    /// without `atomic_multi_key`. Nothing was written.
    #[error("unsupported by this store: {0}")]
    Unsupported(Cow<'static, str>),
    /// A stored value failed to decode (unknown codec version, wrong length).
    #[error("corrupt stored value: {0}")]
    Corrupt(Cow<'static, str>),
    /// The partition is at its storage cap and rejects writes that add
    /// data. Reads and delete-only batches keep working, so pruning still
    /// runs (Durable Objects and `SQLite` report `SQLITE_FULL`; see
    /// <https://developers.cloudflare.com/durable-objects/platform/limits/>).
    /// The pipeline answers a retryable `unavailable` ("storage partition
    /// full"), never `resource_exhausted`.
    #[error("storage partition full")]
    Full,
    /// The backend failed or could not be reached. The outcome of an
    /// `apply` that fails this way is unknown: the pipeline re-reads.
    #[error("storage unavailable: {0}")]
    Unavailable(#[source] BoxError),
}

impl StoreError {
    /// [`StoreError::Unavailable`] wrapping `source`.
    #[must_use]
    pub fn unavailable(source: impl Into<BoxError>) -> Self {
        Self::Unavailable(source.into())
    }
}
