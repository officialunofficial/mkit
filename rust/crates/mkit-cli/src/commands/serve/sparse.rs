//! Server-side sparse-tree reference implementation (issue #158).
//!
//! Relocated out of the parent `serve` module. These helpers capture the
//! "read the source tree, walk it with the supplied filter, produce a
//! verifiable manifest+entries+proof" pipeline once so future server
//! implementations stay byte-for-byte consistent with the client-side
//! verifier.
//!
//! The SSH transport is currently bytes-on-stream framed (mkit-rpc) and
//! has no sparse-tree verb today; the Cloudflare Worker that backs the
//! HTTP transport lives in `web/` outside the workspace. Both are
//! expected to evolve to call these helpers directly. What the Worker
//! would do:
//!   1. Resolve `<project>/trees/<hex>` against R2.
//!   2. Deserialise the resulting bytes into an `Object::Tree`.
//!   3. Cross-check the URL's `?sparse=<filter-hex>` against
//!      `hash_filter(filter_paths_from_body)`. Reject on mismatch with
//!      HTTP 409 (transport surface: `RefConflict`).
//!   4. Call [`build_sparse_response_from_tree`].
//!   5. Serialise via `encode_sparse_response` and return as
//!      `application/x-mkit-sparse`.
//!
//! All four steps are pure once you have the deserialised tree, hence
//! the narrow `(tree, filter)` shape below.

/// Errors raised by [`build_sparse_response_from_tree`].
#[derive(Debug, thiserror::Error)]
pub enum SparseServeError {
    /// Forward of any [`mkit_core::sparse::SparseError`] — the source
    /// tree was unsorted, oversized, or the filter was too large.
    #[error("sparse build: {0}")]
    Build(#[from] mkit_core::sparse::SparseError),
}

/// Build a [`mkit_core::sparse::SparseResponse`] from an already-resolved
/// tree and a filter. Pure — no I/O. The caller has already loaded the
/// tree from whatever backing store they own (object store for `mkit
/// serve`, R2 for the Cloudflare Worker, memory transport for tests).
///
/// This is the reference implementation for the server side: any
/// conforming server MUST produce the same bytes given the same
/// `(tree, filter)` inputs, so a client comparing two server responses
/// would see a byte-for-byte match.
///
/// # Errors
///
/// Forwards [`mkit_core::sparse::SparseError`] — unsorted tree, too
/// many leaves, too many filter paths.
pub fn build_sparse_response_from_tree(
    tree: &mkit_core::object::Tree,
    filter: &[std::path::PathBuf],
) -> Result<mkit_core::sparse::SparseResponse, SparseServeError> {
    let (entries, manifest, proof) = mkit_core::sparse::build_sparse(tree, filter)?;
    Ok(mkit_core::sparse::SparseResponse {
        manifest,
        entries,
        proof,
    })
}

/// Convenience: resolve a `tree_hash` from `store` and build a sparse
/// response. Used by both the on-disk `mkit serve` path (when an SSH
/// verb is eventually added) and by integration tests that drive the
/// server pipeline end-to-end.
///
/// # Errors
///
/// - [`mkit_core::store::StoreError`] surfaces if `tree_hash` is not
///   present or the on-disk object is malformed.
/// - The address must resolve to an `Object::Tree`; anything else is
///   reported as a descriptive error string. (We rewrap rather than
///   introduce a new error type so the downstream serve loop can keep
///   its existing error taxonomy.)
pub fn build_sparse_response_from_store(
    store: &mkit_core::store::ObjectStore,
    tree_hash: &mkit_core::hash::Hash,
    filter: &[std::path::PathBuf],
) -> Result<mkit_core::sparse::SparseResponse, String> {
    use mkit_core::object::Object;
    let tree = match store.read_object(tree_hash) {
        Ok(Object::Tree(t)) => t,
        Ok(_) => return Err("addressed object is not a tree".to_string()),
        Err(e) => return Err(format!("read tree: {e}")),
    };
    build_sparse_response_from_tree(&tree, filter).map_err(|e| e.to_string())
}
