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
//! HTTP transport lives in `apps/` outside the workspace. Both are
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
///
/// Hidden from the public API: this is server-side reference
/// infrastructure for issue #158 with no shipping verb yet (see the
/// module docs), retained so future servers stay byte-consistent.
#[doc(hidden)]
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
#[doc(hidden)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::hash::ZERO;
    use mkit_core::object::{EntryMode, Tree, TreeEntry};
    use std::path::PathBuf;

    fn entry(name: &[u8]) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode: EntryMode::Blob,
            object_hash: ZERO,
        }
    }

    #[test]
    fn builds_response_for_filtered_subtree() {
        // Two lex-sorted entries; a filter on "aa" selects exactly one.
        let tree = Tree {
            entries: vec![entry(b"aa"), entry(b"ab")],
        };
        let resp = build_sparse_response_from_tree(&tree, &[PathBuf::from("aa")])
            .expect("valid sorted tree builds a sparse response");
        assert_eq!(resp.entries.len(), 1);
        assert_eq!(resp.entries[0].name, b"aa");
    }

    #[test]
    fn unsorted_tree_is_rejected() {
        let tree = Tree {
            entries: vec![entry(b"ab"), entry(b"aa")],
        };
        assert!(build_sparse_response_from_tree(&tree, &[PathBuf::from("aa")]).is_err());
    }
}
