//! On-disk bitmap cache for verified sparse-checkout deliveries.
//!
//! Spec: `docs/SPEC-SPARSE-CHECKOUT.md` §6. Cache layout:
//!
//! ```text
//! <repo-root>/.mkit/sparse/<tree-hex>.bitmap
//! ```
//!
//! One file per (`tree_hash`) — the per-filter binding lives inside the
//! file body. A cache hit means "we have *some* verified sparse
//! delivery for this tree"; the caller still has to cross-check the
//! filter hash before trusting the bitmap. The file format is defined
//! by [`mkit_core::sparse::encode_sparse_cache`] /
//! [`mkit_core::sparse::decode_sparse_cache`].
//!
//! This module is feature-gated by `sparse-checkout` because it depends
//! on the `mkit_core::sparse` module which is itself feature-gated.

#![cfg(feature = "sparse-checkout")]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use mkit_core::hash::{Hash, to_hex};
use mkit_core::sparse::{
    SPARSE_CACHE_DIR, SparseManifest, SparseProof, SparseWireError, decode_sparse_cache,
    encode_sparse_cache,
};

/// Errors raised by the cache I/O helpers. Wrapping the `io::Error`
/// directly keeps the call sites concise — the cache is best-effort,
/// so callers usually log-and-continue rather than blow up.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("wire: {0}")]
    Wire(#[from] SparseWireError),
    /// Cache file existed but recorded a different filter hash. Not
    /// strictly an "error" — callers usually treat this as a cache
    /// miss and re-fetch — but distinct from the I/O / wire variants
    /// so a misfit cache doesn't get silently overwritten.
    #[error("cached delivery committed to a different filter")]
    FilterMismatch,
}

/// Compute `<root>/.mkit/sparse/<tree-hex>.bitmap`. The directory may
/// not exist yet; [`store`] creates it on demand.
#[must_use]
pub fn cache_path(repo_root: &Path, tree_hash: &Hash) -> PathBuf {
    repo_root
        .join(mkit_core::MKIT_DIR)
        .join(SPARSE_CACHE_DIR)
        .join(format!("{}.bitmap", to_hex(tree_hash)))
}

/// Persist a verified manifest + proof to the cache. Idempotent:
/// re-storing the same `(tree_hash, manifest, proof)` triple
/// over-writes the existing bytes byte-for-byte.
///
/// # Errors
///
/// Returns [`CacheError::Io`] for any underlying filesystem error. The
/// missing parent directory is created first; if that or the write
/// fails (typically permissions / disk full) the error is propagated.
pub fn store(
    repo_root: &Path,
    tree_hash: &Hash,
    manifest: &SparseManifest,
    proof: &SparseProof,
) -> Result<(), CacheError> {
    let path = cache_path(repo_root, tree_hash);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = encode_sparse_cache(manifest, proof);
    // Write-rename is overkill for a best-effort cache — a torn write
    // surfaces as a wire-decode failure on the next read, which the
    // caller treats as a cache miss. Plain `fs::write` is fine.
    fs::write(path, bytes)?;
    Ok(())
}

/// Load a cached delivery for `(tree_hash, filter_hash)`. Returns
/// `Ok(None)` for a fresh repo / cache miss; `Err(_)` only for I/O or
/// wire failures.
///
/// The function does *not* re-verify the bitmap-root against the
/// bytes — that's the verifier's job. It only enforces that the
/// cached filter hash matches the caller's expected hash, so a stale
/// cache for a different filter doesn't get silently returned.
///
/// # Errors
///
/// - [`CacheError::Io`] — I/O failure other than "not found".
/// - [`CacheError::Wire`] — the cache file exists but is malformed.
/// - [`CacheError::FilterMismatch`] — cache exists for the tree but
///   for a different filter.
pub fn load(
    repo_root: &Path,
    tree_hash: &Hash,
    expected_filter_hash: &Hash,
) -> Result<Option<(SparseManifest, SparseProof)>, CacheError> {
    let path = cache_path(repo_root, tree_hash);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let (bitmap_root, filter_hash, leaf_count, bitmap_bytes) = decode_sparse_cache(&bytes)?;
    if filter_hash != *expected_filter_hash {
        return Err(CacheError::FilterMismatch);
    }
    Ok(Some((
        SparseManifest {
            tree_hash: *tree_hash,
            bitmap_root,
            filter_hash,
            leaf_count,
        },
        SparseProof { bitmap_bytes },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::object::{EntryMode, Tree, TreeEntry};
    use mkit_core::sparse::{build_sparse, hash_filter};

    fn entry(name: &[u8]) -> TreeEntry {
        TreeEntry {
            name: name.to_vec(),
            mode: EntryMode::Blob,
            object_hash: [0u8; 32],
        }
    }

    #[test]
    fn round_trip_load_returns_stored_payload() {
        let td = tempfile::tempdir().unwrap();
        // Need a .mkit directory shape so cache_path's parent is
        // creatable from the helper.
        fs::create_dir_all(td.path().join(mkit_core::MKIT_DIR)).unwrap();
        let tree = Tree {
            entries: vec![entry(b"aa"), entry(b"ab"), entry(b"ac")],
        };
        let filter = vec![PathBuf::from("aa")];
        let (_, manifest, proof) = build_sparse(&tree, &filter).unwrap();

        store(td.path(), &manifest.tree_hash, &manifest, &proof).unwrap();

        let loaded = load(td.path(), &manifest.tree_hash, &manifest.filter_hash)
            .unwrap()
            .expect("just stored");
        assert_eq!(loaded.0.bitmap_root, manifest.bitmap_root);
        assert_eq!(loaded.0.filter_hash, manifest.filter_hash);
        assert_eq!(loaded.0.leaf_count, manifest.leaf_count);
        assert_eq!(loaded.1.bitmap_bytes, proof.bitmap_bytes);
    }

    #[test]
    fn load_returns_none_for_missing_tree() {
        let td = tempfile::tempdir().unwrap();
        let h = [0u8; 32];
        let res = load(td.path(), &h, &hash_filter(&[])).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn load_rejects_mismatched_filter_hash() {
        let td = tempfile::tempdir().unwrap();
        fs::create_dir_all(td.path().join(mkit_core::MKIT_DIR)).unwrap();
        let tree = Tree {
            entries: vec![entry(b"aa"), entry(b"ab")],
        };
        let (_, manifest, proof) = build_sparse(&tree, &[PathBuf::from("aa")]).unwrap();
        store(td.path(), &manifest.tree_hash, &manifest, &proof).unwrap();

        // Lookup with a *different* filter hash → should fail loudly.
        let other_filter_hash = hash_filter(&[PathBuf::from("zz")]);
        let err = load(td.path(), &manifest.tree_hash, &other_filter_hash).unwrap_err();
        assert!(matches!(err, CacheError::FilterMismatch));
    }
}
