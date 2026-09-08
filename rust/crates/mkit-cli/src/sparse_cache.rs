//! On-disk witness cache for verified sparse-checkout deliveries.
//!
//! Spec: `docs/specs/SPEC-SPARSE-CHECKOUT.md` §6. Cache layout:
//!
//! ```text
//! <repo-root>/.mkit/sparse/<tree-hex>.witness
//! ```
//!
//! One file per (`tree_hash`) — the per-filter binding lives inside the
//! file body. A cache hit means "we have *some* verified sparse
//! delivery for this tree"; the caller still has to cross-check the
//! filter hash before using the witness. The file format is defined
//! by [`mkit_core::sparse::encode_sparse_cache`] /
//! [`mkit_core::sparse::decode_sparse_cache`].
//!
//! This module is feature-gated by `sparse-checkout` because it depends
//! on the `mkit_core::sparse` module which is itself feature-gated.

#![cfg(feature = "sparse-checkout")]

use mkit_core::layout::RepoLayout;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use mkit_core::hash::{Hash, to_hex};
use mkit_core::object::Tree;
use mkit_core::sparse::{
    SparseError, SparseManifest, SparseProof, SparseWireError, build_sparse, decode_sparse_cache,
    encode_sparse_cache, hash_filter, tree_hash as compute_tree_hash, verify_sparse,
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

/// Compute `<common dir>/sparse/<tree-hex>.witness`. The directory may
/// not exist yet; [`store`] creates it on demand. Common-dir state:
/// the cache is keyed by tree hash, so it is shared across worktrees.
#[must_use]
pub fn cache_path(layout: &RepoLayout, tree_hash: &Hash) -> PathBuf {
    layout
        .sparse_cache_dir()
        .join(format!("{}.witness", to_hex(tree_hash)))
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
    layout: &RepoLayout,
    tree_hash: &Hash,
    manifest: &SparseManifest,
    proof: &SparseProof,
) -> Result<(), CacheError> {
    let path = cache_path(layout, tree_hash);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = encode_sparse_cache(manifest, proof)?;
    // Write-rename is overkill for a best-effort cache — a torn write
    // surfaces as a wire-decode failure on the next read, which the
    // caller treats as a cache miss. Plain `fs::write` is fine.
    fs::write(path, bytes)?;
    Ok(())
}

/// Read and authenticate a bounded v2 cache witness against the requested
/// tree and filter identities. Unsupported versions, malformed and substituted entries fail.
///
/// # Errors
/// Returns filesystem, wire or identity errors; callers may rebuild on a miss.
pub fn load(
    layout: &RepoLayout,
    tree_hash: &Hash,
    expected_filter_hash: &Hash,
) -> Result<Option<(SparseManifest, SparseProof)>, CacheError> {
    let path = cache_path(layout, tree_hash);
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take((mkit_core::sparse::SPARSE_WIRE_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let (manifest, proof) = decode_sparse_cache(&bytes)?;
    if manifest.filter_hash != *expected_filter_hash || manifest.tree_hash != *tree_hash {
        return Err(CacheError::FilterMismatch);
    }
    Ok(Some((manifest, proof)))
}

/// Errors from [`load_or_build`]'s fresh-build path. A cache-read
/// failure is never one of these — it is always treated as a miss (see
/// [`load_or_build`]'s doc).
#[derive(Debug, thiserror::Error)]
pub enum SparseBuildError {
    #[error("sparse build: {0}")]
    Build(#[from] SparseError),
    #[error("sparse build produced a manifest that fails verify")]
    VerifyFailed,
}

/// Outcome of [`load_or_build`]: whether the on-disk cache satisfied
/// the request or a fresh manifest had to be built.
#[derive(Debug)]
pub enum SparseOutcome {
    /// `(tree_hash, filter_hash)` was already cached — the expensive
    /// `build_sparse` + `verify_sparse` witness construction
    /// was skipped entirely.
    CacheHit,
    /// Full authenticated metadata is already local; sparse grammar/size is unsupported.
    FullMetadata,
    /// No usable cache entry existed (miss, filter mismatch, or a
    /// corrupt/undecodable entry); a fresh manifest was built and
    /// self-verified. `store_error` is `Some` if persisting it back to
    /// the cache failed (best-effort — the caller may want to warn on
    /// stderr, as `store`'s own doc explains this is never fatal).
    Built { store_error: Option<CacheError> },
}

/// Revalidate a cache witness or build it from authenticated local metadata.
/// Unsupported filters and oversized witnesses retain the existing full-metadata
/// restoration path. Cache failures are disposable misses.
///
/// # Errors
/// Invalid local trees or a failed self-verification return a build error.
pub fn load_or_build(
    layout: &RepoLayout,
    tree: &Tree,
    filter: &[PathBuf],
) -> Result<SparseOutcome, SparseBuildError> {
    if mkit_core::sparse::validate_filter(filter).is_err() {
        return Ok(SparseOutcome::FullMetadata);
    }
    let th = compute_tree_hash(tree);
    let fh = hash_filter(filter);
    if let Ok(Some(_)) = load(layout, &th, &fh) {
        return Ok(SparseOutcome::CacheHit);
    }

    let response = match build_sparse(tree, filter) {
        Ok(value) => value,
        Err(SparseError::TooLarge | SparseError::UnsupportedFilter) => {
            return Ok(SparseOutcome::FullMetadata);
        }
        Err(error) => return Err(error.into()),
    };
    if verify_sparse(&th, filter, &response).is_err() {
        return Err(SparseBuildError::VerifyFailed);
    }
    // Best-effort: a write failure here doesn't invalidate the build
    // the caller is about to materialise from, only the next run's
    // ability to skip re-deriving it — surfaced to the caller as
    // `store_error` rather than swallowed, so it can warn on stderr as
    // before.
    let store_error = store(layout, &th, &response.manifest, &response.proof).err();
    Ok(SparseOutcome::Built { store_error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::object::{EntryMode, TreeEntry};

    #[test]
    fn cache_rejects_valid_witness_under_wrong_tree_filename() {
        let td = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(td.path());
        let tree = Tree {
            entries: vec![entry(b"a")],
        };
        let filter = [PathBuf::from("a")];
        let mkit_core::sparse::SparseResponse { manifest, proof } =
            build_sparse(&tree, &filter).unwrap();
        let wrong = [7; 32];
        store(&layout, &wrong, &manifest, &proof).unwrap();
        assert!(load(&layout, &wrong, &hash_filter(&filter)).is_err());
        let mut corrupt = encode_sparse_cache(&manifest, &proof).unwrap();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(cache_path(&layout, &manifest.tree_hash), corrupt).unwrap();
        assert!(load(&layout, &manifest.tree_hash, &hash_filter(&filter)).is_err());
    }

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
        let layout = RepoLayout::single(td.path());
        // Need a .mkit directory shape so cache_path's parent is
        // creatable from the helper.
        fs::create_dir_all(td.path().join(mkit_core::MKIT_DIR)).unwrap();
        let tree = Tree {
            entries: vec![entry(b"aa"), entry(b"ab"), entry(b"ac")],
        };
        let filter = vec![PathBuf::from("aa")];
        let mkit_core::sparse::SparseResponse { manifest, proof } =
            build_sparse(&tree, &filter).unwrap();

        store(&layout, &manifest.tree_hash, &manifest, &proof).unwrap();

        let loaded = load(&layout, &manifest.tree_hash, &manifest.filter_hash)
            .unwrap()
            .expect("just stored");
        assert_eq!(loaded.0.tree_hash, manifest.tree_hash);
        assert_eq!(loaded.0.filter_hash, manifest.filter_hash);
        assert_eq!(loaded.1.tree_bytes, proof.tree_bytes);
    }

    #[test]
    fn load_returns_none_for_missing_tree() {
        let td = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(td.path());
        let h = [0u8; 32];
        let res = load(&layout, &h, &hash_filter(&[])).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn load_rejects_mismatched_filter_hash() {
        let td = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(td.path());
        fs::create_dir_all(td.path().join(mkit_core::MKIT_DIR)).unwrap();
        let tree = Tree {
            entries: vec![entry(b"aa"), entry(b"ab")],
        };
        let mkit_core::sparse::SparseResponse { manifest, proof } =
            build_sparse(&tree, &[PathBuf::from("aa")]).unwrap();
        store(&layout, &manifest.tree_hash, &manifest, &proof).unwrap();

        // Lookup with a *different* filter hash → should fail loudly.
        let other_filter_hash = hash_filter(&[PathBuf::from("zz")]);
        let err = load(&layout, &manifest.tree_hash, &other_filter_hash).unwrap_err();
        assert!(matches!(err, CacheError::FilterMismatch));
    }

    #[test]
    fn load_or_build_hits_cache_on_repeat_call() {
        let td = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(td.path());
        fs::create_dir_all(td.path().join(mkit_core::MKIT_DIR)).unwrap();
        let tree = Tree {
            entries: vec![entry(b"aa"), entry(b"ab"), entry(b"ac")],
        };
        let filter = vec![PathBuf::from("aa")];

        let first = load_or_build(&layout, &tree, &filter).unwrap();
        assert!(
            matches!(first, SparseOutcome::Built { store_error: None }),
            "first call for a never-seen (tree, filter) must build fresh, got {first:?}"
        );

        let second = load_or_build(&layout, &tree, &filter).unwrap();
        assert!(
            matches!(second, SparseOutcome::CacheHit),
            "repeat call with an unchanged filter must hit the cache instead of rebuilding, got {second:?}"
        );
    }

    #[test]
    fn load_or_build_treats_filter_change_as_a_miss_and_rewrites_cache() {
        let td = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(td.path());
        fs::create_dir_all(td.path().join(mkit_core::MKIT_DIR)).unwrap();
        let tree = Tree {
            entries: vec![entry(b"aa"), entry(b"ab"), entry(b"ac")],
        };
        let th = mkit_core::sparse::tree_hash(&tree);

        let first_filter = vec![PathBuf::from("aa")];
        load_or_build(&layout, &tree, &first_filter).unwrap();
        let cached_after_first = load(&layout, &th, &hash_filter(&first_filter))
            .unwrap()
            .expect("first build cached its own filter");

        // Same tree, different filter: the cache file (keyed only by
        // tree_hash) exists but commits to the OLD filter — this must
        // be treated as a miss, never silently returned.
        let second_filter = vec![PathBuf::from("ab")];
        let outcome = load_or_build(&layout, &tree, &second_filter).unwrap();
        assert!(
            matches!(outcome, SparseOutcome::Built { store_error: None }),
            "a filter change for the same tree must miss and rebuild, got {outcome:?}"
        );

        // The miss must have rewritten the cache to the NEW filter, no
        // error surfaced.
        let cached_after_second = load(&layout, &th, &hash_filter(&second_filter))
            .unwrap()
            .expect("miss must rewrite the cache under the new filter");
        assert_ne!(
            cached_after_second.0.filter_hash,
            cached_after_first.0.filter_hash
        );
        assert_eq!(
            cached_after_second.0.filter_hash,
            hash_filter(&second_filter)
        );
    }

    #[test]
    fn load_or_build_treats_corrupt_cache_entry_as_a_miss_and_repairs_it() {
        let td = tempfile::tempdir().unwrap();
        let layout = RepoLayout::single(td.path());
        fs::create_dir_all(td.path().join(mkit_core::MKIT_DIR)).unwrap();
        let tree = Tree {
            entries: vec![entry(b"aa"), entry(b"ab"), entry(b"ac")],
        };
        let filter = vec![PathBuf::from("aa")];
        let th = mkit_core::sparse::tree_hash(&tree);

        load_or_build(&layout, &tree, &filter).unwrap();

        // Corrupt the on-disk cache entry directly.
        let path = cache_path(&layout, &th);
        fs::write(&path, b"not a valid sparse cache body").unwrap();
        assert!(matches!(
            load(&layout, &th, &hash_filter(&filter)),
            Err(CacheError::Wire(_))
        ));

        // A corrupt entry must be treated as a miss — fresh build, no
        // error surfaced — and must repair the cache for next time.
        let outcome = load_or_build(&layout, &tree, &filter).unwrap();
        assert!(
            matches!(outcome, SparseOutcome::Built { store_error: None }),
            "a corrupt cache entry must miss and rebuild, got {outcome:?}"
        );
        assert!(
            load(&layout, &th, &hash_filter(&filter)).unwrap().is_some(),
            "the miss must have repaired the cache entry"
        );
    }
}
