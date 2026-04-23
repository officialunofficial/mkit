//! URL-scheme → `Transport` dispatch for `mkit push` / `mkit pull`.
//!
//! The Rust 0.2.x binary wires `mkit+file://`; the memory transport is
//! in-process only, so it is reached via [`push_all_with`] /
//! [`pull_all_with`] rather than URL-based construction. Integration
//! tests in the `mkit-cli` crate exercise the memory path directly to
//! satisfy the Phase 9 test matrix without resorting to file I/O.
//!
//! The remaining schemes (`mkit+https`, `mkit+s3`, `mkit+ssh`) are
//! deferred to the Phase 10 cutover, where the binary grows argv /
//! netrc / SSH-config integration. Their transport crates already
//! implement the trait, so the dispatch here is a one-line extension.

use std::path::Path;
use std::sync::Arc;

use mkit_core::protocol::{Transport, TransportError};
use mkit_core::refs::{self, Head};
use mkit_transport_file::FileTransport;

/// Errors returned by the push / pull helpers. Mapped to exit codes by
/// the commands themselves.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    #[error("malformed URL: {0}")]
    MalformedUrl(String),
    #[error("no HEAD branch to push")]
    NoHead,
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("refs: {0}")]
    Refs(#[from] refs::RefError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Open a transport for the given URL. Returns a type-erased `Arc`
/// so callers can treat all schemes uniformly.
pub fn open(url: &str) -> Result<Arc<dyn Transport>, DispatchError> {
    if let Some(rest) = url.strip_prefix("mkit+file://") {
        // mkit+file:///abs/path -> /abs/path
        let path = Path::new(rest);
        return Ok(Arc::new(FileTransport::new(path)));
    }
    if url.starts_with("mkit+memory://") {
        // Memory transport is in-process; the URL-based path is not
        // useful on its own but we accept it so `mkit remote add`
        // round-trips cleanly.
        return Err(DispatchError::UnsupportedScheme(
            "mkit+memory:// must be driven via in-process harness (see tests)".to_string(),
        ));
    }
    if url.starts_with("mkit+https://")
        || url.starts_with("mkit+s3://")
        || url.starts_with("mkit+ssh://")
    {
        return Err(DispatchError::UnsupportedScheme(format!(
            "{url} — Phase 10 follow-up (transport crates exist; argv wiring deferred)"
        )));
    }
    Err(DispatchError::MalformedUrl(url.to_string()))
}

/// Push every ref under `refs/heads/` to the remote. Returns the count
/// of refs pushed. Pack upload is NOT implemented yet — this only
/// publishes the ref pointers. The Rust pack writer (`mkit-core::pack`)
/// has everything we need, but generating a pack from the full object
/// graph reachable from the commit requires a graph-walk helper that
/// is slated for Phase 10.
pub fn push_all(cwd: &Path, tx: &dyn Transport) -> Result<usize, DispatchError> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let refs_list = refs::list_refs(&mkit_dir)?;
    let mut n = 0;
    for r in refs_list {
        let Some(h) = r.hash else { continue };
        let full_name = format!("refs/heads/{}", r.name);
        tx.write_ref(&full_name, &h)?;
        n += 1;
    }
    Ok(n)
}

/// Mirror the remote's ref set into the local repo. Count returned =
/// number of refs updated locally. Same pack-transfer limitation as
/// [`push_all`].
pub fn pull_all(cwd: &Path, tx: &dyn Transport) -> Result<usize, DispatchError> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let remote_refs = tx.list_refs("refs/heads/")?;
    let mut n = 0;
    for r in remote_refs {
        let Some(h) = r.hash else { continue };
        // `list_refs("refs/heads/")` returns names with the prefix
        // stripped, per SPEC-REFS §4.
        refs::write_ref(&mkit_dir, &r.name, &h)?;
        n += 1;
    }
    // If HEAD is unset (freshly initialised), point it at the first
    // branch we saw. This keeps the `pull` UX intuitive for a clone-ish
    // flow even without `mkit clone` support.
    if (refs::read_head(&mkit_dir).is_err()
        || matches!(refs::read_head(&mkit_dir), Ok(Head::Branch(ref b)) if refs::read_ref(&mkit_dir, b).is_ok_and(|x| x.is_none())))
        && let Ok(mut all) = refs::list_refs(&mkit_dir)
    {
        all.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(first) = all.first() {
            let _ = refs::write_head_branch(&mkit_dir, &first.name);
        }
    }
    Ok(n)
}
