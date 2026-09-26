//! Stores over the `.mkit` on-disk layout that
//! [`FileTransport`](mkit_transport_file::FileTransport) uses today (PRD
//! §5.1, §6.9): [`FsBlobStore`] for `<root>/packs/<64-hex>` and
//! [`FsLayoutStore`] for refs as files under `<root>/refs/`, so
//! `mkit serve <repo-path>` (ssh) and a `mkit-server --repo-root`
//! deployment serve the same files local `mkit` commands and
//! `mkit+file://` remotes read.
//!
//! Both are std-only: every method is an `async fn` whose body does
//! blocking `std::fs` I/O and never awaits. That is correct under the
//! CLI's blocking executor; a tokio server wraps them in `spawn_blocking`.
//! Because a body never yields, dropping a future either never started it
//! or it already ran to completion (normative rule 4).
//!
//! Neither store keeps replay records or quota counters (overview Q4):
//! [`FsLayoutStore`] holds only the ref class, one key per batch, which is
//! all the pipeline needs for unsigned writes.

mod blob;
mod layout;
#[cfg(test)]
mod tests;

pub use blob::{FsBlobStore, FsPackSink};
pub use layout::{FsLayoutStore, META_MARKER};
use std::io::{self, ErrorKind};

use mkit_transport_file::RefFileError;

use crate::store::StoreError;

/// A failure that is neither I/O nor a ref file's, as
/// [`StoreError::Unavailable`].
fn unavailable(e: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::unavailable(e)
}

/// An I/O failure. A full disk or an exhausted quota (`ENOSPC`, `EDQUOT`)
/// is [`StoreError::Full`]; a directory where a file belongs or the
/// reverse (`EISDIR`, `ENOTDIR`) is [`StoreError::Invalid`], which no
/// retry fixes; anything else is [`StoreError::Unavailable`].
fn io_error(e: io::Error) -> StoreError {
    match e.kind() {
        ErrorKind::StorageFull | ErrorKind::QuotaExceeded => StoreError::Full,
        ErrorKind::IsADirectory | ErrorKind::NotADirectory => {
            StoreError::Invalid(format!("directory/file clash: {e}").into())
        }
        _ => StoreError::unavailable(e),
    }
}

/// A `FileTransport` ref-file failure: a clashing or invalid ref name is
/// [`StoreError::Invalid`], an undecodable ref file
/// [`StoreError::Corrupt`], I/O as [`io_error`], and a path escape (a
/// symlink planted under the root) [`StoreError::Unavailable`].
fn ref_file_error(e: RefFileError) -> StoreError {
    match e {
        RefFileError::InvalidName(name) => {
            StoreError::Invalid(format!("ref name {name} is invalid or clashes with a ref").into())
        }
        RefFileError::Corrupt(name) => {
            StoreError::Corrupt(format!("ref file {name} does not hold a ref id").into())
        }
        RefFileError::Io(e) => io_error(e),
        other => unavailable(other),
    }
}
