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
pub use layout::FsLayoutStore;

use crate::store::StoreError;

/// An I/O or transport failure as [`StoreError::Unavailable`].
fn unavailable(e: impl std::error::Error + Send + Sync + 'static) -> StoreError {
    StoreError::unavailable(e)
}
