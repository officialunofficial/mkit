//! Native clone, fetch and pull for `.mkit` repositories.
//!
//! `mkit-sync` is the filesystem layer behind the `mkit` command line's
//! `clone`, `fetch` and `pull`, as a library. Every call returns a typed
//! report or a typed error and prints nothing: warnings and progress go to a
//! [`SyncObserver`], and cancellation is polled through it.
//!
//! * No mkit config, credentials or environment variables are read by the
//!   library itself (downloaded packs are staged under the system temporary
//!   directory unless [`SyncOptions::staging_dir`] says otherwise). The caller
//!   passes the [`RemoteSource`] (already authenticated; for the transport
//!   backend the credentials live in the [`Transport`](mkit_core::protocol::Transport)
//!   it was built with) and the [`SyncOptions`].
//! * Signature verification of every commit, remix and tag a fetch
//!   introduces is on by default and fails closed. Turning it off is an
//!   explicit option.
//! * [`pull`] refuses anything that is not a fast-forward.
//!
//! The fetch engine reads through the [`RemoteSource`] trait. The always-on
//! backend, [`TransportSource`], wraps mkit-core's synchronous `Transport`, so
//! every transport scheme keeps working. With the `client` feature,
//! `ClientSource` reads `mkit+https` and `mkit+http` remotes through
//! `mkit_client::Client` with an injected signer; with `connect-native`,
//! `NativeHttp` is a small native HTTP channel (gzip only, adding no zstd) for it.

#![deny(unsafe_code)]
#![deny(clippy::print_stdout, clippy::print_stderr)]

mod applied_packs;
#[cfg(feature = "client")]
mod client_source;
mod clone;
mod error;
#[doc(hidden)]
pub mod fanout;
mod fetch;
mod lock;
#[cfg(feature = "connect-native")]
mod native;
mod observer;
pub mod packmap;
mod pull;
#[doc(hidden)]
pub mod restore_fanout;
mod source;
mod stage;
mod verify;
pub mod worktree;

pub use applied_packs::AppliedPacks;
#[cfg(feature = "client")]
pub use client_source::{ClientSource, Executor, FuturesExecutor};
pub use clone::{
    CloneError, CloneInitError, CloneRemote, CloneReport, DEFAULT_REMOTE_NAME, clone,
    init_clone_dir,
};
pub use error::SyncError;
pub use fetch::FetchReport;
pub use lock::{SERVE_LOCK, WORKTREE_LOCK, warn_if_served};
#[cfg(feature = "connect-native")]
pub use native::{NativeClock, NativeHttp, default_tls_config};
pub use observer::{NoopObserver, SyncEvent, SyncObserver};
pub use pull::{PullOutcome, PullReport, fetch, pull};
pub use source::{ErrorClassifier, RemoteSource, TransportSource};

use mkit_core::store::SyncPolicy;

/// Options shared by [`fetch`], [`pull`] and [`clone`]. Start from
/// [`SyncOptions::default`] and set the fields you need.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SyncOptions {
    /// Verify the Ed25519 signature of every commit, remix and tag the call
    /// introduces. `true` by default; failing closed on an unsigned or invalid
    /// object is the point of the check.
    pub verify_signatures: bool,
    /// The branch to land on (clone `-b`, pull). It must exist on the remote;
    /// there is no silent fallback. `None` selects by HEAD.
    pub target_branch: Option<String>,
    /// Object-store durability schedule.
    pub sync_policy: SyncPolicy,
    /// Directory under which downloaded packs are staged before they are
    /// unpacked. `None` uses the system temporary directory.
    pub staging_dir: Option<std::path::PathBuf>,
}

impl SyncOptions {
    /// Set [`verify_signatures`](Self::verify_signatures).
    #[must_use]
    pub fn with_verify_signatures(mut self, verify: bool) -> Self {
        self.verify_signatures = verify;
        self
    }

    /// Set [`target_branch`](Self::target_branch).
    #[must_use]
    pub fn with_target_branch(mut self, branch: Option<String>) -> Self {
        self.target_branch = branch;
        self
    }

    /// Set [`sync_policy`](Self::sync_policy).
    #[must_use]
    pub fn with_sync_policy(mut self, policy: SyncPolicy) -> Self {
        self.sync_policy = policy;
        self
    }

    /// Set [`staging_dir`](Self::staging_dir).
    #[must_use]
    pub fn with_staging_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.staging_dir = dir;
        self
    }
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            verify_signatures: true,
            target_branch: None,
            sync_policy: SyncPolicy::Batch,
            staging_dir: None,
        }
    }
}
