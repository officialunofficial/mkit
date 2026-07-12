//! Sync-over-async bridge driving the async ConnectRPC client from the
//! synchronous [`mkit_core::protocol::Transport`] trait.
//!
//! Mirrors `mkit-transport-enc`'s `tcp::TokioExecutor` — a dedicated,
//! single-worker multi-thread tokio runtime owned by the transport, driven
//! via [`mkit_core::protocol::async_shim::Executor::block_on`]. A
//! multi-thread runtime (not `current_thread`) is required because
//! `connectrpc`'s `hyper-util` client spawns background connection-driver
//! tasks that must keep running after a given `block_on` call returns
//! (e.g. between two sequential `Transport` calls on the same connection
//! pool).

use std::sync::Arc;

use mkit_core::protocol::async_shim::Executor;

/// Owns a dedicated tokio runtime for one [`crate::ConnectTransport`]
/// instance.
#[derive(Clone)]
pub(crate) struct TokioExecutor {
    runtime: Arc<tokio::runtime::Runtime>,
}

impl std::fmt::Debug for TokioExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokioExecutor").finish_non_exhaustive()
    }
}

impl TokioExecutor {
    /// Build a fresh single-worker multi-thread tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if tokio fails to allocate worker threads —
    /// almost always means the host is out of resources.
    pub(crate) fn new() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        Ok(Self {
            runtime: Arc::new(runtime),
        })
    }
}

impl Executor for TokioExecutor {
    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: core::future::Future<Output = T> + Send,
        T: Send,
    {
        // `Handle::block_on` panics if called from inside a tokio worker on
        // the same runtime. `ConnectTransport` is only ever driven from
        // synchronous, non-runtime code (the CLI's push/pull loop), so we
        // never hit that path.
        self.runtime.handle().block_on(fut)
    }
}

impl TokioExecutor {
    /// Escape hatch identical to [`Executor::block_on`] except it drops the
    /// trait method's `F: Future + Send` bound — [`tokio::runtime::Handle::
    /// block_on`] itself has no such requirement.
    ///
    /// `download_pack`'s server-streaming read hits a genuine rustc
    /// limitation, not an actual thread-safety issue: `connectrpc`'s
    /// `ServerStream::message()` return type captures a buffa-generated
    /// `...View<'a>` whose `MessageView` impl is written for a specific
    /// lifetime `'a`, not (as `Send`-bound HRTB inference needs) for *any*
    /// lifetime — "implementation of `MessageView` is not general enough".
    /// The future genuinely is `Send` (every value it holds across an
    /// `.await` is `Send`); the compiler just can't prove it through this
    /// particular GAT shape. Since [`TokioExecutor`] never crosses an
    /// actual thread boundary that would need `Send` for soundness (see
    /// [`block_on`](Executor::block_on)'s panic note — same single-caller
    /// discipline applies here), calling `Handle::block_on` directly is a
    /// sound, narrowly-scoped workaround, not a correctness compromise.
    pub(crate) fn block_on_local<F, T>(&self, fut: F) -> T
    where
        F: core::future::Future<Output = T>,
    {
        self.runtime.handle().block_on(fut)
    }
}
