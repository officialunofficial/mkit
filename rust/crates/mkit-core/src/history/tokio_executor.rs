//! `tokio`-runtime-backed [`Executor`] for the journaled history MMR.
//!
//! Layered identically to the executor introduced for transport-enc
//! (issue #156) but kept inside `mkit-core::history` so the
//! `history-mmr` feature is self-contained — consumers don't need to
//! depend on `mkit-transport-enc` just to persist commit history.
//!
//! ## Threading and `block_on`
//!
//! [`TokioExecutor`] wraps a long-lived [`Arc<tokio::runtime::Runtime>`].
//! Its `block_on` calls [`tokio::runtime::Handle::block_on`] on the
//! wrapped runtime. This is safe from any thread that is **not**
//! itself a tokio worker on the same runtime — synchronous mkit code
//! paths (`refs::update_ref`, the CLI's commit loop) are fine, but
//! calling `block_on` from inside a `runtime.spawn()` task on this
//! runtime would panic. The history module never spawns tasks of its
//! own onto this runtime, so the constraint is purely about external
//! callers.

use std::sync::Arc;

use crate::protocol::async_shim::Executor;

/// `Arc`-shared sync/async bridge for the journaled history MMR.
///
/// Wraps an owned `Arc<tokio::runtime::Runtime>`. The runtime survives
/// for as long as any `TokioExecutor` clone is held, which means a
/// single [`crate::history::CommitHistory`] holding one executor keeps
/// the runtime alive for every `append` / `prove` / `root` call in its
/// lifetime.
#[derive(Clone, Debug)]
pub struct TokioExecutor {
    runtime: Arc<tokio::runtime::Runtime>,
}

impl TokioExecutor {
    /// Build a fresh multi-thread tokio runtime and wrap it.
    ///
    /// Two worker threads is enough to keep the commonware journaled
    /// MMR's internal locks unblocked without dedicating a thread per
    /// shard; bump if profiling ever shows contention.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if tokio refuses to
    /// allocate worker threads (almost always means the host is out of
    /// resources).
    pub fn new() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("mkit-history")
            .build()?;
        Ok(Self {
            runtime: Arc::new(runtime),
        })
    }

    /// Construct a `TokioExecutor` that shares an existing tokio
    /// runtime. Useful when the embedding application already owns
    /// one (e.g. a long-running server that wants the history MMR and
    /// other tokio-based services on the same pool).
    #[must_use]
    pub fn from_runtime(runtime: Arc<tokio::runtime::Runtime>) -> Self {
        Self { runtime }
    }

    /// Borrow the wrapped runtime's handle. Surfaced for callers that
    /// want to run helper async tasks on the same runtime the history
    /// MMR uses.
    #[must_use]
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

impl Executor for TokioExecutor {
    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: core::future::Future<Output = T> + Send,
        T: Send,
    {
        self.runtime.handle().block_on(fut)
    }
}
