//! `TokioSpawner`: `mkit_server::Spawner` over the server's runtime.

use mkit_server::{BoxFuture, Spawner};
use tokio::runtime::Handle;

use crate::Shutdown;

/// Spawns background work (the M1 scheduler's periodic tick, WP-1.14) on
/// the server's tokio runtime. Every task is cancelled at its next await
/// once the server's [`Shutdown`] triggers, so none outlives the drain.
#[derive(Debug, Clone)]
pub struct TokioSpawner {
    handle: Handle,
    shutdown: Shutdown,
}

impl TokioSpawner {
    /// A spawner on `handle`, stopped by `shutdown`.
    #[must_use]
    pub fn new(handle: Handle, shutdown: Shutdown) -> Self {
        Self { handle, shutdown }
    }

    /// A spawner on the current runtime.
    ///
    /// # Panics
    /// Outside a tokio runtime.
    #[must_use]
    pub fn current(shutdown: Shutdown) -> Self {
        Self::new(Handle::current(), shutdown)
    }
}

impl Spawner for TokioSpawner {
    fn spawn(&self, fut: BoxFuture<'static, ()>) {
        let stop = self.shutdown.wait();
        self.handle.spawn(async move {
            tokio::select! {
                () = fut => {}
                () = stop => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tasks_run_and_stop_at_shutdown() {
        let shutdown = Shutdown::new();
        let spawner = TokioSpawner::current(shutdown.clone());
        let (tx, rx) = tokio::sync::oneshot::channel();
        spawner.spawn(Box::pin(async move {
            let _ = tx.send(());
        }));
        rx.await.unwrap();

        let finished = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&finished);
        let (started_tx, started) = tokio::sync::oneshot::channel();
        spawner.spawn(Box::pin(async move {
            let _ = started_tx.send(());
            tokio::time::sleep(Duration::from_hours(1)).await;
            flag.store(true, Ordering::SeqCst);
        }));
        started.await.unwrap();
        shutdown.trigger();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!finished.load(Ordering::SeqCst));
        assert!(shutdown.is_triggered());
    }
}
