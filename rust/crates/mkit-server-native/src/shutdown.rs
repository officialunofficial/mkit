//! Graceful shutdown: SIGINT/SIGTERM, a drain, and a grace deadline.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::watch;

/// A shutdown switch shared by the listener, the [`crate::TokioSpawner`]
/// and whoever triggers it. Cloning shares the switch.
#[derive(Debug, Clone)]
pub struct Shutdown {
    tx: Arc<watch::Sender<bool>>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    /// A switch that is off.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: Arc::new(watch::Sender::new(false)),
        }
    }

    /// Start shutting down. Idempotent.
    pub fn trigger(&self) {
        self.tx.send_replace(true);
    }

    /// Whether [`Self::trigger`] ran.
    #[must_use]
    pub fn is_triggered(&self) -> bool {
        *self.tx.borrow()
    }

    /// Resolves once [`Self::trigger`] runs (at once if it already did).
    pub fn wait(&self) -> impl Future<Output = ()> + Send + 'static {
        let mut rx = self.tx.subscribe();
        async move {
            // The sender lives in `self`'s clones; if every one is gone,
            // nothing can trigger it any more, so wait forever.
            if rx.wait_for(|on| *on).await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Resolves on SIGINT (Ctrl-C) or, on Unix, SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => tracing::info!("SIGINT: shutting down"),
        () = term => tracing::info!("SIGTERM: shutting down"),
    }
}
