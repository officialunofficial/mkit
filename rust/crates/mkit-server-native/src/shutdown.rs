//! Graceful shutdown: SIGINT/SIGTERM, a drain, and a grace deadline.

use std::future::{Future, IntoFuture as _};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
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

/// Serve `router` on `listener` until `shutdown` triggers, then stop
/// accepting and let in-flight requests finish, for at most `grace`.
///
/// Returns once every connection closed, or when `grace` ran out. At that
/// point connections still open are abandoned: they end when the runtime
/// shuts down (the binary returns right after), which drops their
/// requests. An upload dropped that way leaves nothing visible.
///
/// # Errors
/// The listener's I/O error.
pub async fn serve(
    listener: TcpListener,
    router: axum::Router,
    shutdown: Shutdown,
    grace: Duration,
) -> std::io::Result<()> {
    let server = axum::serve(listener, router).with_graceful_shutdown(shutdown.wait());
    let deadline = async {
        shutdown.wait().await;
        tokio::time::sleep(grace).await;
    };
    tokio::select! {
        result = server.into_future() => result,
        () = deadline => {
            tracing::warn!(grace_secs = grace.as_secs(), "shutdown grace expired; dropping in-flight requests");
            Ok(())
        }
    }
}
