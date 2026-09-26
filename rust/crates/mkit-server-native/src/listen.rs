//! The accept loop: hyper-util's HTTP/1.1 + h2c connection builder with a
//! timer, so the header-read timeout and HTTP/2 keepalive take effect, a
//! cap on open connections, and graceful shutdown.

use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceExt as _;

use crate::Shutdown;

/// How the listener treats connections. [`ServeOptions::default`] holds
/// the `mkit-server serve` defaults.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ServeOptions {
    /// After shutdown begins, how long in-flight requests may run before
    /// they are dropped.
    pub grace: Duration,
    /// How long a client may take to send a request's headers (and, on a
    /// new connection, to pick HTTP/1.1 or HTTP/2). A slow or silent client
    /// is disconnected.
    pub header_read_timeout: Duration,
    /// Connections open at once; further clients wait in the kernel's
    /// accept backlog until one closes.
    pub max_connections: usize,
    /// HTTP/2 keepalive: ping an idle connection this often...
    pub h2_keepalive_interval: Duration,
    /// ...and close it if the ping is not answered within this.
    pub h2_keepalive_timeout: Duration,
    /// Concurrent streams per HTTP/2 connection.
    pub h2_max_concurrent_streams: u32,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(30),
            header_read_timeout: Duration::from_secs(10),
            max_connections: 1024,
            h2_keepalive_interval: Duration::from_secs(30),
            h2_keepalive_timeout: Duration::from_secs(20),
            h2_max_concurrent_streams: 128,
        }
    }
}

/// Serve `router` on `listener` until `shutdown` triggers, then stop
/// accepting and let in-flight requests finish, for at most
/// [`ServeOptions::grace`].
///
/// Returns once every connection closed, or when the grace period ran
/// out. Connections still open then are abandoned: they end when the
/// runtime shuts down (the binary shuts it down right after), which drops
/// their requests. An upload dropped that way leaves nothing visible.
///
/// # Errors
/// A non-transient accept error.
pub async fn serve(
    listener: TcpListener,
    router: axum::Router,
    shutdown: Shutdown,
    opts: &ServeOptions,
) -> std::io::Result<()> {
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(opts.max_connections.max(1)));
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(opts.header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(opts.h2_keepalive_interval)
        .keep_alive_timeout(opts.h2_keepalive_timeout)
        .max_concurrent_streams(opts.h2_max_concurrent_streams);
    let builder = Arc::new(builder);
    let stop = shutdown.wait();
    tokio::pin!(stop);
    loop {
        // A slot first, so excess clients wait in the backlog.
        let slot = tokio::select! {
            biased;
            () = &mut stop => break,
            slot = Arc::clone(&slots).acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_) => break,
            },
        };
        let stream = tokio::select! {
            biased;
            () = &mut stop => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) if transient(&e) => {
                    tracing::warn!(error = %e, "accept failed; continuing");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(e) => return Err(e),
            },
        };
        let _ = stream.set_nodelay(true);
        let io = DetectionTimeout::new(stream, opts.header_read_timeout);
        let router = router.clone();
        let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
            router.clone().oneshot(req.map(Body::new))
        });
        let conn = builder
            .serve_connection_with_upgrades(TokioIo::new(io), service)
            .into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "connection ended with an error");
            }
            drop(slot);
        });
    }
    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(opts.grace) => {
            tracing::warn!(
                grace_secs = opts.grace.as_secs(),
                "shutdown grace expired; dropping in-flight requests"
            );
        }
    }
    Ok(())
}

/// An accept error that affects one connection, or passes (descriptor
/// exhaustion): back off briefly and keep accepting.
fn transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionAborted, ConnectionReset, Interrupted};
    matches!(e.kind(), ConnectionAborted | ConnectionReset | Interrupted)
        || e.raw_os_error()
            .is_some_and(|code| code == 23 || code == 24) // ENFILE, EMFILE
}

/// The bytes an HTTP/2 client sends first (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// A new connection's stream whose reads fail once `timeout` passes before
/// the peer has sent enough to pick HTTP/1.1 or HTTP/2. hyper's header
/// read timeout starts only after that choice, so without this a client
/// that connects and sends nothing (or a lone `P`) would hold its
/// connection slot forever. Adapted from connectrpc's `DetectionTimeout`.
struct DetectionTimeout<I> {
    io: I,
    detection: Option<Detection>,
}

struct Detection {
    /// Bytes of [`H2_PREFACE`] seen so far.
    matched: usize,
    sleep: Pin<Box<tokio::time::Sleep>>,
}

impl<I> DetectionTimeout<I> {
    fn new(io: I, timeout: Duration) -> Self {
        let detection = (!timeout.is_zero()).then(|| Detection {
            matched: 0,
            sleep: Box::pin(tokio::time::sleep(timeout)),
        });
        Self { io, detection }
    }
}

impl Detection {
    /// Record bytes read; whether the protocol is now decided. An empty
    /// read is the peer closing.
    fn observe(&mut self, read: &[u8]) -> bool {
        let rest = &H2_PREFACE[self.matched..];
        if read.is_empty() || read.len() >= rest.len() || !rest.starts_with(read) {
            return true;
        }
        self.matched += read.len();
        false
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for DetectionTimeout<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        let Some(detection) = &mut this.detection else {
            return Pin::new(&mut this.io).poll_read(cx, buf);
        };
        let start = buf.filled().len();
        match Pin::new(&mut this.io).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if detection.observe(&buf.filled()[start..]) {
                    this.detection = None;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                std::task::ready!(detection.sleep.as_mut().poll(cx));
                this.detection = None;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "no HTTP request within the header read timeout",
                )))
            }
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for DetectionTimeout<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
