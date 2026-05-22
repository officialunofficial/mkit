//! Minimal `commonware_runtime::{Sink, Stream}` wrappers around the
//! raw `tokio::net::tcp::{OwnedWriteHalf, OwnedReadHalf}`.
//!
//! Why hand-rolled and not the upstream `commonware_runtime::network::tokio`
//! types? Those types are `pub(crate)` — the upstream crate exposes them
//! only through its tokio `Runner::start` Context, which is a one-shot
//! driver that owns its tokio runtime and drops it when the future
//! completes. mkit's `Transport` is sync, long-lived, and must outlive
//! the dial call, so we need to own our own tokio runtime and our own
//! Sink/Stream wrappers tied to that runtime's halves.
//!
//! The implementations are intentionally tiny: `recv` reads exactly
//! `len` bytes into a freshly-allocated buffer; `send` writes the
//! coalesced payload. No timeouts at this layer — the encrypted
//! handshake already enforces its own `handshake_timeout`, and the
//! application-level Hello uses the `Transport` retry policy from
//! `mkit-core::protocol`.

use std::io;

use commonware_runtime::{Error as RuntimeError, IoBuf, IoBufs, Sink, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

/// `commonware_runtime::Sink` over a tokio `OwnedWriteHalf`.
///
/// Coalesces the input `IoBufs` into a single byte run and writes it
/// with `write_all`. Errors collapse to [`RuntimeError::SendFailed`];
/// finer-grained mapping isn't useful at this layer because the
/// encrypted layer above us only branches on "did the send go through
/// or not".
#[derive(Debug)]
pub struct TokioSink {
    inner: OwnedWriteHalf,
}

impl TokioSink {
    /// Wrap a tokio `OwnedWriteHalf`. Public so server-side test
    /// harnesses (the e2e test under `tests/`) can build a `Sink`
    /// without going through the higher-level `connect_tcp` /
    /// `serve_tcp` entry points.
    #[must_use]
    pub fn new(inner: OwnedWriteHalf) -> Self {
        Self { inner }
    }
}

impl Sink for TokioSink {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), RuntimeError> {
        let bufs = bufs.into();
        let coalesced = bufs.coalesce();
        self.inner
            .write_all(coalesced.as_ref())
            .await
            .map_err(|_| RuntimeError::SendFailed)
    }
}

/// `commonware_runtime::Stream` over a tokio `OwnedReadHalf`.
///
/// `recv(len)` reads exactly `len` bytes via `read_exact`. No internal
/// buffering — the encrypted layer above us issues two reads per
/// frame (one for the varint length prefix, one for the body), and
/// those reads are large enough that the syscall overhead is amortised
/// over the message payload. If profiling later shows the cost is
/// material, a `BufReader` can be slotted in without changing the
/// public Stream signature.
#[derive(Debug)]
pub struct TokioStream {
    inner: OwnedReadHalf,
    /// Tiny one-shot peek buffer. The `Stream::peek` API returns a
    /// borrowed slice without doing I/O; an unbuffered tokio half has
    /// no buffered data, so we always return an empty slice here. The
    /// encrypted layer doesn't currently call `peek`, but the trait
    /// requires it.
    peek_buf: [u8; 0],
}

impl TokioStream {
    /// Wrap a tokio `OwnedReadHalf`. Public for the same reason as
    /// [`TokioSink::new`] — keeps the test harness free of an
    /// internal-only constructor wart.
    #[must_use]
    pub fn new(inner: OwnedReadHalf) -> Self {
        Self {
            inner,
            peek_buf: [],
        }
    }
}

impl Stream for TokioStream {
    async fn recv(&mut self, len: usize) -> Result<IoBufs, RuntimeError> {
        let mut buf = vec![0u8; len];
        self.inner
            .read_exact(&mut buf)
            .await
            .map_err(|_| RuntimeError::RecvFailed)?;
        Ok(IoBufs::from(IoBuf::copy_from_slice(&buf)))
    }

    fn peek(&self, _max_len: usize) -> &[u8] {
        // Unbuffered: there is never any buffered data to peek at.
        // The trait contract permits returning `&[]` to signal "do a
        // real `recv` instead".
        &self.peek_buf
    }
}

/// Convenience: split a fully-connected `tokio::net::TcpStream` into
/// our two wrappers, applying `TCP_NODELAY` along the way. NODELAY is
/// the right default for an interactive frame-oriented protocol — we
/// don't want the kernel coalescing a small `Hello` with the next
/// verb's bytes.
pub(crate) fn split_tcp(stream: tokio::net::TcpStream) -> io::Result<(TokioSink, TokioStream)> {
    stream.set_nodelay(true)?;
    let (read, write) = stream.into_split();
    Ok((TokioSink::new(write), TokioStream::new(read)))
}
