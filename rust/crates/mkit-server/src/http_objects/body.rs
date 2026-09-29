//! Response bodies: the length-enforcing wrapper and the end-of-body hook.

use core::pin::Pin;
use core::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;

use crate::store::StoreError;
use crate::{BoxStream, Code, ServerError};

/// A response body. `Stream` carries its exact length: the stream errors
/// instead of yielding more or fewer bytes.
pub enum HttpBody {
    /// No body (HEAD, 204, 304 and every error).
    Empty,
    /// The whole body in memory.
    Bytes(Bytes),
    /// A body of exactly `len` bytes, streamed in pieces.
    Stream {
        /// The exact number of body bytes.
        len: u64,
        /// The pieces, in order.
        stream: BoxStream<'static, Result<Bytes, ServerError>>,
    },
}

impl core::fmt::Debug for HttpBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Bytes(b) => f.debug_tuple("Bytes").field(&b.len()).finish(),
            Self::Stream { len, .. } => f.debug_struct("Stream").field("len", len).finish(),
        }
    }
}

/// Called once when a body ends, with the bytes sent and how it ended
/// (WP-4.13's `ReadServed{bytes}` and `Aborted(INTERNAL)` hook). A body
/// dropped before its end reports `canceled`.
#[cfg(not(target_arch = "wasm32"))]
pub type EndHook = Box<dyn FnOnce(u64, Result<(), &ServerError>) + Send>;
/// Called once when a body ends; see the native definition.
#[cfg(target_arch = "wasm32")]
pub type EndHook = Box<dyn FnOnce(u64, Result<(), &ServerError>)>;

fn overrun() -> ServerError {
    ServerError::unavailable("object body length changed")
}

/// Enforces `remaining` bytes and fires the hook exactly once.
struct Exact {
    inner: BoxStream<'static, Result<Bytes, ServerError>>,
    remaining: u64,
    sent: u64,
    hook: Option<EndHook>,
    done: bool,
}

impl Exact {
    fn end(&mut self, result: Result<(), &ServerError>) {
        self.done = true;
        if let Some(hook) = self.hook.take() {
            hook(self.sent, result);
        }
    }

    fn fail(&mut self, error: ServerError) -> Poll<Option<Result<Bytes, ServerError>>> {
        self.end(Err(&error));
        Poll::Ready(Some(Err(error)))
    }
}

impl Stream for Exact {
    type Item = Result<Bytes, ServerError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(piece))) => {
                let n = piece.len() as u64;
                if n > self.remaining {
                    return self.fail(overrun());
                }
                self.remaining -= n;
                self.sent += n;
                Poll::Ready(Some(Ok(piece)))
            }
            Poll::Ready(Some(Err(error))) => self.fail(error),
            Poll::Ready(None) if self.remaining != 0 => self.fail(overrun()),
            Poll::Ready(None) => {
                self.end(Ok(()));
                Poll::Ready(None)
            }
        }
    }
}

impl Drop for Exact {
    fn drop(&mut self) {
        if !self.done {
            self.end(Err(&ServerError::new(Code::Canceled, "request canceled")));
        }
    }
}

fn wrap(
    stream: BoxStream<'static, Result<Bytes, ServerError>>,
    len: u64,
    hook: Option<EndHook>,
) -> HttpBody {
    HttpBody::Stream {
        len,
        stream: Box::pin(Exact {
            inner: stream,
            remaining: len,
            sent: 0,
            hook,
            done: false,
        }),
    }
}

/// Wrap a backend `stream` so it yields exactly `len` bytes or fails,
/// reporting its end to `hook`. Backend errors are logged and redacted to a
/// fixed message.
#[must_use]
pub fn exact(
    stream: BoxStream<'static, Result<Bytes, StoreError>>,
    len: u64,
    hook: Option<EndHook>,
) -> HttpBody {
    let stream = futures::StreamExt::map(stream, |piece| {
        piece.map_err(|error| {
            tracing::warn!(detail = %error, "object body read failed");
            ServerError::unavailable("object storage request failed")
        })
    });
    wrap(Box::pin(stream), len, hook)
}

/// `body` with `hook` attached: a stream is wrapped, an in-memory body
/// becomes a one-piece stream so the hook still fires when it is consumed.
#[must_use]
pub fn with_hook(body: HttpBody, hook: Option<EndHook>) -> HttpBody {
    let Some(hook) = hook else {
        return body;
    };
    match body {
        HttpBody::Empty => {
            hook(0, Ok(()));
            HttpBody::Empty
        }
        HttpBody::Bytes(bytes) => {
            let len = bytes.len() as u64;
            wrap(
                Box::pin(futures::stream::once(core::future::ready(Ok(bytes)))),
                len,
                Some(hook),
            )
        }
        HttpBody::Stream { len, stream } => wrap(stream, len, Some(hook)),
    }
}
