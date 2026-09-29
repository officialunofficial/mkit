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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::sync::{Arc, Mutex};

    use futures::StreamExt as _;
    use futures_executor::block_on;

    use super::*;

    type Ended = Arc<Mutex<Vec<(u64, Option<Code>)>>>;

    fn hook(ended: &Ended) -> EndHook {
        let ended = ended.clone();
        Box::new(move |sent, result| {
            ended
                .lock()
                .unwrap()
                .push((sent, result.err().map(ServerError::code)));
        })
    }

    fn source(pieces: Vec<Result<&'static [u8], StoreError>>) -> BoxStream<'static, Result<Bytes, StoreError>> {
        Box::pin(futures::stream::iter(
            pieces
                .into_iter()
                .map(|piece| piece.map(Bytes::from_static))
                .collect::<Vec<_>>(),
        ))
    }

    fn collect(body: HttpBody) -> Vec<Result<usize, Code>> {
        let HttpBody::Stream { stream, .. } = body else {
            panic!("expected a stream");
        };
        block_on(stream.map(|p| p.map(|b| b.len()).map_err(|e| e.code())).collect())
    }

    #[test]
    fn an_exact_body_reports_its_end_once() {
        let ended = Ended::default();
        let body = exact(source(vec![Ok(b"abc"), Ok(b"de")]), 5, Some(hook(&ended)));
        assert_eq!(collect(body), vec![Ok(3), Ok(2)]);
        assert_eq!(*ended.lock().unwrap(), [(5, None)]);
    }

    #[test]
    fn a_wrong_length_or_a_backend_failure_fails_the_body_and_the_hook() {
        for (pieces, len, sent, want) in [
            (vec![Ok(&b"abcd"[..])], 3, 0, vec![Err(Code::Unavailable)]),
            (vec![Ok(&b"ab"[..])], 3, 2, vec![Ok(2), Err(Code::Unavailable)]),
            (
                vec![Ok(&b"ab"[..]), Err(StoreError::unavailable("SECRET backend detail"))],
                4,
                2,
                vec![Ok(2), Err(Code::Unavailable)],
            ),
        ] {
            let ended = Ended::default();
            let got = collect(exact(source(pieces), len, Some(hook(&ended))));
            assert_eq!(got, want);
            assert_eq!(*ended.lock().unwrap(), [(sent, Some(Code::Unavailable))]);
        }
    }

    #[test]
    fn a_dropped_body_reports_canceled_with_what_was_sent() {
        let ended = Ended::default();
        let HttpBody::Stream { mut stream, .. } =
            exact(source(vec![Ok(b"abc"), Ok(b"def")]), 6, Some(hook(&ended)))
        else {
            panic!();
        };
        assert_eq!(block_on(stream.next()).unwrap().unwrap().len(), 3);
        drop(stream);
        assert_eq!(*ended.lock().unwrap(), [(3, Some(Code::Canceled))]);
    }

    #[test]
    fn a_backend_error_is_redacted_to_a_fixed_message() {
        let body = exact(
            source(vec![Err(StoreError::unavailable("SECRET backend detail"))]),
            1,
            None,
        );
        let HttpBody::Stream { mut stream, .. } = body else {
            panic!();
        };
        let error = block_on(stream.next()).unwrap().unwrap_err();
        assert!(!format!("{error:?} {error}").contains("SECRET"));
        assert_eq!(error.public_message(), "object storage request failed");
    }

    #[test]
    fn a_hook_also_covers_in_memory_and_empty_bodies() {
        let ended = Ended::default();
        let body = with_hook(HttpBody::Bytes(Bytes::from_static(b"xyz")), Some(hook(&ended)));
        assert!(ended.lock().unwrap().is_empty(), "fires when consumed");
        assert_eq!(collect(body), vec![Ok(3)]);
        assert_eq!(*ended.lock().unwrap(), [(3, None)]);
        with_hook(HttpBody::Empty, Some(hook(&ended)));
        assert_eq!(ended.lock().unwrap()[1], (0, None));
        // Without a hook the body is untouched.
        assert!(matches!(
            with_hook(HttpBody::Bytes(Bytes::new()), None),
            HttpBody::Bytes(_)
        ));
    }
}
