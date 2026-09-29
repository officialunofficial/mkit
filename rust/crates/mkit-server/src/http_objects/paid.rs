//! Paid body accounting. Bytes mean bytes handed to the response stream.
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use bytes::Bytes;
use futures::{Stream, StreamExt};

use super::HttpBody;
use crate::rt::{BoxFuture, Clock, Sleep, Spawner};
use crate::{BoxStream, ServerError};

/// Runtime services required to retain read settlement after cancellation.
/// Native adapters use tasks; Worker adapters must use the request's
/// `wait_until` lifetime. A spawner must run accepted work to completion.
#[derive(Clone)]
pub struct HttpReadRuntime {
    /// Timer used to stop transmission even while the source is pending.
    pub sleep: Arc<dyn Sleep>,
    /// Retains settlement independently of the response body's lifetime.
    pub spawner: Arc<dyn Spawner>,
}

#[cfg(not(target_arch = "wasm32"))]
type Finish = Box<dyn FnOnce(u64, bool) -> BoxFuture<'static, ()> + Send>;
#[cfg(target_arch = "wasm32")]
type Finish = Box<dyn FnOnce(u64, bool) -> BoxFuture<'static, ()>>;

/// Owns the obligation as soon as Pending is durable, including while the
/// byte source is being opened. Dropping it retains a zero-byte abort.
pub(crate) struct ReadFinalizer {
    pub(crate) deadline_ms: u64,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) runtime: HttpReadRuntime,
    pub(crate) finish: Option<Finish>,
    pub(crate) sent: u64,
}

impl core::fmt::Debug for HttpReadRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpReadRuntime").finish_non_exhaustive()
    }
}

impl ReadFinalizer {
    fn start(&mut self, success: bool) -> BoxFuture<'static, ()> {
        let Some(finish) = self.finish.take() else {
            return Box::pin(async {});
        };
        let work = finish(self.sent, success);
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.runtime.spawner.spawn(Box::pin(async move {
            work.await;
            let _ = tx.send(());
        }));
        Box::pin(async move {
            let _ = rx.await;
        })
    }

    pub(crate) async fn complete(mut self, success: bool) {
        self.start(success).await;
    }

    pub(crate) fn wrap(self, body: HttpBody) -> HttpBody {
        let (len, source): (u64, BoxStream<'static, Result<Bytes, ServerError>>) = match body {
            HttpBody::Empty => (0, Box::pin(futures::stream::empty())),
            HttpBody::Bytes(bytes) => (
                bytes.len() as u64,
                Box::pin(futures::stream::once(core::future::ready(Ok(bytes)))),
            ),
            HttpBody::Stream { len, stream } => (len, stream),
        };
        let now = u64::try_from(self.clock.now_ms()).unwrap_or(0);
        let timer = self.runtime.sleep.sleep(core::time::Duration::from_millis(
            self.deadline_ms.saturating_sub(now),
        ));
        HttpBody::Stream {
            len,
            stream: Box::pin(Paid {
                source,
                finalizer: self,
                timer,
                settling: None,
                error: None,
                done: false,
            }),
        }
    }
}

impl Drop for ReadFinalizer {
    fn drop(&mut self) {
        drop(self.start(false));
    }
}

struct Paid {
    source: BoxStream<'static, Result<Bytes, ServerError>>,
    finalizer: ReadFinalizer,
    timer: BoxFuture<'static, ()>,
    settling: Option<BoxFuture<'static, ()>>,
    error: Option<ServerError>,
    done: bool,
}

impl Stream for Paid {
    type Item = Result<Bytes, ServerError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self.settling.is_none() {
            let elapsed = u64::try_from(self.finalizer.clock.now_ms()).unwrap_or(0)
                >= self.finalizer.deadline_ms
                || self.timer.as_mut().poll(cx).is_ready();
            let result = if elapsed {
                Poll::Ready(Some(Err(ServerError::unavailable("read deadline passed"))))
            } else {
                self.source.poll_next_unpin(cx)
            };
            match result {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(_)))
                    if u64::try_from(self.finalizer.clock.now_ms()).unwrap_or(0)
                        >= self.finalizer.deadline_ms =>
                {
                    self.error = Some(ServerError::unavailable("read deadline passed"));
                    self.settling = Some(self.finalizer.start(false));
                }
                Poll::Ready(Some(Ok(piece))) => {
                    self.finalizer.sent += piece.len() as u64;
                    return Poll::Ready(Some(Ok(piece)));
                }
                Poll::Ready(Some(Err(error))) => {
                    self.error = Some(error);
                    self.settling = Some(self.finalizer.start(false));
                }
                Poll::Ready(None) => self.settling = Some(self.finalizer.start(true)),
            }
        }
        if let Some(settling) = &mut self.settling
            && settling.as_mut().poll(cx).is_pending()
        {
            return Poll::Pending;
        }
        self.done = true;
        Poll::Ready(self.error.take().map(Err))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::rt::{ManualClock, ManualSleep};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Queued(Mutex<Vec<BoxFuture<'static, ()>>>);
    impl Spawner for Queued {
        fn spawn(&self, fut: BoxFuture<'static, ()>) {
            self.0.lock().unwrap().push(fut);
        }
    }
    impl Queued {
        fn run(&self) {
            for task in self.0.lock().unwrap().drain(..) {
                futures_executor::block_on(task);
            }
        }
    }
    type Ends = Arc<Mutex<Vec<(u64, bool)>>>;
    fn finalizer() -> (ReadFinalizer, Arc<Queued>, Arc<ManualSleep>, Ends) {
        let tasks = Arc::new(Queued::default());
        let sleep = Arc::new(ManualSleep::new());
        let ended: Ends = Arc::default();
        let save = ended.clone();
        (
            ReadFinalizer {
                deadline_ms: 1000,
                clock: Arc::new(ManualClock::new(0)),
                runtime: HttpReadRuntime {
                    sleep: sleep.clone(),
                    spawner: tasks.clone(),
                },
                sent: 0,
                finish: Some(Box::new(move |n, success| {
                    Box::pin(async move {
                        save.lock().unwrap().push((n, success));
                    })
                })),
            },
            tasks,
            sleep,
            ended,
        )
    }
    fn poll(
        stream: &mut BoxStream<'static, Result<Bytes, ServerError>>,
    ) -> Poll<Option<Result<Bytes, ServerError>>> {
        stream
            .as_mut()
            .poll_next(&mut Context::from_waker(futures::task::noop_waker_ref()))
    }

    #[test]
    fn normal_eof_waits_for_finalizer_and_drop_while_waiting_retains_it() {
        for cancel in [false, true] {
            let (f, tasks, _, ended) = finalizer();
            let HttpBody::Stream { mut stream, .. } =
                f.wrap(HttpBody::Bytes(Bytes::from_static(b"abc")))
            else {
                panic!()
            };
            assert!(matches!(poll(&mut stream), Poll::Ready(Some(Ok(_)))));
            assert!(poll(&mut stream).is_pending());
            assert!(ended.lock().unwrap().is_empty());
            if cancel {
                drop(stream);
                tasks.run();
            } else {
                tasks.run();
                assert!(matches!(poll(&mut stream), Poll::Ready(None)));
            }
            assert_eq!(*ended.lock().unwrap(), [(3, true)]);
        }
    }
    #[test]
    fn deadline_wakes_pending_source_and_aborts_zero_byte_read() {
        let (f, tasks, sleep, ended) = finalizer();
        let HttpBody::Stream { mut stream, .. } = f.wrap(HttpBody::Stream {
            len: 1,
            stream: Box::pin(futures::stream::pending()),
        }) else {
            panic!()
        };
        assert!(poll(&mut stream).is_pending());
        sleep.fire();
        assert!(
            poll(&mut stream).is_pending(),
            "settlement precedes the stream error"
        );
        tasks.run();
        assert!(matches!(poll(&mut stream), Poll::Ready(Some(Err(_)))));
        assert_eq!(*ended.lock().unwrap(), [(0, false)]);
    }
    #[test]
    fn a_backend_poll_cannot_hand_out_a_piece_after_the_deadline() {
        let (mut f, tasks, _, ended) = finalizer();
        let clock = Arc::new(ManualClock::new(0));
        f.clock = clock.clone();
        let source = futures::stream::once(async move {
            clock.set(1000);
            Ok(Bytes::from_static(b"x"))
        });
        let HttpBody::Stream { mut stream, .. } = f.wrap(HttpBody::Stream {
            len: 1,
            stream: Box::pin(source),
        }) else {
            panic!()
        };
        assert!(poll(&mut stream).is_pending());
        tasks.run();
        assert!(matches!(poll(&mut stream), Poll::Ready(Some(Err(_)))));
        assert_eq!(*ended.lock().unwrap(), [(0, false)]);
    }

    #[test]
    fn zero_length_get_settles_successfully() {
        let (f, tasks, _, ended) = finalizer();
        let HttpBody::Stream { mut stream, .. } = f.wrap(HttpBody::Empty) else {
            panic!()
        };
        assert!(poll(&mut stream).is_pending());
        tasks.run();
        assert!(matches!(poll(&mut stream), Poll::Ready(None)));
        assert_eq!(*ended.lock().unwrap(), [(0, true)]);
    }
}
