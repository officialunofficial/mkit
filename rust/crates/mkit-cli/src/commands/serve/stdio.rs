//! The stdin side of `mkit serve`: a reader thread and the idle timeout.
//!
//! A blocking read of stdin cannot be given a deadline, so a thread reads
//! frames (`mkit_rpc::read_frame`) and hands them to the session over a
//! one-slot channel; [`StdioFrameSource::next_frame`] waits on it with
//! `recv_timeout`. Blocking inside the future is correct under the CLI's
//! `block_on`, where nothing else is scheduled.
//!
//! **Idle** means no byte from the client: the thread stamps the time of
//! every read that returns data, and a wait ends with
//! [`FrameIoError::Timeout`] only once the idle period has passed since
//! both the start of the wait and the last byte. So a slow upload that
//! keeps sending never trips it, even when one chunk frame takes longer
//! than the timeout to arrive; time the server spends answering (a long
//! download, verifying a pack) never counts; and a client that sends
//! nothing, before `Hello`, between requests or in the middle of an upload,
//! is cut off.
//!
//! When the session ends the thread may still be blocked on stdin. It is
//! not joined: the process exits under it.

use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use mkit_rpc::mkit::rpc::v1::ssh::SshFrame;
use mkit_server::Redacted;
use mkit_server::ssh::{FrameIoError, FrameSource};

/// When the client last sent a byte, as milliseconds since `base`.
#[derive(Debug)]
struct Activity {
    base: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let ms = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.fetch_max(ms, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        let since = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        self.base.checked_add(since).unwrap_or(self.base)
    }
}

/// A reader that stamps [`Activity`] whenever a read returns data.
struct Stamped<R> {
    inner: R,
    activity: Arc<Activity>,
}

impl<R: Read> Read for Stamped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.activity.touch();
        }
        Ok(n)
    }
}

/// The session's frame source over stdin (or any blocking reader), with an
/// optional idle timeout.
#[derive(Debug)]
pub(super) struct StdioFrameSource {
    rx: Receiver<Result<SshFrame, FrameIoError>>,
    idle: Option<Duration>,
    activity: Arc<Activity>,
}

impl StdioFrameSource {
    /// Start the reader thread on `input`. `idle` is the idle timeout;
    /// `None` waits forever.
    ///
    /// # Errors
    /// The thread could not be spawned.
    pub(super) fn spawn<R: Read + Send + 'static>(
        input: R,
        idle: Option<Duration>,
    ) -> io::Result<Self> {
        let activity = Arc::new(Activity::new());
        // One frame (at most 1 MiB) waits while the next is read.
        let (tx, rx) = mpsc::sync_channel(1);
        let mut reader = Stamped {
            inner: input,
            activity: Arc::clone(&activity),
        };
        std::thread::Builder::new()
            .name("mkit-serve-stdin".to_owned())
            .spawn(move || {
                loop {
                    let item = mkit_rpc::read_frame::<_, SshFrame>(&mut reader)
                        .map_err(FrameIoError::from);
                    let stop = item.is_err();
                    if tx.send(item).is_err() || stop {
                        return;
                    }
                }
            })?;
        Ok(Self { rx, idle, activity })
    }
}

impl FrameSource for StdioFrameSource {
    async fn next_frame(&mut self) -> Result<SshFrame, FrameIoError> {
        let gone = || FrameIoError::Io(Redacted::new("stdin reader stopped"));
        let Some(idle) = self.idle else {
            return self.rx.recv().unwrap_or_else(|_| Err(gone()));
        };
        let waiting_since = Instant::now();
        loop {
            // A deadline past what `Instant` can hold is no deadline.
            let Some(deadline) = waiting_since.max(self.activity.last()).checked_add(idle) else {
                return self.rx.recv().unwrap_or_else(|_| Err(gone()));
            };
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Err(FrameIoError::Timeout);
            };
            match self.rx.recv_timeout(left) {
                Ok(item) => return item,
                // Bytes may have arrived meanwhile: recompute.
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(gone()),
            }
        }
    }
}
