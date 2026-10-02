//! Async and runtime model (PRD §5.2).
//!
//! Traits in this crate use native `async fn` / return-position
//! `impl Future + MaybeSend`. [`MaybeSend`] means `Send` on native targets
//! and is a blanket marker on wasm32, where Workers futures are `!Send`.
//! Where a `dyn` future is needed (hook lists), [`BoxFuture`] carries the
//! same conditional `Send`.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use core::time::Duration;
use std::sync::Arc;

/// `Send` on native targets; implemented for every type on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

/// `Send` on native targets; implemented for every type on wasm32.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// `Sync` on native targets; implemented for every type on wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync + ?Sized> MaybeSync for T {}

/// `Sync` on native targets; implemented for every type on wasm32.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSync for T {}

/// A boxed future that is `Send` on native targets only.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// A boxed future that is `Send` on native targets only.
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A boxed stream that is `Send` on native targets only.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxStream<'a, T> = Pin<Box<dyn futures_core::Stream<Item = T> + Send + 'a>>;
/// A boxed stream that is `Send` on native targets only.
#[cfg(target_arch = "wasm32")]
pub type BoxStream<'a, T> = Pin<Box<dyn futures_core::Stream<Item = T> + 'a>>;

/// Injected time source, in Unix epoch milliseconds.
///
/// Nothing in `mkit-server` reads `SystemTime` or `Instant` directly:
/// `Instant::now()` panics on wasm32 (see
/// `apps/mkit-worker-common/src/adapter.rs`), and tests need to control
/// time. Adapters pass their runtime's clock in.
pub trait Clock: MaybeSend + MaybeSync {
    /// The current time in Unix epoch milliseconds.
    fn now_ms(&self) -> i64;
}

/// The host wall clock. Native targets only; Workers supply their own.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

#[cfg(not(target_arch = "wasm32"))]
impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Saturate rather than panic: a clock this far off is a host fault
        // that the validity-window checks will reject anyway.
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(since) => i64::try_from(since.as_millis()).unwrap_or(i64::MAX),
            Err(before) => i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |ms| -ms),
        }
    }
}

/// A clock that only moves when told to. Usable on every target, and shared
/// across threads through interior mutability.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_ms: AtomicI64,
}

impl ManualClock {
    /// A clock reading `start_ms`.
    #[must_use]
    pub const fn new(start_ms: i64) -> Self {
        Self {
            now_ms: AtomicI64::new(start_ms),
        }
    }

    /// Set the reading to `now_ms`.
    pub fn set(&self, now_ms: i64) {
        self.now_ms.store(now_ms, Ordering::SeqCst);
    }

    /// Move the reading forward (or back, for a negative `delta_ms`).
    pub fn advance(&self, delta_ms: i64) {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.now_ms.load(Ordering::SeqCst)
    }
}

/// Injected task spawner: tokio on native, `wasm_bindgen_futures` or
/// `ctx.wait_until` on Workers.
pub trait Spawner: MaybeSend + MaybeSync {
    /// Run `fut` to completion in the background.
    fn spawn(&self, fut: BoxFuture<'static, ()>);
}

/// Injected timer, the counterpart of [`Clock`] for deadlines: `Instant` and
/// `tokio::time` are not available on every target, so an adapter passes in
/// its runtime's sleep (`tokio::time::sleep` on native, `worker::Delay` on
/// Workers) and core code bounds an external call with [`with_timeout`].
pub trait Sleep: MaybeSend + MaybeSync {
    /// A future that completes once `duration` has elapsed.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

impl<T: Sleep + ?Sized> Sleep for Arc<T> {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        (**self).sleep(duration)
    }
}

/// [`with_timeout`] gave up before the future finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

/// Run `fut`, giving up with [`Elapsed`] once `sleep` says `after` has passed.
/// A future that is ready wins over an elapsed timer, and a timed-out future
/// is dropped, so the caller must not assume its side effects did not land.
///
/// # Errors
/// [`Elapsed`] when the timer completes first.
pub async fn with_timeout<S, F>(sleep: &S, after: Duration, fut: F) -> Result<F::Output, Elapsed>
where
    S: Sleep + ?Sized,
    F: Future,
{
    let fut = core::pin::pin!(fut);
    match futures::future::select(fut, sleep.sleep(after)).await {
        futures::future::Either::Left((output, _)) => Ok(output),
        futures::future::Either::Right(((), _)) => Err(Elapsed),
    }
}

/// A [`Sleep`] that only completes when told to, for tests. Shared across
/// clones; [`ManualSleep::elapsed`] starts already fired.
#[derive(Debug, Clone, Default)]
pub struct ManualSleep {
    fired: Arc<AtomicBool>,
    wake: Arc<tokio::sync::Notify>,
    requested: Arc<std::sync::Mutex<Vec<Duration>>>,
}

impl ManualSleep {
    /// A sleeper whose sleeps stay pending until [`Self::fire`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A sleeper whose sleeps complete immediately.
    #[must_use]
    pub fn elapsed() -> Self {
        let sleeper = Self::default();
        sleeper.fire();
        sleeper
    }

    /// The duration of every sleep requested so far, in order.
    #[must_use]
    pub fn requested(&self) -> Vec<Duration> {
        self.requested
            .lock()
            .map_or_else(|poisoned| poisoned.into_inner().clone(), |v| v.clone())
    }

    /// Complete every current and future sleep.
    pub fn fire(&self) {
        self.fired.store(true, Ordering::SeqCst);
        self.wake.notify_waiters();
    }
}

impl Sleep for ManualSleep {
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        match self.requested.lock() {
            Ok(mut requested) => requested.push(duration),
            Err(poisoned) => poisoned.into_inner().push(duration),
        }
        let (fired, wake) = (self.fired.clone(), self.wake.clone());
        Box::pin(async move {
            loop {
                let notified = wake.notified();
                if fired.load(Ordering::SeqCst) {
                    return;
                }
                notified.await;
            }
        })
    }
}

/// Make a [`MaybeSend`] future satisfy the `+ Send` bound that generated
/// connectrpc service traits require. On native targets the future is
/// already `Send` and is returned unchanged.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn send_wrap<F: Future + Send>(f: F) -> F {
    f
}

/// Make a [`MaybeSend`] future satisfy the `+ Send` bound that generated
/// connectrpc service traits require. The Workers adapter wraps the whole
/// handler future once (PRD §5.2).
///
/// `SendWrapper` checks the thread on every poll and drop: a poll or drop on
/// a thread other than the one that created it panics, and is never
/// undefined behavior. Workers run wasm32 single-threaded, so it cannot
/// fire there; a wasm32 build with the `atomics` target feature can be
/// multi-threaded, and there the caller must keep the future on its
/// creating thread.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn send_wrap<F: Future>(f: F) -> send_wrapper::SendWrapper<F> {
    send_wrapper::SendWrapper::new(f)
}

/// [`send_wrap`] for a stream, e.g. a response stream handed to Connect's
/// `Response::stream_ok`. On native targets the stream is already `Send` and
/// is returned unchanged.
#[cfg(all(feature = "connect", not(target_arch = "wasm32")))]
pub(crate) fn send_wrap_stream<S: futures_core::Stream + Send>(s: S) -> S {
    s
}

/// [`send_wrap`] for a stream, e.g. a response stream handed to Connect's
/// `Response::stream_ok`; the same thread rule applies.
#[cfg(all(feature = "connect", target_arch = "wasm32"))]
pub(crate) fn send_wrap_stream<S: futures_core::Stream>(s: S) -> send_wrapper::SendWrapper<S> {
    send_wrapper::SendWrapper::new(s)
}

// Native only: these assert the native (`Send`) half of the model.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.now_ms(), 1_000);
        clock.advance(250);
        assert_eq!(clock.now_ms(), 1_250);
        clock.set(7);
        assert_eq!(clock.now_ms(), 7);
        assert_eq!(ManualClock::default().now_ms(), 0);
    }

    #[test]
    fn system_clock_is_after_2020() {
        // 2020-01-01T00:00:00Z; a sanity bound, not a precision check.
        assert!(SystemClock.now_ms() > 1_577_836_800_000);
    }

    #[test]
    fn send_wrap_is_identity_on_native() {
        let fut = send_wrap(async { 41 + 1 });
        assert_eq!(futures_executor::block_on(fut), 42);
    }

    fn assert_send<T: Send>(_: &T) {}

    /// A trait shaped like the storage/policy traits later work packages add.
    trait Service {
        fn call(&self) -> impl Future<Output = u8> + MaybeSend;
    }

    struct Seven;
    impl Service for Seven {
        async fn call(&self) -> u8 {
            7
        }
    }

    /// Compile-time check: on native, `MaybeSend: Send` makes a generic
    /// caller see the returned future as `Send` through supertrait
    /// elaboration, without naming the concrete type.
    fn require_send_from_generic<S: Service>(service: &S) -> u8 {
        let fut = service.call();
        assert_send(&fut);
        futures_executor::block_on(fut)
    }

    #[test]
    fn maybe_send_future_is_send_to_generic_callers_on_native() {
        assert_eq!(require_send_from_generic(&Seven), 7);
        let boxed: BoxFuture<'static, u8> = Box::pin(Seven.call());
        assert_send(&boxed);
    }

    #[test]
    fn with_timeout_returns_a_ready_future_and_times_out_a_pending_one() {
        let never = ManualSleep::new();
        let ready = with_timeout(&never, Duration::from_secs(5), async { 9 });
        assert_eq!(futures_executor::block_on(ready), Ok(9));
        let fired = ManualSleep::elapsed();
        let stuck = with_timeout(
            &fired,
            Duration::from_secs(5),
            core::future::pending::<u8>(),
        );
        assert_eq!(futures_executor::block_on(stuck), Err(Elapsed));
        // A ready future still wins over an already-fired timer.
        let both = with_timeout(&fired, Duration::from_secs(5), async { 3 });
        assert_eq!(futures_executor::block_on(both), Ok(3));
    }

    #[test]
    fn manual_sleep_wakes_a_pending_sleep_when_fired() {
        let sleeper = ManualSleep::new();
        let timer = sleeper.sleep(Duration::from_secs(1));
        let woken = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let flag = woken.clone();
        let handle = std::thread::spawn(move || {
            futures_executor::block_on(timer);
            flag.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(!woken.load(Ordering::SeqCst));
        sleeper.fire();
        handle.join().unwrap();
        assert!(woken.load(Ordering::SeqCst));
    }

    #[test]
    fn spawner_accepts_boxed_futures() {
        struct Inline;
        impl Spawner for Inline {
            fn spawn(&self, fut: BoxFuture<'static, ()>) {
                futures_executor::block_on(fut);
            }
        }
        let ran = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        Inline.spawn(Box::pin(async move { flag.store(true, Ordering::SeqCst) }));
        assert!(ran.load(Ordering::SeqCst));
    }
}
