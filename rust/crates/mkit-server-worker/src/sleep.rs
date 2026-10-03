//! Cancellable Worker timers. Timer handles stay opaque JavaScript values:
//! workerd may return objects, whereas `worker::Delay` requires an i32 handle.

/// The Worker's [`Sleep`](mkit_server::Sleep), with cancellation on drop.
#[derive(Debug, Default, Clone, Copy)]
pub struct WorkerSleep;

#[cfg(target_arch = "wasm32")]
impl mkit_server::Sleep for WorkerSleep {
    fn sleep(&self, duration: std::time::Duration) -> mkit_server::BoxFuture<'static, ()> {
        Box::pin(async move {
            let mut remaining = duration;
            loop {
                // JS timers clamp delays above the signed 32-bit limit.
                let chunk = remaining.min(std::time::Duration::from_millis(i32::MAX as u64));
                timer::Timer::new(chunk).await;
                remaining = remaining.saturating_sub(chunk);
                if remaining.is_zero() {
                    break;
                }
            }
        })
    }
}

#[cfg(target_arch = "wasm32")]
mod timer {
    use std::{
        cell::{Cell, RefCell},
        future::Future,
        pin::Pin,
        rc::Rc,
        task::{Context, Poll, Waker},
        time::Duration,
    };
    use worker::js_sys::{self, Function, Reflect};
    use worker::wasm_bindgen::{JsCast, JsValue, closure::Closure};

    pub(super) struct Timer {
        delay_ms: f64,
        fired: Rc<Cell<bool>>,
        waker: Rc<RefCell<Option<Waker>>>,
        callback: Option<Closure<dyn FnMut()>>,
        handle: Option<JsValue>,
        clear: Option<Function>,
    }

    impl Timer {
        pub(super) fn new(duration: Duration) -> Self {
            Self {
                delay_ms: f64::from(u32::try_from(duration.as_millis()).unwrap_or(i32::MAX as u32)),
                fired: Rc::default(),
                waker: Rc::default(),
                callback: None,
                handle: None,
                clear: None,
            }
        }
        fn start(&mut self) -> Result<(), JsValue> {
            let global = js_sys::global();
            let set: Function =
                Reflect::get(&global, &JsValue::from_str("setTimeout"))?.dyn_into()?;
            // Resolve cancellation before scheduling, so every scheduled timer
            // has a clear function even if startup fails partway through.
            let clear: Function =
                Reflect::get(&global, &JsValue::from_str("clearTimeout"))?.dyn_into()?;
            let fired = self.fired.clone();
            let waker = self.waker.clone();
            let callback = Closure::wrap_assert_unwind_safe(Box::new(move || {
                fired.set(true);
                if let Some(waker) = waker.borrow_mut().take() {
                    waker.wake();
                }
            }) as Box<dyn FnMut()>);
            let handle = set.call2(
                &global,
                callback.as_ref(),
                &JsValue::from_f64(self.delay_ms),
            )?;
            self.callback = Some(callback);
            self.handle = Some(handle);
            self.clear = Some(clear);
            Ok(())
        }
    }

    impl Future for Timer {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.fired.get() {
                return Poll::Ready(());
            }
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            if self.callback.is_none() && self.start().is_err() {
                // Sleep has no error channel. Expire immediately on timer
                // failure so a bounded hook call always fails closed.
                tracing::warn!("Worker timer unavailable; expiring timeout");
                return Poll::Ready(());
            }
            Poll::Pending
        }
    }

    impl Drop for Timer {
        fn drop(&mut self) {
            if !self.fired.get()
                && let (Some(clear), Some(handle)) = (&self.clear, self.handle.take())
            {
                let _ = clear.call1(&js_sys::global(), &handle);
            }
            // The callback drops only after the pending JS timer is cancelled.
        }
    }
}

/// Test-only runtime probe, absent from builds without test-faults.
#[cfg(all(target_arch = "wasm32", feature = "__test-faults"))]
pub async fn runtime_probe() -> worker::Result<worker::Response> {
    use mkit_server::{Sleep, with_timeout};
    use std::time::Duration;
    WorkerSleep.sleep(Duration::from_millis(5)).await;
    let expired = with_timeout(
        &WorkerSleep,
        Duration::from_millis(5),
        core::future::pending::<()>(),
    )
    .await
    .is_err();
    worker::Response::from_json(&serde_json::json!({"slept":true,"timedOut":expired}))
}
