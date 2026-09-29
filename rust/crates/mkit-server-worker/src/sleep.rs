//! The Worker's [`Sleep`](mkit_server::Sleep): `worker::Delay`.

/// A [`Sleep`](mkit_server::Sleep) over `setTimeout`, so an outcome-sink call
/// (kind 8) is bounded on Workers, where `std::time` and `tokio::time` are
/// unavailable.
#[derive(Debug, Default, Clone, Copy)]
pub struct WorkerSleep;

#[cfg(target_arch = "wasm32")]
impl mkit_server::Sleep for WorkerSleep {
    fn sleep(&self, duration: std::time::Duration) -> mkit_server::BoxFuture<'static, ()> {
        Box::pin(worker::Delay::from(duration))
    }
}
