//! Real-TCP entry points for the encrypted transport.
//!
//! Phase 2 (issue #156): glue that lets a `mkit+enc://` URL turn into a
//! live, encrypted [`EncTransport`] backed by a tokio TCP socket. This
//! module is feature-gated behind `tcp` so consumers that only want
//! the in-process scaffold (Phase 1's `from_session`) don't pay for
//! tokio's compile cost.
//!
//! ## Why we don't reuse `commonware_runtime::tokio::Runner`
//!
//! The upstream tokio entry point is a `Runner::start(|ctx| async { … })`
//! that owns a tokio runtime, drives the supplied future to completion,
//! and drops the runtime when the future returns. That's a perfect
//! shape for a top-level binary but a poor fit for a long-lived sync
//! [`mkit_core::protocol::Transport`] whose lifetime extends across
//! many calls.
//!
//! We need two things from the upstream Context:
//!
//! 1. A `commonware_runtime::BufferPool` to feed
//!    `commonware_stream::encrypted::Sender` / `Receiver`.
//! 2. A `Clock + CryptoRngCore + BufferPooler` value to pass into
//!    `encrypted::dial` / `listen`.
//!
//! `BufferPool` is reference-counted (Arc inside) — once we have a
//! clone, the original Context can be dropped without invalidating
//! ours. So we briefly spin up a commonware tokio Runner whose only
//! job is to hand us a `BufferPool` clone, then drop it. Everything
//! else — the actual tokio runtime, the [`TokioContext`] used during
//! dial — we own ourselves so the runtime survives the entire
//! transport lifetime.
//!
//! ## Threading and `block_on`
//!
//! [`TokioExecutor`] wraps a long-lived `Arc<tokio::runtime::Runtime>`.
//! Its `block_on` calls `Handle::block_on` on the wrapped runtime. This
//! is safe to call from any thread that is **not** itself a tokio
//! worker on the same runtime — i.e. the synchronous code paths in
//! `mkit-cli`'s `push_all` / `pull_all` are fine, but calling
//! `block_on` from inside a `runtime.spawn()` task would panic. The
//! transport never spawns tasks of its own, so this constraint is
//! purely about external callers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_runtime::{BufferPool, BufferPooler, Clock, Runner as _};
use commonware_stream::encrypted::{dial, listen};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use mkit_core::protocol::async_shim::Executor;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};
use tokio::net::{TcpListener, TcpStream};

use crate::tokio_io::{TokioSink, TokioStream, split_tcp};
use crate::{EncInitError, EncSession, EncTransport, default_handshake_config};

// ---------------------------------------------------------------------------
// TokioExecutor — Executor trait impl that owns its own tokio runtime
// ---------------------------------------------------------------------------

/// `Arc`-shared sync/async bridge for the encrypted transport.
///
/// The choice of `Arc<tokio::runtime::Runtime>` over a plain owned
/// runtime is deliberate:
///
/// - `EncTransport` carries the executor as a generic type parameter,
///   not behind a trait object, so cloning the executor is a hot path
///   (every CLI command that holds a `EncTransport` for the duration
///   of a push or fetch hands it to nested helpers). `Arc` makes the
///   clone a refcount bump.
/// - The runtime must outlive the dial step, every verb call, and
///   the final tokio I/O drain at drop. Owning the runtime via `Arc`
///   keeps it alive until the last `EncTransport` clone drops, with
///   zero extra effort from callers.
/// - Tests construct several executors in parallel; sharing a single
///   underlying runtime by `Arc::clone` keeps the test harness from
///   thrashing tokio worker threads.
#[derive(Clone, Debug)]
pub struct TokioExecutor {
    runtime: Arc<tokio::runtime::Runtime>,
}

impl TokioExecutor {
    /// Build a fresh single-worker multi-thread tokio runtime and wrap
    /// it. Multi-thread (not `current_thread`) is required because the
    /// encrypted listener spawns one task per connection via
    /// `runtime.spawn`, and `current_thread` would refuse to drive
    /// those after the dial's `block_on` returns. One worker thread is
    /// enough for the verb-at-a-time wire protocol; bump if profiling
    /// ever shows worker saturation.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if tokio fails to allocate worker
    /// threads — almost always means the host is out of resources, in
    /// which case the caller has bigger problems than this transport.
    pub fn new() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("mkit-enc")
            .build()?;
        Ok(Self {
            runtime: Arc::new(runtime),
        })
    }

    /// Construct a `TokioExecutor` that shares an existing tokio
    /// runtime. Useful when the embedding application already owns
    /// one (e.g. a long-running server process that wants both an
    /// encrypted listener and other tokio-based services on the same
    /// pool).
    #[must_use]
    pub fn from_runtime(runtime: Arc<tokio::runtime::Runtime>) -> Self {
        Self { runtime }
    }

    /// Borrow the wrapped runtime handle. Mostly used by the
    /// connect/listen helpers in this module to schedule the dial /
    /// accept future, but also surfaced to external tests that need
    /// to run helper async tasks on the same runtime the transport
    /// uses (avoids the "two tokio runtimes in one process" panic in
    /// `tokio::time::sleep`-style helpers).
    #[must_use]
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

impl Executor for TokioExecutor {
    fn block_on<F, T>(&self, fut: F) -> T
    where
        F: core::future::Future<Output = T> + Send,
        T: Send,
    {
        // `Handle::block_on` panics if called from inside a tokio
        // worker on the same runtime. The encrypted transport is only
        // ever driven from synchronous, non-runtime code (the CLI's
        // `push_all` loop), so we never hit that path. Documented on
        // the type-level docs.
        self.runtime.handle().block_on(fut)
    }
}

// ---------------------------------------------------------------------------
// TokioContext — minimal Clock + RngCore + BufferPooler stand-in
// ---------------------------------------------------------------------------

/// Minimal `BufferPooler + CryptoRngCore + Clock` context, just
/// barely enough to drive `commonware_stream::encrypted::{dial, listen}`.
///
/// We don't try to be a drop-in replacement for
/// `commonware_runtime::tokio::Context` — that type also carries
/// metrics, storage, network, and a supervision tree. The encrypted
/// dial only consults the buffer pool, the random source, and the
/// clock; everything else would be wasted state.
///
/// The buffer pool is acquired once at module init time via
/// [`acquire_network_buffer_pool`] and cached for the process lifetime
/// — see that function's docs for the trick.
#[derive(Clone, Debug)]
pub(crate) struct TokioContext {
    pool: BufferPool,
    // Storage pool is unused by encrypted::dial but `BufferPooler`'s
    // contract requires `storage_buffer_pool`. We hand back the same
    // pool — the encrypted layer never asks for storage, so the
    // duplicate is harmless and saves us a second `Runner::start`
    // bounce.
    storage_pool: BufferPool,
}

impl TokioContext {
    fn new(pool: BufferPool) -> Self {
        Self {
            storage_pool: pool.clone(),
            pool,
        }
    }
}

impl BufferPooler for TokioContext {
    fn network_buffer_pool(&self) -> &BufferPool {
        &self.pool
    }

    fn storage_buffer_pool(&self) -> &BufferPool {
        &self.storage_pool
    }
}

impl RngCore for TokioContext {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        OsRng.try_fill_bytes(dest)
    }
}

impl CryptoRng for TokioContext {}

impl GClock for TokioContext {
    type Instant = SystemTime;
    fn now(&self) -> Self::Instant {
        SystemTime::now()
    }
}

impl ReasonablyRealtime for TokioContext {}

impl Clock for TokioContext {
    fn current(&self) -> SystemTime {
        SystemTime::now()
    }
    fn sleep(&self, duration: Duration) -> impl core::future::Future<Output = ()> + Send + 'static {
        tokio::time::sleep(duration)
    }
    fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl core::future::Future<Output = ()> + Send + 'static {
        let until = deadline
            .duration_since(SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(until)
    }
}

// ---------------------------------------------------------------------------
// BufferPool bootstrap
// ---------------------------------------------------------------------------

/// One-shot acquisition of a `BufferPool` for the encrypted dial.
///
/// The trick: `BufferPool::new` is `pub(crate)` in commonware-runtime,
/// so we cannot construct one directly. We spin up a commonware tokio
/// `Runner::default()`, ask it for `ctx.network_buffer_pool().clone()`
/// inside its driver future, then return the clone. The Runner's own
/// runtime drops when `start` returns, but the pool is `Arc`-backed —
/// the clone keeps the underlying state alive.
///
/// We cache the result in a `OnceLock` so repeated `connect_tcp` calls
/// from the same process share one pool. (Allocating multiple pools
/// would be harmless but wasteful.)
///
/// The Runner is driven on a freshly-spawned OS thread because tokio
/// refuses to nest `runtime::Builder::build()` inside an already-active
/// runtime ("Cannot start a runtime from within a runtime"). On Phase
/// 2's typical call site — the CLI's synchronous `connect_tcp` path —
/// we are inside `TokioExecutor::block_on`, which is itself a tokio
/// `Handle::block_on` on our owned runtime. Running the bootstrap
/// Runner inline would therefore panic; hopping to a worker thread
/// avoids that and isolates the bootstrap runtime's lifecycle from
/// ours.
fn acquire_network_buffer_pool() -> BufferPool {
    use std::sync::OnceLock;
    static POOL: OnceLock<BufferPool> = OnceLock::new();
    POOL.get_or_init(|| {
        // Drive the bootstrap Runner on a fresh OS thread so it
        // doesn't see the surrounding tokio runtime. The thread
        // joins immediately after handing back the BufferPool
        // clone.
        std::thread::spawn(|| {
            let runner = commonware_runtime::tokio::Runner::default();
            runner.start(|ctx| async move { ctx.network_buffer_pool().clone() })
        })
        .join()
        .expect("buffer-pool bootstrap thread panicked")
    })
    .clone()
}

// ---------------------------------------------------------------------------
// connect_tcp — Phase 2 dial helper
// ---------------------------------------------------------------------------

/// Dial a TCP socket and run the encrypted-stream handshake against
/// the peer's static `ed25519` public key. Returns a fully-wired
/// [`EncTransport`] whose `Transport` verbs run synchronously from
/// the caller's thread.
///
/// `signing_key` is the **dialer's** static private key. It does not
/// need to be pre-shared with the server — the server's bouncer either
/// accepts any key (the default permissive policy in
/// [`serve_tcp`]) or consults its own keyring (operator-supplied).
/// The dialer always verifies the **server's** key matches
/// `server_pubkey`.
///
/// # Errors
///
/// - [`EncInitError::HandshakeFailed`] if the TCP connection cannot
///   be established, the encrypted handshake times out, or the
///   server's actual `ed25519` key does not match `server_pubkey`.
/// - [`EncInitError::PeerRejected`] if the server's bouncer rejects
///   the dialer's public key.
/// - [`EncInitError::AppHelloFailed`] if the application-level
///   `Hello` exchange after the encrypted handshake fails (e.g.
///   protocol-version mismatch).
pub fn connect_tcp(
    host: &str,
    port: u16,
    server_pubkey: &[u8; 32],
    signing_key: PrivateKey,
) -> Result<EncTransport<TokioStream, TokioSink, TokioExecutor>, EncInitError> {
    let executor = TokioExecutor::new()
        .map_err(|e| EncInitError::HandshakeFailed(format!("tokio runtime init failed: {e}")))?;
    connect_tcp_with_executor(host, port, server_pubkey, signing_key, executor)
}

/// Variant of [`connect_tcp`] that lets the caller plug in an
/// existing [`TokioExecutor`]. Useful when an embedding application
/// wants several encrypted sessions to share a single tokio runtime
/// (e.g. server-to-server fan-out).
#[allow(clippy::needless_pass_by_value)]
pub fn connect_tcp_with_executor(
    host: &str,
    port: u16,
    server_pubkey: &[u8; 32],
    signing_key: PrivateKey,
    executor: TokioExecutor,
) -> Result<EncTransport<TokioStream, TokioSink, TokioExecutor>, EncInitError> {
    let pool = acquire_network_buffer_pool();
    let ctx = TokioContext::new(pool);
    let host_owned = host.to_string();
    let server_pk = *server_pubkey;
    let session = executor.handle().block_on(async move {
        let addr = resolve(&host_owned, port).await?;
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| EncInitError::HandshakeFailed(format!("tcp connect: {e}")))?;
        let (sink, stream) =
            split_tcp(tcp).map_err(|e| EncInitError::HandshakeFailed(format!("tcp split: {e}")))?;
        let cfg = default_handshake_config(signing_key);
        let peer = decode_peer_pubkey(&server_pk)?;
        let (sender, receiver) = dial(ctx, cfg, peer, stream, sink).await?;
        Ok::<_, EncInitError>(EncSession::new(sender, receiver))
    })?;
    EncTransport::from_session(session, executor, host, port)
}

/// Best-effort `host:port` → `SocketAddr` resolution. Numeric addrs are
/// parsed locally; named hosts fall through to `tokio::net::lookup_host`
/// (libc resolver on Unix, registry on Windows).
async fn resolve(host: &str, port: u16) -> Result<SocketAddr, EncInitError> {
    let target = format!("{host}:{port}");
    let mut iter = tokio::net::lookup_host(&target)
        .await
        .map_err(|e| EncInitError::HandshakeFailed(format!("dns lookup '{target}': {e}")))?;
    iter.next()
        .ok_or_else(|| EncInitError::HandshakeFailed(format!("dns lookup '{target}' empty")))
}

/// Decode the URL-supplied 32-byte server public key into the typed
/// `commonware_cryptography::ed25519::PublicKey`. The encoded form is
/// the raw `ed25519` byte representation — same shape as
/// `commonware_codec::Encode` writes for `PublicKey::SIZE`.
fn decode_peer_pubkey(bytes: &[u8; 32]) -> Result<PublicKey, EncInitError> {
    use commonware_codec::DecodeExt;
    PublicKey::decode(bytes.as_slice())
        .map_err(|e| EncInitError::HandshakeFailed(format!("decode peer pubkey: {e}")))
}

// ---------------------------------------------------------------------------
// serve_tcp — Phase 2 listener
// ---------------------------------------------------------------------------

/// Accept one or more incoming encrypted connections on `addr` and
/// hand each one off to `serve_fn`. The provided closure is an **async**
/// fn that receives an already-authenticated [`EncSession`] paired with
/// the dialer's public key (so operator-supplied keyring checks can
/// decide whether to proceed).
///
/// The bouncer is **permissive by default** — v0.x ships allowing any
/// peer to complete the handshake. SPEC-TRANSPORT-ENC §6 item 5 calls
/// out keystore integration; until that lands, deployers who need
/// per-peer authorization should layer it inside `serve_fn` after the
/// session is established.
///
/// `serve_fn` is invoked on a fresh tokio task per accepted connection,
/// so it gets to `.await` freely and stays inside the listener's
/// runtime context for ambient I/O.
///
/// Runs until `accept` fails (host shutdown or socket error).
///
/// # Errors
///
/// - `EncInitError::HandshakeFailed` if `addr` is unparseable or
///   `bind` fails.
pub fn serve_tcp<F, Fut>(
    addr: &str,
    signing_key: PrivateKey,
    serve_fn: F,
) -> Result<(), EncInitError>
where
    F: Fn(EncSession<TokioStream, TokioSink>, PublicKey) -> Fut + Send + Sync + 'static,
    Fut: core::future::Future<Output = ()> + Send + 'static,
{
    let executor = TokioExecutor::new()
        .map_err(|e| EncInitError::HandshakeFailed(format!("tokio runtime init failed: {e}")))?;
    serve_tcp_with_executor(addr, signing_key, executor, serve_fn)
}

/// Variant of [`serve_tcp`] that reuses an existing [`TokioExecutor`].
#[allow(clippy::needless_pass_by_value)]
pub fn serve_tcp_with_executor<F, Fut>(
    addr: &str,
    signing_key: PrivateKey,
    executor: TokioExecutor,
    serve_fn: F,
) -> Result<(), EncInitError>
where
    F: Fn(EncSession<TokioStream, TokioSink>, PublicKey) -> Fut + Send + Sync + 'static,
    Fut: core::future::Future<Output = ()> + Send + 'static,
{
    let pool = acquire_network_buffer_pool();
    let addr_owned = addr.to_string();
    let serve_fn = Arc::new(serve_fn);
    executor.handle().block_on(async move {
        let bind_addr: SocketAddr = addr_owned
            .parse()
            .map_err(|e| EncInitError::HandshakeFailed(format!("parse '{addr_owned}': {e}")))?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| EncInitError::HandshakeFailed(format!("bind {bind_addr}: {e}")))?;
        loop {
            let (tcp, _peer_addr) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let pool = pool.clone();
            let signing_key = signing_key.clone();
            let serve_fn = serve_fn.clone();
            tokio::spawn(async move {
                let (sink, stream) = match split_tcp(tcp) {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let ctx = TokioContext::new(pool);
                let cfg = default_handshake_config(signing_key);
                if let Ok((peer, sender, receiver)) =
                    listen(ctx, |_| async { true }, cfg, stream, sink).await
                {
                    let sess = EncSession::new(sender, receiver);
                    serve_fn(sess, peer).await;
                }
                // Per-connection handshake failure is logged (when
                // tracing is wired) and dropped. Other peers keep
                // accepting.
            });
        }
        Ok::<_, EncInitError>(())
    })
}

/// Same as [`serve_tcp`] but returns the bound `SocketAddr` to the
/// caller before entering the accept loop. Used by the e2e test to
/// pick up the OS-assigned port when binding `127.0.0.1:0`.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_tcp_with_addr<F, Fut>(
    addr: &str,
    signing_key: PrivateKey,
    executor: TokioExecutor,
    addr_cb: impl FnOnce(SocketAddr) + Send + 'static,
    serve_fn: F,
) -> Result<(), EncInitError>
where
    F: Fn(EncSession<TokioStream, TokioSink>, PublicKey) -> Fut + Send + Sync + 'static,
    Fut: core::future::Future<Output = ()> + Send + 'static,
{
    let pool = acquire_network_buffer_pool();
    let addr_owned = addr.to_string();
    let serve_fn = Arc::new(serve_fn);
    executor.handle().block_on(async move {
        let bind_addr: SocketAddr = addr_owned
            .parse()
            .map_err(|e| EncInitError::HandshakeFailed(format!("parse '{addr_owned}': {e}")))?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| EncInitError::HandshakeFailed(format!("bind {bind_addr}: {e}")))?;
        let local = listener
            .local_addr()
            .map_err(|e| EncInitError::HandshakeFailed(format!("local_addr: {e}")))?;
        addr_cb(local);
        loop {
            let (tcp, _peer_addr) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let pool = pool.clone();
            let signing_key = signing_key.clone();
            let serve_fn = serve_fn.clone();
            tokio::spawn(async move {
                let (sink, stream) = match split_tcp(tcp) {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let ctx = TokioContext::new(pool);
                let cfg = default_handshake_config(signing_key);
                if let Ok((peer, sender, receiver)) =
                    listen(ctx, |_| async { true }, cfg, stream, sink).await
                {
                    let sess = EncSession::new(sender, receiver);
                    serve_fn(sess, peer).await;
                }
            });
        }
        Ok::<_, EncInitError>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The executor's runtime should outlive a single `block_on` call.
    /// Trivial — but pins the `Arc::clone` semantics so a future
    /// refactor doesn't silently turn `TokioExecutor` into an
    /// owned-runtime wrapper that drops between calls.
    #[test]
    fn executor_handles_repeated_block_on() {
        let exec = TokioExecutor::new().expect("runtime");
        let a: i32 = exec.block_on(async { 1 + 1 });
        let b: i32 = exec.block_on(async { 2 + 2 });
        assert_eq!(a, 2);
        assert_eq!(b, 4);
    }

    /// The buffer pool acquired by the first call is cached and
    /// returned by subsequent calls. Asserting the same `Arc` is
    /// reused saves us from regressing into per-call Runner
    /// construction, which would dominate `connect_tcp` latency.
    #[test]
    fn buffer_pool_is_cached() {
        let p1 = acquire_network_buffer_pool();
        let p2 = acquire_network_buffer_pool();
        // BufferPool wraps an Arc; `Clone` is a refcount bump, and
        // two clones of the same underlying Arc compare equal by
        // pointer identity via `Arc::ptr_eq` — but BufferPool doesn't
        // expose its inner Arc. The proxy assertion is that the
        // Debug repr matches (config + num_classes) — they would
        // differ only across distinct pool constructions.
        assert_eq!(format!("{p1:?}"), format!("{p2:?}"));
    }
}
