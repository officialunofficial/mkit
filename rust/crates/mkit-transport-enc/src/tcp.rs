//! Real-TCP entry points for the encrypted transport.
//!
//! The glue that lets a `mkit+enc://` URL turn into a live, encrypted
//! [`EncTransport`] backed by a tokio TCP socket. This module is
//! feature-gated behind `tcp` so consumers that only want the
//! in-process path ([`EncTransport::from_session`]) don't pay for
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
//! 2. A `Clock + CryptoRng + BufferPooler` value to pass into
//!    `encrypted::dial` / `listen`.
//!
//! `BufferPool` is reference-counted (Arc inside) — once we have a
//! clone, the original Context can be dropped without invalidating
//! ours. So we briefly spin up a commonware tokio Runner whose only
//! job is to hand us a `BufferPool` clone, then drop it. Everything
//! else — the actual tokio runtime, the `TokioContext` used during
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

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_runtime::{BufferPool, BufferPooler, Clock, Runner as _};
use commonware_stream::encrypted::{dial, listen};
use governor::clock::{Clock as GClock, ReasonablyRealtime};
use mkit_core::protocol::async_shim::Executor;
use rand_core::{TryCryptoRng, TryRng, UnwrapErr};
use tokio::net::{TcpListener, TcpStream};

use crate::tokio_io::{TokioSink, TokioStream, split_tcp};
use crate::{
    EncHandshakeBounds, EncInitError, EncSession, EncTransport, default_handshake_config,
    default_handshake_config_with_bounds,
};

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
// TokioContext — minimal Clock + CryptoRng + BufferPooler stand-in
// ---------------------------------------------------------------------------

/// Minimal `BufferPooler + CryptoRng + Clock` context, just
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

// `TryRng<Error = Infallible>` gives `Rng` for free; `TryCryptoRng`
// (also infallible) gives `CryptoRng` for free — both via blanket
// impls in `rand_core`, so neither is implemented directly here.
// `UnwrapErr` bridges `getrandom::SysRng` (fallible: `getrandom::Error`)
// to the infallible shape, panicking only if the OS random source
// itself fails.
impl TryRng for TokioContext {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        UnwrapErr(getrandom::SysRng).try_next_u32()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        UnwrapErr(getrandom::SysRng).try_next_u64()
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        UnwrapErr(getrandom::SysRng).try_fill_bytes(dest)
    }
}

impl TryCryptoRng for TokioContext {}

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
/// runtime ("Cannot start a runtime from within a runtime"). On the
/// typical call site — the CLI's synchronous `connect_tcp` path — we
/// are inside `TokioExecutor::block_on`, which is itself a tokio
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
// connect_tcp — client dial helper
// ---------------------------------------------------------------------------

/// Dial a TCP socket and run the encrypted-stream handshake against
/// the peer's static `ed25519` public key. Returns a fully-wired
/// [`EncTransport`] whose `Transport` verbs run synchronously from
/// the caller's thread.
///
/// `signing_key` is the **dialer's** static private key. It does not
/// need to be pre-shared with the server — the server's bouncer either
/// accepts any key ([`PeerPolicy::AllowAny`]) or consults its own
/// keyring ([`PeerPolicy::Allowlist`]). The dialer always verifies the
/// **server's** key matches `server_pubkey`.
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
    let session = dial_once(&executor, host, port, server_pubkey, signing_key.clone())?;

    // Wire a redial hook so a `ConnectionFailed` mid-session (SPEC-TRANSPORT
    // §7) can be retried against a freshly-dialed connection instead of
    // failing on the first attempt — see `EncTransport`'s retry docs.
    let reconnect_executor = executor.clone();
    let reconnect_host = host.to_string();
    let reconnect_pubkey = *server_pubkey;
    let reconnect: crate::ReconnectFn<TokioStream, TokioSink> = std::sync::Arc::new(move || {
        dial_once(
            &reconnect_executor,
            &reconnect_host,
            port,
            &reconnect_pubkey,
            signing_key.clone(),
        )
    });

    EncTransport::from_session_with_reconnect(session, executor, host, port, reconnect)
}

/// Dial the TCP socket and drive the encrypted-stream handshake to a
/// raw, ready-to-use [`EncSession`] — no application `Hello` yet.
/// Shared by the initial [`connect_tcp_with_executor`] dial and the
/// redial closure it wires into [`EncTransport`] for retry, so the two
/// paths cannot drift.
fn dial_once(
    executor: &TokioExecutor,
    host: &str,
    port: u16,
    server_pubkey: &[u8; 32],
    signing_key: PrivateKey,
) -> Result<EncSession<TokioStream, TokioSink>, EncInitError> {
    let pool = acquire_network_buffer_pool();
    let ctx = TokioContext::new(pool);
    let host_owned = host.to_string();
    let server_pk = *server_pubkey;
    executor.handle().block_on(async move {
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
    })
}

/// Test-only: dial the TCP + encrypted-stream handshake with a
/// caller-supplied handshake namespace, returning the raw
/// [`EncSession`] WITHOUT the application-level `Hello`/`HelloResponse`
/// exchange [`connect_tcp`] performs automatically. Lets a caller drive
/// the session with arbitrary frames — e.g. to test a server's "first
/// frame must be `Hello`" rejection, or a mismatched handshake
/// namespace. `#[doc(hidden)]`, not part of the stable API.
///
/// # Errors
///
/// [`EncInitError`] if the TCP connection or encrypted-stream handshake
/// fails — the same failure modes as [`connect_tcp_with_executor`],
/// since this shares its dial path up to (but not including) the
/// application-level `Hello`.
#[doc(hidden)]
pub fn dial_tcp_session_for_test(
    host: &str,
    port: u16,
    server_pubkey: &[u8; 32],
    signing_key: PrivateKey,
    namespace: Vec<u8>,
    executor: &TokioExecutor,
) -> Result<EncSession<TokioStream, TokioSink>, EncInitError> {
    let pool = acquire_network_buffer_pool();
    let ctx = TokioContext::new(pool);
    let host_owned = host.to_string();
    let server_pk = *server_pubkey;
    executor.handle().block_on(async move {
        let addr = resolve(&host_owned, port).await?;
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| EncInitError::HandshakeFailed(format!("tcp connect: {e}")))?;
        let (sink, stream) =
            split_tcp(tcp).map_err(|e| EncInitError::HandshakeFailed(format!("tcp split: {e}")))?;
        let mut cfg = default_handshake_config(signing_key);
        cfg.namespace = namespace;
        let peer = decode_peer_pubkey(&server_pk)?;
        let (sender, receiver) = dial(ctx, cfg, peer, stream, sink).await?;
        Ok::<_, EncInitError>(EncSession::new(sender, receiver))
    })
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
// Peer-authorization policy
// ---------------------------------------------------------------------------

/// Server-side peer-authorization policy for the encrypted listener.
///
/// The `commonware_stream::encrypted::listen` bouncer is a
/// `FnOnce(PublicKey) -> Future<bool>` consulted during the handshake.
/// Before any application bytes flow, the bouncer decides whether the
/// dialing peer's static ed25519 key is allowed. A rejected peer never
/// receives a `HelloResponse`, list-refs, packs, or update-ref — the
/// session is torn down at the handshake layer.
///
/// - [`PeerPolicy::AllowAny`] accepts every dialer. This is the historic
///   v0.x behaviour and is retained ONLY for the direct-listen e2e test
///   harness and the explicit `--unsafe-allow-any-enc-peer` operator
///   escape. It is fail-OPEN and must never be the implicit default.
/// - [`PeerPolicy::Allowlist`] accepts only dialers whose 32-byte
///   ed25519 public key is in the set. This is the fail-CLOSED posture
///   `mkit serve --listen-enc` uses once an authorized-peers file is
///   configured.
#[derive(Clone, Debug)]
pub enum PeerPolicy {
    /// Accept any dialer (fail-open; dev / e2e only).
    AllowAny,
    /// Accept only dialers whose 32-byte ed25519 public key is listed.
    Allowlist(HashSet<[u8; 32]>),
}

impl PeerPolicy {
    /// Decide whether `peer` is authorized. `AllowAny` always accepts;
    /// `Allowlist` checks set membership against the peer's encoded
    /// 32-byte ed25519 public key.
    fn admits(&self, peer: &PublicKey) -> bool {
        match self {
            PeerPolicy::AllowAny => true,
            PeerPolicy::Allowlist(set) => match encode_pubkey(peer) {
                Some(bytes) => set.contains(&bytes),
                None => false,
            },
        }
    }
}

/// Encode a `PublicKey` to its raw 32-byte ed25519 representation for
/// allowlist comparison. Returns `None` if the encoded form is not
/// exactly 32 bytes (should never happen for ed25519, but we fail
/// closed rather than panic).
fn encode_pubkey(peer: &PublicKey) -> Option<[u8; 32]> {
    use commonware_codec::Encode as _;
    let encoded = peer.encode();
    let bytes = encoded.as_ref();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Some(out)
}

// ---------------------------------------------------------------------------
// serve_tcp — TCP listener
// ---------------------------------------------------------------------------

/// Accept incoming encrypted connections on `addr`, enforce a
/// [`PeerPolicy`] at the handshake, and hand each authorized connection
/// off to `serve_fn`. The provided closure is an **async** fn that
/// receives an already-authenticated [`EncSession`] paired with the
/// dialer's public key.
///
/// `serve_fn` is invoked on a fresh tokio task per accepted connection,
/// so it gets to `.await` freely and stays inside the listener's
/// runtime context for ambient I/O. Runs until `accept` fails (host
/// shutdown or socket error). Also accepts operator-tunable
/// [`EncHandshakeBounds`] for tightening the handshake/synchrony
/// deadlines on real networks.
///
/// This is the production listener entry point consumed by
/// `mkit serve --listen-enc`.
///
/// # Errors
///
/// - `EncInitError::HandshakeFailed` if `addr` is unparseable or
///   `bind` fails.
pub fn serve_tcp_with_policy_and_bounds<F, Fut>(
    addr: &str,
    signing_key: PrivateKey,
    policy: PeerPolicy,
    bounds: EncHandshakeBounds,
    serve_fn: F,
) -> Result<(), EncInitError>
where
    F: Fn(EncSession<TokioStream, TokioSink>, PublicKey) -> Fut + Send + Sync + 'static,
    Fut: core::future::Future<Output = ()> + Send + 'static,
{
    let executor = TokioExecutor::new()
        .map_err(|e| EncInitError::HandshakeFailed(format!("tokio runtime init failed: {e}")))?;
    serve_tcp_inner(
        addr,
        signing_key,
        policy,
        bounds,
        executor,
        None::<fn(SocketAddr)>,
        serve_fn,
    )
}

/// Like [`serve_tcp_with_policy_and_bounds`] but reuses an existing
/// [`TokioExecutor`] and returns the bound `SocketAddr` to the caller
/// (via `addr_cb`) before entering the accept loop. Used by the e2e /
/// unit tests to pick up the OS-assigned port when binding
/// `127.0.0.1:0`.
///
/// # Errors
///
/// - `EncInitError::HandshakeFailed` if `addr` is unparseable or
///   `bind` fails.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_tcp_with_addr_and_policy<F, Fut>(
    addr: &str,
    signing_key: PrivateKey,
    policy: PeerPolicy,
    executor: TokioExecutor,
    addr_cb: impl FnOnce(SocketAddr) + Send + 'static,
    serve_fn: F,
) -> Result<(), EncInitError>
where
    F: Fn(EncSession<TokioStream, TokioSink>, PublicKey) -> Fut + Send + Sync + 'static,
    Fut: core::future::Future<Output = ()> + Send + 'static,
{
    serve_tcp_inner(
        addr,
        signing_key,
        policy,
        EncHandshakeBounds::default(),
        executor,
        Some(addr_cb),
        serve_fn,
    )
}

/// Back-compat [`serve_tcp_with_addr`] using [`PeerPolicy::AllowAny`].
/// Retained so the existing e2e harness compiles unchanged.
///
/// # Errors
///
/// - `EncInitError::HandshakeFailed` if `addr` is unparseable or
///   `bind` fails.
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
    serve_tcp_inner(
        addr,
        signing_key,
        PeerPolicy::AllowAny,
        EncHandshakeBounds::default(),
        executor,
        Some(addr_cb),
        serve_fn,
    )
}

/// Shared accept-loop implementation for every `serve_tcp*` entry point.
/// The `policy` is consulted by the handshake bouncer; a rejected peer
/// never reaches `serve_fn`.
#[allow(clippy::needless_pass_by_value)]
fn serve_tcp_inner<F, Fut>(
    addr: &str,
    signing_key: PrivateKey,
    policy: PeerPolicy,
    bounds: EncHandshakeBounds,
    executor: TokioExecutor,
    addr_cb: Option<impl FnOnce(SocketAddr) + Send + 'static>,
    serve_fn: F,
) -> Result<(), EncInitError>
where
    F: Fn(EncSession<TokioStream, TokioSink>, PublicKey) -> Fut + Send + Sync + 'static,
    Fut: core::future::Future<Output = ()> + Send + 'static,
{
    let pool = acquire_network_buffer_pool();
    let addr_owned = addr.to_string();
    let serve_fn = Arc::new(serve_fn);
    let policy = Arc::new(policy);
    executor.handle().block_on(async move {
        let bind_addr: SocketAddr = addr_owned
            .parse()
            .map_err(|e| EncInitError::HandshakeFailed(format!("parse '{addr_owned}': {e}")))?;
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| EncInitError::HandshakeFailed(format!("bind {bind_addr}: {e}")))?;
        if let Some(cb) = addr_cb {
            let local = listener
                .local_addr()
                .map_err(|e| EncInitError::HandshakeFailed(format!("local_addr: {e}")))?;
            cb(local);
        }
        loop {
            let (tcp, _peer_addr) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => break,
            };
            let pool = pool.clone();
            let signing_key = signing_key.clone();
            let serve_fn = serve_fn.clone();
            let policy = policy.clone();
            tokio::spawn(async move {
                let (sink, stream) = match split_tcp(tcp) {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let ctx = TokioContext::new(pool);
                let cfg = default_handshake_config_with_bounds(signing_key, bounds);
                // The bouncer runs inside the handshake: a peer the
                // policy rejects gets `PeerRejected` and never receives
                // a HelloResponse / any application data.
                let bouncer = {
                    let policy = policy.clone();
                    move |peer: PublicKey| {
                        let policy = policy.clone();
                        async move { policy.admits(&peer) }
                    }
                };
                if let Ok((peer, sender, receiver)) = listen(ctx, bouncer, cfg, stream, sink).await
                {
                    let sess = EncSession::new(sender, receiver);
                    serve_fn(sess, peer).await;
                }
                // Per-connection handshake failure (including policy
                // rejection) is dropped; other peers keep accepting.
            });
        }
        Ok::<_, EncInitError>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The executor's runtime must outlive a single `block_on` call:
    /// a task spawned during the first `block_on` must still be alive
    /// (not aborted) when the second `block_on` awaits it. If a future
    /// refactor turned `TokioExecutor` into a wrapper that drops and
    /// rebuilds its runtime between calls, the spawned task would be
    /// aborted and the `JoinHandle` would resolve to a `JoinError`
    /// here instead of the value.
    #[test]
    fn executor_handles_repeated_block_on() {
        let exec = TokioExecutor::new().expect("runtime");
        // The task cannot complete until the SECOND block_on sends the
        // value, so it is guaranteed to straddle the call boundary — a
        // rebuilt runtime would have aborted it in between.
        let (tx, rx) = tokio::sync::oneshot::channel::<i32>();
        // Deliberately NOT awaited inside the first block_on: the
        // whole point is smuggling the live JoinHandle across it.
        #[allow(clippy::async_yields_async)]
        let handle = exec.block_on(async move {
            tokio::spawn(async move { rx.await.expect("sender kept alive") + 1 })
        });
        let v: i32 = exec.block_on(async move {
            tx.send(41).expect("task must still be listening");
            handle
                .await
                .expect("runtime (and its spawned tasks) must survive between block_on calls")
        });
        assert_eq!(v, 42);
    }

    /// `PeerPolicy::Allowlist` admits a listed key and rejects an
    /// unlisted one; `AllowAny` admits both. This pins the bouncer
    /// decision in isolation from the TCP machinery.
    #[test]
    fn peer_policy_allowlist_membership() {
        use commonware_cryptography::Signer as _;
        let allowed = PrivateKey::from_seed(11).public_key();
        let denied = PrivateKey::from_seed(22).public_key();

        let mut set = HashSet::new();
        set.insert(encode_pubkey(&allowed).unwrap());
        let allowlist = PeerPolicy::Allowlist(set);

        assert!(allowlist.admits(&allowed));
        assert!(!allowlist.admits(&denied));

        assert!(PeerPolicy::AllowAny.admits(&allowed));
        assert!(PeerPolicy::AllowAny.admits(&denied));
    }

    /// End-to-end over real TCP: an allowlisted client completes the
    /// handshake and the application `Hello` round-trip; a client whose
    /// key is NOT on the allowlist is rejected at the handshake and
    /// never establishes a session (no `HelloResponse`).
    #[test]
    fn allowlist_admits_listed_rejects_unlisted_over_tcp() {
        use commonware_codec::Encode as _;
        use commonware_cryptography::Signer as _;
        use std::sync::mpsc;
        use std::thread;

        fn pubkey_bytes(sk: &PrivateKey) -> [u8; 32] {
            let encoded = sk.public_key().encode();
            let mut out = [0u8; 32];
            out.copy_from_slice(encoded.as_ref());
            out
        }

        let exec = TokioExecutor::new().expect("runtime");
        let server_key = PrivateKey::from_seed(7777);
        let server_pubkey = pubkey_bytes(&server_key);

        let allowed_client = PrivateKey::from_seed(8888);
        let denied_client = PrivateKey::from_seed(9999);

        // Allowlist only the "allowed" client's key.
        let mut set = HashSet::new();
        set.insert(pubkey_bytes(&allowed_client));
        let policy = PeerPolicy::Allowlist(set);

        let (addr_tx, addr_rx) = mpsc::channel();
        let exec_for_server = exec.clone();
        let _server = thread::spawn(move || {
            // serve_fn echoes a single byte so a connected client can
            // observe a completed session. Rejected peers never reach it.
            let serve_fn = move |sess: EncSession<TokioStream, TokioSink>, _peer: PublicKey| {
                let (mut sender, mut receiver) = sess.into_parts();
                async move {
                    if let Ok(bufs) = receiver.recv().await {
                        let _ = sender.send(bufs.coalesce().as_ref().to_vec()).await;
                    }
                }
            };
            let _ = serve_tcp_with_addr_and_policy(
                "127.0.0.1:0",
                server_key,
                policy,
                exec_for_server,
                move |addr| {
                    let _ = addr_tx.send(addr);
                },
                serve_fn,
            );
        });

        let addr = addr_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("listener address");

        // Allowlisted client: handshake + app round-trip succeed.
        {
            let pool = acquire_network_buffer_pool();
            let ctx = TokioContext::new(pool);
            let server_pk = server_pubkey;
            let result = exec.handle().block_on(async move {
                let tcp = TcpStream::connect(addr)
                    .await
                    .map_err(|e| EncInitError::HandshakeFailed(format!("connect: {e}")))?;
                let (sink, stream) = split_tcp(tcp)
                    .map_err(|e| EncInitError::HandshakeFailed(format!("split: {e}")))?;
                let cfg = default_handshake_config(allowed_client);
                let peer = decode_peer_pubkey(&server_pk)?;
                let (mut sender, mut receiver) = dial(ctx, cfg, peer, stream, sink).await?;
                sender
                    .send(b"ping".to_vec())
                    .await
                    .map_err(|e| EncInitError::HandshakeFailed(format!("send: {e}")))?;
                let echo = receiver
                    .recv()
                    .await
                    .map_err(|e| EncInitError::HandshakeFailed(format!("recv: {e}")))?;
                Ok::<_, EncInitError>(echo.coalesce().as_ref().to_vec())
            });
            assert_eq!(result.expect("allowlisted round trip"), b"ping");
        }

        // Non-allowlisted client: handshake is rejected. The dial either
        // returns PeerRejected or the subsequent receive fails — in no
        // case do we get the application echo back.
        {
            let pool = acquire_network_buffer_pool();
            let ctx = TokioContext::new(pool);
            let server_pk = server_pubkey;
            let result = exec.handle().block_on(async move {
                let tcp = TcpStream::connect(addr)
                    .await
                    .map_err(|e| EncInitError::HandshakeFailed(format!("connect: {e}")))?;
                let (sink, stream) = split_tcp(tcp)
                    .map_err(|e| EncInitError::HandshakeFailed(format!("split: {e}")))?;
                let cfg = default_handshake_config(denied_client);
                let peer = decode_peer_pubkey(&server_pk)?;
                let (mut sender, mut receiver) = dial(ctx, cfg, peer, stream, sink).await?;
                // If we somehow got past the handshake, prove no echo
                // comes back.
                sender
                    .send(b"ping".to_vec())
                    .await
                    .map_err(|e| EncInitError::HandshakeFailed(format!("send: {e}")))?;
                let echo = receiver
                    .recv()
                    .await
                    .map_err(|e| EncInitError::HandshakeFailed(format!("recv: {e}")))?;
                Ok::<_, EncInitError>(echo.coalesce().as_ref().to_vec())
            });
            assert!(
                result.is_err(),
                "non-allowlisted client must not complete a round trip, got {result:?}"
            );
        }
    }

    /// SPEC-TRANSPORT-ENC §2.1: `HANDSHAKE_NAMESPACE` is bound into the
    /// encrypted-stream handshake transcript so peers that share
    /// `ed25519` keys with some other `commonware-stream` user can
    /// never cross-replay a handshake into this application. A dialer
    /// using any OTHER namespace must fail the handshake against a
    /// server using the real one — same key, same wire, only the
    /// namespace differs.
    #[test]
    fn mismatched_handshake_namespace_is_rejected_over_tcp() {
        use commonware_codec::Encode as _;
        use commonware_cryptography::Signer as _;
        use std::sync::mpsc;
        use std::thread;

        fn pubkey_bytes(sk: &PrivateKey) -> [u8; 32] {
            let encoded = sk.public_key().encode();
            let mut out = [0u8; 32];
            out.copy_from_slice(encoded.as_ref());
            out
        }

        let exec = TokioExecutor::new().expect("runtime");
        let server_key = PrivateKey::from_seed(4321);
        let server_pubkey = pubkey_bytes(&server_key);
        let client_key = PrivateKey::from_seed(1234);

        let (addr_tx, addr_rx) = mpsc::channel();
        let exec_for_server = exec.clone();
        let _server = thread::spawn(move || {
            let serve_fn = move |sess: EncSession<TokioStream, TokioSink>, _peer: PublicKey| {
                let (mut sender, mut receiver) = sess.into_parts();
                async move {
                    if let Ok(bufs) = receiver.recv().await {
                        let _ = sender.send(bufs.coalesce().as_ref().to_vec()).await;
                    }
                }
            };
            // AllowAny: the only variable under test is the namespace,
            // not peer authorization.
            let _ = serve_tcp_with_addr(
                "127.0.0.1:0",
                server_key,
                exec_for_server,
                move |addr| {
                    let _ = addr_tx.send(addr);
                },
                serve_fn,
            );
        });

        let addr = addr_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("listener address");

        let result = dial_tcp_session_for_test(
            &addr.ip().to_string(),
            addr.port(),
            &server_pubkey,
            client_key,
            b"totally-wrong-namespace".to_vec(),
            &exec,
        );
        assert!(
            result.is_err(),
            "a dialer using the wrong handshake namespace must never complete the \
             handshake against a server using the real one, got {result:?}"
        );
    }

    /// SPEC-TRANSPORT §7 regression (mkit#703): the server accepts the
    /// handshake + app `Hello` on the FIRST connection, then silently
    /// drops the socket instead of answering `ListRefs` — a mid-session
    /// `ConnectionFailed`. `EncTransport::list_refs` must retry against
    /// a freshly redialed connection (the second accepted connection,
    /// which answers normally) rather than failing outright. Before
    /// mkit#703 this transport had no retry path at all: `stream_err`
    /// collapsed every cipher failure to `ConnectionFailed` and nothing
    /// ever attempted a second connection.
    #[test]
    #[ignore = "spawns real TCP and waits out the production backoff ladder; run via the serial --ignored CI lane"]
    fn list_refs_retries_past_dropped_connection_via_reconnect() {
        use commonware_codec::Encode as _;
        use commonware_cryptography::Signer as _;
        use mkit_core::protocol::Transport as _;
        use mkit_rpc::mkit::common::v1::RefEntry;
        use mkit_rpc::mkit::rpc::v1::ProtocolVersion;
        use mkit_rpc::mkit::rpc::v1::ssh::{HelloResponse, ListRefsResponse, SshFrame, ssh_frame};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;
        use std::thread;

        let exec = TokioExecutor::new().expect("runtime");
        let server_key = PrivateKey::from_seed(31415);
        let server_pubkey = {
            let encoded = server_key.public_key().encode();
            let mut out = [0u8; 32];
            out.copy_from_slice(encoded.as_ref());
            out
        };
        let client_key = PrivateKey::from_seed(27182);

        let (addr_tx, addr_rx) = mpsc::channel();
        let exec_for_server = exec.clone();
        let connection_count = Arc::new(AtomicUsize::new(0));
        let connection_count_for_server = connection_count.clone();
        let _server = thread::spawn(move || {
            let serve_fn = move |sess: EncSession<TokioStream, TokioSink>, _peer: PublicKey| {
                let (mut sender, mut receiver) = sess.into_parts();
                let attempt = connection_count_for_server.fetch_add(1, Ordering::SeqCst);
                async move {
                    // App Hello — every connection gets a real
                    // HelloResponse so the client's app-hello succeeds
                    // whether this is the initial dial or the retry's
                    // redial.
                    let Ok(hello) = crate::recv_frame(&mut receiver).await else {
                        return;
                    };
                    if !matches!(hello.body, Some(ssh_frame::Body::Hello(_))) {
                        return;
                    }
                    let reply = SshFrame {
                        body: Some(ssh_frame::Body::HelloResponse(Box::new(
                            HelloResponse::default().with_proto(ProtocolVersion::ProtocolVersion1),
                        ))),
                        ..Default::default()
                    };
                    if crate::send_frame(&mut sender, &reply).await.is_err() {
                        return;
                    }

                    let Ok(req) = crate::recv_frame(&mut receiver).await else {
                        return;
                    };
                    if !matches!(req.body, Some(ssh_frame::Body::ListRefs(_))) {
                        return;
                    }

                    if attempt == 0 {
                        // First connection: drop without responding to
                        // ListRefs — the client must observe this as
                        // `ConnectionFailed` and retry via reconnect.
                        return;
                    }

                    let resp = ListRefsResponse {
                        refs: vec![
                            RefEntry::default()
                                .with_name("refs/heads/main")
                                .with_object_id(vec![0x11u8; 32]),
                        ],
                        ..Default::default()
                    };
                    let resp_frame = SshFrame {
                        body: Some(ssh_frame::Body::ListRefsResponse(Box::new(resp))),
                        ..Default::default()
                    };
                    let _ = crate::send_frame(&mut sender, &resp_frame).await;
                }
            };
            let _ = serve_tcp_with_addr_and_policy(
                "127.0.0.1:0",
                server_key,
                PeerPolicy::AllowAny,
                exec_for_server,
                move |addr| {
                    let _ = addr_tx.send(addr);
                },
                serve_fn,
            );
        });

        let addr = addr_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("listener address");

        let transport = connect_tcp_with_executor(
            &addr.ip().to_string(),
            addr.port(),
            &server_pubkey,
            client_key,
            exec,
        )
        .expect("initial connect + hello succeeds");

        let refs = transport
            .list_refs("")
            .expect("list_refs must succeed after retrying past the dropped first connection");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "refs/heads/main");
        assert_eq!(
            connection_count.load(Ordering::SeqCst),
            2,
            "must have redialed exactly once"
        );
    }

    /// Slow-loris guard: a peer that completes the handshake but
    /// then goes silent must NOT pin the server session forever. The
    /// `serve_fn` reads with `recv_frame_within(<short idle>)`; the
    /// session future must return (signalled over a channel) well within
    /// a bounded wall-clock window even though the client never sends a
    /// frame.
    // #505 PR 5/5: real TCP listener/dialer threads + fixed sleeps —
    // quarantined to the serial `--ignored` CI lane (cloudbuild/ci.yaml,
    // .github/workflows/rust.yml). Only needs localhost networking.
    #[test]
    #[ignore = "real localhost TCP + fixed sleeps; run via the serial --ignored CI lane"]
    fn post_handshake_idle_timeout_drops_silent_peer() {
        use crate::recv_frame_within;
        use commonware_cryptography::Signer as _;
        use std::sync::mpsc;
        use std::thread;

        let exec = TokioExecutor::new().expect("runtime");
        let server_key = PrivateKey::from_seed(4242);
        let server_pubkey = {
            use commonware_codec::Encode as _;
            let encoded = server_key.public_key().encode();
            let mut out = [0u8; 32];
            out.copy_from_slice(encoded.as_ref());
            out
        };
        let client_key = PrivateKey::from_seed(2424);

        let (addr_tx, addr_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let exec_for_server = exec.clone();
        let _server = thread::spawn(move || {
            let done_tx = done_tx.clone();
            let serve_fn = move |sess: EncSession<TokioStream, TokioSink>, _peer: PublicKey| {
                let done_tx = done_tx.clone();
                let (_sender, mut receiver) = sess.into_parts();
                async move {
                    // Short idle deadline: the silent client never sends,
                    // so this returns ConnectionFailed quickly instead of
                    // blocking forever.
                    let r = recv_frame_within(&mut receiver, Duration::from_millis(300)).await;
                    let _ = done_tx.send(r.is_err());
                }
            };
            let _ = serve_tcp_with_addr_and_policy(
                "127.0.0.1:0",
                server_key,
                PeerPolicy::AllowAny,
                exec_for_server,
                move |addr| {
                    let _ = addr_tx.send(addr);
                },
                serve_fn,
            );
        });

        let addr = addr_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("listener address");

        // Client completes the handshake, then deliberately stays silent.
        let server_pk = server_pubkey;
        let _client = thread::spawn(move || {
            let pool = acquire_network_buffer_pool();
            let ctx = TokioContext::new(pool);
            let exec2 = TokioExecutor::new().expect("client runtime");
            let _ = exec2.handle().block_on(async move {
                let tcp = TcpStream::connect(addr).await.ok()?;
                let (sink, stream) = split_tcp(tcp).ok()?;
                let cfg = default_handshake_config(client_key);
                let peer = decode_peer_pubkey(&server_pk).ok()?;
                let (_sender, _receiver) = dial(ctx, cfg, peer, stream, sink).await.ok()?;
                // Hold the connection open without sending anything.
                tokio::time::sleep(Duration::from_secs(5)).await;
                Some(())
            });
        });

        // The session must report completion (timed out → is_err == true)
        // well before the client's 5s hold elapses.
        let timed_out = done_rx
            .recv_timeout(Duration::from_secs(4))
            .expect("server session did not return — slow-loris guard failed");
        assert!(
            timed_out,
            "silent peer should have been dropped via idle timeout"
        );
    }

    #[test]
    fn handshake_bounds_thread_through_config() {
        use crate::{EncHandshakeBounds, default_handshake_config_with_bounds};
        use commonware_cryptography::Signer as _;
        let sk = PrivateKey::from_seed(1);
        let bounds = EncHandshakeBounds {
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(6),
            handshake_timeout: Duration::from_secs(7),
        };
        let cfg = default_handshake_config_with_bounds(sk, bounds);
        assert_eq!(cfg.synchrony_bound, Duration::from_secs(5));
        assert_eq!(cfg.max_handshake_age, Duration::from_secs(6));
        assert_eq!(cfg.handshake_timeout, Duration::from_secs(7));
    }
}
