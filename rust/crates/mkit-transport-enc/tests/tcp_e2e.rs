//! End-to-end TCP round-trip test for the encrypted transport.
//!
//! Pins the TCP wiring: a real `tokio::net::TcpListener`, a real
//! `commonware_stream::encrypted::listen` handshake, and a real
//! `connect_tcp` dial that returns a synchronous [`Transport`] usable
//! from non-async code.
//!
//! Architecture:
//!
//! - Server thread: opens a `TcpListener`, accepts one connection,
//!   runs `encrypted::listen` to complete the handshake, then serves
//!   a canned `Hello` / `ListRefs` round-trip over the resulting
//!   [`mkit_transport_enc::EncSession`].
//! - Proxy thread: stands between the dialer and the encrypted
//!   listener, forwarding bytes in both directions while teeing them
//!   into a shared capture buffer. The dialer points at the proxy's
//!   port; the proxy forwards to the real listener port. The capture
//!   buffer is what we inspect to assert no plaintext leaked.
//! - Main thread: invokes [`connect_tcp_with_executor`] against the
//!   proxy address, runs `list_refs`, then asserts the captured wire
//!   bytes do NOT contain the literal `"refs/heads/"` prefix the
//!   request carried.

#![cfg(feature = "tcp")]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::net::SocketAddr;
use std::sync::{Arc, Barrier, Mutex as StdMutex};
use std::thread;
use std::time::Duration;

use commonware_codec::Encode as _;
use commonware_cryptography::Signer;
use commonware_cryptography::ed25519::PrivateKey;
use mkit_core::protocol::Transport;
use mkit_rpc::mkit::rpc::v1::ProtocolVersion;
use mkit_rpc::mkit::rpc::v1::ssh::{
    HelloResponse, ListRefsResponse, SshFrame, list_refs_response::RefEntry, ssh_frame,
};
use mkit_transport_enc::tcp::{TokioExecutor, connect_tcp_with_executor};
use mkit_transport_enc::tokio_io::{TokioSink, TokioStream};
use mkit_transport_enc::{EncSession, HANDSHAKE_NAMESPACE, recv_frame, send_frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Splice one direction of a TCP byte stream while teeing into a
/// shared capture buffer. Exits when the source half closes.
async fn splice_direction(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    capture: Arc<StdMutex<Vec<u8>>>,
) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                capture.lock().unwrap().extend_from_slice(&buf[..n]);
                if to.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown().await;
}

#[test]
fn list_refs_round_trip_over_real_tcp() {
    // One tokio runtime, shared between the listener / proxy / dial.
    let exec = TokioExecutor::new().expect("tokio runtime");
    let listener_key = PrivateKey::from_seed(1001);
    let dialer_key = PrivateKey::from_seed(2002);
    let server_pk_bytes = pubkey_bytes(&listener_key);

    // ---- Encrypted listener (real TCP port) ---------------------------
    //
    // The listener owns its accept loop on a dedicated thread so the
    // test code can run other operations against the shared executor.
    let listener_ready = Arc::new(Barrier::new(2));
    let listener_addr: Arc<StdMutex<Option<SocketAddr>>> = Arc::new(StdMutex::new(None));
    let ready_for_listener = listener_ready.clone();
    let addr_slot = listener_addr.clone();
    let exec_for_listener = exec.clone();
    let listener_key_clone = listener_key.clone();
    let _listener_handle = thread::spawn(move || {
        exec_for_listener.handle().block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let local = listener.local_addr().expect("local_addr");
            *addr_slot.lock().unwrap() = Some(local);
            ready_for_listener.wait();
            let (tcp, _) = listener.accept().await.expect("accept");
            tcp.set_nodelay(true).ok();
            let (read, write) = tcp.into_split();
            let sink = TokioSink::new(write);
            let stream = TokioStream::new(read);
            let pool = bootstrap_buffer_pool();
            let ctx = MiniContext::new(pool);
            let cfg = handshake_cfg(listener_key_clone);
            let (_peer, sender, receiver) =
                commonware_stream::encrypted::listen(ctx, |_| async { true }, cfg, stream, sink)
                    .await
                    .expect("encrypted listen");
            serve_canned(EncSession::new(sender, receiver))
                .await
                .expect("serve");
        });
    });
    listener_ready.wait();
    let listen_addr = listener_addr.lock().unwrap().expect("listener addr");

    // ---- Proxy listener (the dialer connects here) --------------------
    let captured = Arc::new(StdMutex::new(Vec::<u8>::new()));
    let captured_for_proxy = captured.clone();
    let proxy_ready = Arc::new(Barrier::new(2));
    let proxy_ready_2 = proxy_ready.clone();
    let proxy_addr: Arc<StdMutex<Option<SocketAddr>>> = Arc::new(StdMutex::new(None));
    let proxy_slot = proxy_addr.clone();
    let exec_for_proxy = exec.clone();
    let _proxy_handle = thread::spawn(move || {
        exec_for_proxy.handle().block_on(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
            let addr = listener.local_addr().expect("proxy local_addr");
            *proxy_slot.lock().unwrap() = Some(addr);
            proxy_ready_2.wait();
            let (client_tcp, _) = listener.accept().await.expect("proxy accept");
            client_tcp.set_nodelay(true).ok();
            let upstream = tokio::net::TcpStream::connect(listen_addr)
                .await
                .expect("proxy upstream connect");
            upstream.set_nodelay(true).ok();
            let (cr, cw) = client_tcp.into_split();
            let (ur, uw) = upstream.into_split();
            let cap_a = captured_for_proxy.clone();
            let cap_b = captured_for_proxy.clone();
            let h1 = tokio::spawn(splice_direction(cr, uw, cap_a));
            let h2 = tokio::spawn(splice_direction(ur, cw, cap_b));
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                let _ = h1.await;
                let _ = h2.await;
            })
            .await;
        });
    });
    proxy_ready.wait();
    let proxy_listen_addr = proxy_addr.lock().unwrap().expect("proxy addr");

    // ---- Dial through proxy ------------------------------------------
    let tx = connect_tcp_with_executor(
        &proxy_listen_addr.ip().to_string(),
        proxy_listen_addr.port(),
        &server_pk_bytes,
        dialer_key,
        exec.clone(),
    )
    .expect("connect_tcp succeeds");

    // ---- ListRefs round-trip -----------------------------------------
    let refs = tx.list_refs("refs/heads/").expect("list_refs");
    assert_eq!(refs.len(), 2);
    let names: Vec<_> = refs.iter().map(|r| r.name.clone()).collect();
    assert!(names.iter().any(|n| n == "main"));
    assert!(names.iter().any(|n| n == "sentinel-plaintext"));

    drop(tx);
    // Let the proxy finish writing whatever it had buffered.
    std::thread::sleep(Duration::from_millis(200));

    let cap = captured.lock().unwrap().clone();
    assert!(!cap.is_empty(), "proxy should have captured bytes");
    assert!(
        !contains_subsequence(&cap, b"refs/heads/"),
        "plaintext leaked through encrypted wire (captured {} bytes)",
        cap.len()
    );
    assert!(
        cap.len() > 100,
        "wire capture suspiciously short ({} bytes)",
        cap.len()
    );
    // Listener and proxy threads run until their accepted connection
    // closes; we deliberately don't join them — the test passes if
    // the assertions above hold.
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Bootstrap a buffer pool by piggy-backing on commonware's tokio
/// Runner. The cached pool inside the lib isn't visible to tests, so
/// we run our own one-shot here. The clone we return outlives the
/// runtime via the `Arc`-inside-`BufferPool`. Driven on a fresh OS
/// thread so it doesn't try to build a tokio runtime inside the
/// surrounding one (panics — same constraint as the lib's internal
/// bootstrap).
fn bootstrap_buffer_pool() -> commonware_runtime::BufferPool {
    use commonware_runtime::{BufferPooler as _, Runner as _};
    std::thread::spawn(|| {
        let runner = commonware_runtime::tokio::Runner::default();
        runner.start(|ctx| async move { ctx.network_buffer_pool().clone() })
    })
    .join()
    .expect("pool bootstrap thread")
}

/// Minimal `Clock` / `RngCore` / `BufferPooler` implementation for the
/// listener side. Duplicates the lib's private `TokioContext`
/// because the lib type is `pub(crate)` and this test lives outside
/// the crate. That type may be promoted to `pub` if a third caller
/// ever materialises.
#[derive(Clone, Debug)]
struct MiniContext {
    pool: commonware_runtime::BufferPool,
}
impl MiniContext {
    fn new(pool: commonware_runtime::BufferPool) -> Self {
        Self { pool }
    }
}
impl commonware_runtime::BufferPooler for MiniContext {
    fn network_buffer_pool(&self) -> &commonware_runtime::BufferPool {
        &self.pool
    }
    fn storage_buffer_pool(&self) -> &commonware_runtime::BufferPool {
        &self.pool
    }
}
impl rand_core::RngCore for MiniContext {
    fn next_u32(&mut self) -> u32 {
        rand::rngs::OsRng.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        rand::rngs::OsRng.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::rngs::OsRng.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        rand::rngs::OsRng.try_fill_bytes(dest)
    }
}
impl rand_core::CryptoRng for MiniContext {}
impl governor::clock::Clock for MiniContext {
    type Instant = std::time::SystemTime;
    fn now(&self) -> Self::Instant {
        std::time::SystemTime::now()
    }
}
impl governor::clock::ReasonablyRealtime for MiniContext {}
impl commonware_runtime::Clock for MiniContext {
    fn current(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send + 'static {
        tokio::time::sleep(duration)
    }
    fn sleep_until(
        &self,
        deadline: std::time::SystemTime,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        let until = deadline
            .duration_since(std::time::SystemTime::now())
            .unwrap_or_default();
        tokio::time::sleep(until)
    }
}

fn handshake_cfg(sk: PrivateKey) -> commonware_stream::encrypted::Config<PrivateKey> {
    commonware_stream::encrypted::Config {
        signing_key: sk,
        namespace: HANDSHAKE_NAMESPACE.to_vec(),
        max_message_size: mkit_rpc::MAX_FRAME_BYTES,
        synchrony_bound: Duration::from_secs(30),
        max_handshake_age: Duration::from_secs(30),
        handshake_timeout: Duration::from_secs(30),
    }
}

/// Serve one Hello + `ListRefs` round-trip on the listener side. The
/// dialer sends `prefix = "refs/heads/"` so the names we return are
/// returned without the prefix (matching the `Transport::list_refs`
/// contract — the prefix is what was filtered against, not part of
/// each `Ref::name`).
async fn serve_canned<I, O>(
    sess: EncSession<I, O>,
) -> Result<(), commonware_stream::encrypted::Error>
where
    I: commonware_runtime::Stream,
    O: commonware_runtime::Sink,
{
    let (mut sender, mut receiver) = sess.into_parts();

    // 1) Hello.
    let req = recv_frame(&mut receiver).await.map_err(|_| stream_err())?;
    assert!(matches!(req.body, Some(ssh_frame::Body::Hello(_))));
    let reply = SshFrame {
        body: Some(ssh_frame::Body::HelloResponse(Box::new(
            HelloResponse::default().with_proto(ProtocolVersion::ProtocolVersion1),
        ))),
        ..Default::default()
    };
    send_frame(&mut sender, &reply)
        .await
        .map_err(|_| stream_err())?;

    // 2) ListRefs.
    let req = recv_frame(&mut receiver).await.map_err(|_| stream_err())?;
    assert!(matches!(req.body, Some(ssh_frame::Body::ListRefs(_))));
    // Names come back without the prefix — server returns just the
    // tail under the matched prefix, same as mkit-transport-ssh.
    let entries = vec![
        RefEntry::default()
            .with_name("main")
            .with_object_id(vec![0x11u8; 32]),
        RefEntry::default()
            .with_name("sentinel-plaintext")
            .with_object_id(vec![0x22u8; 32]),
    ];
    let resp = ListRefsResponse {
        refs: entries,
        ..Default::default()
    };
    let frame = SshFrame {
        body: Some(ssh_frame::Body::ListRefsResponse(Box::new(resp))),
        ..Default::default()
    };
    send_frame(&mut sender, &frame)
        .await
        .map_err(|_| stream_err())?;

    // Keep the session alive briefly so the dialer drains the read
    // side before the proxy tears the TCP halves down.
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}

fn stream_err() -> commonware_stream::encrypted::Error {
    commonware_stream::encrypted::Error::UnableToDecode(commonware_codec::Error::Invalid(
        "SshFrame",
        "test serve helper translation",
    ))
}

fn pubkey_bytes(sk: &PrivateKey) -> [u8; 32] {
    let pk = sk.public_key();
    let encoded = pk.encode();
    let bytes = encoded.as_ref();
    assert_eq!(bytes.len(), 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
