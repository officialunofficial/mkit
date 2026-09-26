//! `serve_tcp_listener`'s shutdown over real loopback TCP: once the
//! shutdown future resolves the listener stops accepting, and a session
//! already in flight still runs to completion before the future returns.

#![cfg(feature = "tcp")]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use commonware_codec::Encode as _;
use commonware_cryptography::Signer as _;
use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use mkit_transport_enc::tcp::{TokioExecutor, dial_tcp_session_for_test};
use mkit_transport_enc::tokio_io::{TokioSink, TokioStream};
use mkit_transport_enc::{
    EncHandshakeBounds, EncSession, HANDSHAKE_NAMESPACE, ListenerLimits, PeerPolicy,
    serve_tcp_listener,
};
use tokio::sync::{Notify, mpsc, oneshot};

fn pubkey_bytes(sk: &PrivateKey) -> [u8; 32] {
    let encoded = sk.public_key().encode();
    let mut out = [0u8; 32];
    out.copy_from_slice(encoded.as_ref());
    out
}

#[test]
fn serve_tcp_listener_stops_on_shutdown_and_drains() {
    let exec = TokioExecutor::new().unwrap();
    let server_key = PrivateKey::from_seed(31);
    let server_pk = pubkey_bytes(&server_key);
    let listener = exec
        .handle()
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();

    // The session echoes one message, but only once `release` fires, so
    // it is still in flight when the shutdown begins.
    let release = Arc::new(Notify::new());
    let (started_tx, mut started) = mpsc::unbounded_channel::<()>();
    let serve_fn = {
        let release = Arc::clone(&release);
        move |sess: EncSession<TokioStream, TokioSink>, _peer: PublicKey| {
            let release = Arc::clone(&release);
            let started_tx = started_tx.clone();
            let (mut sender, mut receiver) = sess.into_parts();
            async move {
                let Ok(msg) = receiver.recv().await else {
                    return;
                };
                let _ = started_tx.send(());
                release.notified().await;
                let _ = sender.send(msg.coalesce().as_ref().to_vec()).await;
            }
        }
    };
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let shutdown = async move {
        let _ = stop_rx.await;
    };
    let served = exec.handle().spawn(serve_tcp_listener(
        listener,
        server_key,
        PeerPolicy::AllowAny,
        EncHandshakeBounds::default(),
        ListenerLimits::new(8, 8),
        shutdown,
        serve_fn,
    ));

    let session = dial_tcp_session_for_test(
        "127.0.0.1",
        addr.port(),
        &server_pk,
        PrivateKey::from_seed(32),
        HANDSHAKE_NAMESPACE.to_vec(),
        &exec,
    )
    .unwrap();
    let (mut sender, mut receiver) = session.into_parts();
    exec.handle().block_on(async {
        sender.send(b"ping".to_vec()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), started.recv())
            .await
            .unwrap()
            .unwrap();
    });

    stop_tx.send(()).unwrap();
    // The listener closes: a new connection is refused.
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(addr).is_ok() {
        assert!(Instant::now() < deadline, "listener still accepting");
        std::thread::sleep(Duration::from_millis(20));
    }
    // ...but the future waits for the session in flight.
    std::thread::sleep(Duration::from_millis(100));
    assert!(!served.is_finished(), "returned before the session drained");

    release.notify_one();
    let echoed = exec.handle().block_on(async {
        tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap()
            .unwrap()
    });
    assert_eq!(echoed.coalesce().as_ref(), b"ping");
    let result = exec.handle().block_on(async {
        tokio::time::timeout(Duration::from_secs(10), served)
            .await
            .unwrap()
            .unwrap()
    });
    assert!(result.is_ok(), "{result:?}");
}
