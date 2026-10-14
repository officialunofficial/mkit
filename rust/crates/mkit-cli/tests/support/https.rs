//! Real certificate verification in front of the loopback Connect service.
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};
use tokio_rustls::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};

pub(super) fn ca_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/support/fixtures/ca/ca.crt")
}

pub(super) struct Proxy {
    pub(super) port: u16,
    connections: Arc<AtomicUsize>,
    http2_connections: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Proxy {
    pub(super) fn new(target_port: u16) -> Self {
        Self::configured(target_port, Duration::ZERO, false)
    }

    /// Propagation delay is applied to encrypted bytes, including TLS flights.
    pub(super) fn with_latency(target_port: u16, one_way: Duration) -> Self {
        Self::configured(target_port, one_way, true)
    }

    fn configured(target_port: u16, one_way: Duration, http2: bool) -> Self {
        let http2_connections = Arc::new(AtomicUsize::new(0));
        let negotiated_http2 = Arc::clone(&http2_connections);
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::clone(&connections);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let cert = CertificateDer::from_pem_slice(include_bytes!("fixtures/ca/server.crt")).unwrap();
                let key = PrivateKeyDer::try_from(include_bytes!("fixtures/ca/server-pk8.der").to_vec()).unwrap();
                let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
                let mut config = ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions().unwrap()
                    .with_no_client_auth().with_single_cert(vec![cert], key).unwrap();
                config.alpn_protocols = if http2 {
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                } else {
                    vec![b"http/1.1".to_vec()]
                };
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready_tx.send(listener.local_addr().unwrap().port()).unwrap();
                tokio::pin!(stopped);
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        connection = listener.accept() => {
                            let (stream, _) = connection.unwrap();
                            stream.set_nodelay(true).unwrap();
                            accepted.fetch_add(1, Ordering::SeqCst);
                            let negotiated_http2 = Arc::clone(&negotiated_http2);
                            let acceptor = acceptor.clone();
                            tokio::spawn(async move {
                                // The bridge sits before rustls: handshake records
                                // and application records have identical latency.
                                let (client_side, server_side) = tokio::io::duplex(65_536);
                                let bridge = tokio::spawn(async move {
                                    let (client_read, client_write) = stream.into_split();
                                    let (server_read, server_write) = tokio::io::split(client_side);
                                    tokio::try_join!(
                                        delayed_copy(client_read, server_write, one_way),
                                        delayed_copy(server_read, client_write, one_way),
                                    )
                                });
                                if let Ok(mut tls) = acceptor.accept(server_side).await {
                                    if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
                                        negotiated_http2.fetch_add(1, Ordering::SeqCst);
                                    }
                                    let mut target = tokio::net::TcpStream::connect(("127.0.0.1", target_port)).await.unwrap();
                                    target.set_nodelay(true).unwrap();
                                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut target).await;
                                }
                                bridge.abort();
                            });
                        }
                    }
                }
            });
        });
        Self {
            port: ready_rx.recv().unwrap(),
            connections,
            http2_connections,
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    pub(super) fn http2_connections(&self) -> usize {
        self.http2_connections.load(Ordering::SeqCst)
    }

    pub(super) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

async fn delayed_copy(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    mut writer: impl tokio::io::AsyncWrite + Unpin,
    one_way: Duration,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buffer = vec![0; 32_768].into_boxed_slice();
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return writer.shutdown().await;
        }
        if !one_way.is_zero() {
            tokio::time::sleep(one_way).await;
        }
        writer.write_all(&buffer[..count]).await?;
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
