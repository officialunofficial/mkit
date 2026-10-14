//! Real certificate verification in front of the loopback Connect service.
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
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
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Proxy {
    pub(super) fn new(target_port: u16) -> Self {
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
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready_tx.send(listener.local_addr().unwrap().port()).unwrap();
                tokio::pin!(stopped);
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        connection = listener.accept() => {
                            let (stream, _) = connection.unwrap();
                            let acceptor = acceptor.clone();
                            tokio::spawn(async move {
                                if let Ok(mut tls) = acceptor.accept(stream).await {
                                    let mut target = tokio::net::TcpStream::connect(("127.0.0.1", target_port)).await.unwrap();
                                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut target).await;
                                }
                            });
                        }
                    }
                }
            });
        });
        Self {
            port: ready_rx.recv().unwrap(),
            stop: Some(stop),
            thread: Some(thread),
        }
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
