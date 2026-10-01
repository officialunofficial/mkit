//! Real TLS verification in front of the memory-backed Connect fixture.
use connectrpc::rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use mkit_core::{
    hash::hash,
    protocol::{BackoffIterator, PackKey, Transport, TransportError},
};
use mkit_transport_connect::ConnectTransport;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ca")
        .join(name)
}
fn client(url: &str, ca: Option<&Path>) -> ConnectTransport {
    ConnectTransport::connect_with_signer_and_ca_file(url, None, ca)
        .unwrap()
        .with_retry_hooks_for_test(BackoffIterator::new, |_| {})
}
// Run real trust probes with an isolated environment; a developer's explicit
// CA file must not replace the fixture or invalidate the default-root control.
fn isolated(name: &str) -> bool {
    if std::env::var("MKIT_CA_TEST_CHILD").as_deref() == Ok(name) {
        return false;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name])
        .env_remove("MKIT_SSL_CA_FILE")
        .env("MKIT_CA_TEST_CHILD", name)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    true
}
struct Proxy {
    port: u16,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
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
fn proxy(target_port: u16) -> Proxy {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let cert = CertificateDer::from_pem_file(fixture("server.crt")).unwrap();
            let key = PrivateKeyDer::try_from(include_bytes!("../fixtures/ca/server-pk8.der").to_vec()).unwrap();
            let provider = Arc::new(connectrpc::rustls::crypto::ring::default_provider());
            let mut cfg = ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap()
                .with_no_client_auth().with_single_cert(vec![cert], key).unwrap();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
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
                                let mut target = tokio::net::TcpStream::connect(("127.0.0.1",target_port)).await.unwrap();
                                let _ = tokio::io::copy_bidirectional(&mut tls, &mut target).await;
                            }
                        });
                    }
                }
            }
        });
    });
    Proxy {
        port: ready_rx.recv().unwrap(),
        stop: Some(stop),
        thread: Some(thread),
    }
}
#[test]
fn extra_ca_trusts_real_rpc_and_streamed_pack_transfers() {
    if isolated("tls_tests::extra_ca_trusts_real_rpc_and_streamed_pack_transfers") {
        return;
    }
    let (port, shutdown, server) = super::spawn_server();
    let proxy = proxy(port);
    let client = client(
        &format!("mkit+https://localhost:{}/default", proxy.port),
        Some(&fixture("ca.crt")),
    );
    assert!(client.list_refs("").unwrap().is_empty());
    let data = vec![0xAB; 3 * 1024 * 1024];
    let key = PackKey::from(hash(&data));
    assert!(!client.pack_exists(&key).unwrap());
    client.upload_pack(&data, &key).unwrap();
    assert!(client.pack_exists(&key).unwrap());
    assert_eq!(client.download_pack(&key).unwrap(), data);
    drop(client);
    drop(proxy);
    shutdown.send(()).unwrap();
    server.join().unwrap();
}
#[test]
fn custom_ca_keeps_hostname_verification_and_default_rejects_untrusted_ca() {
    if isolated("tls_tests::custom_ca_keeps_hostname_verification_and_default_rejects_untrusted_ca")
    {
        return;
    }
    let (port, shutdown, server) = super::spawn_server();
    let proxy = proxy(port);
    for (host, ca) in [("127.0.0.1", Some(fixture("ca.crt"))), ("localhost", None)] {
        let client = client(
            &format!("mkit+https://{host}:{}/default", proxy.port),
            ca.as_deref(),
        );
        assert!(
            matches!(
                client.list_refs(""),
                Err(TransportError::ServerError { status: 503 })
            ),
            "{host} must not bypass TLS verification"
        );
    }
    // Same address and server certificate work with the proper name and CA.
    assert!(
        client(
            &format!("mkit+https://localhost:{}/default", proxy.port),
            Some(&fixture("ca.crt"))
        )
        .list_refs("")
        .unwrap()
        .is_empty()
    );
    drop(proxy);
    shutdown.send(()).unwrap();
    server.join().unwrap();
}
#[test]
#[ignore = "subprocess helper, invoked with an isolated environment"]
fn env_probe() {
    let fallback = std::env::var_os("MKIT_TEST_CA_FALLBACK").unwrap();
    let expected_success = std::env::var("MKIT_TEST_CA_SUCCESS").unwrap() == "true";
    let result = ConnectTransport::connect_with_signer_and_ca_file(
        "mkit+https://localhost/default",
        None,
        Some(Path::new(&fallback)),
    );
    assert_eq!(result.is_ok(), expected_success);
    if !expected_success {
        assert!(matches!(result, Err(TransportError::TlsConfiguration(_))));
    }
}
#[test]
fn ca_environment_precedes_the_config_file_without_process_global_mutation() {
    for (env_file, fallback, success) in [
        (Some(fixture("ca.crt")), fixture("missing.crt"), true),
        (Some(fixture("missing.crt")), fixture("ca.crt"), false),
        (Some(PathBuf::new()), fixture("ca.crt"), false),
        (None, fixture("ca.crt"), true),
    ] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--ignored", "--exact", "tls_tests::env_probe"])
            .env_remove("MKIT_SSL_CA_FILE")
            .env("MKIT_TEST_CA_FALLBACK", fallback)
            .env("MKIT_TEST_CA_SUCCESS", success.to_string());
        if let Some(path) = env_file {
            command.env("MKIT_SSL_CA_FILE", path);
        }
        let result = command.output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
