//! Capture actual native HTTP bytes independently of the signing helper.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::protocol::{PackKey, Transport};
use mkit_transport_connect::{ConnectTransport, EnvelopeSigner};

struct TestSigner(SigningKey);
impl EnvelopeSigner for TestSigner {
    fn public_key_hex(&self) -> String {
        to_hex_bytes(&self.0.verifying_key().to_bytes())
    }
    fn sign_hex(&self, message: &[u8; 32]) -> Result<String, String> {
        Ok(to_hex_bytes(&self.0.sign(message).to_bytes()))
    }
}

struct Captured {
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Captured {
    fn header(&self, name: &str) -> &str {
        let values: Vec<_> = self.headers.iter().filter(|(key, _)| key == name).collect();
        assert_eq!(values.len(), 1, "expected one {name} header");
        &values[0].1
    }
    fn has(&self, name: &str) -> bool {
        self.headers.iter().any(|(key, _)| key == name)
    }
}

fn capture_one(listener: &TcpListener, response: &[u8]) -> Captured {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
        if let Some(pos) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end]).unwrap();
    let mut lines = header_text.split("\r\n");
    let path = lines.next().unwrap().split(' ').nth(1).unwrap().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .unwrap()
        .1
        .parse()
        .unwrap();
    while bytes.len() - header_end < len {
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0);
        bytes.extend_from_slice(&buf[..n]);
    }
    stream.write_all(response).unwrap();
    Captured {
        path,
        headers,
        body: bytes[header_end..header_end + len].to_vec(),
    }
}

fn verify(c: &Captured, audience: &str, message: &[u8]) {
    let digest = to_hex(&hash(message));
    assert_eq!(c.header("x-digest"), digest);
    assert_eq!(c.header("x-content-commitment"), format!("body:{digest}"));
    assert_eq!(c.header("x-envelope-version"), "2");
    assert_eq!(c.header("x-audience"), audience);
    assert_eq!(c.header("x-repository"), "default");
    assert!(!c.has("content-encoding"));
    assert!(!c.has("connect-content-encoding"));
    let canonical = format!(
        "mkit-write:v2\n{audience}\ndefault\n{}\nbody:{digest}\n{}\n{}\n{}",
        c.path,
        c.header("x-created-at"),
        c.header("x-expires-at"),
        c.header("idempotency-key")
    );
    let pk: [u8; 32] = hex::decode(c.header("x-public-key"))
        .unwrap()
        .try_into()
        .unwrap();
    let sig = ed25519_dalek::Signature::from_slice(&hex::decode(c.header("x-signature")).unwrap())
        .unwrap();
    VerifyingKey::from_bytes(&pk)
        .unwrap()
        .verify_strict(&hash(canonical.as_bytes()), &sig)
        .unwrap();
}

#[test]
fn all_four_signed_reads_bind_native_message_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        (0..4)
            .map(|_| {
                capture_one(&listener,
        b"HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}"
    )
            })
            .collect::<Vec<_>>()
    });
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[17; 32])));
    let tx =
        ConnectTransport::connect_with_signed_reads(&format!("mkit+{endpoint}/default"), signer)
            .unwrap();
    assert!(tx.list_refs("refs/").is_err());
    assert!(tx.read_ref("refs/main").is_err());
    let key = PackKey::new([7; 32]);
    assert!(tx.pack_exists(&key).is_err());
    assert!(tx.download_pack(&key).is_err());
    let captures = server.join().unwrap();
    let expected = [
        ("ListRefs", [b"\x0a\x05refs/".as_slice(), &[]].concat()),
        ("ReadRef", [b"\x0a\x09refs/main".as_slice(), &[]].concat()),
        ("PackExists", [b"\x0a\x20".as_slice(), &[7; 32]].concat()),
        ("DownloadPack", [b"\x0a\x20".as_slice(), &[7; 32]].concat()),
    ];
    for (capture, (method, message)) in captures.iter().zip(expected) {
        assert_eq!(
            capture.path,
            format!("/mkit.transport.v1.TransportService/{method}")
        );
        if method == "DownloadPack" {
            assert_eq!(&capture.body[..5], &[0, 0, 0, 0, message.len() as u8]);
            assert_eq!(&capture.body[5..], message);
            assert_ne!(capture.header("x-digest"), to_hex(&hash(&capture.body)));
        } else {
            assert_eq!(capture.body, message);
        }
        verify(capture, &endpoint, &message);
    }
    let nonces: std::collections::HashSet<_> = captures
        .iter()
        .map(|c| c.header("idempotency-key"))
        .collect();
    assert_eq!(nonces.len(), 4);
}

#[test]
fn authenticated_redirect_does_not_reach_second_endpoint() {
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("127.0.0.1:0").unwrap();
    let second_url = format!(
        "http://{}/mkit.transport.v1.TransportService/ListRefs",
        second.local_addr().unwrap()
    );
    let response =
        format!("HTTP/1.1 302 Found\r\nlocation: {second_url}\r\ncontent-length: 0\r\n\r\n");
    let endpoint = format!("http://{}", first.local_addr().unwrap());
    let server = thread::spawn(move || capture_one(&first, response.as_bytes()));
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[18; 32])));
    let tx =
        ConnectTransport::connect_for_test_with_signed_reads(endpoint.parse().unwrap(), signer);
    assert!(tx.list_refs("").is_err());
    let captured = server.join().unwrap();
    assert!(captured.has("x-signature"));
    second.set_nonblocking(true).unwrap();
    assert!(
        second.accept().is_err(),
        "redirect forwarded an authenticated request"
    );
}

#[test]
fn default_and_write_only_envelope_reads_remain_unsigned() {
    for write_only in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            capture_one(&listener,
            b"HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}")
        });
        let tx = if write_only {
            ConnectTransport::connect_for_test_with_signer(
                endpoint.parse().unwrap(),
                Some(Arc::new(TestSigner(SigningKey::from_bytes(&[19; 32])))),
            )
        } else {
            ConnectTransport::connect_for_test(endpoint.parse().unwrap())
        };
        assert!(tx.list_refs("").is_err());
        let captured = server.join().unwrap();
        for name in [
            "x-signature",
            "x-public-key",
            "x-digest",
            "x-envelope-version",
        ] {
            assert!(!captured.has(name), "{name} added by unsigned read path");
        }
    }
}

#[test]
fn retry_re_signs_same_read_with_fresh_nonce() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let first = capture_one(&listener, b"HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: 23\r\n\r\n{\"code\":\"unavailable\"}\n");
        let second = capture_one(&listener, b"HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}");
        (first, second)
    });
    let signer = Arc::new(TestSigner(SigningKey::from_bytes(&[20; 32])));
    let tx =
        ConnectTransport::connect_for_test_with_signed_reads(endpoint.parse().unwrap(), signer);
    assert!(tx.list_refs("refs/").is_err());
    let (first, second) = server.join().unwrap();
    assert_eq!(first.body, second.body);
    assert_ne!(
        first.header("idempotency-key"),
        second.header("idempotency-key")
    );
    verify(&first, &endpoint, &first.body);
    verify(&second, &endpoint, &second.body);
}

/// Run after `apps/vcs-worker/tests/managed_data.py` against a fresh local
/// managed workerd. That fixture leaves reader and owner active and revokes
/// writer, and uploads `managed-pack-matrix`.
#[test]
#[ignore = "requires local managed workerd and the managed_data.py fixture"]
fn native_reads_match_managed_workerd_roles_and_revocation() {
    let endpoint = std::env::var("MKIT_MANAGED_TEST_URL").expect("managed workerd URL");
    let connect = |seed: u8, url: &str| {
        ConnectTransport::connect_with_signed_reads(
            url,
            Arc::new(TestSigner(SigningKey::from_bytes(&[seed; 32]))),
        )
        .unwrap()
    };
    let url = format!("mkit+{endpoint}/managed-test");
    let pack_bytes = b"managed-pack-matrix";
    let pack = PackKey::new(hash(pack_bytes));

    for seed in [7, 8] {
        let tx = connect(seed, &url);
        tx.list_refs("refs/heads/").expect("authorized ListRefs");
        tx.read_ref("refs/heads/main").expect("authorized ReadRef");
        assert!(tx.pack_exists(&pack).expect("authorized PackExists"));
        assert_eq!(
            tx.download_pack(&pack).expect("authorized DownloadPack"),
            pack_bytes
        );
    }

    let reader = connect(8, &url);
    assert!(
        reader
            .update_ref(
                "refs/heads/native-reader-denied",
                mkit_core::protocol::RefWriteCondition::Any,
                &[1; 32],
            )
            .is_err()
    );
    assert!(connect(9, &url).list_refs("refs/heads/").is_err());
    assert!(
        connect(8, &format!("mkit+{endpoint}/wrong-repository"))
            .list_refs("refs/heads/")
            .is_err()
    );
    assert!(
        ConnectTransport::connect(&url)
            .unwrap()
            .list_refs("refs/heads/")
            .is_err()
    );
}

/// Run with writer still present in the disposable managed policy. The
/// publication is a throwaway ref in local workerd state, never a live ref.
#[test]
#[ignore = "requires local managed workerd with active writer"]
fn native_writer_reads_and_writes_when_live() {
    let endpoint = std::env::var("MKIT_MANAGED_TEST_URL").expect("managed workerd URL");
    let tx = ConnectTransport::connect_with_signed_reads(
        &format!("mkit+{endpoint}/managed-test"),
        Arc::new(TestSigner(SigningKey::from_bytes(&[9; 32]))),
    )
    .unwrap();
    let pack = PackKey::new(hash(b"managed-pack-matrix"));
    tx.list_refs("refs/heads/").expect("writer ListRefs");
    tx.read_ref("refs/heads/main").expect("writer ReadRef");
    assert!(tx.pack_exists(&pack).expect("writer PackExists"));
    assert_eq!(
        tx.download_pack(&pack).expect("writer DownloadPack"),
        b"managed-pack-matrix"
    );
    tx.update_ref(
        "refs/heads/native-writer-local-fixture",
        mkit_core::protocol::RefWriteCondition::Any,
        &[2; 32],
    )
    .expect("writer UpdateRef");
}

/// Run after removing the reader from the fixture policy. Every method must
/// fail on a new attempt; the client cannot fall back to an unsigned read.
#[test]
#[ignore = "requires local managed workerd after reader revocation"]
fn native_revoked_reader_has_no_read_fallback() {
    let endpoint = std::env::var("MKIT_MANAGED_TEST_URL").expect("managed workerd URL");
    let tx = ConnectTransport::connect_with_signed_reads(
        &format!("mkit+{endpoint}/managed-test"),
        Arc::new(TestSigner(SigningKey::from_bytes(&[8; 32]))),
    )
    .unwrap();
    let pack = PackKey::new(hash(b"managed-pack-matrix"));
    assert!(tx.list_refs("refs/heads/").is_err());
    assert!(tx.read_ref("refs/heads/main").is_err());
    assert!(tx.pack_exists(&pack).is_err());
    assert!(tx.download_pack(&pack).is_err());
}
