//! Host-selected compatibility for legacy HTTP acceptance and diagnostics.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use mkit_core::protocol::{BackoffIterator, Transport, TransportError};
use mkit_transport_connect::ConnectTransport;
use std::io::{Read, Write};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

struct Fixture {
    client: ConnectTransport,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(status: &str, headers: &str, body: Vec<u8>) -> Self {
        Self::responses(vec![(status.into(), headers.into(), body)])
    }
    fn responses(responses: Vec<(String, String, Vec<u8>)>) -> Self {
        assert!(!responses.is_empty());
        let responses: Vec<_> = responses
            .into_iter()
            .map(|(status, headers, body)| {
                let head = format!(
                    "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                (head, body)
            })
            .collect();
        RETRIES.with(|count| count.set(0));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            'connections: while !stopped.load(Ordering::SeqCst) {
                let (mut socket, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                // Accepted sockets may inherit the listener's nonblocking mode.
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let count = match socket.read(&mut buffer) {
                        Ok(0) => continue 'connections,
                        Ok(count) => count,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::WouldBlock
                            ) =>
                        {
                            continue 'connections;
                        }
                        Err(error) => panic!("read request: {error}"),
                    };
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() < 64 * 1024);
                }
                let header_end = request
                    .windows(4)
                    .position(|bytes| bytes == b"\r\n\r\n")
                    .expect("request headers")
                    + 4;
                if !drain_request_body(&mut socket, &mut request, header_end) {
                    continue 'connections;
                }
                let index = {
                    let mut requests = captured.lock().unwrap();
                    let index = requests.len();
                    requests.push(String::from_utf8_lossy(&request).into_owned());
                    index
                };
                let (head, body) = &responses[index.min(responses.len() - 1)];
                if socket.write_all(head.as_bytes()).is_ok() {
                    // A bounded client may close before the remaining body.
                    let _ = socket.write_all(body);
                }
            }
        });
        let client =
            ConnectTransport::connect_for_test(format!("http://{address}").parse().unwrap())
                .with_retry_hooks_for_test(one_retry, record_retry);
        Self {
            client,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Err(payload) = self.thread.take().unwrap().join()
            && !std::thread::panicking()
        {
            std::panic::resume_unwind(payload);
        }
    }
}
fn receive_until(socket: &mut std::net::TcpStream, request: &mut Vec<u8>, end: usize) -> bool {
    let mut buffer = [0; 1024];
    while request.len() < end {
        match socket.read(&mut buffer) {
            Ok(0) => return false,
            Ok(count) => request.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return false;
            }
            Err(error) => panic!("read request body: {error}"),
        }
        assert!(request.len() < 64 * 1024);
    }
    true
}
fn request_line_end(
    socket: &mut std::net::TcpStream,
    request: &mut Vec<u8>,
    cursor: usize,
) -> Option<usize> {
    loop {
        if let Some(offset) = request[cursor..]
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
        {
            return Some(cursor + offset);
        }
        let next = request.len() + 1;
        if !receive_until(socket, request, next) {
            return None;
        }
    }
}
fn drain_request_body(
    socket: &mut std::net::TcpStream,
    request: &mut Vec<u8>,
    header_end: usize,
) -> bool {
    let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
    if headers.lines().any(|line| {
        line.strip_prefix("transfer-encoding:")
            .is_some_and(|value| value.split(',').any(|coding| coding.trim() == "chunked"))
    }) {
        let mut cursor = header_end;
        loop {
            let Some(end) = request_line_end(socket, request, cursor) else {
                return false;
            };
            let size = usize::from_str_radix(
                std::str::from_utf8(&request[cursor..end])
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .trim(),
                16,
            )
            .unwrap();
            cursor = end + 2;
            if size == 0 {
                loop {
                    let Some(end) = request_line_end(socket, request, cursor) else {
                        return false;
                    };
                    if end == cursor {
                        return true;
                    }
                    cursor = end + 2;
                }
            }
            if !receive_until(socket, request, cursor + size + 2) {
                return false;
            }
            assert_eq!(&request[cursor + size..cursor + size + 2], b"\r\n");
            cursor += size + 2;
        }
    }
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("content-length:")
                .map(|value| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    receive_until(socket, request, header_end + content_length)
}

thread_local! {
    static RETRIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
fn record_retry(_: Duration) {
    RETRIES.with(|count| count.set(count.get() + 1));
}
fn one_retry() -> BackoffIterator {
    BackoffIterator::with(Duration::ZERO, Duration::ZERO, 1)
}

#[test]
fn legacy_unary_acceptance_and_timeout_header_are_preserved() {
    for (status, headers) in [
        ("204 No Content", ""),
        (
            "200 OK",
            "Content-Type: application/proto; charset=binary\r\n",
        ),
        ("200 OK", "Content-Type: application/proto-extra\r\n"),
        ("200 OK", "Content-Encoding: gzip\r\n"),
    ] {
        let fixture = Fixture::new(status, headers, Vec::new());
        assert_eq!(fixture.client.read_ref("heads/main").unwrap(), None);
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let timeout = requests[0]
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("connect-timeout-ms: ")
                    .map(|value| value.parse::<u64>().unwrap())
            })
            .expect("legacy server timeout header");
        assert!(timeout > 0 && timeout <= 30_000);
    }
}

#[test]
fn legacy_http_and_body_diagnostics_keep_their_retry_classes() {
    for (status, headers, body, retries, expected) in [
        ("302 Found", "", b"".as_slice(), 1, "HTTP error 302: "),
        (
            "503 Unavailable",
            "",
            b"temporary".as_slice(),
            2,
            "HTTP error 503: temporary",
        ),
        (
            "200 OK",
            "Content-Encoding: br\r\n",
            b"encoded".as_slice(),
            1,
            "unsupported compression encoding: br",
        ),
        (
            "200 OK",
            "Content-Type: text/plain\r\n",
            b"".as_slice(),
            1,
            "unexpected content-type: text/plain",
        ),
    ] {
        let fixture = Fixture::new(status, headers, body.to_vec());
        let error = fixture.client.read_ref("heads/main").unwrap_err();
        match error {
            TransportError::RemoteError(message) => assert_eq!(message, expected),
            TransportError::ServerError { status: 503 } => {
                assert_eq!(expected, "HTTP error 503: temporary");
            }
            other => panic!("unexpected diagnostic: {other:?}"),
        }
        assert_eq!(fixture.requests.lock().unwrap().len(), retries);
    }
}

#[test]
fn metadata_response_bound_preserves_resource_exhausted_retry() {
    let fixture = Fixture::new("200 OK", "", vec![0; 4 * 1024 * 1024 + 1]);
    let result = fixture.client.read_ref("heads/main");
    let requests = fixture.requests.lock().unwrap().len();
    let retries = RETRIES.with(std::cell::Cell::get);
    assert!(
        matches!(&result, Err(TransportError::ServerError { status: 429 })),
        "result={result:?}, requests={requests}, scheduled_retries={retries}"
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
}

#[test]
fn incomplete_error_envelopes_keep_http_fallback_codes_and_messages() {
    for body in [
        br#"{}"#.as_slice(),
        br#"{"code":"future","message":""}"#.as_slice(),
    ] {
        let fixture = Fixture::new(
            "503 Unavailable",
            "Content-Type: application/json\r\n",
            body.to_vec(),
        );
        assert!(matches!(
            fixture.client.read_ref("heads/main"),
            Err(TransportError::ServerError { status: 503 })
        ));
        assert_eq!(
            fixture.requests.lock().unwrap().len(),
            2,
            "body={}, scheduled_retries={}",
            String::from_utf8_lossy(body),
            RETRIES.with(std::cell::Cell::get)
        );
    }
}

struct SlowSigner;
impl mkit_transport_connect::EnvelopeSigner for SlowSigner {
    fn public_key_hex(&self) -> String {
        "ab".repeat(32)
    }
    fn sign_hex(&self, _: &[u8; 32]) -> Result<String, String> {
        std::thread::sleep(Duration::from_millis(30));
        Ok("cd".repeat(64))
    }
}
#[test]
fn signing_time_is_charged_to_the_existing_attempt_timeout() {
    let mut fixture = Fixture::new("200 OK", "", Vec::new());
    fixture.client = ConnectTransport::connect_for_test_with_signer(
        fixture.client.origin().parse().unwrap(),
        Some(Arc::new(SlowSigner)),
    )
    .with_unary_timeout(Duration::from_millis(5));
    assert!(
        matches!(fixture.client.read_ref("heads/main"), Err(TransportError::RemoteError(message)) if message == "client-side deadline exceeded")
    );
    assert!(fixture.requests.lock().unwrap().is_empty());
}

struct PaymentResponder(std::sync::atomic::AtomicUsize);
impl mkit_transport_connect::admission::AdmissionResponder for PaymentResponder {
    fn respond(
        &self,
        context: &mkit_transport_connect::admission::AdmissionContext<'_>,
    ) -> Result<Vec<(String, String)>, mkit_transport_connect::admission::AdmissionResponderError>
    {
        assert!(context.procedure.ends_with("/UpdateRef"));
        assert_eq!(
            context.required.www_authenticate,
            ["Payment realm=repository"]
        );
        assert_eq!(context.required.payment_required, ["opaque-challenge"]);
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(vec![(
            "Payment-Authorization".into(),
            "helper-response".into(),
        )])
    }
}
#[test]
fn malformed_gzip_402_runs_admission_helper_and_retries_both_facade_paths() {
    for via_source in [false, true] {
        let mut fixture = Fixture::responses(vec![
            ("402 Payment Required".into(),
             "Content-Encoding: gzip\r\nWWW-Authenticate: Payment realm=repository\r\nPayment-Required: opaque-challenge\r\n".into(),
             b"malformed gzip".to_vec()),
            ("200 OK".into(), "Content-Type: application/proto\r\n".into(), Vec::new()),
        ]);
        let helper = Arc::new(PaymentResponder(std::sync::atomic::AtomicUsize::new(0)));
        fixture.client =
            ConnectTransport::connect_for_test(fixture.client.origin().parse().unwrap())
                .with_admission(mkit_transport_connect::admission::AdmissionPolicy::new(
                    helper.clone(),
                ));
        if via_source {
            fixture
                .client
                .with_source(|source| {
                    source.update_ref(
                        "refs/heads/main",
                        mkit_core::protocol::RefWriteCondition::Missing,
                        &[2; 32],
                    )
                })
                .unwrap()
                .unwrap();
        } else {
            fixture
                .client
                .update_ref(
                    "refs/heads/main",
                    mkit_core::protocol::RefWriteCondition::Missing,
                    &[2; 32],
                )
                .unwrap();
        }
        assert_eq!(helper.0.load(Ordering::SeqCst), 1);
        let requests = fixture.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            !requests[0]
                .to_ascii_lowercase()
                .contains("payment-authorization:")
        );
        assert!(
            requests[1]
                .to_ascii_lowercase()
                .contains("payment-authorization: helper-response\r\n")
        );
    }
}
