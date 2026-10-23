//! The security-relevant behaviour of `NativeHttp`, against a raw loopback
//! responder that misbehaves on purpose: redirects, oversized bodies, gzip
//! (good and bomb), an unsupported coding, a stalled body, and cleartext to a
//! non-loopback host.
#![cfg(feature = "connect-native")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::time::Duration;

use http::{Request, StatusCode};
use mkit_client::HttpTransport;
use mkit_sync::{Executor as _, NativeHttp};

/// Read a whole request (headers plus the declared body) before answering, so
/// closing never resets a connection that still has unread data.
fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
            let want = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= end + 4 + want {
                break;
            }
        }
    }
    request
}

/// Serve exactly one canned HTTP response, then close. Returns the base URL.
fn respond_once(response: Vec<u8>, stall_after_headers: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        let _ = stream.write_all(&response);
        let _ = stream.flush();
        if stall_after_headers {
            std::thread::sleep(Duration::from_secs(5));
        }
    });
    format!("http://{addr}/")
}

fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn send(http: &NativeHttp, url: &str, limit: usize) -> Result<http::Response<Vec<u8>>, String> {
    let request = Request::post(url).body(b"ping".to_vec()).unwrap();
    http.block_on(http.send(request, limit))
}

#[test]
fn a_plain_response_is_returned() {
    let url = respond_once(response("200 OK", &[], b"hello"), false);
    let http = NativeHttp::new().unwrap();

    let reply = send(&http, &url, 1024).unwrap();

    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.body(), b"hello");
}

#[test]
fn a_gzip_response_is_inflated_and_loses_its_coding_headers() {
    let body = gzip(&b"mkit".repeat(100));
    let url = respond_once(
        response("200 OK", &[("content-encoding", "gzip")], &body),
        false,
    );
    let http = NativeHttp::new().unwrap();

    let reply = send(&http, &url, 4096).unwrap();

    assert_eq!(reply.body(), &b"mkit".repeat(100));
    assert!(reply.headers().get("content-encoding").is_none());
    assert!(reply.headers().get("content-length").is_none());
}

#[test]
fn a_gzip_bomb_is_refused_once_inflated_past_the_limit() {
    // 1 MiB of zeros compresses to about a kilobyte: small on the wire, large
    // once inflated.
    let body = gzip(&vec![0u8; 1 << 20]);
    assert!(body.len() < 4096);
    let url = respond_once(
        response("200 OK", &[("content-encoding", "gzip")], &body),
        false,
    );
    let http = NativeHttp::new().unwrap();

    let err = send(&http, &url, 64 * 1024).unwrap_err();

    assert!(err.contains("decompressed"), "{err}");
}

#[test]
fn an_oversized_response_is_refused_while_it_is_received() {
    let url = respond_once(response("200 OK", &[], &vec![7u8; 100_000]), false);
    let http = NativeHttp::new().unwrap();

    let err = send(&http, &url, 1024).unwrap_err();

    assert!(err.contains("size limit"), "{err}");
}

#[test]
fn only_gzip_is_accepted_as_a_content_coding() {
    for coding in ["br", "zstd", "deflate"] {
        let url = respond_once(
            response("200 OK", &[("content-encoding", coding)], b"x"),
            false,
        );
        let http = NativeHttp::new().unwrap();

        let err = send(&http, &url, 1024).unwrap_err();

        assert!(err.contains("gzip only"), "{coding}: {err}");
    }
}

#[test]
fn a_redirect_is_refused_not_followed() {
    let url = respond_once(
        response(
            "307 Temporary Redirect",
            &[("location", "http://127.0.0.1:1/elsewhere")],
            b"",
        ),
        false,
    );
    let http = NativeHttp::new().unwrap();

    let err = send(&http, &url, 1024).unwrap_err();

    assert!(err.contains("redirect refused"), "{err}");
}

#[test]
fn a_stalled_body_times_out() {
    // Promises 10 bytes, sends none.
    let head = b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n".to_vec();
    let url = respond_once(head, true);
    let http = NativeHttp::new()
        .unwrap()
        .with_timeout(Duration::from_millis(300));

    let err = send(&http, &url, 1024).unwrap_err();

    assert!(err.contains("timed out"), "{err}");
}

#[test]
fn cleartext_http_to_a_non_loopback_host_is_refused_unless_allowed() {
    let http = NativeHttp::new().unwrap();
    // The refusal happens before any connection is attempted.
    let err = send(&http, "http://203.0.113.9/", 1024).unwrap_err();
    assert!(err.contains("non-loopback"), "{err}");

    let allowed = NativeHttp::new()
        .unwrap()
        .allow_insecure_http(true)
        .with_timeout(Duration::from_millis(200));
    let err = send(&allowed, "http://203.0.113.9/", 1024).unwrap_err();
    assert!(!err.contains("non-loopback"), "{err}");
}

const READ_URL_PATH: &str = "mkit.transport.v1.TransportService/ListRefs";
const WRITE_URL_PATH: &str = "mkit.transport.v1.TransportService/UpdateRef";

fn read_request_to(url: &str) -> Request<Vec<u8>> {
    Request::post(format!("{url}{READ_URL_PATH}"))
        .body(b"ping".to_vec())
        .unwrap()
}

fn signed_write_to(url: &str) -> Request<Vec<u8>> {
    Request::post(format!("{url}{WRITE_URL_PATH}"))
        .header("x-signature", "fixed-signature")
        .header("idempotency-key", "fixed-nonce")
        .body(b"signed mutation".to_vec())
        .unwrap()
}

/// What the server saw after the client's second request.
struct Stale {
    /// The second request, read in full on the kept connection (never answered).
    unanswered: Vec<u8>,
    /// Requests that arrived on later connections, each answered `second`.
    later: Vec<Vec<u8>>,
    /// The listener, nonblocking, to look for a connection that must not exist.
    listener: TcpListener,
}

/// Serves one keep-alive exchange, then holds the connection open until the
/// client has written its next request on it, and closes without answering:
/// exactly a server that closes an idle connection as the request arrives.
/// With `expect_resend`, it then answers one later connection (bounded wait for
/// an event the test requires, not a sleep that hides a race).
fn close_when_next_request_arrives(
    expect_resend: bool,
) -> (String, std::thread::JoinHandle<Stale>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stale, _) = listener.accept().unwrap();
        stale
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_request(&mut stale);
        stale
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nfirst")
            .unwrap();
        let unanswered = read_request(&mut stale);
        drop(stale);
        listener.set_nonblocking(true).unwrap();
        let mut later = Vec::new();
        if expect_resend {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while later.is_empty() && std::time::Instant::now() < deadline {
                if let Ok((mut next, _)) = listener.accept() {
                    next.set_nonblocking(false).unwrap();
                    next.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    later.push(read_request(&mut next));
                    next.write_all(&response("200 OK", &[], b"second")).unwrap();
                } else {
                    std::thread::yield_now();
                }
            }
        }
        Stale {
            unanswered,
            later,
            listener,
        }
    });
    (url, server)
}

#[test]
fn two_sequential_requests_work_against_a_server_that_closes_after_each_response() {
    // Keep-alive on the wire (no `connection: close`), then the server closes
    // the socket: the second request must still succeed whether the close is
    // observed before the request is written (hyper discards the connection)
    // or after (the unanswered read is resent on a fresh connection). Either
    // order must succeed, so this is a smoke test needing no sleep; the
    // `..._is_resent_...` tests pin the resend path deterministically.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
            let _ = stream.flush();
            // Dropped here: the connection closes although it was keep-alive.
        }
    });
    let http = NativeHttp::new().unwrap();
    let url = format!("http://{addr}/");

    for _ in 0..2 {
        let reply = http
            .block_on(http.send(read_request_to(&url), 1024))
            .unwrap();
        assert_eq!(reply.body(), b"ok");
    }
}

#[test]
fn a_read_unanswered_on_a_reused_connection_is_resent_once_on_a_fresh_one() {
    let (url, server) = close_when_next_request_arrives(true);
    let http = NativeHttp::new().unwrap();

    let first = http
        .block_on(http.send(read_request_to(&url), 1024))
        .unwrap();
    // Let the connection task return the connection to the pool (the runtime
    // only runs inside `block_on`), without involving the network.
    http.block_on(async {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    });
    // The server holds the connection open until this request is written to
    // it, then closes it without a response: written, unanswered.
    let second = http
        .block_on(http.send(read_request_to(&url), 1024))
        .unwrap();

    assert_eq!(first.body(), b"first");
    assert_eq!(second.body(), b"second");
    let seen = server.join().unwrap();
    assert!(!seen.unanswered.is_empty(), "the race was not reproduced");
    assert_eq!(seen.later.len(), 1, "resent exactly once");
    assert!(seen.later[0].ends_with(b"ping"));
    assert!(seen.listener.accept().is_err(), "resent more than once");
}

#[test]
fn a_signed_read_unanswered_on_a_reused_connection_is_resent() {
    let (url, server) = close_when_next_request_arrives(true);
    let http = NativeHttp::new().unwrap();
    http.block_on(http.send(read_request_to(&url), 1024))
        .unwrap();
    http.block_on(async {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    });
    // Signed reads carry the envelope headers but record no replay entry.
    let request = Request::post(format!("{url}{READ_URL_PATH}"))
        .header("x-signature", "fixed-signature")
        .header("idempotency-key", "fixed-nonce")
        .body(b"ping".to_vec())
        .unwrap();

    let reply = http.block_on(http.send(request, 1024)).unwrap();

    assert_eq!(reply.body(), b"second");
    let seen = server.join().unwrap();
    assert!(!seen.unanswered.is_empty(), "the race was not reproduced");
    assert_eq!(seen.later.len(), 1);
}

#[test]
fn a_signed_write_unanswered_on_a_reused_connection_is_not_resent() {
    use mkit_client::ChannelError;
    let (url, server) = close_when_next_request_arrives(false);
    let http = NativeHttp::new().unwrap();
    http.block_on(http.send(read_request_to(&url), 1024))
        .unwrap();

    let err = http
        .block_on(http.send_classified(signed_write_to(&url), 1024))
        .unwrap_err();

    // The typed, retryable error: the caller keeps the signed identity and
    // decides, because the server may have applied the write.
    assert!(matches!(err, ChannelError::Transient(_)), "{err:?}");
    // The error is returned only after any resend would have connected.
    let seen = server.join().unwrap();
    assert!(seen.unanswered.ends_with(b"signed mutation"));
    assert!(seen.listener.accept().is_err(), "a write was resent");
}

#[test]
fn a_read_failing_on_a_fresh_connection_is_not_resent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_request(&mut stream);
        drop(stream);
        // The client's only error has been returned by the time it is joined;
        // a resend would already be queued on the listener.
        listener.set_nonblocking(true).unwrap();
        listener
    });
    let http = NativeHttp::new().unwrap();

    let err = http
        .block_on(http.send(read_request_to(&url), 1024))
        .unwrap_err();

    assert!(
        err.contains("connection closed before message completed"),
        "{err}"
    );
    let listener = server.join().unwrap();
    assert!(
        listener.accept().is_err(),
        "a fresh-connection failure was resent"
    );
}

#[test]
fn sequential_reads_and_signed_writes_reuse_a_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let mut connections = 0;
        let mut requests = Vec::new();
        while requests.len() < 3 {
            let (mut socket, _) = listener.accept().unwrap();
            connections += 1;
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            loop {
                let request = read_request(&mut socket);
                if request.is_empty() {
                    break;
                }
                requests.push(request);
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .unwrap();
                if requests.len() == 3 {
                    return (connections, requests);
                }
            }
        }
        (connections, requests)
    });
    let http = NativeHttp::new().unwrap();
    for procedure in ["ListRefs", "ReadRef", "UpdateRef"] {
        let request = Request::post(format!(
            "http://{address}/mkit.transport.v1.TransportService/{procedure}"
        ))
        .header("x-signature", "fixed-signature")
        .header("idempotency-key", "fixed-nonce")
        .body(b"same signed bytes".to_vec())
        .unwrap();
        assert_eq!(
            http.block_on(http.send(request, 1024)).unwrap().body(),
            b"ok"
        );
    }
    drop(http);
    let (connections, requests) = server.join().unwrap();
    assert_eq!(connections, 1, "each RPC must not pay another handshake");
    assert_eq!(requests.len(), 3);
    for request in requests {
        assert!(request.ends_with(b"same signed bytes"));
        assert!(String::from_utf8_lossy(&request).contains("x-signature: fixed-signature"));
    }
}

#[test]
fn a_signed_request_received_before_disconnect_is_not_replayed_by_the_pool() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_request(&mut socket);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .unwrap();
        // The write is deliberately received in full, then loses its reply.
        // Allow a separate connection on the unfixed transport so this also
        // tests the parent without hanging.
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut written = read_request(&mut socket);
        if written.is_empty() {
            (socket, _) = listener.accept().unwrap();
            written = read_request(&mut socket);
        }
        drop(socket);
        listener.set_nonblocking(true).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(listener.accept().is_err(), "a written request was replayed");
        written
    });
    let http = NativeHttp::new()
        .unwrap()
        .with_timeout(Duration::from_secs(2));
    assert_eq!(
        send(&http, &format!("http://{address}/"), 1024)
            .unwrap()
            .body(),
        b"ok"
    );
    let request = Request::post(format!(
        "http://{address}/mkit.transport.v1.TransportService/UpdateRef"
    ))
    .header("x-signature", "fixed-signature")
    .header("idempotency-key", "fixed-nonce")
    .body(b"signed mutation".to_vec())
    .unwrap();
    assert!(http.block_on(http.send(request, 1024)).is_err());
    let written = server.join().unwrap();
    assert!(written.ends_with(b"signed mutation"));
    assert!(String::from_utf8_lossy(&written).contains("idempotency-key: fixed-nonce"));
}

#[test]
fn an_idle_connection_expires_while_the_current_thread_runtime_is_paused() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        read_request(&mut first);
        first
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .unwrap();
        // Keep the old connection open: only expiration can force checkout
        // onto the second connection, even with no runtime driving idle tasks.
        let (mut second, _) = listener.accept().unwrap();
        read_request(&mut second);
        second.write_all(&response("200 OK", &[], b"new")).unwrap();
        drop(first);
    });
    let http = NativeHttp::new()
        .unwrap()
        .with_timeout(Duration::from_secs(2));
    let url = format!("http://{address}/");
    assert_eq!(send(&http, &url, 1024).unwrap().body(), b"ok");
    std::thread::sleep(Duration::from_millis(10_100));
    assert_eq!(send(&http, &url, 1024).unwrap().body(), b"new");
    server.join().unwrap();
}

#[test]
fn a_content_encoding_list_is_refused() {
    let url = respond_once(
        response("200 OK", &[("content-encoding", "gzip, identity")], b"x"),
        false,
    );
    let http = NativeHttp::new().unwrap();

    let err = send(&http, &url, 1024).unwrap_err();

    assert!(err.contains("gzip only"), "{err}");
}

#[test]
fn a_connection_failure_keeps_its_cause() {
    // Nothing listens on the port: the message must say why, not just
    // "client error (Connect)".
    let http = NativeHttp::new().unwrap();

    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let err = send(&http, &format!("http://127.0.0.1:{closed}/"), 1024).unwrap_err();

    assert!(err.starts_with("request failed: "), "{err}");
    assert!(
        err.matches(": ").count() >= 2 && !err.ends_with("client error (Connect)"),
        "the cause is missing: {err}"
    );
}

#[test]
fn supplied_headers_survive_on_the_wire() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_request(&mut stream);
        stream.write_all(&response("200 OK", &[], b"ok")).unwrap();
        String::from_utf8(request).unwrap()
    });
    let http = NativeHttp::new().unwrap();
    let request = Request::post(format!("http://{addr}/"))
        .header("user-agent", "observer-agent")
        .header("accept-encoding", "gzip;q=0.8, identity;q=0.2")
        .body(Vec::new())
        .unwrap();
    http.block_on(http.send(request, 1024)).unwrap();
    let wire = server.join().unwrap();
    assert!(wire.contains("user-agent: observer-agent\r\n"), "{wire}");
    assert!(
        wire.contains("accept-encoding: gzip;q=0.8, identity;q=0.2\r\n"),
        "{wire}"
    );
}

#[test]
fn unsupported_negotiation_is_a_typed_refusal_before_connecting() {
    use mkit_sync::NativeHttpError;
    let http = NativeHttp::new().unwrap();
    for value in [
        "br",
        "gzip, zstd",
        "gzip, br;q=0",
        "*",
        "gzip;q=2",
        "gzip;q=0.1234",
        "gzip;foo=1",
        "gzip,",
        "gzip;q=1.001",
    ] {
        let request = Request::post("http://127.0.0.1:1/")
            .header("accept-encoding", value)
            .body(Vec::new())
            .unwrap();
        assert_eq!(
            http.block_on(http.send_typed(request, 1024)).unwrap_err(),
            NativeHttpError::UnsupportedAcceptEncoding,
            "{value}"
        );
    }
    let request = Request::post("http://127.0.0.1:1/")
        .header("accept-encoding", "gzip")
        .header("accept-encoding", "br")
        .body(Vec::new())
        .unwrap();
    assert_eq!(
        http.block_on(http.send_typed(request, 1024)).unwrap_err(),
        NativeHttpError::UnsupportedAcceptEncoding
    );
}

#[test]
fn request_kind_selects_independent_timeout_budgets() {
    let http = NativeHttp::new()
        .unwrap()
        .with_metadata_timeout(Duration::from_millis(200))
        .with_transfer_timeout(Duration::from_secs(5));
    for (procedure, transfer) in [
        ("ReadRef", false),
        ("BeginUpload", false),
        ("CompleteUpload", false),
        ("UploadPack", true),
        ("UploadPart", true),
        ("DownloadPack", true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            // Send headers immediately: the timeout must include the body.
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n");
            std::thread::sleep(Duration::from_millis(500));
            let _ = stream.write_all(b"ok");
        });
        let result = send(
            &http,
            &format!("http://{addr}/mkit.transport.v1.TransportService/{procedure}"),
            1024,
        );
        if transfer {
            assert_eq!(result.unwrap().body(), b"ok", "{procedure}");
        } else {
            assert!(result.unwrap_err().contains("timed out"), "{procedure}");
        }
        server.join().unwrap();
    }
}

fn send_classified(
    http: &NativeHttp,
    url: &str,
    limit: usize,
) -> Result<http::Response<Vec<u8>>, mkit_client::ChannelError> {
    let request = Request::post(url).body(b"ping".to_vec()).unwrap();
    http.block_on(http.send_classified(request, limit))
}

#[test]
fn channel_security_and_response_refusals_are_terminal() {
    use mkit_client::ChannelError;

    let http = NativeHttp::new().unwrap();
    assert!(matches!(
        send_classified(&http, "http://203.0.113.9/", 1024),
        Err(ChannelError::Refused(_))
    ));
    let request = Request::post("http://127.0.0.1:9/")
        .header("accept-encoding", "br")
        .body(Vec::new())
        .unwrap();
    assert!(matches!(
        http.block_on(http.send_classified(request, 1024)),
        Err(ChannelError::Refused(_))
    ));
    for wire in [
        response("307 Temporary Redirect", &[("location", "/elsewhere")], b""),
        response("200 OK", &[], &vec![0; 2048]),
        b"HTTP/1.1 invalid status\r\n\r\n".to_vec(),
        response("200 OK", &[("content-encoding", "br")], b"x"),
        response("200 OK", &[("content-encoding", "gzip")], b"invalid gzip"),
        response(
            "200 OK",
            &[("content-encoding", "gzip")],
            &gzip(&vec![0; 8192]),
        ),
    ] {
        let url = respond_once(wire, false);
        assert!(matches!(
            send_classified(&http, &url, 1024),
            Err(ChannelError::Refused(_))
        ));
    }
}

#[test]
fn actual_connection_and_response_body_io_failures_are_transient() {
    use mkit_client::ChannelError;

    let http = NativeHttp::new().unwrap();
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    assert!(matches!(
        send_classified(&http, &format!("http://{closed}/"), 1024),
        Err(ChannelError::Transient(_))
    ));
    let url = respond_once(
        b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\nshort".to_vec(),
        false,
    );
    assert!(matches!(
        send_classified(&http, &url, 1024),
        Err(ChannelError::Transient(_))
    ));
}

#[test]
fn actual_response_timeout_preserves_terminal_deadline_class() {
    use mkit_client::ChannelError;

    let url = respond_once(
        b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n".to_vec(),
        true,
    );
    let http = NativeHttp::new()
        .unwrap()
        .with_timeout(Duration::from_millis(100));
    assert!(matches!(
        send_classified(&http, &url, 1024),
        Err(ChannelError::TimedOut(cause)) if cause == "client-side deadline exceeded"
    ));
}

struct StreamingBody(std::vec::IntoIter<Vec<u8>>);
impl mkit_client::RequestStream for StreamingBody {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, mkit_client::Error> {
        Ok(self.0.next())
    }
}

#[derive(Default)]
struct StreamingReply {
    bytes: Vec<u8>,
    largest_chunk: usize,
    first_chunk: Option<std::sync::mpsc::Sender<()>>,
}
impl mkit_client::ResponseStream for StreamingReply {
    fn start(&mut self, response: http::Response<()>) -> Result<(), mkit_client::Error> {
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("content-encoding").is_none());
        Ok(())
    }
    fn chunk(&mut self, bytes: &[u8]) -> Result<(), mkit_client::Error> {
        if !bytes.is_empty()
            && let Some(sender) = self.first_chunk.take()
        {
            sender.send(()).unwrap();
        }
        self.largest_chunk = self.largest_chunk.max(bytes.len());
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn finish(&mut self) -> Result<(), mkit_client::Error> {
        Ok(())
    }
}

fn read_chunked_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::BufRead as _;
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        assert_ne!(line, "");
    }
    let mut body = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).unwrap();
        let size = usize::from_str_radix(line.trim(), 16).unwrap();
        if size == 0 {
            reader.read_line(&mut String::new()).unwrap();
            return body;
        }
        let offset = body.len();
        body.resize(offset + size, 0);
        reader.read_exact(&mut body[offset..]).unwrap();
        let mut end = [0; 2];
        reader.read_exact(&mut end).unwrap();
        assert_eq!(&end, b"\r\n");
    }
}

#[test]
fn streaming_upload_delivers_each_pulled_chunk_without_changing_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let body = read_chunked_request(&mut socket);
        socket.write_all(&response("200 OK", &[], b"done")).unwrap();
        body
    });
    let http = NativeHttp::new().unwrap();
    let mut body = StreamingBody(vec![vec![1; 8192], vec![2; 8192], vec![3; 8192]].into_iter());
    let request = Request::post(format!("http://{address}/"))
        .body(())
        .unwrap();
    let mut reply = StreamingReply::default();
    http.block_on(http.send_stream(request, &mut body, 1024, &mut reply))
        .unwrap();
    assert_eq!(reply.bytes, b"done");
    assert_eq!(
        server.join().unwrap(),
        [vec![1; 8192], vec![2; 8192], vec![3; 8192]].concat()
    );
}

#[test]
fn a_streamed_signed_write_survives_an_idle_close_without_changing_its_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (closed_tx, closed_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        read_request(&mut first);
        first
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
            .unwrap();
        drop(first);
        closed_tx.send(()).unwrap();
        let (mut second, _) = listener.accept().unwrap();
        let bytes = read_chunked_request(&mut second);
        second.write_all(&response("200 OK", &[], b"done")).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(listener.accept().is_err(), "streamed request was replayed");
        bytes
    });
    let http = NativeHttp::new()
        .unwrap()
        .with_timeout(Duration::from_secs(2));
    assert_eq!(
        send(&http, &format!("http://{address}/"), 1024)
            .unwrap()
            .body(),
        b"ok"
    );
    // The owned current-thread runtime is paused while the server closes.
    closed_rx.recv().unwrap();
    let chunks = vec![vec![1; 8192], vec![2; 8192], vec![3; 8192]];
    let mut body = StreamingBody(chunks.clone().into_iter());
    let request = Request::post(format!(
        "http://{address}/mkit.transport.v1.TransportService/UploadPack"
    ))
    .header("x-signature", "fixed-signature")
    .header("idempotency-key", "fixed-nonce")
    .body(())
    .unwrap();
    let mut reply = StreamingReply::default();
    http.block_on(http.send_stream(request, &mut body, 1024, &mut reply))
        .unwrap();
    assert_eq!(reply.bytes, b"done");
    assert_eq!(server.join().unwrap(), chunks.concat());
}

#[test]
fn a_partial_response_does_not_contaminate_the_next_exchange() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        read_request(&mut first);
        first
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\nshort")
            .unwrap();
        drop(first);
        let (mut second, _) = listener.accept().unwrap();
        read_request(&mut second);
        second
            .write_all(&response("200 OK", &[], b"clean"))
            .unwrap();
    });
    let http = NativeHttp::new()
        .unwrap()
        .with_timeout(Duration::from_secs(2));
    let url = format!("http://{address}/");
    assert!(send(&http, &url, 1024).is_err());
    assert_eq!(send(&http, &url, 1024).unwrap().body(), b"clean");
    server.join().unwrap();
}

#[test]
fn streaming_response_is_delivered_before_the_server_finishes_sending() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        read_chunked_request(&mut socket);
        socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8192\r\nconnection: close\r\n\r\n")
            .unwrap();
        socket.write_all(&vec![1; 4096]).unwrap();
        socket.flush().unwrap();
        let observed = receiver.recv_timeout(Duration::from_secs(10)).is_ok();
        socket.write_all(&vec![2; 4096]).unwrap();
        observed
    });
    let http = NativeHttp::new().unwrap();
    let request = Request::post(format!("http://{address}/"))
        .body(())
        .unwrap();
    let mut body = StreamingBody(vec![b"request".to_vec()].into_iter());
    let mut reply = StreamingReply {
        first_chunk: Some(sender),
        ..Default::default()
    };
    http.block_on(http.send_stream(request, &mut body, 8192, &mut reply))
        .unwrap();
    assert!(
        server.join().unwrap(),
        "response was buffered before delivery"
    );
    assert_eq!(reply.bytes, [vec![1; 4096], vec![2; 4096]].concat());
}

#[test]
fn streaming_gzip_is_incremental_and_enforces_both_bounds_and_checksum() {
    for kind in ["valid", "inflated limit", "wire limit", "checksum"] {
        let data = vec![7; 128 * 1024];
        let mut compressed = gzip(&data);
        if kind == "checksum" {
            let last = compressed.len() - 1;
            compressed[last] ^= 1;
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            read_chunked_request(&mut socket);
            let _ = socket.write_all(&response(
                "200 OK",
                &[("content-encoding", "gzip")],
                &compressed,
            ));
        });
        let http = NativeHttp::new().unwrap();
        let request = Request::post(format!("http://{address}/"))
            .body(())
            .unwrap();
        let mut body = StreamingBody(vec![b"request".to_vec()].into_iter());
        let mut reply = StreamingReply::default();
        let limit = match kind {
            "inflated limit" => 4096,
            "wire limit" => 16,
            _ => data.len(),
        };
        let result = http.block_on(http.send_stream(request, &mut body, limit, &mut reply));
        if kind == "valid" {
            result.unwrap();
            assert_eq!(reply.bytes, data);
            assert!(reply.largest_chunk < data.len());
        } else {
            assert!(matches!(result, Err(mkit_client::Error::Transport(_))));
        }
        server.join().unwrap();
    }
}

#[test]
fn native_host_header_defaults_reach_requests_and_preserve_explicit_values() {
    let mut defaults = http::HeaderMap::new();
    defaults.insert("authorization", "Bearer default".parse().unwrap());
    let http = NativeHttp::new().unwrap().with_default_headers(defaults);
    for explicit in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let request = read_request(&mut socket);
            socket.write_all(&response("200 OK", &[], b"ok")).unwrap();
            String::from_utf8(request).unwrap()
        });
        let mut request = Request::post(format!("http://{address}/"))
            .body(Vec::new())
            .unwrap();
        if explicit {
            request
                .headers_mut()
                .insert("authorization", "Bearer explicit".parse().unwrap());
        }
        http.block_on(http.send(request, 1024)).unwrap();
        let wire = server.join().unwrap();
        assert!(wire.contains(if explicit {
            "authorization: Bearer explicit\r\n"
        } else {
            "authorization: Bearer default\r\n"
        }));
    }
}

#[test]
fn request_timeout_extension_shortens_buffered_and_streaming_exchange_budgets() {
    for streaming in [false, true] {
        let url = respond_once(
            b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n".to_vec(),
            true,
        );
        let http = NativeHttp::new()
            .unwrap()
            .with_timeout(Duration::from_secs(30));
        let elapsed = std::time::Instant::now();
        let result = if streaming {
            let mut request = Request::post(url).body(()).unwrap();
            request
                .extensions_mut()
                .insert(mkit_client::RequestTimeout(Duration::from_millis(100)));
            let mut body = StreamingBody(vec![b"request".to_vec()].into_iter());
            let mut reply = StreamingReply::default();
            http.block_on(http.send_stream(request, &mut body, 1024, &mut reply))
        } else {
            let mut request = Request::post(url).body(b"request".to_vec()).unwrap();
            request
                .extensions_mut()
                .insert(mkit_client::RequestTimeout(Duration::from_millis(100)));
            http.block_on(http.send_classified(request, 1024))
                .map(|_| ())
                .map_err(|error| match error {
                    mkit_client::ChannelError::Transient(cause) => {
                        mkit_client::Error::Connection(cause)
                    }
                    mkit_client::ChannelError::TimedOut(cause) => {
                        mkit_client::Error::RequestTimeout(cause)
                    }
                    other => mkit_client::Error::Transport(other.to_string()),
                })
        };
        assert!(
            matches!(result, Err(mkit_client::Error::RequestTimeout(cause)) if cause == "client-side deadline exceeded")
        );
        assert!(elapsed.elapsed() < Duration::from_secs(3));
    }
}

#[test]
fn an_early_admission_reply_keeps_its_typed_challenge_after_upload_receiver_closes() {
    use mkit_client::{Client, Destination, Error, RequestStream, ResponseStream};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct InfiniteBody<'a>(&'a AtomicUsize);
    impl RequestStream for InfiniteBody<'_> {
        fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, Error> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(Some(vec![0; 1024 * 1024]))
        }
    }
    struct InfiniteChannel<'a> {
        http: &'a NativeHttp,
        produced: AtomicUsize,
    }
    impl HttpTransport for InfiniteChannel<'_> {
        async fn send(
            &self,
            request: Request<Vec<u8>>,
            limit: usize,
        ) -> Result<http::Response<Vec<u8>>, String> {
            self.http.send(request, limit).await
        }
        async fn send_stream<B: RequestStream + ?Sized, S: ResponseStream + ?Sized>(
            &self,
            request: Request<()>,
            _: &mut B,
            limit: usize,
            sink: &mut S,
        ) -> Result<(), Error> {
            self.http
                .send_stream(request, &mut InfiniteBody(&self.produced), limit, sink)
                .await
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (finished_sender, finished_receiver) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        // Read the request head only; admission happens before body consumption.
        read_request(&mut socket);
        let error = br#"{"code":"permission_denied","message":"admission"}"#;
        socket.write_all(format!(
            "HTTP/1.1 402 Payment Required\r\ncontent-length: {}\r\nwww-authenticate: test challenge\r\nconnection: close\r\n\r\n",
            error.len()
        ).as_bytes()).unwrap();
        socket.flush().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        socket.write_all(error).unwrap();
        socket.flush().unwrap();
        // Keep the socket alive until the client decodes the response, avoiding
        // a TCP reset caused by closing with unread upload bytes.
        finished_receiver
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
    });
    let http = NativeHttp::new()
        .unwrap()
        .with_timeout(Duration::from_secs(3));
    let channel = InfiniteChannel {
        http: &http,
        produced: AtomicUsize::new(0),
    };
    let destination = Destination::new(format!("http://{address}"), "default".to_owned()).unwrap();
    let client = Client::anonymous(&channel, destination).with_unsigned_writes();
    let key = mkit_core::pack::pack_key(b"pack");
    let result = http.block_on(client.upload_pack(&key, b"pack", None, None));
    finished_sender.send(()).unwrap();
    server.join().unwrap();
    assert!(
        matches!(result, Err(Error::PaymentRequired(required)) if required.www_authenticate == ["test challenge"])
    );
    assert!(
        channel.produced.load(Ordering::Relaxed) < 64,
        "producer was not bounded by backpressure"
    );
}

type CapturedNativeFailure = (
    mkit_client::FailureKind,
    u16,
    String,
    Vec<u8>,
    Option<String>,
);
#[derive(Default)]
struct FailureCapture(std::cell::RefCell<Vec<CapturedNativeFailure>>);
impl mkit_client::FailureObserver for FailureCapture {
    fn map_failure(
        &self,
        failure: &mkit_client::FailureDiagnostic<'_>,
    ) -> Option<mkit_client::Error> {
        self.0.borrow_mut().push((
            failure.kind,
            failure.status.map_or(0, |status| status.as_u16()),
            failure.cause.to_owned(),
            failure.body.unwrap_or_default().to_vec(),
            failure
                .headers
                .and_then(|headers| headers.get("content-encoding"))
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        ));
        Some(mkit_client::Error::Transport(
            "mapped native failure".to_owned(),
        ))
    }
}

#[test]
fn diagnosed_coding_failure_preserves_status_headers_and_bounded_wire_body() {
    let url = respond_once(
        response("200 OK", &[("content-encoding", "br")], b"wire"),
        false,
    );
    let http = NativeHttp::new().unwrap();
    let observer = FailureCapture::default();
    let request = Request::post(url).body(Vec::new()).unwrap();
    let result = http.block_on(http.send_diagnosed(request, 16, &observer));
    assert!(
        matches!(result, Err(mkit_client::Error::Transport(message)) if message == "mapped native failure")
    );
    let failures = observer.0.borrow();
    assert_eq!(
        failures.as_slice(),
        &[(
            mkit_client::FailureKind::Coding,
            200,
            "br".to_owned(),
            b"wire".to_vec(),
            Some("br".to_owned())
        )]
    );
}

#[test]
fn diagnosed_body_io_has_a_typed_cause_without_the_native_display_prefix() {
    let url = respond_once(
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhi".to_vec(),
        false,
    );
    let http = NativeHttp::new().unwrap();
    let observer = FailureCapture::default();
    let result = http.block_on(http.send_diagnosed(
        Request::post(url).body(Vec::new()).unwrap(),
        16,
        &observer,
    ));
    assert!(matches!(result, Err(mkit_client::Error::Transport(_))));
    let failures = observer.0.borrow();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, mkit_client::FailureKind::BodyIo);
    assert_eq!(failures[0].1, 200);
    assert!(!failures[0].2.starts_with("response body:"));
    assert_ne!(failures[0].2, "");
}

#[test]
fn timeout_advertisement_is_opt_in_and_uses_the_clamped_budget() {
    for advertise in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            sender.send(read_request(&mut stream)).unwrap();
            stream.write_all(&response("200 OK", &[], b"ok")).unwrap();
        });
        let http = NativeHttp::new()
            .unwrap()
            .with_timeout(Duration::from_secs(10));
        let mut request = Request::post(format!("http://{address}/"))
            .body(Vec::new())
            .unwrap();
        request
            .extensions_mut()
            .insert(mkit_client::RequestTimeout(Duration::from_micros(
                1_234_567,
            )));
        if advertise {
            request
                .extensions_mut()
                .insert(mkit_client::AdvertiseRequestTimeout);
        }
        http.block_on(http.send(request, 16)).unwrap();
        let request = String::from_utf8(receiver.recv_timeout(Duration::from_secs(2)).unwrap())
            .unwrap()
            .to_ascii_lowercase();
        assert_eq!(request.contains("connect-timeout-ms: 1234\r\n"), advertise);
        server.join().unwrap();
    }
}

#[test]
fn diagnosed_wire_limit_never_exposes_more_than_the_selected_budget() {
    let url = respond_once(response("200 OK", &[], &[0; 17]), false);
    let http = NativeHttp::new().unwrap();
    let observer = FailureCapture::default();
    let result = http.block_on(http.send_diagnosed(
        Request::post(url).body(Vec::new()).unwrap(),
        16,
        &observer,
    ));
    assert!(matches!(result, Err(mkit_client::Error::Transport(_))));
    let failures = observer.0.borrow();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].0, mkit_client::FailureKind::WireLimit);
    assert_eq!(failures[0].1, 200);
    assert!(failures[0].3.len() <= 16);
}

#[test]
fn concrete_native_exchange_futures_retain_conditional_send() {
    fn assert_send<T: Send>(_: T) {}
    struct Diagnostics;
    impl mkit_client::FailureObserver for Diagnostics {}
    let http = NativeHttp::new().unwrap();
    let request = || {
        Request::post("http://127.0.0.1:1/")
            .body(Vec::new())
            .unwrap()
    };
    assert_send(http.send_typed(request(), 1024));
    assert_send(http.send(request(), 1024));
    assert_send(http.send_diagnosed(request(), 1024, &Diagnostics));
    let mut body = StreamingBody(Vec::new().into_iter());
    let mut sink = StreamingReply::default();
    assert_send(http.send_stream(
        Request::post("http://127.0.0.1:1/").body(()).unwrap(),
        &mut body,
        1024,
        &mut sink,
    ));
    assert_send(http.send_stream_diagnosed(
        Request::post("http://127.0.0.1:1/").body(()).unwrap(),
        &mut body,
        1024,
        &mut sink,
        &Diagnostics,
    ));
}

#[test]
fn explicitly_erased_local_stream_callbacks_remain_supported() {
    struct LocalBody(std::rc::Rc<()>);
    impl mkit_client::RequestStream for LocalBody {
        fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, mkit_client::Error> {
            assert_eq!(std::rc::Rc::strong_count(&self.0), 1);
            Ok(None)
        }
    }
    struct LocalSink(std::rc::Rc<()>);
    impl mkit_client::ResponseStream for LocalSink {
        fn start(&mut self, _: http::Response<()>) -> Result<(), mkit_client::Error> {
            Ok(())
        }
        fn chunk(&mut self, _: &[u8]) -> Result<(), mkit_client::Error> {
            Ok(())
        }
        fn finish(&mut self) -> Result<(), mkit_client::Error> {
            assert_eq!(std::rc::Rc::strong_count(&self.0), 1);
            Ok(())
        }
    }
    let http = NativeHttp::new().unwrap();
    let mut body = LocalBody(std::rc::Rc::new(()));
    let mut sink = LocalSink(std::rc::Rc::new(()));
    let diagnostics = FailureCapture::default();
    let body: &mut dyn mkit_client::RequestStream = &mut body;
    let sink: &mut dyn mkit_client::ResponseStream = &mut sink;
    let diagnostics: &dyn mkit_client::FailureObserver = &diagnostics;
    drop(http.send_stream_diagnosed(
        Request::post("http://127.0.0.1:1/").body(()).unwrap(),
        body,
        1024,
        sink,
        diagnostics,
    ));
}
