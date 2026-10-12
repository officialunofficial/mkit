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

/// Serve exactly one canned HTTP response, then close. Returns the base URL.
fn respond_once(response: Vec<u8>, stall_after_headers: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(&response);
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
