//! Real sockets: close a used connection after reading the next request.
use bytes::Bytes;
use connectrpc::client::{ClientBody, ClientTransport, HttpClient, full_body};
use http::{Request, Response};
use http_body_util::BodyExt as _;
use mkit_transport_connect::pooled_http::PooledHttpClient;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let end = loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        data.push(byte[0]);
        if data.ends_with(b"\r\n\r\n") {
            break data.len();
        }
        assert!(data.len() < 65536);
    };
    let headers = String::from_utf8_lossy(&data);
    let len: usize = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(|s| s.parse().unwrap())
        })
        .unwrap_or(0);
    data.resize(end + len, 0);
    stream.read_exact(&mut data[end..]).await.unwrap();
    data
}
async fn answer(stream: &mut TcpStream) {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/proto\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await
        .unwrap();
}
fn request(origin: &str, method: &str, content_type: &str, signed: bool) -> Request<ClientBody> {
    let mut req = Request::post(format!(
        "{origin}/mkit.transport.v1.TransportService/{method}"
    ))
    .header("content-type", content_type);
    if signed {
        req = req
            .header("x-envelope-version", "2")
            .header("idempotency-key", "same-nonce")
            .header("x-signature", "same-signature");
    }
    req.body(full_body(Bytes::from_static(b"body"))).unwrap()
}
async fn consume<B: http_body_util::BodyExt>(response: Response<B>) {
    assert_eq!(response.status(), 200);
    assert!(response.into_body().collect().await.is_ok());
}
async fn exercise<T: ClientTransport>(
    client: T,
    method: &str,
    ct: &str,
    signed: bool,
    partial: &[u8],
    retry_reply: bool,
    expect_retry: bool,
) where
    T::Error: std::fmt::Debug,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let partial = partial.to_vec();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        read_request(&mut first).await;
        answer(&mut first).await;
        let lost = read_request(&mut first).await;
        if !partial.is_empty() {
            first.write_all(&partial).await.unwrap();
        }
        drop(first);
        let second =
            tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept()).await;
        if expect_retry {
            let (mut second, _) = second.unwrap().unwrap();
            let repeated = read_request(&mut second).await;
            assert_eq!(lost, repeated, "retry changed signed envelope or body");
            if retry_reply {
                answer(&mut second).await;
            }
            drop(second);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                    .await
                    .is_err(),
                "third attempt"
            );
        } else {
            assert!(second.is_err(), "unexpected replay");
        }
    });
    consume(
        client
            .send(request(&origin, "ReadRef", "application/proto", false))
            .await
            .unwrap(),
    )
    .await;
    let result = client.send(request(&origin, method, ct, signed)).await;
    if expect_retry && retry_reply {
        consume(result.unwrap()).await;
    } else {
        assert!(result.is_err());
    }
    server.await.unwrap();
}
#[tokio::test]
async fn control_stock_client_fails_on_used_connection() {
    exercise(
        HttpClient::plaintext(),
        "ReadRef",
        "application/proto",
        false,
        b"",
        true,
        false,
    )
    .await;
}
#[tokio::test]
async fn retries_read_once_on_fresh_connection() {
    exercise(
        PooledHttpClient::plaintext(),
        "ReadRef",
        "application/proto",
        false,
        b"",
        true,
        true,
    )
    .await;
}
#[tokio::test]
async fn retries_identical_auth_v2_write() {
    exercise(
        PooledHttpClient::plaintext(),
        "AdvanceRefs",
        "application/proto",
        true,
        b"",
        true,
        true,
    )
    .await;
}
#[tokio::test]
async fn never_retries_partial_headers() {
    exercise(
        PooledHttpClient::plaintext(),
        "ReadRef",
        "application/proto",
        false,
        b"HTTP/1.1 200",
        true,
        false,
    )
    .await;
}
#[tokio::test]
async fn streaming_upload_uses_fresh_socket_and_never_replays_mid_body() {
    use connectrpc::ConnectError;
    use futures::StreamExt as _;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut warm, _) = listener.accept().await.unwrap();
        read_request(&mut warm).await;
        answer(&mut warm).await;
        let (mut streamed, _) = listener.accept().await.unwrap();
        read_request(&mut streamed).await;
        let mut first = [0; 12];
        streamed.read_exact(&mut first).await.unwrap();
        drop(streamed);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                .await
                .is_err(),
            "stream replayed"
        );
        drop(warm);
    });
    let client = PooledHttpClient::plaintext();
    consume(
        client
            .send(request(&origin, "ReadRef", "application/proto", false))
            .await
            .unwrap(),
    )
    .await;
    let first = futures::stream::once(async {
        Ok::<_, ConnectError>(hyper::body::Frame::data(Bytes::from_static(b"first-frame")))
    });
    let rest = futures::stream::once(async {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Ok::<_, ConnectError>(hyper::body::Frame::data(Bytes::from_static(b"last-frame")))
    });
    let body = http_body_util::BodyExt::boxed(http_body_util::StreamBody::new(first.chain(rest)));
    let req = Request::post(format!(
        "{origin}/mkit.transport.v1.TransportService/UploadPart"
    ))
    .header("content-type", "application/connect+proto")
    .body(body)
    .unwrap();
    assert!(client.send(req).await.is_err());
    server.await.unwrap();
}
#[tokio::test]
async fn never_retries_unsigned_write() {
    exercise(
        PooledHttpClient::plaintext(),
        "UpdateRef",
        "application/proto",
        false,
        b"",
        true,
        false,
    )
    .await;
}
#[tokio::test]
async fn fresh_failure_is_not_retried_again() {
    exercise(
        PooledHttpClient::plaintext(),
        "ReadRef",
        "application/proto",
        false,
        b"",
        false,
        true,
    )
    .await;
}

#[tokio::test]
async fn first_connection_failure_is_not_retried() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        drop(socket);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                .await
                .is_err()
        );
    });
    assert!(
        PooledHttpClient::plaintext()
            .send(request(&origin, "ReadRef", "application/proto", false))
            .await
            .is_err()
    );
    server.await.unwrap();
}
#[tokio::test]
async fn partial_body_and_http_500_are_not_retried() {
    for response in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\npartial"[..],
        &b"HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n"[..],
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request(&mut socket).await;
            answer(&mut socket).await;
            read_request(&mut socket).await;
            socket.write_all(response).await.unwrap();
            drop(socket);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                    .await
                    .is_err()
            );
        });
        let client = PooledHttpClient::plaintext();
        consume(
            client
                .send(request(&origin, "ReadRef", "application/proto", false))
                .await
                .unwrap(),
        )
        .await;
        let reply = client
            .send(request(&origin, "ReadRef", "application/proto", false))
            .await
            .unwrap();
        if reply.status() == 200 {
            assert!(reply.into_body().collect().await.is_err());
        } else {
            assert_eq!(reply.status(), 500);
        }
        server.await.unwrap();
    }
}
