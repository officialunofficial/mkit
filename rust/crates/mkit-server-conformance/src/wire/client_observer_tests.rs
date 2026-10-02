use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;

use super::*;
use crate::wire::sign::Signer;

struct RequestCapture {
    bytes: Vec<u8>,
    server: SocketAddr,
    client: SocketAddr,
}

fn request(stream: &mut TcpStream) -> Vec<u8> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut buffer = [0; 4096];
    let (header_end, length) = loop {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0, "request headers ended early");
        bytes.extend_from_slice(&buffer[..count]);
        if let Some(end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).unwrap();
            let length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while bytes.len() < header_end + length {
        let count = stream.read(&mut buffer).unwrap();
        assert_ne!(count, 0, "request body ended early");
        bytes.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(bytes.len(), header_end + length);
    bytes
}

fn server(
    responses: Vec<Vec<u8>>,
    persistent: bool,
) -> (Url, thread::JoinHandle<Vec<RequestCapture>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut stream = None;
        let mut requests = Vec::new();
        for response in responses {
            if stream.is_none() {
                stream = Some(listener.accept().unwrap().0);
            }
            let active = stream.as_mut().unwrap();
            requests.push(RequestCapture {
                bytes: request(active),
                server: active.local_addr().unwrap(),
                client: active.peer_addr().unwrap(),
            });
            active.write_all(&response).unwrap();
            if !persistent {
                stream = None;
            }
        }
        requests
    });
    (Url::parse(&format!("http://{address}")).unwrap(), handle)
}

fn fixed(status: u16, body: &[u8], headers: &str) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{headers}\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn client(base: &Url, file: Option<File>) -> Client {
    let mut client = Client::new(base).unwrap();
    client.http_trace = file.map(Arc::new);
    client
}

fn file() -> tempfile::NamedTempFile {
    tempfile::NamedTempFile::new().unwrap()
}

fn records(file: &tempfile::NamedTempFile) -> Vec<serde_json::Value> {
    std::fs::read_to_string(file.path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn header<'a>(record: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    &record["response"]["headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|pair| pair[0] == name)
        .unwrap()[1]
}

fn tuple_matches(record: &serde_json::Value, request: &RequestCapture) {
    assert_eq!(
        record["response"]["outer_tcp"][0],
        request.client.to_string()
    );
    assert_eq!(
        record["response"]["outer_tcp"][1],
        request.server.to_string()
    );
}

#[tokio::test]
async fn observer_preserves_actual_signed_request_bytes_reply_and_filters_secrets() {
    let payload = b"private-request-body";
    let response = b"private-response-body";
    let signed = Signer::new(
        [0x31; 32],
        "https://vcs.launch.invalid",
        "fixture-repository",
    )
    .sign_body(Rpc::SetRepoVisibility.procedure(), payload);
    let secret_headers = format!(
        "Authorization: private-auth\r\nProxy-Authorization: private-proxy\r\nX-Reflected-Signature: {}\r\nContent-Type: {}\r\n",
        signed
            .headers
            .iter()
            .find(|(name, _)| name == "x-signature")
            .unwrap()
            .1,
        "z".repeat(300)
    );
    let reply = fixed(200, response, &secret_headers);
    let (base, server) = server(vec![reply.clone(), reply], false);
    let trace = file();
    let off = client(&base, None)
        .post(
            Rpc::SetRepoVisibility.procedure(),
            UNARY_PROTO,
            &signed.headers,
            payload.to_vec(),
        )
        .await
        .unwrap();
    let on = client(&base, Some(trace.as_file().try_clone().unwrap()))
        .post(
            Rpc::SetRepoVisibility.procedure(),
            UNARY_PROTO,
            &signed.headers,
            payload.to_vec(),
        )
        .await
        .unwrap();
    let captured = server.join().unwrap();
    assert_eq!(captured[0].bytes, captured[1].bytes);
    assert_eq!(on.status, off.status);
    assert_eq!(on.headers, off.headers);
    assert_eq!(on.body, off.body);
    assert_eq!(on.body.as_ref(), response);
    let observed = records(&trace);
    assert_eq!(observed.len(), 1);
    tuple_matches(&observed[0], &captured[1]);
    assert_eq!(observed[0]["response"]["version"], "HTTP/1.1");
    assert_eq!(
        header(&observed[0], "content-type")["value"]
            .as_str()
            .unwrap()
            .len(),
        128
    );
    assert_eq!(header(&observed[0], "content-type")["truncated"], true);
    assert!(header(&observed[0], "content-encoding").is_null());
    assert_eq!(
        observed[0]["collect_eof_upper_bound"]["bytes"],
        response.len()
    );
    assert_eq!(observed[0]["decode_complete"]["bytes"], response.len());
    let serialized = std::fs::read_to_string(trace.path()).unwrap();
    for forbidden in [
        "private-auth",
        "private-proxy",
        "private-request-body",
        "private-response-body",
        "x-signature",
        "idempotency-key",
        "fixture-repository",
        &signed.nonce,
    ] {
        assert!(
            !serialized.contains(forbidden),
            "trace disclosed {forbidden}"
        );
    }
    assert!(serialized.len() < 2048);
}

#[tokio::test]
async fn observer_records_chunked_gzip_and_http500_without_changing_reply() {
    let chunked = b"HTTP/1.1 200 Fixture\r\nTransfer-Encoding: chunked\r\nContent-Type: application/proto\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n".to_vec();
    let mut compressed = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    compressed.write_all(b"decoded-gzip-body").unwrap();
    let compressed = compressed.finish().unwrap();
    let gzip = fixed(200, &compressed, "Content-Encoding: gzip\r\n");
    let error = fixed(
        500,
        b"private-error-body",
        "X-Proxy-Secret: private-proxy\r\n",
    );
    let (base, server) = server(vec![chunked, gzip, error], false);
    let trace = file();
    let client = client(&base, Some(trace.as_file().try_clone().unwrap()));
    assert_eq!(
        client.get("/chunked").await.unwrap().body.as_ref(),
        b"abcde"
    );
    let gzip_reply = client.get("/gzip").await.unwrap();
    assert_eq!(gzip_reply.body.as_ref(), b"decoded-gzip-body");
    assert!(!gzip_reply.headers.contains_key("content-encoding"));
    let error_reply = client.get("/error").await.unwrap();
    assert_eq!(error_reply.status, 500);
    assert_eq!(error_reply.body.as_ref(), b"private-error-body");
    let captured = server.join().unwrap();
    let observed = records(&trace);
    assert_eq!(observed.len(), 3);
    assert_eq!(
        header(&observed[0], "transfer-encoding")["value"],
        "chunked"
    );
    assert_eq!(observed[0]["collect_eof_upper_bound"]["bytes"], 5);
    assert_eq!(header(&observed[1], "content-encoding")["value"], "gzip");
    assert_eq!(
        observed[1]["collect_eof_upper_bound"]["bytes"],
        compressed.len()
    );
    assert_eq!(observed[1]["decode_complete"]["bytes"], 17);
    assert_eq!(observed[2]["response"]["status"], 500);
    assert_eq!(observed[2]["outcome"], "reply");
    for (record, request) in observed.iter().zip(&captured) {
        tuple_matches(record, request);
        let arrival = record["response_arrival"]["ms"].as_u64().unwrap();
        let eof = record["collect_eof_upper_bound"]["ms"].as_u64().unwrap();
        let decoded = record["decode_complete"]["ms"].as_u64().unwrap();
        assert!(
            arrival <= eof && eof <= decoded && decoded <= record["result_ms"].as_u64().unwrap()
        );
    }
    assert_ne!(captured[0].client, captured[1].client);
    assert_ne!(
        observed[0]["response"]["outer_tcp"],
        observed[1]["response"]["outer_tcp"]
    );
    let serialized = std::fs::read_to_string(trace.path()).unwrap();
    assert!(!serialized.contains("private-error-body") && !serialized.contains("private-proxy"));
}

#[tokio::test]
async fn incomplete_body_error_is_unchanged_and_has_no_invented_eof() {
    let response = b"HTTP/1.1 200 Fixture\r\nContent-Length: 5\r\n\r\nab".to_vec();
    let (base, server) = server(vec![response.clone(), response], false);
    let trace = file();
    let off = client(&base, None).get("/incomplete").await.unwrap_err();
    let on = client(&base, Some(trace.as_file().try_clone().unwrap()))
        .get("/incomplete")
        .await
        .unwrap_err();
    let captured = server.join().unwrap();
    assert_eq!(on, off);
    let observed = records(&trace);
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0]["phase"], "response_arrival");
    assert_eq!(observed[0]["outcome"], "error");
    assert!(observed[0].get("collect_eof_upper_bound").is_none());
    assert!(observed[0].get("decode_complete").is_none());
    tuple_matches(&observed[0], &captured[1]);
    let serialized = std::fs::read_to_string(trace.path()).unwrap();
    assert!(!serialized.contains(&on));
}

#[tokio::test]
async fn observer_sink_failure_does_not_replace_original_result() {
    let (base, server) = server(vec![fixed(200, b"ok", "")], false);
    let trace = file();
    let read_only = File::open(trace.path()).unwrap();
    let reply = client(&base, Some(read_only))
        .get("/sink-failure")
        .await
        .unwrap();
    assert_eq!(reply.body.as_ref(), b"ok");
    server.join().unwrap();
    assert!(std::fs::read(trace.path()).unwrap().is_empty());
}

#[test]
fn missing_socket_metadata_stays_unknown_and_non_ascii_header_has_no_unbounded_copy() {
    let response = http::Response::builder()
        .header(
            "content-type",
            http::HeaderValue::from_bytes(&[0xff]).unwrap(),
        )
        .body(())
        .unwrap();
    let (parts, ()) = response.into_parts();
    let mut observed = Some((Instant::now(), serde_json::json!({"phase":"send"})));
    observe_response(&mut observed, &parts);
    let (_, record) = observed.unwrap();
    assert!(record["response"]["outer_tcp"].is_null());
    assert!(header(&record, "content-type")["value"].is_null());
    assert_eq!(header(&record, "content-type")["truncated"], false);
}
