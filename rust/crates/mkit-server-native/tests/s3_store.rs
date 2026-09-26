//! `S3BlobStore` against the in-repo `FakeS3`: what it sends (conditional
//! put, ranges, `SigV4`), that nothing unverified is ever sent, retries and
//! the fallbacks, bounded memory, and the credentials' redaction. The
//! second half checks the fake itself is strict, with raw signed requests.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::sync::Arc;

use bytes::Bytes;
use futures::StreamExt as _;
use mkit_core::hash::hash;
use mkit_server::{BlobBody, BlobKey, BlobStore, ByteRange, CommitOutcome, PackSink, StoreError};
use mkit_server::{ManualClock, SystemClock};
use mkit_server_conformance::fake_s3::{DEFAULT_BUCKET, FakeS3, FakeS3Options};
use mkit_server_native::s3::{Credentials, S3BlobStore, S3Config};
use mkit_transport_s3::sigv4;
use reqwest::{Method, StatusCode};

const PREFIX: &str = "tenant/a";

fn config(fake: &FakeS3) -> S3Config {
    let opts = fake.options();
    S3Config {
        endpoint: fake.endpoint().parse().unwrap(),
        bucket: DEFAULT_BUCKET.to_owned(),
        prefix: Some(PREFIX.to_owned()),
        credentials: Credentials {
            access_key_id: opts.access_key_id.clone(),
            secret_access_key: opts.secret_access_key.clone(),
            region: opts.region.clone(),
        },
    }
}

fn store(fake: &FakeS3) -> S3BlobStore {
    S3BlobStore::new(config(fake), Arc::new(SystemClock)).unwrap()
}

fn key_of(bytes: &[u8]) -> BlobKey {
    BlobKey::new(hash(bytes))
}

fn object_key(bytes: &[u8]) -> String {
    format!("{PREFIX}/packs/{}", key_of(bytes).to_hex())
}

async fn put(s: &S3BlobStore, bytes: &[u8]) -> Result<CommitOutcome, StoreError> {
    let mut sink = s.begin(key_of(bytes), bytes.len() as u64).await?;
    sink.write(Bytes::copy_from_slice(bytes)).await?;
    sink.commit().await
}

async fn read(body: BlobBody) -> Vec<u8> {
    match body {
        BlobBody::Bytes(b) => b.to_vec(),
        BlobBody::Stream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(piece) = stream.next().await {
                out.extend_from_slice(&piece.unwrap());
            }
            out
        }
    }
}

fn puts(fake: &FakeS3) -> usize {
    fake.requests()
        .iter()
        .filter(|r| r.method == Method::PUT)
        .count()
}

#[tokio::test]
async fn put_uses_if_none_match_star() {
    let fake = FakeS3::start();
    let s = store(&fake);
    assert_eq!(put(&s, b"hello").await.unwrap(), CommitOutcome::Created);
    let requests = fake.requests();
    let put = requests.iter().find(|r| r.method == Method::PUT).unwrap();
    assert_eq!(put.header("if-none-match"), Some("*"));
    assert_eq!(put.header("content-length"), Some("5"));
    assert_eq!(
        put.path,
        format!("/{DEFAULT_BUCKET}/{}", object_key(b"hello"))
    );
    assert_eq!(put.status, StatusCode::OK);
    assert_eq!(
        fake.object(DEFAULT_BUCKET, &object_key(b"hello")).unwrap(),
        "hello"
    );
}

#[tokio::test]
async fn hash_mismatch_never_issues_put() {
    let fake = FakeS3::start();
    let s = store(&fake);
    let mut sink = s.begin(key_of(b"other"), 5).await.unwrap();
    sink.write(Bytes::from_static(b"hello")).await.unwrap();
    assert!(matches!(sink.commit().await, Err(StoreError::Invalid(_))));
    // Short and long bodies, an abort and a dropped sink send nothing
    // either.
    let mut sink = s.begin(key_of(b"hello"), 6).await.unwrap();
    sink.write(Bytes::from_static(b"hello")).await.unwrap();
    assert!(matches!(sink.commit().await, Err(StoreError::Invalid(_))));
    let mut sink = s.begin(key_of(b"hello"), 4).await.unwrap();
    assert!(sink.write(Bytes::from_static(b"hello")).await.is_err());
    let mut sink = s.begin(key_of(b"hello"), 5).await.unwrap();
    sink.write(Bytes::from_static(b"hello")).await.unwrap();
    sink.abort().await;
    let mut sink = s.begin(key_of(b"hello"), 5).await.unwrap();
    sink.write(Bytes::from_static(b"hello")).await.unwrap();
    drop(sink);
    assert!(fake.requests().is_empty(), "{:?}", fake.requests());
    assert!(fake.keys(DEFAULT_BUCKET).is_empty());
}

#[tokio::test]
async fn status_412_maps_to_already_present() {
    let fake = FakeS3::start();
    let s = store(&fake);
    assert_eq!(put(&s, b"x").await.unwrap(), CommitOutcome::Created);
    assert_eq!(put(&s, b"x").await.unwrap(), CommitOutcome::AlreadyPresent);
    let statuses: Vec<_> = fake
        .requests()
        .iter()
        .filter(|r| r.method == Method::PUT)
        .map(|r| r.status)
        .collect();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::PRECONDITION_FAILED]);
}

#[tokio::test]
async fn range_get_sends_range_header() {
    let fake = FakeS3::start();
    let s = store(&fake);
    put(&s, b"0123456789").await.unwrap();
    fake.clear_requests();
    let range = ByteRange {
        start: 3,
        end_inclusive: 5,
    };
    let body = s
        .get(&key_of(b"0123456789"), Some(range))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read(body).await, b"345");
    let requests = fake.requests();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].header("range"), Some("bytes=3-5"));
    assert_eq!(requests[0].status, StatusCode::PARTIAL_CONTENT);
    // Past the end: S3 answers 416 without the length, so a HEAD asks.
    fake.clear_requests();
    let past = ByteRange {
        start: 10,
        end_inclusive: 20,
    };
    let got = s.get(&key_of(b"0123456789"), Some(past)).await;
    assert!(matches!(
        got,
        Err(StoreError::RangeNotSatisfiable { len: 10 })
    ));
    let methods: Vec<_> = fake.requests().iter().map(|r| r.method.clone()).collect();
    assert_eq!(methods, [Method::GET, Method::HEAD]);
    // A range of a missing blob is absent, not unsatisfiable.
    assert!(s.get(&key_of(b"nope"), Some(past)).await.unwrap().is_none());
}

#[tokio::test]
async fn authorization_header_is_sigv4() {
    let fake = FakeS3::start();
    let clock = Arc::new(ManualClock::new(1_711_300_000_000));
    let s = S3BlobStore::new(config(&fake), clock).unwrap();
    put(&s, b"signed").await.unwrap();
    s.head(&key_of(b"signed")).await.unwrap().unwrap();
    for request in fake.requests() {
        let auth = request.header("authorization").unwrap();
        assert!(
            auth.starts_with(&format!(
                "AWS4-HMAC-SHA256 Credential={}/20240324/auto/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=",
                fake.options().access_key_id
            )),
            "{auth}"
        );
        // Signed at the injected clock's time, and verified by the fake.
        assert_eq!(request.header("x-amz-date"), Some("20240324T170640Z"));
        assert!(request.status.is_success(), "{request:?}");
    }
    let put = fake
        .requests()
        .into_iter()
        .find(|r| r.method == Method::PUT)
        .unwrap();
    assert_eq!(
        put.header("x-amz-content-sha256"),
        Some(sigv4::sha256_hex(b"signed").as_str())
    );
}

#[tokio::test]
async fn wrong_secret_is_unavailable_and_redacted() {
    let fake = FakeS3::start();
    let mut cfg = config(&fake);
    cfg.credentials.secret_access_key = "wrong-secret-value".to_owned();
    let s = S3BlobStore::new(cfg, Arc::new(SystemClock)).unwrap();
    let err = put(&s, b"x").await.unwrap_err();
    assert!(matches!(err, StoreError::Unavailable(_)));
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("wrong-secret-value"), "{shown}");
    assert!(
        !shown.contains("SignatureDoesNotMatch"),
        "backend detail leaked: {shown}"
    );
    assert_eq!(fake.requests()[0].status, StatusCode::FORBIDDEN);
    assert!(fake.keys(DEFAULT_BUCKET).is_empty());
    assert!(s.probe().await.is_err());
}

#[test]
fn credentials_not_in_debug_output() {
    let fake = FakeS3::start();
    let secret = fake.options().secret_access_key.clone();
    let cfg = config(&fake);
    let s = store(&fake);
    for shown in [format!("{cfg:?}"), format!("{s:?}"), format!("{s:#?}")] {
        assert!(!shown.contains(&secret), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }
}

#[tokio::test]
async fn sink_memory_is_bounded() {
    const CHUNK: usize = 1024 * 1024;
    let fake = FakeS3::start();
    let spool = tempfile::tempdir().unwrap();
    let s = store(&fake).with_spool_dir(spool.path());
    let data: Bytes = (0..64 * CHUNK)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let key = key_of(&data);
    let mut sink = s.begin(key, data.len() as u64).await.unwrap();
    for (i, chunk) in data.chunks(CHUNK).enumerate() {
        sink.write(data.slice_ref(chunk)).await.unwrap();
        // Every byte so far is on disk: the sink holds no more than the
        // chunk in flight.
        assert_eq!(sink.spooled_bytes(), Some(((i + 1) * CHUNK) as u64));
    }
    // The spool file is unnamed: nothing is left to sweep, even now.
    assert_eq!(std::fs::read_dir(spool.path()).unwrap().count(), 0);
    assert!(fake.requests().is_empty());
    assert_eq!(sink.commit().await.unwrap(), CommitOutcome::Created);
    let put = fake
        .requests()
        .into_iter()
        .find(|r| r.method == Method::PUT)
        .unwrap();
    assert_eq!(put.body_len, data.len() as u64);
    let body = s.get(&key, None).await.unwrap().unwrap();
    assert!(matches!(body, BlobBody::Stream { len, .. } if len == data.len() as u64));
    assert_eq!(read(body).await, data);
}

#[tokio::test]
async fn transient_failures_are_retried_from_the_spool() {
    let fake = FakeS3::start();
    let s = store(&fake);
    fake.fail_next(Some(Method::PUT), StatusCode::SERVICE_UNAVAILABLE);
    fake.fail_next(Some(Method::PUT), StatusCode::CONFLICT);
    assert_eq!(put(&s, b"retry").await.unwrap(), CommitOutcome::Created);
    assert_eq!(puts(&fake), 3);
    assert_eq!(
        fake.object(DEFAULT_BUCKET, &object_key(b"retry")).unwrap(),
        "retry"
    );
}

#[tokio::test]
async fn persistent_failure_falls_back_to_head() {
    let fake = FakeS3::start();
    let s = store(&fake);
    // Present (another writer's verified bytes): AlreadyPresent.
    fake.insert_object(
        DEFAULT_BUCKET,
        &object_key(b"there"),
        Bytes::from_static(b"there"),
    );
    for _ in 0..3 {
        fake.fail_next(Some(Method::PUT), StatusCode::INTERNAL_SERVER_ERROR);
    }
    assert_eq!(
        put(&s, b"there").await.unwrap(),
        CommitOutcome::AlreadyPresent
    );
    // Absent: Unavailable, and nothing visible.
    for _ in 0..3 {
        fake.fail_next(Some(Method::PUT), StatusCode::SERVICE_UNAVAILABLE);
    }
    assert!(matches!(
        put(&s, b"gone").await,
        Err(StoreError::Unavailable(_))
    ));
    assert!(s.head(&key_of(b"gone")).await.unwrap().is_none());
    // A 403 is final: no retry.
    fake.clear_requests();
    fake.fail_next(Some(Method::PUT), StatusCode::FORBIDDEN);
    assert!(put(&s, b"denied").await.is_err());
    assert_eq!(puts(&fake), 1);
}

#[tokio::test]
async fn lost_commit_answer_retries_to_already_present() {
    let fake = FakeS3::start();
    let s = store(&fake);
    // The first PUT is stored, but its answer is a 500.
    fake.fail_after_commit(Some(Method::PUT), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        put(&s, b"lost").await.unwrap(),
        CommitOutcome::AlreadyPresent
    );
    let statuses: Vec<_> = fake
        .requests()
        .iter()
        .filter(|r| r.method == Method::PUT)
        .map(|r| r.status)
        .collect();
    assert_eq!(
        statuses,
        [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::PRECONDITION_FAILED
        ]
    );
    assert_eq!(fake.keys(DEFAULT_BUCKET), [object_key(b"lost")]);
    assert_eq!(
        fake.object(DEFAULT_BUCKET, &object_key(b"lost")).unwrap(),
        "lost"
    );
}

#[tokio::test]
async fn retry_after_and_request_timeout_are_honored() {
    let fake = FakeS3::start();
    let s = store(&fake);
    fake.fail_next_retry_after(Some(Method::PUT), StatusCode::SERVICE_UNAVAILABLE, 1);
    let started = std::time::Instant::now();
    assert_eq!(put(&s, b"slow").await.unwrap(), CommitOutcome::Created);
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    // S3's `400 RequestTimeout` (a body that arrived too slowly) is
    // retried; another 400 is not.
    fake.clear_requests();
    fake.fail_next(Some(Method::PUT), StatusCode::BAD_REQUEST);
    assert_eq!(put(&s, b"timed").await.unwrap(), CommitOutcome::Created);
    assert_eq!(puts(&fake), 2);
}

#[tokio::test]
async fn stalled_put_is_abandoned_and_retried() {
    let fake = FakeS3::start();
    let s = store(&fake).with_stall_timeout(std::time::Duration::from_millis(300));
    // A small body fits the socket buffers, so the stall is the missing
    // answer; an 8 MiB one stops moving while the bucket does not read.
    let big: Vec<u8> = (0..8 << 20_u32)
        .map(|i| u8::try_from(i % 241).unwrap())
        .collect();
    for data in [&b"stall"[..], &big] {
        fake.clear_requests();
        fake.stall_next(Some(Method::PUT));
        let started = std::time::Instant::now();
        assert_eq!(put(&s, data).await.unwrap(), CommitOutcome::Created);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        let statuses: Vec<_> = fake.requests().iter().map(|r| r.status).collect();
        assert_eq!(statuses, [StatusCode::REQUEST_TIMEOUT, StatusCode::OK]);
    }
}

#[tokio::test]
async fn probe_is_bounded_and_cached() {
    let fake = FakeS3::start();
    let s = store(&fake);
    fake.stall_next(Some(Method::HEAD));
    let started = std::time::Instant::now();
    assert!(s.probe().await.is_err());
    let took = started.elapsed();
    assert!(
        took >= mkit_server_native::s3::PROBE_TIMEOUT && took < std::time::Duration::from_secs(15),
        "{took:?}"
    );
    // The failure is cached: no second request.
    assert!(s.probe().await.is_err());
    assert_eq!(fake.requests().len(), 1);
}

#[tokio::test]
async fn spool_budget_reserves_the_declared_length() {
    let fake = FakeS3::start();
    let s = store(&fake).with_spool_max_bytes(10);
    // More than the whole spool can ever hold: invalid, not retryable.
    assert!(matches!(
        s.begin(key_of(b"x"), 11).await,
        Err(StoreError::Invalid(_))
    ));
    let first = s.begin(key_of(b"123456"), 6).await.unwrap();
    assert_eq!(s.spool_reserved_bytes(), 6);
    // No room: Full before any byte arrives, and nothing is sent.
    assert!(matches!(
        s.begin(key_of(b"abcdef"), 6).await,
        Err(StoreError::Full)
    ));
    // A drop, an abort and a commit each release their reservation.
    drop(first);
    assert_eq!(s.spool_reserved_bytes(), 0);
    let sink = s.begin(key_of(b"abcdef"), 6).await.unwrap();
    sink.abort().await;
    assert_eq!(s.spool_reserved_bytes(), 0);
    assert_eq!(put(&s, b"abcdef").await.unwrap(), CommitOutcome::Created);
    assert_eq!(s.spool_reserved_bytes(), 0);
    let mut failed = s.begin(key_of(b"other"), 6).await.unwrap();
    failed.write(Bytes::from_static(b"abcdef")).await.unwrap();
    assert!(failed.commit().await.is_err());
    assert_eq!(s.spool_reserved_bytes(), 0);
}

#[test]
fn spool_sweep_removes_only_leftover_spool_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".tmpA1b2C3"), b"crash leftover").unwrap();
    std::fs::write(dir.path().join("keep.txt"), b"not ours").unwrap();
    std::fs::create_dir(dir.path().join(".tmpdir")).unwrap();
    assert_eq!(
        mkit_server_native::s3::sweep_spool_dir(dir.path()).unwrap(),
        1
    );
    assert!(!dir.path().join(".tmpA1b2C3").exists());
    assert!(dir.path().join("keep.txt").exists());
    assert!(dir.path().join(".tmpdir").exists());
}

#[tokio::test]
async fn missing_bucket_is_an_error_not_an_absent_blob() {
    let fake = FakeS3::start();
    let mut cfg = config(&fake);
    cfg.bucket = "no-such-bucket".to_owned();
    let s = S3BlobStore::new(cfg, Arc::new(SystemClock)).unwrap();
    assert!(matches!(
        s.get(&key_of(b"x"), None).await,
        Err(StoreError::Unavailable(_))
    ));
    assert!(s.probe().await.is_err());
}

#[tokio::test]
async fn provider_ignoring_if_none_match_stays_correct() {
    let fake = FakeS3::start_with(FakeS3Options {
        honor_if_none_match: false,
        ..FakeS3Options::default()
    });
    let s = store(&fake);
    assert_eq!(put(&s, b"same").await.unwrap(), CommitOutcome::Created);
    // Reported Created (the contract allows it); the bytes are unchanged.
    assert_eq!(put(&s, b"same").await.unwrap(), CommitOutcome::Created);
    let body = s.get(&key_of(b"same"), None).await.unwrap().unwrap();
    assert_eq!(read(body).await, b"same");
}

#[tokio::test]
async fn delete_reports_existence() {
    let fake = FakeS3::start();
    let s = store(&fake);
    put(&s, b"d").await.unwrap();
    assert!(s.delete(&key_of(b"d")).await.unwrap());
    assert!(!s.delete(&key_of(b"d")).await.unwrap());
    assert!(fake.keys(DEFAULT_BUCKET).is_empty());
}

#[test]
fn config_is_validated() {
    let fake = FakeS3::start();
    let bad = |edit: &dyn Fn(&mut S3Config)| {
        let mut cfg = config(&fake);
        edit(&mut cfg);
        cfg.validate().unwrap_err()
    };
    bad(&|c| c.endpoint = "ftp://h".parse().unwrap());
    bad(&|c| c.endpoint = "https://user:pw@h".parse().unwrap());
    bad(&|c| c.endpoint = "https://h/path".parse().unwrap());
    bad(&|c| c.endpoint = "https://h/?q=1".parse().unwrap());
    bad(&|c| c.bucket = "Upper".to_owned());
    bad(&|c| c.bucket = "ab".to_owned());
    bad(&|c| c.bucket = "-edge".to_owned());
    bad(&|c| c.prefix = Some("a/../b".to_owned()));
    bad(&|c| c.prefix = Some("a//b".to_owned()));
    bad(&|c| c.prefix = Some("a/b/".to_owned()));
    bad(&|c| c.prefix = Some("sp ace".to_owned()));
    bad(&|c| c.credentials.secret_access_key.clear());
    bad(&|c| c.credentials.region = "Auto".to_owned());
    let mut cfg = config(&fake);
    cfg.endpoint = "https://s3.example:443/".parse().unwrap();
    assert_eq!(cfg.validate().unwrap(), "https://s3.example");
    cfg.endpoint = "http://[::1]:9000".parse().unwrap();
    assert_eq!(cfg.validate().unwrap(), "http://[::1]:9000");
    assert!(S3BlobStore::with_keyspace(config(&fake), "a/b", Arc::new(SystemClock)).is_err());
}

// ---------------------------------------------------------------------------
// The fake is strict: raw signed requests the store never sends.
// ---------------------------------------------------------------------------

/// Send a request signed for `payload_sha256`, with `headers`.
async fn raw(
    fake: &FakeS3,
    method: Method,
    path_and_query: &str,
    headers: &[(&str, &str)],
    payload_sha256: &str,
    body: Option<reqwest::Body>,
) -> reqwest::Response {
    let opts = fake.options();
    let creds = Credentials {
        access_key_id: opts.access_key_id.clone(),
        secret_access_key: opts.secret_access_key.clone(),
        region: opts.region.clone(),
    };
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let now = now_secs();
    let signed = sigv4::sign_request_with_payload_hash(
        &creds,
        method.as_str(),
        path,
        &sigv4::canonical_query_string(
            &query
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| p.split_once('=').unwrap_or((p, "")))
                .collect::<Vec<_>>(),
        ),
        payload_sha256,
        &fake.endpoint(),
        now,
    );
    let mut request = reqwest::Client::new()
        .request(method, format!("{}{path_and_query}", fake.endpoint()))
        .header("authorization", signed.authorization)
        .header("x-amz-date", signed.x_amz_date)
        .header("x-amz-content-sha256", signed.x_amz_content_sha256);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    request.send().await.unwrap()
}

fn now_secs() -> i64 {
    mkit_server::Clock::now_ms(&SystemClock) / 1000
}

async fn code(resp: reqwest::Response) -> (StatusCode, String) {
    let status = resp.status();
    let text = resp.text().await.unwrap();
    let code = text
        .split_once("<Code>")
        .and_then(|(_, rest)| rest.split_once("</Code>"))
        .map_or(String::new(), |(code, _)| code.to_owned());
    (status, code)
}

fn object_path(key: &str) -> String {
    format!("/{DEFAULT_BUCKET}/{key}")
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one table of cases
async fn fake_rejects_what_s3_rejects() {
    let fake = FakeS3::start();
    let hello = sigv4::sha256_hex(b"hello");
    let empty = sigv4::sha256_hex(b"");
    let path = object_path("k");
    let cases: Vec<(reqwest::Response, StatusCode, &str)> = vec![
        // A streamed body without Content-Length goes out chunked.
        (
            raw(
                &fake,
                Method::PUT,
                &path,
                &[],
                &hello,
                Some(reqwest::Body::wrap_stream(futures::stream::iter([Ok::<
                    _,
                    std::io::Error,
                >(
                    Bytes::from_static(b"hello"),
                )]))),
            )
            .await,
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
        ),
        (
            raw(&fake, Method::PUT, &path, &[], &empty, Some("hello".into())).await,
            StatusCode::BAD_REQUEST,
            "XAmzContentSHA256Mismatch",
        ),
        (
            raw(
                &fake,
                Method::PUT,
                &path,
                &[("if-none-match", "\"etag\"")],
                &hello,
                Some("hello".into()),
            )
            .await,
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
        ),
        (
            raw(
                &fake,
                Method::PUT,
                &path,
                &[("if-match", "*")],
                &hello,
                Some("hello".into()),
            )
            .await,
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
        ),
        (
            raw(
                &fake,
                Method::POST,
                &format!("{path}?uploads"),
                &[],
                &empty,
                None,
            )
            .await,
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
        ),
        (
            raw(
                &fake,
                Method::PUT,
                &path,
                &[("x-amz-meta-unsigned", "1")],
                &hello,
                Some("hello".into()),
            )
            .await,
            StatusCode::FORBIDDEN,
            "AccessDenied",
        ),
        (
            raw(
                &fake,
                Method::GET,
                &object_path("missing"),
                &[],
                &empty,
                None,
            )
            .await,
            StatusCode::NOT_FOUND,
            "NoSuchKey",
        ),
        (
            raw(&fake, Method::GET, "/other-bucket/k", &[], &empty, None).await,
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
        ),
        (
            reqwest::get(format!("{}{path}", fake.endpoint()))
                .await
                .unwrap(),
            StatusCode::FORBIDDEN,
            "AccessDenied",
        ),
    ];
    for (i, (resp, status, want)) in cases.into_iter().enumerate() {
        assert_eq!(code(resp).await, (status, want.to_owned()), "case {i}");
    }
    // A signature over another path does not verify.
    let resp = reqwest::Client::new()
        .get(format!("{}{}", fake.endpoint(), object_path("a")))
        .header(
            "authorization",
            sigv4::sign_request(
                &Credentials {
                    access_key_id: fake.options().access_key_id.clone(),
                    secret_access_key: fake.options().secret_access_key.clone(),
                    region: fake.options().region.clone(),
                },
                "GET",
                &object_path("b"),
                "",
                b"",
                &fake.endpoint(),
                now_secs(),
            )
            .authorization,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(code(resp).await.0, StatusCode::FORBIDDEN);
    assert!(fake.keys(DEFAULT_BUCKET).is_empty(), "nothing was written");
}

/// A conditional put whose body is held open until `release`.
fn held_put(
    fake: &FakeS3,
    key: &str,
    bytes: &'static [u8],
) -> (
    tokio::task::JoinHandle<StatusCode>,
    futures::channel::mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let (mut tx, rx) = futures::channel::mpsc::channel(1);
    tx.try_send(Ok(Bytes::from_static(&bytes[..1]))).unwrap();
    let endpoint = fake.endpoint();
    let opts = fake.options().clone();
    let path = object_path(key);
    let task = tokio::spawn(async move {
        let signed = sigv4::sign_request(
            &Credentials {
                access_key_id: opts.access_key_id,
                secret_access_key: opts.secret_access_key,
                region: opts.region,
            },
            "PUT",
            &path,
            "",
            bytes,
            &endpoint,
            now_secs(),
        );
        reqwest::Client::new()
            .put(format!("{endpoint}{path}"))
            .header("authorization", signed.authorization)
            .header("x-amz-date", signed.x_amz_date)
            .header("x-amz-content-sha256", signed.x_amz_content_sha256)
            .header("if-none-match", "*")
            .header("content-length", bytes.len().to_string())
            .body(reqwest::Body::wrap_stream(rx))
            .send()
            .await
            .unwrap()
            .status()
    });
    (task, tx)
}

async fn finish(
    mut tx: futures::channel::mpsc::Sender<Result<Bytes, std::io::Error>>,
    rest: &'static [u8],
) {
    use futures::SinkExt as _;
    tx.send(Ok(Bytes::from_static(rest))).await.unwrap();
}

#[tokio::test]
async fn fake_conditional_puts_race_like_s3() {
    let fake = FakeS3::start();
    let s = store(&fake);
    // Racing conditional writes: the first to finish wins, the other gets
    // 412 even though it started first.
    let (first, tx) = held_put(&fake, &object_key(b"race"), b"race");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(put(&s, b"race").await.unwrap(), CommitOutcome::Created);
    finish(tx, b"ace").await;
    assert_eq!(first.await.unwrap(), StatusCode::PRECONDITION_FAILED);

    // A DELETE while a conditional write is in flight: 409, retryable.
    put(&s, b"del").await.unwrap();
    s.delete(&key_of(b"del")).await.unwrap();
    let (held, tx) = held_put(&fake, &object_key(b"del"), b"del");
    // Let the put's headers arrive, so the fake has begun it.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // Delete again while the put's body is still open.
    raw(
        &fake,
        Method::DELETE,
        &object_path(&object_key(b"del")),
        &[],
        &sigv4::sha256_hex(b""),
        None,
    )
    .await;
    finish(tx, b"el").await;
    assert_eq!(held.await.unwrap(), StatusCode::CONFLICT);
    assert!(fake.object(DEFAULT_BUCKET, &object_key(b"del")).is_none());
}
