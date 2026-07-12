//! Integration tests for S3/R2 multipart upload (issue #704).
//!
//! `S3_SINGLE_PUT_MAX` and `MULTIPART_PART_SIZE` are only compiled to
//! their real 5 GiB / 64 MiB values when `test-small-multipart-caps` is
//! OFF; this whole file requires that feature (see `[[test]]` in
//! `Cargo.toml`) precisely so it can drive the real
//! `CreateMultipartUpload` -> `UploadPart` -> `CompleteMultipartUpload`
//! flow against a mockito server with single-digit-MiB bodies instead of
//! multi-GiB ones.
#![cfg(feature = "test-small-multipart-caps")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::time::Duration;

use mkit_core::hash::{Hash, to_hex};
use mkit_core::protocol::{BackoffIterator, PackKey, Transport, TransportError};
use mkit_transport_s3::sigv4::Credentials;
use mkit_transport_s3::{MULTIPART_PART_SIZE, S3_SINGLE_PUT_MAX, S3Transport};

fn demo_creds() -> Credentials {
    Credentials {
        access_key_id: "AKIA_TEST".into(),
        secret_access_key: "secret".into(),
        region: "auto".into(),
    }
}

fn fixed_clock() -> i64 {
    1_711_300_000
}

fn fast_backoff() -> BackoffIterator {
    BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 5)
}

fn noop_sleep(_: Duration) {}

fn build_transport(endpoint: &str) -> S3Transport {
    let mut t = S3Transport::with_parts(endpoint, "bucket", None, demo_creds())
        .expect("construct transport");
    t.set_clock(fixed_clock);
    t.set_sleeper(noop_sleep);
    t.set_backoff(fast_backoff);
    t
}

fn sample_hash() -> Hash {
    [0x77u8; 32]
}

fn sample_key() -> PackKey {
    PackKey::new(sample_hash())
}

/// Deterministic synthetic payload, `bytes` long — big enough to cross
/// `S3_SINGLE_PUT_MAX` but still bounded to a handful of MiB thanks to
/// `test-small-multipart-caps`.
fn synthetic_payload(bytes: usize) -> Vec<u8> {
    let mut x: u64 = 0xC0FF_EE15_0BAD_F00D_u64;
    let mut out = Vec::with_capacity(bytes);
    while out.len() < bytes {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(bytes);
    out
}

const UPLOAD_ID: &str = "test-upload-id-123";

fn init_response_xml() -> Vec<u8> {
    format!("<InitiateMultipartUploadResult><UploadId>{UPLOAD_ID}</UploadId></InitiateMultipartUploadResult>")
        .into_bytes()
}

#[test]
fn multipart_upload_round_trips_above_single_put_cap() {
    // A payload just above the single-PUT cap: exercises the multipart
    // branch instead of today's early-413 rejection.
    let payload_len = usize::try_from(S3_SINGLE_PUT_MAX).unwrap() + 1;
    let payload = synthetic_payload(payload_len);
    let expected_parts = payload_len.div_ceil(MULTIPART_PART_SIZE);
    assert!(
        expected_parts >= 2,
        "test payload must actually need multiple parts, got {expected_parts}"
    );

    let hex = to_hex(sample_key().as_bytes());
    let object_path = format!("/bucket/packs/{hex}");

    let mut server = mockito::Server::new();

    let m_init = server
        .mock("POST", object_path.as_str())
        .match_query(mockito::Matcher::Exact("uploads=".to_owned()))
        .with_status(200)
        .with_body(init_response_xml())
        .create();

    let mut m_parts = Vec::new();
    for part_number in 1..=expected_parts {
        let etag = format!("\"etag-part-{part_number}\"");
        let m = server
            .mock("PUT", object_path.as_str())
            .match_query(mockito::Matcher::Exact(format!(
                "partNumber={part_number}&uploadId={UPLOAD_ID}"
            )))
            .with_status(200)
            .with_header("etag", &etag)
            .create();
        m_parts.push(m);
    }

    let m_complete = server
        .mock("POST", object_path.as_str())
        .match_query(mockito::Matcher::Exact(format!("uploadId={UPLOAD_ID}")))
        .match_header("if-none-match", "*")
        .with_status(200)
        .create();

    let t = build_transport(&server.url());
    t.upload_pack(&payload, &sample_key()).unwrap();

    m_init.assert();
    for m in &m_parts {
        m.assert();
    }
    m_complete.assert();

    // Round-trip: a `download_pack` GET (simulating the now-materialized
    // multipart object) must return the exact bytes that were uploaded.
    // When `pack-shards` is also enabled (e.g. under `--all-features`),
    // `download_pack` probes the shard manifest first; a 404 there
    // signals "no shards published" so it falls through to the
    // monolithic GET below (mirrors `transport_mockito.rs`'s
    // `download_pack_200_returns_body`).
    #[cfg(feature = "pack-shards")]
    let _m_manifest_404 = server
        .mock("GET", format!("{object_path}/shards.manifest").as_str())
        .with_status(404)
        .create();
    let m_download = server
        .mock("GET", object_path.as_str())
        .with_status(200)
        .with_body(payload.clone())
        .create();
    let downloaded = t.download_pack(&sample_key()).unwrap();
    assert_eq!(
        downloaded, payload,
        "multipart round-trip must be byte-exact"
    );
    m_download.assert();
}

#[test]
fn multipart_upload_aborts_on_part_failure() {
    // A part that exhausts its retries must abort the multipart upload
    // (DELETE ?uploadId=...) rather than proceeding to
    // CompleteMultipartUpload or leaving the upload dangling.
    let payload_len = usize::try_from(S3_SINGLE_PUT_MAX).unwrap() + 1;
    let payload = synthetic_payload(payload_len);
    let expected_parts = payload_len.div_ceil(MULTIPART_PART_SIZE);
    assert!(expected_parts >= 2);

    let hex = to_hex(sample_key().as_bytes());
    let object_path = format!("/bucket/packs/{hex}");

    let mut server = mockito::Server::new();

    let _m_init = server
        .mock("POST", object_path.as_str())
        .match_query(mockito::Matcher::Exact("uploads=".to_owned()))
        .with_status(200)
        .with_body(init_response_xml())
        .create();

    // Part 1 succeeds.
    let _m_part1 = server
        .mock("PUT", object_path.as_str())
        .match_query(mockito::Matcher::Exact(format!(
            "partNumber=1&uploadId={UPLOAD_ID}"
        )))
        .with_status(200)
        .with_header("etag", "\"etag-part-1\"")
        .create();

    // Part 2 fails with a persistent 500 (retried `fast_backoff`'s 5
    // attempts, all failing) — 1 initial + 5 retries = 6 expected hits.
    let _m_part2_fail = server
        .mock("PUT", object_path.as_str())
        .match_query(mockito::Matcher::Exact(format!(
            "partNumber=2&uploadId={UPLOAD_ID}"
        )))
        .with_status(500)
        .expect(6)
        .create();

    // No CompleteMultipartUpload call is expected — if one happened,
    // mockito would 501 it and the transport would surface an
    // unexpected status rather than the part failure below.
    let m_abort = server
        .mock("DELETE", object_path.as_str())
        .match_query(mockito::Matcher::Exact(format!("uploadId={UPLOAD_ID}")))
        .with_status(204)
        .create();

    let t = build_transport(&server.url());
    match t.upload_pack(&payload, &sample_key()) {
        Err(TransportError::ServerError { status: 500 }) => {}
        other => panic!("expected the exhausted-retry 500 to propagate, got {other:?}"),
    }
    m_abort.assert();
}

#[test]
fn multipart_upload_412_on_complete_is_idempotent_success() {
    // Packs are content-addressed and immutable: a 412 on
    // CompleteMultipartUpload (If-None-Match: * lost the race against an
    // identical prior upload of the same digest) must be treated as an
    // idempotent no-op per SPEC-TRANSPORT §7, not a caller-visible error.
    let payload_len = usize::try_from(S3_SINGLE_PUT_MAX).unwrap() + 1;
    let payload = synthetic_payload(payload_len);
    let expected_parts = payload_len.div_ceil(MULTIPART_PART_SIZE);

    let hex = to_hex(sample_key().as_bytes());
    let object_path = format!("/bucket/packs/{hex}");

    let mut server = mockito::Server::new();

    let _m_init = server
        .mock("POST", object_path.as_str())
        .match_query(mockito::Matcher::Exact("uploads=".to_owned()))
        .with_status(200)
        .with_body(init_response_xml())
        .create();

    for part_number in 1..=expected_parts {
        server
            .mock("PUT", object_path.as_str())
            .match_query(mockito::Matcher::Exact(format!(
                "partNumber={part_number}&uploadId={UPLOAD_ID}"
            )))
            .with_status(200)
            .with_header("etag", &format!("\"etag-part-{part_number}\""))
            .create();
    }

    let _m_complete = server
        .mock("POST", object_path.as_str())
        .match_query(mockito::Matcher::Exact(format!("uploadId={UPLOAD_ID}")))
        .with_status(412)
        .create();

    let m_abort = server
        .mock("DELETE", object_path.as_str())
        .match_query(mockito::Matcher::Exact(format!("uploadId={UPLOAD_ID}")))
        .with_status(204)
        .create();

    let t = build_transport(&server.url());
    t.upload_pack(&payload, &sample_key())
        .expect("412-already-exists on complete must surface as Ok(()), not an error");
    m_abort.assert();
}
