#![allow(clippy::doc_markdown)]
//! `S3Transport` against a REAL S3-compatible backend (MinIO, via
//! Docker/testcontainers) rather than the in-process `mockito` stub
//! `transport_mockito.rs` uses. Mockito proves the status-code →
//! `TransportError` mapping and retry-loop logic; this proves the SigV4
//! signing this crate implements is actually accepted by a real,
//! independent S3-API implementation end to end — upload, existence
//! check, download, and ref read/write/list all round-trip against it.
//!
//! `#[ignore]`d: requires a running Docker daemon. Run explicitly:
//! `cargo test -p mkit-transport-s3 --test transport_minio -- --ignored --nocapture`.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, Transport};
use mkit_core::refs::RefWriteCondition;
use mkit_transport_s3::S3Transport;
use mkit_transport_s3::sigv4::{Credentials, sign_request};
use testcontainers::runners::SyncRunner;
use testcontainers_modules::minio::MinIO;

// MinIO's documented default root credentials when MINIO_ROOT_USER/
// MINIO_ROOT_PASSWORD aren't set (testcontainers-modules' MinIO image
// doesn't set them) — see https://min.io/docs/minio/linux/reference/minio-server/minio-server.html.
const MINIO_ROOT_USER: &str = "minioadmin";
const MINIO_ROOT_PASSWORD: &str = "minioadmin";
const BUCKET: &str = "mkit-test-bucket";

fn creds() -> Credentials {
    Credentials {
        access_key_id: MINIO_ROOT_USER.into(),
        secret_access_key: MINIO_ROOT_PASSWORD.into(),
        region: "us-east-1".into(),
    }
}

/// `S3Transport` never creates buckets (mirrors real S3, where that's a
/// separate administrative operation) — MinIO needs one to exist before
/// any of this crate's PUT/GET calls will succeed. Signs a bare
/// `PUT /{bucket}` the same way `S3Transport::http_request_once` signs
/// every other request (same `sign_request` call, same three
/// Authorization/x-amz-date/x-amz-content-sha256 headers), so this is
/// exercising the crate's own signer, not a separate signing path.
fn create_bucket(endpoint: &str) {
    // MinIO's own `ready_conditions` (stderr "API:") fires slightly before
    // Docker's port mapping reliably accepts connections — observed
    // directly as an intermittent connection-refused on the very first
    // request. Retry purely to ride out that readiness race; a real
    // signature/auth failure below is a hard `assert!`, not retried.
    let client = reqwest::blocking::Client::new();
    let mut last_err = None;
    for _ in 0..20 {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .try_into()
            .unwrap();
        let signed = sign_request(
            &creds(),
            "PUT",
            &format!("/{BUCKET}"),
            "",
            &[],
            endpoint,
            ts,
        );
        match client
            .put(format!("{endpoint}/{BUCKET}"))
            .header("Authorization", signed.authorization)
            .header("x-amz-date", signed.x_amz_date)
            .header("x-amz-content-sha256", signed.x_amz_content_sha256)
            .send()
        {
            Ok(resp) => {
                assert!(
                    resp.status().is_success(),
                    "MinIO refused bucket creation: {}",
                    resp.status()
                );
                return;
            }
            Err(e) if e.is_connect() => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Err(e) => panic!("bucket-creation request failed (not a connect error): {e}"),
        }
    }
    panic!("MinIO never became reachable for bucket creation: {last_err:?}");
}

fn sample_hash(byte: u8) -> Hash {
    [byte; 32]
}

#[test]
#[ignore = "requires a running Docker daemon"]
fn real_minio_roundtrip_pack_and_refs() {
    let container = MinIO::default().start().expect("MinIO container starts");
    let port = container
        .get_host_port_ipv4(9000)
        .expect("MinIO API port 9000 is mapped");
    let endpoint = format!("http://127.0.0.1:{port}");

    create_bucket(&endpoint);

    let transport =
        S3Transport::with_parts(endpoint, BUCKET, None, creds()).expect("construct S3Transport");

    // Pack upload/exists/download round-trip.
    let key = PackKey::new(sample_hash(0xAB));
    let pack_bytes = b"pretend-pack-bytes-for-a-real-minio-roundtrip";

    assert!(
        !transport.pack_exists(&key).unwrap(),
        "pack must not exist before upload"
    );
    transport
        .upload_pack(pack_bytes, &key)
        .expect("upload_pack against real MinIO");
    assert!(
        transport.pack_exists(&key).unwrap(),
        "pack must exist after upload"
    );
    let downloaded = transport
        .download_pack(&key)
        .expect("download_pack against real MinIO");
    assert_eq!(
        downloaded, pack_bytes,
        "downloaded pack bytes must match what was uploaded"
    );

    // Ref write/read/list round-trip.
    let branch_hash = sample_hash(0xCD);
    transport
        .update_ref("refs/heads/main", RefWriteCondition::Any, &branch_hash)
        .expect("update_ref against real MinIO");
    let read_back = transport
        .read_ref("refs/heads/main")
        .expect("read_ref against real MinIO");
    assert_eq!(read_back, Some(branch_hash));

    let listed = transport
        .list_refs("refs/heads/")
        .expect("list_refs against real MinIO");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "main");
    assert_eq!(listed[0].hash, Some(branch_hash));

    // CAS conflict: a `.missing` write against an existing ref must fail.
    let conflict = transport.update_ref(
        "refs/heads/main",
        RefWriteCondition::Missing,
        &sample_hash(0xEF),
    );
    assert!(
        conflict.is_err(),
        "CAS write with Missing condition must fail when the ref already exists"
    );
}
