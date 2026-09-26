//! The storage suite against `mkit-server-native`'s `S3BlobStore`, served
//! by the in-repo [`FakeS3`]: every blob case, no skips (blob harnesses
//! declare none).
//!
//! One fake serves the whole test binary; each store gets its own key
//! prefix, so every case starts from an empty keyspace and cases can run in
//! parallel.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use mkit_server::SystemClock;
use mkit_server_conformance::fake_s3::{DEFAULT_BUCKET, FakeS3};
use mkit_server_conformance::storage_suite;
use mkit_server_native::s3::{Credentials, S3BlobStore, S3Config};

static FAKE: LazyLock<FakeS3> = LazyLock::new(FakeS3::start);

/// A store over a fresh prefix of the shared fake's bucket.
fn s3_store() -> S3BlobStore {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let opts = FAKE.options();
    let cfg = S3Config {
        endpoint: FAKE.endpoint().parse().expect("the fake's endpoint"),
        bucket: DEFAULT_BUCKET.to_owned(),
        prefix: Some(format!("suite/case-{n}")),
        credentials: Credentials {
            access_key_id: opts.access_key_id.clone(),
            secret_access_key: opts.secret_access_key.clone(),
            region: opts.region.clone(),
        },
    };
    S3BlobStore::new(cfg, Arc::new(SystemClock)).expect("a valid S3 config")
}

storage_suite!(s3, blob = s3_store);
