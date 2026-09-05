//! Integration tests for the `pack-shards` feature on the S3 transport.
//!
//! The mockito server stands in for R2: it serves the manifest at
//! `/bucket/packs/<hex>/shards.manifest` and each shard at
//! `/bucket/packs/<hex>/shards/<index>`. The S3 transport's
//! `download_pack` is expected to detect a manifest, fetch shards in
//! parallel, and reconstruct the pack — falling back to the monolithic
//! pack key when the manifest is missing.
//!
//! These tests only compile when `--features pack-shards` is on. The
//! file is unconditionally listed in the crate's `tests/` directory;
//! every test is gated below.

#![cfg(feature = "pack-shards")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::time::Duration;

use mkit_core::hash::{Hash, hash};
use mkit_core::pack_shard::{Shard, default_config, encode_manifest, encode_pack_to_shards};
use mkit_core::protocol::{BackoffIterator, PackKey, Transport, TransportError};
use mkit_transport_s3::S3Transport;
use mkit_transport_s3::sigv4::Credentials;

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

fn build_transport_with_prefix(endpoint: &str, prefix: &str) -> S3Transport {
    let mut t = S3Transport::with_parts(endpoint, "bucket", Some(prefix.to_owned()), demo_creds())
        .expect("construct transport");
    t.set_clock(fixed_clock);
    t.set_sleeper(noop_sleep);
    t.set_backoff(fast_backoff);
    t
}

/// Deterministic synthetic pack.
fn synthetic_pack(bytes: usize) -> Vec<u8> {
    let mut x: u64 = 0x5EED_C0DE_FEED_FACE;
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

fn key_for(pack: &[u8]) -> PackKey {
    PackKey::new(hash(pack))
}

#[test]
fn requested_pack_identity_rejects_foreign_manifest_before_shards() {
    let mut server = mockito::Server::new();
    let key = key_for(b"requested pack A");
    let other = synthetic_pack(64 * 1024);
    let (shards, manifest) = encode_pack_to_shards(&other, default_config()).unwrap();
    let _manifest = server
        .mock(
            "GET",
            format!("/bucket/packs/{}/shards.manifest", key.to_hex()).as_str(),
        )
        .with_status(200)
        .with_body(encode_manifest(&manifest).unwrap())
        .create();
    let shard_mocks: Vec<_> = shards
        .iter()
        .map(|shard| {
            server
                .mock(
                    "GET",
                    format!("/bucket/packs/{}/shards/{}", key.to_hex(), shard.index).as_str(),
                )
                .with_status(200)
                .with_body(shard.bytes.clone())
                .expect(0)
                .create()
        })
        .collect();
    assert!(matches!(
        build_transport(&server.url()).download_pack(&key),
        Err(TransportError::InvalidResponse)
    ));
    for shard in shard_mocks {
        shard.assert();
    }
}

/// Publish a sharded pack at the mockito server. Drop the requested
/// shard indices (404 them) so the test can exercise loss scenarios.
fn publish_sharded(
    server: &mut mockito::Server,
    pack_size: usize,
    drop_indices: &[u16],
) -> (Vec<u8>, PackKey, Vec<mockito::Mock>) {
    let pack = synthetic_pack(pack_size);
    let key = key_for(&pack);
    let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
    let manifest_bytes = encode_manifest(&manifest).unwrap();

    let hex = mkit_core::hash::to_hex(key.as_bytes());
    let mut mocks = Vec::new();
    // Manifest key.
    let manifest_path = format!("/bucket/packs/{hex}/shards.manifest");
    mocks.push(
        server
            .mock("GET", manifest_path.as_str())
            .with_status(200)
            .with_body(manifest_bytes)
            .create(),
    );
    for shard in &shards {
        let path = format!("/bucket/packs/{hex}/shards/{}", shard.index);
        if drop_indices.contains(&shard.index) {
            mocks.push(server.mock("GET", path.as_str()).with_status(404).create());
        } else {
            mocks.push(
                server
                    .mock("GET", path.as_str())
                    .with_status(200)
                    .with_body(shard.bytes.clone())
                    .create(),
            );
        }
    }
    (pack, key, mocks)
}

fn publish_sharded_under_prefix(
    server: &mut mockito::Server,
    pack_size: usize,
    prefix: &str,
) -> (Vec<u8>, PackKey, Vec<mockito::Mock>) {
    let pack = synthetic_pack(pack_size);
    let key = key_for(&pack);
    let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
    let manifest_bytes = encode_manifest(&manifest).unwrap();

    let hex = mkit_core::hash::to_hex(key.as_bytes());
    let mut mocks = Vec::new();
    let manifest_path = format!("/bucket/{prefix}/packs/{hex}/shards.manifest");
    mocks.push(
        server
            .mock("GET", manifest_path.as_str())
            .with_status(200)
            .with_body(manifest_bytes)
            .create(),
    );
    for shard in &shards {
        let path = format!("/bucket/{prefix}/packs/{hex}/shards/{}", shard.index);
        mocks.push(
            server
                .mock("GET", path.as_str())
                .with_status(200)
                .with_body(shard.bytes.clone())
                .create(),
        );
    }
    (pack, key, mocks)
}

#[test]
fn s3_shard_round_trip_all_shards_present() {
    let mut server = mockito::Server::new();
    let (pack, key, _mocks) = publish_sharded(&mut server, 64 * 1024, &[]);
    let t = build_transport(&server.url());
    assert_eq!(t.download_pack(&key).unwrap(), pack);
}

#[test]
fn s3_shard_round_trip_uses_url_prefix_namespace() {
    let mut server = mockito::Server::new();
    let (pack, key, _mocks) = publish_sharded_under_prefix(&mut server, 64 * 1024, "repo-a");
    let t = build_transport_with_prefix(&server.url(), "repo-a");
    assert_eq!(t.download_pack(&key).unwrap(), pack);
}

#[test]
fn s3_shard_round_trip_k_shards_404() {
    let mut server = mockito::Server::new();
    let dropped = [16u16, 17, 18, 19];
    let (pack, key, _mocks) = publish_sharded(&mut server, 64 * 1024, &dropped);
    let t = build_transport(&server.url());
    assert_eq!(t.download_pack(&key).unwrap(), pack);
}

#[test]
fn s3_shard_fails_when_more_than_k_shards_404() {
    let mut server = mockito::Server::new();
    let dropped = [0u16, 1, 2, 3, 4];
    let (_pack, key, _mocks) = publish_sharded(&mut server, 64 * 1024, &dropped);
    let t = build_transport(&server.url());
    let err = t.download_pack(&key).unwrap_err();
    assert!(matches!(err, TransportError::PackNotFound));
}

#[test]
fn s3_falls_back_to_monolithic_when_manifest_missing() {
    // Manifest returns 404; the monolithic pack key returns the bytes.
    let mut server = mockito::Server::new();
    let body = b"plain-monolithic-pack".to_vec();
    let pack_hash: Hash = hash(&body);
    let key = PackKey::new(pack_hash);
    let hex = mkit_core::hash::to_hex(key.as_bytes());

    let _m_manifest = server
        .mock(
            "GET",
            format!("/bucket/packs/{hex}/shards.manifest").as_str(),
        )
        .with_status(404)
        .create();
    let _m_pack = server
        .mock("GET", format!("/bucket/packs/{hex}").as_str())
        .with_status(200)
        .with_body(body.clone())
        .create();

    let t = build_transport(&server.url());
    assert_eq!(t.download_pack(&key).unwrap(), body);
}

#[test]
fn s3_propagates_undecodable_manifest_never_falls_back() {
    // Manifest exists (200) but its body doesn't decode. SPEC-PACK-SHARDS
    // §5: only a 404/absent manifest falls back to the monolithic pack
    // key; a present-but-undecodable manifest is indistinguishable from
    // tampering and MUST propagate instead of silently downgrading. The
    // monolithic pack key is deliberately left unmocked so the test fails
    // loudly if a fallback is ever (re)introduced.
    let mut server = mockito::Server::new();
    let body = b"plain-monolithic-pack".to_vec();
    let pack_hash: Hash = hash(&body);
    let key = PackKey::new(pack_hash);
    let hex = mkit_core::hash::to_hex(key.as_bytes());

    let _m_manifest = server
        .mock(
            "GET",
            format!("/bucket/packs/{hex}/shards.manifest").as_str(),
        )
        .with_status(200)
        .with_body(b"not-a-manifest")
        .create();

    let t = build_transport(&server.url());
    let err = t.download_pack(&key).unwrap_err();
    assert!(
        matches!(err, TransportError::InvalidResponse),
        "expected InvalidResponse, got {err:?}"
    );
}

#[test]
fn s3_tampered_shard_is_rejected_via_manifest_hash() {
    // Build a sharded pack, corrupt one shard's body, and 404 all four
    // parity shards so the decoder is FORCED to consume the tampered
    // one: with only `minimum_shards` (16) shards servable — indices
    // 0..=15, including tampered shard 0 — the collection loop must
    // wait for all of them, the manifest's BLAKE3 entry must catch the
    // tamper, and the transport must surface `InvalidResponse`. This
    // is deterministic (no dependence on parallel arrival order): the
    // tampered shard can never be skipped.
    let mut server = mockito::Server::new();
    let pack = synthetic_pack(64 * 1024);
    let key = key_for(&pack);
    let config = default_config();
    let (mut shards, manifest) = encode_pack_to_shards(&pack, config).unwrap();
    // Flip a byte in shard 0 so its BLAKE3 no longer matches the
    // manifest entry.
    let last = shards[0].bytes.len() - 1;
    shards[0].bytes[last] ^= 0xFF;
    let manifest_bytes = encode_manifest(&manifest).unwrap();
    let hex = mkit_core::hash::to_hex(key.as_bytes());

    let _m_manifest = server
        .mock(
            "GET",
            format!("/bucket/packs/{hex}/shards.manifest").as_str(),
        )
        .with_status(200)
        .with_body(manifest_bytes)
        .create();
    let minimum = config.minimum_shards.get();
    let mut mocks = Vec::new();
    for shard in &shards {
        let path = format!("/bucket/packs/{hex}/shards/{}", shard.index);
        if shard.index < minimum {
            mocks.push(
                server
                    .mock("GET", path.as_str())
                    .with_status(200)
                    .with_body(shard.bytes.clone())
                    .create(),
            );
        } else {
            // Exactly `extra_shards` failures — one short of aborting
            // the collection loop, so every servable shard (tampered
            // shard 0 included) is consumed.
            mocks.push(server.mock("GET", path.as_str()).with_status(404).create());
        }
    }

    let t = build_transport(&server.url());
    match t.download_pack(&key) {
        Err(TransportError::InvalidResponse) => {}
        Ok(bytes) => panic!(
            "tampered shard must be rejected via the manifest hash, \
             got Ok ({} bytes{})",
            bytes.len(),
            if bytes == pack {
                ", identical to the pack — the tamper was silently repaired \
                 without enough healthy shards, which is impossible"
            } else {
                ", SILENT CORRUPTION"
            },
        ),
        Err(other) => {
            panic!("expected InvalidResponse from the manifest BLAKE3 check, got {other:?}")
        }
    }
}

fn one_retry_backoff() -> BackoffIterator {
    BackoffIterator::with(Duration::from_millis(1), Duration::from_millis(1), 1)
}

fn build_transport_one_retry(endpoint: &str) -> S3Transport {
    let mut t = S3Transport::with_parts(endpoint, "bucket", None, demo_creds())
        .expect("construct transport");
    t.set_clock(fixed_clock);
    t.set_sleeper(noop_sleep);
    t.set_backoff(one_retry_backoff);
    t
}

/// #181 fix A: an idempotent shard GET that returns 503 once then 200
/// is retried and succeeds. The mock asserts both attempts were made.
#[test]
fn s3_shard_get_retries_on_503_then_succeeds() {
    let mut server = mockito::Server::new();
    let pack = synthetic_pack(64 * 1024);
    let key = key_for(&pack);
    let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
    let manifest_bytes = encode_manifest(&manifest).unwrap();
    let hex = mkit_core::hash::to_hex(key.as_bytes());

    let _m_manifest = server
        .mock(
            "GET",
            format!("/bucket/packs/{hex}/shards.manifest").as_str(),
        )
        .with_status(200)
        .with_body(manifest_bytes)
        .create();

    // Shard 0: 503 once then 200 (one_retry_backoff allows one retry).
    let flaky_path = format!("/bucket/packs/{hex}/shards/0");
    let flaky_5xx = server
        .mock("GET", flaky_path.as_str())
        .with_status(503)
        .expect(1)
        .create();
    let flaky_ok = server
        .mock("GET", flaky_path.as_str())
        .with_status(200)
        .with_body(shards[0].bytes.clone())
        .expect(1)
        .create();
    // Leave only minimum-1 other shards available, forcing the retry to
    // complete before reconstruction can cancel redundant workers.
    for shard in shards.iter().skip(1) {
        let path = format!("/bucket/packs/{hex}/shards/{}", shard.index);
        let _m = server
            .mock("GET", path.as_str())
            .with_status(if shard.index < manifest.config.minimum_shards.get() {
                200
            } else {
                404
            })
            .with_body(shard.bytes.clone())
            .create();
    }

    let t = build_transport_one_retry(&server.url());
    assert_eq!(t.download_pack(&key).unwrap(), pack);
    flaky_5xx.assert();
    flaky_ok.assert();
}

/// #181 fix A: a shard GET returning 403 is NOT retried (terminal).
/// Four unavailable extras force this final terminal failure to be observed;
/// the mock asserts the denied shard was attempted exactly once.
#[test]
fn s3_shard_get_does_not_retry_on_403() {
    let mut server = mockito::Server::new();
    let pack = synthetic_pack(64 * 1024);
    let key = key_for(&pack);
    let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
    let manifest_bytes = encode_manifest(&manifest).unwrap();
    let hex = mkit_core::hash::to_hex(key.as_bytes());

    let _m_manifest = server
        .mock(
            "GET",
            format!("/bucket/packs/{hex}/shards.manifest").as_str(),
        )
        .with_status(200)
        .with_body(manifest_bytes)
        .create();

    let denied_path = format!("/bucket/packs/{hex}/shards/0");
    let denied = server
        .mock("GET", denied_path.as_str())
        .with_status(403)
        .expect(1)
        .create();
    for shard in shards.iter().skip(1) {
        let path = format!("/bucket/packs/{hex}/shards/{}", shard.index);
        let _m = server
            .mock("GET", path.as_str())
            .with_status(if shard.index < manifest.config.minimum_shards.get() {
                200
            } else {
                404
            })
            .with_body(shard.bytes.clone())
            .create();
    }

    let t = build_transport(&server.url()); // 5-attempt ladder
    assert!(t.download_pack(&key).is_err());
    denied.assert();
}

/// #181 fix B: a stalled straggler (a shard with no mock → fails fast)
/// does not block the download once quorum is reached. K extras are
/// dropped, leaving exactly `minimum` shards; the collection loop must
/// return without joining the failed stragglers.
#[test]
fn s3_shard_download_does_not_block_on_straggler_after_quorum() {
    let mut server = mockito::Server::new();
    let dropped = [16u16, 17, 18, 19];
    let (pack, key, _mocks) = publish_sharded(&mut server, 64 * 1024, &dropped);
    let t = build_transport(&server.url());
    assert_eq!(t.download_pack(&key).unwrap(), pack);
}

/// #180 regression: shard retries MUST keep using the EFFECTIVE PREFIX
/// path for both the manifest and the shard objects. Here the transport
/// is built with prefix `repo-a` but mockito ONLY serves the prefixed
/// paths (`/bucket/repo-a/packs/...`). If a retry ever dropped the
/// prefix, the request would 404 against the unprefixed path and the
/// round trip would fail. We also flake shard 0 with a 503 to force the
/// retry path specifically through the prefixed key.
#[test]
fn s3_shard_retry_preserves_effective_prefix() {
    let mut server = mockito::Server::new();
    let prefix = "repo-a";
    let pack = synthetic_pack(64 * 1024);
    let key = key_for(&pack);
    let (shards, manifest) = encode_pack_to_shards(&pack, default_config()).unwrap();
    let manifest_bytes = encode_manifest(&manifest).unwrap();
    let hex = mkit_core::hash::to_hex(key.as_bytes());

    let _m_manifest = server
        .mock(
            "GET",
            format!("/bucket/{prefix}/packs/{hex}/shards.manifest").as_str(),
        )
        .with_status(200)
        .with_body(manifest_bytes)
        .create();

    // Shard 0 under the PREFIXED path: 503 then 200. A retry that
    // dropped the prefix would miss this mock and 404.
    let flaky_path = format!("/bucket/{prefix}/packs/{hex}/shards/0");
    let flaky_5xx = server
        .mock("GET", flaky_path.as_str())
        .with_status(503)
        .expect(1)
        .create();
    let flaky_ok = server
        .mock("GET", flaky_path.as_str())
        .with_status(200)
        .with_body(shards[0].bytes.clone())
        .expect(1)
        .create();
    // Leave only minimum-1 other shards available, forcing the retry to
    // complete before reconstruction can cancel redundant workers.
    for shard in shards.iter().skip(1) {
        let path = format!("/bucket/{prefix}/packs/{hex}/shards/{}", shard.index);
        let _m = server
            .mock("GET", path.as_str())
            .with_status(if shard.index < manifest.config.minimum_shards.get() {
                200
            } else {
                404
            })
            .with_body(shard.bytes.clone())
            .create();
    }

    let mut t = S3Transport::with_parts(server.url(), "bucket", Some(prefix.into()), demo_creds())
        .expect("construct transport");
    t.set_clock(fixed_clock);
    t.set_sleeper(noop_sleep);
    t.set_backoff(one_retry_backoff);
    assert_eq!(t.download_pack(&key).unwrap(), pack);
    flaky_5xx.assert();
    flaky_ok.assert();
}

// Helper used by the build to confirm a Shard struct is reachable.
#[allow(dead_code)]
fn _shard_helper() -> Shard {
    Shard {
        index: 0,
        bytes: Vec::new(),
    }
}
