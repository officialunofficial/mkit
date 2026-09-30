//! Scanner-only HTTP retrieval of real pack bytes, independently decoded by core.
#![cfg(all(feature = "http", feature = "hooks"))]
#![allow(clippy::unwrap_used)]

use axum::body::Body;
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use mkit_core::{
    hash::{Hash, from_hex, hash, to_hex},
    object::{Blob, ChunkedBlob, Object},
    pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with},
    repo_identity::Namespace,
    serialize::serialize,
};
use mkit_server::{
    Addressing, Batch, ManualClock, MemoryBlobStore, MemoryKv, MultiAddressing, NamespaceKey,
    NamespaceStore, NoopMetrics, Partition, RepoName,
    auth_v2::AuthV2Config,
    indexed::IndexedConfig,
    pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig},
    policy::{NamespacePolicy, WritePolicy},
    scanner_retrieval::{
        Assignment, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, PATH, PackGrant, RetrievalConfig,
    },
    store::{BlobKey, BlobStore, PackSink, codec, keys, tickets},
    takedown::inventory,
    upload::{UploadLimits, token::TicketKeys},
};
use mkit_server_conformance::wire::sign::{Signer, now_ms};
use mkit_server_native::{RouterOptions, build_router};
use std::{sync::Arc, time::Duration};
use tower::ServiceExt as _;

const AUDIENCE: &str = "https://scanner.native.test";
const REF: &str = "refs/heads/main";

struct Fixture {
    router: axum::Router,
    scanner: Signer,
    capability: String,
    packs: Vec<(Hash, Vec<u8>)>,
    objects: Vec<Hash>,
    manifest: Hash,
    chunks: Vec<Hash>,
    meta: Arc<MemoryKv>,
    partition: Partition,
    ticket_ids: Vec<Hash>,
    clock: Arc<ManualClock>,
}

#[allow(clippy::too_many_lines)] // Complete wire fixture owns tickets, inventory and two raw packs.
async fn fixture() -> Fixture {
    let now = now_ms();
    let epoch_ms = u64::try_from(now).unwrap();
    let clock = Arc::new(ManualClock::new(now));
    let meta = Arc::new(MemoryKv::with_clock(clock.clone()));
    let blobs = MemoryBlobStore::default();
    let owner = Signer::new([7; 32], AUDIENCE, "unused");
    let namespace = Namespace::parse(&format!("ed25519-{}", owner.public_key_hex())).unwrap();
    let identity = format!("{namespace}/room");
    let scanner = Signer::new([9; 32], AUDIENCE, &identity);
    let retrieval = Arc::new(
        RetrievalConfig::parse(
            &format!("active native {}", "0a".repeat(32)),
            &scanner.public_key_hex(),
        )
        .unwrap(),
    );
    let chunks = [b"first bytes".as_slice(), b"second bytes".as_slice()].map(|data| {
        Object::Blob(Blob {
            data: data.to_vec(),
        })
    });
    let chunk_ids: Vec<_> = chunks.iter().map(|o| o.id().unwrap()).collect();
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: 23,
        chunk_size: 0,
        chunks: chunk_ids.clone(),
    });
    let all = [vec![manifest.clone()], chunks.to_vec()];
    let objects: Vec<_> = all.iter().flatten().map(|o| o.id().unwrap()).collect();
    let partition = Partition::Namespace(NamespaceKey::from_namespace(&namespace));
    let mut grants = Vec::new();
    let mut packs = Vec::new();
    let mut ticket_ids = Vec::new();
    for (index, entries) in all.iter().enumerate() {
        let mut writer = PackWriter::new_raw_only();
        for object in entries {
            writer
                .push_raw(object.id().unwrap(), &serialize(object).unwrap())
                .unwrap();
        }
        let bytes = writer.finish().unwrap();
        let id = hash(&bytes);
        let length = bytes.len() as u64;
        let mut sink = blobs.begin(BlobKey::pack(id), length).await.unwrap();
        sink.write(Bytes::copy_from_slice(&bytes)).await.unwrap();
        sink.commit().await.unwrap();
        for object in entries {
            inventory::stage(
                &meta,
                &id,
                length,
                &object.id().unwrap(),
                object,
                None,
                epoch_ms,
            )
            .await
            .unwrap();
        }
        inventory::complete(&meta, &id, length, epoch_ms)
            .await
            .unwrap();
        let reservation_id = format!("scanner:{index}");
        let ticket_id = tickets::ticket_id(&reservation_id);
        let ticket = codec::TicketV1 {
            authority_generation: None,
            repo: RepoName::new("room").unwrap(),
            ref_name: REF.into(),
            signer: from_hex(&owner.public_key_hex()).unwrap(),
            pack_id: id,
            bytes: length,
            part_size: 8 << 20,
            expires_at_ms: epoch_ms + 60_000,
            created_at_ms: epoch_ms,
            reservation_id,
            upload_session: None,
        };
        meta.apply(
            &partition,
            Batch::new().put(keys::ticket(&ticket_id), codec::encode_ticket(&ticket)),
        )
        .await
        .unwrap();
        grants.push(PackGrant {
            id,
            length,
            tickets: vec![ticket_id],
        });
        ticket_ids.push(ticket_id);
        packs.push((id, bytes));
    }
    let assignment = Assignment {
        namespace: NamespaceKey::from_namespace(&namespace).as_str().into(),
        repo_name: "room".into(),
        repository: identity,
        ref_name: REF.into(),
        signer: from_hex(&owner.public_key_hex()).unwrap(),
        packs: grants,
    };
    let capability = retrieval
        .mint(
            AUDIENCE,
            "native-inspection",
            &assignment,
            Duration::from_secs(5),
            epoch_ms,
        )
        .unwrap()
        .capability
        .unwrap();
    let mut config = PipelineConfig::new(
        Addressing::Multi(
            MultiAddressing::new()
                .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
        ),
        AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, "").unwrap()),
        UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        },
    );
    config.write_policy = WritePolicy::Owner;
    config.begin_upload_threshold_bytes = 0;
    config.ticket_keys = Some(TicketKeys::new(vec![("ticket".into(), [8; 32])]).unwrap());
    config.indexed = Some(IndexedConfig::default());
    config.scanner_retrieval = Some(retrieval);
    let pipeline = Pipeline::new(
        blobs,
        meta.clone(),
        Hooks::new(),
        config,
        clock.clone(),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    Fixture {
        router: build_router(Arc::new(pipeline), &RouterOptions::default()),
        scanner,
        capability,
        packs,
        objects,
        manifest: manifest.id().unwrap(),
        chunks: chunk_ids,
        meta,
        partition,
        ticket_ids,
        clock,
    }
}

impl Fixture {
    async fn request(&self, body: Vec<u8>, signer: &Signer) -> http::Response<Body> {
        let envelope = signer.sign_body(PATH, &body);
        let mut request = Request::builder().method("POST").uri(PATH);
        for (name, value) in envelope.headers {
            request = request.header(name, value);
        }
        self.router
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }
    fn body(&self, pack: Hash, range: Option<(u64, u64)>) -> Vec<u8> {
        let mut value = serde_json::json!({"capability":self.capability,"pack_id":to_hex(&pack)});
        if let Some((start, end)) = range {
            value["start"] = start.into();
            value["end_inclusive"] = end.into();
        }
        serde_json::to_vec(&value).unwrap()
    }
    async fn missing(&self, body: Vec<u8>, signer: &Signer) {
        let response = self.request(body, signer).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!response.headers().contains_key("cache-control"));
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            r#"{"code":"not_found","message":"pack not found"}"#
        );
    }
}

#[tokio::test]
async fn scanner_fetches_all_packs_with_ranges_and_decodes_manifest_membership() {
    let fx = fixture().await;
    let mut decoded = Vec::new();
    let mut manifest_chunks = Vec::new();
    for (id, expected) in &fx.packs {
        let response = fx.request(fx.body(*id, None), &fx.scanner).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("cache-control"));
        let whole = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(whole.as_ref(), expected);
        let midpoint = expected.len() as u64 / 2;
        let mut joined = Vec::new();
        for (start, end) in [(0, midpoint - 1), (midpoint, expected.len() as u64 - 1)] {
            let response = fx
                .request(fx.body(*id, Some((start, end))), &fx.scanner)
                .await;
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                response.headers()["content-range"],
                format!("bytes {start}-{end}/{}", expected.len())
            );
            joined.extend_from_slice(&response.into_body().collect().await.unwrap().to_bytes());
        }
        assert_eq!(joined, *expected);
        decode_entries_with(
            &joined,
            &mut NoExternalBases,
            DecodeLimits::default(),
            |entry| {
                decoded.push(entry.id);
                if entry.id == fx.manifest
                    && let Object::ChunkedBlob(manifest) = entry.object
                {
                    manifest_chunks = manifest.chunks;
                }
                Ok(())
            },
        )
        .unwrap();
    }
    decoded.sort_unstable();
    let mut expected = fx.objects.clone();
    expected.sort_unstable();
    assert_eq!(decoded, expected);
    assert_eq!(manifest_chunks, fx.chunks);
}

#[tokio::test]
async fn adapter_and_lifetime_failures_are_uniform() {
    let fx = fixture().await;
    let id = fx.packs[0].0;
    for body in [
        b"{}".to_vec(),
        vec![b' '; MAX_REQUEST_BYTES + 1],
        fx.body([0; 32], None),
        fx.body(id, Some((0, MAX_RESPONSE_BYTES as u64))),
    ] {
        fx.missing(body, &fx.scanner).await;
    }
    fx.missing(
        fx.body(id, None),
        &Signer::new(
            [5; 32],
            AUDIENCE,
            fx.scanner
                .envelope(PATH, "unused".into())
                .repository
                .as_str(),
        ),
    )
    .await;
    fx.meta
        .apply(
            &fx.partition,
            Batch::new().delete(keys::ticket(&fx.ticket_ids[0])),
        )
        .await
        .unwrap();
    fx.missing(fx.body(id, None), &fx.scanner).await;
    fx.clock.advance(60_001);
    fx.missing(fx.body(fx.packs[1].0, None), &fx.scanner).await;
}

#[tokio::test]
async fn active_global_block_is_hidden_by_the_private_failure() {
    use mkit_server::takedown::denial;
    let fx = fixture().await;
    let action = denial::BlockAction {
        id: [17; 32],
        takedown_id: [18; 32],
        reason: "policy".into(),
        blocked_at_ms: u64::try_from(now_ms()).unwrap(),
        chunk_ids: Vec::new(),
    };
    mkit_server::ContentIndex::new(fx.meta.clone())
        .install_block_action(&fx.manifest, &action, u64::try_from(now_ms()).unwrap())
        .await
        .unwrap();
    fx.missing(fx.body(fx.packs[0].0, None), &fx.scanner).await;
}

#[tokio::test]
async fn ticket_expiry_revokes_an_unexpired_capability() {
    let fx = fixture().await;
    let key = keys::ticket(&fx.ticket_ids[0]);
    let raw = fx.meta.get(&fx.partition, &key).await.unwrap().unwrap();
    let mut ticket = codec::decode_ticket(&raw).unwrap();
    ticket.expires_at_ms = ticket.created_at_ms + 1;
    fx.meta
        .apply(
            &fx.partition,
            Batch::new().put(key, codec::encode_ticket(&ticket)),
        )
        .await
        .unwrap();
    fx.clock.advance(2);
    fx.missing(fx.body(fx.packs[0].0, None), &fx.scanner).await;
    // The other pack's ticket and the same attempt capability remain live.
    assert_eq!(
        fx.request(fx.body(fx.packs[1].0, None), &fx.scanner)
            .await
            .status(),
        StatusCode::OK
    );
}
