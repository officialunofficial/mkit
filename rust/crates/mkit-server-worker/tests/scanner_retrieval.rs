//! Private scanner retrieval through the production Worker DO wire and R2 store.
//! Empty durable shards are represented sparsely; populated shards run real SQL.
#![allow(clippy::unwrap_used)]
mod common;

use bytes::Bytes;
use futures::executor::block_on;
use mkit_core::hash::{from_hex, hash, to_hex};
use mkit_core::object::{Blob, ChunkedBlob, Object};
use mkit_core::pack::{DecodeLimits, NoExternalBases, PackWriter, decode_entries_with};
use mkit_core::serialize::serialize;
use mkit_core::write_auth::Headers;
use mkit_server::pipeline::{
    AuthMode, D34Shards, Hooks, Pipeline, PipelineConfig, ShardMap, Sharding,
};
use mkit_server::scanner_retrieval::{Assignment, PATH, PackGrant, RetrievalConfig};
use mkit_server::store::adapter_spi::{codec, keys, tickets};
use mkit_server::takedown::inventory;
use mkit_server::{
    Addressing, Batch, BlobKey, ManualClock, NamespaceKey, NamespaceStore, NoopMetrics, Partition,
    RepoId, RepoName, StoreError,
};
use mkit_server_conformance::wire::sign::{Envelope, Signer};
use mkit_server_worker::naming::DoTarget;
use mkit_server_worker::ns_client::{DoNamespaceStore, NsTransport};
use mkit_server_worker::r2::{PACKS_KEYSPACE, R2BlobStore};
use mkit_server_worker::wire::{NsCall, NsReply, NsRequest};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct SparseTransport {
    inner: common::Loopback,
    populated: Arc<Mutex<HashSet<DoTarget>>>,
    calls: Arc<AtomicU32>,
}
impl NsTransport for SparseTransport {
    async fn call(
        &self,
        target: &DoTarget,
        op: &'static str,
        body: String,
    ) -> Result<String, StoreError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let request: NsRequest = serde_json::from_str(&body).unwrap();
        let empty = !self.populated.lock().unwrap().contains(target);
        if empty {
            let reply = match request.call {
                NsCall::Get { .. } => Some(NsReply::Value { value: None }),
                NsCall::GetMany { keys } => Some(NsReply::Values {
                    values: vec![None; keys.len()],
                }),
                NsCall::Scan { .. } => Some(NsReply::Page {
                    entries: vec![],
                    next: None,
                }),
                _ => None,
            };
            if let Some(reply) = reply {
                return Ok(serde_json::to_string(&reply).unwrap());
            }
        }
        self.populated.lock().unwrap().insert(target.clone());
        self.inner.call(target, op, body).await
    }
}
fn signed(body: &[u8], repository: &str) -> Headers {
    let signer = Signer::new([12; 32], "https://scanner.example", repository);
    let digest = to_hex(&hash(body));
    let envelope_headers = signer.sign(&Envelope {
        version: Some("2".into()),
        audience: "https://scanner.example".into(),
        repository: repository.into(),
        procedure: PATH.into(),
        commitment: format!("body:{digest}"),
        digest: Some(digest),
        created_at: 1000,
        expires_at: 5000,
        nonce: "11".repeat(32),
    });
    mkit_server::auth_v2::headers_from(|name| {
        envelope_headers
            .headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    })
}

#[test]
#[allow(clippy::too_many_lines)] // Multiple staged packs through scanner decoding and terminal ticket states.
fn scanner_reads_and_decodes_staged_pack_ranges_on_worker_backends() {
    block_on(async {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(1000));
        let transport = SparseTransport {
            inner: common::Loopback::new(
                dir.path().into(),
                common::DoConfig {
                    clock: Some(clock.clone()),
                    ..common::DoConfig::default()
                },
            ),
            populated: Arc::default(),
            calls: Arc::default(),
        };
        let writer_key =
            from_hex(&Signer::new([9; 32], "https://scanner.example", "default").public_key_hex())
                .unwrap();
        let namespace = mkit_core::repo_identity::Namespace::Ed25519(writer_key);
        let identity = format!("{namespace}/default");
        let ns = NamespaceKey::from_namespace(&namespace);
        let repo = RepoId {
            namespace: ns.clone(),
            name: RepoName::new("default").unwrap(),
        };
        let meta = DoNamespaceStore::new(transport.clone(), Partition::Coordinator(ns.clone()));
        let bucket = common::SimBucket::default();
        let blobs = R2BlobStore::new(bucket.clone(), PACKS_KEYSPACE);
        let chunk_data = b"scanner verifies this object";
        let chunk = Object::Blob(Blob {
            data: chunk_data.to_vec(),
        });
        let chunk_id = chunk.id().unwrap();
        let manifest = Object::ChunkedBlob(ChunkedBlob {
            total_size: u64::try_from(chunk_data.len()).unwrap(),
            chunk_size: 0,
            chunks: vec![chunk_id],
        });
        let surplus = Object::Blob(Blob {
            data: b"metadata also covers unreachable bytes".to_vec(),
        });
        let partition = D34Shards.ref_shard(&repo, "refs/heads/main");
        let mut staged = Vec::new();
        let mut grants = Vec::new();
        for (index, objects) in [vec![chunk], vec![manifest, surplus]]
            .into_iter()
            .enumerate()
        {
            let mut writer = PackWriter::new_raw_only();
            let mut ids = Vec::new();
            for object in &objects {
                let id = object.id().unwrap();
                ids.push(id);
                writer.push_raw(id, &serialize(object).unwrap()).unwrap();
            }
            let pack = writer.finish().unwrap();
            let pack_id = hash(&pack);
            bucket.replace_object(
                &blobs.object_key(&BlobKey::pack(pack_id)).unwrap(),
                Bytes::copy_from_slice(&pack),
            );
            for object in &objects {
                inventory::stage(
                    &meta,
                    &pack_id,
                    pack.len() as u64,
                    &object.id().unwrap(),
                    object,
                    None,
                    1000,
                )
                .await
                .unwrap();
            }
            inventory::complete(&meta, &pack_id, pack.len() as u64, 1000)
                .await
                .unwrap();
            let reservation = format!("s:{}", to_hex(&[u8::try_from(index + 22).unwrap(); 32]));
            let ticket_id = tickets::ticket_id(&reservation);
            let ticket = codec::TicketV1 {
                authority_generation: None,
                repo: repo.name.clone(),
                ref_name: "refs/heads/main".into(),
                signer: writer_key,
                pack_id,
                bytes: pack.len() as u64,
                part_size: 8 * 1024 * 1024,
                created_at_ms: 999,
                expires_at_ms: 2000,
                reservation_id: reservation,
                upload_session: None,
            };
            meta.apply(
                &partition,
                Batch::new().put(keys::ticket(&ticket_id), codec::encode_ticket(&ticket)),
            )
            .await
            .unwrap();
            grants.push(PackGrant {
                id: pack_id,
                length: pack.len() as u64,
                tickets: vec![ticket_id],
            });
            staged.push((pack, pack_id, ids, ticket, ticket_id));
        }
        let retrieval = Arc::new(
            RetrievalConfig::parse(
                &format!("active scanner {}", "18".repeat(32)),
                &Signer::new([12; 32], "https://scanner.example", "default").public_key_hex(),
            )
            .unwrap(),
        );
        let capability = retrieval
            .mint(
                "https://scanner.example",
                "stable-inspection",
                &Assignment {
                    namespace: ns.as_str().into(),
                    repo_name: "default".into(),
                    repository: identity.clone(),
                    ref_name: "refs/heads/main".into(),
                    signer: writer_key,
                    packs: grants,
                },
                std::time::Duration::from_millis(500),
                1000,
            )
            .unwrap();
        let mut cfg = PipelineConfig::new(
            Addressing::Multi(mkit_server::MultiAddressing::new().with_namespace_policy(
                mkit_server::policy::NamespacePolicy::Allowlist([namespace].into()),
            )),
            AuthMode::AuthV2(
                mkit_server::auth_v2::AuthV2Config::new("https://scanner.example", "").unwrap(),
            ),
            mkit_server::upload::UploadLimits::new(1 << 20, 16),
        );
        cfg.sharding = Sharding::D34;
        cfg.write_policy = mkit_server::policy::WritePolicy::Owner;
        cfg.begin_upload_threshold_bytes = 0;
        cfg.indexed = Some(mkit_server::indexed::IndexedConfig::default());
        cfg.ticket_keys = Some(
            mkit_server::upload::token::TicketKeys::new(vec![("ticket".into(), [7; 32])]).unwrap(),
        );
        cfg.scanner_retrieval = Some(retrieval);
        let pipe = Pipeline::new(
            blobs,
            meta.clone(),
            Hooks::new(),
            cfg,
            clock.clone(),
            Arc::new(NoopMetrics),
        )
        .unwrap();
        let before = transport.calls.load(Ordering::SeqCst);
        let mut ranges = 0_u32;
        let mut decoded_ids = Vec::new();
        let mut manifest_chunks = Vec::new();
        assert_eq!(capability.packs.len(), staged.len());
        for ((pack, pack_id, ids, _, _), descriptor) in staged.iter().zip(&capability.packs) {
            assert_eq!(descriptor.id.as_deref(), Some(pack_id.as_slice()));
            assert_eq!(descriptor.length, Some(pack.len() as u64));
            let mut received = Vec::new();
            for start in (0..pack.len()).step_by(32) {
                let end = (start + 31).min(pack.len() - 1);
                let body = serde_json::to_vec(&serde_json::json!({"capability":capability.capability,"pack_id":to_hex(pack_id),"start":start,"end_inclusive":end})).unwrap();
                let response = pipe
                    .retrieve_scanner_pack(&body, &signed(&body, &identity))
                    .await
                    .unwrap();
                assert!(response.partial);
                assert_eq!(
                    (response.start, response.total),
                    (start as u64, pack.len() as u64)
                );
                assert!(response.bytes.len() <= 32);
                received.extend_from_slice(&response.bytes);
                ranges += 1;
            }
            assert_eq!(&received, pack);
            let mut decoded = Vec::new();
            decode_entries_with(
                &received,
                &mut NoExternalBases,
                DecodeLimits::default(),
                |entry| {
                    decoded.push(entry.id);
                    if let Object::ChunkedBlob(manifest) = entry.object {
                        manifest_chunks.extend(manifest.chunks);
                    }
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                &decoded, ids,
                "decoded object ids equal the metadata ids for each raw pack"
            );
            decoded_ids.extend(decoded);
        }
        assert_eq!(manifest_chunks, vec![chunk_id]);
        assert!(manifest_chunks.iter().all(|id| decoded_ids.contains(id)));
        assert!(
            transport.calls.load(Ordering::SeqCst) - before
                <= ranges * mkit_server::scanner_retrieval::MAX_CALLS
        );
        let (_, pack_id, _, ticket, ticket_id) = &staged[0];
        let body = serde_json::to_vec(
            &serde_json::json!({"capability":capability.capability,"pack_id":to_hex(pack_id)}),
        )
        .unwrap();
        meta.apply(&partition, Batch::new().delete(keys::ticket(ticket_id)))
            .await
            .unwrap();
        let error = pipe
            .retrieve_scanner_pack(&body, &signed(&body, &identity))
            .await
            .unwrap_err();
        assert_eq!(error.code(), mkit_server::Code::NotFound);
        meta.apply(
            &partition,
            Batch::new().put(keys::ticket(ticket_id), codec::encode_ticket(ticket)),
        )
        .await
        .unwrap();
        clock.set(2000);
        assert_eq!(
            pipe.retrieve_scanner_pack(&body, &signed(&body, &identity))
                .await
                .unwrap_err()
                .code(),
            mkit_server::Code::NotFound
        );
        let mut ticket = ticket.clone();
        ticket.expires_at_ms = 5000;
        meta.apply(
            &partition,
            Batch::new().put(keys::ticket(ticket_id), codec::encode_ticket(&ticket)),
        )
        .await
        .unwrap();
        clock.set(2500);
        assert_eq!(
            pipe.retrieve_scanner_pack(&body, &signed(&body, &identity))
                .await
                .unwrap_err()
                .code(),
            mkit_server::Code::NotFound
        );
    });
}
