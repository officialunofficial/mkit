//! Local native/workerd fixture: real indexed ingestion, memory stores.
use bytes::Bytes;
use ed25519_dalek::{Signer as _, SigningKey};
use mkit_core::hash::{hash, to_hex};
use mkit_core::object::{Blob, ChunkedBlob, Commit, EntryMode, Identity, Object, Tree, TreeEntry};
use mkit_core::pack::PackWriter;
use mkit_core::protocol::RefWriteCondition;
use mkit_core::repo_identity::Namespace;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_core::write_auth::{Context, Operation};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::http_objects::HttpObjectsConfig;
use mkit_server::indexed::IndexedConfig;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig, RequestMeta};
use mkit_server::policy::{NamespacePolicy, WritePolicy};
use mkit_server::upload::{UploadLimits, token::TicketKeys};
use mkit_server::{
    Addressing, BeginUploadResult, BlobKey, BlobStore, ManualClock, MemoryBlobStore, MemoryKv,
    MultiAddressing, NoopMetrics, PackSink, Procedure, RefUpdate,
};
use std::sync::Arc;

pub(crate) const VECTORS: &str = include_str!("../golden/http-objects/content-headers.json");
pub(crate) const CONTENT: &[u8] = b"<html>no sniffing</html>";
pub(crate) type TestPipeline = Pipeline<MemoryBlobStore, Arc<MemoryKv>, Hooks>;

#[allow(clippy::too_many_lines)] // One ticketed indexed fixture, shared by both wire adapters.
pub(crate) async fn fixture() -> (TestPipeline, String, String) {
    let key = KeyPair::from_seed([7; 32]);
    let namespace = Namespace::Ed25519(key.public.0);
    let identity = format!("{namespace}/room");
    let prefix = format!("/{identity}/-/refs/heads/main/-/");
    let mut cfg = PipelineConfig::new(
        Addressing::Multi(
            MultiAddressing::new()
                .with_namespace_policy(NamespacePolicy::Allowlist([namespace].into())),
        ),
        AuthMode::AuthV2(AuthV2Config::new("https://headers.test", "").unwrap()),
        UploadLimits {
            max_total_bytes: 1 << 20,
            max_chunks: 64,
        },
    );
    cfg.write_policy = WritePolicy::Owner;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [8; 32])]).unwrap());
    let mut indexed = IndexedConfig::default();
    indexed.extract_min_bytes = 1024;
    cfg.indexed = Some(indexed);
    cfg.http_objects = Some(HttpObjectsConfig::default());
    let blobs = MemoryBlobStore::default();
    let clock = Arc::new(ManualClock::new(1000));
    let pipe = Pipeline::new(
        blobs.clone(),
        Arc::new(MemoryKv::with_clock(clock.clone())),
        Hooks::new(),
        cfg,
        clock,
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let blob = Object::Blob(Blob {
        data: CONTENT.to_vec(),
    });
    let manifest = Object::ChunkedBlob(ChunkedBlob {
        total_size: CONTENT.len() as u64,
        chunk_size: 0,
        chunks: vec![blob.id().unwrap()],
    });
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let mut entries: Vec<TreeEntry> = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| TreeEntry {
            name: case["name"].as_str().unwrap().as_bytes().to_vec(),
            mode: EntryMode::Blob,
            object_hash: blob.id().unwrap(),
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let files = Object::Tree(Tree { entries });
    let root = Object::Tree(Tree {
        entries: vec![
            TreeEntry {
                name: b"chunked.PDF".to_vec(),
                mode: EntryMode::Blob,
                object_hash: manifest.id().unwrap(),
            },
            TreeEntry {
                name: b"files".to_vec(),
                mode: EntryMode::Tree,
                object_hash: files.id().unwrap(),
            },
        ],
    });
    let mut commit = Commit::new_unannotated(
        root.id().unwrap(),
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"content headers".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &key).unwrap().0;
    let commit = Object::Commit(commit);
    let mut writer = PackWriter::new_raw_only();
    for object in [&blob, &manifest, &files, &root, &commit] {
        writer
            .push_raw(object.id().unwrap(), &serialize(object).unwrap())
            .unwrap();
    }
    let pack = writer.finish().unwrap();
    let pack_id = hash(&pack);
    let counter = std::cell::Cell::new(0_u64);
    let auth = |procedure: Procedure| {
        counter.set(counter.get() + 1);
        let body = b"content headers fixture";
        let commitment = format!("body:{}", to_hex(&hash(body)));
        let nonce = format!("{:064x}", counter.get());
        let operation = Operation {
            context: Context {
                audience: "https://headers.test",
                repository: &identity,
            },
            procedure: procedure.connect_path(),
            commitment: &commitment,
            created_at: 1000,
            expires_at: 60_000,
            nonce: &nonce,
        };
        let signature = SigningKey::from_bytes(&[7; 32]).sign(&operation.digest().unwrap());
        let headers = [
            ("x-envelope-version", "2".into()),
            ("x-audience", "https://headers.test".into()),
            ("x-repository", identity.clone()),
            ("x-public-key", to_hex(&key.public.0)),
            (
                "x-signature",
                mkit_core::hash::to_hex_bytes(&signature.to_bytes()),
            ),
            ("x-content-commitment", commitment),
            ("x-digest", to_hex(&hash(body))),
            ("x-created-at", "1000".into()),
            ("x-expires-at", "60000".into()),
            ("idempotency-key", nonce),
        ];
        pipe.authenticate(&RequestMeta {
            procedure,
            header: &|name| {
                headers
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map(|(_, v)| v.clone())
            },
            header_values: None,
            unary_body: Some(body),
            transport_principal: None,
        })
        .unwrap()
    };
    let BeginUploadResult::Ticket { id: ticket, .. } = pipe
        .begin_upload(
            &auth(Procedure::BeginUpload),
            "refs/heads/main",
            &pack_id,
            pack.len() as u64,
        )
        .await
        .unwrap()
    else {
        panic!("ticket")
    };
    let mut sink = blobs
        .begin(BlobKey::pack(pack_id), pack.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::from(pack)).await.unwrap();
    sink.commit().await.unwrap();
    let marker = [b"mkit-upload-marker:v1\0".as_slice(), &ticket, &pack_id].concat();
    let mut sink = blobs
        .begin(BlobKey::upload_marker(hash(&marker)), marker.len() as u64)
        .await
        .unwrap();
    sink.write(Bytes::from(marker)).await.unwrap();
    sink.commit().await.unwrap();
    let update = |name: &str, id| RefUpdate {
        name: name.into(),
        condition: RefWriteCondition::Missing,
        new: Some(id),
    };
    let outcome = pipe
        .advance_refs_with_tickets(
            &auth(Procedure::AdvanceRefs),
            update("refs/heads/main", commit.id().unwrap()),
            update("refs/mkit/packmap/main", pack_id),
            vec![ticket],
        )
        .await
        .unwrap();
    assert_eq!(outcome, mkit_core::protocol::AdvanceOutcome::Committed);
    let object = format!("/{identity}/-/objects/{}", to_hex(&blob.id().unwrap()));
    (pipe, prefix, object)
}
