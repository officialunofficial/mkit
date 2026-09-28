//! Ticketed `UploadPack` over memory and `SQLite` metadata, all shard layouts.
#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use bytes::Bytes;
use mkit_core::hash::{from_hex, hash};
use mkit_core::protocol::PackKey;
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{
    AuthMode, Authenticated, Hooks, Pipeline, PipelineConfig, RequestMeta, Sharding,
};
use mkit_server::policy::NamespacePolicy;
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{
    Batch, BatchOutcome, BlobKey, BlobStore, Cursor, Key, Partition, PartitionStats, ScanPage,
    StoreCapabilities, StoreError, Value,
};
use mkit_server::upload::{
    UploadLimits,
    token::{TicketClaims, TicketKeys},
};
use mkit_server::{
    Addressing, ManualClock, MemoryBlobStore, MemoryKv, MultiAddressing, NamespaceKey,
    NamespaceStore, NoopMetrics, Procedure, RepoId, RepoName,
};
use mkit_server_conformance::wire::sign::{Signer, pack_commitment};
use mkit_server_native::{Blocking, RusqliteConn};

const AUDIENCE: &str = "http://localhost:9876";
const MARKER_DOMAIN: &[u8] = b"mkit-upload-marker:v1\0";

/// Every metadata method panics. A completed upload therefore proves it never
/// consulted either metadata backend, including less common read methods.
struct NoMeta<N>(N);

impl<N: NamespaceStore> NamespaceStore for NoMeta<N> {
    fn capabilities(&self) -> StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, _: &Partition, _: &Key) -> Result<Option<Value>, StoreError> {
        panic!("ticketed metadata get")
    }
    async fn get_many(&self, _: &Partition, _: &[Key]) -> Result<Vec<Option<Value>>, StoreError> {
        panic!("ticketed metadata get_many")
    }
    async fn scan(
        &self,
        _: &Partition,
        _: &Key,
        _: &Key,
        _: Option<&Cursor>,
        _: u32,
    ) -> Result<ScanPage, StoreError> {
        panic!("ticketed metadata scan")
    }
    async fn apply(&self, _: &Partition, _: Batch) -> Result<BatchOutcome, StoreError> {
        panic!("ticketed metadata apply")
    }
    async fn stats(&self, _: &Partition) -> Result<PartitionStats, StoreError> {
        panic!("ticketed metadata stats")
    }
    async fn probe(&self) -> Result<(), StoreError> {
        panic!("ticketed metadata probe")
    }
}

#[derive(Clone, Copy)]
struct Mode {
    multi: bool,
    sharding: Sharding,
}

impl Mode {
    fn repository(self, signer: &Signer) -> String {
        if self.multi {
            format!("ed25519-{}/demo", signer.public_key_hex())
        } else {
            "tickets".into()
        }
    }
}

fn config(mode: Mode, signer: &Signer) -> PipelineConfig {
    let repository = mode.repository(signer);
    let addressing = if mode.multi {
        Addressing::Multi(
            MultiAddressing::new().with_namespace_policy(NamespacePolicy::Any {
                unsafe_without_admission: true,
            }),
        )
    } else {
        Addressing::Single {
            repo: RepoId {
                namespace: NamespaceKey::deployment_default(),
                name: RepoName::new(&repository).unwrap(),
            },
        }
    };
    let mut cfg = PipelineConfig::new(
        addressing,
        AuthMode::AuthV2(
            AuthV2Config::new(AUDIENCE, if mode.multi { "" } else { "tickets" }).unwrap(),
        ),
        UploadLimits {
            max_total_bytes: 1024,
            max_chunks: 4,
        },
    );
    cfg.sharding = mode.sharding;
    cfg.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [9; 32])]).unwrap());
    cfg
}

fn authenticated<N: NamespaceStore>(
    pipe: &Pipeline<MemoryBlobStore, NoMeta<N>, Hooks>,
    signer: &Signer,
    pack: &[u8],
) -> Authenticated {
    let id = hash(pack);
    let mut envelope = signer.envelope(
        Procedure::UploadPack.connect_path(),
        pack_commitment(&id, pack.len() as u64),
    );
    envelope.created_at = 0;
    envelope.expires_at = 240_000;
    let carriage = signer.sign(&envelope);
    pipe.authenticate(&RequestMeta {
        procedure: Procedure::UploadPack,
        header: &|h| {
            carriage
                .headers
                .iter()
                .find(|(k, _)| k == h)
                .map(|(_, v)| v.clone())
        },
        unary_body: None,
        transport_principal: None,
    })
    .unwrap()
}

async fn stream<N: NamespaceStore>(
    pipe: &Pipeline<MemoryBlobStore, NoMeta<N>, Hooks>,
    signer: &Signer,
    pack: &'static [u8],
    token: &[u8],
) {
    let id = hash(pack);
    let a = authenticated(pipe, signer, pack);
    let mut session = pipe
        .open_ticketed_upload(&a, Some(&id), Some(pack.len() as u64), token)
        .await
        .unwrap();
    session
        .push(Some(&id), Some(0), Bytes::from_static(pack), true)
        .await
        .unwrap();
    tokio::task::yield_now().await;
    session.finish().await.unwrap();
}

fn mint_token(
    keys: &TicketKeys,
    signer: &Signer,
    repository: &str,
    pack: &[u8],
    ticket_id: [u8; 32],
) -> Vec<u8> {
    keys.mint(&TicketClaims {
        ticket_id,
        audience: AUDIENCE.into(),
        repository: repository.into(),
        signer: from_hex(&signer.public_key_hex()).unwrap(),
        pack_id: hash(pack),
        bytes: pack.len() as u64,
        part_size: 8 * 1024 * 1024,
        expires_at_ms: 60_000,
        upload_session: Vec::new(),
    })
}

async fn assert_other_repository_denied<N: NamespaceStore>(
    pipe: &Pipeline<MemoryBlobStore, NoMeta<N>, Hooks>,
    blobs: &MemoryBlobStore,
    keys: &TicketKeys,
    signer: &Signer,
    repository: &str,
    pack: &'static [u8],
) {
    let other_repository = repository.replace("/demo", "/other");
    let other_token = mint_token(keys, signer, &other_repository, pack, [0x44; 32]);
    let a = authenticated(pipe, signer, pack);
    let err = pipe
        .open_ticketed_upload(&a, Some(&hash(pack)), Some(pack.len() as u64), &other_token)
        .await
        .unwrap_err();
    assert_eq!(err.code(), mkit_server::Code::PermissionDenied);
    assert!(
        blobs
            .head(&BlobKey::pack(hash(pack)))
            .await
            .unwrap()
            .is_none()
    );
}

async fn scenario<N: NamespaceStore>(backend: N, mode: Mode) {
    let owner = Signer::new([1; 32], AUDIENCE, "unused");
    let repository = mode.repository(&owner);
    let signer = Signer::new([1; 32], AUDIENCE, &repository);
    let cfg = config(mode, &signer);
    let keys = cfg.ticket_keys.clone().unwrap();
    let blobs = MemoryBlobStore::default();
    let pipe = Pipeline::new(
        blobs.clone(),
        NoMeta(backend),
        Hooks::new(),
        cfg,
        Arc::new(ManualClock::new(0)),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    let pack = b"ticketed full pack";
    let id = hash(pack);
    let ticket_id = [0x55; 32];
    let token = mint_token(&keys, &signer, &repository, pack, ticket_id);
    let mut marker_content = Vec::from(MARKER_DOMAIN);
    marker_content.extend_from_slice(&ticket_id);
    marker_content.extend_from_slice(&id);
    let marker = BlobKey::upload_marker(hash(&marker_content));
    if mode.multi {
        assert_other_repository_denied(&pipe, &blobs, &keys, &signer, &repository, pack).await;
    }
    // Two first writes can reach the put-if-absent store together. In Multi mode
    // each repository has its own ticket proof for the same global pack.
    let second_owner = Signer::new([2; 32], AUDIENCE, "unused");
    let other_repository = mode.repository(&second_owner);
    let other_signer = Signer::new([2; 32], AUDIENCE, &other_repository);
    let other_ticket_id = [0x66; 32];
    let other_token = mint_token(
        &keys,
        &other_signer,
        &other_repository,
        pack,
        other_ticket_id,
    );
    let other_marker = {
        let mut content = Vec::from(MARKER_DOMAIN);
        content.extend_from_slice(&other_ticket_id);
        content.extend_from_slice(&id);
        BlobKey::upload_marker(hash(&content))
    };
    let second = if mode.multi { &other_signer } else { &signer };
    let second_token = if mode.multi { &other_token } else { &token };
    tokio::join!(
        stream(&pipe, &signer, pack, &token),
        stream(&pipe, second, pack, second_token),
    );
    assert_eq!(
        blobs
            .head(&BlobKey::from(PackKey::new(id)))
            .await
            .unwrap()
            .unwrap()
            .len,
        pack.len() as u64
    );
    assert!(blobs.head(&marker).await.unwrap().is_some());
    if mode.multi {
        assert_ne!(marker, other_marker);
        assert!(blobs.head(&other_marker).await.unwrap().is_some());
        let a = authenticated(&pipe, &other_signer, pack);
        let err = pipe
            .open_ticketed_upload(&a, Some(&id), Some(pack.len() as u64), &token)
            .await
            .unwrap_err();
        assert_eq!(err.code(), mkit_server::Code::PermissionDenied);
    }
    for _ in 0..2 {
        stream(&pipe, &signer, pack, &token).await;
        assert_eq!(
            blobs.head(&marker).await.unwrap().unwrap().len,
            marker_content.len() as u64
        );
        assert!(
            blobs
                .head(&BlobKey::pack(*marker.hash()))
                .await
                .unwrap()
                .is_none()
        );
    }
    assert!(
        blobs
            .delete(&BlobKey::from(PackKey::new(id)))
            .await
            .unwrap()
    );
    assert!(
        !blobs
            .delete(&BlobKey::from(PackKey::new(id)))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn ticketed_memory_all_layouts_touch_no_metadata() {
    for multi in [false, true] {
        for sharding in [Sharding::Single, Sharding::D34] {
            Box::pin(scenario(MemoryKv::default(), Mode { multi, sharding })).await;
        }
    }
}

#[tokio::test]
async fn ticketed_sqlite_all_layouts_touch_no_metadata() {
    for multi in [false, true] {
        for sharding in [Sharding::Single, Sharding::D34] {
            let dir = tempfile::tempdir().unwrap();
            let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap();
            Box::pin(scenario(
                Blocking::new(SqlKvStore::open(conn).unwrap()),
                Mode { multi, sharding },
            ))
            .await;
        }
    }
}
