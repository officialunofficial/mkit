//! The same signed Multi isolation contract over memory and native `SQLite`.
#![cfg(feature = "sqlite")]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use bytes::Bytes;
use mkit_core::hash::hash;
use mkit_core::protocol::{PackKey, RefWriteCondition};
use mkit_core::repo_identity::Namespace;
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::Hooks;
use mkit_server::pipeline::{AuthMode, Authenticated, Pipeline, PipelineConfig, RequestMeta};
use mkit_server::policy::NamespacePolicy;
use mkit_server::sql::SqlKvStore;
use mkit_server::store::{BlobKey, BlobStore, PackSink};
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, Code, MultiAddressing, NamespaceStore, NoopMetrics, Procedure, RefUpdate,
    SystemClock, UpdateRefResult,
};
use mkit_server::{MemoryBlobStore, MemoryKv};
use mkit_server_conformance::wire::sign::{SignedOp, Signer};
use mkit_server_native::{Blocking, RusqliteConn};

const AUDIENCE: &str = "http://localhost:9876";
const BODY: &[u8] = b"exact request bytes";

fn authenticate<N: NamespaceStore>(
    pipe: &Pipeline<MemoryBlobStore, N>,
    procedure: Procedure,
    headers: &[(String, String)],
) -> Result<Authenticated, mkit_server::ServerError> {
    let lookup = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    pipe.authenticate(&RequestMeta {
        procedure,
        header: &lookup,
        unary_body: Some(BODY),
        transport_principal: None,
    })
}

fn read_auth<N: NamespaceStore>(
    pipe: &Pipeline<MemoryBlobStore, N>,
    procedure: Procedure,
    identity: &str,
) -> Authenticated {
    authenticate(pipe, procedure, &[("x-repository".into(), identity.into())]).unwrap()
}

fn update(name: &str, value: u8) -> RefUpdate {
    RefUpdate {
        name: name.into(),
        condition: RefWriteCondition::Any,
        new: [value; 32],
    }
}

fn namespace(seed: u8) -> String {
    format!(
        "ed25519-{}",
        Signer::new([seed; 32], AUDIENCE, "unused").public_key_hex()
    )
}

async fn isolation<N: NamespaceStore + 'static>(meta: N) {
    let ns_a = namespace(1);
    let ns_b = namespace(2);
    let policy = NamespacePolicy::Allowlist(
        [&ns_a, &ns_b]
            .into_iter()
            .map(|ns| Namespace::parse(ns).unwrap())
            .collect(),
    );
    let auth = AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, "").unwrap());
    let mut config = PipelineConfig::new(
        Addressing::Multi(MultiAddressing::new().with_namespace_policy(policy)),
        auth,
        UploadLimits {
            max_total_bytes: 1024,
            max_chunks: 4,
        },
    );
    config.write_quota = None;
    let blobs = MemoryBlobStore::default();
    let marker_content = b"marker bytes in the separate blob namespace";
    let marker_hash = hash(marker_content);
    let mut sink = blobs
        .begin(
            BlobKey::upload_marker(marker_hash),
            marker_content.len() as u64,
        )
        .await
        .unwrap();
    sink.write(Bytes::from_static(marker_content))
        .await
        .unwrap();
    sink.commit().await.unwrap();
    let pipe = Pipeline::new(
        blobs,
        meta,
        Hooks::new(),
        config,
        Arc::new(SystemClock),
        Arc::new(NoopMetrics),
    )
    .unwrap();
    for (name_a, name_b) in [("one", "two"), ("same", "same"), ("near", "neighbour")] {
        let a = format!("{ns_a}/{name_a}");
        // Also exercise different names inside the SAME namespace partition.
        let b = format!("{}/{name_b}", if name_a == "near" { &ns_a } else { &ns_b });
        isolated_pair(&pipe, &a, &b).await;
        missing_and_pack_guards(&pipe, &ns_a, &a, marker_hash).await;
    }
}

async fn isolated_pair<N: NamespaceStore>(pipe: &Pipeline<MemoryBlobStore, N>, a: &str, b: &str) {
    let writer_a = Signer::new([1; 32], AUDIENCE, a);
    let writer_b = Signer::new(
        [if b.starts_with(&namespace(1)) { 1 } else { 2 }; 32],
        AUDIENCE,
        b,
    );
    let procedure = Procedure::UpdateRef;
    let mut envelope = writer_a.envelope(
        procedure.connect_path(),
        mkit_server_conformance::wire::sign::body_commitment(BODY),
    );
    // The same nonce must be isolated across repositories, including the same
    // signer in the near/neighbour pair within one namespace.
    envelope.nonce = "c".repeat(64);
    envelope.digest = Some(mkit_core::hash::to_hex(&mkit_core::hash::hash(BODY)));
    let signed_a = writer_a.sign(&envelope);
    envelope.repository = b.to_owned();
    let signed_b = writer_b.sign(&envelope);
    for (identity, signed, ref_name, value) in [
        (a, &signed_a, "refs/heads/a", 1),
        (b, &signed_b, "refs/heads/b", 2),
    ] {
        let authenticated = authenticate(pipe, procedure, &signed.headers).unwrap();
        assert_eq!(authenticated.repo().identity, identity);
        assert_eq!(
            pipe.update_ref(&authenticated, update(ref_name, value))
                .await
                .unwrap(),
            UpdateRefResult::Committed
        );
    }
    for (identity, mine, other, value) in [(a, "a", "b", 1), (b, "b", "a", 2)] {
        let refs = pipe
            .list_refs(
                &read_auth(pipe, Procedure::ListRefs, identity),
                "refs/heads",
            )
            .await
            .unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, mine);
        assert_eq!(refs[0].id, [value; 32]);
        let read = read_auth(pipe, Procedure::ReadRef, identity);
        assert_eq!(
            pipe.read_ref(&read, &format!("refs/heads/{mine}"))
                .await
                .unwrap(),
            Some([value; 32])
        );
        assert_eq!(
            pipe.read_ref(&read, &format!("refs/heads/{other}"))
                .await
                .unwrap(),
            None
        );
    }
    let tampered = signed_a.clone().with_header("x-repository", b);
    assert_eq!(
        authenticate(pipe, procedure, &tampered.headers)
            .unwrap_err()
            .code(),
        Code::Unauthenticated
    );
    // Tampering cannot affect B, and a replay under A still returns A's answer.
    let authenticated = authenticate(pipe, procedure, &signed_a.headers).unwrap();
    assert_eq!(
        pipe.update_ref(&authenticated, update("refs/heads/a", 1))
            .await
            .unwrap(),
        UpdateRefResult::Committed
    );
}

async fn missing_and_pack_guards<N: NamespaceStore>(
    pipe: &Pipeline<MemoryBlobStore, N>,
    ns_a: &str,
    existing: &str,
    marker_hash: [u8; 32],
) {
    let missing = format!("{ns_a}/missing");
    assert_eq!(
        pipe.list_refs(&read_auth(pipe, Procedure::ListRefs, &missing), "refs")
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        pipe.read_ref(
            &read_auth(pipe, Procedure::ReadRef, &missing),
            "refs/heads/a"
        )
        .await
        .unwrap_err()
        .code(),
        Code::NotFound
    );
    for identity in [existing, &missing] {
        let exists = pipe
            .pack_exists(
                &read_auth(pipe, Procedure::PackExists, identity),
                PackKey([42; 32]),
            )
            .await;
        if identity == existing {
            assert!(!exists.unwrap());
        } else {
            assert_eq!(exists.unwrap_err().code(), Code::NotFound);
        }
        assert_eq!(
            pipe.download(
                &read_auth(pipe, Procedure::DownloadPack, identity),
                PackKey([42; 32])
            )
            .await
            .err()
            .unwrap()
            .code(),
            Code::NotFound
        );
        let upload: SignedOp = Signer::new([1; 32], AUDIENCE, identity).sign_pack(
            Procedure::UploadPack.connect_path(),
            &[42; 32],
            0,
        );
        let authenticated = authenticate(pipe, Procedure::UploadPack, &upload.headers).unwrap();
        assert_eq!(
            pipe.open_upload(&authenticated, Some(&[42; 32]), Some(0))
                .await
                .err()
                .unwrap()
                .code(),
            Code::FailedPrecondition
        );
    }
    let marker_key = PackKey(marker_hash);
    assert!(
        !pipe
            .pack_exists(
                &read_auth(pipe, Procedure::PackExists, existing),
                marker_key
            )
            .await
            .unwrap()
    );
    assert_eq!(
        pipe.download(
            &read_auth(pipe, Procedure::DownloadPack, existing),
            marker_key,
        )
        .await
        .unwrap_err()
        .code(),
        Code::NotFound
    );
}

#[tokio::test]
async fn multi_repository_isolation_memory() {
    Box::pin(isolation(MemoryKv::default())).await;
}

#[tokio::test]
async fn multi_repository_isolation_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let conn = RusqliteConn::open(dir.path().join("meta.sqlite3")).unwrap();
    Box::pin(isolation(Blocking::new(SqlKvStore::open(conn).unwrap()))).await;
}
