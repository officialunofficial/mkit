//! End-to-end test: a real `mkit_transport_connect::serve` axum server,
//! backed by a temp-dir `FileTransport`, driven by a real (non-wasm)
//! `connectrpc` client over a loopback TCP socket.
//!
//! This is the "native connectrpc client end-to-end" round trip the
//! issue-700 Testing Decisions call for. It is deliberately a plain
//! integration test in THIS crate rather than a new public client API —
//! the polished native CLI Connect client is mkit#701's scope (see
//! README.md "What this crate is (and isn't)").

use std::sync::Arc;

use connectrpc::client::{ClientConfig, HttpClient};
use mkit_core::hash::hash;
use mkit_transport_connect::proto::mkit::transport::v1::{
    AdvanceOutcome, DownloadPackRequest, PackExistsRequest, ReadRefRequest, RefExpectation,
    TransportServiceClient, UpdateRefRequest, UploadPackHeader, UploadPackRequest,
};
use mkit_transport_file::FileTransport;
use tempfile::tempdir;
use tokio::net::TcpListener;

type Client = TransportServiceClient<HttpClient>;

async fn start_server() -> (
    Client,
    tempfile::TempDir,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let repo = tempdir().expect("tempdir");
    let transport = Arc::new(FileTransport::new(repo.path()));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(mkit_transport_connect::serve(
        listener,
        transport,
        async move {
            shutdown_rx.await.ok();
        },
    ));

    let uri: http::Uri = format!("http://{addr}").parse().expect("uri");
    let client = TransportServiceClient::new(HttpClient::plaintext(), ClientConfig::new(uri));
    // `repo` (the TempDir guard) is returned so callers keep it alive until
    // after `shutdown()` — dropping it deletes the on-disk repo, which must
    // not happen while the server task might still be serving a request.
    (client, repo, shutdown_tx, handle)
}

async fn shutdown(
    tx: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let _ = tx.send(());
    handle
        .await
        .expect("server task join")
        .expect("server task io result");
}

#[tokio::test]
async fn push_then_pull_round_trip() {
    let (client, _repo, shutdown_tx, handle) = start_server().await;

    // list_refs on an empty repo is empty, not an error.
    let refs = client
        .list_refs(mkit_transport_connect::proto::mkit::transport::v1::ListRefsRequest::default())
        .await
        .expect("list_refs")
        .into_owned();
    assert!(refs.refs.is_empty());

    // pack_exists on an absent digest is false, not an error.
    let missing_id = hash(b"does-not-exist");
    let exists = client
        .pack_exists(PackExistsRequest::default().with_pack_id(missing_id.to_vec()))
        .await
        .expect("pack_exists")
        .into_owned();
    assert_eq!(exists.exists, Some(false));

    // UploadPack: header then one chunk, client-streaming.
    let payload = b"hello mkit connect transport".to_vec();
    let pack_id = hash(&payload);
    let requests = vec![
        UploadPackRequest {
            body: Some(
                UploadPackHeader::default()
                    .with_pack_id(pack_id.to_vec())
                    .with_total_bytes(payload.len() as u64)
                    .into(),
            ),
            ..Default::default()
        },
        UploadPackRequest {
            body: Some(
                mkit_transport_connect::proto::mkit::transport::v1::PackChunk::default()
                    .with_pack_id(pack_id.to_vec())
                    .with_offset(0)
                    .with_data(payload.clone())
                    .with_last(true)
                    .into(),
            ),
            ..Default::default()
        },
    ];
    client.upload_pack(requests).await.expect("upload_pack");

    // pack_exists now true.
    let exists = client
        .pack_exists(PackExistsRequest::default().with_pack_id(pack_id.to_vec()))
        .await
        .expect("pack_exists after upload")
        .into_owned();
    assert_eq!(exists.exists, Some(true));

    // DownloadPack: server-streaming header then chunk(s), reassembled.
    let mut stream = client
        .download_pack(DownloadPackRequest::default().with_pack_id(pack_id.to_vec()))
        .await
        .expect("download_pack");
    let mut collected = Vec::new();
    let mut saw_header = false;
    while let Some(msg) = stream
        .message()
        .await
        .expect("download_pack stream message")
    {
        match msg.to_owned_message().body {
            Some(
                mkit_transport_connect::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body::Header(_),
            ) => saw_header = true,
            Some(
                mkit_transport_connect::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body::Chunk(
                    c,
                ),
            ) => {
                collected.extend_from_slice(&c.data.unwrap_or_default());
                assert_eq!(c.last, Some(true), "single-chunk payload's only chunk is last");
            }
            None => panic!("DownloadPackResponse with neither header nor chunk set"),
        }
    }
    assert!(
        saw_header,
        "DownloadPack MUST send a header before any chunk"
    );
    assert_eq!(collected, payload);

    // update_ref (create-only) then read_ref confirms it landed.
    let commit_id = hash(b"pretend-commit-object");
    client
        .update_ref(
            UpdateRefRequest::default()
                .with_name("refs/heads/main")
                .with_expectation(RefExpectation::REF_EXPECTATION_MISSING)
                .with_new_id(commit_id.to_vec()),
        )
        .await
        .expect("update_ref (create)");

    let read = client
        .read_ref(ReadRefRequest::default().with_name("refs/heads/main"))
        .await
        .expect("read_ref")
        .into_owned();
    assert_eq!(read.exists, Some(true));
    assert_eq!(read.object_id.unwrap_or_default(), commit_id.to_vec());

    let refs = client
        .list_refs(mkit_transport_connect::proto::mkit::transport::v1::ListRefsRequest::default())
        .await
        .expect("list_refs after update_ref")
        .into_owned();
    assert_eq!(refs.refs.len(), 1);
    assert_eq!(refs.refs[0].name.as_deref(), Some("refs/heads/main"));

    shutdown(shutdown_tx, handle).await;
}

#[tokio::test]
async fn update_ref_cas_conflict_surfaces_as_failed_precondition() {
    let (client, _repo, shutdown_tx, handle) = start_server().await;

    let first = hash(b"first");
    client
        .update_ref(
            UpdateRefRequest::default()
                .with_name("refs/heads/main")
                .with_expectation(RefExpectation::REF_EXPECTATION_MISSING)
                .with_new_id(first.to_vec()),
        )
        .await
        .expect("first create");

    // A second MISSING write against an existing ref MUST fail
    // `failed_precondition`, per SPEC-TRANSPORT-CONNECT §3/§5.
    let second = hash(b"second");
    let err = client
        .update_ref(
            UpdateRefRequest::default()
                .with_name("refs/heads/main")
                .with_expectation(RefExpectation::REF_EXPECTATION_MISSING)
                .with_new_id(second.to_vec()),
        )
        .await
        .expect_err("MISSING against an existing ref must fail");
    assert_eq!(err.code, connectrpc::ErrorCode::FailedPrecondition);

    shutdown(shutdown_tx, handle).await;
}

#[tokio::test]
async fn update_ref_rejects_unspecified_expectation() {
    let (client, _repo, shutdown_tx, handle) = start_server().await;

    let err = client
        .update_ref(
            UpdateRefRequest::default()
                .with_name("refs/heads/main")
                .with_new_id(hash(b"x").to_vec()),
        )
        .await
        .expect_err("UNSPECIFIED expectation must be rejected");
    assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);

    shutdown(shutdown_tx, handle).await;
}

#[tokio::test]
async fn download_pack_missing_digest_is_not_found() {
    let (client, _repo, shutdown_tx, handle) = start_server().await;

    // Establishing a Connect server-streaming call returns `Ok` once HTTP
    // headers arrive (200 OK, Connect's normal streaming-response status);
    // the handler's `not_found` — raised before this crate builds any
    // stream item — surfaces via the stream's termination metadata on the
    // first `message()` poll, per `connectrpc`'s client contract. It is
    // still true that no `DownloadPackResponse` message is ever produced,
    // matching SPEC-TRANSPORT-CONNECT §6.2's "never a partial stream".
    let mut stream = client
        .download_pack(DownloadPackRequest::default().with_pack_id(hash(b"nope").to_vec()))
        .await
        .expect("establishing the stream succeeds");
    let err = stream
        .message()
        .await
        .expect_err("absent digest must fail before any stream message");
    assert_eq!(err.code, connectrpc::ErrorCode::NotFound);

    shutdown(shutdown_tx, handle).await;
}

#[tokio::test]
async fn advance_refs_reports_head_conflict_as_typed_outcome_not_error() {
    let (client, _repo, shutdown_tx, handle) = start_server().await;

    let packmap_id = hash(b"packmap-v1");
    let head_id = hash(b"head-v1");
    let resp = client
        .advance_refs(
            mkit_transport_connect::proto::mkit::transport::v1::AdvanceRefsRequest::default()
                .with_head_ref("refs/heads/main")
                .with_head_expectation(RefExpectation::REF_EXPECTATION_MISSING)
                .with_head_new_id(head_id.to_vec())
                .with_packmap_ref("refs/packmaps/main")
                .with_packmap_expectation(RefExpectation::REF_EXPECTATION_MISSING)
                .with_packmap_new_id(packmap_id.to_vec()),
        )
        .await
        .expect("first advance_refs commits")
        .into_owned();
    assert_eq!(
        resp.outcome.and_then(|o| o.as_known()),
        Some(AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED)
    );

    // Someone else advances the head ref underneath us; our next advance,
    // still asserting MISSING on the head, must report HEAD_CONFLICT as a
    // successful RPC with a typed outcome — never a Connect error.
    client
        .update_ref(
            UpdateRefRequest::default()
                .with_name("refs/heads/main")
                .with_expectation(RefExpectation::REF_EXPECTATION_MATCH)
                .with_expected_id(head_id.to_vec())
                .with_new_id(hash(b"head-v2-external").to_vec()),
        )
        .await
        .expect("external head advance");

    let other_packmap = hash(b"packmap-v2");
    let resp = client
        .advance_refs(
            mkit_transport_connect::proto::mkit::transport::v1::AdvanceRefsRequest::default()
                .with_head_ref("refs/heads/main")
                .with_head_expectation(RefExpectation::REF_EXPECTATION_MATCH)
                .with_head_expected_id(head_id.to_vec())
                .with_head_new_id(hash(b"head-v2-mine").to_vec())
                .with_packmap_ref("refs/packmaps/main")
                .with_packmap_expectation(RefExpectation::REF_EXPECTATION_MATCH)
                .with_packmap_expected_id(packmap_id.to_vec())
                .with_packmap_new_id(other_packmap.to_vec()),
        )
        .await
        .expect("advance_refs with a head conflict is still Ok")
        .into_owned();
    assert_eq!(
        resp.outcome.and_then(|o| o.as_known()),
        Some(AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT)
    );

    shutdown(shutdown_tx, handle).await;
}
