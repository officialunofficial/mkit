//! Integration test: a real (in-process) `TransportService` Connect server
//! <-> [`ConnectTransport`] client, driving every `Transport` trait verb
//! through the actual generated codebase.
//!
//! This is the regression gate SPEC-TRANSPORT-CONNECT's testing decisions
//! call for (mkit#701's "Testing Decisions"): a real server implementing
//! the generated `TransportService` trait, not a mock standing in for one.
//! The server here is memory-backed (`mkit-transport-memory::MemoryTransport`)
//! rather than the production R2/DO-backed reference Worker (a separate,
//! sibling issue, mkit#699) — but the wire path (real HTTP, real protobuf
//! framing, real Connect streaming) is identical.

use std::sync::Arc;
use std::sync::mpsc;

use connectrpc::server::Server;
use connectrpc::{
    ConnectError, ErrorCode, RequestContext, Response, Router, ServiceRequest, ServiceResult,
    ServiceStream,
};
use futures::StreamExt;
use mkit_core::hash::hash as blake3_hash;
use mkit_core::protocol::{AdvanceOutcome, PackKey, RefWriteCondition, Transport, TransportError};
use mkit_transport_connect::{ConnectTransport, generated};
use mkit_transport_memory::MemoryTransport;

use generated::__buffa::oneof::upload_pack_request::Body as UploadBody;

// ---------------------------------------------------------------------------
// Server-side TransportError -> ConnectError (forward direction of
// SPEC-TRANSPORT-CONNECT §5's table). Test-only, but mirrors what a real
// server (mkit#699) must implement.
// ---------------------------------------------------------------------------

fn to_connect_error(err: TransportError) -> ConnectError {
    match err {
        TransportError::PackNotFound => ConnectError::not_found("pack not found"),
        TransportError::AccessDenied => ConnectError::permission_denied("access denied"),
        TransportError::RefConflict => ConnectError::failed_precondition("ref CAS conflict"),
        TransportError::InvalidRef(msg) => ConnectError::invalid_argument(msg),
        TransportError::PayloadTooLarge(n) => {
            ConnectError::resource_exhausted(format!("payload too large: {n} bytes"))
        }
        TransportError::ProtocolError => ConnectError::invalid_argument("protocol error"),
        TransportError::ServerError { status } if status >= 500 || status == 429 => {
            ConnectError::unavailable(format!("server error {status}"))
        }
        TransportError::ServerError { status } => {
            ConnectError::unknown(format!("server error {status}"))
        }
        TransportError::RemoteError(msg) => ConnectError::unknown(msg),
        TransportError::ConnectionFailed
        | TransportError::InvalidResponse
        | TransportError::InsecureScheme => ConnectError::new(
            ErrorCode::Internal,
            "unexpected client-only error surfaced server-side",
        ),
    }
}

fn to_hash(bytes: Option<Vec<u8>>) -> Result<mkit_core::hash::Hash, ConnectError> {
    let bytes = bytes.ok_or_else(|| ConnectError::invalid_argument("missing 32-byte digest"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| ConnectError::invalid_argument("digest must be exactly 32 bytes"))
}

fn wire_to_condition(
    expectation: Option<buffa::EnumValue<generated::RefExpectation>>,
    expected_id: Option<Vec<u8>>,
) -> Result<RefWriteCondition, ConnectError> {
    match expectation.and_then(|e| e.as_known()) {
        Some(generated::RefExpectation::Any) => Ok(RefWriteCondition::Any),
        Some(generated::RefExpectation::Missing) => Ok(RefWriteCondition::Missing),
        Some(generated::RefExpectation::Match) => {
            let hash = to_hash(expected_id)?;
            Ok(RefWriteCondition::Match(hash))
        }
        _ => Err(ConnectError::invalid_argument(
            "REF_EXPECTATION_UNSPECIFIED",
        )),
    }
}

// ---------------------------------------------------------------------------
// TransportService impl, backed by an in-memory Transport.
// ---------------------------------------------------------------------------

struct TestService {
    inner: Arc<MemoryTransport>,
}

#[allow(refining_impl_trait)]
impl generated::TransportService for TestService {
    async fn list_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::ListRefsRequest>,
    ) -> ServiceResult<generated::ListRefsResponse> {
        let msg = request.to_owned_message();
        let prefix = msg.prefix.unwrap_or_default();
        let refs = self.inner.list_refs(&prefix).map_err(to_connect_error)?;
        Ok(Response::new(generated::ListRefsResponse {
            refs: refs
                .into_iter()
                .map(|r| generated::RefEntry {
                    name: Some(r.name),
                    object_id: Some(r.hash.unwrap_or_default().to_vec()),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }))
    }

    async fn read_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::ReadRefRequest>,
    ) -> ServiceResult<generated::ReadRefResponse> {
        let msg = request.to_owned_message();
        let name = msg.name.unwrap_or_default();
        let current = self.inner.read_ref(&name).map_err(to_connect_error)?;
        Ok(Response::new(generated::ReadRefResponse {
            exists: Some(current.is_some()),
            object_id: current.map(|h| h.to_vec()),
            ..Default::default()
        }))
    }

    async fn update_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::UpdateRefRequest>,
    ) -> ServiceResult<generated::UpdateRefResponse> {
        let msg = request.to_owned_message();
        let name = msg.name.unwrap_or_default();
        let condition = wire_to_condition(msg.expectation, msg.expected_id)?;
        let new_id = to_hash(msg.new_id)?;
        self.inner
            .update_ref(&name, condition, &new_id)
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::UpdateRefResponse::default()))
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::AdvanceRefsRequest>,
    ) -> ServiceResult<generated::AdvanceRefsResponse> {
        let msg = request.to_owned_message();
        let head_ref = msg.head_ref.unwrap_or_default();
        let head_condition = wire_to_condition(msg.head_expectation, msg.head_expected_id)?;
        let head_new = to_hash(msg.head_new_id)?;
        let packmap_ref = msg.packmap_ref.unwrap_or_default();
        let packmap_condition =
            wire_to_condition(msg.packmap_expectation, msg.packmap_expected_id)?;
        let packmap_new = to_hash(msg.packmap_new_id)?;

        let outcome = self
            .inner
            .advance_refs(
                &head_ref,
                head_condition,
                &head_new,
                &packmap_ref,
                packmap_condition,
                &packmap_new,
            )
            .map_err(to_connect_error)?;
        let proto_outcome = match outcome {
            AdvanceOutcome::Committed => generated::AdvanceOutcome::Committed,
            AdvanceOutcome::HeadConflict => generated::AdvanceOutcome::HeadConflict,
            AdvanceOutcome::PackmapConflict => generated::AdvanceOutcome::PackmapConflict,
        };
        Ok(Response::new(generated::AdvanceRefsResponse {
            outcome: Some(proto_outcome.into()),
            ..Default::default()
        }))
    }

    async fn pack_exists(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::PackExistsRequest>,
    ) -> ServiceResult<generated::PackExistsResponse> {
        let msg = request.to_owned_message();
        let key = PackKey::new(to_hash(msg.pack_id)?);
        let exists = self.inner.pack_exists(&key).map_err(to_connect_error)?;
        Ok(Response::new(generated::PackExistsResponse {
            exists: Some(exists),
            ..Default::default()
        }))
    }

    async fn upload_pack(
        &self,
        _ctx: RequestContext,
        mut requests: connectrpc::InboundStream<generated::UploadPackRequest>,
    ) -> ServiceResult<generated::UploadPackResponse> {
        let first = requests
            .next()
            .await
            .ok_or_else(|| ConnectError::invalid_argument("empty UploadPack stream"))??;
        let header = match first.to_owned_message().body {
            Some(UploadBody::Header(h)) => *h,
            _ => {
                return Err(ConnectError::invalid_argument(
                    "first message must be header",
                ));
            }
        };
        let pack_id = header.pack_id.unwrap_or_default();
        let total_bytes = header.total_bytes.unwrap_or(0);

        let mut buf = Vec::new();
        loop {
            let item = requests.next().await.ok_or_else(|| {
                ConnectError::invalid_argument("stream ended before a `last` chunk")
            })??;
            match item.to_owned_message().body {
                Some(UploadBody::Chunk(c)) => {
                    if c.pack_id.as_deref() != Some(pack_id.as_slice()) {
                        return Err(ConnectError::invalid_argument("chunk pack_id mismatch"));
                    }
                    let offset = c.offset.unwrap_or(0);
                    if offset != buf.len() as u64 {
                        return Err(ConnectError::invalid_argument("chunk offset out of order"));
                    }
                    buf.extend_from_slice(&c.data.unwrap_or_default());
                    if c.last.unwrap_or(false) {
                        break;
                    }
                }
                _ => return Err(ConnectError::invalid_argument("expected a chunk message")),
            }
        }
        if buf.len() as u64 != total_bytes {
            return Err(ConnectError::invalid_argument(
                "received byte count does not match header.total_bytes",
            ));
        }
        let key = PackKey::new(to_hash(Some(pack_id))?);
        self.inner
            .upload_pack(&buf, &key)
            .map_err(to_connect_error)?;
        Ok(Response::new(generated::UploadPackResponse::default()))
    }

    async fn download_pack(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, generated::DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<generated::DownloadPackResponse>> {
        let msg = request.to_owned_message();
        let key = PackKey::new(to_hash(msg.pack_id)?);
        let bytes = self.inner.download_pack(&key).map_err(to_connect_error)?;

        #[allow(clippy::cast_possible_truncation)]
        let total_bytes = bytes.len() as u64;
        let header = generated::DownloadPackResponse {
            body: Some(
                generated::DownloadPackHeader {
                    total_bytes: Some(total_bytes),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        let chunk = generated::DownloadPackResponse {
            body: Some(
                generated::PackChunk {
                    pack_id: Some(key.as_bytes().to_vec()),
                    offset: Some(0),
                    data: Some(bytes),
                    last: Some(true),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        Response::stream_ok(futures::stream::iter([Ok(header), Ok(chunk)]))
    }
}

// ---------------------------------------------------------------------------
// Server bootstrap
// ---------------------------------------------------------------------------

/// Bind a real Connect server on an ephemeral loopback port, backed by a
/// fresh in-memory [`MemoryTransport`]. Returns the port, a shutdown
/// trigger, and the server thread's join handle.
fn spawn_server() -> (
    u16,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let (addr_tx, addr_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("build server tokio runtime");
        rt.block_on(async move {
            let bound = Server::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral loopback port");
            let port = bound
                .local_addr()
                .expect("bound server has a local addr")
                .port();
            addr_tx.send(port).expect("send bound port to test thread");

            let service = Arc::new(TestService {
                inner: Arc::new(MemoryTransport::new()),
            });
            let router = Router::new().add_service(service);

            bound
                .serve_with_graceful_shutdown(router, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve TransportService");
        });
    });

    let port = addr_rx.recv().expect("recv bound port");
    (port, shutdown_tx, handle)
}

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

#[test]
fn full_roundtrip_through_real_connect_server() {
    let (port, shutdown, handle) = spawn_server();
    let uri: http::Uri = format!("http://127.0.0.1:{port}")
        .parse()
        .expect("valid loopback URI");
    let client = ConnectTransport::connect_for_test(uri);

    // -- packs --------------------------------------------------------
    let data = b"hello from the real Connect wire, not a mock";
    let key = PackKey::from(blake3_hash(data));
    assert!(!client.pack_exists(&key).expect("pack_exists before upload"));
    client.upload_pack(data, &key).expect("upload_pack");
    assert!(client.pack_exists(&key).expect("pack_exists after upload"));
    assert_eq!(
        client.download_pack(&key).expect("download_pack"),
        data.to_vec()
    );

    // Empty pack — SPEC-TRANSPORT-CONNECT §6.1's "one empty last=true chunk"
    // convention.
    let empty_key = PackKey::from(blake3_hash(b""));
    client
        .upload_pack(b"", &empty_key)
        .expect("upload empty pack");
    assert_eq!(
        client
            .download_pack(&empty_key)
            .expect("download empty pack"),
        Vec::<u8>::new()
    );

    // A larger-than-one-chunk pack, to exercise the multi-chunk path.
    let big_data = vec![0xABu8; 3 * 1024 * 1024]; // 3 MiB > 800 KiB chunk size
    let big_key = PackKey::from(blake3_hash(&big_data));
    client
        .upload_pack(&big_data, &big_key)
        .expect("upload big pack");
    assert_eq!(
        client.download_pack(&big_key).expect("download big pack"),
        big_data
    );

    let missing = PackKey::new([0xEEu8; 32]);
    let err = client.download_pack(&missing).expect_err("missing pack");
    assert!(matches!(err, TransportError::PackNotFound), "{err:?}");

    // -- refs -----------------------------------------------------------
    let h1 = blake3_hash(b"commit-1");
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &h1)
        .expect("create refs/heads/main");
    assert_eq!(
        client.read_ref("refs/heads/main").expect("read_ref"),
        Some(h1)
    );

    let conflict = client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &h1)
        .expect_err("create-only on an existing ref must conflict");
    assert!(
        matches!(conflict, TransportError::RefConflict),
        "{conflict:?}"
    );

    let h2 = blake3_hash(b"commit-2");
    client
        .update_ref("refs/heads/main", RefWriteCondition::Match(h1), &h2)
        .expect("CAS-advance refs/heads/main");
    assert_eq!(
        client
            .read_ref("refs/heads/main")
            .expect("read_ref after CAS"),
        Some(h2)
    );

    client
        .update_ref("refs/tags/v1", RefWriteCondition::Any, &h1)
        .expect("create refs/tags/v1");

    let heads = client.list_refs("refs/heads/").expect("list_refs prefix");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].name, "main");
    assert_eq!(heads[0].hash, Some(h2));

    let all = client.list_refs("").expect("list_refs empty prefix");
    assert_eq!(all.len(), 2);

    // -- advance_refs -----------------------------------------------------
    let packmap_h1 = blake3_hash(b"packmap-1");
    let outcome = client
        .advance_refs(
            "refs/heads/feature",
            RefWriteCondition::Missing,
            &h1,
            "refs/packmaps/feature",
            RefWriteCondition::Missing,
            &packmap_h1,
        )
        .expect("first advance_refs commits cleanly");
    assert_eq!(outcome, AdvanceOutcome::Committed);

    // HeadConflict: a fresh packmap ref succeeds, but the head ref already
    // exists so its Missing precondition fails.
    let head_conflict = client
        .advance_refs(
            "refs/heads/feature",
            RefWriteCondition::Missing,
            &h2,
            "refs/packmaps/feature-2",
            RefWriteCondition::Missing,
            &packmap_h1,
        )
        .expect("advance_refs call succeeds even on a CAS conflict");
    assert_eq!(head_conflict, AdvanceOutcome::HeadConflict);

    // PackmapConflict: a fresh head ref would succeed, but the packmap ref
    // already exists so its Missing precondition fails FIRST (packmap-then-
    // head ordering) — the head ref must be left uncreated.
    let packmap_conflict = client
        .advance_refs(
            "refs/heads/feature-3",
            RefWriteCondition::Missing,
            &h1,
            "refs/packmaps/feature",
            RefWriteCondition::Missing,
            &packmap_h1,
        )
        .expect("advance_refs call succeeds even on a CAS conflict");
    assert_eq!(packmap_conflict, AdvanceOutcome::PackmapConflict);
    assert_eq!(
        client
            .read_ref("refs/heads/feature-3")
            .expect("read_ref after packmap conflict"),
        None,
        "packmap-first ordering must leave the head ref uncreated"
    );

    let _ = shutdown.send(());
    handle.join().expect("server thread joins cleanly");
}
