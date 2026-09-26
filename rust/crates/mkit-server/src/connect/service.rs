//! `mkit.transport.v1.TransportService` over the pipeline: decode, one
//! pipeline call inside [`send_wrap`], encode.

use core::fmt;
use std::sync::Arc;

use bytes::Bytes;
use connectrpc::{
    ConnectError, InboundStream, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};
use futures::{StreamExt, stream};
use mkit_core::protocol::{AdvanceOutcome, PackKey};

use super::error::recorded;
use super::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use super::proto::mkit::transport::v1::__buffa::oneof::upload_pack_request::Body as UploadBody;
use super::proto::mkit::transport::v1::{
    AdvanceOutcome as WireOutcome, AdvanceRefsRequest, AdvanceRefsResponse, BeginUploadRequest,
    BeginUploadResponse, CompleteUploadRequest, CompleteUploadResponse, DownloadPackHeader,
    DownloadPackRequest, DownloadPackResponse, GetServerInfoRequest, GetServerInfoResponse,
    ListRefsRequest, ListRefsResponse, PackChunk, PackExistsRequest, PackExistsResponse,
    ReadRefRequest, ReadRefResponse, RefEntry, RefExpectation, TransportService, UpdateRefRequest,
    UpdateRefResponse, UploadPackRequest, UploadPackResponse, UploadPartRequest,
    UploadPartResponse,
};
use super::{Shared, authenticated};
use crate::error::ServerError;
use crate::op::RefUpdate;
use crate::pipeline::{Authenticated, DownloadChunk, HookSet, Pipeline};
use crate::refs::{DigestField, UnusedExpectedId, condition_from_wire, hash_from_slice};
use crate::replay::UpdateRefResult;
use crate::rt::{send_wrap, send_wrap_stream};
use crate::store::{BlobStore, NamespaceStore};
use crate::upload::UploadError;

/// `TransportService` over a [`Pipeline`]. Each handler takes the
/// [`Authenticated`] that [`super::AuthInterceptor`] stored for existing RPCs;
/// the M1 discovery and upload RPCs are unauthenticated stubs until their
/// implementing WPs land.
pub struct ConnectTransport<B, N, H> {
    pipe: Shared<Pipeline<B, N, H>>,
}

impl<B, N, H> fmt::Debug for ConnectTransport<B, N, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectTransport").finish_non_exhaustive()
    }
}

impl<B, N, H> ConnectTransport<B, N, H> {
    /// The service over `pipeline`.
    #[must_use]
    pub fn new(pipeline: Arc<Pipeline<B, N, H>>) -> Self {
        Self {
            pipe: Shared::new(pipeline),
        }
    }
}

/// A wire `(name, expectation, expected_id, new_id)` as a [`RefUpdate`].
/// The name is checked by the pipeline.
fn ref_update(
    name: Option<String>,
    expectation: Option<buffa::EnumValue<RefExpectation>>,
    expected_id: Option<&[u8]>,
    new_id: Option<&[u8]>,
) -> Result<RefUpdate, ServerError> {
    let expectation = expectation.map_or(0, |e| e.to_i32());
    let expected_id = expected_id.unwrap_or_default();
    let condition = condition_from_wire(expectation, expected_id, UnusedExpectedId::Reject)?;
    Ok(RefUpdate {
        name: name.unwrap_or_default(),
        condition,
        new: hash_from_slice(DigestField::NewId, new_id)?,
    })
}

fn not_yet() -> ServerError {
    ServerError::unimplemented("not implemented yet")
}

fn pack_key(pack_id: Option<&[u8]>) -> Result<PackKey, ServerError> {
    Ok(PackKey::new(hash_from_slice(DigestField::PackId, pack_id)?))
}

fn download_message(body: DownloadBody) -> DownloadPackResponse {
    DownloadPackResponse {
        body: Some(body),
        ..Default::default()
    }
}

fn chunk_message(pack_id: &[u8], chunk: &DownloadChunk) -> DownloadPackResponse {
    download_message(DownloadBody::Chunk(Box::new(PackChunk {
        pack_id: Some(pack_id.to_vec()),
        offset: Some(chunk.offset),
        data: Some(chunk.data.to_vec()),
        last: Some(chunk.last),
        ..Default::default()
    })))
}

/// Stream `requests` into an upload session: the header, then each chunk
/// up to the `last` one, then `finish`. The caller keeps the pipeline
/// alive across the stream. Reading stops at `last`; connectrpc drains
/// what follows within its bounds.
async fn upload<B: BlobStore, N: NamespaceStore, H: HookSet>(
    pipe: &Pipeline<B, N, H>,
    a: &Authenticated,
    mut requests: InboundStream<UploadPackRequest>,
) -> Result<(), ConnectError> {
    let header = match requests.next().await.transpose()? {
        None => Err(UploadError::HeaderMissing { stream_empty: true }),
        Some(first) => match first.to_owned_message().body {
            Some(UploadBody::Header(header)) => Ok(header),
            _ => Err(UploadError::HeaderMissing {
                stream_empty: false,
            }),
        },
    };
    let header = header.map_err(ServerError::from)?;
    if !header
        .ticket_token
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        // TODO(WP-1.9): implement ticketed UploadPack before reading chunks.
        return Err(not_yet().into());
    }
    let mut session = pipe
        .begin_upload(a, header.pack_id.as_deref(), header.total_bytes)
        .await?;
    while let Some(item) = requests.next().await {
        let chunk = match item.map(|m| m.to_owned_message().body) {
            Ok(Some(UploadBody::Chunk(chunk))) => *chunk,
            // The request is recorded with the code the client receives.
            Ok(body) => {
                let err = ServerError::from(UploadError::UnexpectedMessage {
                    header: body.is_some(),
                });
                session.abort_with(&err).await;
                return Err(err.into());
            }
            Err(e) => {
                session.abort_with(&recorded(&e)).await;
                return Err(e);
            }
        };
        let data = Bytes::from(chunk.data.unwrap_or_default());
        let last = chunk.last.unwrap_or(false);
        match session
            .push(chunk.pack_id.as_deref(), chunk.offset, data, last)
            .await
        {
            Ok(false) => {}
            Ok(true) => break,
            // `push` already recorded `e`; this only discards the sink.
            Err(e) => {
                session.abort_with(&e).await;
                return Err(e.into());
            }
        }
    }
    session.finish().await?;
    Ok(())
}

#[allow(refining_impl_trait)]
impl<B, N, H> TransportService for ConnectTransport<B, N, H>
where
    B: BlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    async fn list_refs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRefsRequest>,
    ) -> ServiceResult<ListRefsResponse> {
        let a = authenticated(&ctx)?;
        let m = request.to_owned_message();
        if !m.page_token.as_deref().unwrap_or_default().is_empty() {
            // TODO(WP-1.28): implement ListRefs continuation tokens.
            return Err(not_yet().into());
        }
        // TODO(WP-1.28): honour page_size and caps
        let prefix = m.prefix.unwrap_or_default();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let refs = pipe.list_refs(&a, &prefix).await?;
            let refs = refs.into_iter().map(|entry| RefEntry {
                name: Some(entry.name),
                object_id: Some(entry.id.to_vec()),
                ..Default::default()
            });
            Response::ok(ListRefsResponse {
                refs: refs.collect(),
                ..Default::default()
            })
        })
        .await
    }

    async fn read_ref(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ReadRefRequest>,
    ) -> ServiceResult<ReadRefResponse> {
        let a = authenticated(&ctx)?;
        let name = request.to_owned_message().name.unwrap_or_default();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let id = pipe.read_ref(&a, &name).await?;
            Response::ok(ReadRefResponse {
                exists: Some(id.is_some()),
                object_id: Some(id.map(|id| id.to_vec()).unwrap_or_default()),
                ..Default::default()
            })
        })
        .await
    }

    async fn update_ref(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, UpdateRefRequest>,
    ) -> ServiceResult<UpdateRefResponse> {
        let m = request.to_owned_message();
        if m.delete.unwrap_or(false) {
            // TODO(WP-1.10): implement ref deletion.
            return Err(not_yet().into());
        }
        let a = authenticated(&ctx)?;
        let upd = ref_update(
            m.name,
            m.expectation,
            m.expected_id.as_deref(),
            m.new_id.as_deref(),
        )?;
        let pipe = self.pipe.arc();
        send_wrap(async move {
            match pipe.update_ref(&a, upd).await? {
                UpdateRefResult::Committed => Response::ok(UpdateRefResponse::default()),
                // SPEC-TRANSPORT-CONNECT §3: the response never carries the
                // current value.
                UpdateRefResult::Conflict { .. } => Err(ServerError::failed_precondition(
                    "ref CAS precondition failed — read_ref to disambiguate",
                )
                .into()),
            }
        })
        .await
    }

    async fn advance_refs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, AdvanceRefsRequest>,
    ) -> ServiceResult<AdvanceRefsResponse> {
        let m = request.to_owned_message();
        if m.delete.unwrap_or(false) || !m.ticket_ids.is_empty() {
            // TODO(WP-1.10): implement ticket consumption and ref deletion.
            return Err(not_yet().into());
        }
        let a = authenticated(&ctx)?;
        let head = ref_update(
            m.head_ref,
            m.head_expectation,
            m.head_expected_id.as_deref(),
            m.head_new_id.as_deref(),
        )?;
        let packmap = ref_update(
            m.packmap_ref,
            m.packmap_expectation,
            m.packmap_expected_id.as_deref(),
            m.packmap_new_id.as_deref(),
        )?;
        let pipe = self.pipe.arc();
        send_wrap(async move {
            // A conflict is a typed outcome, never an error (§4).
            let outcome = match pipe.advance_refs(&a, head, packmap).await? {
                AdvanceOutcome::Committed => WireOutcome::ADVANCE_OUTCOME_COMMITTED,
                AdvanceOutcome::HeadConflict => WireOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT,
                AdvanceOutcome::PackmapConflict => WireOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT,
            };
            Response::ok(AdvanceRefsResponse {
                outcome: Some(outcome.into()),
                ..Default::default()
            })
        })
        .await
    }

    async fn pack_exists(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, PackExistsRequest>,
    ) -> ServiceResult<PackExistsResponse> {
        let a = authenticated(&ctx)?;
        let key = pack_key(request.to_owned_message().pack_id.as_deref())?;
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let exists = pipe.pack_exists(&a, key).await?;
            Response::ok(PackExistsResponse {
                exists: Some(exists),
                ..Default::default()
            })
        })
        .await
    }

    async fn upload_pack(
        &self,
        ctx: RequestContext,
        requests: InboundStream<UploadPackRequest>,
    ) -> ServiceResult<UploadPackResponse> {
        let a = authenticated(&ctx)?;
        // The session borrows the pipeline: this owned handle keeps it
        // alive for the whole stream.
        let pipe = self.pipe.arc();
        send_wrap(async move {
            upload(&pipe, &a, requests).await?;
            Response::ok(UploadPackResponse::default())
        })
        .await
    }

    async fn download_pack(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<DownloadPackResponse>> {
        let a = authenticated(&ctx)?;
        let key = pack_key(request.to_owned_message().pack_id.as_deref())?;
        let pipe = self.pipe.arc();
        // `not_found` and every other failure to open come back here,
        // before any message (§6.2).
        let download = send_wrap(async move { pipe.download(&a, key).await }).await?;
        let header = download_message(DownloadBody::Header(Box::new(DownloadPackHeader {
            total_bytes: Some(download.total_bytes),
            ..Default::default()
        })));
        let chunks = download.chunks.map(move |chunk| {
            chunk
                .map(|c| chunk_message(&key.0, &c))
                .map_err(ConnectError::from)
        });
        Response::stream_ok(stream::iter([Ok(header)]).chain(send_wrap_stream(chunks)))
    }

    async fn get_server_info(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetServerInfoRequest>,
    ) -> ServiceResult<GetServerInfoResponse> {
        // SECURITY: GetServerInfo stays unauthenticated by SPEC-TRANSPORT-CONNECT §2.1.
        // TODO(WP-1.6): implement deployment discovery and add an explicit Procedure variant.
        Err(not_yet().into())
    }

    async fn begin_upload(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, BeginUploadRequest>,
    ) -> ServiceResult<BeginUploadResponse> {
        // SECURITY: unauthenticated until WP-1.9 adds a Procedure variant; the implementing WP MUST add it.
        // TODO(WP-1.9): implement upload tickets.
        Err(not_yet().into())
    }

    async fn upload_part(
        &self,
        _ctx: RequestContext,
        _requests: InboundStream<UploadPartRequest>,
    ) -> ServiceResult<UploadPartResponse> {
        // SECURITY: unauthenticated until WP-1.11 adds a Procedure variant; the implementing WP MUST add it.
        // TODO(WP-1.11): implement part uploads; only connectrpc may read this stream for now.
        Err(not_yet().into())
    }

    async fn complete_upload(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, CompleteUploadRequest>,
    ) -> ServiceResult<CompleteUploadResponse> {
        // SECURITY: unauthenticated until WP-1.11 adds a Procedure variant; the implementing WP MUST add it.
        // TODO(WP-1.11): implement multipart completion.
        Err(not_yet().into())
    }
}

#[cfg(test)]
mod proto_roundtrip {
    use super::super::proto::mkit::transport::v1::__buffa::oneof::{
        begin_upload_response::Result as BeginResult, upload_part_request::Msg as PartMsg,
    };
    use super::super::proto::mkit::transport::v1::*;
    use buffa::Message;

    fn roundtrip<M: Message + PartialEq + core::fmt::Debug>(message: &M) {
        let encoded = message.encode_to_vec();
        assert_eq!(
            &M::decode_from_slice(&encoded).expect("decode generated message"),
            message
        );
    }

    fn ticket() -> UploadTicket {
        UploadTicket {
            id: Some(vec![0x12; 32]),
            part_size: Some(8 << 20),
            expires_unix_ms: Some(1_700_000_000_000),
            token: Some(vec![0xa1, 0xb2]),
            ..Default::default()
        }
    }

    #[test]
    fn discovery_messages_roundtrip() {
        // Empty messages have no declared fields to populate.
        roundtrip(&GetServerInfoRequest::default());
        roundtrip(&GetServerInfoResponse {
            protocol: Some("mkit.transport.v1".into()),
            spec_version: Some(2),
            max_pack_bytes: Some(1 << 34),
            part_size: Some(8 << 20),
            max_parts: Some(1024),
            max_list_refs_page_size: Some(512),
            begin_upload_threshold_bytes: Some(8 << 20),
            atomic_advance: Some(true),
            indexed_mode: Some(true),
            admission: Some(true),
            receipt_public_key: Some(vec![0x34; 32]),
            receipt_key_id: Some("receipt-key".into()),
            grant_schemes: vec!["ed25519".into(), "eip191-secp256k1".into()],
            namespace_policy: Some("allowlist".into()),
            index_fanout: Some(4096),
            ..Default::default()
        });
    }

    #[test]
    fn ticket_messages_and_both_results_roundtrip() {
        roundtrip(&BeginUploadRequest {
            r#ref: Some("refs/heads/main".into()),
            pack_id: Some(vec![0x56; 32]),
            bytes: Some(1 << 33),
            ..Default::default()
        });
        roundtrip(&AlreadyPresent::default());
        roundtrip(&ticket());
        roundtrip(&BeginUploadResponse {
            result: Some(BeginResult::AlreadyPresent(Box::default())),
            ..Default::default()
        });
        roundtrip(&BeginUploadResponse {
            result: Some(BeginResult::Ticket(Box::new(ticket()))),
            ..Default::default()
        });
    }

    #[test]
    fn part_messages_and_both_stream_alternatives_roundtrip() {
        let header = UploadPartHeader {
            ticket_token: Some(vec![0x78, 0x9a]),
            index: Some(3),
            ..Default::default()
        };
        roundtrip(&header);
        roundtrip(&UploadPartRequest {
            msg: Some(PartMsg::Header(Box::new(header))),
            ..Default::default()
        });
        roundtrip(&UploadPartRequest {
            msg: Some(PartMsg::Chunk(vec![0x01, 0x23, 0x45])),
            ..Default::default()
        });
        roundtrip(&UploadPartResponse {
            receipt: Some(vec![0xab, 0xcd]),
            ..Default::default()
        });
        roundtrip(&CompleteUploadRequest {
            ticket_token: Some(vec![0x78, 0x9a]),
            receipts: vec![vec![0xab, 0xcd], vec![0xef, 0x01]],
            ..Default::default()
        });
        roundtrip(&CompleteUploadResponse::default());
    }

    #[test]
    fn additive_fields_roundtrip() {
        roundtrip(&ListRefsRequest {
            prefix: Some("refs/heads/".into()),
            page_size: Some(1),
            page_token: Some("continuation".into()),
            ..Default::default()
        });
        roundtrip(&ListRefsResponse {
            refs: vec![RefEntry {
                name: Some("main".into()),
                object_id: Some(vec![0x23; 32]),
                ..Default::default()
            }],
            next_page_token: Some("next".into()),
            ..Default::default()
        });
        roundtrip(&UpdateRefRequest {
            delete: Some(true),
            ..Default::default()
        });
        roundtrip(&AdvanceRefsRequest {
            ticket_ids: vec![vec![0x45; 32], vec![0x67; 32]],
            delete: Some(true),
            ..Default::default()
        });
        roundtrip(&UploadPackHeader {
            ticket_token: Some(vec![0x89, 0xab]),
            ..Default::default()
        });
    }
}
