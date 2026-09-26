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
    AdvanceOutcome as WireOutcome, AdvanceRefsRequest, AdvanceRefsResponse, DownloadPackHeader,
    DownloadPackRequest, DownloadPackResponse, ListRefsRequest, ListRefsResponse, PackChunk,
    PackExistsRequest, PackExistsResponse, ReadRefRequest, ReadRefResponse, RefEntry,
    RefExpectation, TransportService, UpdateRefRequest, UpdateRefResponse, UploadPackRequest,
    UploadPackResponse,
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
/// [`Authenticated`] that [`super::AuthInterceptor`] stored; without it
/// every RPC is `unauthenticated` "missing authorization".
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
        let prefix = request.to_owned_message().prefix.unwrap_or_default();
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
        let a = authenticated(&ctx)?;
        let m = request.to_owned_message();
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
        let a = authenticated(&ctx)?;
        let m = request.to_owned_message();
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
}
