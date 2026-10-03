//! `mkit.transport.v1.TransportService` over the pipeline: decode, one
//! pipeline call inside [`send_wrap`], encode.

use core::fmt;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use buffa::Message as _;
use bytes::Bytes;
use connectrpc::{
    ConnectError, InboundStream, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};
use futures::{StreamExt, stream};
use mkit_core::hash::Hash;
use mkit_core::protocol::{AdvanceOutcome, PackKey};

use super::error::recorded;
use super::proto::mkit::transport::v1::__buffa::oneof::begin_upload_response::Result as BeginResult;
use super::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use super::proto::mkit::transport::v1::__buffa::oneof::issue_object_url_request::Target;
use super::proto::mkit::transport::v1::__buffa::oneof::set_repo_visibility_request::Mode as VisibilityMode;
use super::proto::mkit::transport::v1::__buffa::oneof::upload_pack_request::Body as UploadBody;
use super::proto::mkit::transport::v1::__buffa::oneof::upload_part_request::Msg as PartMsg;
use super::proto::mkit::transport::v1::{
    AdvanceOutcome as WireOutcome, AdvanceRefsRequest, AdvanceRefsResponse, BeginUploadRequest,
    BeginUploadResponse, CompleteUploadRequest, CompleteUploadResponse, DownloadPackHeader,
    DownloadPackRequest, DownloadPackResponse, GetReceiptRequest, GetReceiptResponse,
    GetServerInfoRequest, GetServerInfoResponse, ListRefsRequest, ListRefsResponse, PackChunk,
    PackExistsRequest, PackExistsResponse, ReadRefRequest, ReadRefResponse, RefEntry,
    RefExpectation, TransportService, UpdateRefRequest, UpdateRefResponse, UploadPackRequest,
    UploadPackResponse, UploadPartRequest, UploadPartResponse, UploadTicket,
};
use super::proto::mkit::transport::v1::{
    GetAuthorityGenerationRequest, GetAuthorityGenerationResponse, GetGrantEpochRequest,
    GetGrantEpochResponse, IssueObjectUrlRequest, IssueObjectUrlResponse, RepoVisibility,
    SetAuthorityGenerationRequest, SetAuthorityGenerationResponse, SetGrantEpochRequest,
    SetGrantEpochResponse, SetRepoVisibilityRequest, SetRepoVisibilityResponse,
};
use super::{Shared, authenticated};
use crate::error::ServerError;
use crate::op::RefUpdate;
use crate::pipeline::{
    Authenticated, DownloadChunk, HookSet, Pipeline, ServerInfo, VisibilityRequest,
};
use crate::refs::{DigestField, UnusedExpectedId, condition_from_wire, hash_from_slice};
use crate::replay::{BeginUploadResult, UpdateRefResult};
use crate::rt::{send_wrap, send_wrap_stream};
use crate::store::{MultipartBlobStore, NamespaceStore};
use crate::upload::UploadError;
use crate::url_token::UrlTarget;

/// `TransportService` over a [`Pipeline`]. Each handler takes the
/// [`Authenticated`] that [`super::AuthInterceptor`] stored for existing RPCs;
/// `GetServerInfo` is deliberately unauthenticated. The M2 RPCs remain
/// explicit stubs until their implementing WPs land.
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
    delete: bool,
) -> Result<RefUpdate, ServerError> {
    let expectation = expectation.map_or(0, |e| e.to_i32());
    let expected_id = expected_id.unwrap_or_default();
    let condition = condition_from_wire(expectation, expected_id, UnusedExpectedId::Reject)?;
    let new = if delete {
        if !matches!(condition, mkit_core::refs::RefWriteCondition::Match(_))
            || !new_id.unwrap_or_default().is_empty()
        {
            return Err(ServerError::invalid_argument(
                "delete requires MATCH and an empty new_id",
            ));
        }
        None
    } else {
        Some(hash_from_slice(DigestField::NewId, new_id)?)
    };
    Ok(RefUpdate {
        name: name.unwrap_or_default(),
        condition,
        new,
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
async fn upload<B: MultipartBlobStore, N: NamespaceStore, H: HookSet>(
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
    let token = header.ticket_token.as_deref().unwrap_or_default();
    let mut session = if token.is_empty() {
        pipe.open_upload(a, header.pack_id.as_deref(), header.total_bytes)
            .await?
    } else {
        pipe.open_ticketed_upload(a, header.pack_id.as_deref(), header.total_bytes, token)
            .await?
    };
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

/// Read one part's header before opening its sink, then forward nonempty
/// chunks without buffering the part in the Connect layer.
async fn upload_part<B: MultipartBlobStore, N: NamespaceStore, H: HookSet>(
    pipe: &Pipeline<B, N, H>,
    a: &Authenticated,
    mut requests: InboundStream<UploadPartRequest>,
) -> Result<Vec<u8>, ConnectError> {
    let first = match requests.next().await.transpose() {
        Ok(first) => first,
        Err(err) => {
            pipe.record_part_error(a, &recorded(&err));
            return Err(err);
        }
    };
    let header = match first {
        None => Err(UploadError::HeaderMissing { stream_empty: true }),
        Some(first) => match first.to_owned_message().msg {
            Some(PartMsg::Header(header)) => Ok(*header),
            _ => Err(UploadError::HeaderMissing {
                stream_empty: false,
            }),
        },
    }
    .map_err(|error| {
        ServerError::invalid_argument(error.connect_message().replace("UploadPack", "UploadPart"))
    });
    let header = match header {
        Ok(header) => header,
        Err(err) => {
            pipe.record_part_error(a, &err);
            return Err(err.into());
        }
    };
    let mut session = pipe
        .open_part(
            a,
            header.ticket_token.as_deref().unwrap_or_default(),
            header.index.unwrap_or_default(),
        )
        .await?;
    while let Some(item) = requests.next().await {
        let chunk = match item {
            Ok(message) => match message.to_owned_message().msg {
                Some(PartMsg::Chunk(chunk)) => chunk,
                Some(PartMsg::Header(_)) => {
                    let err =
                        ServerError::invalid_argument("UploadPart: saw a second `header` message");
                    session.abort_with(&err).await;
                    return Err(err.into());
                }
                None => {
                    let err = ServerError::invalid_argument(
                        "UploadPart: message with neither `header` nor `chunk` set",
                    );
                    session.abort_with(&err).await;
                    return Err(err.into());
                }
            },
            Err(err) => {
                session.abort_with(&recorded(&err)).await;
                return Err(err);
            }
        };
        if let Err(err) = session.push(Bytes::from(chunk)).await {
            session.abort_with(&err).await;
            return Err(err.into());
        }
    }
    session.finish().await.map_err(Into::into)
}

#[allow(refining_impl_trait)]
impl<B, N, H> TransportService for ConnectTransport<B, N, H>
where
    B: MultipartBlobStore + 'static,
    N: NamespaceStore + 'static,
    H: HookSet + 'static,
{
    async fn list_repos(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, super::proto::mkit::transport::v1::ListReposRequest>,
    ) -> ServiceResult<super::proto::mkit::transport::v1::ListReposResponse> {
        let a = authenticated(&ctx)?;
        let m = request.to_owned_message();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let token = m
                .page_token
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|s| {
                    if s.len() > 512 {
                        return Err(ServerError::invalid_argument(
                            "invalid repository page token",
                        ));
                    }
                    URL_SAFE_NO_PAD
                        .decode(s)
                        .map_err(|_| ServerError::invalid_argument("invalid repository page token"))
                })
                .transpose()?;
            let page = pipe
                .list_repos_page(
                    &a,
                    m.namespace.as_deref().unwrap_or_default(),
                    m.name_prefix.as_deref().unwrap_or_default(),
                    m.page_size,
                    token.as_deref(),
                )
                .await?;
            let response = super::proto::mkit::transport::v1::ListReposResponse {
                repos: page
                    .repos
                    .into_iter()
                    .map(|entry| super::proto::mkit::transport::v1::RepoEntry {
                        name: Some(entry.name),
                        visibility: Some(
                            if entry.visibility == crate::pipeline::RepoVisibility::Public {
                                RepoVisibility::REPO_VISIBILITY_PUBLIC
                            } else {
                                RepoVisibility::REPO_VISIBILITY_PRIVATE
                            }
                            .into(),
                        ),
                        ..Default::default()
                    })
                    .collect(),
                next_page_token: page.next.map(|bytes| URL_SAFE_NO_PAD.encode(bytes)),
                ..Default::default()
            };
            if response.encoded_len() > 64 * 1024 {
                return Err(ServerError::unavailable("repository listing unavailable").into());
            }
            Response::ok(response)
        })
        .await
    }

    async fn list_refs(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, ListRefsRequest>,
    ) -> ServiceResult<ListRefsResponse> {
        let a = authenticated(&ctx)?;
        let m = request.to_owned_message();
        let prefix = m.prefix.unwrap_or_default();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let token = m
                .page_token
                .as_deref()
                .filter(|t| !t.is_empty())
                .map(|t| {
                    if t.len() > 730 {
                        return Err(ServerError::invalid_argument("invalid page token"));
                    }
                    URL_SAFE_NO_PAD
                        .decode(t)
                        .map_err(|_| ServerError::invalid_argument("invalid page token"))
                })
                .transpose()
                .map_err(ConnectError::from)?;
            let page = pipe
                .list_refs_page(&a, &prefix, m.page_size, token.as_deref())
                .await?;
            let refs = page.refs.into_iter().map(|entry| RefEntry {
                name: Some(entry.name),
                object_id: Some(entry.id.to_vec()),
                ..Default::default()
            });
            let response = ListRefsResponse {
                refs: refs.collect(),
                next_page_token: page.next.map(|bytes| URL_SAFE_NO_PAD.encode(bytes)),
                ..Default::default()
            };
            if response.encoded_len() > 2 * 1024 * 1024 {
                return Err(ServerError::unavailable("ref listing unavailable").into());
            }
            Response::ok(response)
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
            m.delete.unwrap_or(false),
        )?;
        let pipe = self.pipe.arc();
        send_wrap(async move {
            match pipe.update_ref_with_meta(&a, upd).await? {
                (UpdateRefResult::Committed, meta) => {
                    let mut response = Response::new(UpdateRefResponse::default());
                    for (name, value) in meta.headers() {
                        response = response.with_header(name, value);
                    }
                    Ok(response)
                }
                // SPEC-TRANSPORT-CONNECT §3: the response never carries the
                // current value.
                (UpdateRefResult::Conflict { .. }, _) => Err(ServerError::failed_precondition(
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
        let delete = m.delete.unwrap_or(false);
        if delete && !m.ticket_ids.is_empty() {
            return Err(ServerError::invalid_argument("delete consumes no tickets").into());
        }
        if m.ticket_ids.len() > crate::store::outbox::MAX_TICKETS_PER_ADVANCE {
            return Err(ServerError::invalid_argument("too many tickets in one advance").into());
        }
        let mut tickets = Vec::with_capacity(m.ticket_ids.len());
        for raw in &m.ticket_ids {
            let id: [u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| ServerError::invalid_argument("ticket id must be 32 bytes"))?;
            if tickets.contains(&id) {
                return Err(ServerError::invalid_argument("duplicate ticket id").into());
            }
            tickets.push(id);
        }
        let head = ref_update(
            m.head_ref,
            m.head_expectation,
            m.head_expected_id.as_deref(),
            m.head_new_id.as_deref(),
            delete,
        )?;
        let packmap = ref_update(
            m.packmap_ref,
            m.packmap_expectation,
            m.packmap_expected_id.as_deref(),
            m.packmap_new_id.as_deref(),
            delete,
        )?;
        let pipe = self.pipe.arc();
        send_wrap(async move {
            // A conflict is a typed outcome, never an error (§4).
            let (outcome, meta) = pipe
                .advance_refs_with_tickets_with_meta(&a, head, packmap, tickets)
                .await?;
            let outcome = match outcome {
                AdvanceOutcome::Committed => WireOutcome::ADVANCE_OUTCOME_COMMITTED,
                AdvanceOutcome::HeadConflict => WireOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT,
                AdvanceOutcome::PackmapConflict => WireOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT,
            };
            let mut response = Response::new(AdvanceRefsResponse {
                outcome: Some(outcome.into()),
                ..Default::default()
            });
            for (name, value) in meta.headers() {
                response = response.with_header(name, value);
            }
            Ok(response)
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
        // SECURITY: deliberately unauthenticated and outside Procedure; it
        // never resolves a repository or reads its state (STC §2.1).
        let info = self.pipe.get().server_info();
        Ok(Response::new(info.into()).with_header("cache-control", "private, max-age=60"))
    }

    async fn get_receipt(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, GetReceiptRequest>,
    ) -> ServiceResult<GetReceiptResponse> {
        // WP-5.8 implements receipt retention and writer-view retrieval.
        Err(not_yet().into())
    }

    async fn begin_upload(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, BeginUploadRequest>,
    ) -> ServiceResult<BeginUploadResponse> {
        let a = authenticated(&ctx)?;
        let message = request.to_owned_message();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let (result, meta) = pipe
                .begin_upload_with_meta(
                    &a,
                    &message.r#ref.unwrap_or_default(),
                    message.pack_id.as_deref().unwrap_or_default(),
                    message.bytes.unwrap_or_default(),
                )
                .await?;
            let result = match result {
                BeginUploadResult::AlreadyPresent => BeginResult::AlreadyPresent(Box::default()),
                BeginUploadResult::Ticket {
                    id,
                    part_size,
                    expires_at_ms,
                    token,
                } => {
                    let expires_unix_ms = i64::try_from(expires_at_ms).map_err(|_| {
                        ServerError::internal(
                            "upload ticket expiry exceeds wire clock",
                            expires_at_ms,
                        )
                    })?;
                    BeginResult::Ticket(Box::new(UploadTicket {
                        id: Some(id.to_vec()),
                        part_size: Some(part_size),
                        expires_unix_ms: Some(expires_unix_ms),
                        token: Some(token),
                        ..Default::default()
                    }))
                }
            };
            let mut response = Response::new(BeginUploadResponse {
                result: Some(result),
                ..Default::default()
            });
            for (name, value) in meta.headers() {
                response = response.with_header(name, value);
            }
            Ok(response)
        })
        .await
    }

    async fn upload_part(
        &self,
        ctx: RequestContext,
        requests: InboundStream<UploadPartRequest>,
    ) -> ServiceResult<UploadPartResponse> {
        let a = authenticated(&ctx)?;
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let receipt = upload_part(&pipe, &a, requests).await?;
            Response::ok(UploadPartResponse {
                receipt: Some(receipt),
                ..Default::default()
            })
        })
        .await
    }

    async fn complete_upload(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, CompleteUploadRequest>,
    ) -> ServiceResult<CompleteUploadResponse> {
        let a = authenticated(&ctx)?;
        let message = request.to_owned_message();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            pipe.complete_upload(
                &a,
                message.ticket_token.as_deref().unwrap_or_default(),
                &message.receipts,
            )
            .await?;
            Response::ok(CompleteUploadResponse::default())
        })
        .await
    }

    async fn get_grant_epoch(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetGrantEpochRequest>,
    ) -> ServiceResult<GetGrantEpochResponse> {
        // Unsigned by design: no repository selector or auth headers are read.
        let message = request.to_owned_message();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let epoch = pipe
                .get_grant_epoch(message.namespace.as_deref().unwrap_or_default())
                .await?;
            Response::ok(GetGrantEpochResponse {
                epoch: Some(epoch),
                ..Default::default()
            })
        })
        .await
    }

    async fn set_grant_epoch(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SetGrantEpochRequest>,
    ) -> ServiceResult<SetGrantEpochResponse> {
        // Unsigned forever: the owner statement is its sole authorization.
        let message = request.to_owned_message();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let epoch = pipe
                .set_grant_epoch(message.signed_statement.as_deref().unwrap_or_default())
                .await?;
            Response::ok(SetGrantEpochResponse {
                epoch: Some(epoch),
                ..Default::default()
            })
        })
        .await
    }

    async fn get_authority_generation(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, GetAuthorityGenerationRequest>,
    ) -> ServiceResult<GetAuthorityGenerationResponse> {
        // Unsigned by design: no repository selector or auth headers are read.
        let message = request.to_owned_message();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let generation = pipe
                .get_authority_generation(message.namespace.as_deref().unwrap_or_default())
                .await?;
            Response::ok(GetAuthorityGenerationResponse {
                generation: Some(generation),
                ..Default::default()
            })
        })
        .await
    }

    async fn set_authority_generation(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, SetAuthorityGenerationRequest>,
    ) -> ServiceResult<SetAuthorityGenerationResponse> {
        // Unsigned forever: the deployment-authority statement is its sole authorization.
        let message = request.to_owned_message();
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let generation = pipe
                .set_authority_generation(message.signed_statement.as_deref().unwrap_or_default())
                .await?;
            Response::ok(SetAuthorityGenerationResponse {
                generation: Some(generation),
                ..Default::default()
            })
        })
        .await
    }

    async fn set_repo_visibility(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, SetRepoVisibilityRequest>,
    ) -> ServiceResult<SetRepoVisibilityResponse> {
        let a = authenticated(&ctx)?;
        let req = match request.to_owned_message().mode {
            Some(VisibilityMode::Visibility(visibility)) => match visibility.as_known() {
                Some(RepoVisibility::REPO_VISIBILITY_PUBLIC) => {
                    VisibilityRequest::Envelope(mkit_attest::grant::Visibility::Public)
                }
                Some(RepoVisibility::REPO_VISIBILITY_PRIVATE) => {
                    VisibilityRequest::Envelope(mkit_attest::grant::Visibility::Private)
                }
                _ => return Err(ServerError::invalid_argument("invalid visibility").into()),
            },
            Some(VisibilityMode::SignedStatement(statement)) => {
                VisibilityRequest::Statement(statement)
            }
            None => {
                return Err(
                    ServerError::invalid_argument("SetRepoVisibility requires a mode").into(),
                );
            }
        };
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let meta = pipe.set_repo_visibility_with_meta(&a, req).await?;
            let mut response = Response::new(SetRepoVisibilityResponse::default());
            for (name, value) in meta.headers() {
                response = response.with_header(name, value);
            }
            Ok(response)
        })
        .await
    }

    async fn issue_object_url(
        &self,
        ctx: RequestContext,
        request: ServiceRequest<'_, IssueObjectUrlRequest>,
    ) -> ServiceResult<IssueObjectUrlResponse> {
        let a = authenticated(&ctx)?;
        let message = request.to_owned_message();
        let invalid = || ServerError::invalid_argument("invalid object URL target");
        let target = match message.target {
            Some(Target::ObjectId(id)) => {
                UrlTarget::Object(Hash::try_from(id.as_slice()).map_err(|_| invalid())?)
            }
            Some(Target::RefPath(path)) => UrlTarget::path(
                path.r#ref.unwrap_or_default(),
                path.path.unwrap_or_default(),
            )
            .map_err(|_| invalid())?,
            None => {
                return Err(
                    ServerError::invalid_argument("IssueObjectUrl requires a target").into(),
                );
            }
        };
        let pipe = self.pipe.arc();
        send_wrap(async move {
            let minted = pipe
                .issue_object_url(&a, target, message.ttl_seconds.unwrap_or_default())
                .await?;
            Response::ok(IssueObjectUrlResponse {
                token: Some(minted.expose().to_owned()),
                expires_unix_ms: Some(minted.expires_at_ms),
                ..Default::default()
            })
        })
        .await
    }
}

impl From<ServerInfo> for GetServerInfoResponse {
    fn from(info: ServerInfo) -> Self {
        Self {
            protocol: Some(info.protocol.into()),
            spec_version: Some(info.spec_version),
            max_pack_bytes: Some(info.max_pack_bytes),
            part_size: Some(info.part_size),
            max_parts: Some(info.max_parts),
            max_list_refs_page_size: Some(info.max_list_refs_page_size),
            begin_upload_threshold_bytes: Some(info.begin_upload_threshold_bytes),
            atomic_advance: Some(info.atomic_advance),
            indexed_mode: Some(info.indexed_mode),
            admission: Some(info.admission),
            receipt_public_key: Some(info.receipt_public_key),
            receipt_key_id: Some(info.receipt_key_id),
            grant_schemes: info.grant_schemes,
            namespace_policy: Some(info.namespace_policy.into()),
            index_fanout: Some(info.index_fanout),
            max_delta_chain_depth: Some(info.max_delta_chain_depth),
            leases: Some(info.capabilities.leases),
            // Launch inspection is synchronous only (SPEC-SERVER §18).
            async_inspection: Some(false),
            inspection_max_objects: info.inspection_max_objects,
            __buffa_unknown_fields: buffa::UnknownFields::default(),
        }
    }
}

#[cfg(test)]
mod proto_roundtrip {
    use super::super::proto::mkit::transport::v1::__buffa::oneof::{
        begin_upload_response::Result as BeginResult, upload_part_request::Msg as PartMsg,
    };
    use super::super::proto::mkit::transport::v1::*;
    use super::ServerInfo;
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
    fn admission_challenge_roundtrips_with_zero_one_and_eight_entries() {
        for count in [0, 1, 8] {
            let message = AdmissionChallenge {
                challenges: (0..count)
                    .map(|index| Challenge {
                        scheme: Some(format!("scheme{index}")),
                        value: Some(format!("opaque-{index}")),
                        ..Default::default()
                    })
                    .collect(),
                description: (count != 0).then(|| "Admission required".into()),
                ..Default::default()
            };
            roundtrip(&message);
            let json = serde_json::to_vec(&message).expect("serialize challenge");
            assert_eq!(
                serde_json::from_slice::<AdmissionChallenge>(&json).expect("parse challenge"),
                message
            );
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
            grant_schemes: vec!["ed25519".into(), "secp256k1-eip191".into()],
            namespace_policy: Some("allowlist".into()),
            index_fanout: Some(4096),
            inspection_max_objects: Some(10_000),
            ..Default::default()
        });
    }

    #[test]
    fn discovery_explicitly_denies_unimplemented_lease_and_async_capabilities() {
        for indexed_mode in [false, true] {
            let response = GetServerInfoResponse::from(ServerInfo {
                capabilities: crate::pipeline::PipelineCapabilities {
                    leases: false,
                    atomic_advance: false,
                },
                protocol: "mkit.transport.v1",
                spec_version: 2,
                max_pack_bytes: 1 << 30,
                part_size: 8 << 20,
                max_parts: 128,
                max_list_refs_page_size: 512,
                begin_upload_threshold_bytes: 0,
                atomic_advance: false,
                indexed_mode,
                admission: false,
                receipt_public_key: Vec::new(),
                receipt_key_id: String::new(),
                grant_schemes: Vec::new(),
                namespace_policy: "allowlist",
                index_fanout: 4096,
                max_delta_chain_depth: if indexed_mode { 50 } else { 0 },
                inspection_max_objects: None,
            });
            roundtrip(&response);
            let json = serde_json::to_value(&response).unwrap();
            assert_eq!(json["leases"], false);
            assert_eq!(json["asyncInspection"], false);
            assert_eq!(json["indexedMode"], indexed_mode);
            assert!(response.receipt_public_key.unwrap().is_empty());
            assert!(response.receipt_key_id.unwrap().is_empty());
        }
    }

    #[test]
    fn inspection_limit_roundtrips_and_is_absent_without_inspection() {
        for limit in [None, Some(10_000)] {
            let response = GetServerInfoResponse {
                inspection_max_objects: limit,
                ..Default::default()
            };
            roundtrip(&response);
            let json = serde_json::to_value(&response).unwrap();
            assert_eq!(
                json.get("inspectionMaxObjects"),
                limit.map(serde_json::Value::from).as_ref()
            );
            assert_eq!(
                serde_json::from_value::<GetServerInfoResponse>(json).unwrap(),
                response
            );
        }
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
    fn m2_messages_roundtrip() {
        use super::super::proto::mkit::transport::v1::__buffa::oneof::issue_object_url_request::Target;
        use super::super::proto::mkit::transport::v1::__buffa::oneof::set_repo_visibility_request::Mode;
        use super::super::proto::mkit::transport::v1::{RefPath, RepoVisibility};

        roundtrip(&GetGrantEpochRequest {
            namespace: Some("namespace".into()),
            ..Default::default()
        });
        roundtrip(&GetGrantEpochResponse {
            epoch: Some(42),
            ..Default::default()
        });
        roundtrip(&SetGrantEpochRequest {
            signed_statement: Some("statement.scheme.blob".into()),
            ..Default::default()
        });
        roundtrip(&SetGrantEpochResponse {
            epoch: Some(43),
            ..Default::default()
        });
        for visibility in [
            RepoVisibility::Unspecified,
            RepoVisibility::Public,
            RepoVisibility::Private,
        ] {
            roundtrip(&SetRepoVisibilityRequest {
                mode: Some(Mode::Visibility(visibility.into())),
                ..Default::default()
            });
        }
        roundtrip(&SetRepoVisibilityRequest {
            mode: Some(Mode::SignedStatement("statement.scheme.blob".into())),
            ..Default::default()
        });
        roundtrip(&SetRepoVisibilityResponse::default());
        roundtrip(&IssueObjectUrlRequest {
            target: Some(Target::ObjectId(vec![0x42; 32])),
            ttl_seconds: Some(15),
            ..Default::default()
        });
        let ref_path = RefPath {
            r#ref: Some("refs/heads/main".into()),
            path: Some("dir/file".into()),
            ..Default::default()
        };
        roundtrip(&ref_path);
        roundtrip(&IssueObjectUrlRequest {
            target: Some(Target::RefPath(Box::new(ref_path))),
            ttl_seconds: Some(20),
            ..Default::default()
        });
        roundtrip(&IssueObjectUrlResponse {
            token: Some("signed.token".into()),
            expires_unix_ms: Some(1_700_000_000_000),
            ..Default::default()
        });
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
