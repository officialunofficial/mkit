//! [`TransportServer`] — a `mkit.transport.v1.TransportService` Connect
//! handler generic over any [`Transport`] backend.
//!
//! Every unary RPC runs the wrapped [`Transport`] call inside
//! [`tokio::task::spawn_blocking`]: `Transport`'s methods are synchronous
//! (`FileTransport`'s `Match` CAS path takes an OS file lock), so running
//! them directly on the async executor thread would stall every other
//! in-flight request on that thread for the duration of the I/O.

use std::sync::Arc;

use connectrpc::{
    ConnectError, InboundStream, RequestContext, Response, ServiceRequest, ServiceResult,
    ServiceStream,
};
use mkit_core::protocol::{AdvanceOutcome as TransportAdvanceOutcome, PackKey, Transport};

use crate::error::map_transport_error;
use crate::hashutil::hash_from_slice;
use crate::pack::{chunk_download, drain_upload};
use crate::proto::mkit::transport::v1::{
    AdvanceOutcome, AdvanceRefsRequest, AdvanceRefsResponse, DownloadPackRequest,
    DownloadPackResponse, ListRefsRequest, ListRefsResponse, PackExistsRequest, PackExistsResponse,
    ReadRefRequest, ReadRefResponse, RefEntry, TransportService, UpdateRefRequest,
    UpdateRefResponse, UploadPackRequest, UploadPackResponse,
};
use crate::refs_convert::condition_from_wire;

/// Run a blocking [`Transport`] call on tokio's blocking thread pool and
/// translate its [`TransportError`](mkit_core::protocol::TransportError)
/// into a [`ConnectError`] per SPEC-TRANSPORT-CONNECT §5.
///
/// `pub(crate)` so [`crate::health`]'s [`Transport`]-backed health checker
/// (mkit#796) reuses the exact same spawn_blocking + error-mapping path
/// every RPC handler in this file already goes through, rather than a
/// second hand-rolled copy.
pub(crate) async fn blocking<T, F, R>(transport: Arc<T>, f: F) -> Result<R, ConnectError>
where
    T: Transport + Send + Sync + 'static,
    F: FnOnce(&T) -> mkit_core::protocol::TransportResult<R> + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(move || f(&transport))
        .await
        .map_err(|e| ConnectError::internal(format!("transport task panicked: {e}")))?
        .map_err(map_transport_error)
}

/// A `mkit.transport.v1.TransportService` server wrapping any
/// [`Transport`] backend — the "reuse the same trait every other
/// transport already implements" design SPEC-TRANSPORT-CONNECT §7.2
/// calls for. `mkit serve --http` instantiates this over
/// `mkit-transport-file::FileTransport`; a future backend (R2 + DO, for
/// the reference Worker in mkit#699) would implement `Transport` and
/// plug in unchanged.
pub struct TransportServer<T> {
    transport: Arc<T>,
}

impl<T> TransportServer<T> {
    /// Wrap `transport` in a Connect service.
    pub fn new(transport: Arc<T>) -> Self {
        Self { transport }
    }
}

impl<T> Clone for TransportServer<T> {
    fn clone(&self) -> Self {
        Self {
            transport: Arc::clone(&self.transport),
        }
    }
}

// connectrpc 0.8's generated trait methods return
// `impl Encodable<Resp> + Send + use<'a, Self>` so handlers MAY return
// zero-copy views; these handlers return the concrete owned response
// types, which is a (harmless, crate-internal) refinement of that
// signature — the same pattern `apps/repo-worker`'s `RepoService` impl
// uses.
#[allow(refining_impl_trait)]
impl<T: Transport + Send + Sync + 'static> TransportService for TransportServer<T> {
    async fn list_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ListRefsRequest>,
    ) -> ServiceResult<ListRefsResponse> {
        let prefix = request.prefix.unwrap_or_default().to_owned();
        let refs = blocking(Arc::clone(&self.transport), move |t| t.list_refs(&prefix)).await?;
        let entries = refs
            .into_iter()
            // A `Ref` with `hash: None` is on-disk-malformed; per its doc
            // comment such entries are silently skipped by callers that
            // only care about valid refs — this is that caller.
            .filter_map(|r| {
                let hash = r.hash?;
                Some(
                    RefEntry::default()
                        .with_name(r.name)
                        .with_object_id(hash.to_vec()),
                )
            })
            .collect();
        Response::ok(ListRefsResponse {
            refs: entries,
            ..Default::default()
        })
    }

    async fn read_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, ReadRefRequest>,
    ) -> ServiceResult<ReadRefResponse> {
        let name = request.name.unwrap_or_default().to_owned();
        let hash = blocking(Arc::clone(&self.transport), move |t| t.read_ref(&name)).await?;
        let resp = match hash {
            Some(h) => ReadRefResponse::default()
                .with_exists(true)
                .with_object_id(h.to_vec()),
            None => ReadRefResponse::default().with_exists(false),
        };
        Response::ok(resp)
    }

    async fn update_ref(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, UpdateRefRequest>,
    ) -> ServiceResult<UpdateRefResponse> {
        let name = request.name.unwrap_or_default().to_owned();
        let condition = condition_from_wire(request.expectation, request.expected_id)?;
        let new_id = hash_from_slice(request.new_id.unwrap_or_default())?;
        blocking(Arc::clone(&self.transport), move |t| {
            t.update_ref(&name, condition, &new_id)
        })
        .await?;
        Response::ok(UpdateRefResponse::default())
    }

    async fn advance_refs(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, AdvanceRefsRequest>,
    ) -> ServiceResult<AdvanceRefsResponse> {
        let head_ref = request.head_ref.unwrap_or_default().to_owned();
        let head_condition =
            condition_from_wire(request.head_expectation, request.head_expected_id)?;
        let head_new_id = hash_from_slice(request.head_new_id.unwrap_or_default())?;
        let packmap_ref = request.packmap_ref.unwrap_or_default().to_owned();
        let packmap_condition =
            condition_from_wire(request.packmap_expectation, request.packmap_expected_id)?;
        let packmap_new_id = hash_from_slice(request.packmap_new_id.unwrap_or_default())?;

        let outcome = blocking(Arc::clone(&self.transport), move |t| {
            t.advance_refs(
                &head_ref,
                head_condition,
                &head_new_id,
                &packmap_ref,
                packmap_condition,
                &packmap_new_id,
            )
        })
        .await?;

        let wire_outcome = match outcome {
            TransportAdvanceOutcome::Committed => AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
            TransportAdvanceOutcome::HeadConflict => AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT,
            TransportAdvanceOutcome::PackmapConflict => {
                AdvanceOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT
            }
        };
        Response::ok(AdvanceRefsResponse::default().with_outcome(wire_outcome))
    }

    async fn pack_exists(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, PackExistsRequest>,
    ) -> ServiceResult<PackExistsResponse> {
        let key = hash_from_slice(request.pack_id.unwrap_or_default())?;
        let key = PackKey::from_hash(key);
        let exists = blocking(Arc::clone(&self.transport), move |t| t.pack_exists(&key)).await?;
        Response::ok(PackExistsResponse::default().with_exists(exists))
    }

    async fn upload_pack(
        &self,
        _ctx: RequestContext,
        requests: InboundStream<UploadPackRequest>,
    ) -> ServiceResult<UploadPackResponse> {
        // Drains and validates the ENTIRE stream (header ordering, offset
        // contiguity, declared vs. received length, BLAKE3) before this
        // handler ever calls into `Transport::upload_pack` — so a
        // rejected upload never reaches storage, per
        // SPEC-TRANSPORT-CONNECT §6.1 / the `Invariants` table in
        // SPEC-TRANSPORT-CONNECT.md §11.
        let (pack_id, bytes) = drain_upload(requests).await?;
        let key = PackKey::from_hash(pack_id);
        blocking(Arc::clone(&self.transport), move |t| {
            t.upload_pack(&bytes, &key)
        })
        .await?;
        Response::ok(UploadPackResponse::default())
    }

    async fn download_pack(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, DownloadPackRequest>,
    ) -> ServiceResult<ServiceStream<DownloadPackResponse>> {
        let pack_id = hash_from_slice(request.pack_id.unwrap_or_default())?;
        let key = PackKey::from_hash(pack_id);
        // The whole pack is fetched and validated BEFORE any stream
        // message is produced, so a `PackNotFound` (or any other
        // transport error) surfaces as a Connect error with zero bytes
        // sent — never a partial stream. See SPEC-TRANSPORT-CONNECT §6.2.
        let bytes = blocking(Arc::clone(&self.transport), move |t| t.download_pack(&key)).await?;
        let items = chunk_download(pack_id, &bytes).into_iter().map(Ok);
        Response::stream_ok(futures::stream::iter(items))
    }
}
