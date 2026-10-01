//! Existing ticket lifetime and denial checks for the private scanner route.
use super::{HookSet, Pipeline};
use crate::ServerError;
use crate::scanner_retrieval::{RetrievalResponse, service::missing};
use crate::store::{MultipartBlobStore, NamespaceStore};

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    #[cfg(feature = "remote-hooks")]
    pub(super) fn retrieval_assignment(
        op: &crate::op::Operation,
        advance: &super::advance::AdvanceWrite<'_>,
        snapshot: &super::Snapshot,
        set: &crate::indexed::inspection::InspectionSet,
    ) -> Result<crate::scanner_retrieval::Assignment, ServerError> {
        use super::{codec, internal, keys, meta_error};
        let mut packs: Vec<crate::scanner_retrieval::PackGrant> = Vec::new();
        for id in advance.ids {
            let raw = snapshot
                .get(&keys::ticket(id))
                .ok_or_else(|| internal("retrieval ticket missing"))?;
            let ticket = codec::decode_ticket(raw).map_err(meta_error)?;
            if !set.raw_packs().contains(&ticket.pack_id) {
                continue;
            }
            if let Some(pack) = packs.iter_mut().find(|pack| pack.id == ticket.pack_id) {
                if pack.length != ticket.bytes {
                    return Err(internal("retrieval length mismatch"));
                }
                pack.tickets.push(*id);
            } else {
                packs.push(crate::scanner_retrieval::PackGrant {
                    id: ticket.pack_id,
                    length: ticket.bytes,
                    tickets: vec![*id],
                });
            }
        }
        Ok(crate::scanner_retrieval::Assignment {
            namespace: op.repo.namespace.as_str().to_owned(),
            repo_name: op.repo.name.as_str().to_owned(),
            repository: advance.repository.to_owned(),
            ref_name: advance.head_ref.to_owned(),
            signer: advance.signer,
            packs,
        })
    }

    /// Whether adapters may mount the private route. Default false.
    #[must_use]
    pub fn scanner_retrieval_enabled(&self) -> bool {
        self.cfg.scanner_retrieval.is_some()
    }

    /// Verify both credentials, strongly check existing bound ticket state and
    /// global denial, then read one bounded raw pack range. No public membership
    /// authorization or pack decoding is involved.
    ///
    /// # Errors
    /// Uniform `not_found`, including storage errors and exhausted budgets.
    // Preserve the async interface when the feature containing its awaits is disabled.
    #[cfg_attr(not(feature = "remote-hooks"), allow(clippy::unused_async))]
    pub async fn retrieve_scanner_pack(
        &self,
        body: &[u8],
        headers: &mkit_core::write_auth::Headers,
    ) -> Result<RetrievalResponse, ServerError> {
        #[cfg(feature = "remote-hooks")]
        let result = self
            .retrieve_inner(body, headers)
            .await
            .map_err(|_| missing());
        #[cfg(not(feature = "remote-hooks"))]
        let result: Result<RetrievalResponse, ServerError> = {
            let _ = (body, headers);
            Err(missing())
        };
        self.metrics.incr(
            "mkit_server_scanner_retrieval_calls",
            &[("result", if result.is_ok() { "ok" } else { "not_found" })],
            1,
        );
        if let Ok(response) = &result {
            self.metrics.incr(
                "mkit_server_scanner_retrieval_bytes",
                &[],
                response.bytes.len() as u64,
            );
        }
        result
    }

    #[cfg(feature = "remote-hooks")]
    async fn retrieve_inner(
        &self,
        body: &[u8],
        headers: &mkit_core::write_auth::Headers,
    ) -> Result<RetrievalResponse, ServerError> {
        use crate::indexed::budget::{Budgeted, SliceBudget};
        use crate::scanner_retrieval::{MAX_CALLS, MAX_RESPONSE_BYTES};
        use crate::store::{BlobKey, BlobStore, ByteRange};
        let (claims, request, repo) =
            request_authority(&self.cfg, self.clock.as_ref(), body, headers)?;
        let pack_id = mkit_core::hash::from_hex(&request.pack_id).map_err(|_| missing())?;
        if mkit_core::hash::to_hex(&pack_id) != request.pack_id {
            return Err(missing());
        }
        let pack = claims
            .assignment
            .packs
            .iter()
            .find(|pack| pack.id == pack_id)
            .ok_or_else(missing)?;
        let (start, end, partial) = match (request.start, request.end_inclusive) {
            (None, None) => (0, pack.length.checked_sub(1).ok_or_else(missing)?, false),
            (Some(start), Some(end)) => (start, end, true),
            _ => return Err(missing()),
        };
        let length = end
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(missing)?;
        if end >= pack.length || length > MAX_RESPONSE_BYTES as u64 {
            return Err(missing());
        }
        let budget = SliceBudget::new(MAX_CALLS);
        let meta = Budgeted::new(&self.meta, &budget);
        let blobs = Budgeted::new(&self.blobs, &budget);
        let partition = self.shards.ref_shard(&repo, &claims.assignment.ref_name);
        check_tickets(
            &meta,
            &partition,
            &repo,
            &claims.assignment,
            pack,
            self.clock.as_ref(),
        )
        .await?;
        crate::takedown::denial::require_pack_clear_for_scanner(
            &meta,
            self.shards.as_ref(),
            &repo,
            &pack.id,
        )
        .await?;
        let now = u64::try_from(self.clock.now_ms()).map_err(|_| missing())?;
        if now >= claims.expires_at_ms {
            return Err(missing());
        }
        let raw = blobs
            .get(
                &BlobKey::pack(pack.id),
                Some(ByteRange {
                    start,
                    end_inclusive: end,
                }),
            )
            .await
            .map_err(|_| missing())?
            .ok_or_else(missing)?;
        let bytes = collect_segment(raw, length).await?;
        let now = u64::try_from(self.clock.now_ms()).map_err(|_| missing())?;
        if now >= claims.expires_at_ms {
            return Err(missing());
        }
        check_tickets(
            &meta,
            &partition,
            &repo,
            &claims.assignment,
            pack,
            self.clock.as_ref(),
        )
        .await?;
        let now = u64::try_from(self.clock.now_ms()).map_err(|_| missing())?;
        if now >= claims.expires_at_ms {
            return Err(missing());
        }
        Ok(RetrievalResponse {
            bytes,
            start,
            total: pack.length,
            partial,
        })
    }
}

#[cfg(feature = "remote-hooks")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    capability: String,
    pack_id: String,
    start: Option<u64>,
    end_inclusive: Option<u64>,
}

#[cfg(feature = "remote-hooks")]
fn request_authority(
    cfg: &super::PipelineConfig,
    clock: &dyn crate::Clock,
    body: &[u8],
    headers: &mkit_core::write_auth::Headers,
) -> Result<(crate::scanner_retrieval::Claims, Request, crate::RepoId), ServerError> {
    use crate::scanner_retrieval::{MAX_REQUEST_BYTES, PATH};
    if body.len() > MAX_REQUEST_BYTES {
        return Err(missing());
    }
    let config = cfg.scanner_retrieval.as_ref().ok_or_else(missing)?;
    let crate::pipeline::AuthMode::AuthV2(auth) = &cfg.auth else {
        return Err(missing());
    };
    let now = u64::try_from(clock.now_ms()).map_err(|_| missing())?;
    let request: Request = serde_json::from_slice(body).map_err(|_| missing())?;
    let claims = config.verify(&request.capability, auth.audience(), now)?;
    let signed = crate::auth_v2::verify_unary_for(
        auth,
        &claims.assignment.repository,
        PATH,
        body,
        clock.now_ms(),
        headers,
    )?;
    if !config.accepts(&signed.signer) {
        return Err(missing());
    }
    let repo = cfg
        .addressing
        .resolve(Some(&claims.assignment.repository), true)?
        .repo;
    if repo.namespace.as_str() != claims.assignment.namespace
        || repo.name.as_str() != claims.assignment.repo_name
    {
        return Err(missing());
    }
    Ok((claims, request, repo))
}

#[cfg(feature = "remote-hooks")]
async fn check_tickets<N: NamespaceStore>(
    store: &N,
    partition: &crate::Partition,
    repo: &crate::RepoId,
    assignment: &crate::scanner_retrieval::Assignment,
    pack: &crate::scanner_retrieval::PackGrant,
    clock: &dyn crate::Clock,
) -> Result<(), ServerError> {
    use crate::store::{codec, keys, tickets};
    let keys: Vec<_> = pack.tickets.iter().map(keys::ticket).collect();
    let rows = store
        .get_many(partition, &keys)
        .await
        .map_err(|_| missing())?;
    if rows.len() != keys.len() {
        return Err(missing());
    }
    let now = u64::try_from(clock.now_ms()).map_err(|_| missing())?;
    for (id, raw) in pack.tickets.iter().zip(rows) {
        let t = codec::decode_ticket(&raw.ok_or_else(missing)?).map_err(|_| missing())?;
        if tickets::ticket_id(&t.reservation_id) != *id
            || t.repo != repo.name
            || t.ref_name != assignment.ref_name
            || t.signer != assignment.signer
            || t.pack_id != pack.id
            || t.bytes != pack.length
            || now >= t.expires_at_ms
        {
            return Err(missing());
        }
    }
    Ok(())
}

#[cfg(feature = "remote-hooks")]
async fn collect_segment(raw: crate::BlobBody, length: u64) -> Result<bytes::Bytes, ServerError> {
    use crate::BlobBody;
    use futures::StreamExt as _;
    let length = usize::try_from(length).map_err(|_| missing())?;
    if length > crate::scanner_retrieval::MAX_RESPONSE_BYTES {
        return Err(missing());
    }
    let BlobBody::Stream { len, mut stream } = raw else {
        return match raw {
            BlobBody::Bytes(bytes) if bytes.len() == length => Ok(bytes),
            _ => Err(missing()),
        };
    };
    if len != length as u64 {
        return Err(missing());
    }
    let mut bytes = bytes::BytesMut::with_capacity(length);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| missing())?;
        if chunk.len() > length - bytes.len() {
            return Err(missing());
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != length {
        return Err(missing());
    }
    Ok(bytes.freeze())
}
