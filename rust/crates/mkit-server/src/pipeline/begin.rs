//! `BeginUpload`'s pre-admission decisions and pure ref-shard fragment.
use super::{
    Addressing, AuthMode, Authenticated, BeginUploadResult, HookSet, Key, MultipartBlobStore,
    NamespaceStore, OpKind, Operation, PackKey, Partition, Pipeline, PlanClock, ServerError,
    Sharding, Snapshot, StorageOp, StoredResult, TicketCaps, check_ref_name, codec, internal, keys,
    meta_error, ms, store_error, stored_mismatch,
};
use crate::replay::StoredRejection;
use crate::store::tickets;
use crate::store::tickets::{TicketPlanError, TicketSpec};
use crate::upload::token::{TicketClaims, TicketKeys};
use mkit_core::hash::Hash;

pub(super) const CAP_MESSAGE: &str = "too many open upload tickets";

#[derive(Debug, Clone)]
pub(super) enum BeginWrite {
    Return(BeginUploadResult),
    Open(Box<TicketOpen>),
}

#[derive(Debug, Clone)]
pub(super) struct TicketOpen {
    pub spec: TicketSpec,
    keys: TicketKeys,
    caps: TicketCaps,
    audience: String,
    repository: String,
    reserved: bool,
}

impl TicketOpen {
    pub(super) fn reserved(&self) -> bool {
        self.reserved
    }
}

pub(super) fn decision_keys(
    repo: &crate::repo::RepoName,
    name: &str,
    pack: &Hash,
    signer: &Hash,
) -> Result<Vec<Key>, ServerError> {
    Ok(vec![
        keys::ticket_index(repo, name, pack, signer).map_err(meta_error)?,
        keys::tickets_per_ref(repo, name).map_err(meta_error)?,
        keys::tickets_per_signer(repo, name, signer).map_err(meta_error)?,
        keys::membership(repo, pack),
    ])
}

pub(super) fn open_keys(spec: &TicketSpec) -> Vec<Key> {
    let k = tickets::keys(spec);
    vec![k.ticket, k.index, k.per_ref, k.per_signer, k.reservation]
}

pub(super) async fn read_indexed<N: NamespaceStore>(
    meta: &N,
    p: &Partition,
    spec: &TicketSpec,
    snap: &mut Snapshot,
) -> Result<(), ServerError> {
    let k = tickets::keys(spec);
    if let Some(index) = snap.get(&k.index) {
        let id = codec::decode_ref_id(index).map_err(meta_error)?;
        let key = keys::ticket(&id);
        if !snap.contains(&key) {
            let value = meta.get(p, &key).await.map_err(meta_error)?;
            snap.insert(key, value);
        }
    }
    Ok(())
}

fn result(
    keys: &TicketKeys,
    audience: &str,
    repository: &str,
    ticket: &codec::TicketV1,
) -> BeginUploadResult {
    let id = tickets::ticket_id(&ticket.reservation_id);
    let claims = TicketClaims {
        authority_generation: ticket.authority_generation,
        ticket_id: id,
        audience: audience.to_owned(),
        repository: repository.to_owned(),
        signer: ticket.signer,
        pack_id: ticket.pack_id,
        bytes: ticket.bytes,
        part_size: ticket.part_size,
        expires_at_ms: ticket.expires_at_ms,
        upload_session: ticket.upload_session.clone().unwrap_or_default(),
    };
    BeginUploadResult::Ticket {
        id,
        part_size: ticket.part_size,
        expires_at_ms: ticket.expires_at_ms,
        token: keys.mint(&claims),
    }
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Open a stateless authenticated upload ticket in the target ref shard.
    ///
    /// # Errors
    /// Invalid geometry/ref, unsupported auth or missing keys, policy or cap
    /// refusal, and the usual replay, quota, lease and storage errors.
    pub async fn begin_upload(
        &self,
        a: &Authenticated,
        ref_name: &str,
        pack_id: &[u8],
        bytes: u64,
    ) -> Result<BeginUploadResult, ServerError> {
        self.begin_upload_with_meta(a, ref_name, pack_id, bytes)
            .await
            .map(|(result, _)| result)
    }

    /// Begin a resumable upload and return success-only admission headers.
    pub async fn begin_upload_with_meta(
        &self,
        a: &Authenticated,
        ref_name: &str,
        pack_id: &[u8],
        bytes: u64,
    ) -> Result<(BeginUploadResult, super::ResponseMeta), ServerError> {
        self.observe(a, async {
            check_ref_name(ref_name)?;
            if ref_name.starts_with(mkit_core::refs::PACKMAP_REF_PREFIX) {
                return Err(ServerError::invalid_argument(
                    "BeginUpload names a branch or tag, not its packmap",
                ));
            }
            if self.cfg.sharding == Sharding::D34 && !ref_name.starts_with("refs/heads/") {
                return Err(ServerError::invalid_argument(
                    "BeginUpload requires refs/heads/ on this server",
                ));
            }
            let id: Hash = pack_id
                .try_into()
                .map_err(|_| ServerError::invalid_argument("pack_id must be 32 bytes"))?;
            if bytes == 0 || bytes > self.cfg.upload_limits.max_total_bytes {
                return Err(ServerError::invalid_argument(
                    "upload bytes outside server limit",
                ));
            }
            if !matches!(self.cfg.auth, AuthMode::AuthV2(_)) {
                return Err(ServerError::new(
                    crate::Code::Unimplemented,
                    "BeginUpload requires auth v2",
                ));
            }
            if self.cfg.ticket_keys.is_none() {
                return Err(ServerError::new(
                    crate::Code::Unimplemented,
                    "upload tickets are not configured",
                ));
            }
            if bytes > self.cfg.part_size && !self.blobs.supports_multipart() {
                return Err(ServerError::unimplemented(
                    "multipart uploads are not supported by this storage backend",
                ));
            }
            match self
                .write(
                    a,
                    OpKind::BeginUpload {
                        ref_name: ref_name.into(),
                        key: PackKey(id),
                        bytes,
                    },
                )
                .await?
            {
                (StoredResult::BeginUpload(answer), meta) => Ok((answer, meta)),
                (other, _) => Err(stored_mismatch(&other)),
            }
        })
        .await
    }

    pub(super) async fn begin_decision(
        &self,
        op: &Operation,
        a: &Authenticated,
        ahead: Option<&mut Snapshot>,
    ) -> Result<Option<BeginUploadResult>, ServerError> {
        let OpKind::BeginUpload { ref_name, key, .. } = &op.kind else {
            return Ok(None);
        };
        let snap = ahead.ok_or_else(|| internal("ticket write lacks snapshot"))?;
        let auth = op
            .auth
            .as_ref()
            .ok_or_else(|| internal("ticket write lacks signer"))?;
        let ks = decision_keys(&op.repo.name, ref_name, &key.0, &auth.signer)?;
        let now = ms(self.clock.now_ms().saturating_add(a.business_skew_ms));
        if let Some(index) = snap.get(&ks[0]) {
            let id = codec::decode_ref_id(index).map_err(meta_error)?;
            let k = keys::ticket(&id);
            let value = self
                .meta
                .get(&self.shards.ref_shard(&op.repo, ref_name), &k)
                .await
                .map_err(meta_error)?;
            snap.insert(k.clone(), value);
            if let Some(raw) = snap.get(&k) {
                let ticket = codec::decode_ticket(raw).map_err(meta_error)?;
                if ticket.repo != op.repo.name
                    || ticket.ref_name != *ref_name
                    || ticket.pack_id != key.0
                    || ticket.signer != auth.signer
                    || tickets::ticket_id(&ticket.reservation_id) != id
                {
                    return Err(internal("ticket index binding mismatch"));
                }
                if ticket.expires_at_ms > now {
                    if self.cfg.authority_fence.is_some()
                        && ticket.authority_generation != op.authz.authority_generation
                    {
                        return Err(crate::authority::moved());
                    }
                    let (keys, audience) = self.ticket_config()?;
                    return Ok(Some(result(keys, audience, &a.repo().identity, &ticket)));
                }
            }
        }
        let present = if matches!(self.cfg.addressing, Addressing::Multi(_)) {
            snap.get(&ks[3]).is_some()
        } else {
            self.blobs
                .head(&(*key).into())
                .await
                .map_err(|e| store_error(StorageOp::BlobHead, e))?
                .is_some()
        };
        let present = if present && let Some(cfg) = self.cfg.indexed.as_ref() {
            let clear = if self.cfg.takedown_denial {
                crate::takedown::denial::require_pack_clear(
                    &self.blobs,
                    &self.meta,
                    self.shards.as_ref(),
                    &op.repo,
                    &key.0,
                    cfg,
                    self.metrics.as_ref(),
                )
                .await
            } else {
                crate::takedown::denial::require_clear(&self.meta, &key.0).await
            };
            match clear {
                Ok(()) => true,
                Err(e) if e.public_message() == "object blocked" => false,
                Err(e) => return Err(e),
            }
        } else {
            present
        };
        if present {
            return Ok(Some(BeginUploadResult::AlreadyPresent));
        }
        for (k, cap) in [
            (&ks[1], self.cfg.ticket_caps.per_ref),
            (&ks[2], self.cfg.ticket_caps.per_signer),
        ] {
            let count = snap
                .get(k)
                .map(codec::decode_u64)
                .transpose()
                .map_err(meta_error)?
                .unwrap_or(0);
            if count >= cap {
                return Err(ServerError::failed_precondition(CAP_MESSAGE));
            }
        }
        Ok(None)
    }

    fn ticket_config(&self) -> Result<(&TicketKeys, &str), ServerError> {
        let keys = self
            .cfg
            .ticket_keys
            .as_ref()
            .ok_or_else(|| internal("missing ticket keys"))?;
        let AuthMode::AuthV2(auth) = &self.cfg.auth else {
            return Err(internal("missing ticket audience"));
        };
        // The token encodes the audience with a u16 length; never let minting panic.
        if u16::try_from(auth.audience().len()).is_err() {
            return Err(internal("ticket audience too long"));
        }
        Ok((keys, auth.audience()))
    }

    pub(super) fn begin_write(
        &self,
        op: &Operation,
        a: &Authenticated,
        existing: Option<BeginUploadResult>,
        reservation: Option<String>,
    ) -> Result<Option<BeginWrite>, ServerError> {
        let OpKind::BeginUpload {
            ref_name,
            key,
            bytes,
        } = &op.kind
        else {
            return Ok(None);
        };
        if let Some(answer) = existing {
            return Ok(Some(BeginWrite::Return(answer)));
        }
        let auth = op
            .auth
            .as_ref()
            .ok_or_else(|| internal("missing ticket signer"))?;
        let (keys, audience) = self.ticket_config()?;
        let now = ms(self.clock.now_ms().saturating_add(a.business_skew_ms));
        let expires = now
            .checked_add(self.cfg.ticket_ttl_ms)
            .ok_or_else(|| internal("ticket expiry overflow"))?;
        let reserved = reservation.is_some();
        let rid = reservation
            .unwrap_or_else(|| crate::store::outbox::synthetic_reservation_id(&auth.replay_scope));
        // Validate admission-supplied ids before any infallible key constructor.
        keys::reservation(&rid).map_err(meta_error)?;
        Ok(Some(BeginWrite::Open(Box::new(TicketOpen {
            spec: TicketSpec {
                authority_generation: op.authz.authority_generation,
                repo: op.repo.name.clone(),
                ref_name: ref_name.clone(),
                signer: auth.signer,
                pack_id: key.0,
                bytes: *bytes,
                part_size: self.cfg.part_size,
                expires_at_ms: expires,
                created_at_ms: now,
                now_ms: now,
                reservation_id: rid,
                upload_session: None,
            },
            keys: keys.clone(),
            caps: self.cfg.ticket_caps,
            audience: audience.into(),
            repository: a.repo().identity.clone(),
            reserved,
        }))))
    }
}

pub(super) fn plan(
    begin: &BeginWrite,
    snap: &Snapshot,
    clock: &PlanClock,
    pre: &mut Vec<crate::store::Precondition>,
    writes: &mut Vec<crate::store::Write>,
) -> Result<StoredResult, ServerError> {
    let BeginWrite::Open(open) = begin else {
        let BeginWrite::Return(answer) = begin else {
            unreachable!()
        };
        if let BeginUploadResult::Ticket { id, .. } = answer {
            let key = keys::ticket(id);
            let raw = snap
                .get(&key)
                .ok_or_else(|| ServerError::aborted_retryable("upload ticket race"))?;
            pre.push(crate::store::Precondition::Equals(key, raw.clone()));
        }
        return Ok(StoredResult::BeginUpload(answer.clone()));
    };
    let mut spec = open.spec.clone();
    spec.now_ms = ms(clock.business_now_ms);
    let k = tickets::keys(&spec);
    let index = snap.get(&k.index).cloned();
    let indexed_ticket = index
        .as_ref()
        .map(codec::decode_ref_id)
        .transpose()
        .map_err(meta_error)?
        .and_then(|id| snap.get(&keys::ticket(&id)).cloned());
    let reads = tickets::TicketReads {
        ticket: snap.get(&k.ticket).cloned(),
        indexed_ticket,
        index,
        per_ref: snap.get(&k.per_ref).cloned(),
        per_signer: snap.get(&k.per_signer).cloned(),
        reservation: snap.get(&k.reservation).cloned(),
    };
    match tickets::plan_ticket_open(&spec, &reads, open.caps, pre, writes) {
        Ok(id) => Ok(StoredResult::BeginUpload(BeginUploadResult::Ticket {
            id,
            part_size: spec.part_size,
            expires_at_ms: spec.expires_at_ms,
            token: open.keys.mint(&TicketClaims {
                authority_generation: spec.authority_generation,
                ticket_id: id,
                audience: open.audience.clone(),
                repository: open.repository.clone(),
                signer: spec.signer,
                pack_id: spec.pack_id,
                bytes: spec.bytes,
                part_size: spec.part_size,
                expires_at_ms: spec.expires_at_ms,
                upload_session: spec.upload_session.clone().unwrap_or_default(),
            }),
        })),
        Err(TicketPlanError::Existing(ticket)) if !open.reserved => {
            if spec.authority_generation.is_some()
                && ticket.authority_generation != spec.authority_generation
            {
                return Err(crate::authority::moved());
            }
            let key = keys::ticket(&tickets::ticket_id(&ticket.reservation_id));
            let raw = snap
                .get(&key)
                .ok_or_else(|| ServerError::aborted_retryable("upload ticket race"))?;
            pre.push(crate::store::Precondition::Equals(key, raw.clone()));
            Ok(StoredResult::BeginUpload(result(
                &open.keys,
                &open.audience,
                &open.repository,
                &ticket,
            )))
        }
        Err(TicketPlanError::CapExceeded { .. }) if !open.reserved => Ok(StoredResult::Rejected(
            StoredRejection::new(crate::Code::FailedPrecondition, CAP_MESSAGE)
                .expect("final cap error"),
        )),
        Err(TicketPlanError::Existing(_)) => {
            Err(ServerError::aborted_retryable("upload ticket race"))
        }
        Err(TicketPlanError::CapExceeded { .. }) => {
            Err(ServerError::failed_precondition(CAP_MESSAGE))
        }
        Err(TicketPlanError::Corrupt(err)) => Err(meta_error(err)),
        Err(TicketPlanError::Invalid(detail)) => Err(internal(detail)),
    }
}
