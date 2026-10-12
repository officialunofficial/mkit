use crate::connect::{Built, RESPONSE_LIMIT, Rpc, pending_delay};
use crate::{
    Clock, Destination, Error, HttpTransport, Plan, Signer,
    proto::{
        AdvanceOutcome, AdvanceRefsRequest, AdvanceRefsResponse, BeginUploadRequest,
        BeginUploadResponse, CompleteUploadRequest, CompleteUploadResponse, GetServerInfoRequest,
        GetServerInfoResponse, PackChunk, ReadRefRequest, ReadRefResponse, RefExpectation,
        UpdateRefRequest, UpdateRefResponse, UploadPackHeader, UploadPackRequest,
        UploadPackResponse, UploadPartHeader, UploadPartRequest, UploadPartResponse,
        begin_upload_response, upload_part_request,
    },
};
use buffa::Message;
use mkit_core::hash::{hash, to_hex};
use mkit_core::{
    hash::Hash,
    pack,
    refs::{self, RefWriteCondition},
    transfer,
    upload_parts::{PartPlan, part_subtree_cv},
    write_auth::{ContentCommitment, PartCommitment},
};
use std::collections::HashSet;
use std::time::Duration;

const CHUNK_SIZE: usize = 800 * 1024;

/// The host certifies whether the supplied entries contain the whole closure.
/// Reset requires a self-contained plan and an atomic conditioned advance.
#[derive(Clone, Copy, Debug)]
pub enum PackmapMode {
    Append { self_contained: bool },
    ResetSelfContained,
}

/// Wire outcomes and reasons requiring host replanning. A conflict never
/// asserts that an earlier ambiguous operation did not commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Committed,
    HeadConflict,
    PackmapContended,
    TicketRejected,
    PacklistNotInRepository,
    DeltaBaseUnavailable,
}

/// One ticketed advance. The host owns the head lease, input policy, deadline,
/// persistence and scheduling of subsequent advances.
#[derive(Debug)]
pub struct Push {
    destination: Destination,
    head_ref: String,
    packmap_ref: String,
    condition: RefWriteCondition,
    tip: Hash,
    mode: PackmapMode,
    plan: Plan,
    deadline_ms: i64,
}

impl Push {
    pub fn new(
        destination: Destination,
        branch: &str,
        condition: RefWriteCondition,
        tip: Hash,
        mode: PackmapMode,
        plan: Plan,
        deadline_ms: i64,
    ) -> Result<Self, Error> {
        let head_ref = format!("refs/heads/{branch}");
        let packmap_ref = format!("refs/mkit/packmap/{branch}");
        if !refs::validate_ref_name(&head_ref) || !refs::validate_ref_name(&packmap_ref) {
            return Err(Error::Invalid("ref name"));
        }
        if matches!(mode, PackmapMode::ResetSelfContained)
            && matches!(condition, RefWriteCondition::Any)
        {
            return Err(Error::Invalid("reset requires conditioned atomic advance"));
        }
        Ok(Self {
            destination,
            head_ref,
            packmap_ref,
            condition,
            tip,
            mode,
            plan,
            deadline_ms,
        })
    }

    /// Runs the operation over host boundaries. The host transport may retry
    /// an exact signed request, journal it, add grants or stop on cancellation.
    /// The host clock schedules pending polls without requiring tokio.
    // One linear retry loop over upload, advance and head-conflict handling.
    #[allow(clippy::too_many_lines)]
    pub async fn run<T: HttpTransport, S: Signer, C: Clock>(
        &self,
        transport: &T,
        signer: &S,
        clock: &C,
    ) -> Result<Outcome, Error> {
        let mut rpc = Rpc::signed(
            transport,
            signer,
            clock,
            &self.destination,
            self.deadline_ms,
        );
        let info: GetServerInfoResponse = rpc
            .unary("GetServerInfo", &GetServerInfoRequest::default())
            .await?;
        if info.spec_version != Some(2) || info.atomic_advance != Some(true) {
            return Err(Error::Invalid("ticketed atomic transport required"));
        }
        if self.plan.limits.max_pack_bytes > info.max_pack_bytes.unwrap_or(0)
            || self.plan.limits.max_parts > info.max_parts.unwrap_or(0)
            || self.plan.limits.ticket_threshold_bytes
                != info.begin_upload_threshold_bytes.unwrap_or(0)
        {
            return Err(Error::Invalid("plan limits exceed server capabilities"));
        }
        if self.plan.packs.is_empty() {
            return commit_head(&rpc, &self.head_ref, self.condition, self.tip).await;
        }
        let mut tickets = Vec::new();
        for pack in &self.plan.packs {
            if let Some(ticket) = upload(
                &mut rpc,
                &self.head_ref,
                &pack.key,
                &pack.bytes,
                self.plan.limits,
            )
            .await?
            {
                tickets.push(ticket);
            }
        }
        let keys: Vec<_> = self.plan.pack_ids().copied().collect();
        for _ in 0..8 {
            let prior = read_ref(&rpc, &self.packmap_ref).await?;
            let prev = match self.mode {
                PackmapMode::ResetSelfContained => None,
                PackmapMode::Append { self_contained } => match prior {
                    None => None,
                    Some(root) => match walk_chain(&rpc, root, &self.head_ref).await {
                        Ok(held) if keys.iter().all(|key| held.contains(key)) => {
                            return commit_head(&rpc, &self.head_ref, self.condition, self.tip)
                                .await;
                        }
                        Ok(_) => Some(root),
                        Err(Error::Packlist(_) | Error::Invalid(_)) if self_contained => None,
                        Err(Error::Remote(error))
                            if self_contained && error.code == "not_found" =>
                        {
                            None
                        }
                        Err(error) => return Err(error),
                    },
                },
            };
            let bytes = transfer::encode_packlist(prev, &keys)?;
            if bytes.len() as u64 > self.plan.limits.max_pack_bytes {
                return Err(Error::Limit("packmap node"));
            }
            let node = pack::pack_key(&bytes);
            let node_ticket =
                upload(&mut rpc, &self.head_ref, &node, &bytes, self.plan.limits).await?;
            let (head_expectation, head_expected_id) = condition(self.condition);
            let (packmap_expectation, packmap_expected_id) =
                condition(prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match));
            let request = AdvanceRefsRequest {
                head_ref: Some(self.head_ref.clone()),
                head_expectation: Some(head_expectation.into()),
                head_expected_id,
                head_new_id: Some(self.tip.to_vec()),
                packmap_ref: Some(self.packmap_ref.clone()),
                packmap_expectation: Some(packmap_expectation.into()),
                packmap_expected_id,
                packmap_new_id: Some(node.to_vec()),
                ticket_ids: tickets
                    .iter()
                    .copied()
                    .chain(node_ticket)
                    .map(|id| id.to_vec())
                    .collect(),
                ..Default::default()
            };
            let result = advance(&rpc, &request).await;
            match result {
                Ok(response) => match response.outcome.and_then(|outcome| outcome.as_known()) {
                    Some(AdvanceOutcome::Committed) => return Ok(Outcome::Committed),
                    Some(AdvanceOutcome::PackmapConflict) => {}
                    Some(AdvanceOutcome::HeadConflict) => {
                        return head_conflict(&rpc, &self.head_ref, self.tip).await;
                    }
                    _ => return Err(Error::Invalid("advance outcome")),
                },
                Err(Error::Remote(error))
                    if error.code == "failed_precondition" && !request.ticket_ids.is_empty() =>
                {
                    if error.message == "delta base not available in this repository" {
                        return Ok(Outcome::DeltaBaseUnavailable);
                    }
                    if read_ref(&rpc, &self.head_ref).await? == Some(self.tip) {
                        return Ok(Outcome::Committed);
                    }
                    return Ok(Outcome::TicketRejected);
                }
                Err(Error::Remote(error))
                    if error.code == "invalid_argument"
                        && error.message
                            == "packlist lists a pack that is not in this repository" =>
                {
                    if read_ref(&rpc, &self.head_ref).await? == Some(self.tip) {
                        return Ok(Outcome::Committed);
                    }
                    return Ok(Outcome::PacklistNotInRepository);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(Outcome::PackmapContended)
    }
}

// The upload steps share one ticket/deadline state across the single-part
// and multipart paths; splitting them would thread that state through helpers.
#[allow(clippy::too_many_lines)]
async fn upload<T: HttpTransport, S: Signer, C: Clock>(
    rpc: &mut Rpc<'_, T, S, C>,
    head_ref: &str,
    key: &Hash,
    bytes: &[u8],
    limits: crate::Limits,
) -> Result<Option<Hash>, Error> {
    let ticket = if bytes.len() as u64 >= limits.ticket_threshold_bytes {
        let response: BeginUploadResponse = rpc
            .unary(
                "BeginUpload",
                &BeginUploadRequest {
                    r#ref: Some(head_ref.to_owned()),
                    pack_id: Some(key.to_vec()),
                    bytes: Some(bytes.len() as u64),
                    ..Default::default()
                },
            )
            .await?;
        match response.result {
            Some(begin_upload_response::Result::AlreadyPresent(_)) => return Ok(None),
            Some(begin_upload_response::Result::Ticket(ticket)) => Some(ticket),
            _ => return Err(Error::Invalid("BeginUpload outcome")),
        }
    } else {
        None
    };
    let id = if let Some(ticket) = &ticket {
        let id: Hash = ticket
            .id
            .as_deref()
            .ok_or(Error::Invalid("ticket id"))?
            .try_into()
            .map_err(|_| Error::Invalid("ticket id"))?;
        let part_size = ticket.part_size.ok_or(Error::Invalid("ticket part size"))?;
        if part_size < 8 * 1024 * 1024
            || !part_size.is_power_of_two()
            || ticket.token.as_deref().is_none_or(<[u8]>::is_empty)
        {
            return Err(Error::Invalid("ticket geometry/token"));
        }
        rpc.deadline_ms = rpc.deadline_ms.min(
            ticket
                .expires_unix_ms
                .ok_or(Error::Invalid("ticket expiry"))?,
        );
        if rpc
            .auth
            .is_some_and(|(_, clock)| rpc.deadline_ms <= clock.now_ms())
        {
            return Err(Error::Deadline);
        }
        Some(id)
    } else {
        None
    };
    if let (Some(ticket), Some(id)) = (&ticket, id)
        && bytes.len() as u64 > ticket.part_size.unwrap_or(0)
    {
        let plan = PartPlan::new(
            bytes.len() as u64,
            ticket.part_size.unwrap_or(0),
            limits.max_parts,
        )
        .map_err(|_| Error::Limit("multipart geometry"))?;
        let mut receipts = Vec::new();
        for index in 0..plan.count() {
            let offset = usize::try_from(
                plan.offset(index)
                    .map_err(|_| Error::Invalid("part offset"))?,
            )
            .map_err(|_| Error::Invalid("part offset"))?;
            let len = usize::try_from(
                plan.expected_len(index)
                    .map_err(|_| Error::Invalid("part length"))?,
            )
            .map_err(|_| Error::Invalid("part length"))?;
            let part = &bytes[offset..offset + len];
            let commitment = part_commitment(id, &plan, index, part)?;
            let messages = part_messages(ticket.token.clone(), index, part);
            let response: UploadPartResponse =
                rpc.stream("UploadPart", messages, &commitment).await?;
            let receipt = response
                .receipt
                .filter(|receipt| !receipt.is_empty() && receipt.len() <= 512)
                .ok_or(Error::Invalid("part receipt"))?;
            receipts.push(receipt);
        }
        let _: CompleteUploadResponse = rpc
            .unary(
                "CompleteUpload",
                &CompleteUploadRequest {
                    ticket_token: ticket.token.clone(),
                    receipts,
                    ..Default::default()
                },
            )
            .await?;
    } else {
        let messages = pack_messages(
            key,
            bytes,
            ticket.as_ref().and_then(|ticket| ticket.token.clone()),
        );
        let _: UploadPackResponse = rpc
            .stream("UploadPack", messages, &pack_commitment(key, bytes))
            .await?;
    }
    Ok(id)
}

/// The `UploadPack` stream: a header, then ordered chunks ending in `last`.
pub(crate) fn pack_messages(
    key: &Hash,
    bytes: &[u8],
    ticket_token: Option<Vec<u8>>,
) -> impl Iterator<Item = UploadPackRequest> {
    let key = *key;
    let total = bytes.len();
    let header = UploadPackRequest {
        body: Some(
            UploadPackHeader {
                pack_id: Some(key.to_vec()),
                total_bytes: Some(total as u64),
                ticket_token,
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    };
    let chunks = bytes
        .chunks(CHUNK_SIZE)
        .enumerate()
        .map(move |(index, bytes_chunk)| UploadPackRequest {
            body: Some(
                PackChunk {
                    pack_id: Some(key.to_vec()),
                    offset: Some((index * CHUNK_SIZE) as u64),
                    data: Some(bytes_chunk.to_vec()),
                    last: Some(index * CHUNK_SIZE + bytes_chunk.len() == total),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        });
    std::iter::once(header).chain(chunks)
}

pub(crate) fn pack_commitment(key: &Hash, bytes: &[u8]) -> String {
    ContentCommitment::Pack {
        id: *key,
        len: bytes.len() as u64,
    }
    .to_string()
}

/// The `UploadPart` stream: a header, then the part in chunks.
pub(crate) fn part_messages(
    ticket_token: Option<Vec<u8>>,
    index: u32,
    part: &[u8],
) -> impl Iterator<Item = UploadPartRequest> {
    let header = UploadPartRequest {
        msg: Some(
            UploadPartHeader {
                ticket_token,
                index: Some(index),
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    };
    let chunks = part.chunks(CHUNK_SIZE).map(|bytes| UploadPartRequest {
        msg: Some(upload_part_request::Msg::Chunk(bytes.to_vec())),
        ..Default::default()
    });
    std::iter::once(header).chain(chunks)
}

/// The signed commitment of one part (SPEC-TRANSPORT-CONNECT §7.6).
pub(crate) fn part_commitment(
    ticket: Hash,
    plan: &PartPlan,
    index: u32,
    part: &[u8],
) -> Result<String, Error> {
    Ok(ContentCommitment::Part(PartCommitment {
        ticket,
        index,
        subtree: part_subtree_cv(plan, index, part).map_err(|_| Error::Invalid("part hash"))?,
        len: part.len() as u64,
    })
    .to_string())
}

pub(crate) fn condition(condition: RefWriteCondition) -> (RefExpectation, Option<Vec<u8>>) {
    match condition {
        RefWriteCondition::Any => (RefExpectation::Any, None),
        RefWriteCondition::Missing => (RefExpectation::Missing, None),
        RefWriteCondition::Match(hash) => (RefExpectation::Match, Some(hash.to_vec())),
    }
}

async fn read_ref<T: HttpTransport, S: Signer, C: Clock>(
    rpc: &Rpc<'_, T, S, C>,
    name: &str,
) -> Result<Option<Hash>, Error> {
    let response: ReadRefResponse = rpc
        .unary(
            "ReadRef",
            &ReadRefRequest {
                name: Some(name.to_owned()),
                ..Default::default()
            },
        )
        .await?;
    match response.exists {
        Some(false) => Ok(None),
        Some(true) => response
            .object_id
            .as_deref()
            .ok_or(Error::Invalid("ref value"))?
            .try_into()
            .map(Some)
            .map_err(|_| Error::Invalid("ref value")),
        _ => Err(Error::Invalid("ref presence")),
    }
}

async fn walk_chain<T: HttpTransport, S: Signer, C: Clock>(
    rpc: &Rpc<'_, T, S, C>,
    root: Hash,
    head_ref: &str,
) -> Result<HashSet<Hash>, Error> {
    Ok(crate::read::walk_nodes(rpc, root, head_ref)
        .await?
        .into_iter()
        .flat_map(|node| node.packs)
        .collect())
}

/// One `AdvanceRefs` with the whole-push waits: poll a definitive pending or
/// membership-lag answer on the host clock, keeping the same signed identity
/// until it expires. Per-RPC calls never wait; this loop is the only place the
/// crate calls `Clock::wait`.
pub(crate) async fn advance<T: HttpTransport, S: Signer, C: Clock>(
    rpc: &Rpc<'_, T, S, C>,
    message: &AdvanceRefsRequest,
) -> Result<AdvanceRefsResponse, Error> {
    let (_, clock) = rpc.auth.ok_or(Error::Invalid("signed client required"))?;
    let body = message.encode_to_vec();
    let commitment = format!("body:{}", to_hex(&hash(&body)));
    let sign = || rpc.build("AdvanceRefs", body.clone(), &commitment, false, None);
    let expiry = |built: &Built| built.identity.map_or(i64::MAX, |id| id.expires_at_ms);
    let mut built = sign().await?;
    let mut expires = expiry(&built);
    let mut lag_start = None;
    let mut saw_pending = false;
    let mut renewed_after_unauthenticated = false;
    loop {
        let now = clock.now_ms();
        if now >= rpc.deadline_ms {
            return Err(Error::Deadline);
        }
        // Only a definitive pending/lag answer reaches this continuation.
        // Keep exactly the same nonce and timestamps until actual expiry.
        if now > expires {
            built = sign().await?;
            expires = expiry(&built);
        }
        match rpc.send(&built.request, RESPONSE_LIMIT).await {
            Ok((bytes, _)) => {
                return AdvanceRefsResponse::decode_from_slice(&bytes)
                    .map_err(|_| Error::Invalid("advance protobuf"));
            }
            Err(Error::Remote(error)) => {
                // A post-pending authentication rejection is definitive,
                // including expiry in transit or a small server clock lead.
                // Recover once; an ambiguous transport error never reaches here.
                if saw_pending && !renewed_after_unauthenticated && error.code == "unauthenticated"
                {
                    renewed_after_unauthenticated = true;
                    built = sign().await?;
                    expires = expiry(&built);
                    continue;
                }
                let delay = if let Some(delay) = pending_delay(&error) {
                    lag_start = None;
                    renewed_after_unauthenticated = false;
                    delay
                } else if !message.ticket_ids.is_empty()
                    && error.code == "unavailable"
                    && error.message == "repository membership not yet visible"
                {
                    let start = *lag_start.get_or_insert(now);
                    if now.saturating_sub(start) >= 60_000 {
                        return Err(Error::Remote(error));
                    }
                    Duration::from_secs(2)
                } else {
                    return Err(Error::Remote(error));
                };
                saw_pending = true;
                if now.saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX))
                    >= rpc.deadline_ms
                {
                    return Err(Error::Deadline);
                }
                clock.wait(delay).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn commit_head<T: HttpTransport, S: Signer, C: Clock>(
    rpc: &Rpc<'_, T, S, C>,
    name: &str,
    lease: RefWriteCondition,
    tip: Hash,
) -> Result<Outcome, Error> {
    let (expectation, expected_id) = condition(lease);
    let request = UpdateRefRequest {
        name: Some(name.to_owned()),
        expectation: Some(expectation.into()),
        expected_id,
        new_id: Some(tip.to_vec()),
        ..Default::default()
    };
    match rpc
        .unary::<_, UpdateRefResponse>("UpdateRef", &request)
        .await
    {
        Ok(_) => Ok(Outcome::Committed),
        Err(Error::Remote(error)) if error.code == "failed_precondition" => {
            head_conflict(rpc, name, tip).await
        }
        Err(error) => Err(error),
    }
}
async fn head_conflict<T: HttpTransport, S: Signer, C: Clock>(
    rpc: &Rpc<'_, T, S, C>,
    name: &str,
    tip: Hash,
) -> Result<Outcome, Error> {
    Ok(if read_ref(rpc, name).await? == Some(tip) {
        Outcome::Committed
    } else {
        Outcome::HeadConflict
    })
}
