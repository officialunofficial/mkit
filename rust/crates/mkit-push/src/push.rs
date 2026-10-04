use crate::connect::Rpc;
use crate::{Clock, Destination, Error, HttpTransport, Plan, Signer, proto::*};
use mkit_core::{
    hash::Hash,
    pack,
    refs::{self, RefWriteCondition},
    transfer,
    upload_parts::{PartPlan, part_subtree_cv},
    write_auth::{ContentCommitment, PartCommitment},
};
use std::collections::HashSet;

const CHUNK_SIZE: usize = 800 * 1024;
const MAX_CHAIN_DEPTH: usize = 100_000;
const MAX_CHAIN_PACKS: usize = 1_000_000;

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
    pub async fn run<T: HttpTransport, S: Signer, C: Clock>(
        &self,
        transport: &T,
        signer: &S,
        clock: &C,
    ) -> Result<Outcome, Error> {
        let mut rpc = Rpc {
            transport,
            signer,
            clock,
            destination: &self.destination,
            deadline_ms: self.deadline_ms,
        };
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
                    Some(root) => match walk_chain(&rpc, root).await {
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
                    Some(AdvanceOutcome::PackmapConflict) => continue,
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
            || ticket.token.as_deref().is_none_or(|token| token.is_empty())
        {
            return Err(Error::Invalid("ticket geometry/token"));
        }
        rpc.deadline_ms = rpc.deadline_ms.min(
            ticket
                .expires_unix_ms
                .ok_or(Error::Invalid("ticket expiry"))?,
        );
        if rpc.deadline_ms <= rpc.clock.now_ms() {
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
            let offset = plan
                .offset(index)
                .map_err(|_| Error::Invalid("part offset"))? as usize;
            let len = plan
                .expected_len(index)
                .map_err(|_| Error::Invalid("part length"))? as usize;
            let part = &bytes[offset..offset + len];
            let commitment = ContentCommitment::Part(PartCommitment {
                ticket: id,
                index,
                subtree: part_subtree_cv(&plan, index, part)
                    .map_err(|_| Error::Invalid("part hash"))?,
                len: len as u64,
            })
            .to_string();
            let header = UploadPartRequest {
                msg: Some(
                    UploadPartHeader {
                        ticket_token: ticket.token.clone(),
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
            let response: UploadPartResponse = rpc
                .stream(
                    "UploadPart",
                    std::iter::once(header).chain(chunks),
                    &commitment,
                )
                .await?;
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
        let header = UploadPackRequest {
            body: Some(
                UploadPackHeader {
                    pack_id: Some(key.to_vec()),
                    total_bytes: Some(bytes.len() as u64),
                    ticket_token: ticket.as_ref().and_then(|ticket| ticket.token.clone()),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        };
        let chunks = bytes
            .chunks(CHUNK_SIZE)
            .enumerate()
            .map(|(index, bytes_chunk)| UploadPackRequest {
                body: Some(
                    PackChunk {
                        pack_id: Some(key.to_vec()),
                        offset: Some((index * CHUNK_SIZE) as u64),
                        data: Some(bytes_chunk.to_vec()),
                        last: Some(index * CHUNK_SIZE + bytes_chunk.len() == bytes.len()),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            });
        let _: UploadPackResponse = rpc
            .stream(
                "UploadPack",
                std::iter::once(header).chain(chunks),
                &ContentCommitment::Pack {
                    id: *key,
                    len: bytes.len() as u64,
                }
                .to_string(),
            )
            .await?;
    }
    Ok(id)
}

fn condition(condition: RefWriteCondition) -> (RefExpectation, Option<Vec<u8>>) {
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
) -> Result<HashSet<Hash>, Error> {
    let mut cursor = Some(root);
    let mut seen = HashSet::new();
    let mut packs = HashSet::new();
    while let Some(key) = cursor {
        if seen.len() >= MAX_CHAIN_DEPTH || !seen.insert(key) {
            return Err(Error::Limit("packmap depth/cycle"));
        }
        let node = transfer::decode_packlist(&rpc.download(key).await?)?;
        packs.extend(node.packs);
        if packs.len() > MAX_CHAIN_PACKS {
            return Err(Error::Limit("packmap pack count"));
        }
        cursor = node.prev;
    }
    Ok(packs)
}

async fn advance<T: HttpTransport, S: Signer, C: Clock>(
    rpc: &Rpc<'_, T, S, C>,
    request: &AdvanceRefsRequest,
) -> Result<AdvanceRefsResponse, Error> {
    rpc.advance(request).await
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
