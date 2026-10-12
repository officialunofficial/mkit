//! The write RPCs, shared by the typed [`Client`](crate::Client) calls and the
//! whole-push run so both build the same request and tell the observer the same
//! thing.

use crate::connect::{Clock, Error, HttpTransport, Identity, Opts, Rpc, Signer};
use crate::proto::{
    AdvanceRefsRequest, BeginUploadRequest, BeginUploadResponse, CompleteUploadRequest,
    CompleteUploadResponse, RefExpectation, UpdateRefRequest, UpdateRefResponse,
    UploadPackResponse, UploadPartResponse,
};
use crate::push::{condition, pack_commitment, pack_messages, part_commitment, part_messages};
use crate::seams::{Observer, RefMove, RefTarget, WriteIntent, procedures};
use mkit_core::{hash::Hash, refs::RefWriteCondition, upload_parts::PartPlan};

pub(crate) type Called<R> = Result<(R, Option<Identity>), Error>;

pub(crate) async fn begin_upload<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
    rpc: &Rpc<'_, T, S, C, O>,
    head_ref: &str,
    pack_id: &Hash,
    bytes: u64,
    identity: Option<&Identity>,
) -> Called<BeginUploadResponse> {
    let request = BeginUploadRequest {
        r#ref: Some(head_ref.to_owned()),
        pack_id: Some(pack_id.to_vec()),
        bytes: Some(bytes),
        ..Default::default()
    };
    let intent = WriteIntent::new(procedures::BEGIN_UPLOAD)
        .with_target_ref(head_ref)
        .with_pack(*pack_id, bytes);
    let opts = Opts {
        identity,
        intent: Some(&intent),
        ..Opts::default()
    };
    rpc.unary_with("BeginUpload", &request, opts).await
}

pub(crate) async fn upload_pack<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
    rpc: &Rpc<'_, T, S, C, O>,
    pack_id: &Hash,
    pack: &[u8],
    ticket_token: Option<Vec<u8>>,
    new_objects: Option<&[Hash]>,
    identity: Option<&Identity>,
) -> Called<UploadPackResponse> {
    let intent = WriteIntent::new(procedures::UPLOAD_PACK)
        .with_pack(*pack_id, pack.len() as u64)
        .with_new_objects(new_objects);
    let opts = Opts {
        identity,
        intent: Some(&intent),
        ..Opts::default()
    };
    rpc.stream_with(
        "UploadPack",
        pack_messages(pack_id, pack, ticket_token),
        &pack_commitment(pack_id, pack),
        opts,
    )
    .await
}

pub(crate) async fn upload_part<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
    rpc: &Rpc<'_, T, S, C, O>,
    ticket_id: Hash,
    ticket_token: Option<Vec<u8>>,
    plan: &PartPlan,
    index: u32,
    part: &[u8],
    identity: Option<&Identity>,
) -> Called<UploadPartResponse> {
    let commitment = part_commitment(ticket_id, plan, index, part)?;
    let tickets = [ticket_id];
    let intent = WriteIntent::new(procedures::UPLOAD_PART)
        .with_tickets(&tickets)
        .with_part(index, part.len() as u64);
    let opts = Opts {
        identity,
        intent: Some(&intent),
        ..Opts::default()
    };
    rpc.stream_with(
        "UploadPart",
        part_messages(ticket_token, index, part),
        &commitment,
        opts,
    )
    .await
}

pub(crate) async fn complete_upload<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
    rpc: &Rpc<'_, T, S, C, O>,
    ticket_id: Option<Hash>,
    ticket_token: Option<Vec<u8>>,
    receipts: Vec<Vec<u8>>,
    identity: Option<&Identity>,
) -> Called<CompleteUploadResponse> {
    let request = CompleteUploadRequest {
        ticket_token,
        receipts,
        ..Default::default()
    };
    let tickets: Vec<Hash> = ticket_id.into_iter().collect();
    let intent = WriteIntent::new(procedures::COMPLETE_UPLOAD).with_tickets(&tickets);
    let opts = Opts {
        identity,
        intent: Some(&intent),
        ..Opts::default()
    };
    rpc.unary_with("CompleteUpload", &request, opts).await
}

/// `UpdateRef`: set `new_id`, or delete when it is `None`.
pub(crate) async fn update_ref<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
    rpc: &Rpc<'_, T, S, C, O>,
    name: &str,
    expected: RefWriteCondition,
    new_id: Option<Hash>,
    identity: Option<&Identity>,
) -> Called<UpdateRefResponse> {
    let (expectation, expected_id) = condition(expected);
    let request = UpdateRefRequest {
        name: Some(name.to_owned()),
        expectation: Some(expectation.into()),
        expected_id,
        new_id: new_id.map(|id| id.to_vec()),
        delete: new_id.is_none().then_some(true),
        ..Default::default()
    };
    let moves = [RefMove::new(
        name,
        expected,
        new_id.map_or(RefTarget::Delete, RefTarget::Set),
    )];
    let intent = WriteIntent::new(procedures::UPDATE_REF).with_ref_moves(&moves);
    let opts = Opts {
        identity,
        intent: Some(&intent),
        ..Opts::default()
    };
    rpc.unary_with("UpdateRef", &request, opts).await
}

/// The ref moves and tickets an `AdvanceRefs` request carries, read back from
/// the request itself so the observer sees exactly what is sent.
pub(crate) struct Advance {
    moves: Vec<RefMove>,
    tickets: Vec<Hash>,
}

fn id32(bytes: &[u8]) -> Result<Hash, Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Invalid("advance request id"))
}

fn old(
    expectation: Option<buffa::EnumValue<RefExpectation>>,
    expected_id: Option<&[u8]>,
) -> Result<RefWriteCondition, Error> {
    match expectation.and_then(|value| value.as_known()) {
        Some(RefExpectation::Any) => Ok(RefWriteCondition::Any),
        Some(RefExpectation::Missing) => Ok(RefWriteCondition::Missing),
        Some(RefExpectation::Match) => Ok(RefWriteCondition::Match(id32(
            expected_id.unwrap_or_default(),
        )?)),
        _ => Err(Error::Invalid("advance request expectation")),
    }
}

impl Advance {
    pub(crate) fn from_request(request: &AdvanceRefsRequest) -> Result<Self, Error> {
        let head = request.head_ref.clone().unwrap_or_default();
        let tickets = request
            .ticket_ids
            .iter()
            .map(|id| id32(id))
            .collect::<Result<Vec<_>, _>>()?;
        let mut moves = Vec::new();
        if let Some(source) = request.source_ref.as_deref().filter(|s| !s.is_empty()) {
            // A branch copy: the destination head is written; the packmap
            // twin follows server-side and is not carried by the request.
            moves.push(RefMove::new(
                head,
                RefWriteCondition::Missing,
                RefTarget::CopyFrom {
                    source: source.to_owned(),
                    expected_tip: request.expected_tip.as_deref().map(id32).transpose()?,
                },
            ));
            return Ok(Self { moves, tickets });
        }
        let target = |new_id: Option<&[u8]>| -> Result<RefTarget, Error> {
            if request.delete == Some(true) {
                return Ok(RefTarget::Delete);
            }
            let id = new_id.ok_or(Error::Invalid("advance request new id"))?;
            Ok(RefTarget::Set(id32(id)?))
        };
        moves.push(RefMove::new(
            head,
            old(
                request.head_expectation,
                request.head_expected_id.as_deref(),
            )?,
            target(request.head_new_id.as_deref())?,
        ));
        if let Some(packmap) = request.packmap_ref.clone().filter(|r| !r.is_empty()) {
            moves.push(RefMove::new(
                packmap,
                old(
                    request.packmap_expectation,
                    request.packmap_expected_id.as_deref(),
                )?,
                target(request.packmap_new_id.as_deref())?,
            ));
        }
        Ok(Self { moves, tickets })
    }

    pub(crate) fn intent(&self) -> WriteIntent<'_> {
        WriteIntent::new(procedures::ADVANCE_REFS)
            .with_ref_moves(&self.moves)
            .with_tickets(&self.tickets)
    }
}

pub(crate) async fn advance_refs<T: HttpTransport, S: Signer, C: Clock, O: Observer>(
    rpc: &Rpc<'_, T, S, C, O>,
    request: &AdvanceRefsRequest,
    identity: Option<&Identity>,
) -> Called<crate::proto::AdvanceRefsResponse> {
    let advance = Advance::from_request(request)?;
    let intent = advance.intent();
    let opts = Opts {
        identity,
        intent: Some(&intent),
        ..Opts::default()
    };
    rpc.unary_with("AdvanceRefs", request, opts).await
}
