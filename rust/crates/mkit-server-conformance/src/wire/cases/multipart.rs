//! Multipart uploads over real Connect streams (STC §7.6).

use buffa::Message;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan, part_subtree_cv};
use mkit_transport_connect::generated::__buffa::oneof::{
    begin_upload_response::Result as BeginResult, upload_part_request::Msg as PartMsg,
};
use mkit_transport_connect::generated::{
    BeginUploadRequest, BeginUploadResponse, CompleteUploadRequest, CompleteUploadResponse,
    PackExistsRequest, PackExistsResponse, UploadPartHeader, UploadPartRequest, UploadPartResponse,
    UploadTicket,
};

use super::{CaseResult, Ctx, Failure, ensure, sign_unary, want_code, want_ok};
use crate::wire::client::{Rpc, RpcError, StreamReply, frames};
use crate::wire::sign::Signer;

const CHUNK: usize = 256 * 1024;

fn pack(ctx: &Ctx) -> Vec<u8> {
    let mut data: Vec<u8> = (0_u8..=250)
        .cycle()
        .take(usize::try_from(MIN_PART_SIZE).expect("part size fits usize") * 2 + 1024 * 1024 + 17)
        .collect();
    data[..32].copy_from_slice(&hash(ctx.ns().as_bytes()));
    data
}

fn ticket(result: BeginUploadResponse) -> Result<UploadTicket, Failure> {
    match result.result {
        Some(BeginResult::Ticket(ticket)) => Ok(*ticket),
        other => Err(Failure::Fail(format!(
            "expected multipart ticket, got {other:?}"
        ))),
    }
}

async fn begin(
    ctx: &Ctx,
    signer: &Signer,
    repository: Option<&str>,
    key: &[u8; 32],
    len: usize,
) -> Result<UploadTicket, Failure> {
    let request = BeginUploadRequest {
        r#ref: Some(ctx.head("main")),
        pack_id: Some(key.to_vec()),
        bytes: Some(len as u64),
        ..Default::default()
    };
    let signed_request = sign_unary(signer, Rpc::BeginUpload, &request, |env| {
        if let Some(repository) = repository {
            repository.clone_into(&mut env.repository);
        }
    });
    let response: BeginUploadResponse = want_ok(ctx.send(&signed_request).await?, "BeginUpload")?;
    let ticket = ticket(response)?;
    ensure!(
        ticket.id.as_deref().is_some_and(|id| id.len() == 32),
        "ticket id is not 32 bytes"
    );
    ensure!(
        ticket.part_size == Some(MIN_PART_SIZE),
        "multipart baseline must use 8 MiB parts"
    );
    ensure!(
        ticket.token.as_ref().is_some_and(|token| !token.is_empty()),
        "ticket token is empty"
    );
    Ok(ticket)
}

async fn part(
    ctx: &Ctx,
    signer: &Signer,
    repository: Option<&str>,
    ticket: &UploadTicket,
    plan: &PartPlan,
    index: u32,
    bytes: &[u8],
) -> Result<Vec<u8>, Failure> {
    let cv = part_subtree_cv(plan, index, bytes).map_err(|e| e.to_string())?;
    let id = ticket.id.as_ref().ok_or("missing ticket id")?;
    let commitment = format!(
        "part:{}:{index}:{}:{}",
        to_hex_bytes(id),
        to_hex(&cv),
        bytes.len()
    );
    let mut envelope = signer.envelope(Rpc::UploadPart.procedure(), commitment);
    if let Some(repository) = repository {
        repository.clone_into(&mut envelope.repository);
    }
    let headers = signer.sign(&envelope).headers;
    let mut messages = vec![UploadPartRequest {
        msg: Some(PartMsg::Header(Box::new(UploadPartHeader {
            ticket_token: ticket.token.clone(),
            index: Some(index),
            ..Default::default()
        }))),
        ..Default::default()
    }];
    for chunk in bytes.chunks(CHUNK) {
        messages.push(UploadPartRequest {
            msg: Some(PartMsg::Chunk(chunk.to_vec())),
            ..Default::default()
        });
    }
    let response: StreamReply<UploadPartResponse> = ctx
        .client()
        .stream(Rpc::UploadPart, frames(&messages), &headers)
        .await?;
    ensure!(
        response.error.is_none(),
        "UploadPart {index}: {:?}",
        response.error
    );
    ensure!(
        response.messages.len() == 1,
        "UploadPart {index}: {} responses",
        response.messages.len()
    );
    let receipt = response
        .messages
        .into_iter()
        .next()
        .and_then(|message| message.receipt);
    ensure!(
        receipt.as_ref().is_some_and(|receipt| !receipt.is_empty()),
        "empty part receipt"
    );
    receipt.ok_or_else(|| Failure::Fail("missing part receipt".into()))
}

async fn parts(
    ctx: &Ctx,
    signer: &Signer,
    repository: Option<&str>,
    ticket: &UploadTicket,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, Failure> {
    let plan =
        PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, u32::MAX).map_err(|e| e.to_string())?;
    let mut receipts = Vec::new();
    for index in 0..plan.count() {
        let offset = usize::try_from(plan.offset(index).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let len = usize::try_from(plan.expected_len(index).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        receipts.push(
            part(
                ctx,
                signer,
                repository,
                ticket,
                &plan,
                index,
                &bytes[offset..offset + len],
            )
            .await?,
        );
    }
    Ok(receipts)
}

async fn complete(
    ctx: &Ctx,
    signer: &Signer,
    repository: Option<&str>,
    ticket: &UploadTicket,
    receipts: Vec<Vec<u8>>,
) -> Result<Result<CompleteUploadResponse, RpcError>, Failure> {
    let request = CompleteUploadRequest {
        ticket_token: ticket.token.clone(),
        receipts,
        ..Default::default()
    };
    let signed_request = sign_unary(signer, Rpc::CompleteUpload, &request, |env| {
        if let Some(repository) = repository {
            repository.clone_into(&mut env.repository);
        }
    });
    Ok(ctx.send(&signed_request).await?)
}

/// Complete the Uno canonical fixture using the existing streamed multipart path.
pub(super) async fn complete_uno_ticket(
    ctx: &Ctx,
    signer: &Signer,
    repository: &str,
    ticket: &UploadTicket,
    bytes: &[u8],
) -> Result<Vec<u8>, Failure> {
    let id = ticket.id.clone().ok_or("ticket has no id")?;
    let receipts = parts(ctx, signer, Some(repository), ticket, bytes).await?;
    want_ok(
        complete(ctx, signer, Some(repository), ticket, receipts).await?,
        "Uno CompleteUpload",
    )?;
    Ok(id)
}

pub(super) async fn three_parts(ctx: Ctx) -> CaseResult {
    let bytes = pack(&ctx);
    let id = hash(&bytes);
    let signer = ctx.v2_signer("main")?;
    let ticket = begin(&ctx, &signer, None, &id, bytes.len()).await?;
    let receipts = parts(&ctx, &signer, None, &ticket, &bytes).await?;
    ensure!(receipts.len() == 3, "expected three receipts");
    ctx.expect_exists(&id, false).await?;
    want_ok(
        complete(&ctx, &signer, None, &ticket, receipts.clone()).await?,
        "CompleteUpload",
    )?;
    ctx.expect_exists(&id, true).await?;
    want_ok(
        complete(&ctx, &signer, None, &ticket, receipts).await?,
        "repeated CompleteUpload",
    )?;
    Ok(())
}

pub(super) async fn resume_receipts(ctx: Ctx) -> CaseResult {
    let bytes = pack(&ctx);
    let id = hash(&bytes);
    let ticket = begin(&ctx, &ctx.v2_signer("main")?, None, &id, bytes.len()).await?;
    let plan =
        PartPlan::new(bytes.len() as u64, MIN_PART_SIZE, u32::MAX).map_err(|e| e.to_string())?;
    let signer = ctx.v2_signer("main")?;
    let first_end = usize::try_from(MIN_PART_SIZE).map_err(|e| e.to_string())?;
    let second_end = usize::try_from(2 * MIN_PART_SIZE).map_err(|e| e.to_string())?;
    let first = part(&ctx, &signer, None, &ticket, &plan, 0, &bytes[..first_end]).await?;
    let old_second = part(
        &ctx,
        &signer,
        None,
        &ticket,
        &plan,
        1,
        &bytes[first_end..second_end],
    )
    .await?;
    let fresh = ctx.reconnect()?;
    drop(ctx);
    let signer = fresh.v2_signer("main")?;
    let new_second = part(
        &fresh,
        &signer,
        None,
        &ticket,
        &plan,
        1,
        &bytes[first_end..second_end],
    )
    .await?;
    ensure!(
        old_second == new_second,
        "resending a verified part changed its receipt"
    );
    let last = part(
        &fresh,
        &signer,
        None,
        &ticket,
        &plan,
        2,
        &bytes[second_end..],
    )
    .await?;
    want_ok(
        complete(
            &fresh,
            &signer,
            None,
            &ticket,
            vec![first, new_second, last],
        )
        .await?,
        "resumed CompleteUpload",
    )?;
    fresh.expect_exists(&id, true).await
}

pub(super) async fn root_mismatch_invisible(ctx: Ctx) -> CaseResult {
    let bytes = pack(&ctx);
    let wrong = hash(b"wrong multipart root");
    let signer = ctx.v2_signer("main")?;
    let ticket = begin(&ctx, &signer, None, &wrong, bytes.len()).await?;
    let receipts = parts(&ctx, &signer, None, &ticket, &bytes).await?;
    want_code(
        complete(&ctx, &signer, None, &ticket, receipts).await?,
        "invalid_argument",
        "mismatched root",
    )?;
    ctx.expect_exists(&wrong, false).await
}

async fn exists_in_repo(ctx: &Ctx, repository: &str, id: &[u8]) -> Result<bool, Failure> {
    let request = PackExistsRequest {
        pack_id: Some(id.to_vec()),
        ..Default::default()
    };
    let body = request.encode_to_vec();
    let headers = vec![("x-repository".to_owned(), repository.to_owned())];
    let response: PackExistsResponse = want_ok(
        ctx.client().unary(Rpc::PackExists, body, &headers).await?,
        "PackExists",
    )?;
    Ok(response.exists == Some(true))
}

pub(super) async fn cross_repository_no_oracle(ctx: Ctx) -> CaseResult {
    let (repo_a, repo_b) = super::repository::identities(&ctx, "multipart-a", "multipart-b")?;
    let signer_a = ctx.v2_signer("repository-a")?;
    let signer_b = ctx.v2_signer("repository-b")?;
    let bytes = pack(&ctx);
    let id = hash(&bytes);
    let ticket_a = begin(&ctx, &signer_a, Some(&repo_a), &id, bytes.len()).await?;
    let ticket_b = begin(&ctx, &signer_b, Some(&repo_b), &id, bytes.len()).await?;
    let receipts_b = parts(&ctx, &signer_b, Some(&repo_b), &ticket_b, &bytes).await?;
    want_code(
        complete(
            &ctx,
            &signer_a,
            Some(&repo_a),
            &ticket_b,
            receipts_b.clone(),
        )
        .await?,
        "permission_denied",
        "foreign ticket",
    )?;
    let count = receipts_b.len();
    let foreign = complete(&ctx, &signer_a, Some(&repo_a), &ticket_a, receipts_b)
        .await?
        .err()
        .ok_or("foreign receipts were accepted")?;
    let garbage = complete(
        &ctx,
        &signer_a,
        Some(&repo_a),
        &ticket_a,
        vec![b"garbage receipt".to_vec(); count],
    )
    .await?
    .err()
    .ok_or("garbage receipts were accepted")?;
    ensure!(
        foreign.code == "invalid_argument",
        "foreign receipt code {} is not invalid_argument",
        foreign.code
    );
    ensure!(
        foreign.code == garbage.code,
        "foreign receipt code {} differs from garbage receipt code {}",
        foreign.code,
        garbage.code
    );
    ensure!(
        !exists_in_repo(&ctx, &repo_a, &id).await?,
        "foreign receipts made the pack a member"
    );
    Ok(())
}
