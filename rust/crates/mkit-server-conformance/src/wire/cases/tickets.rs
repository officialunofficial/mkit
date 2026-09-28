//! `BeginUpload`'s unary outcomes and per-signer cap over the real wire.

use buffa::Message;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result as BeginResult;
use mkit_transport_connect::generated::{BeginUploadRequest, BeginUploadResponse, UploadTicket};

use super::{CaseResult, Ctx, Failure, ensure, sign_unary, want_code, want_ok};
use crate::wire::client::Rpc;

fn request(name: String, salt: u64) -> BeginUploadRequest {
    BeginUploadRequest {
        r#ref: Some(name),
        pack_id: Some(hash(&salt.to_be_bytes()).to_vec()),
        bytes: Some(8),
        ..Default::default()
    }
}

fn ticket(response: BeginUploadResponse) -> Result<UploadTicket, Failure> {
    match response.result {
        Some(BeginResult::Ticket(ticket)) => Ok(*ticket),
        other => Err(Failure::Fail(format!(
            "BeginUpload expected a ticket, got {other:?}"
        ))),
    }
}

pub(super) async fn begin_upload_new(ctx: Ctx) -> CaseResult {
    let req = request(ctx.head("main"), 1);
    let result: BeginUploadResponse =
        want_ok(ctx.call(Rpc::BeginUpload, &req).await?, "BeginUpload")?;
    let ticket = ticket(result)?;
    ensure!(
        ticket.id.as_deref().is_some_and(|id| id.len() == 32),
        "ticket id must be 32 bytes"
    );
    let part_size = ticket.part_size.unwrap_or_default();
    ensure!(
        part_size >= mkit_core::upload_parts::MIN_PART_SIZE && part_size.is_power_of_two(),
        "invalid ticket part size {part_size}"
    );
    ensure!(
        ticket.expires_unix_ms.is_some_and(|expires| expires > 0),
        "ticket expiry must be positive"
    );
    ensure!(
        ticket
            .token
            .as_deref()
            .is_some_and(|token| !token.is_empty()),
        "ticket token is empty"
    );
    Ok(())
}

pub(super) async fn begin_upload_idempotent(ctx: Ctx) -> CaseResult {
    let req = request(ctx.head("main"), 2);
    let signer = ctx.v2_signer("main")?;
    let envelope = sign_unary(&signer, Rpc::BeginUpload, &req, |_| {});
    let first: BeginUploadResponse = want_ok(ctx.send(&envelope).await?, "first BeginUpload")?;
    let again: BeginUploadResponse = want_ok(
        ctx.call(Rpc::BeginUpload, &req).await?,
        "live ticket BeginUpload",
    )?;
    ensure!(
        first == again,
        "a fresh nonce returned a different live ticket"
    );
    let replay: BeginUploadResponse = want_ok(ctx.send(&envelope).await?, "BeginUpload replay")?;
    ensure!(
        first.encode_to_vec() == replay.encode_to_vec(),
        "the replay changed ticket bytes"
    );
    let different: BeginUploadResponse = want_ok(
        ctx.call_as("other-signer", Rpc::BeginUpload, &req).await?,
        "other signer BeginUpload",
    )?;
    ensure!(
        ticket(first)?.id != ticket(different)?.id,
        "different signers received the same ticket"
    );
    Ok(())
}

pub(super) async fn begin_upload_caps(ctx: Ctx) -> CaseResult {
    let cap = ctx.profile().ticket_per_signer;
    ensure!(cap > 0, "ticket_per_signer must be positive");
    for index in 0..cap {
        let req = request(ctx.head("capped"), 100 + index);
        let result: BeginUploadResponse = want_ok(
            ctx.call_as("capped", Rpc::BeginUpload, &req).await?,
            "BeginUpload below cap",
        )?;
        ticket(result)?;
    }
    let signer = ctx.v2_signer("capped")?;
    let req = request(ctx.head("capped"), 100 + cap);
    let envelope = sign_unary(&signer, Rpc::BeginUpload, &req, |_| {});
    let result: Result<BeginUploadResponse, _> = ctx.send(&envelope).await?;
    let error = want_code(result, "failed_precondition", "BeginUpload at cap")?;
    ensure!(
        error.message == "too many open upload tickets",
        "unexpected cap message {:?}",
        error.message
    );
    // A cap rejection writes no replay row: changing the body under the
    // same nonce must still reach the cap, rather than fail its fingerprint.
    let changed = request(ctx.head("capped"), 101 + cap);
    let changed = sign_unary(&signer, Rpc::BeginUpload, &changed, |env| {
        env.nonce.clone_from(&envelope.nonce);
    });
    let result: Result<BeginUploadResponse, _> = ctx.send(&changed).await?;
    want_code(
        result,
        "failed_precondition",
        "cap rejection left no replay row",
    )?;
    Ok(())
}

pub(super) async fn begin_upload_packmap_refused(ctx: Ctx) -> CaseResult {
    let req = request(ctx.packmap("main"), 3);
    let result: Result<BeginUploadResponse, _> = ctx.call(Rpc::BeginUpload, &req).await?;
    want_code(result, "invalid_argument", "BeginUpload targeting packmap")?;
    Ok(())
}
