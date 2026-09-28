//! `BeginUpload`'s unary outcomes and per-signer cap over the real wire.

use buffa::Message;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result as BeginResult;
use mkit_transport_connect::generated::{
    BeginUploadRequest, BeginUploadResponse, UploadPackRequest, UploadTicket,
};

use super::{
    CaseResult, Commit, Ctx, Failure, ensure, sign_unary, upload_msgs, want_code, want_ok,
};
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

fn ticketed_msgs(pack: &[u8], token: Vec<u8>) -> Vec<UploadPackRequest> {
    let mut msgs = upload_msgs(pack, 2);
    if let Some(
        mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body::Header(
            header,
        ),
    ) = &mut msgs[0].body
    {
        header.ticket_token = Some(token);
    }
    msgs
}

async fn open_for_pack(ctx: &Ctx, pack: &[u8]) -> Result<UploadTicket, Failure> {
    let req = BeginUploadRequest {
        r#ref: Some(ctx.head("ticketed")),
        pack_id: Some(hash(pack).to_vec()),
        bytes: Some(pack.len() as u64),
        ..Default::default()
    };
    ticket(want_ok(
        ctx.call(Rpc::BeginUpload, &req).await?,
        "BeginUpload",
    )?)
}

pub(super) async fn upload_pack_ticketed(ctx: Ctx) -> CaseResult {
    let pack = b"ticketed conformance pack";
    let opened = open_for_pack(&ctx, pack).await?;
    let id = hash(pack);
    let msgs = ticketed_msgs(pack, opened.token.unwrap_or_default());
    let headers = ctx.auth_headers(Rpc::UploadPack, Commit::Pack(&id, pack.len() as u64));
    for _ in 0..2 {
        let error = ctx.upload_with(&msgs, &headers).await?;
        ensure!(error.is_none(), "ticketed UploadPack: {error:?}");
    }
    ctx.expect_exists(&id, true).await?;
    Ok(())
}

pub(super) async fn upload_pack_bad_token(ctx: Ctx) -> CaseResult {
    let pack = b"bad ticket token pack";
    let id = hash(pack);
    let msgs = ticketed_msgs(pack, vec![0x55; 16]);
    let headers = ctx.auth_headers(Rpc::UploadPack, Commit::Pack(&id, pack.len() as u64));
    let error = ctx.upload_with(&msgs, &headers).await?;
    ensure!(
        error.as_ref().map(|e| e.code.as_str()) == Some("failed_precondition"),
        "bad ticket token: {error:?}"
    );
    ctx.expect_exists(&id, false).await
}

pub(super) async fn upload_pack_binding_denied(ctx: Ctx) -> CaseResult {
    let pack = b"ticket binding original";
    let opened = open_for_pack(&ctx, pack).await?;
    let different = b"ticket binding altered";
    let id = hash(different);
    let msgs = ticketed_msgs(different, opened.token.unwrap_or_default());
    let headers = ctx.auth_headers(Rpc::UploadPack, Commit::Pack(&id, different.len() as u64));
    let error = ctx.upload_with(&msgs, &headers).await?;
    ensure!(
        error.as_ref().map(|e| e.code.as_str()) == Some("permission_denied"),
        "ticket binding: {error:?}"
    );
    ctx.expect_exists(&id, false).await
}

pub(super) async fn upload_pack_expired_token(ctx: Ctx) -> CaseResult {
    let pack = b"expired ticket token pack";
    let opened = open_for_pack(&ctx, pack).await?;
    let id = hash(pack);
    let msgs = ticketed_msgs(pack, opened.token.unwrap_or_default());
    // The test directive shifts auth time too. Sign inside that shifted
    // validity window so ticket expiry is the first failing check.
    let skew = 100_000_000_i64;
    let signer = ctx.v2_signer("main")?;
    let mut envelope = signer.envelope(
        Rpc::UploadPack.procedure(),
        crate::wire::sign::pack_commitment(&id, pack.len() as u64),
    );
    envelope.created_at += skew;
    envelope.expires_at += skew;
    let mut headers = signer.sign(&envelope).headers;
    headers.push((crate::wire::CLOCK_SKEW_HEADER.into(), skew.to_string()));
    let error = ctx.upload_with(&msgs, &headers).await?;
    ensure!(
        error.as_ref().map(|e| e.code.as_str()) == Some("failed_precondition"),
        "expired ticket token: {error:?}"
    );
    ctx.expect_exists(&id, false).await
}
