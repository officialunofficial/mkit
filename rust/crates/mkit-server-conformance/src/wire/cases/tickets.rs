//! `BeginUpload`'s unary outcomes and per-signer cap over the real wire.

use buffa::Message;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result as BeginResult;
use mkit_transport_connect::generated::{
    AdvanceOutcome, AdvanceRefsRequest, AdvanceRefsResponse, BeginUploadRequest,
    BeginUploadResponse, UploadPackRequest, UploadTicket,
};

use super::{
    A, B, CaseResult, Commit, Ctx, Exp, Failure, advance_req, ensure, repository, sign_unary,
    upload_msgs, want_code, want_ok, want_outcome,
};
use crate::wire::client::{Rpc, RpcError};
use crate::wire::profile::Feature;
use crate::wire::sign::Signer;

pub(super) fn request(name: String, salt: u64) -> BeginUploadRequest {
    BeginUploadRequest {
        r#ref: Some(name),
        pack_id: Some(hash(&salt.to_be_bytes()).to_vec()),
        bytes: Some(8),
        ..Default::default()
    }
}

pub(super) fn ticket(response: BeginUploadResponse) -> Result<UploadTicket, Failure> {
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

fn ticket_advance(ctx: &Ctx, branch: &str, ids: Vec<Vec<u8>>) -> AdvanceRefsRequest {
    let mut req = advance_req(
        (&ctx.head(branch), Exp::Missing, &A),
        (&ctx.packmap(branch), Exp::Missing, &B),
    );
    req.ticket_ids = ids;
    req
}

fn exact(error: crate::wire::client::RpcError, message: &str) -> CaseResult {
    ensure!(
        error.message == message,
        "message {:?}, want {message:?}",
        error.message
    );
    Ok(())
}

pub(super) async fn advance_ticket_id_errors(ctx: Ctx) -> CaseResult {
    let id = vec![7; 32];
    let mut req = ticket_advance(&ctx, "ticket-errors", vec![vec![7; 31]]);
    exact(
        want_code(
            ctx.advance(&req).await?,
            "invalid_argument",
            "short ticket id",
        )?,
        "ticket id must be 32 bytes",
    )?;
    req.ticket_ids = vec![id.clone(), id];
    exact(
        want_code(
            ctx.advance(&req).await?,
            "invalid_argument",
            "duplicate ticket id",
        )?,
        "duplicate ticket id",
    )?;
    req.ticket_ids = (0..8).map(|i| vec![i; 32]).collect();
    exact(
        want_code(
            ctx.advance(&req).await?,
            "invalid_argument",
            "eight tickets",
        )?,
        "too many tickets in one advance",
    )
}

pub(super) async fn advance_marker_then_upload(ctx: Ctx) -> CaseResult {
    let pack = b"ticket advance marker roundtrip";
    let opened = open_for_pack(&ctx, pack).await?;
    let id = opened
        .id
        .clone()
        .ok_or_else(|| Failure::Fail("missing ticket id".into()))?;
    let req = ticket_advance(&ctx, "ticketed", vec![id]);
    exact(
        want_code(
            ctx.advance(&req).await?,
            "failed_precondition",
            "missing marker",
        )?,
        "upload not complete for ticket",
    )?;
    let pack_id = hash(pack);
    let msgs = ticketed_msgs(pack, opened.token.unwrap_or_default());
    let headers = ctx.auth_headers(Rpc::UploadPack, Commit::Pack(&pack_id, pack.len() as u64));
    ensure!(
        ctx.upload_with(&msgs, &headers).await?.is_none(),
        "ticket upload failed"
    );
    want_outcome(
        ctx.advance(&req).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )
}

pub(super) async fn advance_conflicts_keep_ticket(ctx: Ctx) -> CaseResult {
    let pack = b"ticket advance conflict pack";
    let opened = open_for_pack(&ctx, pack).await?;
    let id = opened
        .id
        .clone()
        .ok_or_else(|| Failure::Fail("missing ticket id".into()))?;
    let pack_id = hash(pack);
    let msgs = ticketed_msgs(pack, opened.token.unwrap_or_default());
    let headers = ctx.auth_headers(Rpc::UploadPack, Commit::Pack(&pack_id, pack.len() as u64));
    ensure!(
        ctx.upload_with(&msgs, &headers).await?.is_none(),
        "ticket upload failed"
    );

    let head = ctx.head("ticketed");
    let pm = ctx.packmap("ticketed");
    let mut wrong_packmap = advance_req((&head, Exp::Missing, &A), (&pm, Exp::Match(&B), &B));
    wrong_packmap.ticket_ids = vec![id.clone()];
    want_outcome(
        ctx.advance(&wrong_packmap).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_PACKMAP_CONFLICT,
    )?;

    let mut wrong_head = advance_req((&head, Exp::Match(&A), &A), (&pm, Exp::Missing, &B));
    wrong_head.ticket_ids = vec![id.clone()];
    want_outcome(
        ctx.advance(&wrong_head).await?,
        AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT,
    )?;

    want_outcome(
        ctx.advance(&ticket_advance(&ctx, "ticketed", vec![id]))
            .await?,
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )
}

/// Where a case's ticketed calls go: the deployment's one repository, or,
/// under Multi, a repository the `repository-a` signer owns (so its
/// tickets bind to that owner; any other signer is denied by policy).
struct Target(Option<(Signer, String)>);

impl Target {
    fn new(ctx: &Ctx, name: &str) -> Result<Self, Failure> {
        if !ctx.profile().has(Feature::MultiRepo) {
            return Ok(Self(None));
        }
        let (repository, _) = repository::identities(ctx, name, "unused")?;
        Ok(Self(Some((ctx.v2_signer("repository-a")?, repository))))
    }

    /// `rpc` as the owner, or as the `other-signer` stranger.
    async fn call<M: Message>(
        &self,
        ctx: &Ctx,
        stranger: bool,
        rpc: Rpc,
        req: &impl Message,
    ) -> Result<Result<M, RpcError>, String> {
        let label = if stranger { "other-signer" } else { "main" };
        let Some((owner, repository)) = &self.0 else {
            return ctx.call_as(label, rpc, req).await;
        };
        let other;
        let who = if stranger {
            other = ctx
                .v2_signer(label)
                .map_err(|_| "needs auth v2".to_owned())?;
            &other
        } else {
            owner
        };
        let request = sign_unary(who, rpc, req, |env| {
            repository.clone_into(&mut env.repository);
        });
        ctx.send(&request).await
    }
}

pub(super) async fn advance_ticket_bindings(ctx: Ctx) -> CaseResult {
    let target = Target::new(&ctx, "bindings")?;
    let pack = b"ticket advance bindings";
    let begin = BeginUploadRequest {
        r#ref: Some(ctx.head("ticketed")),
        pack_id: Some(hash(pack).to_vec()),
        bytes: Some(pack.len() as u64),
        ..Default::default()
    };
    let id = ticket(want_ok(
        target.call(&ctx, false, Rpc::BeginUpload, &begin).await?,
        "BeginUpload",
    )?)?
    .id
    .ok_or_else(|| Failure::Fail("missing ticket id".into()))?;
    let advance = |branch: &str, ids, stranger| {
        let req = ticket_advance(&ctx, branch, ids);
        let (target, ctx) = (&target, &ctx);
        async move {
            target
                .call::<AdvanceRefsResponse>(ctx, stranger, Rpc::AdvanceRefs, &req)
                .await
        }
    };
    exact(
        want_code(
            advance("ticketed", vec![vec![0xff; 32]], false).await?,
            "failed_precondition",
            "unknown ticket",
        )?,
        "invalid or expired upload ticket",
    )?;
    exact(
        want_code(
            advance("wrong-ref", vec![id.clone()], false).await?,
            "failed_precondition",
            "ticket ref mismatch",
        )?,
        "invalid or expired upload ticket",
    )?;
    let error = want_code(
        advance("ticketed", vec![id], true).await?,
        "permission_denied",
        "ticket signer mismatch",
    )?;
    // Under Multi the stranger is refused as a non-owner before the ticket
    // binding is looked at, with the policy's own message.
    if !ctx.profile().has(Feature::MultiRepo) {
        exact(error, "upload ticket binding mismatch")?;
    }
    Ok(())
}

pub(super) async fn begin_upload_per_ref_cap(ctx: Ctx) -> CaseResult {
    let (per_ref, per_signer) = (
        ctx.profile().ticket_per_ref,
        ctx.profile().ticket_per_signer,
    );
    ensure!(
        per_ref > 0 && per_signer > 0,
        "ticket caps must be positive"
    );
    if per_ref > 4_096 {
        return Err(Failure::Skip(format!(
            "a per-ref cap of {per_ref} needs too many BeginUpload calls"
        )));
    }
    let name = ctx.head("per-ref");
    let mut opened = 0;
    while opened < per_ref {
        // A fresh signer per block keeps every signer under its own cap.
        let label = format!("per-ref-{}", opened / per_signer);
        let req = request(name.clone(), 1_000 + opened);
        let result: BeginUploadResponse = want_ok(
            ctx.call_as(&label, Rpc::BeginUpload, &req).await?,
            "BeginUpload below the per-ref cap",
        )?;
        ticket(result)?;
        opened += 1;
    }
    let over = request(name, 1_000 + per_ref);
    let result: Result<BeginUploadResponse, _> =
        ctx.call_as("per-ref-over", Rpc::BeginUpload, &over).await?;
    exact(
        want_code(
            result,
            "failed_precondition",
            "BeginUpload at the per-ref cap",
        )?,
        "too many open upload tickets",
    )?;
    // The cap is per target ref: the same signer opens one on another ref.
    let elsewhere = request(ctx.head("per-ref-other"), 1);
    let result: BeginUploadResponse = want_ok(
        ctx.call_as("per-ref-over", Rpc::BeginUpload, &elsewhere)
            .await?,
        "BeginUpload on another ref",
    )?;
    ticket(result)?;
    Ok(())
}

pub(super) async fn expiry_timer_frees_cap_slot(ctx: Ctx) -> CaseResult {
    let cap = ctx.profile().ticket_per_signer;
    ensure!(cap > 0, "ticket_per_signer must be positive");
    let name = ctx.head("expiring");
    let mut last_expiry = 0;
    for salt in 0..cap {
        let mut req = request(name.clone(), salt);
        // One real session suffices; the remaining tickets fill the cap
        // without spending a large upload quota or opening needless sessions.
        if salt == 0
            && ctx.profile().has(Feature::Multipart)
            && ctx.profile().max_pack_bytes > mkit_core::upload_parts::MIN_PART_SIZE
        {
            req.bytes = Some(mkit_core::upload_parts::MIN_PART_SIZE + 1);
        }
        let result: BeginUploadResponse = want_ok(
            ctx.call_as("expiring", Rpc::BeginUpload, &req).await?,
            "BeginUpload below cap",
        )?;
        last_expiry = last_expiry.max(ticket(result)?.expires_unix_ms.unwrap_or_default());
    }
    let next = request(name.clone(), cap);
    let full: Result<BeginUploadResponse, _> =
        ctx.call_as("expiring", Rpc::BeginUpload, &next).await?;
    want_code(full, "failed_precondition", "BeginUpload at the cap")?;
    // Skew the business clock past every expiry and tick the shard: the
    // kind-2 handler closes each ticket and returns its cap slots.
    let skew = last_expiry - crate::wire::sign::now_ms() + 1_000;
    super::timers::tick_shard(&ctx, &name, skew).await?;
    let freed: BeginUploadResponse = want_ok(
        ctx.call_as("expiring", Rpc::BeginUpload, &next).await?,
        "BeginUpload after the expiry timer",
    )?;
    ticket(freed)?;
    Ok(())
}

pub(super) async fn advance_other_repository(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("repository-a")?;
    let namespace = format!("ed25519-{}", signer.public_key_hex());
    let repo_a = format!("{namespace}/ticket-a");
    let repo_b = format!("{namespace}/ticket-b");
    let pack = b"repository binding ticket";
    let begin = BeginUploadRequest {
        r#ref: Some(ctx.head("main")),
        pack_id: Some(hash(pack).to_vec()),
        bytes: Some(pack.len() as u64),
        ..Default::default()
    };
    let opened: BeginUploadResponse = want_ok(
        ctx.send(
            &sign_unary(&signer, Rpc::BeginUpload, &begin, |env| {
                env.repository.clone_from(&repo_a);
            })
            .with_header("x-repository", &repo_a),
        )
        .await?,
        "BeginUpload repository A",
    )?;
    let id = ticket(opened)?
        .id
        .ok_or_else(|| Failure::Fail("missing ticket id".into()))?;
    let req = ticket_advance(&ctx, "main", vec![id]);
    let response: Result<mkit_transport_connect::generated::AdvanceRefsResponse, _> = ctx
        .send(
            &sign_unary(&signer, Rpc::AdvanceRefs, &req, |env| {
                env.repository.clone_from(&repo_b);
            })
            .with_header("x-repository", &repo_b),
        )
        .await?;
    exact(
        want_code(
            response,
            "failed_precondition",
            "ticket in another repository",
        )?,
        "invalid or expired upload ticket",
    )
}

pub(super) async fn advance_expired_ticket(ctx: Ctx) -> CaseResult {
    let pack = b"ticket advance expiry";
    let opened = open_for_pack(&ctx, pack).await?;
    let id = opened
        .id
        .ok_or_else(|| Failure::Fail("missing ticket id".into()))?;
    let expires = opened
        .expires_unix_ms
        .ok_or_else(|| Failure::Fail("missing ticket expiry".into()))?;
    let req = ticket_advance(&ctx, "ticketed", vec![id]);
    let skew = expires - crate::wire::sign::now_ms() + 1_000;
    let signer = ctx.v2_signer("main")?;
    let envelope = sign_unary(&signer, Rpc::AdvanceRefs, &req, |env| {
        env.created_at += skew;
        env.expires_at += skew;
    })
    .with_header(crate::wire::CLOCK_SKEW_HEADER, skew.to_string());
    let response: Result<mkit_transport_connect::generated::AdvanceRefsResponse, _> =
        ctx.send(&envelope).await?;
    exact(
        want_code(response, "failed_precondition", "expired ticket")?,
        "invalid or expired upload ticket",
    )
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
    let expires = opened
        .expires_unix_ms
        .ok_or_else(|| Failure::Fail("expired ticket case needs a ticket expiry".into()))?;
    let msgs = ticketed_msgs(pack, opened.token.unwrap_or_default());
    // The test directive shifts auth time too. Sign inside that shifted
    // validity window so ticket expiry is the first failing check.
    let skew = expires - crate::wire::sign::now_ms() + 1_000;
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
