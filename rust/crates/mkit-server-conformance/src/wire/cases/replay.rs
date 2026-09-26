//! The replay ledger (SPEC-TRANSPORT-CONNECT §7.1): a signed write retried
//! with the same nonce returns its saved result and repeats no effect; a
//! nonce reused for another operation is `invalid_argument`.

use buffa::Message as _;
use futures::future::join_all;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::{AdvanceOutcome, AdvanceRefsResponse, UpdateRefResponse};

use super::{
    A, B, C, CaseResult, Ctx, Exp, advance_req, ensure, outcome_name, random_pack, update_req,
    upload_msgs, want_code, want_ok,
};
use crate::wire::client::{Rpc, RpcError};
use crate::wire::sign::{SignedOp, Signer};

/// A signed request: exact body bytes and headers, replayable.
struct Signed {
    rpc: Rpc,
    body: Vec<u8>,
    op: SignedOp,
}

fn signed(signer: &Signer, rpc: Rpc, msg: &impl buffa::Message) -> Signed {
    let body = msg.encode_to_vec();
    let op = signer.sign_body(rpc.procedure(), &body);
    Signed { rpc, body, op }
}

async fn send_update(ctx: &Ctx, s: &Signed) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    ctx.client()
        .unary(s.rpc, s.body.clone(), &s.op.headers)
        .await
}

async fn send_advance(ctx: &Ctx, s: &Signed) -> Result<Result<i32, RpcError>, String> {
    let got: Result<AdvanceRefsResponse, _> = ctx
        .client()
        .unary(s.rpc, s.body.clone(), &s.op.headers)
        .await?;
    Ok(got.map(|r| r.outcome.map_or(0, |o| o.to_i32())))
}

fn update(ctx: &Ctx, signer: &Signer, exp: Exp<'_>, new: &[u8]) -> Signed {
    signed(
        signer,
        Rpc::UpdateRef,
        &update_req(&ctx.head("main"), exp, new),
    )
}

pub(super) async fn same_op_after_ref_moved(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let a = update(&ctx, &signer, Exp::Missing, &A);
    want_ok(send_update(&ctx, &a).await?, "first UpdateRef")?;
    let b = update(&ctx, &signer, Exp::Match(&A), &B);
    want_ok(send_update(&ctx, &b).await?, "second UpdateRef")?;
    // A re-executed MISSING would now fail, and would not move the ref.
    want_ok(send_update(&ctx, &a).await?, "replayed first UpdateRef")?;
    ctx.expect_ref(&ctx.head("main"), Some(&B)).await
}

/// All duplicates succeed with the one result. A duplicate that meets the
/// operation in flight may get a retryable `aborted` (§5), and is retried.
pub(super) async fn concurrent_duplicates(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let op = update(&ctx, &signer, Exp::Missing, &A);
    let attempt = |ctx: &Ctx, op: &Signed| {
        let (ctx, rpc, body, headers) =
            (ctx.clone(), op.rpc, op.body.clone(), op.op.headers.clone());
        async move {
            for _ in 0..20 {
                let got: Result<UpdateRefResponse, RpcError> =
                    ctx.client().unary(rpc, body.clone(), &headers).await?;
                match got {
                    Err(e) if e.code == "aborted" => {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    other => return Ok(other.map(|_| ())),
                }
            }
            Err("still `aborted` after 20 retries".to_owned())
        }
    };
    let results = join_all((0..16).map(|_| attempt(&ctx, &op))).await;
    for (i, result) in results.into_iter().enumerate() {
        want_ok(result?, &format!("duplicate {i}"))?;
    }
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await
}

pub(super) async fn nonce_reuse_different_op(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let a = update(&ctx, &signer, Exp::Missing, &A);
    want_ok(send_update(&ctx, &a).await?, "first UpdateRef")?;
    // Another operation, correctly signed, under the same nonce.
    let body = update_req(&ctx.head("main"), Exp::Any, &C).encode_to_vec();
    let mut env = signer.envelope(
        Rpc::UpdateRef.procedure(),
        crate::wire::sign::body_commitment(&body),
    );
    env.digest = Some(mkit_core::hash::to_hex(&hash(&body)));
    env.nonce.clone_from(&a.op.nonce);
    let reuse = Signed {
        rpc: Rpc::UpdateRef,
        body,
        op: signer.sign(&env),
    };
    want_code(
        send_update(&ctx, &reuse).await?,
        "invalid_argument",
        "a reused nonce",
    )?;
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await
}

/// A CAS conflict is a result too: its retry answers the same conflict
/// even after the precondition would hold.
pub(super) async fn conflict_result_replayed(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    want_ok(
        send_update(&ctx, &update(&ctx, &signer, Exp::Missing, &A)).await?,
        "create",
    )?;
    let stale = update(&ctx, &signer, Exp::Match(&B), &C);
    want_code(
        send_update(&ctx, &stale).await?,
        "failed_precondition",
        "stale MATCH",
    )?;
    want_ok(
        send_update(&ctx, &update(&ctx, &signer, Exp::Match(&A), &B)).await?,
        "move to B",
    )?;
    want_code(
        send_update(&ctx, &stale).await?,
        "failed_precondition",
        "replayed stale MATCH",
    )?;
    ctx.expect_ref(&ctx.head("main"), Some(&B)).await
}

pub(super) async fn advance_replay_equals_first(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let (head, packmap) = (ctx.head("main"), ctx.packmap("main"));
    let first = signed(
        &signer,
        Rpc::AdvanceRefs,
        &advance_req((&head, Exp::Missing, &A), (&packmap, Exp::Missing, &A)),
    );
    let committed = AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED as i32;
    let got = want_ok(send_advance(&ctx, &first).await?, "AdvanceRefs")?;
    ensure!(got == committed, "AdvanceRefs: {}", outcome_name(got));
    want_ok(
        send_update(&ctx, &update(&ctx, &signer, Exp::Match(&A), &B)).await?,
        "move head",
    )?;
    let got = want_ok(send_advance(&ctx, &first).await?, "replayed AdvanceRefs")?;
    ensure!(
        got == committed,
        "replayed AdvanceRefs: {}, want COMMITTED",
        outcome_name(got)
    );
    ctx.expect_ref(&head, Some(&B)).await?;
    ctx.expect_ref(&packmap, Some(&A)).await?;
    // A conflict replays as the same conflict, with no further effect.
    let conflict = signed(
        &signer,
        Rpc::AdvanceRefs,
        &advance_req((&head, Exp::Match(&C), &C), (&packmap, Exp::Match(&A), &C)),
    );
    let head_conflict = AdvanceOutcome::ADVANCE_OUTCOME_HEAD_CONFLICT as i32;
    let got = want_ok(
        send_advance(&ctx, &conflict).await?,
        "conflicting AdvanceRefs",
    )?;
    ensure!(
        got == head_conflict,
        "conflicting AdvanceRefs: {}",
        outcome_name(got)
    );
    want_ok(
        send_update(&ctx, &update(&ctx, &signer, Exp::Match(&B), &C)).await?,
        "move head to C",
    )?;
    let packmap_before = ctx.read(&packmap).await?;
    let got = want_ok(
        send_advance(&ctx, &conflict).await?,
        "replayed conflicting AdvanceRefs",
    )?;
    ensure!(
        got == head_conflict,
        "replayed conflict: {}, want HEAD_CONFLICT",
        outcome_name(got)
    );
    ctx.expect_ref(&head, Some(&C)).await?;
    ctx.expect_ref(&packmap, packmap_before.as_deref()).await
}

pub(super) async fn upload_replay_succeeds(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let pack = random_pack(500);
    let id = hash(&pack);
    let op = signer.sign_pack(Rpc::UploadPack.procedure(), &id, pack.len() as u64);
    let msgs = upload_msgs(&pack, 2);
    for attempt in ["first", "replayed"] {
        let got = ctx.upload_with(&msgs, &op.headers).await?;
        ensure!(got.is_none(), "{attempt} UploadPack: {got:?}");
    }
    let bytes = ctx.fetch(&id).await?;
    ensure!(bytes == pack, "downloaded bytes differ");
    Ok(())
}

/// §7.1: expired requests are rejected even when their result is cached.
/// Needs the `test-faults` clock skew to reach the expiry without waiting.
pub(super) async fn expired_retry_rejected(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let a = update(&ctx, &signer, Exp::Missing, &A);
    want_ok(send_update(&ctx, &a).await?, "UpdateRef")?;
    let mut headers = a.op.headers.clone();
    headers.push((
        crate::wire::CLOCK_SKEW_HEADER.to_owned(),
        "300000".to_owned(),
    ));
    let got: Result<UpdateRefResponse, RpcError> =
        ctx.client().unary(a.rpc, a.body.clone(), &headers).await?;
    want_code(got, "unauthenticated", "a replay past its expiry")?;
    ctx.expect_ref(&ctx.head("main"), Some(&A)).await
}
