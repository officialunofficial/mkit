//! Exactly one terminal outcome per reservation, delivered at least once.
use super::admission::{
    calls, credential, ledger, mode, paid, post, snapshot, stub, wait_new, want_error,
};
use super::{A, B, CaseResult, Ctx, Exp, ensure, sign_unary, update_req};
use crate::wire::client::{Rpc, UNARY_JSON};
use std::time::Duration;

async fn release(ctx: &Ctx) -> CaseResult {
    stub(ctx)?
        .post("/__stub/release", UNARY_JSON, &[], vec![])
        .await?;
    mode(ctx, "normal", "normal").await
}
pub(super) async fn aborted_on_cas_loss(ctx: Ctx) -> CaseResult {
    mode(&ctx, "hold", "normal").await?;
    let before = snapshot(&ctx).await?;
    let initial = calls(&ctx).await?;
    let req = update_req(&ctx.head("main"), Exp::Missing, &A);
    let mut tasks = Vec::new();
    for (label, value) in [("main", A), ("racer", B)] {
        let req = update_req(&ctx.head("main"), Exp::Missing, &value);
        let signed = sign_unary(&ctx.v2_signer(label)?, Rpc::UpdateRef, &req, |_| {});
        let challenge = post(&ctx, &signed).await?;
        want_error(&challenge, 402, "permission_denied")?;
        let signed = signed.with_header("Authorization", credential(&challenge)?);
        let ctx = ctx.clone();
        tasks.push(tokio::spawn(async move { post(&ctx, &signed).await }));
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while calls(&ctx).await? < initial + 4 {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "held racer deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    release(&ctx).await?;
    let mut successes = 0;
    for task in tasks {
        let reply = task.await.map_err(|_| "race task")??;
        if reply.status == 200 {
            successes += 1;
        } else {
            want_error(&reply, 400, "failed_precondition")?;
        }
    }
    ensure!(successes == 1, "CAS must have one winner");
    let head = ctx
        .read(&req.name.ok_or("ref name")?)
        .await?
        .ok_or("winner absent")?;
    ensure!(head == A || head == B, "unexpected CAS winner");
    let rows = wait_new(&ctx, &before, 2).await?;
    ensure!(rows.len() == 2, "race reservation count");
    ensure!(
        rows.iter()
            .filter(|r| r["kind"] == "committed" && r["settled"] == true)
            .count()
            == 1,
        "committed race outcome"
    );
    ensure!(
        rows.iter()
            .filter(|r| r["kind"] == "aborted"
                && r["reason"] == 1
                && r["released"] == true
                && r["settled"] == false)
            .count()
            == 1,
        "REF_CONFLICT must release"
    );
    Ok(())
}
pub(super) async fn expired_ticket(ctx: Ctx) -> CaseResult {
    mode(&ctx, "normal", "normal").await?;
    let before = snapshot(&ctx).await?;
    let req = mkit_transport_connect::generated::BeginUploadRequest {
        r#ref: Some(ctx.head("main")),
        pack_id: Some(mkit_core::hash::hash(&super::random_pack(64)).to_vec()),
        bytes: Some(64),
        ..Default::default()
    };
    let (_, reply) = paid(&ctx, "main", Rpc::BeginUpload, &req).await?;
    ensure!(reply.status == 200, "ticket rejected");
    let rows = wait_new(&ctx, &before, 1).await?;
    ensure!(
        rows.len() == 1
            && rows[0]["kind"] == "expired"
            && rows[0]["released"] == true
            && rows[0]["settled"] == false,
        "unused ticket must release only"
    );
    ctx.expect_ref(&ctx.head("main"), None).await
}
pub(super) async fn backpressure_hook_down(ctx: Ctx) -> CaseResult {
    let cap = ctx.profile().backlog_cap.ok_or("backlog cap missing")?;
    mode(&ctx, "normal", "normal").await?;
    let (ticketed, _) = super::admission::prepare_ticket(&ctx, "ticketed").await?;
    mode(&ctx, "normal", "down").await?;
    let before = snapshot(&ctx).await?;
    let mut committed = None;
    for i in 0..cap {
        let (signed, reply) = paid(
            &ctx,
            &format!("writer{i}"),
            Rpc::UpdateRef,
            &update_req(&ctx.head(&format!("ref{i}")), Exp::Missing, &A),
        )
        .await?;
        ensure!(reply.status == 200, "backlog setup rejected");
        committed = Some(signed);
    }
    let count = calls(&ctx).await?;
    let signed = sign_unary(
        &ctx.v2_signer("blocked")?,
        Rpc::UpdateRef,
        &update_req(&ctx.head("blocked"), Exp::Missing, &B),
        |_| {},
    );
    let blocked = post(&ctx, &signed).await?;
    want_error(&blocked, 503, "unavailable")?;
    ensure!(
        blocked
            .headers
            .get("retry-after")
            .is_some_and(|v| v == "30"),
        "backpressure retry-after"
    );
    ensure!(calls(&ctx).await? == count, "backpressure reached Admit");
    ctx.expect_ref(&ctx.head("ref0"), Some(&A)).await?;
    let saved = post(&ctx, &committed.ok_or("no committed write")?).await?;
    ensure!(saved.status == 200, "non-admitted committed replay blocked");
    ensure!(
        calls(&ctx).await? == count,
        "committed replay reached Admit"
    );
    super::want_outcome(
        ctx.advance(&ticketed).await?,
        mkit_transport_connect::generated::AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )?;
    ensure!(
        calls(&ctx).await? == count,
        "ticketed advance reached Admit"
    );
    mode(&ctx, "normal", "normal").await?;
    ensure!(
        wait_new(
            &ctx,
            &before,
            usize::try_from(cap).map_err(|_| "cap too large")? + 1
        )
        .await?
        .len()
            == usize::try_from(cap).map_err(|_| "cap too large")? + 1,
        "backlog reservation count"
    );
    let (_, reply) = paid(
        &ctx,
        "recovered",
        Rpc::UpdateRef,
        &update_req(&ctx.head("recovered"), Exp::Missing, &A),
    )
    .await?;
    ensure!(reply.status == 200, "admission did not recover");
    wait_new(
        &ctx,
        &before,
        usize::try_from(cap).map_err(|_| "cap too large")? + 2,
    )
    .await?;
    Ok(())
}
pub(super) async fn eventual_completeness(ctx: Ctx) -> CaseResult {
    mode(&ctx, "normal", "down").await?;
    let before = snapshot(&ctx).await?;
    for i in 0..9 {
        let (_, reply) = paid(
            &ctx,
            &format!("payer{i}"),
            Rpc::UpdateRef,
            &update_req(&ctx.head(&format!("ref{i}")), Exp::Missing, &A),
        )
        .await?;
        ensure!(reply.status == 200, "budget fixture commit");
    }
    mode(&ctx, "normal", "normal").await?;
    let rows = wait_new(&ctx, &before, 9).await?;
    ensure!(
        rows.len() == 9
            && rows
                .iter()
                .all(|r| r["kind"] == "committed" && r["settled"] == true),
        "outcome budget dropped rows"
    );
    // Inspect the ledger again; its fixture rejects a second distinct terminal body.
    ensure!(
        ledger(&ctx).await?.as_object().is_some(),
        "ledger unavailable"
    );
    Ok(())
}
