//! The per-signer write quota (SPEC-TRANSPORT-CONNECT §7.1): exhaustion is
//! `resource_exhausted`, allocates nothing (no replay record), and a
//! replayed write is never charged again. Each case exhausts its own
//! signer, so it needs a profile that declares a tiny quota.

use mkit_core::hash::hash;
use mkit_transport_connect::generated::UpdateRefResponse;

use super::{
    A, CaseResult, Ctx, Exp, Failure, Signed, header_msg, random_pack, sign_unary, update_req,
    want_code, want_ok,
};
use crate::wire::client::{Rpc, RpcError};
use crate::wire::profile::QuotaLimits;
use crate::wire::sign::Signer;

const EXHAUSTED: &str = "resource_exhausted";

fn limits(ctx: &Ctx) -> Result<QuotaLimits, Failure> {
    ctx.profile()
        .quota
        .ok_or_else(|| Failure::Skip("needs a declared quota".to_owned()))
}

/// A signed `UpdateRef(<ns>/<leaf>, MISSING, A)`, optionally under
/// `nonce`.
fn signed(ctx: &Ctx, signer: &Signer, leaf: &str, nonce: Option<&str>) -> Signed {
    let req = update_req(&ctx.head(leaf), Exp::Missing, &A);
    sign_unary(signer, Rpc::UpdateRef, &req, |env| {
        if let Some(nonce) = nonce {
            nonce.clone_into(&mut env.nonce);
        }
    })
}

async fn send(ctx: &Ctx, s: &Signed) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    ctx.send(s).await
}

/// A fresh signed write of `<ns>/<leaf>`.
async fn write(
    ctx: &Ctx,
    signer: &Signer,
    leaf: &str,
    nonce: Option<&str>,
) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    send(ctx, &signed(ctx, signer, leaf, nonce)).await
}

/// Spend the whole op budget of `signer`.
async fn exhaust(ctx: &Ctx, signer: &Signer, ops: u32) -> CaseResult {
    for i in 0..ops {
        want_ok(
            write(ctx, signer, &format!("r{i}"), None).await?,
            &format!("write {i} of {ops}"),
        )?;
    }
    Ok(())
}

pub(super) async fn ops_exhaustion(ctx: Ctx) -> CaseResult {
    let q = limits(&ctx)?;
    let signer = ctx.v2_signer("quota")?;
    exhaust(&ctx, &signer, q.max_ops).await?;
    want_code(
        write(&ctx, &signer, "over", None).await?,
        EXHAUSTED,
        "one write over the budget",
    )?;
    ctx.expect_ref(&ctx.head("over"), None).await?;
    // Another signer is not affected.
    let other = ctx.v2_signer("other")?;
    want_ok(
        write(&ctx, &other, "other", None).await?,
        "another signer's write",
    )?;
    Ok(())
}

pub(super) async fn bytes_exhaustion(ctx: Ctx) -> CaseResult {
    let q = limits(&ctx)?;
    let total = q.max_bytes.saturating_add(1);
    if total > ctx.profile().max_pack_bytes {
        return Err(Failure::Skip(
            "the byte quota exceeds the pack cap".to_owned(),
        ));
    }
    let signer = ctx.v2_signer("quota")?;
    let id = hash(&random_pack(32));
    let op = signer.sign_pack(Rpc::UploadPack.procedure(), &id, total);
    // Refused at the header, before any chunk is read (§7.1).
    let got = ctx
        .upload_with(&[header_msg(&id, total)], &op.headers)
        .await?;
    let code = got.as_ref().map(|e| e.code.as_str());
    super::ensure!(
        code == Some(EXHAUSTED),
        "an upload over the byte budget: {code:?}"
    );
    ctx.expect_exists(&id, false).await
}

pub(super) async fn exhaustion_allocates_no_replay(ctx: Ctx) -> CaseResult {
    let q = limits(&ctx)?;
    let signer = ctx.v2_signer("quota")?;
    exhaust(&ctx, &signer, q.max_ops).await?;
    let x = signed(&ctx, &signer, "x", None);
    want_code(send(&ctx, &x).await?, EXHAUSTED, "write X over the budget")?;
    // Had X left a replay record, another operation under its nonce would
    // be `invalid_argument` (fingerprint mismatch), and X's retry `ok`.
    want_code(
        write(&ctx, &signer, "y", Some(&x.nonce)).await?,
        EXHAUSTED,
        "write Y under X's nonce",
    )?;
    want_code(send(&ctx, &x).await?, EXHAUSTED, "X retried")?;
    ctx.expect_ref(&ctx.head("x"), None).await?;
    ctx.expect_ref(&ctx.head("y"), None).await
}

pub(super) async fn replay_not_charged(ctx: Ctx) -> CaseResult {
    let q = limits(&ctx)?;
    let signer = ctx.v2_signer("quota")?;
    let first = signed(&ctx, &signer, "r0", None);
    want_ok(send(&ctx, &first).await?, "first write")?;
    for i in 0..3 {
        want_ok(send(&ctx, &first).await?, &format!("replay {i}"))?;
    }
    // The replays were free: the rest of the budget is intact.
    for i in 1..q.max_ops {
        want_ok(
            write(&ctx, &signer, &format!("r{i}"), None).await?,
            &format!("write {i} after replays"),
        )?;
    }
    want_code(
        write(&ctx, &signer, "over", None).await?,
        EXHAUSTED,
        "one write over the budget",
    )?;
    Ok(())
}
