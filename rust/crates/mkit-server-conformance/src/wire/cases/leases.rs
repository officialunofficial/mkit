//! Epoch bump directives over the existing `ListRefs` wire route.

use buffa::Message;
use mkit_transport_connect::generated::{ListRefsRequest, ListRefsResponse};

use mkit_transport_connect::generated::UpdateRefResponse;

use super::grants;
use super::{
    A, B, CaseResult, Commit, Ctx, Exp, Failure, Signed, ensure, epochs, repository, sign_unary,
    update_req, want_code, want_ok,
};
use crate::wire::CLOCK_SKEW_HEADER;
use crate::wire::client::Rpc;
use crate::wire::sign::Signer;

const BUMP: &str = "x-mkit-test-bump-epoch";

pub(super) async fn bump_completes_and_writes_continue(ctx: Ctx) -> CaseResult {
    if !ctx.profile().fresh_target {
        return Err(Failure::Skip(
            "epoch bump requires a fresh disposable target".into(),
        ));
    }
    let name = ctx.head("main");
    ctx.set(&name, Exp::Missing, &A).await?;

    let body = ListRefsRequest {
        prefix: Some(name.clone()),
        ..Default::default()
    }
    .encode_to_vec();
    let mut headers = ctx.auth_headers(Rpc::ListRefs, Commit::Body(&body));
    headers.push((BUMP.into(), "1".into()));
    let bumped: Result<ListRefsResponse, _> = ctx
        .client()
        .unary(Rpc::ListRefs, body.clone(), &headers)
        .await?;
    want_ok(bumped, "listing after epoch bump")?;

    // Repeating the same epoch must instead fail at the bump's monotonicity
    // check, proving that the first directive changed the coordinator epoch.
    let repeated: Result<ListRefsResponse, _> =
        ctx.client().unary(Rpc::ListRefs, body, &headers).await?;
    want_code(repeated, "invalid_argument", "repeated epoch bump")?;

    ctx.set(&name, Exp::Match(&A), &B).await?;
    ctx.expect_ref(&name, Some(&B)).await
}

/// Shift the authenticated request business time; lease time remains real.
const SKEW_MS: i64 = 120_000;

/// A grantee's `UpdateRef(<ns>/<leaf>, ANY, id)` under `header`, with the
/// envelope and the business clock both skewed by `skew_ms`.
fn write(
    ctx: &Ctx,
    grantee: &Signer,
    repo: &str,
    (leaf, id): (&str, &[u8]),
    (header, skew_ms): (&str, i64),
) -> Signed {
    sign_unary(
        grantee,
        Rpc::UpdateRef,
        &update_req(&ctx.head(leaf), Exp::Any, id),
        |env| {
            repo.clone_into(&mut env.repository);
            env.created_at += skew_ms;
            env.expires_at += skew_ms;
        },
    )
    .with_header("x-write-grant", header)
    .with_header(CLOCK_SKEW_HEADER, skew_ms.to_string())
}

/// Warm `main` with an epoch-0 grant, then move the owner to epoch 1.
/// Returns the grantee, the repository and the epoch-0 and epoch-1 grant
/// headers.
async fn warm_then_bump(ctx: &Ctx, expire: bool) -> Result<(Signer, String, [String; 2]), Failure> {
    let owner = grants::ed_owner(ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = grants::repo(ctx, &owner);
    let old = grants::grant(ctx, &owner, &repo, &grantee);
    let mut new = grants::grant(ctx, &owner, &repo, &grantee);
    new.epoch = 1;
    let headers = [owner.signed_header(&old), owner.signed_header(&new)];
    let warm = grants::signed_update(ctx, &grantee, &repo, Some(&headers[0]));
    want_ok(ctx.send::<UpdateRefResponse>(&warm).await?, "epoch 0 write")?;
    if expire {
        // Lease expiry uses the real clock, not request clock skew.
        tokio::time::sleep(std::time::Duration::from_secs(31)).await;
    }
    let set = epochs::set_epoch(ctx, &owner, 1).await?;
    ensure!(set.epoch == Some(1), "SetGrantEpoch stored {:?}", set.epoch);
    Ok((grantee, repo, headers))
}

async fn absent(ctx: &Ctx, repo: &str, leaf: &str) -> CaseResult {
    let read = want_ok(repository::read(ctx, repo, leaf).await?, "ReadRef")?;
    ensure!(read.exists != Some(true), "{leaf} was committed");
    Ok(())
}

/// A shard that never held a lease renews first (SPEC-WRITE-GRANTS §5.4):
/// after an epoch change an epoch-0 grant is refused on it, and epoch 1 works.
pub(super) async fn idle_shard_renews_at_new_epoch(ctx: Ctx) -> CaseResult {
    let (grantee, repo, [old, new]) = warm_then_bump(&ctx, false).await?;
    let denied = write(&ctx, &grantee, &repo, ("idle", &A), (&old, 0));
    want_code(
        ctx.send::<UpdateRefResponse>(&denied).await?,
        "permission_denied",
        "epoch 0 grant on an idle shard",
    )?;
    absent(&ctx, &repo, "idle").await?;
    let allowed = write(&ctx, &grantee, &repo, ("idle", &A), (&new, 0));
    want_ok(
        ctx.send::<UpdateRefResponse>(&allowed).await?,
        "epoch 1 grant on an idle shard",
    )?;
    Ok(())
}

/// The warm shard's lease expires before revocation is requested and completes;
/// no acknowledgement is in flight. The shard then renews at epoch 1 and refuses
/// its old grant, even on a skewed request. Per amended R-159, the ack race stays
/// in-crate: `expiry_races_ack_memory` and `expiry_races_ack_sqlite` in
/// `mkit-server-native/tests/epoch_leases.rs`.
pub(super) async fn lease_expires_before_revocation_completes(ctx: Ctx) -> CaseResult {
    let (grantee, repo, [old, new]) = warm_then_bump(&ctx, true).await?;
    let denied = write(&ctx, &grantee, &repo, ("main", &B), (&old, SKEW_MS));
    want_code(
        ctx.send::<UpdateRefResponse>(&denied).await?,
        "permission_denied",
        "epoch 0 grant on the expired-lease shard",
    )?;
    let read = want_ok(repository::read(&ctx, &repo, "main").await?, "ReadRef")?;
    ensure!(
        read.object_id.as_deref() == Some(&A),
        "the refused write changed the warm ref"
    );
    let allowed = write(&ctx, &grantee, &repo, ("main", &B), (&new, SKEW_MS));
    want_ok(
        ctx.send::<UpdateRefResponse>(&allowed).await?,
        "epoch 1 grant on the expired-lease shard",
    )?;
    Ok(())
}
