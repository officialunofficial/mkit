//! Unsigned grant-epoch RPCs and signed owner statements over Connect.

use buffa::Message;
use mkit_attest::grant::EpochStatement;
use mkit_core::hash::hash;
use mkit_transport_connect::generated::{
    GetGrantEpochRequest, GetGrantEpochResponse, SetGrantEpochRequest, SetGrantEpochResponse,
    UpdateRefResponse,
};

use super::grants::{self, Owner};
use super::{CaseResult, Ctx, Failure, ensure, want_code, want_ok};
use crate::wire::client::{Rpc, RpcError};
use crate::wire::profile::WireAuth;
use crate::wire::sign::now_ms;

fn statement(ctx: &Ctx, owner: &Owner, new_epoch: u64) -> EpochStatement {
    let WireAuth::AuthV2 { audience, .. } = &ctx.profile().auth else {
        unreachable!()
    };
    let now = now_ms();
    EpochStatement {
        namespace: owner.namespace(),
        new_epoch,
        audiences: vec![audience.clone()],
        created_ms: now - 1_000,
        expiry_ms: now + 3_600_000,
        nonce: hash(format!("{}:{new_epoch}", ctx.case).as_bytes()),
    }
}

fn signed(owner: &Owner, statement: &EpochStatement) -> String {
    owner.signed_statement(&statement.encode().expect("valid epoch fixture"))
}

async fn get(
    ctx: &Ctx,
    namespace: &str,
    headers: &[(String, String)],
) -> Result<Result<GetGrantEpochResponse, RpcError>, String> {
    ctx.client()
        .unary(
            Rpc::GetGrantEpoch,
            GetGrantEpochRequest {
                namespace: Some(namespace.into()),
                ..Default::default()
            }
            .encode_to_vec(),
            headers,
        )
        .await
}

async fn set(
    ctx: &Ctx,
    signed_statement: &str,
) -> Result<Result<SetGrantEpochResponse, RpcError>, String> {
    ctx.client()
        .unary(
            Rpc::SetGrantEpoch,
            SetGrantEpochRequest {
                signed_statement: Some(signed_statement.into()),
                ..Default::default()
            }
            .encode_to_vec(),
            &[],
        )
        .await
}

/// `SetGrantEpoch(new_epoch)` for `owner`, retried while the server answers
/// `unavailable` (the revocation is still waiting on a shard's ack: STC §7.9
/// tells the caller to retry).
pub(super) async fn set_epoch(
    ctx: &Ctx,
    owner: &Owner,
    new_epoch: u64,
) -> Result<SetGrantEpochResponse, Failure> {
    let statement = signed(owner, &statement(ctx, owner, new_epoch));
    let mut attempt = 0;
    loop {
        match set(ctx, &statement).await? {
            Err(error) if error.code == "unavailable" && attempt < 5 => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            result => return want_ok(result, "SetGrantEpoch"),
        }
    }
}

/// The owner's stored grant epoch. The fixed `0x` owners are shared by every
/// case and every run against a deployment, so their epoch is not known to
/// be zero.
pub(super) async fn current(ctx: &Ctx, owner: &Owner) -> Result<u64, Failure> {
    want_ok(
        get(ctx, &owner.namespace().to_string(), &[]).await?,
        "current GetGrantEpoch",
    )?
    .epoch
    .ok_or_else(|| Failure::Fail("GetGrantEpoch omitted the epoch".into()))
}

fn epoch_is(response: SetGrantEpochResponse, expected: u64) -> CaseResult {
    ensure!(
        response.epoch == Some(expected),
        "stored epoch was not {expected}"
    );
    Ok(())
}

pub(super) async fn get_unsigned_zero(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let response = want_ok(
        get(&ctx, &owner.namespace().to_string(), &[]).await?,
        "unsigned GetGrantEpoch",
    )?;
    ensure!(response.epoch == Some(0), "absent epoch was not zero");
    Ok(())
}

pub(super) async fn get_ignores_auth_headers(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let headers = vec![
        ("x-repository".into(), "malformed".into()),
        ("x-envelope-version".into(), "2".into()),
        ("x-signature".into(), "bad".into()),
        ("authorization".into(), "bad".into()),
    ];
    let response = want_ok(
        get(&ctx, &owner.namespace().to_string(), &headers).await?,
        "Get ignores auth",
    )?;
    ensure!(
        response.epoch == Some(0),
        "auth headers changed epoch answer"
    );
    Ok(())
}

pub(super) async fn get_bad_namespace_invalid_argument(ctx: Ctx) -> CaseResult {
    want_code(
        get(&ctx, "ED25519-bad", &[]).await?,
        "invalid_argument",
        "bad namespace",
    )?;
    Ok(())
}

pub(super) async fn set_advances_and_get_reflects(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let response = want_ok(
        set(&ctx, &signed(&owner, &statement(&ctx, &owner, 1))).await?,
        "set epoch 1",
    )?;
    epoch_is(response, 1)?;
    let response = want_ok(
        get(&ctx, &owner.namespace().to_string(), &[]).await?,
        "get epoch 1",
    )?;
    ensure!(response.epoch == Some(1), "get did not reflect set");
    Ok(())
}

pub(super) async fn set_retry_same_epoch(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let first = statement(&ctx, &owner, 1);
    epoch_is(
        want_ok(set(&ctx, &signed(&owner, &first)).await?, "first set")?,
        1,
    )?;
    let mut other = first;
    other.nonce = hash(b"different valid epoch statement");
    epoch_is(
        want_ok(
            set(&ctx, &signed(&owner, &other)).await?,
            "retry same epoch",
        )?,
        1,
    )
}

pub(super) async fn set_over_step_denied(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    want_code(
        set(&ctx, &signed(&owner, &statement(&ctx, &owner, 1_025))).await?,
        "permission_denied",
        "epoch over step",
    )?;
    Ok(())
}

pub(super) async fn set_decrease_denied(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    epoch_is(
        want_ok(
            set(&ctx, &signed(&owner, &statement(&ctx, &owner, 1))).await?,
            "set 1",
        )?,
        1,
    )?;
    want_code(
        set(&ctx, &signed(&owner, &statement(&ctx, &owner, 0))).await?,
        "permission_denied",
        "epoch decrease",
    )?;
    Ok(())
}

pub(super) async fn wrong_audience(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let mut statement = statement(&ctx, &owner, 1);
    statement.audiences = vec!["https://other.example.test".into()];
    want_code(
        set(&ctx, &signed(&owner, &statement)).await?,
        "permission_denied",
        "wrong epoch audience",
    )?;
    Ok(())
}

pub(super) async fn expired(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let mut statement = statement(&ctx, &owner, 1);
    statement.created_ms = now_ms() - 60_000;
    statement.expiry_ms = now_ms() - 1;
    want_code(
        set(&ctx, &signed(&owner, &statement)).await?,
        "permission_denied",
        "expired epoch",
    )?;
    Ok(())
}

pub(super) async fn not_yet_valid(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let mut statement = statement(&ctx, &owner, 1);
    statement.created_ms = now_ms() + 31_000;
    statement.expiry_ms = statement.created_ms + 60_000;
    want_code(
        set(&ctx, &signed(&owner, &statement)).await?,
        "permission_denied",
        "future epoch",
    )?;
    Ok(())
}

pub(super) async fn scheme_not_advertised(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let raw = signed(&owner, &statement(&ctx, &owner, 1));
    // An unrecognized scheme token cannot be advertised by any deployment.
    let raw = raw.replacen(".ed25519.", ".unknown.", 1);
    want_code(
        set(&ctx, &raw).await?,
        "permission_denied",
        "unadvertised scheme",
    )?;
    Ok(())
}

pub(super) async fn namespace_not_served(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("unlisted-epoch-owner")?;
    let owner = Owner::Ed(signer);
    want_code(
        set(&ctx, &signed(&owner, &statement(&ctx, &owner, 1))).await?,
        "permission_denied",
        "unserved namespace",
    )?;
    Ok(())
}

pub(super) async fn oversize_statement(ctx: Ctx) -> CaseResult {
    want_code(
        set(&ctx, &"x".repeat(8_193)).await?,
        "permission_denied",
        "oversize epoch statement",
    )?;
    Ok(())
}

pub(super) async fn zero_x_secp256k1_statement(ctx: Ctx) -> CaseResult {
    let owner = grants::k1_owner();
    let next = current(&ctx, &owner).await? + 1;
    epoch_is(
        want_ok(
            set(&ctx, &signed(&owner, &statement(&ctx, &owner, next))).await?,
            "0x secp epoch",
        )?,
        next,
    )
}

pub(super) async fn zero_x_webauthn_statement(ctx: Ctx) -> CaseResult {
    let owner = grants::web_owner();
    let next = current(&ctx, &owner).await? + 1;
    epoch_is(
        want_ok(
            set(&ctx, &signed(&owner, &statement(&ctx, &owner, next))).await?,
            "0x WebAuthn epoch",
        )?,
        next,
    )
}

pub(super) async fn old_grant_denied_new_grant_works_after_set(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = grants::repo(&ctx, &owner);
    let old = grants::grant(&ctx, &owner, &repo, &grantee);
    let old_header = owner.signed_header(&old);
    want_ok(
        ctx.send::<UpdateRefResponse>(&grants::signed_update(
            &ctx,
            &grantee,
            &repo,
            Some(&old_header),
        ))
        .await?,
        "old grant before set",
    )?;
    epoch_is(
        want_ok(
            set(&ctx, &signed(&owner, &statement(&ctx, &owner, 1))).await?,
            "set epoch",
        )?,
        1,
    )?;
    want_code(
        ctx.send::<UpdateRefResponse>(&grants::signed_update(
            &ctx,
            &grantee,
            &repo,
            Some(&old_header),
        ))
        .await?,
        "permission_denied",
        "old grant after set",
    )?;
    let mut new = old;
    new.epoch = 1;
    let new_header = owner.signed_header(&new);
    want_ok(
        ctx.send::<UpdateRefResponse>(&grants::signed_update(
            &ctx,
            &grantee,
            &repo,
            Some(&new_header),
        ))
        .await?,
        "new grant after set",
    )?;
    Ok(())
}
