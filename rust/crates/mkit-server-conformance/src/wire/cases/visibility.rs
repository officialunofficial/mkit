//! M2 `SetRepoVisibility`: the envelope mode, the unsigned owner-signed
//! statement mode and their shared bounds (SPEC-WRITE-GRANTS §9.1).

use buffa::Message;
use mkit_attest::grant::{RepositoryIdentity, Visibility, VisibilityStatement};
use mkit_transport_connect::generated::__buffa::oneof::set_repo_visibility_request::Mode;
use mkit_transport_connect::generated::{
    ReadRefResponse, RepoVisibility, SetRepoVisibilityRequest, SetRepoVisibilityResponse,
    UpdateRefResponse,
};

use super::reads::{audience, owned, seeded_repo, signed_for, unsigned};
use super::{CaseResult, Ctx, Failure, ensure, grants, want_code, want_ok};
use crate::wire::client::{Rpc, RpcError};
use crate::wire::profile::random_bytes;
use crate::wire::sign::{Signer, now_ms};

/// An envelope-mode `SetRepoVisibility` by `owner`, which must succeed.
pub(super) async fn set_envelope(
    ctx: &Ctx,
    owner: &Signer,
    repo: &str,
    private: bool,
) -> CaseResult {
    let req = SetRepoVisibilityRequest {
        mode: Some(Mode::Visibility(
            if private {
                RepoVisibility::REPO_VISIBILITY_PRIVATE
            } else {
                RepoVisibility::REPO_VISIBILITY_PUBLIC
            }
            .into(),
        )),
        ..Default::default()
    };
    let s = signed_for(owner, repo, Rpc::SetRepoVisibility, &req);
    want_ok(
        ctx.send::<SetRepoVisibilityResponse>(&s).await?,
        "envelope SetRepoVisibility",
    )?;
    Ok(())
}

/// The owner-signed `mkit-repo-visibility:v1` statement for `repo`.
fn statement(
    ctx: &Ctx,
    owner: &grants::Owner,
    repo: &str,
    visibility: Visibility,
    created_ms: i64,
) -> Result<String, Failure> {
    let statement = VisibilityStatement {
        repository: RepositoryIdentity::parse(repo).expect("valid visibility fixture"),
        visibility,
        audiences: vec![audience(ctx)?],
        created_ms,
        expiry_ms: created_ms + 60_000,
        nonce: random_bytes(),
    };
    Ok(owner.signed_statement(
        &statement.encode().expect("valid visibility fixture"),
    ))
}

/// Statement mode: unsigned transport, `signed_statement` set.
async fn set_statement(
    ctx: &Ctx,
    repo: &str,
    signed_statement: &str,
) -> Result<Result<SetRepoVisibilityResponse, RpcError>, String> {
    ctx.client()
        .unary(
            Rpc::SetRepoVisibility,
            SetRepoVisibilityRequest {
                mode: Some(Mode::SignedStatement(signed_statement.into())),
                ..Default::default()
            }
            .encode_to_vec(),
            &[("x-repository".to_owned(), repo.to_owned())],
        )
        .await
}

/// An anonymous `ReadRef` of `main`, for the visibility assertions.
async fn anonymous_read_is_not_found(ctx: &Ctx, repo: &str) -> CaseResult {
    let req = mkit_transport_connect::generated::ReadRefRequest {
        name: Some(ctx.head("main")),
        ..Default::default()
    };
    want_code(
        ctx.send::<ReadRefResponse>(&unsigned(repo, Rpc::ReadRef, &req))
            .await?,
        "not_found",
        "anonymous read of a private repository",
    )?;
    Ok(())
}

/// The envelope mode: the owner flips its repository private and public.
pub(super) async fn envelope_owner(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, false).await?;
    set_envelope(&ctx, &owner, &repo, true).await?;
    anonymous_read_is_not_found(&ctx, &repo).await?;
    let read = want_ok(
        ctx.send::<ReadRefResponse>(&signed_for(
            &owner,
            &repo,
            Rpc::ReadRef,
            &mkit_transport_connect::generated::ReadRefRequest {
                name: Some(ctx.head("main")),
                ..Default::default()
            },
        ))
        .await?,
        "owner read of its private repository",
    )?;
    ensure!(read.exists == Some(true), "owner could not read main");
    set_envelope(&ctx, &owner, &repo, false).await?;
    let read = want_ok(
        ctx.send::<ReadRefResponse>(&unsigned(
            &repo,
            Rpc::ReadRef,
            &mkit_transport_connect::generated::ReadRefRequest {
                name: Some(ctx.head("main")),
                ..Default::default()
            },
        ))
        .await?,
        "anonymous read after public",
    )?;
    ensure!(read.exists == Some(true), "public repository stayed hidden");
    Ok(())
}

/// Statement mode with an Ed25519 owner statement.
pub(super) async fn statement_ed25519(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let repo = grants::repo(&ctx, &owner);
    let grants::Owner::Ed(signer) = &owner else {
        unreachable!()
    };
    seeded_repo(&ctx, signer, &repo, false).await?;
    let header = statement(&ctx, &owner, &repo, Visibility::Private, now_ms() - 1_000)?;
    want_ok(set_statement(&ctx, &repo, &header).await?, "ed25519 statement")?;
    anonymous_read_is_not_found(&ctx, &repo).await?;
    Ok(())
}

/// Statement mode accepts a secp256k1/EIP-191 owner statement.
pub(super) async fn statement_eip191(ctx: Ctx) -> CaseResult {
    let owner = grants::k1_owner();
    let repo = grants::repo(&ctx, &owner);
    // A `0x` repository is created by a grantee under the owner's grant.
    let grantee = ctx.v2_signer("grant-grantee")?;
    let header = owner.signed_header(&grants::grant_at_epoch(&ctx, &owner, &repo, &grantee).await?);
    let signed = grants::signed_update(&ctx, &grantee, &repo, Some(&header));
    want_ok(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "create the 0x repository",
    )?;
    let header = statement(&ctx, &owner, &repo, Visibility::Private, now_ms() - 1_000)?;
    want_ok(
        set_statement(&ctx, &repo, &header).await?,
        "eip191 statement",
    )?;
    anonymous_read_is_not_found(&ctx, &repo).await?;
    Ok(())
}

/// A valid write grant never authorizes `SetRepoVisibility`.
pub(super) async fn grant_never_authorizes(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = grants::repo(&ctx, &owner);
    let grants::Owner::Ed(signer) = &owner else {
        unreachable!()
    };
    seeded_repo(&ctx, signer, &repo, false).await?;
    let header = owner.signed_header(&grants::grant(&ctx, &owner, &repo, &grantee));
    let req = SetRepoVisibilityRequest {
        mode: Some(Mode::Visibility(
            RepoVisibility::REPO_VISIBILITY_PRIVATE.into(),
        )),
        ..Default::default()
    };
    let s = signed_for(&grantee, &repo, Rpc::SetRepoVisibility, &req)
        .with_header("x-write-grant", header);
    want_code(
        ctx.send::<SetRepoVisibilityResponse>(&s).await?,
        "permission_denied",
        "grant authorized visibility",
    )?;
    Ok(())
}

/// A statement older than the stored one is `permission_denied`.
pub(super) async fn older_created_denied(ctx: Ctx) -> CaseResult {
    let owner = grants::ed_owner(&ctx)?;
    let repo = grants::repo(&ctx, &owner);
    let grants::Owner::Ed(signer) = &owner else {
        unreachable!()
    };
    seeded_repo(&ctx, signer, &repo, false).await?;
    let now = now_ms();
    let first = statement(&ctx, &owner, &repo, Visibility::Private, now - 1_000)?;
    want_ok(set_statement(&ctx, &repo, &first).await?, "first statement")?;
    let older = statement(&ctx, &owner, &repo, Visibility::Public, now - 2_000)?;
    want_code(
        set_statement(&ctx, &repo, &older).await?,
        "permission_denied",
        "older statement",
    )?;
    // The newer statement still stands.
    anonymous_read_is_not_found(&ctx, &repo).await?;
    Ok(())
}

/// No `mode`, and `REPO_VISIBILITY_UNSPECIFIED`, are `invalid_argument`.
pub(super) async fn bad_mode_invalid_argument(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, false).await?;
    for (what, req) in [
        ("unset mode", SetRepoVisibilityRequest::default()),
        (
            "UNSPECIFIED",
            SetRepoVisibilityRequest {
                mode: Some(Mode::Visibility(
                    RepoVisibility::REPO_VISIBILITY_UNSPECIFIED.into(),
                )),
                ..Default::default()
            },
        ),
    ] {
        let s = signed_for(&owner, &repo, Rpc::SetRepoVisibility, &req);
        want_code(
            ctx.send::<SetRepoVisibilityResponse>(&s).await?,
            "invalid_argument",
            what,
        )?;
    }
    Ok(())
}

/// A `signed_statement` over the 8,192-byte cap is `permission_denied`.
pub(super) async fn oversize_statement_permission_denied(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, false).await?;
    want_code(
        set_statement(&ctx, &repo, &"x".repeat(8_193)).await?,
        "permission_denied",
        "oversize statement",
    )?;
    Ok(())
}
