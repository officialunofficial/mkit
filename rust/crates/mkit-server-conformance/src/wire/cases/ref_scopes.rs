//! §8.2–8.3 grant ref scopes over real Connect requests.

use mkit_attest::grant::RefScopes;
use mkit_transport_connect::generated::{
    AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse, UpdateRefResponse,
};

use super::grants::{self, Owner};
use super::{
    A, B, C, CaseResult, Ctx, Exp, Signed, advance_req, ensure, repository, sign_unary, update_req,
    want_code, want_ok,
};
use crate::wire::client::Rpc;
use crate::wire::sign::Signer;

fn setup(ctx: &Ctx) -> Result<(Owner, Signer, String), super::Failure> {
    let owner = grants::ed_owner(ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = grants::repo(ctx, &owner);
    Ok((owner, grantee, repo))
}

fn header(ctx: &Ctx, owner: &Owner, grantee: &Signer, repo: &str, scopes: &str) -> String {
    let mut grant = grants::grant(ctx, owner, repo, grantee);
    let scopes = scopes
        .replace("refs/heads/main", &ctx.head("main"))
        .replace("refs/heads/other", &ctx.head("other"));
    grant.ref_scopes = Some(RefScopes::parse(&scopes).expect("valid scope fixture"));
    owner.signed_header(&grant)
}

fn update(
    signer: &Signer,
    repo: &str,
    name: &str,
    exp: Exp<'_>,
    new: Option<&[u8]>,
    grant: Option<&str>,
) -> Signed {
    let mut body = update_req(name, exp, new.unwrap_or_default());
    if new.is_none() {
        body.delete = Some(true);
    }
    let signed = sign_unary(signer, Rpc::UpdateRef, &body, |env| {
        repo.clone_into(&mut env.repository);
    });
    if let Some(grant) = grant {
        signed.with_header("x-write-grant", grant)
    } else {
        signed
    }
}

fn advance(
    signer: &Signer,
    repo: &str,
    head: (&str, Exp<'_>, &[u8]),
    packmap: (&str, Exp<'_>, &[u8]),
    grant: Option<&str>,
) -> Signed {
    let body = advance_req(head, packmap);
    let signed = sign_unary(signer, Rpc::AdvanceRefs, &body, |env| {
        repo.clone_into(&mut env.repository);
    });
    if let Some(grant) = grant {
        signed.with_header("x-write-grant", grant)
    } else {
        signed
    }
}

async fn seed_head(ctx: &Ctx, repo: &str) -> CaseResult {
    let owner = ctx.v2_signer("repository-a")?;
    want_ok(
        ctx.send::<UpdateRefResponse>(&update(
            &owner,
            repo,
            &ctx.head("main"),
            Exp::Missing,
            Some(&A),
            None,
        ))
        .await?,
        "owner seed head",
    )?;
    Ok(())
}

async fn head_is(ctx: &Ctx, repo: &str, id: &[u8]) -> CaseResult {
    let read = want_ok(repository::read(ctx, repo, "main").await?, "ReadRef")?;
    ensure!(
        read.object_id.as_deref() == Some(id),
        "unexpected head value"
    );
    Ok(())
}

pub(super) async fn create_only_rejects_update(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    seed_head(&ctx, &repo).await?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=c");
    want_code(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Match(&A),
            Some(&B),
            Some(&grant),
        ))
        .await?,
        "permission_denied",
        "create-only update",
    )?;
    head_is(&ctx, &repo, &A).await
}

pub(super) async fn cu_grant_creates_but_match_update_denied_opaque(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=cu");
    want_ok(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Missing,
            Some(&A),
            Some(&grant),
        ))
        .await?,
        "create with cu",
    )?;
    want_code(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Match(&A),
            Some(&B),
            Some(&grant),
        ))
        .await?,
        "permission_denied",
        "opaque update with cu",
    )?;
    head_is(&ctx, &repo, &A).await
}

pub(super) async fn force_allows_non_ff(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    seed_head(&ctx, &repo).await?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=f");
    want_ok(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Match(&A),
            Some(&B),
            Some(&grant),
        ))
        .await?,
        "force update",
    )?;
    head_is(&ctx, &repo, &B).await
}

pub(super) async fn delete_needs_d(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    seed_head(&ctx, &repo).await?;
    let no_delete = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=f");
    want_code(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Match(&A),
            None,
            Some(&no_delete),
        ))
        .await?,
        "permission_denied",
        "delete without d",
    )?;
    let delete = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=d");
    want_ok(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Match(&A),
            None,
            Some(&delete),
        ))
        .await?,
        "delete with d",
    )?;
    Ok(())
}

pub(super) async fn any_on_absent_needs_c(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    let force = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=f");
    want_code(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Any,
            Some(&A),
            Some(&force),
        ))
        .await?,
        "permission_denied",
        "force-only Any absent",
    )?;
    let create = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=c");
    want_ok(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Any,
            Some(&A),
            Some(&create),
        ))
        .await?,
        "create-only Any absent",
    )?;
    head_is(&ctx, &repo, &A).await
}

pub(super) async fn any_on_present_needs_f(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    seed_head(&ctx, &repo).await?;
    let create = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=c");
    want_code(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Any,
            Some(&B),
            Some(&create),
        ))
        .await?,
        "permission_denied",
        "create-only Any present",
    )?;
    let force = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=f");
    want_ok(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Any,
            Some(&B),
            Some(&force),
        ))
        .await?,
        "force-only Any present",
    )?;
    head_is(&ctx, &repo, &B).await
}

pub(super) async fn direct_packmap_update_denied(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/*=cufd");
    want_code(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.packmap("main"),
            Exp::Any,
            Some(&A),
            Some(&grant),
        ))
        .await?,
        "permission_denied",
        "direct packmap write",
    )?;
    Ok(())
}

pub(super) async fn head_only_update_ok(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=c");
    want_ok(
        ctx.send::<UpdateRefResponse>(&update(
            &grantee,
            &repo,
            &ctx.head("main"),
            Exp::Missing,
            Some(&A),
            Some(&grant),
        ))
        .await?,
        "head-only create",
    )?;
    head_is(&ctx, &repo, &A).await
}

pub(super) async fn advance_wrong_packmap_denied(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=c");
    let signed = advance(
        &grantee,
        &repo,
        (&ctx.head("main"), Exp::Missing, &A),
        (&ctx.packmap("other"), Exp::Missing, &B),
        Some(&grant),
    );
    want_code(
        ctx.send::<AdvanceRefsResponse>(&signed).await?,
        "permission_denied",
        "wrong packmap pair",
    )?;
    Ok(())
}

pub(super) async fn rebaseline_push_under_head_scope(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    let owner_signer = ctx.v2_signer("repository-a")?;
    want_ok(
        ctx.send::<AdvanceRefsResponse>(&advance(
            &owner_signer,
            &repo,
            (&ctx.head("main"), Exp::Missing, &A),
            (&ctx.packmap("main"), Exp::Missing, &B),
            None,
        ))
        .await?,
        "owner seed advance",
    )?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=f");
    want_ok(
        ctx.send::<AdvanceRefsResponse>(&advance(
            &grantee,
            &repo,
            (&ctx.head("main"), Exp::Match(&A), &B),
            (&ctx.packmap("main"), Exp::Match(&B), &C),
            Some(&grant),
        ))
        .await?,
        "rebaseline advance",
    )?;
    head_is(&ctx, &repo, &B).await
}

fn begin(ctx: &Ctx, signer: &Signer, repo: &str, grant: &str) -> Signed {
    let body = BeginUploadRequest {
        r#ref: Some(ctx.head("main")),
        pack_id: Some(A.to_vec()),
        bytes: Some(1),
        ..Default::default()
    };
    sign_unary(signer, Rpc::BeginUpload, &body, |env| {
        repo.clone_into(&mut env.repository);
    })
    .with_header("x-write-grant", grant)
}

pub(super) async fn begin_upload_any_flag(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/heads/main=d");
    want_ok(
        ctx.send::<BeginUploadResponse>(&begin(&ctx, &grantee, &repo, &grant))
            .await?,
        "BeginUpload with matching d flag",
    )?;
    Ok(())
}

pub(super) async fn begin_upload_unmatched_denied(ctx: Ctx) -> CaseResult {
    let (owner, grantee, repo) = setup(&ctx)?;
    let grant = header(&ctx, &owner, &grantee, &repo, "refs/heads/other=c");
    want_code(
        ctx.send::<BeginUploadResponse>(&begin(&ctx, &grantee, &repo, &grant))
            .await?,
        "permission_denied",
        "BeginUpload unmatched ref",
    )?;
    Ok(())
}
