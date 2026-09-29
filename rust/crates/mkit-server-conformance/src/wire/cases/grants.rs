//! M2 owner-signed write grants over real Connect requests.

use buffa::Message;
use mkit_attest::grant::{
    Capabilities, Grant, Namespace, OwnerScheme, RefScopes, RepoScope, RepositoryIdentity,
    SignedHeader,
};
use mkit_core::hash::{from_hex, hash};
use mkit_transport_connect::generated::__buffa::oneof::{
    begin_upload_response::Result as BeginResult, upload_pack_request::Body as UploadBody,
    upload_part_request::Msg as PartMsg,
};
use mkit_transport_connect::generated::{
    AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse, ListRefsRequest,
    ListRefsResponse, UpdateRefResponse, UploadPartHeader, UploadPartRequest, UploadPartResponse,
};

use super::{
    A, B, CaseResult, Commit, Ctx, Exp, Failure, Signed, advance_req, ensure, repository,
    sign_unary, update_req, upload_msgs, want_code, want_ok,
};
use crate::wire::client::{Rpc, frames};
use crate::wire::profile::WireAuth;
use crate::wire::sign::{Signer, now_ms, pack_commitment};

/// The relying party configured by the in-process M2 profiles.
pub const RP_ID: &str = "example.test";
/// The origin configured for [`RP_ID`].
pub const RP_ORIGIN: &str = "https://example.test";

struct Owner(Signer);

impl Owner {
    fn namespace(&self) -> Namespace {
        Namespace::Ed25519(from_hex(&self.0.public_key_hex()).expect("valid grant fixture"))
    }

    fn signed_header(&self, grant: &Grant) -> String {
        let statement = grant.encode().expect("valid grant fixture");
        SignedHeader {
            blob: self.0.sign_grant_statement(&statement).to_vec(),
            statement,
            scheme: OwnerScheme::Ed25519,
        }
        .encode()
        .expect("valid grant fixture")
    }
}

fn ed_owner(ctx: &Ctx) -> Result<Owner, Failure> {
    Ok(Owner(ctx.v2_signer("repository-a")?))
}

fn repo(ctx: &Ctx, owner: &Owner) -> String {
    format!(
        "{}/{}-{}",
        owner.namespace(),
        ctx.profile().run_id,
        ctx.case.replace('.', "-")
    )
}

fn grant(ctx: &Ctx, owner: &Owner, repo: &str, grantee: &Signer) -> Grant {
    let now = now_ms();
    let WireAuth::AuthV2 { audience, .. } = &ctx.profile().auth else {
        unreachable!()
    };
    Grant {
        namespace: owner.namespace(),
        scope: RepoScope::Repository(RepositoryIdentity::parse(repo).expect("valid grant fixture")),
        grantee: from_hex(&grantee.public_key_hex()).expect("valid grant fixture"),
        capabilities: Capabilities::Write,
        audiences: vec![audience.clone()],
        ref_scopes: Some(RefScopes::parse("refs/heads/*=cuf").expect("valid grant fixture")),
        epoch: 0,
        created_ms: now - 1000,
        expiry_ms: now + 3_600_000,
        nonce: hash(repo.as_bytes()),
    }
}

fn signed_update(ctx: &Ctx, grantee: &Signer, repo: &str, header: Option<&str>) -> Signed {
    let mut signed = sign_unary(
        grantee,
        Rpc::UpdateRef,
        &update_req(&ctx.head("main"), Exp::Any, &A),
        |env| {
            repo.clone_into(&mut env.repository);
        },
    );
    if let Some(header) = header {
        signed = signed.with_header("x-write-grant", header);
    }
    signed
}

async fn valid(ctx: Ctx, owner: Owner) -> CaseResult {
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let header = owner.signed_header(&grant(&ctx, &owner, &repo, &grantee));
    let signed = signed_update(&ctx, &grantee, &repo, Some(&header));
    want_ok(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "grant UpdateRef",
    )?;
    let read = want_ok(
        repository::read(&ctx, &repo, "main").await?,
        "grant ReadRef",
    )?;
    ensure!(
        read.object_id.as_deref() == Some(&A),
        "granted write was not stored"
    );
    Ok(())
}

pub(super) async fn valid_ed25519(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    valid(ctx, owner).await
}

pub(super) async fn push_flow(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let header = owner.signed_header(&grant(&ctx, &owner, &repo, &grantee));
    let pack = b"granted push flow pack";
    let pack_id = hash(pack);
    let begin = BeginUploadRequest {
        r#ref: Some(ctx.head("main")),
        pack_id: Some(pack_id.to_vec()),
        bytes: Some(pack.len() as u64),
        ..Default::default()
    };
    let signed_begin = sign_unary(&grantee, Rpc::BeginUpload, &begin, |env| {
        repo.clone_into(&mut env.repository);
    })
    .with_header("x-write-grant", &header);
    let response: BeginUploadResponse =
        want_ok(ctx.send(&signed_begin).await?, "granted BeginUpload")?;
    let Some(BeginResult::Ticket(ticket)) = response.result else {
        return Err(Failure::Fail(
            "granted BeginUpload did not return a ticket".into(),
        ));
    };
    let ticket_id = ticket
        .id
        .ok_or_else(|| Failure::Fail("missing ticket id".into()))?;
    let mut messages = upload_msgs(pack, 2);
    if let Some(UploadBody::Header(first)) = &mut messages[0].body {
        first.ticket_token = ticket.token;
    }
    let mut envelope = grantee.envelope(
        Rpc::UploadPack.procedure(),
        pack_commitment(&pack_id, pack.len() as u64),
    );
    envelope.repository.clone_from(&repo);
    let upload_headers = grantee.sign(&envelope).headers;
    ensure!(
        ctx.upload_with(&messages, &upload_headers).await?.is_none(),
        "granted ticketed UploadPack failed"
    );
    let mut advance = advance_req(
        (&ctx.head("main"), Exp::Missing, &A),
        (&ctx.packmap("main"), Exp::Missing, &B),
    );
    advance.ticket_ids = vec![ticket_id];
    let signed_advance = sign_unary(&grantee, Rpc::AdvanceRefs, &advance, |env| {
        repo.clone_into(&mut env.repository);
    })
    .with_header("x-write-grant", header);
    let result: AdvanceRefsResponse =
        want_ok(ctx.send(&signed_advance).await?, "granted AdvanceRefs")?;
    ensure!(
        result.outcome
            == Some(
                mkit_transport_connect::generated::AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED.into()
            ),
        "granted AdvanceRefs did not commit: {result:?}"
    );
    Ok(())
}

pub(super) async fn part_path_ignores_header(ctx: Ctx) -> CaseResult {
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &ed_owner(&ctx)?);
    let ticket = [0x41; 32];
    let subtree = [0x42; 32];
    let mut envelope = grantee.envelope(
        Rpc::UploadPart.procedure(),
        format!(
            "part:{}:0:{}:1",
            mkit_core::hash::to_hex(&ticket),
            mkit_core::hash::to_hex(&subtree)
        ),
    );
    envelope.repository = repo;
    let signed = grantee
        .sign(&envelope)
        .with_header("x-write-grant", "malformed");
    let message = UploadPartRequest {
        msg: Some(PartMsg::Header(Box::new(UploadPartHeader {
            ticket_token: Some(vec![0xff]),
            index: Some(0),
            ..Default::default()
        }))),
        ..Default::default()
    };
    let reply = ctx
        .client()
        .stream::<UploadPartResponse>(Rpc::UploadPart, frames(&[message]), &signed.headers)
        .await?;
    let error = reply
        .error
        .ok_or_else(|| Failure::Fail("invalid ticket accepted".into()))?;
    ensure!(
        error.code == "failed_precondition" && error.message == "invalid or expired upload ticket",
        "part path parsed grant header: {error}"
    );
    Ok(())
}

async fn denied(ctx: Ctx, owner: Owner, mutate: impl FnOnce(&mut Grant)) -> CaseResult {
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let mut statement = grant(&ctx, &owner, &repo, &grantee);
    mutate(&mut statement);
    let header = owner.signed_header(&statement);
    let signed = signed_update(&ctx, &grantee, &repo, Some(&header));
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "rejected write grant",
    )?;
    Ok(())
}

pub(super) async fn wrong_audience(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    denied(ctx, owner, |g| {
        g.audiences = vec!["https://other.example.test".into()];
    })
    .await
}

pub(super) async fn repository_out_of_scope(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let other = format!("{}/other", owner.namespace());
    denied(ctx, owner, |g| {
        g.scope =
            RepoScope::Repository(RepositoryIdentity::parse(&other).expect("valid grant fixture"));
    })
    .await
}

pub(super) async fn namespace_scope_covers_new_repo(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let mut statement = grant(&ctx, &owner, &repo, &grantee);
    statement.scope = RepoScope::Namespace;
    let signed = signed_update(
        &ctx,
        &grantee,
        &repo,
        Some(&owner.signed_header(&statement)),
    );
    want_ok(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "namespace-scope new repo",
    )?;
    Ok(())
}

pub(super) async fn grantee_mismatch(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    denied(ctx, owner, |g| g.grantee = [0x44; 32]).await
}

pub(super) async fn read_only_grant_for_write(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    denied(ctx, owner, |g| {
        g.capabilities = Capabilities::Read;
        g.ref_scopes = None;
    })
    .await
}

pub(super) async fn expired(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let mut statement = grant(&ctx, &owner, &repo, &grantee);
    statement.expiry_ms = statement.created_ms + 60_000;
    let signed = signed_update(
        &ctx,
        &grantee,
        &repo,
        Some(&owner.signed_header(&statement)),
    )
    .with_header(crate::wire::CLOCK_SKEW_HEADER, "61000");
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "expired write grant",
    )?;
    Ok(())
}

pub(super) async fn not_yet_valid(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let mut statement = grant(&ctx, &owner, &repo, &grantee);
    statement.created_ms = now_ms() + 31_000;
    statement.expiry_ms = statement.created_ms + 60_000;
    let signed = signed_update(
        &ctx,
        &grantee,
        &repo,
        Some(&owner.signed_header(&statement)),
    )
    .with_header(crate::wire::CLOCK_SKEW_HEADER, "-1000");
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "future write grant",
    )?;
    statement.created_ms = now_ms() + 29_000;
    statement.expiry_ms = statement.created_ms + 60_000;
    let corrected = signed
        .with_header("x-write-grant", owner.signed_header(&statement))
        .with_header(crate::wire::CLOCK_SKEW_HEADER, "1000");
    want_ok(
        ctx.send::<UpdateRefResponse>(&corrected).await?,
        "within clock lead",
    )?;
    Ok(())
}

async fn bump(ctx: &Ctx, repository: &str) -> CaseResult {
    let owner = ctx.v2_signer("repository-a")?;
    let create = sign_unary(
        &owner,
        Rpc::UpdateRef,
        &update_req(&ctx.head("seed"), Exp::Any, &A),
        |env| repository.clone_into(&mut env.repository),
    );
    want_ok(
        ctx.send::<UpdateRefResponse>(&create).await?,
        "create repository before epoch bump",
    )?;
    let body = ListRefsRequest {
        prefix: Some(ctx.head("seed")),
        ..Default::default()
    }
    .encode_to_vec();
    let mut headers = ctx.auth_headers(Rpc::ListRefs, Commit::Body(&body));
    headers.retain(|(name, _)| name != "x-repository");
    headers.push(("x-repository".into(), repository.to_owned()));
    headers.push(("x-mkit-test-bump-epoch".into(), "1".into()));
    let result = ctx
        .client()
        .unary::<ListRefsResponse>(Rpc::ListRefs, body, &headers)
        .await?;
    want_ok(result, "test epoch bump")?;
    Ok(())
}

pub(super) async fn epoch_above_stored(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    denied(ctx, owner, |g| g.epoch = 1).await
}

pub(super) async fn epoch_below_stored(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    bump(&ctx, &repo(&ctx, &owner)).await?;
    denied(ctx, owner, |_| {}).await
}

pub(super) async fn new_epoch_grant_works(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    bump(&ctx, &repo).await?;
    let mut statement = grant(&ctx, &owner, &repo, &grantee);
    statement.epoch = 1;
    let signed = signed_update(
        &ctx,
        &grantee,
        &repo,
        Some(&owner.signed_header(&statement)),
    );
    want_ok(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "new epoch write grant",
    )?;
    Ok(())
}

pub(super) async fn owner_with_bad_grant_denied(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let owner_signer = &owner.0;
    let repo = repo(&ctx, &owner);
    let signed = signed_update(&ctx, owner_signer, &repo, Some("bad"));
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "owner with bad grant",
    )?;
    Ok(())
}

pub(super) async fn header_without_auth_unauthenticated(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let repo = repo(&ctx, &owner);
    let mut signed = signed_update(&ctx, &ctx.v2_signer("grant-grantee")?, &repo, Some("bad"));
    signed
        .headers
        .retain(|(name, _)| name == "x-repository" || name == "x-write-grant");
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "unauthenticated",
        "grant without auth v2",
    )?;
    Ok(())
}

pub(super) async fn duplicate_header_denied(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let repo = repo(&ctx, &owner);
    let grantee = ctx.v2_signer("grant-grantee")?;
    let header = owner.signed_header(&grant(&ctx, &owner, &repo, &grantee));
    let mut signed = signed_update(&ctx, &grantee, &repo, Some(&header));
    signed.headers.push(("x-write-grant".into(), header));
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "duplicate write grant",
    )?;
    Ok(())
}

pub(super) async fn oversize_header_denied(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let repo = repo(&ctx, &owner);
    let signed = signed_update(
        &ctx,
        &ctx.v2_signer("grant-grantee")?,
        &repo,
        Some(&"A".repeat(8193)),
    );
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "oversize write grant",
    )?;
    Ok(())
}

pub(super) async fn non_ascii_header_denied(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let repo = repo(&ctx, &owner);
    let signed = signed_update(&ctx, &ctx.v2_signer("grant-grantee")?, &repo, Some("é"));
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "non-ASCII write grant",
    )?;
    Ok(())
}

pub(super) async fn retry_with_changed_grant_returns_saved_result(ctx: Ctx) -> CaseResult {
    let owner = ed_owner(&ctx)?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let header = owner.signed_header(&grant(&ctx, &owner, &repo, &grantee));
    let signed = signed_update(&ctx, &grantee, &repo, Some(&header));
    let first = want_ok(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "first grant write",
    )?;
    let retry = want_ok(
        ctx.send::<UpdateRefResponse>(&signed.with_header("x-write-grant", "bad"))
            .await?,
        "saved grant write",
    )?;
    ensure!(
        first.encode_to_vec() == retry.encode_to_vec(),
        "saved grant write changed"
    );
    Ok(())
}
