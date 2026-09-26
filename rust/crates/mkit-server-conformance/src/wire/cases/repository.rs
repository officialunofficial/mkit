//! Repository addressing and isolation (SPEC-TRANSPORT-CONNECT §7.4).

use buffa::Message as _;
use mkit_core::hash::{hash, to_hex};
use mkit_transport_connect::generated::{
    DownloadPackRequest, DownloadPackResponse, ListRefsRequest, ListRefsResponse,
    PackExistsRequest, PackExistsResponse, ReadRefRequest, ReadRefResponse, UpdateRefResponse,
};

use super::{
    A, B, C, CaseResult, Commit, Ctx, Exp, Failure, Signed, ensure, sign_unary, update_req,
    upload_msgs, want_code, want_ok,
};
use crate::wire::client::{Rpc, frame};
use crate::wire::sign::pack_commitment;

fn identities(name_a: &str, name_b: &str) -> (String, String) {
    (
        format!("ed25519-{}/{name_a}", "a".repeat(64)),
        format!("0x{}/{name_b}", "b".repeat(40)),
    )
}

fn read_headers(ctx: &Ctx, rpc: Rpc, body: &[u8], repository: &str) -> Vec<(String, String)> {
    let mut headers = ctx.auth_headers(rpc, Commit::Body(body));
    headers.retain(|(name, _)| name != "x-repository");
    headers.push(("x-repository".to_owned(), repository.to_owned()));
    headers
}

async fn list(
    ctx: &Ctx,
    repository: &str,
) -> Result<Result<ListRefsResponse, crate::wire::client::RpcError>, String> {
    let body = ListRefsRequest {
        prefix: Some(ctx.head("")),
        ..Default::default()
    }
    .encode_to_vec();
    let headers = read_headers(ctx, Rpc::ListRefs, &body, repository);
    ctx.client().unary(Rpc::ListRefs, body, &headers).await
}

async fn read(
    ctx: &Ctx,
    repository: &str,
    leaf: &str,
) -> Result<Result<ReadRefResponse, crate::wire::client::RpcError>, String> {
    let body = ReadRefRequest {
        name: Some(ctx.head(leaf)),
        ..Default::default()
    }
    .encode_to_vec();
    let headers = read_headers(ctx, Rpc::ReadRef, &body, repository);
    ctx.client().unary(Rpc::ReadRef, body, &headers).await
}

fn signed_update(ctx: &Ctx, repository: &str, leaf: &str, id: &[u8]) -> Result<Signed, Failure> {
    Ok(sign_unary(
        &ctx.v2_signer(repository)?,
        Rpc::UpdateRef,
        &update_req(&ctx.head(leaf), Exp::Any, id),
        |env| repository.clone_into(&mut env.repository),
    ))
}

async fn set(ctx: &Ctx, repository: &str, leaf: &str, id: &[u8]) -> CaseResult {
    want_ok(
        ctx.send::<UpdateRefResponse>(&signed_update(ctx, repository, leaf, id)?)
            .await?,
        "UpdateRef",
    )?;
    Ok(())
}

pub(super) async fn single_header_mismatch(ctx: Ctx) -> CaseResult {
    // Both bare and namespaced spellings are well formed in Single mode.
    let (namespaced, _) = identities("other", "other");
    for repository in ["conformance-other-repository".to_owned(), namespaced] {
        want_code(
            list(&ctx, &repository).await?,
            "not_found",
            "ListRefs with another repository",
        )?;
        want_code(
            read(&ctx, &repository, "main").await?,
            "not_found",
            "ReadRef with another repository",
        )?;
    }
    Ok(())
}

pub(super) async fn single_malformed(ctx: Ctx) -> CaseResult {
    for repository in ["Uppercase", ".leading", "../escape", "default/", "ns/name"] {
        want_code(
            list(&ctx, repository).await?,
            "invalid_argument",
            "ListRefs with malformed repository",
        )?;
        want_code(
            read(&ctx, repository, "main").await?,
            "invalid_argument",
            "ReadRef with malformed repository",
        )?;
    }
    Ok(())
}

pub(super) async fn single_signed_missing(ctx: Ctx) -> CaseResult {
    let mut op = super::auth::signed_main(&ctx, &ctx.v2_signer("main")?, |_| {});
    super::auth::rejected(
        &ctx,
        &op.clone().with_header("x-repository", ""),
        "signed UpdateRef with empty X-Repository",
    )
    .await?;
    op.headers.retain(|(name, _)| name != "x-repository");
    super::auth::rejected(&ctx, &op, "signed UpdateRef without X-Repository").await
}

async fn isolated_pair(ctx: &Ctx, name_a: &str, name_b: &str) -> CaseResult {
    let (repo_a, repo_b) = identities(name_a, name_b);
    set(ctx, &repo_a, "main", &A).await?;
    set(ctx, &repo_b, "main", &B).await?;
    set(ctx, &repo_a, "only-a", &A).await?;
    set(ctx, &repo_b, "only-b", &B).await?;
    for (repository, id, own, other) in [
        (&repo_a, &A, "only-a", "only-b"),
        (&repo_b, &B, "only-b", "only-a"),
    ] {
        let refs = want_ok(list(ctx, repository).await?, "ListRefs")?.refs;
        let names: Vec<_> = refs
            .iter()
            .map(|r| r.name.as_deref().unwrap_or_default())
            .collect();
        ensure!(
            names == ["main", own],
            "ListRefs crossed repository boundary: {names:?}"
        );
        ensure!(
            refs.iter().all(|r| r.object_id.as_deref() == Some(id)),
            "ListRefs returned another repository's ids"
        );
        let value = want_ok(read(ctx, repository, "main").await?, "ReadRef own ref")?;
        ensure!(
            value.exists == Some(true) && value.object_id.as_deref() == Some(id),
            "ReadRef returned another repository's id"
        );
        let absent = want_ok(
            read(ctx, repository, other).await?,
            "ReadRef other repo's ref",
        )?;
        ensure!(
            absent.exists != Some(true)
                && absent.object_id.as_deref().unwrap_or_default().is_empty(),
            "ReadRef exposed another repository's ref"
        );
    }
    set(ctx, &repo_a, "main", &C).await?;
    let value = want_ok(
        read(ctx, &repo_b, "main").await?,
        "ReadRef after other repo write",
    )?;
    ensure!(
        value.object_id.as_deref() == Some(&B),
        "write changed another repository's ref"
    );
    Ok(())
}

pub(super) async fn isolation_refs(ctx: Ctx) -> CaseResult {
    isolated_pair(&ctx, "one", "two").await?;
    // Equal names force the namespace partition to provide isolation.
    isolated_pair(&ctx, "same", "same").await
}

pub(super) async fn signature_mismatch(ctx: Ctx) -> CaseResult {
    let (repo_a, repo_b) = identities("one", "two");
    set(&ctx, &repo_a, "main", &A).await?;
    set(&ctx, &repo_b, "main", &B).await?;
    let op = signed_update(&ctx, &repo_a, "main", &C)?.with_header("x-repository", &repo_b);
    want_code(
        ctx.send::<UpdateRefResponse>(&op).await?,
        "unauthenticated",
        "signature for A sent to B",
    )?;
    for (repository, id) in [(&repo_a, &A), (&repo_b, &B)] {
        let value = want_ok(
            read(&ctx, repository, "main").await?,
            "ReadRef after rejected write",
        )?;
        ensure!(
            value.object_id.as_deref() == Some(id),
            "rejected write changed a repository"
        );
    }
    Ok(())
}

pub(super) async fn multi_invalid(ctx: Ctx) -> CaseResult {
    for repository in ["", "default", "ns/name", "Uppercase"] {
        want_code(
            list(&ctx, repository).await?,
            "invalid_argument",
            "Multi ListRefs without a valid identity",
        )?;
        let mut op = signed_update(&ctx, &identities("one", "two").0, "main", &A)?;
        op = op.with_header("x-repository", repository);
        want_code(
            ctx.send::<UpdateRefResponse>(&op).await?,
            "invalid_argument",
            "Multi signed write without a valid identity",
        )?;
    }
    let body = ListRefsRequest::default().encode_to_vec();
    want_code(
        ctx.client()
            .unary::<ListRefsResponse>(Rpc::ListRefs, body, &[])
            .await?,
        "invalid_argument",
        "Multi ListRefs with absent header",
    )?;
    let mut op = signed_update(&ctx, &identities("one", "two").0, "main", &A)?;
    op.headers.retain(|(name, _)| name != "x-repository");
    want_code(
        ctx.send::<UpdateRefResponse>(&op).await?,
        "invalid_argument",
        "Multi signed write with absent header",
    )?;
    Ok(())
}

pub(super) async fn read_missing_repo(ctx: Ctx) -> CaseResult {
    let name = format!("missing-{}", to_hex(&hash(ctx.ns().as_bytes())));
    let (repository, _) = identities(&name, "unused");
    want_code(
        list(&ctx, &repository).await?,
        "not_found",
        "ListRefs nonexistent repository",
    )?;
    want_code(
        read(&ctx, &repository, "main").await?,
        "not_found",
        "ReadRef nonexistent repository",
    )?;
    Ok(())
}

pub(super) async fn packs_need_membership(ctx: Ctx) -> CaseResult {
    let (repository, _) = identities("packs", "unused");
    set(&ctx, &repository, "main", &A).await?;
    let id = hash(b"multi-repository pack");
    let body = PackExistsRequest {
        pack_id: Some(id.to_vec()),
        ..Default::default()
    }
    .encode_to_vec();
    let headers = read_headers(&ctx, Rpc::PackExists, &body, &repository);
    want_code(
        ctx.client()
            .unary::<PackExistsResponse>(Rpc::PackExists, body, &headers)
            .await?,
        "unimplemented",
        "Multi PackExists",
    )?;
    let body = frame(
        &DownloadPackRequest {
            pack_id: Some(id.to_vec()),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let headers = read_headers(&ctx, Rpc::DownloadPack, &body, &repository);
    let reply = ctx
        .client()
        .stream::<DownloadPackResponse>(Rpc::DownloadPack, body, &headers)
        .await?;
    ensure!(
        reply.messages.is_empty()
            && reply.error.as_ref().map(|e| e.code.as_str()) == Some("unimplemented"),
        "Multi DownloadPack: {reply:?}"
    );
    let pack = b"multi-repository pack";
    let signer = ctx.v2_signer("pack")?;
    let mut envelope = signer.envelope(
        Rpc::UploadPack.procedure(),
        pack_commitment(&id, pack.len() as u64),
    );
    repository.clone_into(&mut envelope.repository);
    let headers = signer.sign(&envelope).headers;
    let error = ctx.upload_with(&upload_msgs(pack, 2), &headers).await?;
    ensure!(
        error.as_ref().map(|e| e.code.as_str()) == Some("unimplemented"),
        "Multi UploadPack: {error:?}"
    );
    Ok(())
}
