//! Repository addressing and isolation (SPEC-TRANSPORT-CONNECT §7.4).

use buffa::Message as _;
use mkit_core::hash::{hash, to_hex};
use mkit_transport_connect::generated::__buffa::oneof::download_pack_response::Body as DownloadBody;
use mkit_transport_connect::generated::{
    DownloadPackRequest, DownloadPackResponse, ListRefsRequest, ListRefsResponse,
    PackExistsRequest, PackExistsResponse, ReadRefRequest, ReadRefResponse, UpdateRefResponse,
};

use super::{
    A, B, C, CaseResult, Commit, Ctx, Exp, Failure, Signed, ensure, eventually_listed, sign_unary,
    update_req, upload_msgs, want_code, want_ok,
};
use crate::wire::client::{Rpc, frame};
use crate::wire::sign::pack_commitment;

pub(super) fn identities(
    ctx: &Ctx,
    name_a: &str,
    name_b: &str,
) -> Result<(String, String), Failure> {
    let a = ctx.v2_signer("repository-a")?;
    let b = ctx.v2_signer("repository-b")?;
    Ok((
        format!("ed25519-{}/{name_a}", a.public_key_hex()),
        format!("ed25519-{}/{name_b}", b.public_key_hex()),
    ))
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

pub(super) async fn read(
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
    let a = ctx.v2_signer("repository-a")?;
    let label = if repository.starts_with(&format!("ed25519-{}/", a.public_key_hex())) {
        "repository-a"
    } else {
        "repository-b"
    };
    Ok(sign_unary(
        &ctx.v2_signer(label)?,
        Rpc::UpdateRef,
        &update_req(&ctx.head(leaf), Exp::Any, id),
        |env| repository.clone_into(&mut env.repository),
    ))
}

pub(super) async fn set(ctx: &Ctx, repository: &str, leaf: &str, id: &[u8]) -> CaseResult {
    want_ok(
        ctx.send::<UpdateRefResponse>(&signed_update(ctx, repository, leaf, id)?)
            .await?,
        "UpdateRef",
    )?;
    Ok(())
}

pub(super) async fn single_header_mismatch(ctx: Ctx) -> CaseResult {
    // Both bare and namespaced spellings are well formed in Single mode.
    let namespaced = format!("ed25519-{}/other", "a".repeat(64));
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
    let (repo_a, repo_b) = identities(ctx, name_a, name_b)?;
    set(ctx, &repo_a, "main", &A).await?;
    set(ctx, &repo_b, "main", &B).await?;
    set(ctx, &repo_a, "only-a", &A).await?;
    set(ctx, &repo_b, "only-b", &B).await?;
    for (repository, id, own, other) in [
        (&repo_a, &A, "only-a", "only-b"),
        (&repo_b, &B, "only-b", "only-a"),
    ] {
        let refs = eventually_listed(
            "repository ListRefs",
            || async { Ok(want_ok(list(ctx, repository).await?, "ListRefs")?.refs) },
            |refs| {
                refs.len() == 2
                    && refs.iter().any(|r| r.name.as_deref() == Some("main"))
                    && refs.iter().any(|r| r.name.as_deref() == Some(own))
            },
        )
        .await?;
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
    let (repo_a, repo_b) = identities(&ctx, "one", "two")?;
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
        let mut op = signed_update(&ctx, &identities(&ctx, "one", "two")?.0, "main", &A)?;
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
    let mut op = signed_update(&ctx, &identities(&ctx, "one", "two")?.0, "main", &A)?;
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
    let (repository, _) = identities(&ctx, &name, "unused")?;
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
    let (repository, _) = identities(&ctx, "packs", "unused")?;
    set(&ctx, &repository, "main", &A).await?;
    let id = hash(b"multi-repository pack");
    let body = PackExistsRequest {
        pack_id: Some(id.to_vec()),
        ..Default::default()
    }
    .encode_to_vec();
    let headers = read_headers(&ctx, Rpc::PackExists, &body, &repository);
    let reply = want_ok(
        ctx.client()
            .unary::<PackExistsResponse>(Rpc::PackExists, body, &headers)
            .await?,
        "Multi PackExists",
    )?;
    ensure!(reply.exists != Some(true), "non-member pack exists");
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
            && reply.error.as_ref().map(|e| e.code.as_str()) == Some("not_found"),
        "Multi DownloadPack: {reply:?}"
    );
    let pack = b"multi-repository pack";
    let signer = ctx.v2_signer("repository-a")?;
    let mut envelope = signer.envelope(
        Rpc::UploadPack.procedure(),
        pack_commitment(&id, pack.len() as u64),
    );
    repository.clone_into(&mut envelope.repository);
    let headers = signer.sign(&envelope).headers;
    let error = ctx.upload_with(&upload_msgs(pack, 2), &headers).await?;
    ensure!(
        error.as_ref().map(|e| e.code.as_str()) == Some("failed_precondition"),
        "Multi UploadPack: {error:?}"
    );
    Ok(())
}

pub(super) async fn upload_needs_ticket(ctx: Ctx) -> CaseResult {
    let (repository, _) = identities(&ctx, "needs-ticket", "unused")?;
    let pack = b"multi needs ticket";
    let id = hash(pack);
    let signer = ctx.v2_signer("repository-a")?;
    let mut envelope = signer.envelope(
        Rpc::UploadPack.procedure(),
        pack_commitment(&id, pack.len() as u64),
    );
    repository.clone_into(&mut envelope.repository);
    let headers = signer.sign(&envelope).headers;
    let error = ctx.upload_with(&upload_msgs(pack, 2), &headers).await?;
    ensure!(
        error.as_ref().map(|e| e.code.as_str()) == Some("failed_precondition"),
        "Multi upload without ticket: {error:?}"
    );
    Ok(())
}

pub(super) async fn ticketed_upload_multi(ctx: Ctx) -> CaseResult {
    use mkit_transport_connect::generated::__buffa::oneof::{
        begin_upload_response::Result as BeginResult, upload_pack_request::Body as UploadBody,
    };
    use mkit_transport_connect::generated::{BeginUploadRequest, BeginUploadResponse};
    let (repository, _) = identities(&ctx, "ticketed", "unused")?;
    let pack = b"multi ticketed conformance pack";
    let id = hash(pack);
    let signer = ctx.v2_signer("repository-a")?;
    let req = BeginUploadRequest {
        r#ref: Some(ctx.head("main")),
        pack_id: Some(id.to_vec()),
        bytes: Some(pack.len() as u64),
        ..Default::default()
    };
    let signed_begin = sign_unary(&signer, Rpc::BeginUpload, &req, |env| {
        repository.clone_into(&mut env.repository);
    });
    let response: BeginUploadResponse =
        want_ok(ctx.send(&signed_begin).await?, "Multi BeginUpload")?;
    let Some(BeginResult::Ticket(ticket)) = response.result else {
        return Err(Failure::Fail(
            "Multi BeginUpload did not return a ticket".into(),
        ));
    };
    let mut msgs = upload_msgs(pack, 2);
    if let Some(UploadBody::Header(header)) = &mut msgs[0].body {
        header.ticket_token = ticket.token;
    }
    let mut envelope = signer.envelope(
        Rpc::UploadPack.procedure(),
        pack_commitment(&id, pack.len() as u64),
    );
    repository.clone_into(&mut envelope.repository);
    let headers = signer.sign(&envelope).headers;
    let error = ctx.upload_with(&msgs, &headers).await?;
    ensure!(error.is_none(), "Multi ticketed UploadPack: {error:?}");
    Ok(())
}
/// Fixtures are planted in-process by the Multi baseline because Multi uploads
/// still need tickets. Bytes equal `ctx.ns()`, with membership only in repo
/// `packs` owned by `repository-a`; see the baseline's `plant_membership`.
async fn pack_read(ctx: &Ctx, repository: &str, hint: Option<&str>, member: bool) -> CaseResult {
    let pack = ctx.ns().into_bytes();
    let id = hash(&pack);
    let body = PackExistsRequest {
        pack_id: Some(id.to_vec()),
        ..Default::default()
    }
    .encode_to_vec();
    let mut headers = read_headers(ctx, Rpc::PackExists, &body, repository);
    if let Some(hint) = hint {
        headers.push(("x-mkit-ref".into(), hint.into()));
    }
    let reply: PackExistsResponse = want_ok(
        ctx.client().unary(Rpc::PackExists, body, &headers).await?,
        "membership PackExists",
    )?;
    ensure!(
        reply.exists == Some(member),
        "PackExists with hint {hint:?}: expected {member}, got {:?}",
        reply.exists
    );
    let body = frame(
        &DownloadPackRequest {
            pack_id: Some(id.to_vec()),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let mut headers = read_headers(ctx, Rpc::DownloadPack, &body, repository);
    if let Some(hint) = hint {
        headers.push(("x-mkit-ref".into(), hint.into()));
    }
    let reply = ctx
        .client()
        .stream::<DownloadPackResponse>(Rpc::DownloadPack, body, &headers)
        .await?;
    if !member {
        ensure!(
            reply.messages.is_empty()
                && reply.error.as_ref().map(|e| e.code.as_str()) == Some("not_found"),
            "non-member DownloadPack with hint {hint:?}: {reply:?}"
        );
        return Ok(());
    }
    ensure!(reply.error.is_none(), "member DownloadPack: {reply:?}");
    let mut messages = reply.messages.into_iter().map(|message| message.body);
    let Some(Some(DownloadBody::Header(header))) = messages.next() else {
        return Err("member DownloadPack did not begin with a header".into());
    };
    ensure!(
        header.total_bytes == Some(pack.len() as u64),
        "wrong pack length"
    );
    let (mut bytes, mut last) = (Vec::new(), false);
    for body in messages {
        ensure!(!last, "DownloadPack sent a message after last");
        let Some(DownloadBody::Chunk(chunk)) = body else {
            return Err("DownloadPack sent a non-chunk after its header".into());
        };
        ensure!(
            chunk.pack_id.as_deref() == Some(id.as_slice())
                && chunk.offset == Some(bytes.len() as u64),
            "DownloadPack chunk has wrong id or offset"
        );
        bytes.extend_from_slice(chunk.data.as_deref().unwrap_or_default());
        last = chunk.last == Some(true);
    }
    ensure!(
        last && bytes == pack,
        "member DownloadPack bytes differ from fixture"
    );
    Ok(())
}

/// The planted membership fixtures exist only where a harness seeds them
/// (`Profile::planted_membership`): an in-process baseline, never a served
/// deployment.
fn planted(ctx: &Ctx) -> CaseResult {
    if !ctx.profile().planted_membership {
        return Err(Failure::Skip(
            "needs planted membership fixtures (in-process baseline only)".into(),
        ));
    }
    Ok(())
}

pub(super) async fn isolation_packs(ctx: Ctx) -> CaseResult {
    planted(&ctx)?;
    let (repo_a, repo_other_namespace) = identities(&ctx, "packs", "packs")?;
    let namespace = repo_a
        .split_once('/')
        .ok_or("repository has no namespace")?
        .0;
    let repo_same_namespace = format!("{namespace}/other-packs");
    for repository in [&repo_a, &repo_other_namespace, &repo_same_namespace] {
        set(&ctx, repository, "main", &A).await?;
    }
    pack_read(&ctx, &repo_a, None, true).await?;
    pack_read(&ctx, &repo_a, Some("refs/heads/main"), true).await?;
    for repository in [&repo_other_namespace, &repo_same_namespace] {
        pack_read(&ctx, repository, None, false).await?;
        pack_read(&ctx, repository, Some("refs/heads/main"), false).await?;
    }
    Ok(())
}

pub(super) async fn membership_read_your_writes(ctx: Ctx) -> CaseResult {
    if !ctx.profile().sharding_d34 {
        return Err(Failure::Skip(
            "requires separate membership and ref shards (D34)".into(),
        ));
    }
    planted(&ctx)?;
    let (repository, _) = identities(&ctx, "packs", "unused")?;
    set(&ctx, &repository, "main", &A).await?;
    // No relay runs in this baseline: only refs/heads/main holds membership.
    pack_read(&ctx, &repository, None, false).await?;
    pack_read(&ctx, &repository, Some("refs/heads/./main"), false).await?;
    pack_read(&ctx, &repository, Some("refs/mkit/private/main"), false).await?;
    pack_read(&ctx, &repository, Some("refs/heads/main"), true).await?;
    pack_read(&ctx, &repository, Some("refs/heads/unknown"), false).await?;
    pack_read(&ctx, &repository, None, false).await
}

pub(super) async fn malformed_membership_hint(ctx: Ctx) -> CaseResult {
    planted(&ctx)?;
    let (repo_a, repo_b) = identities(&ctx, "packs", "packs")?;
    set(&ctx, &repo_a, "main", &A).await?;
    set(&ctx, &repo_b, "main", &B).await?;
    // A positive control proves the blob exists and malformed hints cannot
    // override an indexed membership hit. B stays absent for every bad hint.
    for hint in [
        "../refs/heads/main",
        "refs/heads/../main",
        "refs/mkit/private/main",
        "main",
    ] {
        pack_read(&ctx, &repo_a, Some(hint), true).await?;
        pack_read(&ctx, &repo_b, Some(hint), false).await?;
    }
    let oversized = format!("refs/heads/{}", "a".repeat(513));
    pack_read(&ctx, &repo_b, Some(&oversized), false).await
}
