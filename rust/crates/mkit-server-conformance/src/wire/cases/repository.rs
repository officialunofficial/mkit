//! Repository addressing and isolation (SPEC-TRANSPORT-CONNECT §7.4).

use buffa::Message as _;
use mkit_core::hash::{hash, to_hex};
use mkit_transport_connect::generated::__buffa::oneof::download_pack_response::Body as DownloadBody;
use mkit_transport_connect::generated::__buffa::oneof::{
    begin_upload_response::Result as BeginResult, upload_pack_request::Body as UploadBody,
};
use mkit_transport_connect::generated::{
    AdvanceOutcome, AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse,
    DownloadPackRequest, DownloadPackResponse, ListRefsRequest, ListRefsResponse,
    PackExistsRequest, PackExistsResponse, ReadRefRequest, ReadRefResponse, UpdateRefResponse,
};

use super::{
    A, B, C, CaseResult, Commit, Ctx, Exp, Failure, Signed, advance_req, ensure, eventually_listed,
    sign_unary, update_req, upload_msgs, want_code, want_ok, want_outcome,
};
use crate::wire::RELAY_DELAY_MS_HEADER;
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

pub(super) fn read_headers(
    ctx: &Ctx,
    rpc: Rpc,
    body: &[u8],
    repository: &str,
) -> Vec<(String, String)> {
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

pub(super) fn signed_update(
    ctx: &Ctx,
    repository: &str,
    leaf: &str,
    id: &[u8],
) -> Result<Signed, Failure> {
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
/// `PackExists` for `id` in `repository` with an optional ref hint — the
/// M0 affordance for "pack is a member" (HEAD `packs/*`).
async fn pack_exists(
    ctx: &Ctx,
    repository: &str,
    id: [u8; 32],
    hint: Option<&str>,
) -> Result<bool, Failure> {
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
    Ok(reply.exists == Some(true))
}

/// Fixtures are planted in-process by the Multi baseline because Multi uploads
/// still need tickets. Bytes equal `ctx.ns()`, with membership only in repo
/// `packs` owned by `repository-a`; see the baseline's `plant_membership`. A
/// served deployment seeds them over the wire ([`seed_membership`]), and a
/// member-true read then polls: the membership relay may lag the commit.
async fn pack_read(ctx: &Ctx, repository: &str, hint: Option<&str>, member: bool) -> CaseResult {
    let pack = ctx.ns().into_bytes();
    let id = hash(&pack);
    let got = if member && !ctx.profile().planted_membership {
        eventually_listed(
            "membership PackExists",
            || pack_exists(ctx, repository, id, hint),
            |m| *m,
        )
        .await?
    } else {
        pack_exists(ctx, repository, id, hint).await?
    };
    ensure!(
        got == member,
        "PackExists with hint {hint:?}: expected {member}, got {got}"
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

/// The membership fixtures a served deployment does not plant are seeded
/// over the wire instead (M2): a real ticketed push by `repository`'s
/// `repository-a` signer — a `BeginUpload` for `refs/heads/main`, the
/// ticketed `UploadPack` of `ctx.ns()`'s bytes, and a ticketed
/// `AdvanceRefs` head/packmap pair consuming the ticket into membership.
/// The in-process baseline planted them already, so this is a no-op there.
async fn seed_membership(ctx: &Ctx, repository: &str) -> CaseResult {
    if ctx.profile().planted_membership {
        return Ok(());
    }
    seed_membership_delayed(ctx, repository, None).await?;
    Ok(())
}

/// [`seed_membership`] whose final `AdvanceRefs` asks the server to hold the
/// ref shard's relay for `relay_delay_ms` (`test-faults`, D34). Returns when
/// that `AdvanceRefs` was sent, which starts the hold: the server's clock
/// starts at its commit, later than this.
async fn seed_membership_delayed(
    ctx: &Ctx,
    repository: &str,
    relay_delay_ms: Option<u64>,
) -> Result<std::time::Instant, Failure> {
    let pack = ctx.ns().into_bytes();
    let id = hash(&pack);
    let signer = ctx.v2_signer("repository-a")?;
    let begin = BeginUploadRequest {
        r#ref: Some("refs/heads/main".to_owned()),
        pack_id: Some(id.to_vec()),
        bytes: Some(pack.len() as u64),
        ..Default::default()
    };
    let opened: BeginUploadResponse = want_ok(
        ctx.send(&sign_unary(&signer, Rpc::BeginUpload, &begin, |env| {
            env.repository = repository.to_string();
        }))
        .await?,
        "membership seed BeginUpload",
    )?;
    let Some(BeginResult::Ticket(ticket)) = opened.result else {
        return Err(Failure::Fail(format!(
            "membership seed BeginUpload returned {opened:?}"
        )));
    };
    let mut msgs = upload_msgs(&pack, 2);
    if let Some(UploadBody::Header(header)) = &mut msgs[0].body {
        header.ticket_token = ticket.token;
    }
    let mut envelope = signer.envelope(
        Rpc::UploadPack.procedure(),
        pack_commitment(&id, pack.len() as u64),
    );
    repository.clone_into(&mut envelope.repository);
    let headers = signer.sign(&envelope).headers;
    ensure!(
        ctx.upload_with(&msgs, &headers).await?.is_none(),
        "membership seed UploadPack failed"
    );
    // The head/packmap pair the ticket binds to, consuming it into the
    // pack's membership in `repository`.
    let mut advance = advance_req(
        ("refs/heads/main", Exp::Missing, &A),
        ("refs/mkit/packmap/main", Exp::Missing, &B),
    );
    advance.ticket_ids = vec![ticket.id.unwrap_or_default()];
    let mut commit = sign_unary(&signer, Rpc::AdvanceRefs, &advance, |env| {
        env.repository = repository.to_string();
    });
    if let Some(delay) = relay_delay_ms {
        commit = commit.with_header(RELAY_DELAY_MS_HEADER, delay.to_string());
    }
    let sent = std::time::Instant::now();
    let response: Result<AdvanceRefsResponse, _> = ctx.send(&commit).await?;
    want_outcome(
        response.map(|r| r.outcome.map_or(0, |o| o.to_i32())),
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )?;
    Ok(sent)
}

pub(super) async fn isolation_packs(ctx: Ctx) -> CaseResult {
    let (repo_a, repo_other_namespace) = identities(&ctx, "packs", "packs")?;
    seed_membership(&ctx, &repo_a).await?;
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
    if !ctx.profile().planted_membership {
        return Err(Failure::Skip(
            "needs the membership index held undelivered; a served deployment's relay may deliver at any time".into(),
        ));
    }
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
    let (repo_a, repo_b) = identities(&ctx, "packs", "packs")?;
    seed_membership(&ctx, &repo_a).await?;
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

/// How long the lag cases hold the relay. The unhinted read must land inside
/// this window; a slower server skips instead of failing.
const LAG_MS: u64 = 8_000;

/// A D34 served deployment with `test-faults`: the lag cases seed over the
/// wire and rely on a running relay.
fn need_lag_window(ctx: &Ctx) -> CaseResult {
    if !ctx.profile().sharding_d34 {
        return Err(Failure::Skip(
            "requires separate membership and ref shards (D34)".into(),
        ));
    }
    if ctx.profile().planted_membership {
        return Err(Failure::Skip(
            "seeds over the wire and needs a relay; the in-process baseline runs none".into(),
        ));
    }
    Ok(())
}

pub(super) async fn membership_lag_window(ctx: Ctx) -> CaseResult {
    need_lag_window(&ctx)?;
    let (repository, _) = identities(&ctx, "lag", "unused")?;
    let started = seed_membership_delayed(&ctx, &repository, Some(LAG_MS)).await?;
    let pack = ctx.ns().into_bytes();
    // The relay is held: the committed pack is not yet a member without
    // its ref hint (a stale membership index answers false).
    let early = pack_exists(&ctx, &repository, hash(&pack), None).await?;
    if started.elapsed().as_millis() >= u128::from(LAG_MS) {
        return Err(Failure::Skip(
            "the lag window closed before the read".into(),
        ));
    }
    ensure!(!early, "membership was visible while its relay was held");
    // Then the relay delivers, within the bound (STC §7.9).
    pack_read(&ctx, &repository, None, true).await
}

pub(super) async fn d36_hint_reads_during_lag(ctx: Ctx) -> CaseResult {
    need_lag_window(&ctx)?;
    let (repo_a, repo_b) = identities(&ctx, "lag", "lag")?;
    let namespace = repo_a
        .split_once('/')
        .ok_or("repository has no namespace")?
        .0;
    let repo_c = format!("{namespace}/lag-two");
    // The same ref name in two other repositories: the hint must resolve
    // in the repository being read, never across repositories. They exist
    // before the timed push, so the window holds only reads.
    for (repository, label) in [(&repo_b, "repository-b"), (&repo_c, "repository-a")] {
        let signed = sign_unary(
            &ctx.v2_signer(label)?,
            Rpc::UpdateRef,
            &update_req("refs/heads/main", Exp::Any, &A),
            |env| repository.clone_into(&mut env.repository),
        );
        want_ok(ctx.send::<UpdateRefResponse>(&signed).await?, "UpdateRef")?;
    }
    let started = seed_membership_delayed(&ctx, &repo_a, Some(LAG_MS)).await?;
    // Inside the window the index has not seen the push: only a hinted read,
    // which checks the ref shard that holds the membership from its commit,
    // finds the pack.
    let id = hash(&ctx.ns().into_bytes());
    let (plain, hinted) = (
        pack_exists(&ctx, &repo_a, id, None).await?,
        pack_exists(&ctx, &repo_a, id, Some("refs/heads/main")).await?,
    );
    let in_window = |started: std::time::Instant| {
        if started.elapsed().as_millis() >= u128::from(LAG_MS) {
            Err(Failure::Skip(
                "the lag window closed before the reads".into(),
            ))
        } else {
            Ok(())
        }
    };
    in_window(started)?;
    ensure!(!plain, "membership was visible while its relay was held");
    ensure!(hinted, "the ref hint did not find the committed pack");
    // The hinted `DownloadPack` must land in the window too, or it would
    // prove nothing about the index it bypasses.
    pack_read(&ctx, &repo_a, Some("refs/heads/main"), true).await?;
    in_window(started)?;
    for repository in [&repo_b, &repo_c] {
        pack_read(&ctx, repository, Some("refs/heads/main"), false).await?;
    }
    Ok(())
}

pub(super) async fn isolation_replay(ctx: Ctx) -> CaseResult {
    let (repo_a, repo_b) = identities(&ctx, "replay", "replay")?;
    let namespace = repo_a
        .split_once('/')
        .ok_or("repository has no namespace")?
        .0;
    let repo_a_two = format!("{namespace}/replay-two");
    let req = update_req(&ctx.head("main"), Exp::Any, &A);
    let signed = |label: &str, repository: &str, nonce: Option<&str>| {
        Ok::<_, Failure>(sign_unary(
            &ctx.v2_signer(label)?,
            Rpc::UpdateRef,
            &req,
            |env| {
                repository.clone_into(&mut env.repository);
                if let Some(nonce) = nonce {
                    nonce.clone_into(&mut env.nonce);
                }
            },
        ))
    };
    let first = signed("repository-a", &repo_a, None)?;
    want_ok(ctx.send::<UpdateRefResponse>(&first).await?, "first write")?;
    // The very same nonce and body, validly signed for other repositories:
    // one of the same owner, one of another namespace. A replay ledger that
    // leaked across repositories would answer with the first write's saved
    // result and commit nothing.
    for (label, repository) in [("repository-a", &repo_a_two), ("repository-b", &repo_b)] {
        let again = signed(label, repository, Some(&first.nonce))?;
        want_ok(
            ctx.send::<UpdateRefResponse>(&again).await?,
            "same nonce elsewhere",
        )?;
        let value = want_ok(read(&ctx, repository, "main").await?, "ReadRef")?;
        ensure!(
            value.object_id.as_deref() == Some(&A),
            "a replay record in one repository answered a request to {repository}"
        );
    }
    // A true replay in repository A is answered from its saved result.
    set(&ctx, &repo_a, "main", &B).await?;
    want_ok(
        ctx.send::<UpdateRefResponse>(&first).await?,
        "replay in place",
    )?;
    let value = want_ok(read(&ctx, &repo_a, "main").await?, "ReadRef")?;
    ensure!(
        value.object_id.as_deref() == Some(&B),
        "a replay re-executed instead of returning its saved result"
    );
    Ok(())
}
