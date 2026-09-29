//! M2 signed reads, private repositories and URL tokens
//! (SPEC-WRITE-GRANTS §7, §9.4; SPEC-HTTP-OBJECTS §3, §6).

use buffa::Message;
use mkit_attest::grant::Capabilities;
use mkit_core::hash::{hash, to_hex};
use mkit_server::url_token::{Binding, UrlTarget, UrlTokenConfig, UrlTokenKeys};
use mkit_transport_connect::generated::__buffa::oneof::issue_object_url_request::Target;
use mkit_transport_connect::generated::{
    DownloadPackRequest, DownloadPackResponse, IssueObjectUrlRequest, IssueObjectUrlResponse,
    ListRefsRequest, ListRefsResponse, PackExistsRequest, PackExistsResponse, ReadRefRequest,
    ReadRefResponse, RefPath, UpdateRefResponse,
};

use super::{
    A, CaseResult, Ctx, Exp, Failure, Signed, ensure, grants, sign_unary, update_req, want_code,
    want_ok,
};
use crate::wire::client::{
    Reply, Rpc, STREAM_PROTO, UNARY_PROTO, decode_stream, decode_unary, frame,
};
use crate::wire::sign::{Signer, body_commitment, now_ms};
use crate::wire::{URL_TOKEN_SEED, URL_TOKEN_TTL_MS};

/// This case's `repository-a` owner and its repository.
pub(super) fn owned(ctx: &Ctx) -> Result<(Signer, String), Failure> {
    let owner = ctx.v2_signer("repository-a")?;
    let repo = format!(
        "ed25519-{}/{}-{}",
        owner.public_key_hex(),
        ctx.profile().run_id,
        ctx.case.replace('.', "-")
    );
    Ok((owner, repo))
}

/// This case's grant owner: the case name is in the key derivation, so a
/// case bumping the namespace's grant epoch never couples to another
/// case's grants.
fn case_owner(ctx: &Ctx) -> Result<grants::Owner, Failure> {
    grants::ed_owner(ctx)
}

/// The test-faults epoch bump for `repo`, signed by its `owner`.
async fn bump_epoch(ctx: &Ctx, owner: &Signer, repo: &str) -> CaseResult {
    let body = list_req(ctx).encode_to_vec();
    let s =
        signed_body_on(owner, Rpc::ListRefs, repo, body).with_header("x-mkit-test-bump-epoch", "1");
    want_ok(ctx.send::<ListRefsResponse>(&s).await?, "test epoch bump")?;
    Ok(())
}

/// `req` signed by `signer` for `repository`.
pub(super) fn signed_for(
    signer: &Signer,
    repository: &str,
    rpc: Rpc,
    req: &impl Message,
) -> Signed {
    sign_unary(signer, rpc, req, |env| {
        repository.to_owned().clone_into(&mut env.repository);
    })
}

/// `body` signed by `signer` for `repository`: `sign_unary` for a
/// pre-encoded body, so one body signs for two repositories.
fn signed_body_on(signer: &Signer, rpc: Rpc, repository: &str, body: Vec<u8>) -> Signed {
    let mut env = signer.envelope(rpc.procedure(), body_commitment(&body));
    env.digest = Some(to_hex(&hash(&body)));
    repository.clone_into(&mut env.repository);
    let op = signer.sign(&env);
    Signed {
        rpc,
        body,
        headers: op.headers,
        nonce: op.nonce,
    }
}

/// `req` with only the `x-repository` addressing header: unsigned.
pub(super) fn unsigned(repository: &str, rpc: Rpc, req: &impl Message) -> Signed {
    Signed {
        rpc,
        body: req.encode_to_vec(),
        headers: vec![("x-repository".to_owned(), repository.to_owned())],
        nonce: String::new(),
    }
}

fn read_req(ctx: &Ctx, leaf: &str) -> ReadRefRequest {
    ReadRefRequest {
        name: Some(ctx.head(leaf)),
        ..Default::default()
    }
}

fn list_req(ctx: &Ctx) -> ListRefsRequest {
    ListRefsRequest {
        prefix: Some(ctx.head("")),
        ..Default::default()
    }
}

fn issue_req(target: Option<Target>) -> IssueObjectUrlRequest {
    IssueObjectUrlRequest {
        target,
        ..Default::default()
    }
}

/// The owner creates `repository` (a `main` ref) and, when `private`, sets
/// its visibility envelope to PRIVATE.
pub(super) async fn seeded_repo(
    ctx: &Ctx,
    owner: &Signer,
    repo: &str,
    private: bool,
) -> CaseResult {
    let create = signed_for(
        owner,
        repo,
        Rpc::UpdateRef,
        &update_req(&ctx.head("main"), Exp::Any, &A),
    );
    want_ok(
        ctx.send::<UpdateRefResponse>(&create).await?,
        "create the repository",
    )?;
    if private {
        super::visibility::set_envelope(ctx, owner, repo, true).await?;
    }
    Ok(())
}

/// A tampered copy of `signed`: the signature stays hex but no longer
/// verifies.
fn bad_signature(signed: &Signed) -> Signed {
    let mut flipped = signed.header("x-signature").as_bytes().to_vec();
    let last = flipped.last_mut().expect("a signature is signed");
    *last = if *last == b'0' { b'1' } else { b'0' };
    signed.clone().with_header(
        "x-signature",
        String::from_utf8(flipped).expect("hex stays utf-8"),
    )
}

/// A raw unary reply, for the byte-identical comparison.
async fn raw(ctx: &Ctx, s: &Signed) -> Result<Reply, Failure> {
    ctx.client()
        .post(s.rpc.procedure(), UNARY_PROTO, &s.headers, s.body.clone())
        .await
        .map_err(Failure::Fail)
}

/// A raw server-streaming reply (`DownloadPack` requests are framed).
async fn raw_stream(ctx: &Ctx, s: &Signed) -> Result<Reply, Failure> {
    ctx.client()
        .post(s.rpc.procedure(), STREAM_PROTO, &s.headers, s.body.clone())
        .await
        .map_err(Failure::Fail)
}

/// The headers two `not_found` replies must share: everything but `date`
/// and `content-length`, which the transport stamps per response and the
/// spec does not pin.
fn comparable_headers(reply: &Reply) -> Vec<(String, String)> {
    reply
        .headers
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "date" | "content-length"))
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("<binary>").to_owned(),
            )
        })
        .collect()
}

/// The Connect error code of a failed read reply.
fn reply_code(reply: &Reply, stream: bool, what: &str) -> Result<String, Failure> {
    if stream {
        decode_stream::<DownloadPackResponse>(reply)
            .map_err(Failure::Fail)?
            .error
            .map(|e| e.code)
            .ok_or_else(|| Failure::Fail(format!("{what}: stream had no error")))
    } else {
        Ok(decode_unary::<ReadRefResponse>(reply)
            .map_err(Failure::Fail)?
            .expect_err("a private repo without read access must fail")
            .code)
    }
}

/// Both replies must be the same `not_found`, byte for byte.
fn same_not_found(private: &Reply, missing: &Reply, what: &str) -> CaseResult {
    ensure!(
        private.status == missing.status,
        "{what}: private HTTP {} vs missing HTTP {}",
        private.status,
        missing.status,
    );
    ensure!(
        private.body == missing.body,
        "{what}: private body {:?} vs missing {:?}",
        private.body,
        missing.body,
    );
    ensure!(
        comparable_headers(private) == comparable_headers(missing),
        "{what}: private headers differ from missing"
    );
    Ok(())
}

/// The audience every auth v2 profile signs for.
pub(super) fn audience(ctx: &Ctx) -> Result<String, Failure> {
    let crate::wire::profile::WireAuth::AuthV2 { audience, .. } = &ctx.profile().auth else {
        return Err(Failure::Skip("needs an auth v2 profile".into()));
    };
    Ok(audience.clone())
}

/// Mint `IssueObjectUrl` as `signer` for `target`, asserting success.
async fn mint(
    ctx: &Ctx,
    signer: &Signer,
    repo: &str,
    req: &IssueObjectUrlRequest,
) -> Result<IssueObjectUrlResponse, Failure> {
    let call = signed_for(signer, repo, Rpc::IssueObjectUrl, req);
    want_ok(
        ctx.send::<IssueObjectUrlResponse>(&call).await?,
        "IssueObjectUrl",
    )
}

/// The URL-token verification key set this suite's servers run with.
fn token_config() -> UrlTokenConfig {
    let keys = UrlTokenKeys::parse_key_file(&format!("active {URL_TOKEN_SEED}"))
        .expect("the suite's fixed token seed is valid");
    UrlTokenConfig::with_ttl_ms(keys, URL_TOKEN_TTL_MS).expect("the suite's token ttl is valid")
}

/// A bad signature is rejected at stage 0 — before the repository is read —
/// so a public, a private and a missing repository all answer the same
/// `unauthenticated`.
pub(super) async fn signed_verified_in_full(ctx: Ctx) -> CaseResult {
    let (owner, public_repo) = owned(&ctx)?;
    let private_repo = format!("{public_repo}-priv");
    seeded_repo(&ctx, &owner, &public_repo, false).await?;
    seeded_repo(&ctx, &owner, &private_repo, true).await?;
    let missing = format!(
        "ed25519-{}/{}-missing",
        ctx.v2_signer("outsider")?.public_key_hex(),
        ctx.profile().run_id
    );
    for repo in [public_repo, private_repo, missing] {
        let s = bad_signature(&signed_for(
            &owner,
            &repo,
            Rpc::ReadRef,
            &read_req(&ctx, "main"),
        ));
        want_code(
            ctx.send::<ReadRefResponse>(&s).await?,
            "unauthenticated",
            &format!("bad signature on {repo}"),
        )?;
    }
    Ok(())
}

/// A public repository reads unsigned.
pub(super) async fn public_unsigned_ok(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, false).await?;
    let read = want_ok(
        ctx.send::<ReadRefResponse>(&unsigned(&repo, Rpc::ReadRef, &read_req(&ctx, "main")))
            .await?,
        "unsigned ReadRef",
    )?;
    ensure!(
        read.object_id.as_deref() == Some(&A[..]),
        "unsigned ReadRef did not see the write"
    );
    want_ok(
        ctx.send::<ListRefsResponse>(&unsigned(&repo, Rpc::ListRefs, &list_req(&ctx)))
            .await?,
        "unsigned ListRefs",
    )?;
    Ok(())
}

/// An unsigned read of a private repository is `not_found`.
pub(super) async fn private_anonymous_not_found(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, true).await?;
    want_code(
        ctx.send::<ReadRefResponse>(&unsigned(&repo, Rpc::ReadRef, &read_req(&ctx, "main")))
            .await?,
        "not_found",
        "anonymous ReadRef",
    )?;
    Ok(())
}

/// The owner reads its private repository.
pub(super) async fn private_owner_ok(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, true).await?;
    let read = want_ok(
        ctx.send::<ReadRefResponse>(&signed_for(
            &owner,
            &repo,
            Rpc::ReadRef,
            &read_req(&ctx, "main"),
        ))
        .await?,
        "owner ReadRef",
    )?;
    ensure!(
        read.object_id.as_deref() == Some(&A[..]),
        "owner ReadRef did not see the write"
    );
    want_ok(
        ctx.send::<PackExistsResponse>(&signed_for(
            &owner,
            &repo,
            Rpc::PackExists,
            &PackExistsRequest {
                pack_id: Some(A.to_vec()),
                ..Default::default()
            },
        ))
        .await?,
        "owner PackExists",
    )?;
    if ctx.profile().sharding_d34 {
        // D34 ListRefs (WP-1.28b) reads the relayed ref index; no relay
        // worker runs in-process, so the fresh write is not listed yet.
        return Err(Failure::Skip(
            "D34 ListRefs reads a lagging ref index".into(),
        ));
    }
    let listed = want_ok(
        ctx.send::<ListRefsResponse>(&signed_for(&owner, &repo, Rpc::ListRefs, &list_req(&ctx)))
            .await?,
        "owner ListRefs",
    )?;
    // ListRefs names are prefix-stripped (SPEC-TRANSPORT-CONNECT §7.9).
    ensure!(
        listed
            .refs
            .iter()
            .any(|r| r.name.as_deref() == Some("main")),
        "owner ListRefs missed the ref: {:?}",
        listed
            .refs
            .iter()
            .map(|r| r.name.clone())
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// A `read` grant reads a private repository.
pub(super) async fn private_read_grant_ok(ctx: Ctx) -> CaseResult {
    let owner = case_owner(&ctx)?;
    let grantee = ctx.v2_signer("read-grantee")?;
    let repo = grants::repo(&ctx, &owner);
    let grants::Owner::Ed(owner_signer) = &owner else {
        unreachable!()
    };
    seeded_repo(&ctx, owner_signer, &repo, true).await?;
    let mut statement = grants::grant_at_epoch(&ctx, &owner, &repo, &grantee).await?;
    statement.capabilities = Capabilities::Read;
    statement.ref_scopes = None;
    let header = owner.signed_header(&statement);
    let read = signed_for(&grantee, &repo, Rpc::ReadRef, &read_req(&ctx, "main"))
        .with_header("x-write-grant", header);
    let resp = want_ok(
        ctx.send::<ReadRefResponse>(&read).await?,
        "read-grant ReadRef",
    )?;
    ensure!(
        resp.object_id.as_deref() == Some(&A[..]),
        "read-grant ReadRef did not see the write"
    );
    Ok(())
}

/// A write-only grant is no read authorization: `not_found`, not denied.
pub(super) async fn private_write_only_not_found(ctx: Ctx) -> CaseResult {
    let owner = case_owner(&ctx)?;
    let grantee = ctx.v2_signer("write-grantee")?;
    let repo = grants::repo(&ctx, &owner);
    let grants::Owner::Ed(owner_signer) = &owner else {
        unreachable!()
    };
    seeded_repo(&ctx, owner_signer, &repo, true).await?;
    let header = owner.signed_header(&grants::grant_at_epoch(&ctx, &owner, &repo, &grantee).await?);
    let read = signed_for(&grantee, &repo, Rpc::ReadRef, &read_req(&ctx, "main"))
        .with_header("x-write-grant", header);
    want_code(
        ctx.send::<ReadRefResponse>(&read).await?,
        "not_found",
        "write-only grant ReadRef",
    )?;
    Ok(())
}

/// An expired envelope is `unauthenticated` even on a private repository:
/// stage 0 precedes visibility.
pub(super) async fn private_expired_signature_unauthenticated(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, true).await?;
    let stale = now_ms() - 3_600_000;
    let s = sign_unary(&owner, Rpc::ReadRef, &read_req(&ctx, "main"), |env| {
        env.repository.clone_from(&repo);
        env.created_at = stale;
        env.expires_at = stale + 60_000;
    });
    want_code(
        ctx.send::<ReadRefResponse>(&s).await?,
        "unauthenticated",
        "expired envelope on a private repo",
    )?;
    Ok(())
}

/// A grant minted before an epoch bump no longer reads (test-faults).
pub(super) async fn private_grant_old_epoch_not_found(ctx: Ctx) -> CaseResult {
    let owner = case_owner(&ctx)?;
    let grantee = ctx.v2_signer("read-grantee")?;
    let repo = grants::repo(&ctx, &owner);
    let grants::Owner::Ed(owner_signer) = &owner else {
        unreachable!()
    };
    seeded_repo(&ctx, owner_signer, &repo, true).await?;
    // Minted at the current epoch, before the bump.
    let mut statement = grants::grant_at_epoch(&ctx, &owner, &repo, &grantee).await?;
    statement.capabilities = Capabilities::Read;
    statement.ref_scopes = None;
    bump_epoch(&ctx, owner_signer, &repo).await?;
    let stale = signed_for(&grantee, &repo, Rpc::ReadRef, &read_req(&ctx, "main"))
        .with_header("x-write-grant", owner.signed_header(&statement));
    want_code(
        ctx.send::<ReadRefResponse>(&stale).await?,
        "not_found",
        "old-epoch read grant",
    )?;
    // At the new epoch the same grantee reads again.
    let mut current = grants::grant_at_epoch(&ctx, &owner, &repo, &grantee).await?;
    current.capabilities = Capabilities::Read;
    current.ref_scopes = None;
    let fresh = signed_for(&grantee, &repo, Rpc::ReadRef, &read_req(&ctx, "main"))
        .with_header("x-write-grant", owner.signed_header(&current));
    want_ok(
        ctx.send::<ReadRefResponse>(&fresh).await?,
        "new-epoch read grant",
    )?;
    Ok(())
}

/// One unsigned read to compare between a private and a missing repository.
struct AnonymousRead<'a> {
    rpc: Rpc,
    stream: bool,
    body: &'a [u8],
    hint: Option<&'a str>,
}

/// An unsigned caller sees the same `not_found` bytes for the private and
/// the missing repository (`[private, missing]`).
async fn anonymous_not_found(
    ctx: &Ctx,
    read: &AnonymousRead<'_>,
    [private, missing]: [&str; 2],
    what: &str,
) -> CaseResult {
    let content_type = if read.stream {
        STREAM_PROTO
    } else {
        UNARY_PROTO
    };
    let send = |repository: &str| {
        let mut headers = vec![("x-repository".to_owned(), repository.to_owned())];
        if let Some(h) = read.hint {
            headers.push(("x-mkit-ref".to_owned(), h.to_owned()));
        }
        let (client, body) = (ctx.client(), read.body.to_vec());
        async move {
            client
                .post(read.rpc.procedure(), content_type, &headers, body)
                .await
                .map_err(Failure::Fail)
        }
    };
    let (private, missing) = (send(private).await?, send(missing).await?);
    let what = format!("{what} anonymous");
    let code = reply_code(&private, read.stream, &what)?;
    ensure!(
        code == "not_found",
        "{what}: private read failed with {code}"
    );
    same_not_found(&private, &missing, &what)
}

/// For every read procedure, an unauthorized private repository's reply is
/// byte-identical to a missing repository's: HTTP status, Connect code,
/// message, details and body — and every response header except `date` and
/// `content-length`, which are per-response transport noise the spec does
/// not pin (SPEC-WRITE-GRANTS §9.1).
pub(super) async fn private_not_found_byte_identical(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, true).await?;
    let outsider = ctx.v2_signer("outsider")?;
    let missing = format!(
        "ed25519-{}/{}-missing",
        outsider.public_key_hex(),
        ctx.profile().run_id
    );
    let pack = mkit_core::hash::hash(b"private byte-identical pack");
    for hint in [None, Some(ctx.head("main"))] {
        for (what, rpc, body, stream) in [
            (
                "ReadRef",
                Rpc::ReadRef,
                read_req(&ctx, "main").encode_to_vec(),
                false,
            ),
            (
                "ListRefs",
                Rpc::ListRefs,
                list_req(&ctx).encode_to_vec(),
                false,
            ),
            (
                "PackExists",
                Rpc::PackExists,
                PackExistsRequest {
                    pack_id: Some(pack.to_vec()),
                    ..Default::default()
                }
                .encode_to_vec(),
                false,
            ),
            (
                "DownloadPack",
                Rpc::DownloadPack,
                frame(
                    &DownloadPackRequest {
                        pack_id: Some(pack.to_vec()),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ),
                true,
            ),
            (
                "IssueObjectUrl",
                Rpc::IssueObjectUrl,
                issue_req(Some(Target::ObjectId(pack.to_vec()))).encode_to_vec(),
                false,
            ),
        ] {
            let what = format!("{what} hint={hint:?}");
            let mut private = signed_body_on(&outsider, rpc, &repo, body.clone());
            let mut missing_reply = signed_body_on(&outsider, rpc, &missing, body.clone());
            if let Some(h) = &hint {
                private = private.with_header("x-mkit-ref", h);
                missing_reply = missing_reply.with_header("x-mkit-ref", h);
            }
            let (private, missing_reply) = if stream {
                (
                    raw_stream(&ctx, &private).await?,
                    raw_stream(&ctx, &missing_reply).await?,
                )
            } else {
                (raw(&ctx, &private).await?, raw(&ctx, &missing_reply).await?)
            };
            // Both must be `not_found`, not merely identical.
            let code = reply_code(&private, stream, &what)?;
            ensure!(
                code == "not_found",
                "{what}: private read failed with {code}"
            );
            same_not_found(&private, &missing_reply, &what)?;
            // The anonymous variant; `IssueObjectUrl` has no unsigned form.
            if rpc != Rpc::IssueObjectUrl {
                let target = AnonymousRead {
                    rpc,
                    stream,
                    body: &body,
                    hint: hint.as_deref(),
                };
                anonymous_not_found(&ctx, &target, [&repo, &missing], &what).await?;
            }
        }
    }
    Ok(())
}

/// The owner mints a URL token that `precheck`, `check_binding` and
/// `check_epoch` all accept at the stored epoch.
pub(super) async fn url_token_mint_ok(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, false).await?;
    let minted = mint(
        &ctx,
        &owner,
        &repo,
        &issue_req(Some(Target::ObjectId(A.to_vec()))),
    )
    .await?;
    let token = minted
        .token
        .ok_or_else(|| Failure::Fail("IssueObjectUrl omitted the token".into()))?;
    let audience = audience(&ctx)?;
    let now = now_ms();
    let bound = token_config()
        .precheck(&token, now)
        .and_then(|pre| {
            pre.check_binding(
                &Binding {
                    audience: &audience,
                    repository: &repo,
                    target: &UrlTarget::Object(A),
                },
                now,
                URL_TOKEN_TTL_MS,
            )
        })
        .map_err(|_| Failure::Fail("minted token failed verification".into()))?;
    let epoch = super::epochs::current(&ctx, &grants::ed_owner(&ctx)?).await?;
    bound
        .check_epoch(epoch)
        .map_err(|_| Failure::Fail("minted token's epoch is stale".into()))?;
    Ok(())
}

/// `IssueObjectUrl` on a private repository without read access is the
/// uniform `not_found`.
pub(super) async fn url_token_private_without_read_not_found(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, true).await?;
    let outsider = ctx.v2_signer("outsider")?;
    let s = signed_for(
        &outsider,
        &repo,
        Rpc::IssueObjectUrl,
        &issue_req(Some(Target::ObjectId(A.to_vec()))),
    );
    want_code(
        ctx.send::<IssueObjectUrlResponse>(&s).await?,
        "not_found",
        "outsider IssueObjectUrl",
    )?;
    Ok(())
}

/// An unsigned `IssueObjectUrl` is `unauthenticated`.
pub(super) async fn url_token_anonymous_unauthenticated(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, false).await?;
    let s = unsigned(
        &repo,
        Rpc::IssueObjectUrl,
        &issue_req(Some(Target::ObjectId(A.to_vec()))),
    );
    want_code(
        ctx.send::<IssueObjectUrlResponse>(&s).await?,
        "unauthenticated",
        "anonymous IssueObjectUrl",
    )?;
    Ok(())
}

/// `IssueObjectUrl` bounds: a missing target, a short object id and invalid
/// `ref_path` paths are all `invalid_argument`.
pub(super) async fn url_token_bounds_invalid_argument(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, false).await?;
    let ref_path = |path: &str| {
        issue_req(Some(Target::RefPath(Box::new(RefPath {
            r#ref: Some(ctx.head("main")),
            path: Some(path.to_owned()),
            ..Default::default()
        }))))
    };
    for (what, req) in [
        ("target unset", issue_req(None)),
        (
            "31-byte object id",
            issue_req(Some(Target::ObjectId(vec![0x42; 31]))),
        ),
        ("path `.`", ref_path(".")),
        ("path `..`", ref_path("a/../b")),
        ("path `a//b`", ref_path("a//b")),
        ("1,025-byte path", ref_path(&"x".repeat(1025))),
    ] {
        let s = signed_for(&owner, &repo, Rpc::IssueObjectUrl, &req);
        want_code(
            ctx.send::<IssueObjectUrlResponse>(&s).await?,
            "invalid_argument",
            what,
        )?;
    }
    Ok(())
}

/// `ttl_seconds` 0 and `u32::MAX` both mint at the configured
/// `url_token_ttl`.
pub(super) async fn url_token_ttl_clamped(ctx: Ctx) -> CaseResult {
    let (owner, repo) = owned(&ctx)?;
    seeded_repo(&ctx, &owner, &repo, false).await?;
    for ttl in [0u32, u32::MAX] {
        let minted = mint(
            &ctx,
            &owner,
            &repo,
            &IssueObjectUrlRequest {
                target: Some(Target::ObjectId(A.to_vec())),
                ttl_seconds: Some(ttl),
                ..Default::default()
            },
        )
        .await?;
        let expires = minted
            .expires_unix_ms
            .ok_or_else(|| Failure::Fail("IssueObjectUrl omitted expires_unix_ms".into()))?;
        let ttl_ms = i64::try_from(URL_TOKEN_TTL_MS).unwrap_or(i64::MAX);
        let span = expires - now_ms();
        ensure!(
            span <= ttl_ms && span > ttl_ms - 60_000,
            "ttl {ttl}: expiry - now = {span} ms, want ≈ {ttl_ms}"
        );
    }
    Ok(())
}
