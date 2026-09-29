//! M2 owner-signed write grants over real Connect requests.

use buffa::Message;
use k256::ecdsa::SigningKey as K1Key;
use mkit_attest::eth;
use mkit_attest::grant::{
    Capabilities, Grant, Namespace, OwnerScheme, RefScopes, RepoScope, RepositoryIdentity,
    SignedHeader, WebAuthnAssertion, webauthn_challenge,
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
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256Key};
use sha2::{Digest, Sha256};

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

/// Fixed secp256k1 owner seed. It owns a real `0x` namespace: never
/// allowlist it on a shared or staging deployment.
const K1_SEED: [u8; 32] = [0x21; 32];
/// Fixed P-256 owner seed. It owns a real `0x` namespace: never allowlist
/// it on a shared or staging deployment.
const P256_SEED: [u8; 32] = [0x31; 32];

pub(super) enum Owner {
    Ed(Signer),
    K1(K1Key),
    Web(P256Key),
}

impl Owner {
    pub(super) fn namespace(&self) -> Namespace {
        match self {
            Self::Ed(signer) => {
                Namespace::Ed25519(from_hex(&signer.public_key_hex()).expect("valid grant fixture"))
            }
            Self::K1(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                Namespace::Address(
                    eth::address_secp256k1(
                        &point.as_bytes()[1..]
                            .try_into()
                            .expect("valid grant fixture"),
                    )
                    .expect("valid grant fixture"),
                )
            }
            Self::Web(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                Namespace::Address(
                    eth::address_p256(
                        &point.as_bytes()[1..]
                            .try_into()
                            .expect("valid grant fixture"),
                    )
                    .expect("valid grant fixture"),
                )
            }
        }
    }

    pub(super) fn signed_header(&self, grant: &Grant) -> String {
        let statement = grant.encode().expect("valid grant fixture");
        self.signed_statement(&statement)
    }

    pub(super) fn signed_statement(&self, statement: &[u8]) -> String {
        let (scheme, blob) = match self {
            Self::Ed(signer) => (
                OwnerScheme::Ed25519,
                signer.sign_grant_statement(statement).to_vec(),
            ),
            Self::K1(key) => {
                let (signature, recovery) =
                    key.sign_prehash_recoverable(&eth::eip191_hash(statement));
                let mut blob = signature.to_bytes().to_vec();
                blob.push(27 + recovery.to_byte());
                (OwnerScheme::Secp256k1Eip191, blob)
            }
            Self::Web(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                let public_key: [u8; 64] = point.as_bytes()[1..]
                    .try_into()
                    .expect("valid grant fixture");
                let mut authenticator_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
                authenticator_data.push(1); // user present
                authenticator_data.extend_from_slice(&0u32.to_be_bytes());
                let client_data_json = format!(
                    r#"{{"type":"webauthn.get","challenge":"{}","origin":"{RP_ORIGIN}","crossOrigin":false}}"#,
                    webauthn_challenge(statement),
                ).into_bytes();
                let signed = [
                    authenticator_data.as_slice(),
                    Sha256::digest(&client_data_json).as_slice(),
                ]
                .concat();
                let signature: P256Signature = key.sign(&signed);
                let assertion = WebAuthnAssertion {
                    public_key,
                    authenticator_data,
                    client_data_json,
                    signature: signature.normalize_s().to_bytes().into(),
                };
                (
                    OwnerScheme::WebAuthnP256,
                    assertion.encode().expect("valid grant fixture"),
                )
            }
        };
        SignedHeader {
            statement: statement.to_vec(),
            scheme,
            blob,
        }
        .encode()
        .expect("valid grant fixture")
    }
}

pub(super) fn k1_owner() -> Owner {
    Owner::K1(K1Key::from_slice(&K1_SEED).expect("valid grant fixture"))
}
pub(super) fn web_owner() -> Owner {
    Owner::Web(P256Key::from_slice(&P256_SEED).expect("valid grant fixture"))
}

/// Fixed `0x` namespaces the in-process allowlist must admit for grant cases.
///
/// Their keys are public test seeds: never allowlist these namespaces on a
/// shared or staging deployment.
#[must_use]
pub fn owner_namespaces() -> [Namespace; 2] {
    [k1_owner().namespace(), web_owner().namespace()]
}

pub(super) fn ed_owner(ctx: &Ctx) -> Result<Owner, Failure> {
    Ok(Owner::Ed(ctx.v2_signer("repository-a")?))
}

pub(super) fn repo(ctx: &Ctx, owner: &Owner) -> String {
    format!(
        "{}/{}-{}",
        owner.namespace(),
        ctx.profile().run_id,
        ctx.case.replace('.', "-")
    )
}

pub(super) fn grant(ctx: &Ctx, owner: &Owner, repo: &str, grantee: &Signer) -> Grant {
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

/// [`grant`] at the owner's stored epoch, for the fixed `0x` owners whose
/// epoch the epoch cases advance (SPEC-WRITE-GRANTS §8.2).
pub(super) async fn grant_at_epoch(
    ctx: &Ctx,
    owner: &Owner,
    repo: &str,
    grantee: &Signer,
) -> Result<Grant, Failure> {
    let mut statement = grant(ctx, owner, repo, grantee);
    statement.epoch = super::epochs::current(ctx, owner).await?;
    Ok(statement)
}

pub(super) fn signed_update(
    ctx: &Ctx,
    grantee: &Signer,
    repo: &str,
    header: Option<&str>,
) -> Signed {
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
    let header = owner.signed_header(&grant_at_epoch(&ctx, &owner, &repo, &grantee).await?);
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

pub(super) async fn valid_secp256k1_eip191(ctx: Ctx) -> CaseResult {
    valid(ctx, k1_owner()).await
}

pub(super) async fn valid_webauthn_p256(ctx: Ctx) -> CaseResult {
    valid(ctx, web_owner()).await
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

pub(super) async fn zero_x_without_grant_denied(ctx: Ctx) -> CaseResult {
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &k1_owner());
    let signed = signed_update(&ctx, &grantee, &repo, None);
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "0x without grant",
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

pub(super) async fn ed25519_scheme_on_0x_denied(ctx: Ctx) -> CaseResult {
    let owner = k1_owner();
    let ed_signer = ctx.v2_signer("repository-a")?;
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let statement = grant_at_epoch(&ctx, &owner, &repo, &grantee)
        .await?
        .encode()
        .expect("valid grant fixture");
    let header = SignedHeader {
        statement: statement.clone(),
        scheme: OwnerScheme::Ed25519,
        blob: ed_signer.sign_grant_statement(&statement).to_vec(),
    }
    .encode()
    .expect("valid grant fixture");
    let signed = signed_update(&ctx, &grantee, &repo, Some(&header));
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "Ed25519 on 0x",
    )?;
    Ok(())
}

pub(super) async fn webauthn_unconfigured_rp_denied(ctx: Ctx) -> CaseResult {
    let owner = web_owner();
    let grantee = ctx.v2_signer("grant-grantee")?;
    let repo = repo(&ctx, &owner);
    let statement = grant_at_epoch(&ctx, &owner, &repo, &grantee).await?;
    let mut signed_header =
        SignedHeader::parse(&owner.signed_header(&statement)).expect("valid grant fixture");
    let mut assertion = WebAuthnAssertion::parse(&signed_header.blob).expect("valid grant fixture");
    assertion.authenticator_data[..32].copy_from_slice(&Sha256::digest(b"other.example.test"));
    signed_header.blob = assertion.encode().expect("valid grant fixture");
    let signed = signed_update(
        &ctx,
        &grantee,
        &repo,
        Some(&signed_header.encode().expect("valid grant fixture")),
    );
    want_code(
        ctx.send::<UpdateRefResponse>(&signed).await?,
        "permission_denied",
        "unconfigured relying party",
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
    if ctx.profile().sharding_d34 {
        want_code(result, "unimplemented", "D34 listing after epoch bump")?;
    } else {
        want_ok(result, "test epoch bump")?;
    }
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
    let Owner::Ed(owner_signer) = &owner else {
        unreachable!()
    };
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
