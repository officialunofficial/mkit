//! Bearer and auth v2 authentication (SPEC-TRANSPORT-CONNECT §5, §7.1).
//! Every rejection leaves the server unchanged.

use buffa::Message as _;
use mkit_core::hash::{hash, to_hex};
use mkit_core::write_auth::MAX_VALIDITY_MS;
use mkit_transport_connect::generated::{
    ListRefsRequest, ListRefsResponse, UpdateRefResponse, UploadPackResponse,
};

use super::{
    A, CaseResult, Ctx, Exp, Failure, ensure, random_pack, update_req, upload_msgs, want_code,
    want_ok,
};
use crate::wire::client::{Rpc, RpcError, UNARY_PROTO, decode_unary, frames};
use crate::wire::sign::{Envelope, SignedOp, Signer, body_commitment, now_ms, pack_commitment};

const UNAUTH: &str = "unauthenticated";

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

/// `UpdateRef(<ns>/main, ANY, A)` as exact bytes.
fn update_body(ctx: &Ctx) -> Vec<u8> {
    update_req(&ctx.head("main"), Exp::Any, &A).encode_to_vec()
}

async fn send_update(
    ctx: &Ctx,
    body: Vec<u8>,
    headers: &[(String, String)],
) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    ctx.client().unary(Rpc::UpdateRef, body, headers).await
}

/// An `UpdateRef` with `headers` must be `unauthenticated` and change
/// nothing.
async fn rejected_update(
    ctx: &Ctx,
    body: Vec<u8>,
    headers: &[(String, String)],
    what: &str,
) -> CaseResult {
    want_code(send_update(ctx, body, headers).await?, UNAUTH, what)?;
    ctx.expect_ref(&ctx.head("main"), None).await
}

/// An upload of a fresh pack with `headers` must be `unauthenticated`, and
/// the pack must not be stored.
async fn rejected_upload(
    ctx: &Ctx,
    pack: &[u8],
    headers: &[(String, String)],
    what: &str,
) -> CaseResult {
    let got = ctx.upload_with(&upload_msgs(pack, 2), headers).await?;
    let code = got.as_ref().map(|e| e.code.as_str());
    ensure!(
        code == Some(UNAUTH),
        "{what}: expected {UNAUTH}, got {code:?}"
    );
    ctx.expect_exists(&hash(pack), false).await
}

// ------------------------------------------------------------- bearer

async fn bearer_rejections(ctx: &Ctx, auth: &[(String, String)], what: &str) -> CaseResult {
    let list = ListRefsRequest::default().encode_to_vec();
    let got: Result<ListRefsResponse, _> = ctx.client().unary(Rpc::ListRefs, list, auth).await?;
    want_code(got, UNAUTH, &format!("ListRefs {what}"))?;
    let got = send_update(ctx, update_body(ctx), auth).await?;
    want_code(got, UNAUTH, &format!("UpdateRef {what}"))?;
    // Read back with the right token.
    ctx.expect_ref(&ctx.head("main"), None).await
}

pub(super) async fn bearer_missing(ctx: Ctx) -> CaseResult {
    bearer_rejections(&ctx, &[], "without a token").await
}

pub(super) async fn bearer_wrong(ctx: Ctx) -> CaseResult {
    let crate::wire::profile::WireAuth::Bearer { token } = &ctx.profile().auth else {
        return Err(Failure::Skip("needs a bearer profile".to_owned()));
    };
    let wrong = [
        "Bearer conformance-wrong-token".to_owned(),
        format!("Bearer {token}x"),
        format!("Basic {token}"),
        format!("Bearer{token}"),
    ];
    for value in wrong {
        bearer_rejections(
            &ctx,
            &headers(&[("authorization", &value)]),
            "with a wrong token",
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn bearer_streaming(ctx: Ctx) -> CaseResult {
    let id = hash(&random_pack(32));
    let req = mkit_transport_connect::generated::DownloadPackRequest {
        pack_id: Some(id.to_vec()),
        ..Default::default()
    };
    let body = crate::wire::client::frame(&req.encode_to_vec());
    let reply = ctx
        .client()
        .stream::<mkit_transport_connect::generated::DownloadPackResponse>(
            Rpc::DownloadPack,
            body,
            &[],
        )
        .await?;
    let code = reply.error.map(|e| e.code);
    ensure!(
        reply.messages.is_empty() && code.as_deref() == Some(UNAUTH),
        "DownloadPack without a token: {code:?}"
    );
    rejected_upload(&ctx, &random_pack(100), &[], "UploadPack without a token").await?;
    // With the token the same download passes authentication.
    let reply = ctx.download(&id).await?;
    let code = reply.error.map(|e| e.code);
    ensure!(
        code.as_deref() == Some("not_found"),
        "DownloadPack with the token: {code:?}"
    );
    Ok(())
}

// ------------------------------------------------------------ auth v2

fn update_proc() -> &'static str {
    Rpc::UpdateRef.procedure()
}

/// A valid envelope over `body` for `UpdateRef`.
fn body_envelope(signer: &Signer, body: &[u8]) -> Envelope {
    let mut env = signer.envelope(update_proc(), body_commitment(body));
    env.digest = Some(to_hex(&hash(body)));
    env
}

pub(super) async fn v2_missing_headers(ctx: Ctx) -> CaseResult {
    rejected_update(&ctx, update_body(&ctx), &[], "unsigned UpdateRef").await?;
    let req = super::advance_req(
        (&ctx.head("main"), Exp::Any, &A),
        (&ctx.packmap("main"), Exp::Any, &A),
    );
    let got: Result<mkit_transport_connect::generated::AdvanceRefsResponse, _> = ctx
        .client()
        .unary(Rpc::AdvanceRefs, req.encode_to_vec(), &[])
        .await?;
    want_code(got, UNAUTH, "unsigned AdvanceRefs")?;
    ctx.expect_ref(&ctx.packmap("main"), None).await?;
    rejected_upload(&ctx, &random_pack(100), &[], "unsigned UploadPack").await?;
    // Every required header matters: drop each in turn.
    let signer = ctx.v2_signer("main")?;
    let body = update_body(&ctx);
    let op = signer.sign(&body_envelope(&signer, &body));
    for (name, _) in &op.headers {
        let mut partial = op.headers.clone();
        partial.retain(|(n, _)| n != name);
        rejected_update(
            &ctx,
            body.clone(),
            &partial,
            &format!("UpdateRef without {name}"),
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn v2_wrong_audience(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let body = update_body(&ctx);
    let mut env = body_envelope(&signer, &body);
    "https://conformance.invalid".clone_into(&mut env.audience);
    rejected_update(
        &ctx,
        body.clone(),
        &signer.sign(&env).headers,
        "signed for another audience",
    )
    .await?;
    // Signed for the right audience, sent with another.
    let op = signer
        .sign(&body_envelope(&signer, &body))
        .with_header("x-audience", "https://conformance.invalid");
    rejected_update(&ctx, body, &op.headers, "x-audience rewritten").await
}

pub(super) async fn v2_wrong_repository(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let body = update_body(&ctx);
    let mut env = body_envelope(&signer, &body);
    "conformance-wrong-repository".clone_into(&mut env.repository);
    rejected_update(
        &ctx,
        body.clone(),
        &signer.sign(&env).headers,
        "signed for another repository",
    )
    .await?;
    let op = signer
        .sign(&body_envelope(&signer, &body))
        .with_header("x-repository", "conformance-wrong-repository");
    rejected_update(&ctx, body, &op.headers, "x-repository rewritten").await
}

pub(super) async fn v2_wrong_procedure(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let body = update_body(&ctx);
    let mut env = body_envelope(&signer, &body);
    Rpc::AdvanceRefs.procedure().clone_into(&mut env.procedure);
    rejected_update(
        &ctx,
        body,
        &signer.sign(&env).headers,
        "signed for AdvanceRefs",
    )
    .await
}

pub(super) async fn v2_bad_signature(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let other = ctx.v2_signer("other")?;
    let body = update_body(&ctx);
    let op = signer.sign(&body_envelope(&signer, &body));
    let flipped = flip_hex(header(&op, "x-signature"));
    let tampered = op.clone().with_header("x-signature", flipped);
    rejected_update(
        &ctx,
        body.clone(),
        &tampered.headers,
        "a flipped signature bit",
    )
    .await?;
    // A valid signature by one key, presented under another key.
    let swapped = op.with_header("x-public-key", other.public_key_hex());
    rejected_update(&ctx, body, &swapped.headers, "another signer's public key").await
}

fn header<'a>(op: &'a SignedOp, name: &str) -> &'a str {
    op.headers
        .iter()
        .find(|(n, _)| n == name)
        .map_or("", |(_, v)| v)
}

/// `hex` with its last character changed (still hex).
fn flip_hex(hex: &str) -> String {
    let mut out = hex.to_owned();
    let last = out.pop().unwrap_or('0');
    out.push(if last == '0' { '1' } else { '0' });
    out
}

pub(super) async fn v2_body_digest_mismatch(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let body = update_body(&ctx);
    let op = signer.sign_body(update_proc(), &body);
    // The signed body, then a different body under the same signature.
    let other = update_req(&ctx.head("main"), Exp::Any, &[0xab; 32]).encode_to_vec();
    rejected_update(&ctx, other, &op.headers, "a body other than the signed one").await?;
    // X-Digest that disagrees with the signed commitment.
    let wrong_digest = op.with_header("x-digest", to_hex(&hash(b"other")));
    rejected_update(
        &ctx,
        body,
        &wrong_digest.headers,
        "X-Digest differs from the commitment",
    )
    .await
}

pub(super) async fn v2_expired(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let body = update_body(&ctx);
    let now = now_ms();
    let windows = [
        ("expired", now - 400_000, now - 100_000),
        ("created in the future", now + 120_000, now + 180_000),
        (
            "a validity window over 300 s",
            now - 1_000,
            now - 1_000 + MAX_VALIDITY_MS + 1,
        ),
        ("expiry before creation", now, now - 1),
    ];
    for (what, created_at, expires_at) in windows {
        let mut env = body_envelope(&signer, &body);
        env.created_at = created_at;
        env.expires_at = expires_at;
        rejected_update(&ctx, body.clone(), &signer.sign(&env).headers, what).await?;
    }
    Ok(())
}

pub(super) async fn v2_version_not_2(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let body = update_body(&ctx);
    for version in [Some("1"), Some("3"), Some(""), None] {
        let mut env = body_envelope(&signer, &body);
        env.version = version.map(str::to_owned);
        let what = format!("X-Envelope-Version {version:?}");
        rejected_update(&ctx, body.clone(), &signer.sign(&env).headers, &what).await?;
    }
    Ok(())
}

pub(super) async fn v2_pack_commitment_mismatch(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let pack = random_pack(100);
    let id = hash(&pack);
    let proc = Rpc::UploadPack.procedure();
    let wrong = [
        ("a longer declared length", pack_commitment(&id, 101)),
        ("another pack id", pack_commitment(&[7; 32], 100)),
        ("a body commitment", body_commitment(b"")),
    ];
    for (what, commitment) in wrong {
        let op = signer.sign(&signer.envelope(proc, commitment));
        rejected_upload(&ctx, &pack, &op.headers, what).await?;
    }
    Ok(())
}

/// Deflate `data` into one gzip member.
fn gzip(data: &[u8]) -> Result<Vec<u8>, Failure> {
    use std::io::Write as _;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).map_err(|e| format!("gzip: {e}"))?;
    Ok(enc.finish().map_err(|e| format!("gzip: {e}"))?)
}

/// A signature over the compressed body bytes, sent with
/// `Content-Encoding: gzip`, fails closed: rejected, nothing written.
/// SPEC-WRITE-GRANTS §9.2 has yet to say whether the commitment covers the
/// encoded or the decoded bytes, so any error code passes.
pub(super) async fn v2_gzip_signed_fails_closed(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let body = gzip(&update_body(&ctx))?;
    let mut headers = signer.sign_body(update_proc(), &body).headers;
    headers.push(("content-encoding".to_owned(), "gzip".to_owned()));
    let reply = ctx
        .client()
        .post(update_proc(), UNARY_PROTO, &headers, body)
        .await?;
    let got = decode_unary::<UpdateRefResponse>(&reply)?;
    ensure!(got.is_err(), "a signed gzip request was accepted");
    ctx.expect_ref(&ctx.head("main"), None).await
}

/// Reads stay unsigned in M0 (signed reads are M2).
pub(super) async fn v2_reads_unsigned_ok(ctx: Ctx) -> CaseResult {
    let ns = format!("{}/", ctx.head("dir"));
    let list = ListRefsRequest {
        prefix: Some(ns),
        ..Default::default()
    };
    let got: Result<ListRefsResponse, _> = ctx
        .client()
        .unary(Rpc::ListRefs, list.encode_to_vec(), &[])
        .await?;
    want_ok(got, "unsigned ListRefs")?;
    ctx.expect_ref(&ctx.head("main"), None).await?;
    let id = hash(&random_pack(32));
    ctx.expect_exists(&id, false).await?;
    let reply = ctx.download(&id).await?;
    let code = reply.error.map(|e| e.code);
    ensure!(
        code.as_deref() == Some("not_found"),
        "unsigned DownloadPack: {code:?}"
    );
    // A signed upload of a fresh pack, then the unsigned download of it.
    let pack = random_pack(200);
    let msgs = upload_msgs(&pack, 2);
    let op = signer_pack(&ctx, &pack)?;
    let reply = ctx
        .client()
        .stream::<UploadPackResponse>(Rpc::UploadPack, frames(&msgs), &op.headers)
        .await?;
    ensure!(
        reply.error.is_none(),
        "signed UploadPack: {:?}",
        reply.error
    );
    let got = ctx.fetch(&hash(&pack)).await?;
    ensure!(got == pack, "unsigned download returned other bytes");
    Ok(())
}

fn signer_pack(ctx: &Ctx, pack: &[u8]) -> Result<SignedOp, Failure> {
    let signer = ctx.v2_signer("main")?;
    Ok(signer.sign_pack(Rpc::UploadPack.procedure(), &hash(pack), pack.len() as u64))
}
