//! Bearer and auth v2 authentication (SPEC-TRANSPORT-CONNECT §5, §7.1).
//! Every rejection leaves the server unchanged.

use buffa::Message as _;
use mkit_core::hash::{hash, to_hex};
use mkit_core::write_auth::MAX_VALIDITY_MS;
use mkit_transport_connect::generated::{
    ListRefsRequest, ListRefsResponse, UpdateRefRequest, UpdateRefResponse, UploadPackResponse,
};

use super::{
    A, CaseResult, Ctx, Exp, Failure, Signed, ensure, random_pack, sign_unary, update_req,
    upload_msgs, want_code, want_ok,
};
use crate::wire::client::{Rpc, UNARY_PROTO, decode_unary, frames};
use crate::wire::sign::{Envelope, Signer, body_commitment, now_ms, pack_commitment};

pub(super) const UNAUTH: &str = "unauthenticated";

/// `UpdateRef(<ns>/main, ANY, A)`.
pub(super) fn main_update(ctx: &Ctx) -> UpdateRefRequest {
    update_req(&ctx.head("main"), Exp::Any, &A)
}

/// `main_update` signed by `signer`, after `edit`.
pub(super) fn signed_main(ctx: &Ctx, signer: &Signer, edit: impl FnOnce(&mut Envelope)) -> Signed {
    sign_unary(signer, Rpc::UpdateRef, &main_update(ctx), edit)
}

/// `s` must be `unauthenticated`, and `<ns>/main` still absent.
pub(super) async fn rejected(ctx: &Ctx, s: &Signed, what: &str) -> CaseResult {
    want_code(ctx.send::<UpdateRefResponse>(s).await?, UNAUTH, what)?;
    ctx.expect_ref(&ctx.head("main"), None).await
}

/// `main_update` sent with exactly `headers`, which must be rejected.
async fn rejected_with(ctx: &Ctx, headers: &[(String, String)], what: &str) -> CaseResult {
    let s = Signed {
        rpc: Rpc::UpdateRef,
        body: main_update(ctx).encode_to_vec(),
        headers: headers.to_vec(),
        nonce: String::new(),
    };
    rejected(ctx, &s, what).await
}

/// An upload of a fresh pack with `headers` must fail (with `code`, when
/// one is given), and the pack must not be stored.
async fn rejected_upload(
    ctx: &Ctx,
    pack: &[u8],
    headers: &[(String, String)],
    code: Option<&str>,
    what: &str,
) -> CaseResult {
    let got = ctx.upload_with(&upload_msgs(pack, 2), headers).await?;
    let got = got.as_ref().map(|e| e.code.as_str());
    match code {
        Some(code) => ensure!(got == Some(code), "{what}: expected {code}, got {got:?}"),
        None => ensure!(got.is_some(), "{what}: expected an error, got ok"),
    }
    ctx.expect_exists(&hash(pack), false).await
}

// ------------------------------------------------------------- bearer

async fn bearer_rejections(ctx: &Ctx, auth: &[(String, String)], what: &str) -> CaseResult {
    let list = ListRefsRequest::default().encode_to_vec();
    let got: Result<ListRefsResponse, _> = ctx.client().unary(Rpc::ListRefs, list, auth).await?;
    want_code(got, UNAUTH, &format!("ListRefs {what}"))?;
    // Read back with the right token.
    rejected_with(ctx, auth, &format!("UpdateRef {what}")).await
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
        let auth = [("authorization".to_owned(), value)];
        bearer_rejections(&ctx, &auth, "with a wrong token").await?;
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
    let pack = random_pack(100);
    rejected_upload(&ctx, &pack, &[], Some(UNAUTH), "UploadPack without a token").await?;
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

pub(super) async fn v2_missing_headers(ctx: Ctx) -> CaseResult {
    rejected_with(&ctx, &[], "unsigned UpdateRef").await?;
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
    let pack = random_pack(100);
    rejected_upload(&ctx, &pack, &[], Some(UNAUTH), "unsigned UploadPack").await?;
    // Every required header matters: drop each in turn.
    let op = signed_main(&ctx, &ctx.v2_signer("main")?, |_| {});
    for (name, _) in &op.headers {
        let mut partial = op.clone();
        partial.headers.retain(|(n, _)| n != name);
        rejected(&ctx, &partial, &format!("UpdateRef without {name}")).await?;
    }
    Ok(())
}

pub(super) async fn v2_wrong_audience(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let other = |env: &mut Envelope| "https://conformance.invalid".clone_into(&mut env.audience);
    rejected(
        &ctx,
        &signed_main(&ctx, &signer, other),
        "signed for another audience",
    )
    .await?;
    // Signed for the right audience, sent with another.
    let op =
        signed_main(&ctx, &signer, |_| {}).with_header("x-audience", "https://conformance.invalid");
    rejected(&ctx, &op, "x-audience rewritten").await
}

pub(super) async fn v2_wrong_repository(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let other = |env: &mut Envelope| "conformance-wrong-repository".clone_into(&mut env.repository);
    want_code(
        ctx.send::<UpdateRefResponse>(&signed_main(&ctx, &signer, other))
            .await?,
        "not_found",
        "signed for another repository",
    )?;
    let op = signed_main(&ctx, &signer, |_| {})
        .with_header("x-repository", "conformance-wrong-repository");
    want_code(
        ctx.send::<UpdateRefResponse>(&op).await?,
        "not_found",
        "x-repository rewritten",
    )?;
    ctx.expect_ref(&ctx.head("main"), None).await
}

pub(super) async fn v2_wrong_procedure(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let op = signed_main(&ctx, &signer, |env| {
        Rpc::AdvanceRefs.procedure().clone_into(&mut env.procedure);
    });
    rejected(&ctx, &op, "signed for AdvanceRefs").await
}

pub(super) async fn v2_bad_signature(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let other = ctx.v2_signer("other")?;
    let op = signed_main(&ctx, &signer, |_| {});
    let flipped = flip_hex(op.header("x-signature"));
    let tampered = op.clone().with_header("x-signature", flipped);
    rejected(&ctx, &tampered, "a flipped signature bit").await?;
    // A valid signature by one key, presented under another key.
    let swapped = op.with_header("x-public-key", other.public_key_hex());
    rejected(&ctx, &swapped, "another signer's public key").await
}

/// `hex` with its last character changed (still hex).
fn flip_hex(hex: &str) -> String {
    let mut out = hex.to_owned();
    let last = out.pop().unwrap_or('0');
    out.push(if last == '0' { '1' } else { '0' });
    out
}

pub(super) async fn v2_body_digest_mismatch(ctx: Ctx) -> CaseResult {
    let op = signed_main(&ctx, &ctx.v2_signer("main")?, |_| {});
    // A different body under the signature of the first.
    let other = Signed {
        body: update_req(&ctx.head("main"), Exp::Any, &[0xab; 32]).encode_to_vec(),
        ..op.clone()
    };
    rejected(&ctx, &other, "a body other than the signed one").await?;
    // X-Digest that disagrees with the signed commitment.
    let wrong_digest = op.with_header("x-digest", to_hex(&hash(b"other")));
    rejected(&ctx, &wrong_digest, "X-Digest differs from the commitment").await
}

/// §7.1: the validity interval MUST be positive and at most 300,000 ms;
/// expired requests MUST be rejected. (The 30 s clock lead is
/// `auth.v2_clock_lead_bound`.)
pub(super) async fn v2_expired(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let now = now_ms();
    let windows = [
        ("expired", now - 400_000, now - 100_000),
        (
            "a validity window over 300 s",
            now - 1_000,
            now - 1_000 + MAX_VALIDITY_MS + 1,
        ),
        ("expiry before creation", now, now - 1),
        ("a zero-length window (expiry == creation)", now, now),
    ];
    for (what, created_at, expires_at) in windows {
        let op = signed_main(&ctx, &signer, |env| {
            env.created_at = created_at;
            env.expires_at = expires_at;
        });
        rejected(&ctx, &op, what).await?;
    }
    Ok(())
}

pub(super) async fn v2_version_not_2(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    for version in [Some("1"), Some("3"), Some(""), None] {
        let op = signed_main(&ctx, &signer, |env| {
            env.version = version.map(str::to_owned);
        });
        rejected(&ctx, &op, &format!("X-Envelope-Version {version:?}")).await?;
    }
    Ok(())
}

/// §7.1: the handler MUST compare the `pack:` commitment with the upload
/// header before reading chunks. The spec names no code for a mismatch,
/// so any error passes; the pack must not be stored.
// TODO(spec pass, M1/M2): fix the code (mkit-server sends
// `unauthenticated`, a ticket mismatch `permission_denied`), then assert it.
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
        rejected_upload(&ctx, &pack, &op.headers, None, what).await?;
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

/// Opt-in (`strict-gzip-auth`): a signature over the compressed body bytes,
/// sent with `Content-Encoding: gzip`, fails closed (rejected, nothing
/// written), as mkit-server and vcs-worker do today. SPEC-WRITE-GRANTS §9.2
/// ("exact HTTP request body bytes") leaves open whether `body:` covers the
/// encoded or the decoded bytes; the M2 spec pass (WP-2.6/2.9) decides, so
/// any error code passes.
pub(super) async fn v2_gzip_signed_fails_closed(ctx: Ctx) -> CaseResult {
    let signer = ctx.v2_signer("main")?;
    let body = gzip(&main_update(&ctx).encode_to_vec())?;
    let mut headers = signer.sign_body(Rpc::UpdateRef.procedure(), &body).headers;
    headers.push(("content-encoding".to_owned(), "gzip".to_owned()));
    let reply = ctx
        .client()
        .post(Rpc::UpdateRef.procedure(), UNARY_PROTO, &headers, body)
        .await?;
    let got = decode_unary::<UpdateRefResponse>(&reply)?;
    ensure!(got.is_err(), "a signed gzip request was accepted");
    ctx.expect_ref(&ctx.head("main"), None).await
}

/// Reads stay unsigned in M0 (signed reads are M2).
pub(super) async fn v2_reads_unsigned_ok(ctx: Ctx) -> CaseResult {
    let list = ListRefsRequest {
        prefix: Some(format!("{}/", ctx.head("dir"))),
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
    let signer = ctx.v2_signer("main")?;
    let op = signer.sign_pack(Rpc::UploadPack.procedure(), &hash(&pack), pack.len() as u64);
    let reply = ctx
        .client()
        .stream::<UploadPackResponse>(Rpc::UploadPack, frames(&upload_msgs(&pack, 2)), &op.headers)
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
