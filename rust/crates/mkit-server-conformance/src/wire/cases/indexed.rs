//! Indexed-mode responses over the real Connect wire.

use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::object::{Commit, Identity, Object, Tree};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result as BeginResult;
use mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body as UploadBody;
use mkit_transport_connect::generated::{
    AdvanceOutcome, AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse,
};

use super::{
    CaseResult, Commit as WireCommit, Ctx, Exp, Failure, Feature, advance_req, ensure,
    eventually_listed, sign_unary, upload_msgs, want_ok, want_outcome,
};
use crate::wire::client::{Rpc, UNARY_PROTO, decode_unary};
use crate::wire::profile::WireAuth;
use crate::wire::sign::pack_commitment;

fn pack() -> Result<(Vec<u8>, Hash), Failure> {
    let tree = Object::Tree(Tree {
        entries: Vec::new(),
    });
    let tree_id = tree.id().map_err(|e| format!("tree id: {e}"))?;
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"indexed wire".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer)
        .map_err(|e| format!("sign commit: {e}"))?
        .0;
    let commit = Object::Commit(commit);
    let head = commit.id().map_err(|e| format!("commit id: {e}"))?;
    let mut writer = PackWriter::new_raw_only();
    writer
        .push_raw(
            tree_id,
            &serialize(&tree).map_err(|e| format!("tree bytes: {e}"))?,
        )
        .map_err(|e| format!("tree frame: {e}"))?;
    writer
        .push_raw(
            head,
            &serialize(&commit).map_err(|e| format!("commit bytes: {e}"))?,
        )
        .map_err(|e| format!("commit frame: {e}"))?;
    Ok((writer.finish().map_err(|e| format!("pack: {e}"))?, head))
}

pub(super) async fn pending_verification_unavailable(ctx: Ctx) -> CaseResult {
    let (pack, head) = pack()?;
    let pack_id = hash(&pack);
    let branch = ctx.head("pending");
    let opened: BeginUploadResponse = want_ok(
        ctx.call(
            Rpc::BeginUpload,
            &BeginUploadRequest {
                r#ref: Some(branch.clone()),
                pack_id: Some(pack_id.to_vec()),
                bytes: Some(pack.len() as u64),
                ..Default::default()
            },
        )
        .await?,
        "BeginUpload",
    )?;
    let Some(BeginResult::Ticket(ticket)) = opened.result else {
        return Err(Failure::Fail("BeginUpload did not issue a ticket".into()));
    };
    let id = ticket.id.ok_or("ticket has no id")?;
    let mut messages = upload_msgs(&pack, 2);
    if let Some(UploadBody::Header(header)) = &mut messages[0].body {
        header.ticket_token = ticket.token;
    }
    let headers = ctx.auth_headers(
        Rpc::UploadPack,
        WireCommit::Pack(&pack_id, pack.len() as u64),
    );
    ensure!(
        ctx.upload_with(&messages, &headers).await?.is_none(),
        "ticketed UploadPack failed"
    );

    let mut request = advance_req(
        (&branch, Exp::Missing, &head),
        (&ctx.packmap("pending"), Exp::Missing, &pack_id),
    );
    request.ticket_ids = vec![id];
    let signed = sign_unary(&ctx.v2_signer("main")?, Rpc::AdvanceRefs, &request, |_| {})
        .with_header("x-mkit-test-fault", "indexed-pending");
    let reply = ctx
        .client()
        .post(
            Rpc::AdvanceRefs.procedure(),
            UNARY_PROTO,
            &signed.headers,
            signed.body.clone(),
        )
        .await?;
    ensure!(reply.status == 503, "pending HTTP status {}", reply.status);
    ensure!(
        reply
            .headers
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            == Some("5"),
        "pending Retry-After is not 5"
    );
    let Err(error) = decode_unary::<AdvanceRefsResponse>(&reply)? else {
        return Err(Failure::Fail(
            "pending advance unexpectedly committed".into(),
        ));
    };
    ensure!(error.code == "unavailable", "pending code {}", error.code);
    ensure!(
        error.message == "pack verification pending",
        "pending message {:?}",
        error.message
    );
    ensure!(
        error.details
            == [(
                "mkit.transport.v1.PendingVerification".into(),
                "CIgn".into()
            )],
        "pending details {:?}",
        error.details
    );

    // Reuse the signed nonce. A saved replay error would answer Pending again.
    let retry = signed.with_header("x-mkit-test-fault", "");
    want_outcome(
        ctx.send::<AdvanceRefsResponse>(&retry)
            .await?
            .map(|response| response.outcome.map_or(0, |outcome| outcome.to_i32())),
        AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
    )?;
    Ok(())
}

/// A pack of more than two 16 MiB windows: 720 blobs just under the 64 KiB
/// extraction size, a tree naming them and a signed commit.
fn large_pack() -> Result<(Vec<u8>, Hash), Failure> {
    verification_pack(None)
}

fn verification_pack(extracted: Option<&[u8]>) -> Result<(Vec<u8>, Hash), Failure> {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    for n in 0..720_u32 {
        let data: Vec<u8> = (0..50_000_u32)
            .map(|i| {
                u8::try_from((i.wrapping_mul(31) ^ n.wrapping_mul(2_654_435_761)) & 0xff)
                    .unwrap_or(0)
            })
            .collect();
        let blob = Object::Blob(mkit_core::object::Blob { data });
        let id = blob.id().map_err(|e| format!("blob id: {e}"))?;
        writer
            .push_raw(
                id,
                &serialize(&blob).map_err(|e| format!("blob bytes: {e}"))?,
            )
            .map_err(|e| format!("blob frame: {e}"))?;
        entries.push(mkit_core::object::TreeEntry {
            name: format!("f{n:04}").into_bytes(),
            mode: mkit_core::object::EntryMode::Blob,
            object_hash: id,
        });
    }
    if let Some(data) = extracted {
        let blob = Object::Blob(mkit_core::object::Blob {
            data: data.to_vec(),
        });
        let id = blob.id().map_err(|e| format!("extracted blob id: {e}"))?;
        writer
            .push_raw(
                id,
                &serialize(&blob).map_err(|e| format!("extracted blob bytes: {e}"))?,
            )
            .map_err(|e| format!("extracted blob frame: {e}"))?;
        entries.push(mkit_core::object::TreeEntry {
            name: b"extracted.txt".to_vec(),
            mode: mkit_core::object::EntryMode::Blob,
            object_hash: id,
        });
        entries.sort_by(|a, b| a.name.cmp(&b.name));
    }
    let tree = Object::Tree(Tree { entries });
    let tree_id = tree.id().map_err(|e| format!("tree id: {e}"))?;
    let signer = KeyPair::from_seed([9; 32]);
    let mut commit = Commit::new_unannotated(
        tree_id,
        Vec::new(),
        Identity::ed25519(signer.public.0),
        signer.public.0,
        b"indexed async wire".to_vec(),
        42,
        [0; 64],
    );
    commit.signature = sign_commit(&commit, &signer)
        .map_err(|e| format!("sign commit: {e}"))?
        .0;
    let commit = Object::Commit(commit);
    let head = commit.id().map_err(|e| format!("commit id: {e}"))?;
    writer
        .push_raw(
            tree_id,
            &serialize(&tree).map_err(|e| format!("tree bytes: {e}"))?,
        )
        .map_err(|e| format!("tree frame: {e}"))?;
    writer
        .push_raw(
            head,
            &serialize(&commit).map_err(|e| format!("commit bytes: {e}"))?,
        )
        .map_err(|e| format!("commit frame: {e}"))?;
    Ok((writer.finish().map_err(|e| format!("pack: {e}"))?, head))
}

/// The scheduled verifier end to end: `AdvanceRefs` answers pending while the
/// alarm's slices verify a pack of three windows (the Worker fails the second
/// slice mid-pack, and the job resumes from the first slice's checkpoint), and
/// the same signed request then commits.
pub(super) async fn async_verification_commits(ctx: Ctx) -> CaseResult {
    let (pack, head) = large_pack()?;
    commit_large_pack(&ctx, &pack, head).await?;
    Ok(())
}

async fn commit_large_pack(ctx: &Ctx, pack: &[u8], head: Hash) -> Result<(String, u32), Failure> {
    ensure!(
        pack.len() > 33 << 20,
        "suite bug: the pack fits two windows"
    );
    let (repository, _) = super::repository::identities(ctx, "async-verify", "unused")?;
    let signer = ctx.v2_signer("repository-a")?;
    let pack_id = hash(pack);
    let branch = ctx.head("async");
    let begin = BeginUploadRequest {
        r#ref: Some(branch.clone()),
        pack_id: Some(pack_id.to_vec()),
        bytes: Some(pack.len() as u64),
        ..Default::default()
    };
    let signed_begin = sign_unary(&signer, Rpc::BeginUpload, &begin, |env| {
        repository.clone_into(&mut env.repository);
    });
    let opened: BeginUploadResponse = want_ok(ctx.send(&signed_begin).await?, "BeginUpload")?;
    let Some(BeginResult::Ticket(ticket)) = opened.result else {
        return Err(Failure::Fail("BeginUpload did not issue a ticket".into()));
    };
    let id = ticket.id.ok_or("ticket has no id")?;
    let mut messages = upload_msgs(pack, 48);
    if let Some(UploadBody::Header(header)) = &mut messages[0].body {
        header.ticket_token = ticket.token;
    }
    let mut envelope = signer.envelope(
        Rpc::UploadPack.procedure(),
        pack_commitment(&pack_id, pack.len() as u64),
    );
    repository.clone_into(&mut envelope.repository);
    let headers = signer.sign(&envelope).headers;
    ensure!(
        ctx.upload_with(&messages, &headers).await?.is_none(),
        "ticketed UploadPack failed"
    );

    let mut request = advance_req(
        (&branch, Exp::Missing, &head),
        (&ctx.packmap("async"), Exp::Missing, &pack_id),
    );
    request.ticket_ids = vec![id];
    let advance = sign_unary(&signer, Rpc::AdvanceRefs, &request, |env| {
        repository.clone_into(&mut env.repository);
    });
    let mut pending = 0;
    for _ in 0..240 {
        match ctx.send::<AdvanceRefsResponse>(&advance).await? {
            Ok(response) => {
                ensure!(
                    pending > 0,
                    "the first advance committed before any slice ran"
                );
                want_outcome(
                    Ok(response.outcome.map_or(0, |outcome| outcome.to_i32())),
                    AdvanceOutcome::ADVANCE_OUTCOME_COMMITTED,
                )?;
                return Ok((repository, pending));
            }
            Err(error) => {
                ensure!(
                    error.code == "unavailable" && error.message == "pack verification pending",
                    "advance answered {error}, not a pending verification"
                );
                ensure!(
                    error.details.len() == 1,
                    "pending details {:?}",
                    error.details
                );
                pending += 1;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
    Err(Failure::Fail(format!(
        "the advance was still pending after {pending} polls"
    )))
}

/// The production-only intersection: no test directives, ticketed upload,
/// scheduled verification/extraction, public paired refs and exact pack bytes.
/// The HTTP opt-in additionally proves the extracted bytes and proof refusal.
pub(super) async fn launch_verification_commits(ctx: Ctx) -> CaseResult {
    let data: Vec<_> = (0..131_072_u32)
        .map(|i| u8::try_from((i.wrapping_mul(17) ^ (i >> 9)) & 0xff).unwrap_or(0))
        .collect();
    let extracted = Object::Blob(mkit_core::object::Blob { data: data.clone() })
        .id()
        .map_err(|e| format!("extracted id: {e}"))?;
    let (pack, head) = verification_pack(Some(&data))?;
    let pack_id = hash(&pack);
    let (repository, pending) = commit_large_pack(&ctx, &pack, head).await?;
    super::visibility::set_envelope(&ctx, &ctx.v2_signer("repository-a")?, &repository, false)
        .await?;

    let mut profile = ctx.profile().clone();
    if let WireAuth::AuthV2 {
        repository: selected,
        ..
    } = &mut profile.auth
    {
        repository.clone_into(selected);
    }
    let reader = Ctx::new(ctx.client().clone(), std::sync::Arc::new(profile), ctx.case);
    eventually_listed(
        "published head and packmap",
        || async {
            Ok((
                reader.read(&reader.head("async")).await?,
                reader.read(&reader.packmap("async")).await?,
            ))
        },
        |pair| {
            pair.0.as_deref() == Some(head.as_slice())
                && pair.1.as_deref() == Some(pack_id.as_slice())
        },
    )
    .await?;
    ensure!(
        reader.fetch(&pack_id).await? == pack,
        "public DownloadPack bytes differ"
    );
    if ctx.profile().has(Feature::HttpObjects) {
        check_extracted_http(&ctx, &repository, &extracted, &data).await?;
    }
    ctx.set_note(format!(
        "pack_bytes={} pending_polls={pending} extracted_blob={} extracted_blob_bytes={} http={}",
        pack.len(),
        to_hex(&extracted),
        data.len(),
        ctx.profile().has(Feature::HttpObjects)
    ));
    Ok(())
}

async fn check_extracted_http(
    ctx: &Ctx,
    repository: &str,
    extracted: &Hash,
    data: &[u8],
) -> CaseResult {
    let object = format!("/{repository}/-/objects/{}", to_hex(extracted));
    let reply = ctx.client().get(&object).await?;
    ensure!(
        reply.status == 200,
        "extracted object HTTP {}: {:?}",
        reply.status,
        reply.body
    );
    ensure!(reply.body.as_ref() == data, "extracted object bytes differ");
    ensure!(
        reply
            .headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            == Some("application/octet-stream"),
        "object-id media type differs"
    );
    let file = format!("/{repository}/-/{}/-/extracted.txt", ctx.head("async"));
    let reply = ctx.client().get(&file).await?;
    ensure!(
        reply.status == 200 && reply.body.as_ref() == data,
        "published ref file bytes differ: HTTP {}",
        reply.status
    );
    ensure!(
        reply
            .headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            == Some("text/plain; charset=utf-8"),
        "ref-file media type ignores extension"
    );
    ensure!(
        reply
            .headers
            .get("content-disposition")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| h.starts_with("inline;") && h.contains("extracted.txt")),
        "ref-file filename/disposition missing"
    );
    ensure!(
        reply
            .headers
            .get("x-content-type-options")
            .and_then(|h| h.to_str().ok())
            == Some("nosniff"),
        "ref-file nosniff missing"
    );
    ensure!(
        reply
            .headers
            .get("content-security-policy")
            .and_then(|h| h.to_str().ok())
            == Some("sandbox; default-src 'none'"),
        "ref-file sandbox CSP missing"
    );
    let proof = ctx.client().get(&format!("{file}?proof=1")).await?;
    ensure!(
        proof.status == 416,
        "release Worker proof request HTTP {}, expected unsupported 416",
        proof.status
    );
    Ok(())
}
