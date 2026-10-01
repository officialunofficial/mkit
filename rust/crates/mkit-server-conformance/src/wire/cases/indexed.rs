//! Indexed-mode responses over the real Connect wire.

use buffa::Message as _;
use mkit_core::hash::{Hash, hash, to_hex};
use mkit_core::object::{Commit, Identity, Object, Tree};
use mkit_core::pack::PackWriter;
use mkit_core::serialize::serialize;
use mkit_core::sign::{KeyPair, sign_commit};
use mkit_transport_connect::generated::__buffa::oneof::begin_upload_response::Result as BeginResult;
use mkit_transport_connect::generated::__buffa::oneof::upload_pack_request::Body as UploadBody;
use mkit_transport_connect::generated::{
    AdvanceOutcome, AdvanceRefsResponse, BeginUploadRequest, BeginUploadResponse,
    DownloadPackRequest, DownloadPackResponse, GetServerInfoResponse, ReadRefRequest,
    ReadRefResponse,
};

use super::{
    CaseResult, Commit as WireCommit, Ctx, Exp, Failure, Feature, Signed, advance_req, ensure,
    eventually_listed, sign_unary, upload_msgs, want_ok, want_outcome,
};
use crate::wire::client::{Rpc, UNARY_PROTO, decode_unary, frame};
use crate::wire::sign::pack_commitment;

fn pack() -> Result<(Vec<u8>, Hash), Failure> {
    pack_with_blob(None)
}

fn pack_with_blob(data: Option<&[u8]>) -> Result<(Vec<u8>, Hash), Failure> {
    let mut writer = PackWriter::new_raw_only();
    let mut entries = Vec::new();
    if let Some(data) = data {
        let blob = Object::Blob(mkit_core::object::Blob {
            data: data.to_vec(),
        });
        let id = blob.id().map_err(|e| format!("blob id: {e}"))?;
        writer
            .push_raw(
                id,
                &serialize(&blob).map_err(|e| format!("blob bytes: {e}"))?,
            )
            .map_err(|e| format!("blob frame: {e}"))?;
        entries.push(mkit_core::object::TreeEntry {
            name: b"inspected.txt".to_vec(),
            mode: mkit_core::object::EntryMode::Blob,
            object_hash: id,
        });
    }
    let tree = Object::Tree(Tree { entries });
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
    verification_pack_entries(extracted, 720)
}

fn verification_pack_entries(
    extracted: Option<&[u8]>,
    count: u32,
) -> Result<(Vec<u8>, Hash), Failure> {
    verification_fixture_pack(extracted, count, false)
}

fn verification_fixture_pack(
    extracted: Option<&[u8]>,
    count: u32,
    multipart: bool,
) -> Result<(Vec<u8>, Hash), Failure> {
    let mut writer = PackWriter::new_raw_only();
    if multipart {
        // Surplus canonical objects are verified too; the published tree stays unchanged.
        for byte in 0_u8..17 {
            let surplus = Object::Blob(mkit_core::object::Blob {
                data: vec![byte; 500_000],
            });
            let id = surplus.id().map_err(|e| format!("surplus id: {e}"))?;
            writer
                .push_raw(
                    id,
                    &serialize(&surplus).map_err(|e| format!("surplus bytes: {e}"))?,
                )
                .map_err(|e| format!("surplus frame: {e}"))?;
        }
    }
    let mut entries = Vec::new();
    for n in 0..count {
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
    commit_pack(ctx, pack, head, false).await
}

async fn commit_pack(
    ctx: &Ctx,
    pack: &[u8],
    head: Hash,
    canonical: bool,
) -> Result<(String, u32), Failure> {
    let (repository, advance) = ticketed_pair(ctx, pack, head, "async", canonical).await?;
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

async fn ticketed_advance(
    ctx: &Ctx,
    pack: &[u8],
    head: Hash,
    leaf: &str,
) -> Result<(String, Signed), Failure> {
    ticketed_pair(ctx, pack, head, leaf, false).await
}

async fn upload_ticket(
    ctx: &Ctx,
    pack: &[u8],
    repository: &str,
    branch: &str,
) -> Result<Vec<u8>, Failure> {
    let signer = ctx.v2_signer("repository-a")?;
    let pack_id = hash(pack);
    let begin = BeginUploadRequest {
        r#ref: Some(branch.to_owned()),
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
    if ctx.case == "uno.public_fixture" && pack.len() > 8 * 1024 * 1024 {
        return super::multipart::complete_uno_ticket(ctx, &signer, repository, &ticket, pack)
            .await;
    }
    let id = ticket.id.ok_or("ticket has no id")?;
    let mut messages = upload_msgs(pack, 48);
    if let Some(UploadBody::Header(header)) = &mut messages[0].body {
        header.ticket_token = ticket.token;
    }
    let mut envelope = signer.envelope(
        Rpc::UploadPack.procedure(),
        pack_commitment(&pack_id, pack.len() as u64),
    );
    envelope.repository = repository.to_owned();
    let headers = signer.sign(&envelope).headers;
    ensure!(
        ctx.upload_with(&messages, &headers).await?.is_none(),
        "ticketed UploadPack failed"
    );

    Ok(id)
}

async fn ticketed_pair(
    ctx: &Ctx,
    pack: &[u8],
    head: Hash,
    leaf: &str,
    canonical: bool,
) -> Result<(String, Signed), Failure> {
    let (repository, _) = super::repository::identities(ctx, "async-verify", "unused")?;
    let signer = ctx.v2_signer("repository-a")?;
    let pack_id = hash(pack);
    let branch = ctx.head(leaf);
    let mut ids = vec![upload_ticket(ctx, pack, &repository, &branch).await?];
    let packmap = if canonical {
        let node = mkit_core::transfer::encode_packlist(None, &[pack_id])
            .map_err(|e| format!("packlist: {e}"))?;
        ids.push(upload_ticket(ctx, &node, &repository, &branch).await?);
        hash(&node)
    } else {
        pack_id
    };
    let mut request = advance_req(
        (&branch, Exp::Missing, &head),
        (&ctx.packmap(leaf), Exp::Missing, &packmap),
    );
    request.ticket_ids = ids;
    let advance = sign_unary(&signer, Rpc::AdvanceRefs, &request, |env| {
        repository.clone_into(&mut env.repository);
    });
    Ok((repository, advance))
}

/// A real sync inspector must refuse this fixture's advance. The receiver
/// chooses reject or fail-closed failure; verification pending is not success.
pub(super) async fn inspection_rejects_advance(ctx: Ctx) -> CaseResult {
    let reply = ctx
        .client()
        .post(
            "/mkit.transport.v1.TransportService/GetServerInfo",
            UNARY_PROTO,
            &[],
            Vec::new(),
        )
        .await?;
    let info = want_ok(
        decode_unary::<GetServerInfoResponse>(&reply)?,
        "GetServerInfo",
    )?;
    ensure!(
        info.indexed_mode == Some(true)
            && info.async_inspection == Some(false)
            && info.inspection_max_objects.is_some_and(|bound| bound > 0),
        "rejection fixture has no active sync inspector"
    );
    let (pack, head) = pack_with_blob(Some(b"launch inspected content"))?;
    let (repository, advance) = ticketed_advance(&ctx, &pack, head, "reject").await?;
    let owner = ctx.v2_signer("repository-a")?;
    // Make public absence a real reader check rather than private denial.
    super::visibility::set_envelope(&ctx, &owner, &repository, false).await?;
    let mut pending = 0;
    let mut terminal = None;
    for _ in 0..240 {
        match ctx.send::<AdvanceRefsResponse>(&advance).await? {
            Ok(response) => {
                return Err(Failure::Fail(format!(
                    "inspection refusal unexpectedly succeeded: {:?}",
                    response.outcome
                )));
            }
            Err(error)
                if error.code == "unavailable" && error.message == "pack verification pending" =>
            {
                ensure!(
                    error.details.len() == 1,
                    "pending details {:?}",
                    error.details
                );
                pending += 1;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(error) => {
                ensure!(
                    error.code == "permission_denied"
                        || (error.code == "unavailable"
                            && error.message == "inspection unavailable; retry"),
                    "advance answered {error}, not an inspection refusal"
                );
                terminal = Some(error);
                break;
            }
        }
    }
    let error = terminal.ok_or_else(|| {
        Failure::Fail(format!(
            "no inspection refusal after {pending} verification polls"
        ))
    })?;
    for name in [ctx.head("reject"), ctx.packmap("reject")] {
        let request = ReadRefRequest {
            name: Some(name.clone()),
            ..Default::default()
        };
        for signed in [true, false] {
            let read = if signed {
                super::reads::signed_for(&owner, &repository, Rpc::ReadRef, &request)
            } else {
                super::reads::unsigned(&repository, Rpc::ReadRef, &request)
            };
            let response: ReadRefResponse =
                want_ok(ctx.send(&read).await?, "ReadRef after refusal")?;
            ensure!(
                response.exists != Some(true)
                    && response.object_id.as_deref().unwrap_or_default().is_empty(),
                "inspection refusal moved {name} for signed={signed}"
            );
        }
    }
    ctx.set_note(format!(
        "repository={repository} head_ref={} packmap_ref={} pack_id={} pack_bytes={} pending_polls={pending} refusal={}",
        ctx.head("reject"), ctx.packmap("reject"), to_hex(&hash(&pack)), pack.len(), error.code
    ));
    Ok(())
}

/// The production-only intersection: no test directives, ticketed upload,
/// scheduled verification/extraction, public paired refs and exact pack bytes.
/// The HTTP opt-in additionally proves the extracted bytes and proof refusal.
pub(super) async fn launch_verification_commits(ctx: Ctx) -> CaseResult {
    launch_verified_fixture(ctx, true, true).await
}

/// Bounded setup for preservation/admin checks; the large-pack case stays separate.
pub(super) async fn launch_admin_fixture(ctx: Ctx) -> CaseResult {
    launch_verified_fixture(ctx, false, true).await
}

/// Separate Uno gate: public-by-default repositories, retaining the original Set fixture.
pub(super) async fn uno_public_fixture(ctx: Ctx) -> CaseResult {
    launch_verified_fixture(ctx, false, false).await
}

async fn uno_payment_challenge(ctx: &Ctx) -> CaseResult {
    let (repository, _) = super::repository::identities(ctx, "async-verify", "unused")?;
    let begin = BeginUploadRequest {
        r#ref: Some(ctx.head("payment-probe")),
        pack_id: Some(hash(b"thirteen-byte").to_vec()),
        bytes: Some(13),
        ..Default::default()
    };
    let signed = sign_unary(
        &ctx.v2_signer("repository-a")?,
        Rpc::BeginUpload,
        &begin,
        |env| {
            repository.clone_into(&mut env.repository);
        },
    );
    let reply = ctx.send::<BeginUploadResponse>(&signed).await?;
    let error = reply.err().ok_or("Uno admission did not challenge")?;
    ensure!(
        error.http_status == 402 && error.code == "permission_denied",
        "Uno challenge was {error}"
    );
    ensure!(
        error.details.len() == 1,
        "Uno challenge omitted typed detail"
    );
    Ok(())
}

async fn uno_already_present(
    ctx: &Ctx,
    repository: &str,
    pack_id: Hash,
    bytes: usize,
) -> CaseResult {
    let begin = BeginUploadRequest {
        r#ref: Some(ctx.head("async")),
        pack_id: Some(pack_id.to_vec()),
        bytes: Some(bytes as u64),
        ..Default::default()
    };
    let signed = sign_unary(
        &ctx.v2_signer("repository-a")?,
        Rpc::BeginUpload,
        &begin,
        |env| {
            repository.clone_into(&mut env.repository);
        },
    );
    let opened: BeginUploadResponse = want_ok(ctx.send(&signed).await?, "Uno AlreadyPresent")?;
    ensure!(
        matches!(opened.result, Some(BeginResult::AlreadyPresent(_))),
        "verified Uno pack was not AlreadyPresent"
    );
    Ok(())
}

async fn launch_verified_fixture(ctx: Ctx, large: bool, set_visibility: bool) -> CaseResult {
    let data: Vec<_> = (0..131_072_u32)
        .map(|i| u8::try_from((i.wrapping_mul(17) ^ (i >> 9)) & 0xff).unwrap_or(0))
        .collect();
    let extracted = Object::Blob(mkit_core::object::Blob { data: data.clone() })
        .id()
        .map_err(|e| format!("extracted id: {e}"))?;
    let (pack, head) = if large {
        verification_pack(Some(&data))?
    } else {
        verification_fixture_pack(Some(&data), 0, !set_visibility)?
    };
    let pack_id = hash(&pack);
    if !set_visibility {
        uno_payment_challenge(&ctx).await?;
    }
    let published_packmap = if large {
        pack_id
    } else {
        hash(
            &mkit_core::transfer::encode_packlist(None, &[pack_id])
                .map_err(|e| format!("packlist: {e}"))?,
        )
    };
    let (repository, pending) = if large {
        commit_large_pack(&ctx, &pack, head).await?
    } else {
        commit_pack(&ctx, &pack, head, true).await?
    };
    if set_visibility {
        super::visibility::set_envelope(&ctx, &ctx.v2_signer("repository-a")?, &repository, false)
            .await?;
    }

    eventually_listed(
        "published head and packmap",
        || async {
            Ok((
                public_read_ref(&ctx, &repository, ctx.head("async")).await?,
                public_read_ref(&ctx, &repository, ctx.packmap("async")).await?,
            ))
        },
        |pair| {
            pair.0.as_deref() == Some(head.as_slice())
                && pair.1.as_deref() == Some(published_packmap.as_slice())
        },
    )
    .await?;
    let body = frame(
        &DownloadPackRequest {
            pack_id: Some(pack_id.to_vec()),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let reply = ctx
        .client()
        .stream::<DownloadPackResponse>(
            Rpc::DownloadPack,
            body,
            &[("x-repository".into(), repository.clone())],
        )
        .await?;
    ensure!(
        Ctx::downloaded_bytes(&pack_id, reply)? == pack,
        "public DownloadPack bytes differ"
    );
    if ctx.profile().has(Feature::HttpObjects) {
        check_extracted_http(&ctx, &repository, &extracted, &data).await?;
    }
    if !set_visibility {
        uno_already_present(&ctx, &repository, pack_id, pack.len()).await?;
    }
    ctx.set_note(format!(
        "repository={repository} head_ref={} packmap_ref={} pack_bytes={} pending_polls={pending} extracted_blob={} extracted_blob_bytes={} http={}",
        ctx.head("async"),
        ctx.packmap("async"),
        pack.len(),
        to_hex(&extracted),
        data.len(),
        ctx.profile().has(Feature::HttpObjects)
    ));
    Ok(())
}

async fn public_read_ref(
    ctx: &Ctx,
    repository: &str,
    name: String,
) -> Result<Option<Vec<u8>>, Failure> {
    let response: ReadRefResponse = want_ok(
        ctx.client()
            .unary(
                Rpc::ReadRef,
                ReadRefRequest {
                    name: Some(name),
                    ..Default::default()
                }
                .encode_to_vec(),
                &[("x-repository".into(), repository.into())],
            )
            .await?,
        "public ReadRef",
    )?;
    let id = response.object_id.unwrap_or_default();
    if response.exists == Some(true) {
        ensure!(id.len() == 32, "public ReadRef returned an invalid id");
        Ok(Some(id))
    } else {
        ensure!(id.is_empty(), "absent public ReadRef returned an id");
        Ok(None)
    }
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

#[cfg(test)]
mod uno_geometry_tests {
    use super::*;

    #[test]
    fn canonical_uno_pack_has_two_parts_and_unchanged_published_head() {
        use mkit_core::pack::{DecodeLimits, NoExternalBases, decode_entries_with};
        use mkit_core::upload_parts::{MIN_PART_SIZE, PartPlan};
        let data = vec![9; 131_072];
        let (_, expected_head) = verification_pack_entries(Some(&data), 0).unwrap();
        let (pack, head) = verification_fixture_pack(Some(&data), 0, true).unwrap();
        assert_eq!(head, expected_head);
        assert_eq!(
            PartPlan::new(pack.len() as u64, MIN_PART_SIZE, 2)
                .unwrap()
                .count(),
            2
        );
        let decoded =
            decode_entries_with(&pack, &mut NoExternalBases, DecodeLimits::default(), |entry| {
                assert!(entry.bytes.len() <= 512 * 1024);
                Ok(())
            })
            .unwrap();
        println!("Uno canonical pack bytes={} raw_entries={}", pack.len(), decoded.raw_count);
        assert_eq!(decoded.raw_count, 20);
        assert!(decoded.ids.contains(&head));
    }
}
