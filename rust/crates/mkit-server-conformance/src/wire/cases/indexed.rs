//! Indexed-mode responses over the real Connect wire.

use mkit_core::hash::{Hash, hash};
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
    CaseResult, Commit as WireCommit, Ctx, Exp, Failure, advance_req, ensure, sign_unary,
    upload_msgs, want_ok, want_outcome,
};
use crate::wire::client::{Rpc, UNARY_PROTO, decode_unary};

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
