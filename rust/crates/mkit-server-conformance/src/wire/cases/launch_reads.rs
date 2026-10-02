//! Local release-Worker paid-read fixtures. URL tokens never enter TAP logs.

use std::fs::OpenOptions;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::sync::Arc;

use mkit_core::hash::to_hex;
use mkit_core::object::{Blob, Object};
use mkit_transport_connect::generated::__buffa::oneof::issue_object_url_request::Target;
use mkit_transport_connect::generated::{IssueObjectUrlRequest, IssueObjectUrlResponse};

use super::{CaseResult, Ctx, want_ok};
use crate::wire::client::Rpc;

const PUBLIC_CASE: &str = "launch.read_fixture_public";

async fn fixture(ctx: &Ctx, private: bool) -> CaseResult {
    let data: Vec<_> = (0..131_072_u32)
        .map(|i| u8::try_from((i.wrapping_mul(17) ^ (i >> 9)) & 0xff).unwrap_or(0))
        .collect();
    let object = Object::Blob(Blob { data })
        .id()
        .map_err(|error| format!("read fixture object: {error}"))?;
    let (repository, _) = super::repository::identities(ctx, "async-verify", "unused")?;
    let owner = ctx.v2_signer("repository-a")?;
    if private {
        super::visibility::set_envelope(ctx, &owner, &repository, true).await?;
    }
    let request = IssueObjectUrlRequest {
        target: Some(Target::ObjectId(object.to_vec())),
        ..Default::default()
    };
    let signed = super::reads::signed_for(&owner, &repository, Rpc::IssueObjectUrl, &request);
    let minted: IssueObjectUrlResponse = want_ok(ctx.send(&signed).await?, "read fixture URL")?;
    let token = minted.token.ok_or("read fixture URL omitted token")?;
    let path = std::env::var_os("MKIT_LAUNCH_READ_FIXTURE")
        .ok_or("set MKIT_LAUNCH_READ_FIXTURE to an owned scratch file")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("create private read fixture file: {error}"))?;
    let json = serde_json::json!({
        "repository": repository,
        "object": to_hex(&object),
        "bytes": 131_072,
        "ref": ctx.head("async"),
        "private": private,
        "token": token,
    });
    file.write_all(json.to_string().as_bytes())
        .map_err(|error| format!("write private read fixture file: {error}"))?;
    Ok(())
}

pub(super) async fn public(ctx: Ctx) -> CaseResult {
    super::indexed::launch_verification_commits(ctx.clone()).await?;
    fixture(&ctx, false).await?;
    ctx.set_note("public paid-read fixture minted; URL token omitted".into());
    Ok(())
}

pub(super) async fn private(ctx: Ctx) -> CaseResult {
    // Both phases address the already-published public fixture with its original
    // signer and refs; this phase does not upload or replay the producer.
    let seeded = Ctx::new(
        ctx.client().clone(),
        Arc::new(ctx.profile().clone()),
        PUBLIC_CASE,
    );
    fixture(&seeded, true).await?;
    ctx.set_note("private paid-read fixture minted; URL token omitted".into());
    Ok(())
}
