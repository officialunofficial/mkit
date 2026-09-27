//! Namespace allowlists and owner writes (SPEC-TRANSPORT-CONNECT §7.5).

use mkit_transport_connect::generated::UpdateRefResponse;

use super::{
    A, B, CaseResult, Ctx, Exp, ensure, repository, sign_unary, update_req, want_code, want_ok,
};
use crate::wire::client::Rpc;

pub(super) async fn owner_write_allowed(ctx: Ctx) -> CaseResult {
    let (repo, _) = repository::identities(&ctx, "owned", "unused")?;
    repository::set(&ctx, &repo, "main", &A).await?;
    let read = want_ok(
        repository::read(&ctx, &repo, "main").await?,
        "ReadRef owner write",
    )?;
    ensure!(
        read.exists == Some(true) && read.object_id.as_deref() == Some(&A),
        "owner write did not create its ref"
    );
    Ok(())
}

pub(super) async fn non_owner_write_denied(ctx: Ctx) -> CaseResult {
    let (repo, _) = repository::identities(&ctx, "owned", "unused")?;
    repository::set(&ctx, &repo, "main", &A).await?;
    let non_owner = ctx.v2_signer("repository-b")?;
    for leaf in ["main", "absent"] {
        let op = sign_unary(
            &non_owner,
            Rpc::UpdateRef,
            &update_req(&ctx.head(leaf), Exp::Any, &B),
            |env| repo.clone_into(&mut env.repository),
        );
        want_code(
            ctx.send::<UpdateRefResponse>(&op).await?,
            "permission_denied",
            "non-owner UpdateRef",
        )?;
    }
    let read = want_ok(
        repository::read(&ctx, &repo, "main").await?,
        "ReadRef after denial",
    )?;
    ensure!(
        read.exists == Some(true) && read.object_id.as_deref() == Some(&A),
        "non-owner write changed the existing ref"
    );
    let read = want_ok(
        repository::read(&ctx, &repo, "absent").await?,
        "ReadRef denied creation",
    )?;
    ensure!(
        read.exists != Some(true) && read.object_id.as_deref().unwrap_or_default().is_empty(),
        "non-owner write created a ref"
    );
    Ok(())
}

pub(super) async fn non_allowlisted_namespace_denied(ctx: Ctx) -> CaseResult {
    // This namespace's own key signs the write, isolating the allowlist decision.
    // Namespace-policy profiles omit this label from their allowlist.
    let owner = ctx.v2_signer("non-allowlisted")?;
    let repo = format!("ed25519-{}/denied", owner.public_key_hex());
    let op = sign_unary(
        &owner,
        Rpc::UpdateRef,
        &update_req(&ctx.head("main"), Exp::Any, &A),
        |env| repo.clone_into(&mut env.repository),
    );
    want_code(
        ctx.send::<UpdateRefResponse>(&op).await?,
        "permission_denied",
        "UpdateRef outside namespace allowlist",
    )?;
    want_code(
        repository::read(&ctx, &repo, "main").await?,
        "not_found",
        "ReadRef after namespace denial",
    )?;
    Ok(())
}
