//! Shared black-box `ListRepos` case for the in-process host and vcs-worker.

use mkit_transport_connect::generated::{ListReposRequest, ListReposResponse, RepoVisibility};

use super::{CaseResult, Ctx, ensure, grants, reads, visibility, want_code, want_ok};
use crate::wire::client::Rpc;

#[allow(clippy::too_many_lines)] // One isolated namespace-prefix lifecycle over the public wire.
pub(super) async fn listing(ctx: Ctx) -> CaseResult {
    let (owner, selector) = reads::owned(&ctx)?;
    let namespace = selector.split_once('/').ok_or("invalid test identity")?.0;
    let prefix = format!("{}-repo-list-", ctx.profile().run_id);
    let req = |token: &str| ListReposRequest {
        namespace: Some(namespace.into()),
        name_prefix: Some(prefix.clone()),
        page_size: Some(1),
        page_token: Some(token.into()),
        ..Default::default()
    };
    let empty = want_ok(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &req("")))
            .await?,
        "empty namespace prefix",
    )?;
    ensure!(
        empty.repos.is_empty()
            && empty
                .next_page_token
                .as_deref()
                .unwrap_or_default()
                .is_empty(),
        "empty listing has a continuation"
    );
    let private = format!("{namespace}/{prefix}a-private");
    let inherited = format!("{namespace}/{prefix}b-inherited");
    let public = format!("{namespace}/{prefix}c-public");
    // Visibility before creation must not register the repository or its listing row.
    visibility::set_envelope(&ctx, &owner, &private, true).await?;
    visibility::set_envelope(&ctx, &owner, &public, false).await?;
    let uncreated = want_ok(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &req("")))
            .await?,
        "pre-creation listing",
    )?;
    ensure!(
        uncreated == empty,
        "visibility created a phantom repository"
    );
    reads::seeded_repo(&ctx, &owner, &private, false).await?;
    let hidden = want_ok(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &req("")))
            .await?,
        "private-only listing",
    )?;
    ensure!(
        hidden == empty,
        "private rows changed the public listing shape"
    );
    reads::seeded_repo(&ctx, &owner, &inherited, false).await?;
    reads::seeded_repo(&ctx, &owner, &public, false).await?;
    let first = want_ok(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &req("")))
            .await?,
        "public first page",
    )?;
    ensure!(
        first.repos.len() == 1
            && first.repos[0].name.as_deref() == Some(format!("{prefix}b-inherited").as_str()),
        "first merged page wrong"
    );
    ensure!(
        first.repos[0].visibility == Some(RepoVisibility::REPO_VISIBILITY_PUBLIC.into()),
        "public visibility wrong"
    );
    let token = first.next_page_token.clone().unwrap_or_default();
    ensure!(!token.is_empty(), "missing public continuation");
    let second = want_ok(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &req(&token)))
            .await?,
        "public second page",
    )?;
    ensure!(
        second.repos.len() == 1
            && second.repos[0].name.as_deref() == Some(format!("{prefix}c-public").as_str()),
        "second merged page wrong"
    );
    ensure!(
        second
            .next_page_token
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        "unexpected final continuation"
    );
    let mut full = req("");
    full.page_size = Some(100);
    let all = want_ok(
        ctx.send::<ListReposResponse>(&reads::signed_for(&owner, &selector, Rpc::ListRepos, &full))
            .await?,
        "owner listing",
    )?;
    ensure!(
        all.repos.len() == 3
            && all.repos[0].visibility == Some(RepoVisibility::REPO_VISIBILITY_PRIVATE.into()),
        "owner lacks private listing"
    );
    let stranger = ctx.v2_signer("repository-b")?;
    let other = want_ok(
        ctx.send::<ListReposResponse>(&reads::signed_for(
            &stranger,
            &selector,
            Rpc::ListRepos,
            &full,
        ))
        .await?,
        "other signed caller",
    )?;
    ensure!(
        other.repos.len() == 2,
        "stranger listed a private repository"
    );
    let grant_owner = grants::Owner::Ed(ctx.v2_signer("repository-a")?);
    let mut grant = grants::grant(&ctx, &grant_owner, &private, &stranger);
    grant.capabilities = mkit_attest::grant::Capabilities::Read;
    grant.ref_scopes = None;
    let header = grant_owner.signed_header(&grant);
    let holder = reads::signed_for(&stranger, &private, Rpc::ListRepos, &full)
        .with_header("x-write-grant", header.clone());
    let granted = want_ok(
        ctx.send::<ListReposResponse>(&holder).await?,
        "read grant holder listing",
    )?;
    ensure!(granted == other, "grant added namespace listing rights");
    want_code(
        ctx.send::<ListReposResponse>(
            &reads::unsigned(&private, Rpc::ListRepos, &full).with_header("x-write-grant", header),
        )
        .await?,
        "unauthenticated",
        "unsigned listing grant",
    )?;
    let mut bad = token.into_bytes();
    bad[0] = if bad[0] == b'A' { b'B' } else { b'A' };
    let bad = String::from_utf8(bad).map_err(|e| e.to_string())?;
    want_code(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &req(&bad)))
            .await?,
        "invalid_argument",
        "tampered listing token",
    )?;
    let mut oversize = full.clone();
    oversize.page_size = Some(101);
    want_code(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &oversize))
            .await?,
        "invalid_argument",
        "oversized listing page",
    )?;
    let mut mismatched = full.clone();
    mismatched.namespace = Some("root".into());
    want_code(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &mismatched))
            .await?,
        "invalid_argument",
        "namespace/header mismatch",
    )?;
    visibility::set_envelope(&ctx, &owner, &inherited, true).await?;
    let changed = want_ok(
        ctx.send::<ListReposResponse>(&reads::unsigned(&selector, Rpc::ListRepos, &full))
            .await?,
        "public-to-private change",
    )?;
    ensure!(
        changed.repos.len() == 1
            && changed.repos[0].name.as_deref() == Some(format!("{prefix}c-public").as_str()),
        "visibility change left a listing row"
    );
    Ok(())
}
