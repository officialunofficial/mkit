//! `IssueObjectUrl` over the pipeline (SPEC-WRITE-GRANTS §9.4): the
//! unconfigured answer before any repository access, the signed-read
//! gate, the §9.3 `not_found` on a private repository and the stored
//! epoch the minted token binds.

use zeroize::Zeroizing;

use super::grants::{config, environment, repository};
use super::policy::{PolicyAdmission, PolicyHook, policy_hooks};
use super::visibility::{assert_not_found, put_epoch, put_repo, repo_id};
use super::*;
use crate::url_token::{Binding, TokenRejected, UrlTokenConfig, UrlTokenKeys};

fn tokens() -> UrlTokenConfig {
    UrlTokenConfig::with_ttl_ms(
        UrlTokenKeys::new(Zeroizing::new([9; 32]), Vec::new()).unwrap(),
        60_000,
    )
    .unwrap()
}

/// Multi + owner policy + auth v2 (visibility applies) with tokens.
fn token_env(owner: &SigningKey) -> Env<Hooks<PolicyHook, PolicyAdmission>> {
    let clock = clock();
    let mut c = config(owner, AuthorizerRole::Check);
    c.url_tokens = Some(tokens());
    build(c, Spy::new(store(&clock)), policy_hooks(false), clock)
}

/// Single + auth v2 with tokens: [`Pipeline::visibility_applies`] is
/// false, so `IssueObjectUrl` reads the `e` row itself.
fn single_token_env() -> Env {
    let clock = clock();
    let mut c = cfg(authv2());
    c.url_tokens = Some(tokens());
    build(c, Spy::new(store(&clock)), Hooks::new(), clock)
}

fn signed_issue(signer: &SigningKey, repo: &str, n: u32) -> Req {
    Req::signed_for(signer, Procedure::IssueObjectUrl, repo, b"t", &nonce(n), T0)
}

fn issue<H: HookSet>(
    e: &Env<H>,
    req: &Req,
    target: UrlTarget,
    ttl_seconds: u32,
) -> Result<MintedToken, ServerError> {
    let a = e.auth(req).unwrap();
    now(e.pipe.issue_object_url(&a, target, ttl_seconds))
}

/// The token bound to `repo`/`target` under `tokens()`.
fn bound(token: &str, repository: &str, target: &UrlTarget) -> crate::url_token::BoundToken {
    tokens()
        .precheck(token, T0)
        .unwrap()
        .check_binding(
            &Binding {
                audience: AUDIENCE,
                repository,
                target,
            },
            T0,
            60_000,
        )
        .unwrap()
}

#[test]
fn issue_object_url_needs_configured_tokens() {
    let owner = key(1);
    let env = environment(&owner, AuthorizerRole::Check, false);
    let a = env
        .auth(&signed_issue(&owner, &repository(&owner), 1))
        .unwrap();
    let err = now(env.pipe.issue_object_url(&a, UrlTarget::Object(A), 0)).unwrap_err();
    assert_eq!(err.code(), Code::Unimplemented);
    assert_eq!(err.public_message(), "URL tokens not configured");
}

#[test]
fn issue_object_url_unsigned_is_unauthenticated() {
    let owner = key(1);
    let env = token_env(&owner);
    let req = Req::unsigned(Procedure::IssueObjectUrl).header("x-repository", &repository(&owner));
    assert_eq!(env.auth(&req).unwrap_err().code(), Code::Unauthenticated);
}

#[test]
fn issue_object_url_mints_a_token_bound_to_the_stored_epoch() {
    let owner = key(1);
    let repo = repository(&owner);
    let env = token_env(&owner);
    let id = repo_id(&env, &owner);
    put_repo(&env, &id, None);
    put_epoch(&env, &id, 3);
    let target = UrlTarget::path(HEAD, "a/b").unwrap();
    let minted = issue(&env, &signed_issue(&owner, &repo, 1), target.clone(), 0).unwrap();
    // A `0` request takes the configured lifetime.
    assert_eq!(minted.expires_at_ms, T0 + 60_000);
    let bound = bound(minted.expose(), &repo, &target);
    // `authorize_read`'s epoch, not a second read: the stored `e` was 3.
    assert_eq!(bound.epoch(), 3);
    bound.check_epoch(3).unwrap();
    assert_eq!(bound.check_epoch(4), Err(TokenRejected));
}

#[test]
fn issue_object_url_on_a_private_repo_is_the_missing_repo_error() {
    let owner = key(1);
    let stranger = key(2);
    let repo = repository(&owner);
    let env = token_env(&owner);
    let target = UrlTarget::Object(A);
    let missing = issue(&env, &signed_issue(&stranger, &repo, 1), target.clone(), 0).unwrap_err();
    assert_not_found(&missing, "missing");

    let id = repo_id(&env, &owner);
    put_repo(&env, &id, Some(codec::StoredVisibility::Private));
    let denied = issue(&env, &signed_issue(&stranger, &repo, 2), target.clone(), 0).unwrap_err();
    assert_eq!(
        (
            denied.code(),
            denied.public_message(),
            denied.details(),
            denied.headers()
        ),
        (
            missing.code(),
            missing.public_message(),
            missing.details(),
            missing.headers()
        )
    );
    // The owner still mints.
    issue(&env, &signed_issue(&owner, &repo, 3), target, 0).unwrap();
}

#[test]
fn issue_object_url_binds_the_epoch_without_visibility() {
    let env = single_token_env();
    // No `e` row yet: the absent epoch is 0.
    let target = UrlTarget::Object(A);
    let minted = issue(&env, &signed_issue(&key(1), REPO, 1), target.clone(), 0).unwrap();
    assert_eq!(bound(minted.expose(), REPO, &target).epoch(), 0);
    put_epoch(&env, &repo(), 9);
    let minted = issue(&env, &signed_issue(&key(1), REPO, 2), target.clone(), 0).unwrap();
    assert_eq!(bound(minted.expose(), REPO, &target).epoch(), 9);
}
