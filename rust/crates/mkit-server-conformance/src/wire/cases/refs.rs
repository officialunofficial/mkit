//! `ReadRef`, `UpdateRef` and `ListRefs` (SPEC-TRANSPORT-CONNECT §3,
//! SPEC-REFS §3–§4).

use mkit_transport_connect::generated::{
    AdvanceRefsResponse, ReadRefRequest, ReadRefResponse, RefExpectation,
};

use super::{A, B, C, CaseResult, Ctx, Exp, advance_req, ensure, want_code, want_ok};
use crate::wire::client::Rpc;

const INVALID: &str = "invalid_argument";

pub(super) async fn read_missing(ctx: Ctx) -> CaseResult {
    ctx.expect_ref(&ctx.head("never-written"), None).await
}

pub(super) async fn update_any_then_read(ctx: Ctx) -> CaseResult {
    let name = ctx.head("main");
    ctx.set(&name, Exp::Any, &A).await?;
    ctx.expect_ref(&name, Some(&A)).await?;
    // ANY is last-writer-wins over an existing ref.
    ctx.set(&name, Exp::Any, &B).await?;
    ctx.expect_ref(&name, Some(&B)).await
}

pub(super) async fn update_missing_conflict(ctx: Ctx) -> CaseResult {
    let name = ctx.head("main");
    ctx.set(&name, Exp::Missing, &A).await?;
    want_code(
        ctx.update(&name, Exp::Missing, &B).await?,
        "failed_precondition",
        "MISSING on an existing ref",
    )?;
    ctx.expect_ref(&name, Some(&A)).await
}

pub(super) async fn update_match_conflict(ctx: Ctx) -> CaseResult {
    let name = ctx.head("main");
    let absent = ctx.head("absent");
    want_code(
        ctx.update(&absent, Exp::Match(&A), &B).await?,
        "failed_precondition",
        "MATCH on an absent ref",
    )?;
    ctx.expect_ref(&absent, None).await?;
    ctx.set(&name, Exp::Missing, &A).await?;
    want_code(
        ctx.update(&name, Exp::Match(&B), &C).await?,
        "failed_precondition",
        "MATCH with a stale id",
    )?;
    ctx.expect_ref(&name, Some(&A)).await?;
    ctx.set(&name, Exp::Match(&A), &C).await?;
    ctx.expect_ref(&name, Some(&C)).await
}

pub(super) async fn update_unspecified(ctx: Ctx) -> CaseResult {
    let name = ctx.head("main");
    want_code(
        ctx.update(&name, Exp::Unset, &A).await?,
        INVALID,
        "expectation unset",
    )?;
    let explicit = Exp::Raw(RefExpectation::REF_EXPECTATION_UNSPECIFIED, &[]);
    want_code(
        ctx.update(&name, explicit, &A).await?,
        INVALID,
        "expectation UNSPECIFIED",
    )?;
    ctx.expect_ref(&name, None).await
}

pub(super) async fn update_any_with_expected_id(ctx: Ctx) -> CaseResult {
    let name = ctx.head("main");
    let any = Exp::Raw(RefExpectation::REF_EXPECTATION_ANY, &B);
    want_code(
        ctx.update(&name, any, &A).await?,
        INVALID,
        "ANY with an expected_id",
    )?;
    let missing = Exp::Raw(RefExpectation::REF_EXPECTATION_MISSING, &B);
    want_code(
        ctx.update(&name, missing, &A).await?,
        INVALID,
        "MISSING with an expected_id",
    )?;
    ctx.expect_ref(&name, None).await
}

/// Names that fail the SPEC-REFS §3 grammar.
fn bad_names(ctx: &Ctx) -> Vec<String> {
    let base = ctx.head("x");
    vec![
        format!("{base}/../escape"),
        format!("{base}//double"),
        format!("{base}/.hidden"),
        format!("{base}/ref.lock"),
        format!("{base}/sp ace"),
        format!("/{base}"),
        String::new(),
    ]
}

async fn read_code(
    ctx: &Ctx,
    name: &str,
) -> Result<Result<ReadRefResponse, crate::wire::client::RpcError>, String> {
    let req = ReadRefRequest {
        name: Some(name.to_owned()),
        ..Default::default()
    };
    ctx.call(Rpc::ReadRef, &req).await
}

pub(super) async fn invalid_ref_name(ctx: Ctx) -> CaseResult {
    for name in bad_names(&ctx) {
        want_code(
            read_code(&ctx, &name).await?,
            INVALID,
            &format!("ReadRef {name:?}"),
        )?;
        want_code(
            ctx.update(&name, Exp::Any, &A).await?,
            INVALID,
            &format!("UpdateRef {name:?}"),
        )?;
        let req = advance_req((&name, Exp::Any, &A), (&ctx.packmap("main"), Exp::Any, &A));
        let resp: Result<AdvanceRefsResponse, _> = ctx.call(Rpc::AdvanceRefs, &req).await?;
        want_code(resp, INVALID, &format!("AdvanceRefs head {name:?}"))?;
    }
    ctx.expect_ref(&ctx.packmap("main"), None).await
}

/// A valid ref name of exactly `len` bytes under this case's namespace,
/// in components of at most 64 bytes (filesystem-backed servers).
fn name_of_len(ctx: &Ctx, len: usize) -> String {
    let mut name = ctx.head("long");
    while name.len() < len {
        let room = len - name.len();
        // "/" plus 1..=63 bytes; never leave a 1-byte remainder that
        // cannot hold "/x".
        let take = match room {
            66.. => 64,
            65 => 32,
            _ => room,
        };
        name.push('/');
        name.push_str(&"a".repeat(take - 1));
    }
    name
}

/// SPEC-REFS §3 caps a ref name at 512 bytes (mkit#1120).
pub(super) async fn name_over_512_bytes(ctx: Ctx) -> CaseResult {
    let at_cap = name_of_len(&ctx, 512);
    let over = name_of_len(&ctx, 513);
    ensure!(
        at_cap.len() == 512 && over.len() == 513,
        "suite bug: name lengths"
    );
    ctx.set(&at_cap, Exp::Missing, &A).await?;
    ctx.expect_ref(&at_cap, Some(&A)).await?;
    want_code(
        read_code(&ctx, &over).await?,
        INVALID,
        "ReadRef of a 513-byte name",
    )?;
    want_code(
        ctx.update(&over, Exp::Any, &A).await?,
        INVALID,
        "UpdateRef of a 513-byte name",
    )?;
    Ok(())
}

pub(super) async fn new_id_wrong_length(ctx: Ctx) -> CaseResult {
    let name = ctx.head("main");
    want_code(
        ctx.update(&name, Exp::Any, &[0xaa; 31]).await?,
        INVALID,
        "31-byte new_id",
    )?;
    want_code(
        ctx.update(&name, Exp::Any, &[]).await?,
        INVALID,
        "empty new_id",
    )?;
    want_code(
        ctx.update(&name, Exp::Match(&[0xaa; 33]), &A).await?,
        INVALID,
        "33-byte expected_id",
    )?;
    ctx.expect_ref(&name, None).await
}

/// Create `leaves` under `<ns>/<dir>` with ids A, B, C, ...
async fn populate(ctx: &Ctx, dir: &str, leaves: &[&str]) -> CaseResult {
    for (i, leaf) in leaves.iter().enumerate() {
        let id = [0x10 + u8::try_from(i).unwrap_or(0); 32];
        ctx.set(&ctx.head(&format!("{dir}/{leaf}")), Exp::Missing, &id)
            .await?;
    }
    Ok(())
}

/// The listing of `prefix`: names (sorted as returned) and ids.
async fn listing(ctx: &Ctx, prefix: &str) -> Result<Vec<(String, Vec<u8>)>, super::Failure> {
    want_ok(ctx.list(prefix).await?, &format!("ListRefs {prefix:?}"))
}

pub(super) async fn list_prefix_stripped(ctx: Ctx) -> CaseResult {
    // Created out of order; the listing is sorted (SPEC-REFS §4.1).
    let leaves = ["zeta", "alpha", "mid/nested", "mid/also"];
    populate(&ctx, "dir", &leaves).await?;
    let prefix = format!("{}/", ctx.head("dir"));
    let got = listing(&ctx, &prefix).await?;
    let names: Vec<_> = got.iter().map(|(n, _)| n.as_str()).collect();
    ensure!(
        names == ["alpha", "mid/also", "mid/nested", "zeta"],
        "ListRefs {prefix:?}: names {names:?}"
    );
    for (name, id) in &got {
        let i = leaves.iter().position(|l| l == name).unwrap_or(0);
        let want = [0x10 + u8::try_from(i).unwrap_or(0); 32];
        ensure!(id.as_slice() == want, "ListRefs: wrong id for {name}");
    }
    Ok(())
}

/// SPEC-REFS §4: a prefix matches only at a `/` boundary, with or without
/// its trailing `/`, and never yields a malformed name.
pub(super) async fn list_prefix_component_boundary(ctx: Ctx) -> CaseResult {
    populate(&ctx, "b", &["feat/x", "featx", "feature/y"]).await?;
    let base = ctx.head("b");
    for prefix in [format!("{base}/feat"), format!("{base}/feat/")] {
        let got = listing(&ctx, &prefix).await?;
        let names: Vec<_> = got.iter().map(|(n, _)| n.as_str()).collect();
        ensure!(
            names == ["x"],
            "ListRefs {prefix:?}: names {names:?}, want [\"x\"]"
        );
    }
    Ok(())
}

pub(super) async fn list_invalid_prefix(ctx: Ctx) -> CaseResult {
    let base = ctx.head("x");
    for prefix in [
        format!("{base}/../y"),
        "/".to_owned(),
        format!("{base}/sp ace"),
    ] {
        want_code(
            ctx.list(&prefix).await?,
            INVALID,
            &format!("ListRefs {prefix:?}"),
        )?;
    }
    Ok(())
}
