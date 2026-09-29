//! The per-signer write quota (SPEC-TRANSPORT-CONNECT §7.1): exhaustion is
//! `resource_exhausted`, allocates nothing (no replay record), and a
//! replayed write is never charged again. Each case exhausts its own
//! signer, so it needs a profile that declares a tiny quota.
//!
//! Under D34 (`profile.sharding_d34`) the quota is per (signer, branch), so
//! the cases spend the budget as a chain of writes to ONE branch and show
//! that another branch is unaffected. [`namespace_cap_after_rollup`] covers
//! the Multi namespace cap, which spans branches after a ref shard's rollup.

use mkit_core::hash::hash;
use mkit_transport_connect::generated::{ListRefsRequest, ListRefsResponse, UpdateRefResponse};

use buffa::Message as _;

use super::{
    A, CaseResult, Ctx, Exp, Failure, Signed, ensure, header_msg, random_pack, repository,
    sign_unary, update_req, want_code, want_ok,
};
use crate::wire::client::{Rpc, RpcError};
use crate::wire::profile::QuotaLimits;
use crate::wire::sign::Signer;

const EXHAUSTED: &str = "resource_exhausted";

fn limits(ctx: &Ctx) -> Result<QuotaLimits, Failure> {
    ctx.profile()
        .quota
        .ok_or_else(|| Failure::Skip("needs a declared quota".to_owned()))
}

/// The value step `i` of a D34 chain writes.
fn chain_id(i: u32) -> [u8; 32] {
    hash(format!("quota-chain-{i}").as_bytes())
}

/// A signed `UpdateRef` that spends one op: step `i` of the case's
/// writes. Under Single sharding each step creates its own branch
/// `<leaf>{i}` (MISSING, `A`); under D34 the quota is per branch, so every
/// step moves the one branch `<leaf>` (ANY, a distinct id). Optionally
/// under `nonce`.
fn signed(ctx: &Ctx, signer: &Signer, leaf: &str, i: u32, nonce: Option<&str>) -> Signed {
    let req = if d34(ctx) {
        update_req(&ctx.head(leaf), Exp::Any, &chain_id(i))
    } else {
        update_req(&ctx.head(&format!("{leaf}{i}")), Exp::Missing, &A)
    };
    sign_unary(signer, Rpc::UpdateRef, &req, |env| {
        if let Some(nonce) = nonce {
            nonce.clone_into(&mut env.nonce);
        }
    })
}

fn d34(ctx: &Ctx) -> bool {
    ctx.profile().sharding_d34
}

/// What ref `<leaf>` (step `i` of the case's writes, see [`signed`]) holds
/// once step `i - 1` was the last to commit: `None` under Single, where
/// step `i` names its own untouched branch.
fn held_before(ctx: &Ctx, leaf: &str, i: u32) -> (String, Option<[u8; 32]>) {
    if d34(ctx) {
        (ctx.head(leaf), i.checked_sub(1).map(chain_id))
    } else {
        (ctx.head(&format!("{leaf}{i}")), None)
    }
}

async fn send(ctx: &Ctx, s: &Signed) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    ctx.send(s).await
}

/// A fresh signed step `i` (see [`signed`]).
async fn write(
    ctx: &Ctx,
    signer: &Signer,
    leaf: &str,
    i: u32,
    nonce: Option<&str>,
) -> Result<Result<UpdateRefResponse, RpcError>, String> {
    send(ctx, &signed(ctx, signer, leaf, i, nonce)).await
}

/// Spend the whole op budget of `signer`.
async fn exhaust(ctx: &Ctx, signer: &Signer, ops: u32) -> CaseResult {
    for i in 0..ops {
        want_ok(
            write(ctx, signer, "r", i, None).await?,
            &format!("write {i} of {ops}"),
        )?;
    }
    Ok(())
}

pub(super) async fn ops_exhaustion(ctx: Ctx) -> CaseResult {
    let q = limits(&ctx)?;
    let signer = ctx.v2_signer("quota")?;
    exhaust(&ctx, &signer, q.max_ops).await?;
    want_code(
        write(&ctx, &signer, "r", q.max_ops, None).await?,
        EXHAUSTED,
        "one write over the budget",
    )?;
    let (name, held) = held_before(&ctx, "r", q.max_ops);
    ctx.expect_ref(&name, held.as_ref().map(<[u8; 32]>::as_slice))
        .await?;
    // Another signer is not affected.
    let other = ctx.v2_signer("other")?;
    want_ok(
        write(&ctx, &other, "other", 0, None).await?,
        "another signer's write",
    )?;
    if d34(&ctx) {
        // The quota is per (signer, branch): the same signer's other
        // branch is untouched by the exhausted one.
        want_ok(
            write(&ctx, &signer, "elsewhere", 0, None).await?,
            "the exhausted signer's write to a different branch",
        )?;
    }
    Ok(())
}

pub(super) async fn bytes_exhaustion(ctx: Ctx) -> CaseResult {
    let q = limits(&ctx)?;
    let total = q.max_bytes.saturating_add(1);
    if total > ctx.profile().max_pack_bytes {
        return Err(Failure::Skip(
            "the byte quota exceeds the pack cap".to_owned(),
        ));
    }
    let signer = ctx.v2_signer("quota")?;
    let id = hash(&random_pack(32));
    let op = signer.sign_pack(Rpc::UploadPack.procedure(), &id, total);
    // Refused at the header, before any chunk is read (§7.1).
    let got = ctx
        .upload_with(&[header_msg(&id, total)], &op.headers)
        .await?;
    let code = got.as_ref().map(|e| e.code.as_str());
    super::ensure!(
        code == Some(EXHAUSTED),
        "an upload over the byte budget: {code:?}"
    );
    ctx.expect_exists(&id, false).await
}

pub(super) async fn exhaustion_allocates_no_replay(ctx: Ctx) -> CaseResult {
    let q = limits(&ctx)?;
    let signer = ctx.v2_signer("quota")?;
    exhaust(&ctx, &signer, q.max_ops).await?;
    // X and Y are two different writes over the budget: under D34 both move
    // the exhausted branch (a different branch would have its own budget).
    let (x_step, y_step) = (q.max_ops, q.max_ops + 1);
    let x = signed(&ctx, &signer, "r", x_step, None);
    want_code(send(&ctx, &x).await?, EXHAUSTED, "write X over the budget")?;
    // Had X left a replay record, another operation under its nonce would
    // be `invalid_argument` (fingerprint mismatch), and X's retry `ok`.
    want_code(
        write(&ctx, &signer, "r", y_step, Some(&x.nonce)).await?,
        EXHAUSTED,
        "write Y under X's nonce",
    )?;
    want_code(send(&ctx, &x).await?, EXHAUSTED, "X retried")?;
    for step in [x_step, y_step] {
        let (name, held) = held_before(&ctx, "r", step);
        // Under D34 neither write landed: the branch still holds the last
        // committed step; under Single both names stay absent.
        let want = if d34(&ctx) {
            Some(chain_id(q.max_ops - 1))
        } else {
            held
        };
        ctx.expect_ref(&name, want.as_ref().map(<[u8; 32]>::as_slice))
            .await?;
    }
    Ok(())
}

pub(super) async fn replay_not_charged(ctx: Ctx) -> CaseResult {
    let q = limits(&ctx)?;
    let signer = ctx.v2_signer("quota")?;
    let first = signed(&ctx, &signer, "r", 0, None);
    want_ok(send(&ctx, &first).await?, "first write")?;
    for i in 0..3 {
        want_ok(send(&ctx, &first).await?, &format!("replay {i}"))?;
    }
    // The replays were free: the rest of the budget is intact.
    for i in 1..q.max_ops {
        want_ok(
            write(&ctx, &signer, "r", i, None).await?,
            &format!("write {i} after replays"),
        )?;
    }
    want_code(
        write(&ctx, &signer, "r", q.max_ops, None).await?,
        EXHAUSTED,
        "one write over the budget",
    )?;
    Ok(())
}

/// The clock skew that makes a ref shard's rollup timer due: the rollup
/// period is 60 s from the shard's first charge in a window.
const ROLLUP_SKEW_MS: u64 = 65_000;

/// Run the due timers of `ref_name`'s shard, as if `ROLLUP_SKEW_MS` had
/// passed, through a `ListRefs` of `repository`.
async fn force_rollup(ctx: &Ctx, repository: &str, ref_name: &str) -> CaseResult {
    let body = ListRefsRequest {
        prefix: Some(ctx.head("")),
        ..Default::default()
    }
    .encode_to_vec();
    let mut headers = repository::read_headers(ctx, Rpc::ListRefs, &body, repository);
    headers.push((super::timers::RUN.into(), ref_name.into()));
    headers.push((super::timers::SKEW.into(), ROLLUP_SKEW_MS.to_string()));
    want_ok(
        ctx.client()
            .unary::<ListRefsResponse>(Rpc::ListRefs, body, &headers)
            .await?,
        "timer ListRefs",
    )?;
    Ok(())
}

/// D34 + Multi: the namespace cap counts the owner's writes across every
/// branch, and a ref shard learns the other shards' usage from its
/// rollup. Half the budget goes to branch `b1`, whose shard is then rolled
/// up (clock skew plus `run-timers`, in a window longer than the 60 s
/// rollup period); a fresh shard for `b2` reads that total when it is
/// created, so the other half fits and one write more is refused as the
/// NAMESPACE cap even though `b2`'s own per-branch budget is not spent.
pub(super) async fn namespace_cap_after_rollup(ctx: Ctx) -> CaseResult {
    if !d34(&ctx) {
        return Err(Failure::Skip(
            "the namespace rollup is a D34 ref-shard mechanism".to_owned(),
        ));
    }
    let q = limits(&ctx)?;
    let window = u64::try_from(q.window_ms).unwrap_or(0);
    if q.max_ops < 4 || window < 10 * ROLLUP_SKEW_MS {
        return Err(Failure::Skip(
            "needs a quota of at least 4 ops and a window well over the 60 s rollup period"
                .to_owned(),
        ));
    }
    // A rollup near a window edge would read the next window: stay clear.
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(0);
    if window - now % window < 3 * ROLLUP_SKEW_MS {
        return Err(Failure::Skip(
            "too close to the end of a quota window to force a rollup".to_owned(),
        ));
    }
    let (repo, _) = repository::identities(&ctx, "namespace-cap", "unused")?;
    let first = q.max_ops / 2;
    let second = q.max_ops - first;
    let write = |leaf: &'static str, i: u32| {
        let ctx = &ctx;
        let repo = &repo;
        async move {
            let signed = repository::signed_update(ctx, repo, leaf, &chain_id(i))?;
            Ok::<_, Failure>(ctx.send::<UpdateRefResponse>(&signed).await?)
        }
    };
    for i in 0..first {
        want_ok(write("b1", i).await?, &format!("b1 write {i}"))?;
    }
    force_rollup(&ctx, &repo, &ctx.head("b1")).await?;
    for i in 0..second {
        want_ok(write("b2", i).await?, &format!("b2 write {i}"))?;
    }
    let refused = want_code(
        write("b2", second).await?,
        EXHAUSTED,
        "one write over the namespace budget",
    )?;
    ensure!(
        refused.message.contains("namespace"),
        "the refusal must be the namespace cap (b2 spent {second} of {} per-branch ops): {}",
        q.max_ops,
        refused.message
    );
    let read = want_ok(repository::read(&ctx, &repo, "b2").await?, "ReadRef b2")?;
    ensure!(
        read.object_id.as_deref() == Some(&chain_id(second - 1)[..]),
        "the refused write must not have moved b2"
    );
    Ok(())
}
