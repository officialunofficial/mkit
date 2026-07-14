// SPDX-License-Identifier: MIT OR Apache-2.0
//! `grpc.health.v1.Health` glue shared by both Workers (mkit#813, deferred
//! step 7 of mkit#797): the R2-HEAD half of the reachability probe and the
//! `service` field match decision `check()` makes before probing at all.
//!
//! NOT here: the `impl Health for HealthServer` trait impl itself, or the
//! generated `Health`/`HealthCheckRequest`/`HealthCheckResponse` types. Each
//! Worker's `connectrpc-build` codegen produces its own nominally distinct
//! `Health` trait (`mkit_repo_worker::proto::grpc::health::v1::Health` and
//! `mkit_vcs_worker::proto::grpc::health::v1::Health` are different types,
//! even though byte-identical in shape) — a crate with no generated proto
//! code of its own cannot implement either. Unifying that would mean this
//! crate owning a shared `grpc.health.v1` generated tree that both Workers'
//! `_connectrpc.rs` re-export instead of independently generating, which is
//! a codegen-pipeline change (build.rs, `scripts/regen-{repo,transport}-proto.sh`,
//! the `buf lint`/`breaking` gates, `scripts/check-generated-fresh.sh`) — a
//! separate, larger refactor than "shared glue" extraction, not attempted
//! here. Also NOT here: the RefStore DO round trip each Worker's `probe()`
//! also performs — repo-worker's `do_call` addresses a per-room DO instance
//! (an extra `room` argument), vcs-worker's addresses one fixed instance (no
//! `room` concept at all); that's a real architectural difference, not
//! duplication, so it stays in each Worker's own `worker_impl::health`.
//!
//! Because this crate pulls in no generated proto types for this, it adds no
//! `buffa`/`connectrpc` dependency and does not grow the vendored-codegen
//! "3 lockfiles" buffa-bump runbook to 4 (a risk mkit#797's plan flagged
//! for any health-check extraction that shares the trait impl itself).

use worker::Env;
use worker::send::SendFuture;

/// R2 key the reachability probe HEADs. Never written by any real handler
/// in either Worker — a `None` result IS the successful case (the bucket
/// answered; nothing needs to exist there).
pub const HEALTH_PROBE_KEY: &str = "__mkit-health-check__";

/// True when a `HealthCheckRequest.service` should be treated as targeting
/// `expected` — an empty `service` names no specific service either (the
/// whole-process health entry point), matching every registered service.
///
/// Pure and host-testable (see `#[cfg(test)]` below) — previously this
/// decision was inline, untested logic inside each Worker's
/// `#[cfg(target_arch = "wasm32")]`-gated `check()`.
pub fn service_name_matches(requested: &str, expected: &str) -> bool {
    requested.is_empty() || requested == expected
}

/// Cheap R2 reachability check: a HEAD on [`HEALTH_PROBE_KEY`], a key no
/// real handler in either Worker ever writes. Returns `false` on any
/// failure (missing binding, network error, etc.) — the caller ANDs this
/// with its own backing-store probe (a RefStore DO round trip) to decide
/// `SERVING` vs `NOT_SERVING`.
///
/// Touches real `worker::Env`/R2 types, so — like the rest of this crate's
/// `worker::*`-touching glue — it is not unit-tested here; it's verified by
/// the wasm32 build, each Worker's own integration tests (against fakes),
/// and a manual `wrangler dev` pass. Wrapped in [`SendFuture`] internally so
/// callers can `.await` it directly, matching this crate's other
/// `worker::*`-touching async helpers (e.g. `adapter::dispatch_oneshot`).
pub async fn r2_head_probe(env: &Env, bucket_binding: &str) -> bool {
    let env = env.clone();
    let bucket_binding = bucket_binding.to_string();
    SendFuture::new(async move {
        let Ok(bucket) = env.bucket(&bucket_binding) else {
            return false;
        };
        bucket.head(HEALTH_PROBE_KEY).await.is_ok()
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_service_matches_anything() {
        assert!(service_name_matches("", "mkit.repo.v1.RepoService"));
        assert!(service_name_matches(
            "",
            "mkit.transport.v1.TransportService"
        ));
    }

    #[test]
    fn matching_service_name_matches() {
        assert!(service_name_matches(
            "mkit.repo.v1.RepoService",
            "mkit.repo.v1.RepoService"
        ));
    }

    #[test]
    fn unknown_service_name_does_not_match() {
        assert!(!service_name_matches(
            "acme.NoSuchService",
            "mkit.repo.v1.RepoService"
        ));
    }

    #[test]
    fn cross_worker_service_name_does_not_match() {
        assert!(!service_name_matches(
            "mkit.transport.v1.TransportService",
            "mkit.repo.v1.RepoService"
        ));
    }
}
