//! Baseline: the wire suite against the pipeline's Connect binding
//! (`mkit_server::connect::service`) over the memory stores, served by
//! `axum` on a loopback port, in three auth profiles: `none`, `bearer`, and
//! `auth-v2` with a tiny quota, plus a Multi auth-v2 baseline for the
//! repository cases. The memory store commits batches
//! atomically, so every profile declares `atomic-advance`. With this
//! crate's `test-faults` feature another profile adds the clock-skew
//! directive and `GET /__mkit_test/stats`.
//!
//! The `mutant_*` tests serve the same pipeline over a deliberately broken
//! store and check that the cases meant to catch the breakage fail.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use mkit_attest::grant::{AcceptedSchemes, OwnerScheme, RelyingParty};
use mkit_server::auth_v2::AuthV2Config;
use mkit_server::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use mkit_server::policy::NamespacePolicy;
use mkit_server::quota::QuotaLimits as ServerQuota;
use mkit_server::store::keys::ParsedKey;
use mkit_server::upload::UploadLimits;
use mkit_server::{
    Addressing, Batch, BatchOutcome, BlobKey, BlobStore, Cursor, Key, MemoryBlobStore, MemoryKv,
    MultiAddressing, NamespaceKey, NamespaceStore, PackSink, Partition, PartitionStats,
    Precondition, Redacted, RepoId, RepoName, ScanPage, StoreCapabilities, StoreError, SystemClock,
    Value, Write,
};
use mkit_server_conformance::wire::{
    Feature, Milestone, Profile, QuotaLimits, Verdict, WireAuth, WireTarget, run,
};

const REPOSITORY: &str = "default";
const TOKEN: &str = "conformance-bearer-token";
const MAX_PACK: u64 = 4 << 20;
const MULTIPART_MAX_PACK: u64 = 24 << 20;
const QUOTA: ServerQuota = ServerQuota {
    window_ms: 3_600_000,
    max_ops: 6,
    max_bytes: 2 << 20,
};

/// Cases the pipeline fails today, each with the reason: fixed in flight,
/// never an accepted behavior. An entry that starts passing fails the
/// baseline until it is removed.
const PIPELINE_DIVERGENCES: &[(&str, &str)] = &[];

/// A replay-expiry or quota-window index key.
fn is_index(key: &Key) -> bool {
    matches!(
        mkit_server::store::keys::parse(key),
        Some(ParsedKey::ReplayExpiry { .. } | ParsedKey::QuotaWindow { .. })
    )
}

/// How the store under the pipeline is broken, for the mutant tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutant {
    /// A correct store.
    None,
    /// Checks key preconditions, pauses, then writes unconditionally: a
    /// read-then-write compare-and-swap.
    ReadThenWrite,
    /// Drops every delete: nothing is ever pruned.
    NoPrune,
    /// Prunes records but leaks their expiry-index rows (`px`, `qx`): the
    /// delete is dropped and the row hidden from scans, so pruning goes on
    /// while the rows pile up.
    LeakIndex,
}

/// A memory store shared with the test (for the stats endpoint), maybe
/// broken.
#[derive(Clone)]
struct Shared(Arc<MemoryKv>, Mutant, Arc<Mutex<BTreeSet<Key>>>);

impl Shared {
    /// [`Mutant::ReadThenWrite`]: check, yield, write.
    async fn racy_apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        let mut deadline = Vec::new();
        for (index, pre) in batch.preconditions.iter().enumerate() {
            let held = match pre {
                Precondition::Absent(k) => self.0.get(p, k).await?.is_none(),
                Precondition::Present(k) => self.0.get(p, k).await?.is_some(),
                Precondition::Equals(k, v) => self.0.get(p, k).await?.as_ref() == Some(v),
                Precondition::NotAfter(_) => {
                    deadline.push(pre.clone());
                    true
                }
            };
            if !held {
                return Ok(BatchOutcome::PreconditionFailed {
                    index,
                    observed: None,
                });
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let unchecked = Batch {
            preconditions: deadline,
            writes: batch.writes,
        };
        self.0.apply(p, unchecked).await
    }
}

impl NamespaceStore for Shared {
    fn capabilities(&self) -> StoreCapabilities {
        self.0.capabilities()
    }
    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.0.get(p, key).await
    }
    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        self.0.get_many(p, keys).await
    }
    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        let mut page = self.0.scan(p, start, end, after, limit).await?;
        let leaked = self.2.lock().unwrap();
        page.entries.retain(|(k, _)| !leaked.contains(k));
        Ok(page)
    }
    async fn apply(&self, p: &Partition, mut batch: Batch) -> Result<BatchOutcome, StoreError> {
        match self.1 {
            Mutant::None => {}
            Mutant::ReadThenWrite => return self.racy_apply(p, batch).await,
            Mutant::NoPrune => batch.writes.retain(|w| matches!(w, Write::Put(..))),
            Mutant::LeakIndex => {
                let mut leaked = self.2.lock().unwrap();
                batch.writes.retain(|w| match w {
                    Write::Delete(k) if is_index(k) => {
                        leaked.insert(k.clone());
                        false
                    }
                    _ => true,
                });
            }
        }
        self.0.apply(p, batch).await
    }
    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.0.stats(p).await
    }
    async fn probe(&self) -> Result<(), StoreError> {
        self.0.probe().await
    }
}

/// Serve a pipeline in `auth` mode with `quota`; returns its origin and the
/// metadata store.
async fn serve(
    auth: impl FnOnce(&str) -> AuthMode,
    quota: Option<ServerQuota>,
) -> (String, Shared) {
    serve_mutant(auth, quota, Mutant::None).await
}

/// [`serve`] over a store broken as `mutant` says.
async fn serve_mutant(
    auth: impl FnOnce(&str) -> AuthMode,
    quota: Option<ServerQuota>,
    mutant: Mutant,
) -> (String, Shared) {
    serve_addressing(auth, quota, mutant, None).await
}

async fn serve_addressing(
    auth: impl FnOnce(&str) -> AuthMode,
    quota: Option<ServerQuota>,
    mutant: Mutant,
    multi: Option<&Profile>,
) -> (String, Shared) {
    serve_sharding(
        auth,
        quota,
        mutant,
        multi,
        mkit_server::pipeline::Sharding::Single,
        multi.map_or(MAX_PACK, |profile| profile.max_pack_bytes),
    )
    .await
}

async fn serve_sharding(
    auth: impl FnOnce(&str) -> AuthMode,
    quota: Option<ServerQuota>,
    mutant: Mutant,
    multi: Option<&Profile>,
    sharding: mkit_server::pipeline::Sharding,
    max_pack: u64,
) -> (String, Shared) {
    let (listener, origin) = common::listener().await;
    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPOSITORY).unwrap(),
    };
    let limits = UploadLimits {
        max_total_bytes: max_pack,
        max_chunks: 64,
    };
    let addressing = multi.map_or(Addressing::Single { repo }, |profile| {
        Addressing::Multi(
            MultiAddressing::new()
                .with_namespace_policy(NamespacePolicy::Allowlist(multi_allowlist(profile))),
        )
    });
    let mut cfg = PipelineConfig::new(addressing, auth(&origin), limits);
    if multi.is_some_and(|profile| profile.has(Feature::Grants)) {
        cfg.grants = Some(
            mkit_server::GrantConfig::new_allowing_loopback(
                &origin,
                AcceptedSchemes::of(&OwnerScheme::ALL),
                vec![
                    RelyingParty::new(
                        mkit_server_conformance::wire::GRANT_RP_ID,
                        [mkit_server_conformance::wire::GRANT_RP_ORIGIN],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        );
    }
    cfg.write_quota = quota;
    cfg.sharding = sharding;
    cfg.ticket_keys = Some(
        mkit_server::upload::token::TicketKeys::parse(
            "dev 1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap(),
    );
    cfg.ticket_caps.per_signer = 4;
    let clock = Arc::new(SystemClock);
    let kv = Arc::new(MemoryKv::with_clock(clock.clone()));
    let meta = Shared(kv, mutant, Arc::default());
    let blobs = MemoryBlobStore::default();
    if let Some(profile) = multi {
        plant_membership(&blobs, &meta, &cfg.addressing, sharding, profile).await;
    }
    let pipe = Pipeline::new(
        blobs,
        meta.clone(),
        Hooks::new(),
        cfg,
        clock,
        Arc::new(mkit_server::NoopMetrics),
    )
    .unwrap();
    let app = axum::Router::new().fallback_service(mkit_server::connect::service(Arc::new(pipe)));
    #[cfg(feature = "test-faults")]
    let app = app.route(
        mkit_server_conformance::wire::STATS_PATH,
        axum::routing::get({
            let meta = meta.clone();
            move || stats(meta.clone())
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await });
    (origin, meta)
}

/// Seed the wire fixtures directly, so Multi uploads keep their ticket guard.
/// No timers/outbox rows are planted: ref-only membership remains unrelayed.
async fn plant_membership(
    blobs: &MemoryBlobStore,
    meta: &Shared,
    addressing: &Addressing,
    sharding: mkit_server::pipeline::Sharding,
    profile: &Profile,
) {
    use mkit_server::pipeline::{D34Shards, ShardMap, Sharding, SinglePartition};
    use mkit_server::store::keys;

    let WireAuth::AuthV2 {
        audience,
        repository,
        seed,
    } = &profile.auth
    else {
        panic!("Multi membership fixtures need auth v2");
    };
    let shards: &dyn ShardMap = match sharding {
        Sharding::D34 => &D34Shards,
        _ => &SinglePartition,
    };
    for case in [
        "repo.isolation_packs",
        "repo.membership_read_your_writes",
        "repo.malformed_membership_hint_no_op",
    ] {
        let signer = mkit_server_conformance::wire::sign::Signer::derive(
            seed,
            &profile.run_id,
            &format!("{case}/repository-a"),
            audience,
            repository,
        );
        let identity = format!("ed25519-{}/packs", signer.public_key_hex());
        let repo = addressing.resolve(Some(&identity), false).unwrap().repo;
        let bytes = bytes::Bytes::from(format!("conformance/{}/{case}", profile.run_id));
        let id = mkit_core::hash::hash(&bytes);
        let key = BlobKey::pack(id);
        let mut sink = blobs.begin(key, bytes.len() as u64).await.unwrap();
        sink.write(bytes).await.unwrap();
        sink.commit().await.unwrap();
        let source = shards.ref_shard(&repo, "refs/heads/main");
        let index = shards.membership(&repo, &key);
        let ref_only = case == "repo.membership_read_your_writes";
        if ref_only && sharding == Sharding::D34 {
            assert_ne!(source, index, "read-your-writes requires a lagging index");
        }
        let mut partitions = vec![source];
        if !ref_only {
            partitions.push(index.clone());
        }
        for partition in partitions {
            let batch = Batch {
                preconditions: vec![],
                writes: vec![Write::Put(
                    keys::membership(&repo.name, &id),
                    Value::default(),
                )],
            };
            assert_eq!(
                meta.apply(&partition, batch).await.unwrap(),
                BatchOutcome::Committed
            );
        }
        if ref_only && sharding == Sharding::D34 {
            assert!(
                meta.get(&index, &keys::membership(&repo.name, &id))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}

/// Every Multi case's repository owners are admitted, while the denial case's
/// `non-allowlisted` label stays outside the set.
fn multi_allowlist(profile: &Profile) -> BTreeSet<mkit_core::repo_identity::Namespace> {
    let WireAuth::AuthV2 {
        audience,
        repository,
        seed,
    } = &profile.auth
    else {
        panic!("Multi baseline needs auth v2");
    };
    let mut allowed: BTreeSet<_> = mkit_server_conformance::wire::CASES
        .iter()
        .filter(|case| case.requires.contains(&Feature::MultiRepo))
        .flat_map(|case| {
            ["repository-a", "repository-b"].map(|label| {
                let label = format!("{}/{label}", case.name);
                let signer = mkit_server_conformance::wire::sign::Signer::derive(
                    seed,
                    &profile.run_id,
                    &label,
                    audience,
                    repository,
                );
                mkit_core::repo_identity::Namespace::parse(&format!(
                    "ed25519-{}",
                    signer.public_key_hex()
                ))
                .unwrap()
            })
        })
        .collect();
    if profile.has(Feature::Grants) {
        allowed.extend(mkit_server_conformance::wire::grant_owner_namespaces());
    }
    allowed
}

/// `GET /__mkit_test/stats`: the single partition's stats.
#[cfg(feature = "test-faults")]
async fn stats(meta: Shared) -> axum::Json<serde_json::Value> {
    let p = Partition::Namespace(NamespaceKey::deployment_default());
    let s = meta.stats(&p).await.unwrap();
    axum::Json(serde_json::json!({ "bytes": s.bytes, "keys": s.keys }))
}

fn profile(auth: WireAuth) -> Profile {
    let mut p = Profile::new(auth);
    p.milestone = mkit_server_conformance::wire::Milestone::M1;
    p.atomic_advance = true;
    p.max_pack_bytes = MAX_PACK;
    p.list_refs = 200;
    // A server started empty for this test: whole-server listings are bounded.
    p.fresh_target = true;
    p.derive_features();
    p.features.insert(Feature::Health);
    p
}

fn authv2(origin: &str) -> AuthMode {
    AuthMode::AuthV2(AuthV2Config::new(origin, REPOSITORY).unwrap())
}

fn v2_profile(origin: &str) -> Profile {
    let mut p = profile(WireAuth::AuthV2 {
        audience: origin.to_owned(),
        repository: REPOSITORY.to_owned(),
        seed: [0x5e; 32],
    });
    p.quota = Some(QuotaLimits {
        max_ops: QUOTA.max_ops,
        max_bytes: QUOTA.max_bytes,
        window_ms: QUOTA.window_ms,
    });
    p.derive_features();
    // The pipeline rejects a signature over gzip bytes (fails closed).
    p.features.insert(Feature::StrictGzipAuth);
    p.features.insert(Feature::Tickets);
    p.ticket_per_signer = 4;
    p
}

async fn check(origin: String, profile: Profile) {
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    let report = run(&target, None).await;
    if target.profile.has(Feature::Tickets) {
        for name in [
            "tickets.begin_upload_new",
            "tickets.begin_upload_idempotent",
            "tickets.begin_upload_caps",
            "tickets.begin_upload_packmap_refused",
            "tickets.upload_pack_ticketed",
            "tickets.upload_pack_bad_token",
            "tickets.upload_pack_binding_denied",
        ] {
            assert!(
                matches!(report.verdict(name), Some(Verdict::Pass(_))),
                "{name} did not pass"
            );
        }
    }
    common::judge(&report, PIPELINE_DIVERGENCES);
    for name in ["info.shape_and_policy", "info.ignores_repository_header"] {
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{name} did not run"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_open() {
    let (origin, _) = serve(|_| AuthMode::Open, None).await;
    check(origin, profile(WireAuth::None)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_bearer() {
    let auth = |_: &str| AuthMode::Bearer {
        token: Redacted::new(TOKEN),
    };
    let (origin, _) = serve(auth, None).await;
    let token = TOKEN.to_owned();
    check(origin, profile(WireAuth::Bearer { token })).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_auth_v2_quota_atomic() {
    let (origin, _) = serve(authv2, Some(QUOTA)).await;
    let profile = v2_profile(&origin);
    check(origin, profile).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_memory_multipart() {
    let (origin, _) = serve_sharding(
        authv2,
        None,
        Mutant::None,
        None,
        mkit_server::pipeline::Sharding::Single,
        MULTIPART_MAX_PACK,
    )
    .await;
    let mut profile = profile(WireAuth::AuthV2 {
        audience: origin.clone(),
        repository: REPOSITORY.to_owned(),
        seed: [0x5e; 32],
    });
    profile.max_pack_bytes = MULTIPART_MAX_PACK;
    profile.features.insert(Feature::Tickets);
    profile.features.insert(Feature::Multipart);
    let report = run(
        &WireTarget {
            base_url: origin.parse().unwrap(),
            profile,
        },
        Some("multipart."),
    )
    .await;
    common::judge(&report, PIPELINE_DIVERGENCES);
    for name in [
        "multipart.three_parts",
        "multipart.resume_receipts",
        "multipart.root_mismatch_invisible",
    ] {
        assert!(
            matches!(report.verdict(name), Some(Verdict::Pass(_))),
            "{name} did not pass"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_multi_repository() {
    let auth = |origin: &str| AuthMode::AuthV2(AuthV2Config::new(origin, "").unwrap());
    // Key derivation is independent of the audience; fix the run id before
    // startup so the allowlist and every case derive the same owners.
    let mut profile = profile(WireAuth::AuthV2 {
        audience: "http://localhost".to_owned(),
        repository: "ignored-in-multi-mode".to_owned(),
        seed: [0x5e; 32],
    });
    profile.milestone = Milestone::M1;
    profile.features.insert(Feature::MultiRepo);
    profile.features.insert(Feature::NamespacePolicy);
    profile.features.insert(Feature::Tickets);
    profile.features.insert(Feature::Multipart);
    profile.max_pack_bytes = MULTIPART_MAX_PACK;
    let (origin, _) = serve_addressing(auth, None, Mutant::None, Some(&profile)).await;
    let WireAuth::AuthV2 { audience, .. } = &mut profile.auth else {
        unreachable!()
    };
    audience.clone_from(&origin);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    // M0 cases exercise headerless reads and packs; the Multi cases
    // carry repository identities and exercise repository-scoped membership.
    let report = run(&target, Some("repo.")).await;
    let repository_report = run(&target, Some("repository.")).await;
    let multipart_report = run(&target, Some("multipart.")).await;
    let policy_report = run(&target, Some("policy.")).await;
    let ticket_repo_report = run(&target, Some("tickets.advance_other_repository")).await;
    let info_report = run(&target, Some("info.")).await;
    common::judge(&info_report, PIPELINE_DIVERGENCES);
    for name in ["info.shape_and_policy", "info.ignores_repository_header"] {
        assert!(
            matches!(info_report.verdict(name), Some(Verdict::Pass(_))),
            "{name} did not run"
        );
    }
    common::judge(&report, PIPELINE_DIVERGENCES);
    common::judge(&repository_report, PIPELINE_DIVERGENCES);
    common::judge(&multipart_report, PIPELINE_DIVERGENCES);
    assert!(matches!(
        multipart_report.verdict("multipart.cross_repository_no_oracle"),
        Some(Verdict::Pass(_))
    ));
    common::judge(&policy_report, PIPELINE_DIVERGENCES);
    common::judge(&ticket_repo_report, PIPELINE_DIVERGENCES);
    for case in mkit_server_conformance::wire::CASES.iter().filter(|c| {
        c.requires.contains(&Feature::MultiRepo)
            && !c.requires.contains(&Feature::Grants)
            && !c.requires.contains(&Feature::IndexedMode)
    }) {
        let case_report = if case.name.starts_with("policy.") {
            &policy_report
        } else if case.name.starts_with("multipart.") {
            &multipart_report
        } else if case.name.starts_with("repository.") {
            &repository_report
        } else if case.name.starts_with("tickets.") {
            &ticket_repo_report
        } else {
            &report
        };
        if case.name == "repo.membership_read_your_writes" {
            assert!(
                matches!(case_report.verdict(case.name), Some(Verdict::Skip(reason))
                if reason == "requires separate membership and ref shards (D34)")
            );
        } else {
            assert!(
                matches!(case_report.verdict(case.name), Some(Verdict::Pass(_))),
                "{} did not run",
                case.name
            );
        }
    }
}

/// D34 keeps the planted ref-shard membership separate from its lagging
/// repository index. These cases make real HTTP requests to both pack reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_d34_multi_membership() {
    let mut profile = profile(WireAuth::AuthV2 {
        audience: "http://localhost".into(),
        repository: "ignored-in-multi-mode".into(),
        seed: [0x5e; 32],
    });
    profile.features.insert(Feature::MultiRepo);
    profile.sharding_d34 = true;
    let auth = |origin: &str| AuthMode::AuthV2(AuthV2Config::new(origin, "").unwrap());
    let (origin, _) = serve_sharding(
        auth,
        None,
        Mutant::None,
        Some(&profile),
        mkit_server::pipeline::Sharding::D34,
        MAX_PACK,
    )
    .await;
    let WireAuth::AuthV2 { audience, .. } = &mut profile.auth else {
        unreachable!()
    };
    audience.clone_from(&origin);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    for case in [
        "repo.packs_need_membership",
        "repo.isolation_packs",
        "repo.membership_read_your_writes",
        "repo.malformed_membership_hint_no_op",
    ] {
        let report = run(&target, Some(case)).await;
        common::judge(&report, PIPELINE_DIVERGENCES);
        assert_eq!(report.passes(), [case], "{case} did not run and pass");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_grants_single_and_d34() {
    for sharding in [
        mkit_server::pipeline::Sharding::Single,
        mkit_server::pipeline::Sharding::D34,
    ] {
        let mut profile = profile(WireAuth::AuthV2 {
            audience: "http://localhost".into(),
            repository: "ignored-in-multi-mode".into(),
            seed: [0x5e; 32],
        });
        profile.milestone = Milestone::M2;
        profile
            .features
            .extend([Feature::MultiRepo, Feature::Grants]);
        #[cfg(feature = "test-faults")]
        profile.features.insert(Feature::TestFaults);
        profile.sharding_d34 = sharding == mkit_server::pipeline::Sharding::D34;
        let auth = |origin: &str| AuthMode::AuthV2(AuthV2Config::new(origin, "").unwrap());
        let (origin, _) = serve_sharding(
            auth,
            None,
            Mutant::None,
            Some(&profile),
            sharding,
            profile.max_pack_bytes,
        )
        .await;
        let WireAuth::AuthV2 { audience, .. } = &mut profile.auth else {
            unreachable!()
        };
        audience.clone_from(&origin);
        let target = WireTarget {
            base_url: origin.parse().unwrap(),
            profile,
        };
        for case in [
            "info.shape_and_policy",
            "grants.valid_ed25519",
            "grants.valid_secp256k1_eip191",
            "grants.valid_webauthn_p256",
            "grants.push_flow",
            "grants.part_path_ignores_header",
            "grants.zero_x_without_grant_denied",
            "grants.wrong_audience",
            "grants.repository_out_of_scope",
            "grants.namespace_scope_covers_new_repo",
            "grants.grantee_mismatch",
            "grants.read_only_grant_for_write",
            "grants.ed25519_scheme_on_0x_denied",
            "grants.webauthn_unconfigured_rp_denied",
            "grants.epoch_above_stored",
            "grants.owner_with_bad_grant_denied",
            "grants.header_without_auth_unauthenticated",
            "grants.duplicate_header_denied",
            "grants.oversize_header_denied",
            "grants.non_ascii_header_denied",
            "grants.retry_with_changed_grant_returns_saved_result",
            "ref_scopes.create_only_rejects_update",
            "ref_scopes.cu_grant_creates_but_match_update_denied_opaque",
            "ref_scopes.force_allows_non_ff",
            "ref_scopes.delete_needs_d",
            "ref_scopes.any_on_absent_needs_c",
            "ref_scopes.any_on_present_needs_f",
            "ref_scopes.direct_packmap_update_denied",
            "ref_scopes.head_only_update_ok",
            "ref_scopes.advance_wrong_packmap_denied",
            "ref_scopes.rebaseline_push_under_head_scope",
            "ref_scopes.begin_upload_any_flag",
            "ref_scopes.begin_upload_unmatched_denied",
            "epochs.get_unsigned_zero",
            "epochs.get_ignores_auth_headers",
            "epochs.get_bad_namespace_invalid_argument",
            "epochs.set_advances_and_get_reflects",
            "epochs.set_retry_same_epoch",
            "epochs.set_over_step_denied",
            "epochs.set_decrease_denied",
            "epochs.wrong_audience",
            "epochs.expired",
            "epochs.not_yet_valid",
            "epochs.scheme_not_advertised",
            "epochs.namespace_not_served",
            "epochs.oversize_statement",
            "epochs.zero_x_secp256k1_statement",
            "epochs.zero_x_webauthn_statement",
            "epochs.old_grant_denied_new_grant_works_after_set",
            #[cfg(feature = "test-faults")]
            "grants.expired",
            #[cfg(feature = "test-faults")]
            "grants.not_yet_valid",
            #[cfg(feature = "test-faults")]
            "grants.epoch_below_stored",
            #[cfg(feature = "test-faults")]
            "grants.new_epoch_grant_works",
        ] {
            let report = run(&target, Some(case)).await;
            common::judge(&report, PIPELINE_DIVERGENCES);
            assert_eq!(report.passes(), [case], "{case} did not run and pass");
        }
    }
}

/// The `test-faults` profile: an auth v2 server whose quota window is
/// short enough for the growth case to wait out (it prunes on the real
/// clock: about 80 s), with room for the case's probe writes.
#[cfg(feature = "test-faults")]
async fn serve_test_faults(mutant: Mutant) -> WireTarget {
    let quota = ServerQuota {
        window_ms: 5_000,
        max_ops: 1_000,
        ..QUOTA
    };
    let (origin, _) = serve_mutant(authv2, Some(quota), mutant).await;
    let mut profile = v2_profile(&origin);
    profile.quota = Some(QuotaLimits {
        max_ops: quota.max_ops,
        max_bytes: quota.max_bytes,
        window_ms: quota.window_ms,
    });
    profile.features.insert(Feature::TestFaults);
    WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    }
}

/// The `test-faults` cases: the clock-skew directive and the stats
/// endpoint. The rest of the suite ran on the auth v2 profile above.
#[cfg(feature = "test-faults")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_auth_v2_test_faults() {
    let target = serve_test_faults(Mutant::None).await;
    for case in [
        "timers.directive_fires_due",
        "timers.redelivery_is_idempotent",
        "replay.expired_retry_rejected",
        "growth.replay_and_quota_pruned",
    ] {
        let report = run(&target, Some(case)).await;
        common::judge(&report, PIPELINE_DIVERGENCES);
        assert_eq!(report.passes(), [case], "{case} did not run and pass");
    }
}

/// Run each case in `cases` alone against `target`; each must fail.
async fn must_fail(target: &WireTarget, cases: &[&str]) {
    for case in cases {
        let report = run(target, Some(case)).await;
        eprintln!("{}", report.tap());
        assert!(
            matches!(report.verdict(case), Some(Verdict::Fail(_))),
            "{case} did not catch the mutant: {:?}",
            report.verdict(case)
        );
    }
}

/// A read-then-write compare-and-swap lets several racers win: the
/// concurrent cases must catch it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutant_read_then_write_fails_concurrent_cas() {
    let (origin, _) = serve_mutant(|_| AuthMode::Open, None, Mutant::ReadThenWrite).await;
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile: profile(WireAuth::None),
    };
    let cases = [
        "refs.concurrent_missing_one_winner",
        "refs.concurrent_match_one_winner",
        "advance.concurrent_one_committed",
    ];
    must_fail(&target, &cases).await;
}

/// A store that never deletes never prunes: the growth case must catch it.
#[cfg(feature = "test-faults")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutant_no_prune_fails_growth() {
    let target = serve_test_faults(Mutant::NoPrune).await;
    must_fail(&target, &["growth.replay_and_quota_pruned"]).await;
}

/// A store that prunes records but leaks their index rows: the growth
/// case's exact key-count bound must catch it.
#[cfg(feature = "test-faults")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutant_index_leak_fails_growth() {
    let target = serve_test_faults(Mutant::LeakIndex).await;
    must_fail(&target, &["growth.replay_and_quota_pruned"]).await;
}

/// The epoch-lease case runs through HTTP against real D34 partitions,
/// with a stored lease check after both writes to prove the bumped epoch
/// reached the ref shard.
#[cfg(feature = "test-faults")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pipeline_d34_epoch_leases() {
    use mkit_server::pipeline::{D34Shards, ShardMap, Sharding};
    use mkit_server::store::{codec, keys};

    let (origin, meta) =
        serve_sharding(authv2, None, Mutant::None, None, Sharding::D34, MAX_PACK).await;
    let mut profile = v2_profile(&origin);
    profile.quota = None;
    profile.derive_features();
    profile.milestone = Milestone::M1;
    profile.sharding_d34 = true;
    profile.features.insert(Feature::TestFaults);
    profile.features.insert(Feature::EpochLeases);
    let case = "leases.bump_completes_and_writes_continue";
    let name = format!("refs/heads/conformance/{}/{case}/main", profile.run_id);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    let report = run(&target, Some(case)).await;
    common::judge(&report, PIPELINE_DIVERGENCES);
    assert_eq!(report.passes(), [case]);
    let tickets = run(&target, Some("tickets.")).await;
    common::judge(&tickets, PIPELINE_DIVERGENCES);
    let applicable = mkit_server_conformance::wire::CASES
        .iter()
        .filter(|case| {
            case.name.starts_with("tickets.") && case.skip_reason(&target.profile).is_none()
        })
        .count();
    assert_eq!(
        tickets.passes().len(),
        applicable,
        "all ticket cases run under D34"
    );

    let repo = RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPOSITORY).unwrap(),
    };
    let shard = D34Shards.ref_shard(&repo, &name);
    let value = meta
        .get(&shard, &keys::epoch_lease())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(codec::decode_epoch_lease(&value).unwrap().epoch, 1);
    assert!(
        meta.get(&Partition::Namespace(repo.namespace), &keys::epoch_lease())
            .await
            .unwrap()
            .is_none(),
        "D34 wire coverage must not use the Single partition"
    );
}
