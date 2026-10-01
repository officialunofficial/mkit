// SPDX-License-Identifier: MIT OR Apache-2.0
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, Challenge, DefaultAdmission,
    DeliveryError, Hooks, NoPreReceive, NoReceipts, Outcome, OutcomeKind, OutcomeSink,
};
use mkit_server::purge::{LocalInvalidation, PurgeSink, Request as PurgeRequest, SliceBudget};
use mkit_server::{AuthzFacts, Operation, Procedure};
use mkit_server::{BoxFuture, ServerError, StoreError};
use mkit_server_worker::adapter::{self, ConfigError, WorkerConfig};
use mkit_server_worker::embedding::PurgeHooks;
use mkit_server_worker::purge::{LocalCache, WorkerCache};
use std::sync::Arc;
use worker::{Context, Env, Request, RequestInit, Response, Result, event};

struct HostAuthorize;
impl Authorizer for HostAuthorize {
    async fn authorize(&self, op: &Operation) -> core::result::Result<AuthzFacts, ServerError> {
        // Multi owner/grant enforcement already established these facts.
        worker::console_log!("MKIT_UNO_STAGE authorize {}", op.procedure().connect_path());
        Ok(op.authz.clone())
    }
}
struct HostAdmit;
impl Admission for HostAdmit {
    async fn admit(
        &self,
        input: &AdmissionInput<'_>,
    ) -> core::result::Result<AdmissionDecision, ServerError> {
        worker::console_log!(
            "MKIT_UNO_STAGE admit {}",
            input.op.procedure().connect_path()
        );
        // This fixed local pricing example challenges the dedicated 13-byte probe.
        if input.op.procedure() == Procedure::BeginUpload && input.declared_bytes == 13 {
            return Ok(AdmissionDecision::challenge(
                vec![Challenge {
                    scheme: "uno-local".into(),
                    value: "fixture".into(),
                }],
                "local acceptance payment challenge",
            ));
        }
        let mut decision = DefaultAdmission.admit(input).await?;
        if input.op.procedure().is_write() {
            if let Some(nonce) = input.idempotency_key {
                decision = decision.with_reservation(nonce);
            }
        }
        Ok(decision)
    }
}
#[derive(Clone)]
struct HostOutcome;
impl OutcomeSink for HostOutcome {
    async fn deliver(&self, outcome: &Outcome) -> core::result::Result<(), DeliveryError> {
        // The host callback records bounded metadata, never body or auth bytes.
        let kind = match outcome.kind {
            OutcomeKind::Committed { .. } => "committed",
            OutcomeKind::Aborted { .. } => "aborted",
            OutcomeKind::Expired => "expired",
            OutcomeKind::ReadServed { .. } => "read",
            _ => "other",
        };
        worker::console_log!("MKIT_UNO_OUTCOME {} {}", kind, outcome.reservation_id);
        Ok(())
    }
}
struct HostPurge;
impl PurgeSink for HostPurge {
    fn deliver<'a>(
        &'a self,
        request: &'a PurgeRequest,
    ) -> BoxFuture<'a, core::result::Result<(), StoreError>> {
        Box::pin(async move {
            // A real cache invalidator for this single local cache fixture.
            // This is not a claim of global deployed CDN purge coverage.
            let local = LocalCache {
                cache: WorkerCache,
                snapshot_deployment: None,
            };
            let budget = SliceBudget::new(64);
            if local.invalidate(request, 0, &budget).await?.is_some() {
                return Err(StoreError::Unavailable(
                    "local fixture purge incomplete".into(),
                ));
            }
            worker::console_log!("MKIT_UNO_PURGE delivered");
            Ok(())
        })
    }
}
fn config(env: &Env) -> core::result::Result<WorkerConfig, ConfigError> {
    let purge = PurgeHooks::new(
        Arc::new(HostPurge),
        Arc::new(LocalCache {
            cache: WorkerCache,
            snapshot_deployment: None,
        }),
    );
    let mut cfg = WorkerConfig::from_env_with_purge(env, purge)?;
    cfg.admin_on_public_path = false;
    cfg.validate()?;
    Ok(cfg)
}
type HostHooks = Hooks<HostAuthorize, HostAdmit, NoPreReceive, NoReceipts, HostOutcome>;
fn hooks(_: &Env, _: &WorkerConfig) -> core::result::Result<HostHooks, ConfigError> {
    Ok(Hooks {
        authorizer: HostAuthorize,
        admission: HostAdmit,
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: HostOutcome,
    })
}
fn sink(_: &Env, _: &WorkerConfig) -> core::result::Result<HostOutcome, ConfigError> {
    Ok(HostOutcome)
}
mkit_server_worker::durable_objects!(config, sink);

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let mut cfg = config(&env)
        .map_err(|_| worker::Error::RustError("Uno fixture configuration refused".into()))?;
    cfg.http_mount = cfg.http_mount.take().map(|mount| mount.with_context(ctx));
    let path = req.path();
    let internal_admin = path.strip_prefix("/_uno/operator");
    if path.starts_with("/mkit.server.admin.v1/") {
        return Response::error("public admin route absent", 404);
    }
    let target = internal_admin.unwrap_or(&path);
    let mut init = RequestInit::new();
    init.with_method(req.method())
        .with_headers(req.headers().clone())
        .with_body(req.inner().body().map(Into::into));
    let request = Request::new_with_init(&format!("https://uno.internal.invalid{target}"), &init)?;
    if internal_admin.is_some() {
        adapter::serve_admin_with(request, env, &cfg).await
    } else {
        adapter::serve_with(request, env, &cfg, hooks).await
    }
}
