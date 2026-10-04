// SPDX-License-Identifier: MIT OR Apache-2.0
use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, Challenge, DefaultAdmission,
    DeliveryError, Hooks, NoPreReceive, NoReceipts, Outcome, OutcomeKind, OutcomeSink,
};
use mkit_server::purge::{PurgeSink, Request as PurgeRequest};
use mkit_server::{AuthzFacts, Operation, Procedure};
use mkit_server::{BoxFuture, ServerError, StoreError};
use mkit_server_worker::adapter::{self, ConfigError, WorkerConfig};
use mkit_server_worker::embedding::{HookCapabilities, PurgeHooks};
use mkit_server_worker::purge::{LocalCache, WorkerCache};
use std::sync::Arc;
use worker::{Context, Env, Request, RequestInit, Response, Result, event};

struct HostAuthorize {
    fenced: bool,
}
impl Authorizer for HostAuthorize {
    async fn authorize(&self, op: &Operation) -> core::result::Result<AuthzFacts, ServerError> {
        // Multi owner/grant enforcement already established these facts.
        worker::console_log!(
            "MKIT_EMBED_STAGE authorize {}",
            op.procedure().connect_path()
        );
        let mut facts = op.authz.clone();
        if self.fenced {
            facts.authority_generation = Some(0);
        }
        Ok(facts)
    }
}
struct HostAdmit;
impl Admission for HostAdmit {
    async fn admit(
        &self,
        input: &AdmissionInput<'_>,
    ) -> core::result::Result<AdmissionDecision, ServerError> {
        worker::console_log!(
            "MKIT_EMBED_STAGE admit {}",
            input.op.procedure().connect_path()
        );
        // This fixed local pricing example challenges the dedicated 13-byte probe.
        if input.op.procedure() == Procedure::BeginUpload && input.declared_bytes == 13 {
            return Ok(AdmissionDecision::challenge(
                vec![Challenge {
                    scheme: "embedding-local".into(),
                    value: "fixture".into(),
                }],
                "local acceptance payment challenge",
            ));
        }
        if matches!(input.op.procedure(), Procedure::HttpGetObject) {
            let paid = input.credential_headers.iter().any(|h| {
                h.name.eq_ignore_ascii_case("authorization")
                    && h.value.expose() == "Payment embedding-fixture"
            });
            if !paid {
                return Ok(AdmissionDecision::challenge(
                    vec![Challenge {
                        scheme: "embedding-local".into(),
                        value: "embedding-fixture".into(),
                    }],
                    "local read payment challenge",
                ));
            }
            thread_local! { static SERIAL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
            let serial = SERIAL.with(|counter| {
                let next = counter.get() + 1;
                counter.set(next);
                next
            });
            let reservation = format!("embedding-read:{serial}");
            return Ok(AdmissionDecision::allow(Vec::new())
                .with_reservation(&reservation)
                .with_response_header("Payment-Receipt", reservation));
        }
        let mut decision = DefaultAdmission.admit(input).await?;
        if input.op.procedure().is_write()
            && let Some(nonce) = input.idempotency_key
        {
            decision = decision.with_reservation(nonce);
        }
        Ok(decision)
    }
}
#[derive(Clone)]
struct HostOutcome {
    fail_committed: bool,
}
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
        if self.fail_committed && matches!(outcome.kind, OutcomeKind::Committed { .. }) {
            worker::console_log!(
                "MKIT_EMBED_OUTCOME_RETRY {} {}",
                kind,
                outcome.reservation_id
            );
            return Err(DeliveryError::new(
                "local fixture sink unavailable",
                Some(std::time::Duration::from_secs(60)),
            ));
        }
        let bytes = match outcome.kind {
            OutcomeKind::ReadServed { bytes_served, .. } => bytes_served,
            _ => 0,
        };
        worker::console_log!(
            "MKIT_EMBED_OUTCOME {} {} {}",
            kind,
            outcome.reservation_id,
            bytes
        );
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
            // Core delivery has completed paired LocalCache under the shared purse.
            // This callback acknowledges only that local work, not deployed CDN purge.
            // It performs no additional physical cache/API calls.
            request.validate()?;
            worker::console_log!("MKIT_EMBED_PURGE delivered");
            Ok(())
        })
    }
}
fn config(env: &Env) -> core::result::Result<WorkerConfig, ConfigError> {
    let purge = PurgeHooks::new(
        Arc::new(HostPurge),
        Arc::new(LocalCache { cache: WorkerCache }),
    );
    let capabilities = HookCapabilities {
        authorizer: Some(
            if env
                .var("AUTHORITY_FENCE")
                .is_ok_and(|v| v.to_string() == "true")
            {
                mkit_server::policy::AuthorizerRole::Authority
            } else {
                mkit_server::policy::AuthorizerRole::Check
            },
        ),
        admission: true,
        outcomes: true,
    };
    let mut cfg = WorkerConfig::from_env_with_hooks(env, capabilities, Some(purge))?;
    cfg.admin_on_public_path = false;
    cfg.validate()?;
    Ok(cfg)
}
type HostHooks = Hooks<HostAuthorize, HostAdmit, NoPreReceive, NoReceipts, HostOutcome>;
fn hooks(env: &Env, cfg: &WorkerConfig) -> core::result::Result<HostHooks, ConfigError> {
    Ok(Hooks {
        authorizer: HostAuthorize {
            fenced: cfg.authority_fence.is_some(),
        },
        admission: HostAdmit,
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: sink(env, cfg)?,
    })
}
fn sink(env: &Env, _: &WorkerConfig) -> core::result::Result<HostOutcome, ConfigError> {
    Ok(HostOutcome {
        fail_committed: env
            .var("FIXTURE_OUTCOME_FAIL")
            .is_ok_and(|v| v.to_string() == "true"),
    })
}
mkit_server_worker::durable_objects!(config, sink);

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    std::panic::set_hook(Box::new(|info| {
        worker::console_error!("MKIT_EMBED_PANIC {info}")
    }));
    let mut cfg = config(&env)
        .map_err(|_| worker::Error::RustError("Embedding fixture configuration refused".into()))?;
    cfg.http_mount = cfg.http_mount.take().map(|mount| mount.with_context(ctx));
    let path = req.path();
    let internal_admin = path.strip_prefix("/_embedding/operator");
    if path.starts_with("/mkit.server.admin.v1/") {
        return Response::error("public admin route absent", 404);
    }
    let target = internal_admin.unwrap_or(&path);
    let mut init = RequestInit::new();
    init.with_method(req.method())
        .with_headers(req.headers().clone())
        .with_body(req.inner().body().map(Into::into));
    let query = req
        .url()?
        .query()
        .map_or_else(String::new, |raw| format!("?{raw}"));
    let request = Request::new_with_init(
        &format!("https://embedding.internal.invalid{target}{query}"),
        &init,
    )?;
    if internal_admin.is_some() {
        adapter::serve_admin_with(request, env, &cfg).await
    } else {
        adapter::serve_with(request, env, &cfg, hooks).await
    }
}
