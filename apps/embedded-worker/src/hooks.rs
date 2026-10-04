// SPDX-License-Identifier: MIT OR Apache-2.0
use std::sync::Arc;

use mkit_server::pipeline::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, DefaultAdmission, DeliveryError,
    Hooks, NoPreReceive, NoReceipts, Outcome, OutcomeKind, OutcomeSink,
};
use mkit_server::purge::{PurgeSink, Request as PurgeRequest};
use mkit_server::{AuthzFacts, BoxFuture, Operation, ServerError, StoreError};
use mkit_server_worker::adapter::{ConfigError, WorkerConfig};
use mkit_server_worker::embedding::{HookCapabilities, PurgeHooks};
use mkit_server_worker::purge::{LocalCache, WorkerCache};
use worker::{Env, Method, Request, RequestInit};

use crate::receiver::Delivery;

pub struct HostAuthorize;
impl Authorizer for HostAuthorize {
    async fn authorize(&self, op: &Operation) -> Result<AuthzFacts, ServerError> {
        // Envelope verification already ran. This Check hook adds no authority.
        worker::console_log!("REFERENCE authorize {}", op.procedure().connect_path());
        Ok(op.authz.clone())
    }
}
pub struct HostAdmit;
impl Admission for HostAdmit {
    async fn admit(&self, input: &AdmissionInput<'_>) -> Result<AdmissionDecision, ServerError> {
        worker::console_log!("REFERENCE admit {}", input.op.procedure().connect_path());
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
pub struct HostOutcome(Env);
impl OutcomeSink for HostOutcome {
    async fn deliver(&self, outcome: &Outcome) -> Result<(), DeliveryError> {
        let result = async {
            let ns = self.0.durable_object("HOST_EVENTS")?;
            // One receiver per repository; no public receiver route.
            let stub = ns
                .id_from_name(&format!("{}:{}", outcome.audience, outcome.repository))?
                .get_stub()?;
            let counter = match outcome.kind {
                OutcomeKind::RepoStorageChanged {
                    stored_bytes,
                    version,
                } => Some((stored_bytes, version)),
                _ => None,
            };
            let kind = match outcome.kind {
                OutcomeKind::Committed { .. } => "committed",
                OutcomeKind::RepoStorageChanged { .. } => "storage",
                _ => "terminal",
            };
            let body = serde_json::to_string(&Delivery {
                reservation_id: outcome.reservation_id.clone(),
                kind: kind.into(),
                counter,
            })?;
            let mut init = RequestInit::new();
            init.with_method(Method::Post).with_body(Some(body.into()));
            let response = stub
                .fetch_with_request(Request::new_with_init("https://events.invalid/", &init)?)
                .await?;
            if response.status_code() != 200 {
                return Err(worker::Error::RustError("receiver unavailable".into()));
            }
            worker::console_log!("REFERENCE outcome {} {}", kind, outcome.reservation_id);
            Ok::<_, worker::Error>(())
        }
        .await;
        result.map_err(|_| {
            worker::console_log!("REFERENCE outcome retry {}", outcome.reservation_id);
            DeliveryError::new("host receiver unavailable", None)
        })
    }
}
pub struct HostPurge;
impl PurgeSink for HostPurge {
    fn deliver<'a>(&'a self, request: &'a PurgeRequest) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            request.validate()?;
            // Paired LocalCache completed first. This host has no other serving cache.
            // A host with a CDN must invalidate it before acknowledging here.
            worker::console_log!("REFERENCE purge delivered");
            Ok(())
        })
    }
}
pub fn config(env: &Env) -> Result<WorkerConfig, ConfigError> {
    let mut cfg = WorkerConfig::from_env_with_hooks(
        env,
        HookCapabilities {
            authorizer: Some(mkit_server::policy::AuthorizerRole::Check),
            admission: true,
            outcomes: true,
        },
        Some(PurgeHooks::new(
            Arc::new(HostPurge),
            Arc::new(LocalCache { cache: WorkerCache }),
        )),
    )?;
    cfg.admin_on_public_path = false;
    cfg.validate()?;
    Ok(cfg)
}
pub type HostHooks = Hooks<HostAuthorize, HostAdmit, NoPreReceive, NoReceipts, HostOutcome>;
pub fn hooks(env: &Env, cfg: &WorkerConfig) -> Result<HostHooks, ConfigError> {
    Ok(Hooks {
        authorizer: HostAuthorize,
        admission: HostAdmit,
        pre_receive: NoPreReceive,
        receipts: NoReceipts,
        outcomes: sink(env, cfg)?,
    })
}
pub fn sink(env: &Env, _: &WorkerConfig) -> Result<HostOutcome, ConfigError> {
    Ok(HostOutcome(env.clone()))
}
