//! Optional authority fence RPCs; independent of the grant epoch.

use super::{
    AuthMode, HookSet, Pipeline, meta_error, ms,
    revocation::{RevokeBudget, RevokeProgress},
};
use crate::{
    authority::FenceKind,
    error::ServerError,
    policy::NamespacePolicy,
    repo::{Addressing, NamespaceKey},
    store::{MultipartBlobStore, NamespaceStore, codec, keys},
};
use mkit_attest::grant::EpochTransition;
use mkit_core::repo_identity::Namespace;

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    pub(super) async fn stored_authority_generation(
        &self,
        ns: &NamespaceKey,
    ) -> Result<u64, ServerError> {
        self.meta
            .get(&self.shards.coordinator(ns), &keys::authority_generation())
            .await
            .map_err(meta_error)?
            .as_ref()
            .map(codec::decode_u64)
            .transpose()
            .map_err(meta_error)
            .map(|generation| generation.unwrap_or(0))
    }

    /// Establish durable mode without creating an accounting namespace, then
    /// complete the shared initial barrier before issuing any fenced grant.
    pub(super) async fn ensure_authority_activation(
        &self,
        ns: &NamespaceKey,
    ) -> Result<Option<u64>, ServerError> {
        let p = self.shards.coordinator(ns);
        let wanted = [keys::authority_generation(), keys::lease_recovery()];
        for _ in 0..1 {
            let rows = self.meta.get_many(&p, &wanted).await.map_err(meta_error)?;
            let [generation, raw_mode] = rows.as_slice() else {
                return Err(super::internal("authority activation row count"));
            };
            let current = generation
                .as_ref()
                .map(codec::decode_u64)
                .transpose()
                .map_err(meta_error)?
                .unwrap_or(0);
            let mut mode = raw_mode
                .as_ref()
                .map(codec::decode_lease_recovery)
                .transpose()
                .map_err(meta_error)?
                .unwrap_or(codec::LeaseRecovery {
                    resumed_at_ms: 0,
                    authority_fence: None,
                    authority_ready: None,
                    activation_only: Some(true),
                });
            if self.cfg.authority_fence.is_none() {
                if generation.is_some() || mode.authority_fence == Some(true) {
                    return Err(ServerError::unavailable(
                        "persisted authority fence requires enabled executor",
                    ));
                }
                return Ok(None);
            }
            if mode.authority_fence == Some(true) && generation.is_none() {
                return Err(ServerError::unavailable(
                    "authority generation missing from fenced namespace",
                ));
            }
            if mode.authority_fence != Some(true) {
                mode.authority_fence = Some(true);
                mode.authority_ready = Some(false);
                let batch = crate::store::Batch::new()
                    .require(super::lease::observed_guard(
                        wanted[0].clone(),
                        generation.as_ref(),
                    ))
                    .require(super::lease::observed_guard(
                        wanted[1].clone(),
                        raw_mode.as_ref(),
                    ))
                    .put(wanted[0].clone(), codec::encode_u64(current))
                    .put(wanted[1].clone(), codec::encode_lease_recovery(&mode));
                match self.meta.apply(&p, batch).await.map_err(meta_error)? {
                    crate::store::BatchOutcome::Committed => {}
                    crate::store::BatchOutcome::PreconditionFailed { .. } => continue,
                    crate::store::BatchOutcome::DeadlinePassed { .. } => {
                        return Err(super::internal("activation had no deadline"));
                    }
                }
                // Use the installed raw value below; the barrier itself rereads
                // generation and recovery, and the ready CAS guards both.
            }
            if mode.authority_ready == Some(true) {
                return Ok(None);
            }
            if self
                .revoke_fence_step(ns, &RevokeBudget::default(), FenceKind::Authority)
                .await?
                != RevokeProgress::Complete
            {
                return Err(
                    ServerError::unavailable("authority activation pending; retry")
                        .with_header("Retry-After", "1"),
                );
            }
            let prior = codec::encode_lease_recovery(&mode);
            mode.authority_ready = Some(true);
            let batch = crate::store::Batch::new()
                .require(crate::store::Precondition::Equals(
                    wanted[0].clone(),
                    codec::encode_u64(current),
                ))
                .require(crate::store::Precondition::Equals(wanted[1].clone(), prior))
                .put(wanted[1].clone(), codec::encode_lease_recovery(&mode));
            match self.meta.apply(&p, batch).await.map_err(meta_error)? {
                crate::store::BatchOutcome::Committed => return Ok(Some(current)),
                crate::store::BatchOutcome::PreconditionFailed { .. } => {}
                crate::store::BatchOutcome::DeadlinePassed { .. } => {
                    return Err(super::internal("activation ready had no deadline"));
                }
            }
        }
        Err(
            ServerError::unavailable("authority activation contention; retry")
                .with_header("Retry-After", "1"),
        )
    }

    // Keep streaming-session futures small while the authoritative read is pending.
    pub(super) fn check_ticket_generation<'a>(
        &'a self,
        ns: &'a NamespaceKey,
        generation: Option<u64>,
    ) -> crate::BoxFuture<'a, Result<(), ServerError>> {
        Box::pin(async move {
            if self.cfg.authority_fence.is_none() {
                if generation.is_some() {
                    return Err(ServerError::unavailable(
                        "fenced ticket requires enabled executor",
                    ));
                }
                Box::pin(self.ensure_authority_activation(ns)).await?;
            } else {
                // A generation-bearing authenticated ticket is issued only after
                // activation. Do not repeat the activation scan on every chunk.
                let current = self
                    .meta
                    .get(&self.shards.coordinator(ns), &keys::authority_generation())
                    .await
                    .map_err(meta_error)?;
                let current = current
                    .as_ref()
                    .map(codec::decode_u64)
                    .transpose()
                    .map_err(meta_error)?
                    .ok_or_else(|| {
                        ServerError::unavailable(
                            "authority generation missing from fenced namespace",
                        )
                    })?;
                if generation != Some(current) {
                    return Err(crate::authority::moved());
                }
            }
            Ok(())
        })
    }

    /// Read the optional namespace authority generation outside auth-v2.
    /// # Errors
    /// Disabled fencing, invalid namespace or storage failure.
    pub async fn get_authority_generation(&self, namespace: &str) -> Result<u64, ServerError> {
        if self.cfg.authority_fence.is_none() {
            return Err(ServerError::unimplemented("authority fencing is disabled"));
        }
        let ns = Namespace::parse(namespace)
            .map_err(|_| ServerError::invalid_argument("invalid namespace"))?;
        self.authority_namespace(&ns).await?;
        self.stored_authority_generation(&NamespaceKey::from_namespace(&ns))
            .await
    }

    async fn authority_namespace(&self, ns: &Namespace) -> Result<(), ServerError> {
        let Addressing::Multi(multi) = &self.cfg.addressing else {
            return Err(ServerError::unimplemented(
                "authority fencing requires multi addressing",
            ));
        };
        match &multi.namespace_policy {
            NamespacePolicy::Allowlist(allowed) if allowed.contains(ns) => Ok(()),
            NamespacePolicy::Any { .. } if matches!(ns, Namespace::Ed25519(_)) => {
                let key = NamespaceKey::from_namespace(ns);
                if self
                    .meta
                    .get(&self.shards.coordinator(&key), &keys::namespace_record())
                    .await
                    .map_err(meta_error)?
                    .is_some()
                {
                    Ok(())
                } else {
                    Err(ServerError::permission_denied("namespace not served"))
                }
            }
            _ => Err(ServerError::permission_denied("namespace not served")),
        }
    }

    /// Verify a deployment statement, install its target and finish the lease barrier.
    /// Completion retries are idempotent; each call scans at most one four-shard slice.
    /// # Errors
    /// Disabled configuration, rejected statement or pending completion (`Retry-After: 1`).
    pub async fn set_authority_generation(&self, wire: &str) -> Result<u64, ServerError> {
        let fence = self
            .cfg
            .authority_fence
            .as_ref()
            .ok_or_else(|| ServerError::unimplemented("authority fencing is disabled"))?;
        let AuthMode::AuthV2(auth) = &self.cfg.auth else {
            return Err(ServerError::unimplemented(
                "authority fencing requires auth-v2",
            ));
        };
        let statement = fence.verify(wire, auth.audience(), self.clock.now_ms())?;
        self.authority_namespace(&statement.namespace).await?;
        let ns = NamespaceKey::from_namespace(&statement.namespace);
        if self
            .transition_fence(&ns, statement.generation, FenceKind::Authority)
            .await?
            == EpochTransition::Reject
        {
            return Err(ServerError::permission_denied(
                "authority generation step rejected",
            ));
        }
        if let Some(completed) = Box::pin(self.ensure_authority_activation(&ns)).await? {
            if self.stored_authority_generation(&ns).await? == completed {
                return Ok(completed);
            }
            return Err(
                ServerError::unavailable("authority revocation pending; retry")
                    .with_header("Retry-After", "1"),
            );
        }
        let start = ms(self.clock.now_ms());
        for _ in 0..1 {
            let elapsed = ms(self.clock.now_ms()).saturating_sub(start);
            if elapsed >= 5_000 {
                break;
            }
            let before = self.stored_authority_generation(&ns).await?;
            let budget = RevokeBudget::new((5_000 - elapsed).min(1_000));
            if self
                .revoke_fence_step(&ns, &budget, FenceKind::Authority)
                .await?
                == RevokeProgress::Complete
            {
                let after = self.stored_authority_generation(&ns).await?;
                if before == after {
                    return Ok(after);
                }
            }
        }
        Err(
            ServerError::unavailable("authority revocation pending; retry")
                .with_header("Retry-After", "1"),
        )
    }
}
