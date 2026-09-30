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

    pub(super) async fn check_ticket_generation(
        &self,
        ns: &NamespaceKey,
        generation: Option<u64>,
    ) -> Result<(), ServerError> {
        if self.cfg.authority_fence.is_some()
            && generation != Some(self.stored_authority_generation(ns).await?)
        {
            return Err(crate::authority::moved());
        }
        Ok(())
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
    /// Completion retries are idempotent; each call scans at most five four-shard slices.
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
        let start = ms(self.clock.now_ms());
        for _ in 0..5 {
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
