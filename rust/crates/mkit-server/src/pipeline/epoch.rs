//! Unsigned namespace epoch RPCs (SPEC-WRITE-GRANTS §§5.2–5.4).

use mkit_attest::grant::{EpochTransition, GrantError, MAX_GRANT_HEADER_BYTES};
use mkit_core::hash::to_hex_bytes;
use mkit_core::repo_identity::Namespace;

use crate::error::ServerError;
use crate::policy::NamespacePolicy;
use crate::repo::{Addressing, NamespaceKey};
use crate::store::{MultipartBlobStore, NamespaceStore, codec, keys};

use super::{
    HookSet, Pipeline, meta_error, ms,
    revocation::{RevokeBudget, RevokeProgress},
};

/// At most five revocation slices and five seconds per SetGrantEpoch request.
/// The slice count also terminates when the injected clock is frozen.
const MAX_REVOKE_SLICES: usize = 5;
const MAX_REVOKE_ELAPSED_MS: u64 = 5_000;

fn rejected(reason: &str) -> ServerError {
    ServerError::permission_denied(format!("epoch statement rejected: {reason}"))
}

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Read a namespace epoch without authentication or repository resolution.
    ///
    /// # Errors
    /// `invalid_argument` for a bad namespace, `unimplemented` under Single,
    /// or a mapped storage error.
    pub async fn get_grant_epoch(&self, namespace: &str) -> Result<u64, ServerError> {
        let namespace = Namespace::parse(namespace)
            .map_err(|_| ServerError::invalid_argument("invalid namespace"))?;
        let Addressing::Multi(multi) = &self.cfg.addressing else {
            return Err(ServerError::unimplemented(
                "grant epochs require multi-repository addressing",
            ));
        };
        let key = NamespaceKey::from_namespace(&namespace);
        let coordinator = self.shards.coordinator(&key);
        match &multi.namespace_policy {
            NamespacePolicy::Allowlist(allowed) if !allowed.contains(&namespace) => return Ok(0),
            NamespacePolicy::Any { .. } => {
                // A 0x namespace is served only through an allowlist. Under
                // Any, even an existing record cannot make it grant-writable.
                if matches!(namespace, Namespace::Address(_)) {
                    return Ok(0);
                }
                if self
                    .meta
                    .get(&coordinator, &keys::namespace_record())
                    .await
                    .map_err(meta_error)?
                    .is_none()
                {
                    return Ok(0);
                }
            }
            _ => {}
        }
        self.meta
            .get(&coordinator, &keys::grant_epoch())
            .await
            .map_err(meta_error)?
            .as_ref()
            .map(codec::decode_u64)
            .transpose()
            .map_err(meta_error)
            .map(|epoch| epoch.unwrap_or(0))
    }

    /// Verify an owner epoch statement, CAS the coordinator epoch, then
    /// fence every leased shard before reporting completion.
    ///
    /// # Errors
    /// `permission_denied` for a rejected statement, `unimplemented` under
    /// Single, or `unavailable` while completion is pending.
    pub async fn set_grant_epoch(&self, signed_statement: &str) -> Result<u64, ServerError> {
        let Addressing::Multi(multi) = &self.cfg.addressing else {
            return Err(ServerError::unimplemented(
                "grant epochs require multi-repository addressing",
            ));
        };
        // Check the byte count before the header's base64 decoding or any
        // expensive signature work (§5.2 check 1).
        if signed_statement.len() > MAX_GRANT_HEADER_BYTES {
            return Err(rejected(GrantError::HeaderTooLong.reason()));
        }
        let config = self
            .cfg
            .grants
            .as_ref()
            .ok_or_else(|| rejected(GrantError::SchemeNotAdvertised.reason()))?;
        let verified = config
            .verify_epoch(signed_statement, self.clock.now_ms())
            .map_err(|error| rejected(error.reason()))?;
        let statement = verified.statement();
        let namespace = &statement.namespace;
        let key = NamespaceKey::from_namespace(namespace);

        // §5.2 check 6. Allowlisted namespaces can raise an epoch before a
        // repository exists. Under Any, only an admitted write can create
        // the namespace record that makes a later epoch change acceptable.
        match &multi.namespace_policy {
            NamespacePolicy::Allowlist(allowed) if !allowed.contains(namespace) => {
                return Err(rejected("namespace not served"));
            }
            NamespacePolicy::Any { .. } => {
                if matches!(namespace, Namespace::Address(_)) {
                    return Err(rejected("namespace not served"));
                }
                let coordinator = self.shards.coordinator(&key);
                if self
                    .meta
                    .get(&coordinator, &keys::namespace_record())
                    .await
                    .map_err(meta_error)?
                    .is_none()
                {
                    return Err(rejected("namespace not served"));
                }
            }
            _ => {}
        }

        tracing::debug!(statement_id = %to_hex_bytes(verified.id()), "epoch statement accepted");
        if self.transition_epoch(&key, statement.new_epoch).await? == EpochTransition::Reject {
            return Err(rejected("epoch step"));
        }

        let start = ms(self.clock.now_ms());
        for _ in 0..MAX_REVOKE_SLICES {
            let elapsed = ms(self.clock.now_ms()).saturating_sub(start);
            if elapsed >= MAX_REVOKE_ELAPSED_MS {
                break;
            }
            let budget = RevokeBudget::new((MAX_REVOKE_ELAPSED_MS - elapsed).min(1_000));
            if self.revoke_step(&key, &budget).await? == RevokeProgress::Complete {
                return Ok(statement.new_epoch);
            }
        }
        Err(ServerError::unavailable("epoch revocation pending; retry")
            .with_header("Retry-After", "1"))
    }
}
