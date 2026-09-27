//! Once-per-isolate deployment sharding validation over the root RefStore.

use std::cell::OnceCell;

use futures::future::{FutureExt, Shared};
use mkit_server::BoxFuture;
use mkit_server::pipeline::Sharding;
use mkit_server::store::keys;
use mkit_server::{
    Batch, BatchOutcome, Key, NamespaceKey, NamespaceStore, Partition, Precondition, Value,
};

/// Public refusal text, shared with the adapter's unavailable response.
pub const MISMATCH_MESSAGE: &str = "deployment sharding mismatch";

/// Server-side detail of a refused deployment (never returned to clients).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardError(pub String);

impl core::fmt::Display for GuardError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GuardError {}

type Check = Shared<BoxFuture<'static, Result<(), GuardError>>>;

/// Shares both an in-flight check and its result across requests in an isolate.
/// A canceled request leaves the check available to the next request. Success
/// and refusal are cached for the isolate's lifetime, including backend errors.
#[derive(Default)]
pub struct DeploymentGuard {
    check: OnceCell<(Sharding, Option<String>, Check)>,
}

impl core::fmt::Debug for DeploymentGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeploymentGuard")
            .field("initialized", &self.check.get().is_some())
            .finish()
    }
}

impl DeploymentGuard {
    /// Check the configured mode once, sharing at most three store calls.
    /// `store` must describe the same deployment for this cache's lifetime.
    /// A changed mode or jurisdiction in a reused isolate refuses locally without
    /// store calls: both are fixed for the deployment lifetime.
    pub fn check<S: NamespaceStore + 'static>(
        &self,
        store: S,
        mode: Sharding,
        jurisdiction: Option<String>,
    ) -> Check {
        let (checked_mode, checked_jurisdiction, check) = self.check.get_or_init(|| {
            let future: BoxFuture<'static, Result<(), GuardError>> = Box::pin(async move {
                let result = check_mode(&store, mode).await;
                if let Err(error) = &result {
                    crate::log_failure(&error.0);
                }
                result
            });
            (mode, jurisdiction.clone(), future.shared())
        });
        if *checked_mode != mode || *checked_jurisdiction != jurisdiction {
            let error = GuardError(format!(
                "{MISMATCH_MESSAGE}: configured={} isolate={} configured-jurisdiction={jurisdiction:?} isolate-jurisdiction={checked_jurisdiction:?}",
                mode_name(mode).unwrap_or("unsupported"),
                mode_name(*checked_mode).unwrap_or("unsupported"),
            ));
            crate::log_failure(&error.0);
            let refused: BoxFuture<'static, Result<(), GuardError>> =
                Box::pin(async move { Err(error) });
            return refused.shared();
        }
        check.clone()
    }
}

fn mode_name(mode: Sharding) -> Result<&'static str, GuardError> {
    match mode {
        Sharding::Single => Ok("single"),
        Sharding::D34 => Ok("d34"),
        _ => Err(GuardError("unsupported deployment sharding mode".into())),
    }
}

fn compare(observed: &Value, mode: &str) -> Result<(), GuardError> {
    if observed.as_bytes() == mode.as_bytes() {
        Ok(())
    } else {
        Err(GuardError(format!(
            "{MISMATCH_MESSAGE}: configured={mode} stored={}",
            String::from_utf8_lossy(observed.as_bytes())
        )))
    }
}

async fn check_mode<S: NamespaceStore>(store: &S, sharding: Sharding) -> Result<(), GuardError> {
    let mode = mode_name(sharding)?;
    let root = Partition::Namespace(NamespaceKey::deployment_default());
    let marker = keys::sharding_marker();
    let failure = |error| {
        GuardError(format!(
            "deployment sharding guard: configured={mode}: {error}"
        ))
    };
    if let Some(observed) = store.get(&root, &marker).await.map_err(failure)? {
        return compare(&observed, mode);
    }
    // The exclusive upper bound is above every permitted (<= MAX_KEY_BYTES) key.
    let rows = store
        .scan(
            &root,
            &Key::new(Vec::new()),
            &Key::new(vec![0xff; mkit_server::MAX_KEY_BYTES + 1]),
            None,
            1,
        )
        .await
        .map_err(failure)?;
    if let Some((key, value)) = rows.entries.first()
        && *key == marker
    {
        // Another isolate may have installed the marker after our get.
        return compare(value, mode);
    }
    if !rows.entries.is_empty() && mode == "d34" {
        // Unmarked data was written by a single-sharding deployment.
        return compare(&Value::new(b"single".to_vec()), mode);
    }
    let batch = Batch::new()
        .require(Precondition::Absent(marker.clone()))
        .put(marker, Value::new(mode.as_bytes().to_vec()));
    match store.apply(&root, batch).await.map_err(failure)? {
        BatchOutcome::Committed => Ok(()),
        BatchOutcome::PreconditionFailed {
            observed: Some(value),
            ..
        } => compare(&value, mode),
        BatchOutcome::PreconditionFailed { observed: None, .. } => Err(GuardError(format!(
            "deployment sharding guard corrupt reply: configured={mode}; failed Absent has no observed value"
        ))),
        BatchOutcome::DeadlinePassed { .. } => Err(GuardError(format!(
            "deployment sharding guard corrupt reply: configured={mode}; batch has no deadline"
        ))),
    }
}
