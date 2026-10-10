//! Kind 16 on a Worker: the server-side fork job (SPEC-SERVER §9.9).
//!
//! The job row and its timer live in the destination's namespace coordinator,
//! so that is the class that registers the handler. A slice makes at most
//! [`mkit_server::fork::SLICE_CALLS`] storage calls across the deployment's
//! partitions (reads of the source, writes of the destination); the handler
//! reserves them from the alarm's allowance before it runs, and a fire the
//! allowance cannot hold is retried on a later alarm. Like indexed
//! verification it needs a Paid alarm budget, so Free registers nothing.
//!
//! The handler's `takedown_denial` and `extract_min_bytes` MUST equal the
//! pipeline's: the first selects the pack proof and whether the publication
//! walk honours the fork's cleared set, the second which holder rows are copied.

use std::sync::Arc;

use crate::classes::ShardClass;
use mkit_server::fork::{ForkTimer, SLICE_CALLS};
use mkit_server::pipeline::D34Shards;
use mkit_server::timers::TimerRegistry;
use mkit_server::{Clock, NamespaceStore};

/// Calls a fire reserves: one slice, plus the job-row commits, which are not
/// charged to the slice but are still subrequests.
pub const FORK_ALARM_CALLS: u32 = SLICE_CALLS + 40;

// A fire fits one launch alarm with room for dispatch and settlement.
const _: () = assert!(FORK_ALARM_CALLS < crate::purge::LAUNCH_ALARM_OPERATIONS);

/// Register kind 16 on a Paid deployment's namespace coordinators when it
/// runs indexed mode on leased sharding; on every other class or deployment
/// `registry` comes back as it was. `store` reaches every partition.
#[must_use]
pub fn with_fork_timer<S, T>(
    registry: TimerRegistry<'static, S>,
    class: ShardClass,
    enabled: bool,
    (takedown_denial, extract_min_bytes): (bool, u64),
    store: T,
    clock: Arc<dyn Clock>,
    alarm_budget: Option<mkit_server::purge::SliceBudget>,
) -> TimerRegistry<'static, S>
where
    S: NamespaceStore,
    T: NamespaceStore + 'static,
{
    let Some(budget) = alarm_budget else {
        return registry;
    };
    if class != ShardClass::NsCoordinator || !enabled {
        return registry;
    }
    registry.register(crate::purge::Budgeted {
        handler: ForkTimer {
            store,
            shards: Arc::new(D34Shards),
            clock,
            takedown_denial,
            extract_min_bytes: Some(extract_min_bytes),
        },
        budget: Some(budget),
        calls: FORK_ALARM_CALLS,
    })
}

/// [`with_fork_timer`] for a Durable Object of `env`.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub(crate) fn register_configured<S: NamespaceStore>(
    registry: TimerRegistry<'static, S>,
    env: &worker::Env,
    class: ShardClass,
    alarm_budget: Option<mkit_server::purge::SliceBudget>,
    cfg: &crate::adapter::WorkerConfig,
) -> TimerRegistry<'static, S> {
    use crate::ns_client::{StubTransport, WorkerNamespaceStore};
    let Some(indexed) = cfg.indexed else {
        return registry;
    };
    let enabled = cfg.sharding == mkit_server::pipeline::Sharding::D34;
    with_fork_timer(
        registry,
        class,
        enabled,
        (cfg.takedown_denial, indexed.extract_min_bytes),
        WorkerNamespaceStore::new(
            StubTransport::new(env.clone(), cfg.placement.clone()),
            cfg.probe_partition(),
        ),
        Arc::new(crate::clock::WorkerClock),
        alarm_budget,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_server::{ManualClock, MemoryKv};

    fn kinds(class: ShardClass, enabled: bool, budget: bool) -> String {
        let registry = with_fork_timer(
            TimerRegistry::<MemoryKv>::new(),
            class,
            enabled,
            (true, 65_536),
            MemoryKv::default(),
            Arc::new(ManualClock::new(0)),
            budget.then(|| mkit_server::purge::SliceBudget::new(960)),
        );
        format!("{registry:?}")
    }

    #[test]
    fn kind_16_is_registered_on_paid_coordinators_of_leased_indexed_deployments_only() {
        assert!(kinds(ShardClass::NsCoordinator, true, true).contains("TimerKind(16)"));
        // Free has no alarm allowance to reserve from.
        assert!(!kinds(ShardClass::NsCoordinator, true, false).contains("TimerKind(16)"));
        assert!(!kinds(ShardClass::NsCoordinator, false, true).contains("TimerKind(16)"));
        for class in [
            ShardClass::RefStore,
            ShardClass::RefShard,
            ShardClass::RepoIndexShard,
            ShardClass::ContentIndexShard,
        ] {
            assert!(
                !kinds(class, true, true).contains("TimerKind(16)"),
                "{class:?}"
            );
        }
    }
}
