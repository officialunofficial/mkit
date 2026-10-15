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
//! Configured registration uses the pipeline configuration for
//! `takedown_denial` and `extract_min_bytes`: the first selects the pack proof
//! and whether the publication walk honors the fork's cleared set, the second
//! which holder rows are copied.

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
/// Low-level registration: callers must match the pipeline settings. Configured
/// deployments should build [`ForkTimer::from_config`] and register that handler.
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
    register_timer(
        registry,
        class,
        enabled,
        ForkTimer {
            store,
            shards: Arc::new(D34Shards),
            clock,
            takedown_denial,
            extract_min_bytes: Some(extract_min_bytes),
        },
        alarm_budget,
    )
}

fn register_timer<S: NamespaceStore, T: NamespaceStore + 'static>(
    registry: TimerRegistry<'static, S>,
    class: ShardClass,
    enabled: bool,
    timer: ForkTimer<T>,
    alarm_budget: Option<mkit_server::purge::SliceBudget>,
) -> TimerRegistry<'static, S> {
    let Some(budget) = alarm_budget else {
        return registry;
    };
    if class != ShardClass::NsCoordinator || !enabled {
        return registry;
    }
    registry.register(crate::purge::Budgeted {
        handler: timer,
        budget: Some(budget),
        calls: FORK_ALARM_CALLS,
    })
}

#[cfg(any(target_arch = "wasm32", test))]
fn configured_timer<T>(
    config: &mkit_server::pipeline::PipelineConfig,
    store: T,
    clock: Arc<dyn Clock>,
) -> ForkTimer<T> {
    ForkTimer::from_config(store, Arc::new(D34Shards), clock, config)
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
    let config = match cfg.pipeline_config() {
        Ok(config) => config,
        Err(error) => {
            crate::log_failure(&error.to_string());
            return registry;
        }
    };
    let enabled =
        config.sharding == mkit_server::pipeline::Sharding::D34 && config.indexed.is_some();
    let timer = configured_timer(
        &config,
        WorkerNamespaceStore::new(
            StubTransport::new(env.clone(), cfg.placement.clone()),
            cfg.probe_partition(),
        ),
        Arc::new(crate::clock::WorkerClock),
    );
    register_timer(registry, class, enabled, timer, alarm_budget)
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
    fn configured_fork_timer_matches_pipeline_denial_mode() {
        use mkit_server::fork::ForkEnv;
        use mkit_server::pipeline::{AuthMode, PipelineConfig};

        for denial in [false, true] {
            let mut config = PipelineConfig::new(
                mkit_server::Addressing::Multi(mkit_server::MultiAddressing::new()),
                AuthMode::Open,
                mkit_server::upload::UploadLimits::new(1 << 20, 64),
            );
            config.takedown_denial = denial;
            config.indexed = Some(mkit_server::indexed::IndexedConfig::default());
            let timer =
                configured_timer(&config, MemoryKv::default(), Arc::new(ManualClock::new(0)));
            let env = ForkEnv::from_config(
                &timer.store,
                timer.shards.as_ref(),
                timer.clock.as_ref(),
                &config,
            );
            assert_eq!(timer.takedown_denial, config.takedown_denial);
            assert_eq!(timer.takedown_denial, env.takedown_denial);
            assert_eq!(timer.extract_min_bytes, env.extract_min_bytes);
            let registry = register_timer::<MemoryKv, _>(
                TimerRegistry::new(),
                ShardClass::NsCoordinator,
                true,
                timer,
                Some(mkit_server::purge::SliceBudget::new(960)),
            );
            assert!(format!("{registry:?}").contains("TimerKind(16)"));
        }
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
