//! The transport-neutral request pipeline (PRD §5.4).
//!
//! This part holds the pipeline's surface: the stages as hook traits with
//! the M0 defaults ([`HookSet`], [`Hooks`]), shard routing ([`ShardMap`],
//! [`SinglePartition`]) and the pure write planners ([`plan_write`]) whose
//! batches carry a `NotAfter` commit deadline. The entry points that run
//! the stages in order land next (WP-M0-05a part 2).

mod hooks;
mod plan;
mod shard;
#[cfg(test)]
mod tests;

pub use hooks::{
    Admission, AdmissionDecision, AdmissionInput, Authorizer, Challenge, DefaultAdmission, HookSet,
    Hooks, NoOutcomes, NoPreReceive, NoReceipts, OpenAuthorizer, OutboxRow, OutcomeSink,
    PreReceive, ReceiptSigner,
};
pub use plan::{
    MAX_REPLAN, PRUNE_LIMIT, Plan, PlanClock, Planned, ReplayGuard, Snapshot, WriteKind,
    WriteRequest, plan_write,
};
pub use shard::{ShardMap, SinglePartition};
