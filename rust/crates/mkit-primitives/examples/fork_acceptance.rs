//! Drive the pure acceptance entry point with deterministic host observations.
//!
//! The packaged support module supplies authenticated-inventory stand-ins and
//! typed facts. A real host acquires and authenticates those observations.
#[path = "../tests/support/fork.rs"]
pub mod host_facts;

use mkit_primitives::{
    error::Failure,
    fork::{ForkDecision, ForkPlan, decide_fork_acceptance},
};

fn main() -> Result<(), Failure> {
    let plan = ForkPlan::seal(
        host_facts::binding(),
        host_facts::inventories(),
        host_facts::LIMITS,
    )?;
    let request = host_facts::attempt(1);
    let destination = host_facts::facts(&plan, &request);
    let final_source = host_facts::proof(&plan);
    let decision = decide_fork_acceptance(
        &plan,
        &request,
        &destination,
        Some(&final_source),
        1,
        host_facts::LIMITS,
    )?;
    assert!(matches!(decision.decision(), ForkDecision::AcceptFork(_)));
    assert!(decision.matches(&destination, 1));
    assert_eq!(decision.source_fence(), Some(&final_source));
    // Persist the accepted plan/result, saved replay, exact optional reservation
    // settlement, and outcome responsibility atomically after all guards compare.
    // This example performs no commit and emits no reader-visible membership.
    Ok(())
}
