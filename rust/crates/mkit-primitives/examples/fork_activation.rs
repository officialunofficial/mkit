//! Decide one membership activation from retained acceptance and acquired facts.
#[path = "../tests/support/fork_advance.rs"]
pub mod host_facts;

use mkit_primitives::{
    decision::guards_hold,
    error::Failure,
    fork::{ForkActivationDecision, decide_fork_activation},
};

fn main() -> Result<(), Failure> {
    let advance = host_facts::advance();
    let result = host_facts::result();
    let mut unit = host_facts::unit();
    let proof = host_facts::proof();
    {
        let facts = host_facts::facts(&advance, &result, &unit, &proof);
        let guard = decide_fork_activation(&facts, 200, host_facts::LIMITS)?;
        assert_eq!(*guard.decision(), ForkActivationDecision::Install);
        assert!(guards_hold(&guard, &facts.guards(), 200));
        // A host compares every guard and discharges its destination proof and
        // authority permit while installing both witnesses atomically. Terminal
        // response, replay, reservation and outcome were settled at acceptance.
    }
    // Model a complete byte-identical pair observed after that atomic unit.
    unit.live = Some(unit.expected);
    unit.published = Some(unit.expected);
    let replay = host_facts::facts(&advance, &result, &unit, &proof);
    let guard = decide_fork_activation(&replay, 200, host_facts::LIMITS)?;
    assert_eq!(*guard.decision(), ForkActivationDecision::Replay);
    assert!(guards_hold(&guard, &replay.guards(), 200));
    Ok(())
}
