//! Frozen decision projections from the former CLI and client push loops.
//! Chain walking, failure classification, reset authorization, and conflict I/O
//! stay in those drivers: notably, their depth/count errors differ.
#![allow(clippy::unwrap_used)]

use std::collections::HashSet;

use mkit_core::{
    hash::{Hash, to_hex},
    pack::pack_key,
    refs::RefWriteCondition,
    transfer::{
        encode_packlist,
        packmap::{ChainState, Node, PlanError, plan_advance},
    },
};
use proptest::prelude::*;

// These retain the old pure decisions, rather than invoking the new planner.
// `reset` represents either an authorized rollover or a classified broken chain.
fn former_cli(prior: Option<Hash>, held: &[Hash], keys: &[Hash], reset: bool) -> Option<Node> {
    let prev = if reset {
        None
    } else if let Some(head) = prior {
        let have: HashSet<&Hash> = held.iter().collect();
        if keys.iter().all(|key| have.contains(key)) {
            return None;
        }
        Some(head)
    } else {
        None
    };
    let bytes = encode_packlist(prev, keys).unwrap();
    Some(Node {
        key: pack_key(&bytes),
        bytes,
        condition: prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
    })
}

fn former_client(
    prior: Option<Hash>,
    held: &[Hash],
    keys: &[Hash],
    reset: bool,
    cap: u64,
) -> Result<Option<Node>, PlanError> {
    let packs: HashSet<Hash> = held.iter().copied().collect();
    let prev = match (reset, prior) {
        (true, _) | (false, None) => None,
        (false, Some(_)) if keys.iter().all(|key| packs.contains(key)) => return Ok(None),
        (false, Some(root)) => Some(root),
    };
    let bytes = encode_packlist(prev, keys)?;
    if bytes.len() as u64 > cap {
        return Err(PlanError::NodeTooLarge);
    }
    Ok(Some(Node {
        key: pack_key(&bytes),
        bytes,
        condition: prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match),
    }))
}

fn state(prior: Option<Hash>, held: &HashSet<Hash>, reset: bool) -> ChainState {
    if reset {
        ChainState::Reset { prior }
    } else {
        prior.map_or(ChainState::Missing, |head| ChainState::Append {
            head,
            packs: held.clone(),
        })
    }
}

#[test]
#[allow(clippy::too_many_lines)] // Keep fixture cases and their assertions together.
fn former_driver_fixture_matrix_matches_literal_wire_and_ids() {
    let (a, b, c, retry_head) = ([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]);
    // Expected ids are independently derived from the existing pinned MKPL
    // codec layout, not claimed to be captures of former driver executions.
    let fixtures = [
        (
            "first",
            None,
            vec![],
            vec![b],
            false,
            Some("ed1197878af9fe071d21bff4a0c171933076e0cc4d6e8558005a3cc14e6970a3"),
        ),
        (
            "append",
            Some(a),
            vec![c],
            vec![b],
            false,
            Some("81b13163a68e2dc4bf09d23bc83f515a361a5f0a301d903e745123e35c1a429e"),
        ),
        (
            "partial overlap",
            Some(a),
            vec![b],
            vec![b, c],
            false,
            Some("04b9aceef7673b4f4c8b039c2aea4f7cc98f9d40fbf4455d8736231bcce12cde"),
        ),
        (
            "full overlap retry",
            Some(a),
            vec![c, b],
            vec![b, c],
            false,
            None,
        ),
        (
            "rollover",
            Some(a),
            vec![b, c],
            vec![b, c],
            true,
            Some("d00f0c74759dd0d64e01110e4f19ba2f99454127037e6e4ba288f662f6931a22"),
        ),
        (
            "changed head retry",
            Some(retry_head),
            vec![b],
            vec![b, c],
            false,
            Some("baeabbc75a5852eabaa2f986a07034887f88128d7592b5001b6c90d976fda7d4"),
        ),
        (
            "reset retry",
            Some(retry_head),
            vec![b, c],
            vec![b, c],
            true,
            Some("d00f0c74759dd0d64e01110e4f19ba2f99454127037e6e4ba288f662f6931a22"),
        ),
        (
            "broken chain reset",
            Some(a),
            vec![],
            vec![b, c],
            true,
            Some("d00f0c74759dd0d64e01110e4f19ba2f99454127037e6e4ba288f662f6931a22"),
        ),
    ];
    for (label, prior, held, keys, reset, expected_id) in fixtures {
        let held_set = held.iter().copied().collect();
        let planned = plan_advance(state(prior, &held_set, reset), &keys, None).unwrap();
        assert_eq!(
            planned,
            former_cli(prior, &held, &keys, reset),
            "{label}: CLI"
        );
        assert_eq!(
            Ok(planned.as_ref()),
            former_client(prior, &held, &keys, reset, u64::MAX)
                .as_ref()
                .map(Option::as_ref),
            "{label}: client"
        );
        assert_eq!(
            planned.as_ref().map(|node| to_hex(&node.key)),
            expected_id.map(str::to_owned),
            "{label}"
        );
        if let Some(node) = planned {
            // Independent literal encoding for this fixture's one-byte counts.
            let mut wire = b"MKPL\x01".to_vec();
            match prior.filter(|_| !reset) {
                Some(head) => {
                    wire.push(1);
                    wire.extend_from_slice(&head);
                }
                None => wire.push(0),
            }
            wire.push(u8::try_from(keys.len()).unwrap());
            for key in &keys {
                wire.extend_from_slice(key);
            }
            assert_eq!(node.bytes, wire, "{label}: wire");
            assert_eq!(
                node.condition,
                prior.map_or(RefWriteCondition::Missing, RefWriteCondition::Match)
            );
            let length = u64::try_from(node.bytes.len()).unwrap();
            assert_eq!(
                plan_advance(state(prior, &held_set, reset), &keys, Some(length - 1)),
                Err(PlanError::NodeTooLarge),
                "{label}: under-size cap"
            );
            assert_eq!(
                plan_advance(state(prior, &held_set, reset), &keys, Some(length)),
                Ok(Some(node)),
                "{label}: exact-size cap"
            );
            for cap in [length - 1, length] {
                assert_eq!(
                    plan_advance(state(prior, &held_set, reset), &keys, Some(cap)),
                    former_client(prior, &held, &keys, reset, cap),
                    "{label}: byte boundary"
                );
            }
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_retry_inputs_match_both_former_drivers(
        prior in proptest::option::of(any::<[u8; 32]>()),
        held_seeds in prop::collection::vec(0_u8..8, 0..32),
        key_seeds in prop::collection::vec(0_u8..8, 1..32),
        reset in any::<bool>(),
        cap in 0_u64..1200,
    ) {
        let held: Vec<Hash> = held_seeds.iter().map(|seed| [*seed; 32]).collect();
        let keys: Vec<Hash> = key_seeds.iter().map(|seed| [*seed; 32]).collect();
        let held_set = held.iter().copied().collect();
        prop_assert_eq!(
            plan_advance(state(prior, &held_set, reset), &keys, None),
            Ok(former_cli(prior, &held, &keys, reset)),
        );
        prop_assert_eq!(
            plan_advance(state(prior, &held_set, reset), &keys, Some(cap)),
            former_client(prior, &held, &keys, reset, cap),
        );
    }
}

#[test]
fn codec_entry_cap_and_idempotent_short_circuit_are_preserved() {
    use mkit_core::transfer::{PACKLIST_MAX_ENTRIES, PackListError};
    let keys = vec![[0x22; 32]; PACKLIST_MAX_ENTRIES as usize + 1];
    let expected = PlanError::Packlist(PackListError::TooManyEntries(PACKLIST_MAX_ENTRIES + 1));
    assert_eq!(
        plan_advance(ChainState::Missing, &keys, None),
        Err(expected)
    );
    let held = HashSet::from([[0x22; 32]]);
    assert_eq!(
        plan_advance(
            ChainState::Append {
                head: [0x11; 32],
                packs: held
            },
            &keys,
            Some(0)
        ),
        Ok(None)
    );
    assert_eq!(
        plan_advance(
            ChainState::Reset {
                prior: Some([0x11; 32])
            },
            &keys,
            None
        ),
        Err(PlanError::Packlist(PackListError::TooManyEntries(
            PACKLIST_MAX_ENTRIES + 1
        )))
    );
}
