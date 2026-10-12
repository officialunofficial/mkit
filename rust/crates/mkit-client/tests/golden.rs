//! Pins the bytes of a fixed plan. A change to these ids means pack bytes
//! changed: restarted pushes would no longer reproduce their pack ids, so the
//! change must be called out under "Breaking" in the CHANGELOG.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)] // unwrap is the assertion in test helpers

use mkit_client::{Entry, Limits, Plan};
use mkit_core::{
    hash::{Hash, hash, to_hex},
    pack::pack_key,
    transfer::encode_packlist,
};

/// Entries stay under 64 bytes, so no build (with or without a zstd writer)
/// compresses them: the bytes are the same for every feature set.
fn fixture() -> Vec<Entry> {
    let raw = |seed: u8, len: usize| {
        let bytes: Vec<u8> = (0..len)
            .map(|i| seed.wrapping_mul(31).wrapping_add(i as u8))
            .collect();
        Entry::Raw {
            id: hash(&bytes),
            bytes,
        }
    };
    vec![
        raw(1, 40),
        raw(2, 33),
        Entry::Delta {
            base: hash(
                &(0..40)
                    .map(|i| 1_u8.wrapping_mul(31).wrapping_add(i))
                    .collect::<Vec<u8>>(),
            ),
            stream: vec![7; 20],
        },
        raw(3, 50),
    ]
}

fn ids(limits: Limits) -> (Vec<String>, String) {
    let plan = Plan::prepare(fixture(), limits).unwrap();
    let keys: Vec<Hash> = plan.pack_ids().copied().collect();
    let node = encode_packlist(None, &keys).unwrap();
    (keys.iter().map(to_hex).collect(), to_hex(&pack_key(&node)))
}

#[test]
fn one_pack_plan_ids_are_stable() {
    let (packs, node) = ids(Limits::default());
    assert_eq!(
        packs,
        ["377baa94219010ebe93689587e6eff487491cf87debc778fcf510a74d295af6c"]
    );
    assert_eq!(
        node,
        "b05415c01f7d174385cd2487e8f26bbc6744b541656187d855c5e42a732b846c"
    );
}

#[test]
fn split_plan_ids_are_stable() {
    // A tight payload cap forces several packs, pinning the split points too.
    let (packs, node) = ids(Limits {
        payload_bytes: 100,
        ..Limits::default()
    });
    assert_eq!(
        packs,
        [
            "eebfaf7a2f5697fbd6eba7f73b21d1a06a062be19825b8bb7bd7884c69d55464",
            "cdeb25cbea80e759021686dc0339ec945952d754c45f807f847fbc206fa095a3",
            "d1d22d68702bf09ed25a14d4446740f3b1186cfe7f71182d03dbd3db6552f67d",
        ]
    );
    assert_eq!(
        node,
        "d64e7ed3aa76692e2759c567dc97010979c5d022740a2bc683c646274a96f53a"
    );
}
