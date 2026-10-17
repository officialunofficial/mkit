//! Frozen nonempty paths exercise the same bytes on native and 32-bit wasm.
#![allow(clippy::unwrap_used)]
use mkit_core::hash;
use mkit_primitives::{
    evidence::{
        PackSource, ProfileId, RepositoryId, RulesetBinding, SourceBinding,
        pages::{EvidenceBinding, INDEXED_RULESET, PageView},
        proof::verify_path,
    },
    limits::EvidenceLimits,
};

fn binding() -> EvidenceBinding {
    let pack = include_bytes!("../fixtures/framing/earlier-delta-base.bin");
    EvidenceBinding {
        source: PackSource {
            id: hash::hash(pack),
            len: 189,
            binding: SourceBinding([7; 32]),
        },
        repository: RepositoryId([9; 32]),
        ruleset: RulesetBinding {
            ruleset: INDEXED_RULESET,
            profile: ProfileId::Indexed,
        },
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn frozen_multilevel_paths_preserve_inclusion_and_absence_semantics() {
    let binding = binding();
    let limits = EvidenceLimits {
        allocated_bytes: 0,
        ..EvidenceLimits::indexed()
    };
    let root = PageView::from_bytes(
        include_bytes!("../fixtures/evidence/page-proof-multilevel-root.bin"),
        binding,
        limits,
    )
    .unwrap();
    assert_eq!((root.height(), root.items()), (2, 2));
    assert_eq!(
        hash::to_hex(&root.commitment().digest),
        "dd182955ff93c419f1af9e37e1d0aa3e926c397a0f54081ffaad9c5b3dcc99a8"
    );
    for (bytes, key, value) in [
        (
            include_bytes!("../fixtures/evidence/proof-multilevel-inclusion.bin").as_slice(),
            [7; 32],
            Some(b"omega".as_slice()),
        ),
        (
            include_bytes!("../fixtures/evidence/proof-multilevel-absence.bin").as_slice(),
            [5; 32],
            None,
        ),
    ] {
        let answer = verify_path(bytes, binding, root.commitment(), key, limits).unwrap();
        assert_eq!(answer.root(), root.commitment());
        assert_eq!(answer.binding(), binding);
        assert_eq!(answer.key(), key);
        assert_eq!(answer.value(), value);
    }
}
