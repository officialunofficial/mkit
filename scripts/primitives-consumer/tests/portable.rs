//! Portable fixtures consumed through the published API only, natively and on wasm32.
#![allow(clippy::unwrap_used)]
use mkit_core::hash;
use mkit_primitives::{
    error::FailureCode,
    evidence::{
        PackSource, ProfileId, RepositoryId, RulesetBinding, RulesetId, SourceBinding,
        acceptance::{AcceptanceEvidence, AcceptanceEvidenceDecodeCfg},
        pages::{EvidenceBinding, INDEXED_RULESET, PageView},
        proof::verify_path,
    },
    limits::{EvidenceLimits, IndexedProfile, VerifyLimits},
    pack_verify::{
        Acquisition, Request, Response,
        framing::{FramingDriver, FramingStep},
    },
};
use primitives_consumer::embedded::ACCEPTANCE;
use serde_json::Value;

fn number(cfg: &Value, name: &str) -> u32 {
    u32::try_from(cfg[name].as_u64().unwrap()).unwrap()
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn acceptance_fixtures_decode_re_encode_and_refuse_as_recorded() {
    assert_eq!(ACCEPTANCE.len(), 49, "packaged fixture inventory changed");
    for (name, raw, case) in ACCEPTANCE {
        let case: Value = serde_json::from_str(case).unwrap();
        let config = &case["cfg"];
        let cfg = AcceptanceEvidenceDecodeCfg {
            max_envelope_bytes: number(config, "max_envelope_bytes"),
            max_operation_bytes: number(config, "max_operation_bytes"),
            max_heads: number(config, "max_heads"),
            max_head_bytes: number(config, "max_head_bytes"),
            max_total_head_bytes: number(config, "max_total_head_bytes"),
            max_external_dependencies: number(config, "max_external_dependencies"),
            ruleset_id: RulesetId(number(config, "ruleset_id")),
            profile_limits_digest: hash::from_hex(
                config["profile_limits_digest"].as_str().unwrap(),
            )
            .unwrap(),
        };
        let expected = &case["expected"];
        match AcceptanceEvidence::decode(raw, &cfg) {
            Ok(evidence) => {
                assert_eq!(expected["decode"], "ok", "{name}");
                assert_eq!(evidence.encode(), *raw, "{name}");
                assert_eq!(
                    hash::to_hex(&evidence.digest()),
                    expected["digest"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    evidence.encoded_len(),
                    usize::try_from(case["encoded_len"].as_u64().unwrap()).unwrap(),
                    "{name}"
                );
                match expected["recheck_heads"].as_str().unwrap() {
                    "ok" => evidence.recheck_heads().unwrap(),
                    code => assert_eq!(
                        evidence.recheck_heads().unwrap_err().code.as_str(),
                        code,
                        "{name}"
                    ),
                }
            }
            Err(error) => {
                assert_eq!(
                    error.code.as_str(),
                    expected["failure_code"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn authenticated_inclusion_and_absence_paths_verify() {
    let pack = include_bytes!("../fixtures/framing/earlier-delta-base.bin");
    let binding = EvidenceBinding {
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
    };
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
        assert_eq!(answer.key(), key);
        assert_eq!(answer.value(), value);
    }
}

fn frame(bytes: &[u8]) -> Result<u32, FailureCode> {
    let source = PackSource {
        id: hash::hash(bytes),
        len: u64::try_from(bytes.len()).unwrap(),
        binding: SourceBinding([1; 32]),
    };
    let profile = IndexedProfile {
        pack_bytes: 5 << 30,
        decoded_bytes: 4 << 30,
        delta_depth: 50,
    };
    let mut driver = FramingDriver::new(
        source,
        RepositoryId([9; 32]),
        profile,
        VerifyLimits::indexed(),
        23,
    )
    .map_err(|error| error.code)?;
    for _ in 0..100 {
        match driver.step().map_err(|error| error.code)? {
            FramingStep::Request(Request::Bytes {
                request,
                source,
                range,
            }) => {
                let begin = usize::try_from(range.offset).unwrap();
                let end = begin + usize::try_from(range.len).unwrap();
                driver
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&bytes[begin..end]),
                    })
                    .map_err(|error| error.code)?;
            }
            FramingStep::RetainEvidence(page) => {
                let commitment = page.commitment;
                driver
                    .acknowledge_retention(commitment)
                    .map_err(|error| error.code)?;
            }
            FramingStep::Frame(_) | FramingStep::Progress => {}
            FramingStep::Complete(summary) => return Ok(summary.entries()),
            _ => panic!("unexpected transition"),
        }
    }
    panic!("bounded fixture exceeded transition ceiling")
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn framing_fixtures_complete_or_refuse_with_stable_codes() {
    assert_eq!(
        frame(include_bytes!("../fixtures/framing/earlier-delta-base.bin")),
        Ok(3)
    );
    for bytes in [
        include_bytes!("../fixtures/framing/payload-high-bit.bin").as_slice(),
        include_bytes!("../fixtures/framing/payload-u32-max.bin").as_slice(),
    ] {
        assert_eq!(frame(bytes), Err(FailureCode::PackfileTooLarge));
    }
}
