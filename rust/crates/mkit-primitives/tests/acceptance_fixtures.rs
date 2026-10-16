//! Portable fixture consumption; CI never regenerates bytes or expected digests.

use mkit_core::hash;
use mkit_primitives::evidence::RulesetId;
use mkit_primitives::evidence::acceptance::{AcceptanceEvidence, AcceptanceEvidenceDecodeCfg};
use serde_json::Value;

fn wide(value: &Value) -> u64 {
    value.as_str().unwrap().parse().unwrap()
}

fn number(cfg: &Value, name: &str) -> u32 {
    u32::try_from(cfg[name].as_u64().unwrap()).unwrap()
}

fn assert_summary(evidence: &AcceptanceEvidence, semantic: &Value) {
    assert_eq!(
        u64::from(evidence.ruleset_id().0),
        semantic["ruleset_id"].as_u64().unwrap()
    );
    assert_eq!(
        hash::to_hex(&evidence.profile_limits_digest()),
        semantic["profile_limits_digest"].as_str().unwrap()
    );
    assert_eq!(
        hash::to_hex(&evidence.repository().0),
        semantic["repository"].as_str().unwrap()
    );
    assert_eq!(
        hash::to_hex_bytes(evidence.operation()),
        semantic["operation"].as_str().unwrap()
    );
    assert_eq!(evidence.epoch(), wide(&semantic["epoch"]));
    let pack = evidence.pack();
    assert_eq!(
        hash::to_hex(&pack.id),
        semantic["pack"]["id"].as_str().unwrap()
    );
    assert_eq!(pack.len, wide(&semantic["pack"]["len"]));
    assert_eq!(pack.object_count, wide(&semantic["pack"]["object_count"]));
    assert_eq!(pack.delta_count, wide(&semantic["pack"]["delta_count"]));
    assert_eq!(
        hash::to_hex(&pack.object_set_root),
        semantic["pack"]["object_set_root"].as_str().unwrap()
    );
    assert_eq!(
        evidence.witness().generation,
        wide(&semantic["membership_generation"])
    );
    assert_eq!(
        evidence.witness().removal_version,
        wide(&semantic["removal_version"])
    );
    assert_eq!(evidence.denial_version(), wide(&semantic["denial_version"]));
}

fn assert_heads(evidence: &AcceptanceEvidence, semantic: &Value) {
    let heads: Vec<_> = evidence.heads().collect();
    let expected_heads = semantic["heads"].as_array().unwrap();
    assert_eq!(heads.len(), expected_heads.len());
    for (head, expected) in heads.iter().zip(expected_heads) {
        assert_eq!(
            hash::to_hex(&head.object_id),
            expected["object_id"].as_str().unwrap()
        );
        assert_eq!(u64::from(head.kind), expected["kind"].as_u64().unwrap());
        assert_eq!(
            hash::to_hex(&head.signer),
            expected["signer"].as_str().unwrap()
        );
        assert_eq!(expected["signature_result"].as_u64().unwrap(), 1);
        assert_eq!(
            hash::to_hex_bytes(head.canonical_bytes),
            expected["canonical_bytes"].as_str().unwrap()
        );
    }
    let dependencies: Vec<_> = evidence
        .external_dependencies()
        .map(|id| hash::to_hex(&id))
        .collect();
    let expected_dependencies: Vec<_> = semantic["external_dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    assert_eq!(dependencies, expected_dependencies);
}

#[test]
fn portable_acceptance_fixtures() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/acceptance");
    let mut cases: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    cases.sort();
    assert_eq!(cases.len(), 49, "fixture inventory changed without review");
    for path in cases {
        let case: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let raw = std::fs::read(path.with_extension("bin")).unwrap();
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
        let result = AcceptanceEvidence::decode(&raw, &cfg);
        if case["expected"]["decode"] == "ok" {
            let evidence = result.unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(evidence.encode(), raw, "{}", path.display());
            assert_summary(&evidence, &case["semantic"]);
            assert_heads(&evidence, &case["semantic"]);

            assert_eq!(
                hash::to_hex(&evidence.digest()),
                case["expected"]["digest"].as_str().unwrap(),
                "{}",
                path.display()
            );
            assert_eq!(
                evidence.encoded_len(),
                usize::try_from(case["encoded_len"].as_u64().unwrap()).unwrap()
            );
            if case["expected"]["recheck_heads"] == "ok" {
                evidence.recheck_heads().unwrap();
            } else {
                assert_eq!(
                    evidence.recheck_heads().unwrap_err().code.as_str(),
                    case["expected"]["recheck_heads"].as_str().unwrap()
                );
            }
        } else {
            assert_eq!(
                result.unwrap_err().code.as_str(),
                case["expected"]["failure_code"].as_str().unwrap(),
                "{}",
                path.display()
            );
        }
    }
}
