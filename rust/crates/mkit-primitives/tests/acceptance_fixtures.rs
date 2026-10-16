//! Portable fixture consumption; CI never regenerates bytes or expected digests.

use mkit_core::hash;
use mkit_primitives::evidence::acceptance::{AcceptanceEvidence, AcceptanceEvidenceDecodeCfg};
use serde_json::Value;

fn number(cfg: &Value, name: &str) -> u32 {
    u32::try_from(cfg[name].as_u64().unwrap()).unwrap()
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
            ruleset_id: number(config, "ruleset_id"),
            profile_limits_digest: hash::from_hex(
                config["profile_limits_digest"].as_str().unwrap(),
            )
            .unwrap(),
        };
        let result = AcceptanceEvidence::decode(&raw, &cfg);
        if case["expected"]["decode"] == "ok" {
            let evidence = result.unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            assert_eq!(evidence.encode(), raw, "{}", path.display());
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
