//! Bounded acceptance-evidence decoder fuzzing and stable seed replay.

use mkit_primitives::evidence::acceptance::{AcceptanceEvidence, AcceptanceEvidenceDecodeCfg};

/// Replay one input with a fixed finite budget and a smaller hostile budget.
/// Inputs over 64 KiB are outside this target's host acquisition budget.
pub fn exercise(bytes: &[u8]) {
    if bytes.len() > 64 * 1024 {
        return;
    }
    let mut cfg = AcceptanceEvidenceDecodeCfg {
        max_envelope_bytes: 64 * 1024,
        max_operation_bytes: 1024,
        max_heads: 16,
        max_head_bytes: 4096,
        max_total_head_bytes: 32 * 1024,
        max_external_dependencies: 64,
        ruleset_id: 1,
        profile_limits_digest: [0x11; 32],
    };
    for hostile in [false, true] {
        if hostile {
            let budget = u32::from(bytes.first().copied().unwrap_or(0));
            cfg.max_envelope_bytes = budget;
            cfg.max_operation_bytes = budget;
            cfg.max_heads = budget % 8;
            cfg.max_head_bytes = budget;
            cfg.max_total_head_bytes = budget;
            cfg.max_external_dependencies = budget % 8;
        }
        let decoded = AcceptanceEvidence::decode(bytes, &cfg);
        assert_eq!(decoded, AcceptanceEvidence::decode(bytes, &cfg));
        if let Ok(evidence) = decoded {
            assert_eq!(evidence.encode(), bytes);
            assert_eq!(evidence.encoded_len(), bytes.len());
            let again = AcceptanceEvidence::decode(evidence.encode(), &cfg);
            assert_eq!(again.as_ref(), Ok(&evidence));
            if let Ok(again) = again {
                assert_eq!(again.digest(), evidence.digest());
                assert_eq!(evidence.recheck_heads(), again.recheck_heads());
            }
            assert_eq!(
                evidence.check_binding(
                    &evidence.pack().id,
                    evidence.pack().len,
                    &evidence.repository(),
                    evidence.operation(),
                    evidence.epoch()
                ),
                Ok(())
            );
        }
    }
}
