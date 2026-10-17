//! The same frozen byte and count checks execute natively and on 32-bit wasm.

use mkit_core::hash::domain_digest;
use mkit_primitives::{
    closure::output::{PageDecodeCfg, decode_missing, decode_witness, validate_state_page},
    error::FailureCode,
    evidence::{PageCommitment, PageKind},
};

fn page(domain: &[u8], bytes: &[u8]) -> PageCommitment {
    PageCommitment {
        digest: domain_digest(domain, bytes),
        kind: PageKind::Closure,
        len: bytes.len() as u64,
        items: 1,
    }
}
const CFG: PageDecodeCfg = PageDecodeCfg {
    max_bytes: 4096,
    max_reasons: 64,
    max_work: 8192,
};

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn frozen_closure_pages_have_portable_bytes_and_bindings() {
    let state = include_bytes!("../fixtures/closure/state-member.bin");
    let witness = include_bytes!("../fixtures/closure/witness-member.bin");
    let missing = include_bytes!("../fixtures/closure/missing-all-reasons.bin");
    validate_state_page(page(b"mkit-closure-state:v1", state), state, CFG).unwrap();
    let member = decode_witness(page(b"mkit-closure-witness:v1", witness), witness, CFG).unwrap();
    assert_eq!(member.fact.supplier.id, [3; 32]);
    assert_eq!(member.fact.revision.0, [6; 32]);
    let absent = decode_missing(page(b"mkit-closure-missing:v1", missing), missing, CFG).unwrap();
    assert_eq!(absent.missing.object, [0x31; 32]);
    assert_eq!(absent.missing.reasons.len(), 6);
    let mut tampered = page(b"mkit-closure-witness:v1", witness);
    tampered.digest[0] ^= 1;
    assert_eq!(
        decode_witness(tampered, witness, CFG).unwrap_err().code,
        FailureCode::InvalidResponse
    );
}

#[cfg_attr(not(target_arch = "wasm32"), test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
fn count_checks_precede_platform_sized_allocations() {
    let cfg = PageDecodeCfg {
        max_bytes: 4096,
        max_reasons: u64::MAX,
        max_work: u64::MAX,
    };
    // A current page without a predecessor, one ID and one minimal head reason.
    let mut bytes = vec![0; 52];
    bytes[0] = 1;
    for count in [1u64 << 32, u64::MAX] {
        bytes[34..42].copy_from_slice(&count.to_le_bytes());
        let expected = if count == u64::MAX {
            FailureCode::ResourceLimit
        } else {
            FailureCode::InvalidResponse
        };
        assert_eq!(
            decode_missing(page(b"mkit-closure-missing:v1", &bytes), &bytes, cfg)
                .unwrap_err()
                .code,
            expected
        );
    }
    #[cfg(target_arch = "wasm32")]
    assert_eq!(usize::BITS, 32);
}
