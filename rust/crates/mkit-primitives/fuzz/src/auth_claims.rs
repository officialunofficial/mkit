//! Bounded auth-claims fuzz body, independent of host token formats.

use mkit_primitives::auth::{ClaimsPrincipal, validate_claims_binding};

/// Exercise one claims/request binding plan. Only the first 75 bytes matter;
/// strings have fixed finite sizes and the body allocates no memory.
///
/// # Panics
/// Panics if validation disagrees with the field-mutation model.
pub fn claims_binding(data: &[u8]) {
    let byte = |offset| data.get(offset).copied().unwrap_or(0);
    let mut signer = [0; 32];
    let mut pack = [0; 32];
    for (index, value) in signer.iter_mut().enumerate() {
        *value = byte(index);
    }
    for (index, value) in pack.iter_mut().enumerate() {
        *value = byte(32 + index);
    }
    let mut other_signer = signer;
    other_signer[0] ^= 1;
    let mut other_pack = pack;
    other_pack[0] ^= 1;
    let mut raw_bytes = [0; 8];
    for (index, value) in raw_bytes.iter_mut().enumerate() {
        *value = byte(64 + index);
    }
    let bytes = u64::from_le_bytes(raw_bytes);
    let mask = byte(72);
    let claims = ClaimsPrincipal {
        audience: "https://example.test",
        repository: "repo",
        signer: &signer,
    };
    let request = ClaimsPrincipal {
        audience: if mask & 1 == 0 {
            claims.audience
        } else {
            "https://other.test"
        },
        repository: if mask & 2 == 0 {
            claims.repository
        } else {
            "other"
        },
        signer: if mask & 4 == 0 {
            &signer
        } else {
            &other_signer
        },
    };
    let requested_pack = if mask & 8 == 0 { &pack } else { &other_pack };
    let requested_bytes = if mask & 16 == 0 { bytes } else { bytes ^ 1 };
    let result = validate_claims_binding(
        claims,
        request,
        &pack,
        bytes,
        requested_pack,
        requested_bytes,
    );
    assert_eq!(result.is_ok(), mask.trailing_zeros() >= 5);
    assert_eq!(claims.check(request).is_ok(), mask.trailing_zeros() >= 3);
}

#[cfg(test)]
mod tests {
    use super::claims_binding;

    #[test]
    fn stable_seed_replay() {
        crate::replay_seeds(claims_binding);
        claims_binding(&[]);
        claims_binding(&[0; 75]);
        claims_binding(&[255; 75]);
        let mut seed = 0x510e_527f_ade6_82d1_u64;
        for _ in 0..1024 {
            let mut bytes = [0; 75];
            for byte in &mut bytes {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed.to_le_bytes()[0];
            }
            claims_binding(&bytes);
        }
        for mask in 0..32 {
            let mut data = [0; 75];
            data[72] = mask;
            claims_binding(&data);
        }
    }
}
