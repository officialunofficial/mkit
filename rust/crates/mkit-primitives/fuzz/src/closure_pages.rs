//! Authenticated malformed-page replay, independent of closure proof construction.

use mkit_core::hash::domain_digest;
use mkit_primitives::{
    closure::output::{
        PageDecodeCfg, decode_missing, decode_witness, encode_missing, encode_witness,
        validate_state_page,
    },
    error::FailureCode,
    evidence::{PageCommitment, PageKind},
};

const CFG: PageDecodeCfg = PageDecodeCfg {
    max_bytes: 4096,
    max_reasons: 64,
    max_work: 8192,
};

#[derive(Clone, Copy)]
enum Format {
    State,
    Witness,
    Missing,
}
impl Format {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::State => b"mkit-closure-state:v1",
            Self::Witness => b"mkit-closure-witness:v1",
            Self::Missing => b"mkit-closure-missing:v1",
        }
    }
}

fn decode(format: Format, page: PageCommitment, bytes: &[u8]) -> Result<(), FailureCode> {
    match format {
        Format::State => validate_state_page(page, bytes, CFG).map_err(|error| error.code),
        Format::Witness => {
            let decoded = decode_witness(page, bytes, CFG).map_err(|error| error.code)?;
            let (encoded_page, encoded) = encode_witness(decoded.previous, &decoded.fact)
                .expect("one bounded decoded witness can be reencoded");
            assert_eq!(encoded.as_slice(), bytes, "witness encoding is canonical");
            assert_eq!(encoded_page, page);
            Ok(())
        }
        Format::Missing => {
            let decoded = decode_missing(page, bytes, CFG).map_err(|error| error.code)?;
            let (encoded_page, encoded) = encode_missing(decoded.previous, &decoded.missing)
                .expect("one bounded decoded missing page can be reencoded");
            assert_eq!(encoded.as_slice(), bytes, "missing encoding is canonical");
            assert_eq!(encoded_page, page);
            Ok(())
        }
    }
}

/// Replay each grammar with an authentic commitment, then corrupt its bindings.
///
/// # Panics
///
/// Panics if decoding is nondeterministic, accepts a wrong commitment, or accepts
/// witness or missing bytes that do not round-trip to their exact encoding.
pub fn replay(data: &[u8]) {
    let bytes = &data[..data.len().min(4096)];
    for format in [Format::State, Format::Witness, Format::Missing] {
        let page = PageCommitment {
            digest: domain_digest(format.domain(), bytes),
            kind: PageKind::Closure,
            len: bytes.len() as u64,
            items: 1,
        };
        assert_eq!(decode(format, page, bytes), decode(format, page, bytes));

        let mut wrong_role = page;
        wrong_role.kind = PageKind::Objects;
        let mut wrong_count = page;
        wrong_count.items = 0;
        let mut wrong_length = page;
        wrong_length.len += 1;
        let mut wrong_hash = page;
        wrong_hash.digest[0] ^= 1;
        for invalid in [wrong_role, wrong_count, wrong_length, wrong_hash] {
            let first = decode(format, invalid, bytes);
            assert!(first.is_err(), "wrong role, count, length or hash accepted");
            assert_eq!(first, decode(format, invalid, bytes));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_authenticated_closure_page_seeds() {
        crate::replay_seeds(replay);
        for (index, seed) in [
            include_bytes!("../../fixtures/closure/state-gray.bin").as_slice(),
            include_bytes!("../../fixtures/closure/state-black.bin").as_slice(),
            include_bytes!("../../fixtures/closure/state-absent.bin").as_slice(),
            include_bytes!("../../fixtures/closure/state-member.bin").as_slice(),
            include_bytes!("../../fixtures/closure/witness-member.bin").as_slice(),
            include_bytes!("../../fixtures/closure/missing-all-reasons.bin").as_slice(),
        ]
        .into_iter()
        .enumerate()
        {
            let format = match index {
                0..=3 => Format::State,
                4 => Format::Witness,
                _ => Format::Missing,
            };
            let page = PageCommitment {
                digest: domain_digest(format.domain(), seed),
                kind: PageKind::Closure,
                len: seed.len() as u64,
                items: 1,
            };
            assert!(
                decode(format, page, seed).is_ok(),
                "valid frozen page refused"
            );
            replay(seed);
            // Every byte position and every strict prefix enters authenticated
            // parsing; these cases cannot stop at a stale digest check.
            for end in 0..seed.len() {
                replay(&seed[..end]);
                let mut mutated = seed.to_vec();
                mutated[end] ^= 0xff;
                replay(&mutated);
            }
            let mut trailing = seed.to_vec();
            trailing.push(0);
            replay(&trailing);
        }
        replay(&[0; 1024]);
        replay(&[0; 1025]);
        replay(&[0; 4096]);
        replay(&[0; 4097]);
    }
}
