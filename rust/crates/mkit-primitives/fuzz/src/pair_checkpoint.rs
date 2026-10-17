//! Bounded malformed-checkpoint replay for the local pair-coverage format.

use mkit_primitives::{
    closure::pair::{PairCheckpointCfg, PairWalker},
    error::FailureCode,
};

const CFG: PairCheckpointCfg = PairCheckpointCfg { max_bytes: 1 << 16 };

/// Decode arbitrary bytes as a pair checkpoint; refusal must be deterministic.
///
/// # Panics
/// Panics when decoding reports a code other than `InvalidCheckpoint`; that is
/// the decoder's only stable refusal.
pub fn replay(data: &[u8]) {
    if let Err(error) = PairWalker::validate_checkpoint(data, CFG) {
        assert_eq!(error.code, FailureCode::InvalidCheckpoint);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn seeds_decode_or_refuse_deterministically() {
        crate::replay_seeds(super::replay);
    }
}
