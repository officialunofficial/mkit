//! Stable seed replay shared by decoder and transition harnesses.
#![forbid(unsafe_code)]

#[path = "../../tests/support/fork.rs"]
pub mod fork;

/// Largest input admitted by a fuzz body before applying its own tighter limits.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

/// Replay deterministic boundary seeds through the same body used by a fuzz target.
/// Bodies and their target registrations land alongside each owning decoder.
pub fn replay_seeds(mut body: impl FnMut(&[u8])) {
    body(&[]);
    let zeros = [0; 64];
    let high = [255; 64];
    for len in [1, 3, 4, 7, 8, 31, 32, 63, 64] {
        body(&zeros[..len]);
        body(&high[..len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_seed_replay_is_bounded_and_repeatable() {
        let mut first = Vec::new();
        replay_seeds(|seed| {
            assert!(seed.len() <= MAX_INPUT_BYTES);
            first.push(seed.to_vec());
        });
        let mut second = Vec::new();
        replay_seeds(|seed| second.push(seed.to_vec()));
        assert_eq!(first, second);
        assert!(first.iter().any(Vec::is_empty));
        assert!(first.iter().any(|seed| seed.len() == 32));
    }
}
