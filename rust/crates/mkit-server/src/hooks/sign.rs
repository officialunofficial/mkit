//! Runtime-specific nonce source for remote hooks.

use crate::rt::{MaybeSend, MaybeSync};

/// The source of the fresh 32-byte nonce every attempt carries.
pub trait NonceSource: MaybeSend + MaybeSync {
    /// Fill `nonce` with 32 fresh random bytes; `false` on failure.
    fn fill(&self, nonce: &mut [u8; 32]) -> bool;
}

/// The operating system's CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsNonces;

impl NonceSource for OsNonces {
    fn fill(&self, nonce: &mut [u8; 32]) -> bool {
        getrandom::fill(nonce).is_ok()
    }
}
