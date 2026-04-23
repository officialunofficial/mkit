//! Sigstore signer — scaffold only.
//!
//! Will eventually wrap Fulcio OIDC + Rekor. Tracked in
//! `docs/SPEC-ATTESTATIONS.md` §6.2. The scaffold exists so a signer
//! router can dispatch on signer kind and get a concrete
//! `Error::SigstoreNotImplemented` back instead of a compile-time
//! branch.

use crate::Error;
use crate::signer::Signer;

#[derive(Debug, Default)]
pub struct SigstoreSigner;

impl SigstoreSigner {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Signer for SigstoreSigner {
    fn keyid(&self) -> Result<String, Error> {
        Err(Error::SigstoreNotImplemented)
    }
    fn sign(&mut self, _pae: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::SigstoreNotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_methods_return_not_implemented() {
        let mut s = SigstoreSigner::new();
        assert!(matches!(s.keyid(), Err(Error::SigstoreNotImplemented)));
        assert!(matches!(s.sign(b"pae"), Err(Error::SigstoreNotImplemented)));
    }
}
