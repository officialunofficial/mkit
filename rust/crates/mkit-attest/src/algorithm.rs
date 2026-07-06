//! Algorithm identifiers for mkit signing.
//!
//! Uses COSE numeric IDs from the IANA registry
//! (<https://www.iana.org/assignments/cose/cose.xhtml>) so clients on
//! different platforms can interop at the wire:
//!
//! * `Ed25519`   — COSE `-19` (fully-specified `EdDSA` w/ Ed25519). The
//!   default mkit signer algorithm.
//! * `Secp256k1` — COSE `-47` (`ES256K`, secp256k1 + SHA-256). Used by
//!   wallet / browser-crypto clients.
//! * `P256`      — COSE `-7`  (`ES256`, P-256 + SHA-256). Used by iOS
//!   Secure Enclave and `WebAuthn` clients.
//!
//! The canonical `keyid` shape is `"<prefix>:<hex-pubkey>"` where
//! `<prefix>` is per-algorithm ([`Algorithm::prefix`]). The legacy
//! `blake3:` prefix is accepted by [`Algorithm::from_keyid`] and maps
//! to `Ed25519` for backward compatibility with attestations produced
//! before the multi-algorithm split.

use core::fmt;
use core::str::FromStr;

/// Signing algorithm. One variant per supported (curve, hash) pair.
///
/// The enum is `Copy` because it is a small fixed tag; callers are
/// expected to pass it by value through trait and function signatures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Ed25519 (COSE `-19`). Default mkit signer algorithm.
    Ed25519,
    /// secp256k1 + SHA-256 (COSE `-47`, `ES256K`).
    Secp256k1,
    /// P-256 + SHA-256 (COSE `-7`, `ES256`).
    P256,
    /// BLS12-381 M-of-N threshold (`MinSig` variant — signature in
    /// G1, public key in G2). Used by the release-party flow; see
    /// `docs/specs/SPEC-RELEASE-THRESHOLD.md`. No COSE id is registered for
    /// BLS threshold; [`Algorithm::cose_id`] returns a **provisional**
    /// project-local negative integer (`-256`) chosen outside the IANA
    /// reserved ranges. This value is NOT stable — it will be swapped
    /// for the assigned id (in a patch release) if IANA ever registers
    /// one, so do not persist it as a long-lived identifier. The stable
    /// wire-level identifier is `Algorithm::Bls12381Threshold
    /// = 5` in the mkit-rpc proto.
    ///
    /// Feature-gated behind `bls-threshold` because the `Signer`
    /// implementation pulls a sizeable dep tree (blst); the enum
    /// variant lives or dies with the implementation it identifies.
    #[cfg(feature = "bls-threshold")]
    Bls12381Threshold,
}

impl Algorithm {
    /// COSE numeric identifier per IANA registry.
    ///
    /// * `Ed25519`   — `-19` (fully-specified `EdDSA` w/ Ed25519)
    /// * `Secp256k1` — `-47` (ES256K)
    /// * `P256`      — `-7`  (ES256)
    #[must_use]
    pub fn cose_id(self) -> i32 {
        match self {
            Self::Ed25519 => -19,
            Self::Secp256k1 => -47,
            Self::P256 => -7,
            // No IANA COSE id is registered for BLS12-381 threshold.
            // -256 is a PROVISIONAL project-local id, outside the
            // assigned range (lowest assigned is -65535 in 2026) and
            // gives us room — if IANA ever registers one, we swap to the
            // assigned value in a patch release. Treat it as unstable.
            #[cfg(feature = "bls-threshold")]
            Self::Bls12381Threshold => -256,
        }
    }

    /// Short textual prefix used at the front of the canonical keyid.
    ///
    /// `<prefix>:<hex-pubkey>` is the canonical keyid shape. See
    /// `docs/specs/SPEC-ATTESTATIONS.md` §6.3.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Secp256k1 => "secp256k1",
            Self::P256 => "p256",
            // Matches the `KEYID_PREFIX` constant in
            // `signer_bls_threshold` (minus the trailing colon).
            #[cfg(feature = "bls-threshold")]
            Self::Bls12381Threshold => "bls12381-thr",
        }
    }

    /// Parse the algorithm out of a `"<prefix>:..."` keyid string.
    ///
    /// Accepts the canonical per-algorithm prefixes returned by
    /// [`Self::prefix`] and, for backward compatibility with
    /// attestations produced before the multi-algorithm split, the
    /// legacy `blake3:` prefix (which maps to `Ed25519`).
    ///
    /// Returns `None` if the keyid has no `':'` separator or if the
    /// prefix before the first `':'` is unknown.
    #[must_use]
    pub fn from_keyid(keyid: &str) -> Option<Self> {
        let (prefix, _) = keyid.split_once(':')?;
        match prefix {
            "ed25519" | "blake3" => Some(Self::Ed25519),
            "secp256k1" => Some(Self::Secp256k1),
            "p256" => Some(Self::P256),
            #[cfg(feature = "bls-threshold")]
            "bls12381-thr" => Some(Self::Bls12381Threshold),
            _ => None,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

/// `FromStr` parses the canonical prefix form (`"ed25519"`,
/// `"secp256k1"`, `"p256"`). Does NOT accept keyid strings with a
/// trailing `":hex"` — use [`Algorithm::from_keyid`] for that.
impl FromStr for Algorithm {
    type Err = UnknownAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(Self::Ed25519),
            "secp256k1" => Ok(Self::Secp256k1),
            "p256" => Ok(Self::P256),
            #[cfg(feature = "bls-threshold")]
            "bls12381-thr" => Ok(Self::Bls12381Threshold),
            other => Err(UnknownAlgorithm(other.to_owned())),
        }
    }
}

/// Error returned by `<Algorithm as FromStr>::from_str` for an unknown
/// prefix. Carries the offending string so callers can surface it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAlgorithm(pub String);

impl fmt::Display for UnknownAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown algorithm prefix: {}", self.0)
    }
}

impl std::error::Error for UnknownAlgorithm {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_ids_match_iana_registry() {
        assert_eq!(Algorithm::Ed25519.cose_id(), -19);
        assert_eq!(Algorithm::Secp256k1.cose_id(), -47);
        assert_eq!(Algorithm::P256.cose_id(), -7);
    }

    #[test]
    fn prefix_strings() {
        assert_eq!(Algorithm::Ed25519.prefix(), "ed25519");
        assert_eq!(Algorithm::Secp256k1.prefix(), "secp256k1");
        assert_eq!(Algorithm::P256.prefix(), "p256");
    }

    #[test]
    fn display_uses_prefix() {
        assert_eq!(Algorithm::Ed25519.to_string(), "ed25519");
        assert_eq!(Algorithm::Secp256k1.to_string(), "secp256k1");
        assert_eq!(Algorithm::P256.to_string(), "p256");
    }

    #[test]
    fn from_str_roundtrip_through_prefix() {
        for alg in [Algorithm::Ed25519, Algorithm::Secp256k1, Algorithm::P256] {
            let parsed: Algorithm = alg.prefix().parse().expect("round-trip parse");
            assert_eq!(parsed, alg);
        }
    }

    #[test]
    fn from_str_rejects_unknown() {
        let err: Result<Algorithm, _> = "rsa".parse();
        assert!(err.is_err());
        let err = "".parse::<Algorithm>().unwrap_err();
        assert_eq!(err.0, "");
    }

    #[test]
    fn from_keyid_parses_canonical_prefixes() {
        assert_eq!(
            Algorithm::from_keyid("ed25519:abc"),
            Some(Algorithm::Ed25519)
        );
        assert_eq!(
            Algorithm::from_keyid("secp256k1:dead"),
            Some(Algorithm::Secp256k1)
        );
        assert_eq!(Algorithm::from_keyid("p256:feed"), Some(Algorithm::P256));
    }

    #[test]
    fn from_keyid_legacy_blake3_maps_to_ed25519() {
        // Backward compat with attestations produced before the
        // multi-algorithm split. repo-key signer still emits
        // `blake3:<hex>` as its keyid.
        assert_eq!(
            Algorithm::from_keyid("blake3:deadbeef"),
            Some(Algorithm::Ed25519)
        );
    }

    #[test]
    fn from_keyid_unknown_prefix_returns_none() {
        assert_eq!(Algorithm::from_keyid("rsa:abc"), None);
        assert_eq!(Algorithm::from_keyid("sigstore:https://x"), None);
    }

    #[test]
    fn from_keyid_missing_colon_returns_none() {
        assert_eq!(Algorithm::from_keyid("ed25519"), None);
        assert_eq!(Algorithm::from_keyid(""), None);
    }

    #[test]
    fn from_keyid_handles_multiple_colons() {
        // Only the first `:` splits prefix from body.
        assert_eq!(
            Algorithm::from_keyid("sigstore:https://example.com/workflow"),
            None
        );
        // A trailing `:...:...` body is still valid prefix-lookup.
        assert_eq!(
            Algorithm::from_keyid("ed25519:aa:bb"),
            Some(Algorithm::Ed25519)
        );
    }
}
