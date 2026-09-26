//! The deployment side of verification: the owner schemes it accepts (§4),
//! its own auth v2 audience (§3.2, §7 step 5) and its `WebAuthn` relying
//! parties (§4.3), as a [`VerifierConfig`].

use std::net::{Ipv4Addr, Ipv6Addr};

use mkit_core::write_auth::validate_audience;

use super::webauthn::RelyingParty;
use super::{GrantError, OwnerScheme};

/// The owner schemes a deployment accepts, as advertised in `GetServerInfo`'s
/// `grant_schemes` (§4). A statement signed under any other scheme fails
/// verification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AcceptedSchemes(u8);

impl AcceptedSchemes {
    /// No scheme: every owner-signed statement is rejected.
    pub const NONE: Self = Self(0);

    fn bit(scheme: OwnerScheme) -> u8 {
        match scheme {
            OwnerScheme::Ed25519 => 1,
            OwnerScheme::Secp256k1Eip191 => 1 << 1,
            OwnerScheme::WebAuthnP256 => 1 << 2,
        }
    }

    /// The set of these schemes.
    #[must_use]
    pub fn of(schemes: &[OwnerScheme]) -> Self {
        Self(schemes.iter().fold(0, |acc, s| acc | Self::bit(*s)))
    }

    /// Parse advertised scheme tokens. Duplicates are harmless.
    ///
    /// # Errors
    /// `UnknownScheme` for a token not defined in §4.
    pub fn from_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Result<Self, GrantError> {
        let mut out = Self::NONE;
        for token in tokens {
            let scheme = OwnerScheme::from_token(token).ok_or(GrantError::UnknownScheme)?;
            out.0 |= Self::bit(scheme);
        }
        Ok(out)
    }

    /// Whether `scheme` is accepted.
    #[must_use]
    pub fn contains(self, scheme: OwnerScheme) -> bool {
        self.0 & Self::bit(scheme) != 0
    }

    /// The accepted schemes' tokens, in §4 table order (for `grant_schemes`).
    pub fn tokens(self) -> impl Iterator<Item = &'static str> {
        OwnerScheme::ALL
            .into_iter()
            .filter(move |s| self.contains(*s))
            .map(OwnerScheme::token)
    }
}

/// A deployment's verifier configuration: its own auth v2 audience, the
/// owner schemes it accepts, and the `WebAuthn` relying parties it accepts
/// `webauthn-p256` assertions for (§4.3).
///
/// Only [`VerifierConfig::new`] and [`VerifierConfig::new_allowing_loopback`]
/// build one. Both require a canonical auth v2 origin (SPEC-TRANSPORT-CONNECT
/// §7.1), and refuse `webauthn-p256` without a relying party (§4.3: "a
/// deployment that has configured no relying party MUST NOT accept, or
/// advertise, `webauthn-p256`"). `new` also enforces §3.2 and §10: a
/// deployment's own audience is "an origin whose host the operator controls,
/// never a loopback address". That rule binds the deployment's own audience
/// only; a grant's audience list may name loopback origins, and they simply
/// never match a deployment built with `new`. `new` refuses loopback relying
/// parties for the same reason: any local process can ask a passkey to sign
/// for `localhost`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierConfig {
    audience: String,
    schemes: AcceptedSchemes,
    relying_parties: Vec<RelyingParty>,
}

impl VerifierConfig {
    /// A production configuration. `relying_parties` may be empty unless
    /// `schemes` includes `webauthn-p256`; relying parties configured while
    /// that scheme is not accepted are unused.
    ///
    /// # Errors
    /// `Audience` for an origin outside the auth v2 rules;
    /// `LoopbackAudience` for a loopback or unspecified host (see
    /// [`is_loopback_origin`]); `NoRelyingParty` if `schemes` includes
    /// `webauthn-p256` and `relying_parties` is empty; `RelyingParty` for two
    /// relying parties with one id; `LoopbackRelyingParty` for a relying
    /// party with id `localhost` or `*.localhost`, or a loopback origin.
    pub fn new(
        audience: &str,
        schemes: AcceptedSchemes,
        relying_parties: Vec<RelyingParty>,
    ) -> Result<Self, GrantError> {
        if is_loopback_origin(audience) {
            validate_audience(audience).map_err(|_| GrantError::Audience)?;
            return Err(GrantError::LoopbackAudience);
        }
        let cfg = Self::new_allowing_loopback(audience, schemes, relying_parties)?;
        if cfg.relying_parties.iter().any(RelyingParty::is_loopback) {
            return Err(GrantError::LoopbackRelyingParty);
        }
        Ok(cfg)
    }

    /// **Development and tests only.** As [`VerifierConfig::new`], but a
    /// loopback audience such as `http://localhost:8080` or
    /// `http://[::1]:8443`, and loopback relying parties, are allowed. A
    /// deployment reachable by anyone else MUST NOT use this (§3.2, §10):
    /// every local deployment shares a loopback audience, so a grant for one
    /// would verify at all of them.
    ///
    /// # Errors
    /// `Audience`, `NoRelyingParty` or `RelyingParty`, as
    /// [`VerifierConfig::new`].
    pub fn new_allowing_loopback(
        audience: &str,
        schemes: AcceptedSchemes,
        relying_parties: Vec<RelyingParty>,
    ) -> Result<Self, GrantError> {
        validate_audience(audience).map_err(|_| GrantError::Audience)?;
        if schemes.contains(OwnerScheme::WebAuthnP256) && relying_parties.is_empty() {
            return Err(GrantError::NoRelyingParty);
        }
        for (i, rp) in relying_parties.iter().enumerate() {
            if relying_parties[..i].iter().any(|r| r.id() == rp.id()) {
                return Err(GrantError::RelyingParty);
            }
        }
        Ok(Self {
            audience: audience.to_owned(),
            schemes,
            relying_parties,
        })
    }

    /// The deployment's own auth v2 audience, which §7 step 5, §5.2 check 4
    /// and §9.1 look for, byte for byte.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The accepted owner schemes.
    #[must_use]
    pub fn schemes(&self) -> AcceptedSchemes {
        self.schemes
    }

    /// The configured `WebAuthn` relying parties (§4.3 rule 4).
    #[must_use]
    pub fn relying_parties(&self) -> &[RelyingParty] {
        &self.relying_parties
    }

    /// Whether `rp_id` is configured with `origin` (§4.3 rule 4).
    pub(crate) fn allows_relying_party(&self, rp_id: &str, origin: &str) -> bool {
        self.relying_parties
            .iter()
            .any(|rp| rp.id() == rp_id && rp.allows(origin))
    }
}

/// Whether an origin's host is a loopback or unspecified address, so it can
/// never be an origin "whose host the operator controls" (§3.2, §10).
///
/// Loopback here is: `localhost` and every `*.localhost` name (RFC 6761
/// §6.3); any IPv4 address in `127.0.0.0/8` or `0.0.0.0/8`, in every form
/// the WHATWG URL host parser accepts (so `127.1` and `0x7f.0.0.1` count);
/// and the IPv6 addresses `::1` and `::`, plus the IPv4-mapped or
/// -compatible forms of the IPv4 ranges. A host that ends in a number but is
/// not a valid IPv4 address also counts, failing closed. Any other input,
/// including a non-origin, is not loopback; [`VerifierConfig::new`] checks
/// the origin rules separately.
#[must_use]
pub fn is_loopback_origin(origin: &str) -> bool {
    let Some(authority) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return false;
    };
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((v6, _)) = rest.split_once(']') else {
            return false;
        };
        return v6.parse::<Ipv6Addr>().is_ok_and(|ip| {
            ip.is_loopback() || ip.is_unspecified() || ip.to_ipv4().is_some_and(ipv4_is_local)
        });
    }
    let host = authority.split_once(':').map_or(authority, |(h, _)| h);
    let host = host.to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match whatwg_ipv4(&host) {
        Ipv4Host::NotIpv4 => false,
        Ipv4Host::Invalid => true,
        Ipv4Host::Addr(ip) => ipv4_is_local(ip),
    }
}

fn ipv4_is_local(ip: Ipv4Addr) -> bool {
    matches!(ip.octets()[0], 0 | 127)
}

enum Ipv4Host {
    NotIpv4,
    Invalid,
    Addr(Ipv4Addr),
}

/// One WHATWG IPv4 number: `0x` hex, a leading-`0` octal, or decimal.
fn whatwg_number(part: &str) -> Option<u64> {
    let (digits, radix) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else {
            (part, 10)
        };
    if digits.is_empty() {
        return (radix == 16).then_some(0);
    }
    u64::from_str_radix(digits, radix).ok()
}

/// The WHATWG URL IPv4 host parser: a host whose last label is a number is
/// an IPv4 address (in one of the dotted forms `a`, `a.b`, `a.b.c`,
/// `a.b.c.d`), or else invalid.
fn whatwg_ipv4(host: &str) -> Ipv4Host {
    let labels: Vec<&str> = host.split('.').collect();
    let last = labels.last().copied().unwrap_or_default();
    let is_number = !last.is_empty()
        && (last.bytes().all(|b| b.is_ascii_digit())
            || last
                .strip_prefix("0x")
                .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit())));
    if !is_number {
        return Ipv4Host::NotIpv4;
    }
    if labels.len() > 4 {
        return Ipv4Host::Invalid;
    }
    let Some(numbers) = labels
        .iter()
        .map(|l| whatwg_number(l))
        .collect::<Option<Vec<u64>>>()
    else {
        return Ipv4Host::Invalid;
    };
    let (init, tail) = numbers.split_at(numbers.len() - 1);
    if init.iter().any(|n| *n > 255) {
        return Ipv4Host::Invalid;
    }
    let tail_bits = 8 * (5 - numbers.len());
    if tail[0] >= 1 << tail_bits {
        return Ipv4Host::Invalid;
    }
    let mut value = tail[0];
    for (i, n) in init.iter().enumerate() {
        value |= n << (24 - 8 * i);
    }
    u32::try_from(value).map_or(Ipv4Host::Invalid, |v| Ipv4Host::Addr(Ipv4Addr::from(v)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_schemes_from_tokens() {
        let all =
            AcceptedSchemes::from_tokens(["ed25519", "secp256k1-eip191", "webauthn-p256"]).unwrap();
        assert!(OwnerScheme::ALL.iter().all(|s| all.contains(*s)));
        assert_eq!(
            all.tokens().collect::<Vec<_>>(),
            ["ed25519", "secp256k1-eip191", "webauthn-p256"]
        );
        let ed = AcceptedSchemes::from_tokens(["ed25519", "ed25519"]).unwrap();
        assert_eq!(ed, AcceptedSchemes::of(&[OwnerScheme::Ed25519]));
        assert!(!ed.contains(OwnerScheme::Secp256k1Eip191));
        assert_eq!(
            AcceptedSchemes::from_tokens([]).unwrap(),
            AcceptedSchemes::NONE
        );
        for bad in ["ED25519", "p256", ""] {
            assert_eq!(
                AcceptedSchemes::from_tokens(["ed25519", bad]),
                Err(GrantError::UnknownScheme)
            );
        }
    }

    #[test]
    fn verifier_config_rejects_loopback_audience() {
        let ed = AcceptedSchemes::of(&[OwnerScheme::Ed25519]);
        for loopback in [
            "http://localhost",
            "http://localhost:8080",
            "https://git.localhost",
            "http://127.0.0.1:8080",
            "http://127.1",
            "http://127.255.255.254",
            "http://0x7f.0.0.1",
            "http://0177.0.0.1",
            "http://2130706433",
            "http://0.0.0.0:8080",
            "http://0",
            "http://[::1]:8443",
            "https://[::1]",
            "http://[::]",
            "http://[::ffff:127.0.0.1]",
            "http://[::ffff:7f00:1]",
            "http://1.2.3.4.5",
            "http://256.0.0.1",
            "http://1.2.3.08",
        ] {
            assert!(is_loopback_origin(loopback), "{loopback}");
            assert_eq!(
                VerifierConfig::new(loopback, ed, vec![]),
                Err(GrantError::LoopbackAudience),
                "{loopback}"
            );
        }
        // The explicit development constructor allows the valid ones.
        let dev = VerifierConfig::new_allowing_loopback("http://[::1]:8443", ed, vec![]).unwrap();
        assert_eq!(dev.audience(), "http://[::1]:8443");
        assert!(VerifierConfig::new_allowing_loopback("http://localhost:8080", ed, vec![]).is_ok());
        for public in [
            "https://git.example.com",
            "https://127.example.com",
            "https://localhost.example.com",
            "https://example.com1",
            "http://10.0.0.1:8080",
            "http://128.0.0.1",
            "https://[2001:db8::1]:8443",
        ] {
            assert!(!is_loopback_origin(public), "{public}");
            let cfg = VerifierConfig::new(public, ed, vec![]).unwrap();
            assert_eq!(cfg.audience(), public);
            assert_eq!(cfg.schemes(), ed);
        }
    }

    #[test]
    fn verifier_config_requires_a_canonical_origin() {
        let ed = AcceptedSchemes::of(&[OwnerScheme::Ed25519]);
        for bad in [
            "https://git.example.com/",
            "https://Git.example.com",
            "https://git.example.com:443",
            "git.example.com",
            "https://*.example.com",
            "HTTP://LOCALHOST",
            "http://localhost:80",
        ] {
            let err = VerifierConfig::new(bad, ed, vec![]).unwrap_err();
            assert!(
                matches!(err, GrantError::Audience),
                "{bad}: {err:?} (a bad origin is an audience error, loopback or not)"
            );
            assert_eq!(
                VerifierConfig::new_allowing_loopback(bad, ed, vec![]),
                Err(GrantError::Audience),
                "{bad}"
            );
        }
    }

    #[test]
    fn verifier_config_webauthn_needs_relying_party() {
        let schemes = AcceptedSchemes::of(&[OwnerScheme::Ed25519, OwnerScheme::WebAuthnP256]);
        assert_eq!(
            VerifierConfig::new("https://git.example.com", schemes, vec![]),
            Err(GrantError::NoRelyingParty)
        );
        assert_eq!(
            VerifierConfig::new_allowing_loopback("http://localhost:8080", schemes, vec![]),
            Err(GrantError::NoRelyingParty)
        );
        let rp = RelyingParty::new("example.com", ["https://example.com"]).unwrap();
        let cfg =
            VerifierConfig::new("https://git.example.com", schemes, vec![rp.clone()]).unwrap();
        assert_eq!(cfg.relying_parties(), std::slice::from_ref(&rp));
        assert!(cfg.allows_relying_party("example.com", "https://example.com"));
        assert!(!cfg.allows_relying_party("example.com", "https://example.org"));
        assert!(!cfg.allows_relying_party("example.org", "https://example.com"));
        // Relying parties without the scheme are allowed and unused.
        let ed = AcceptedSchemes::of(&[OwnerScheme::Ed25519]);
        assert!(VerifierConfig::new("https://git.example.com", ed, vec![rp.clone()]).is_ok());
        // One id configured twice is ambiguous.
        let twin = RelyingParty::new("example.com", ["https://www.example.com"]).unwrap();
        assert_eq!(
            VerifierConfig::new("https://git.example.com", schemes, vec![rp, twin]),
            Err(GrantError::RelyingParty)
        );
    }

    #[test]
    fn verifier_config_rejects_loopback_relying_party() {
        let schemes = AcceptedSchemes::of(&[OwnerScheme::WebAuthnP256]);
        let public = RelyingParty::new("example.com", ["https://example.com"]).unwrap();
        for (id, origin) in [
            ("localhost", "http://localhost:8080"),
            ("dev.localhost", "https://dev.localhost"),
            ("example.net", "http://127.0.0.1:8080"),
        ] {
            let rp = RelyingParty::new(id, [origin]).unwrap();
            assert_eq!(
                VerifierConfig::new(
                    "https://git.example.com",
                    schemes,
                    vec![public.clone(), rp.clone()]
                ),
                Err(GrantError::LoopbackRelyingParty),
                "{id} {origin}"
            );
            assert!(
                VerifierConfig::new_allowing_loopback("https://git.example.com", schemes, vec![rp])
                    .is_ok()
            );
        }
    }
}
