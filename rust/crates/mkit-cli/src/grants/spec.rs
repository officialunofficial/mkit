//! Turning command-line spellings into the canonical statements of
//! SPEC-WRITE-GRANTS §3, §5.1 and §9.1.
//!
//! The statement codecs in `mkit-attest` never sort or repair, so this
//! module does the canonicalizing a person expects: `--cap write,read` becomes
//! `read,write`, audiences and ref scopes are sorted and deduplicated, and ref
//! flags are put in `cufd` order.

use mkit_attest::grant::text::encode_audiences;
use mkit_attest::grant::{
    Capabilities, EpochStatement, Grant, GrantError, MAX_AUDIENCES, MAX_REF_SCOPES, Namespace,
    RefFlags, RefPattern, RefScopes, RepoScope, RepositoryIdentity, Visibility,
    VisibilityStatement,
};

/// Longest lifetime `--ttl` accepts (§1.1): 30 days.
pub const MAX_TTL_SECS: u64 = 2_592_000;
/// Default `--ttl` of a grant.
pub const DEFAULT_GRANT_TTL: &str = "7d";
/// Default lifetime of an epoch or visibility statement. Short on purpose:
/// the statement is signed for one command, and a shorter window narrows what
/// a leaked statement can do.
pub const DEFAULT_STATEMENT_TTL_MS: i64 = 10 * 60 * 1000;

/// Slack on top of `--timeout` so the last re-send still lands before expiry.
const STATEMENT_SLACK_MS: i64 = 2 * 60 * 1000;

/// How long an epoch or visibility statement stays valid: the default, or,
/// when the command will wait longer than that for the server, the wait plus a
/// little slack, so a re-send late in a long `--timeout` is not rejected as
/// expired. Never above the 30-day statement maximum.
#[must_use]
pub fn statement_lifetime_ms(wait: std::time::Duration) -> i64 {
    let wait_ms = i64::try_from(wait.as_millis()).unwrap_or(i64::MAX);
    wait_ms
        .saturating_add(STATEMENT_SLACK_MS)
        .clamp(DEFAULT_STATEMENT_TTL_MS, MAX_TTL_SECS.cast_signed() * 1000)
}

/// `30d`, `12h`, `90m`, `3600s`, or bare seconds; at most 30 days. Returns
/// milliseconds.
///
/// # Errors
/// An unparsable, zero or too-long duration.
pub fn parse_ttl(text: &str) -> Result<i64, String> {
    let text = text.trim();
    let (digits, unit) = match text.char_indices().last() {
        Some((i, 'd')) => (&text[..i], 86_400),
        Some((i, 'h')) => (&text[..i], 3_600),
        Some((i, 'm')) => (&text[..i], 60),
        Some((i, 's')) => (&text[..i], 1),
        Some(_) => (text, 1),
        None => return Err("empty duration".to_owned()),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| format!("`{text}` is not a duration (use 30d, 12h, 90m or 3600s)"))?;
    let seconds = value
        .checked_mul(unit)
        .filter(|s| *s > 0)
        .ok_or_else(|| format!("`{text}` is not a positive duration"))?;
    if seconds > MAX_TTL_SECS {
        return Err(format!(
            "`{text}` exceeds the 30-day maximum grant lifetime (SPEC-WRITE-GRANTS §1.1)"
        ));
    }
    i64::try_from(seconds * 1000).map_err(|_| "duration out of range".to_owned())
}

/// Accept `read`, `write` or both in either order, and spell them
/// canonically (§3.2): `read`, `read,write` or `write`.
///
/// # Errors
/// Anything but a non-empty set of `read` and `write`.
pub fn canonical_capabilities(text: &str) -> Result<Capabilities, String> {
    let (mut read, mut write) = (false, false);
    for part in text.split(',') {
        match part.trim() {
            "read" => read = true,
            "write" => write = true,
            other => {
                return Err(format!(
                    "capability `{other}` is not `read` or `write` (use --cap read, read,write or write)"
                ));
            }
        }
    }
    Ok(match (read, write) {
        (true, true) => Capabilities::ReadWrite,
        (true, false) => Capabilities::Read,
        _ => Capabilities::Write,
    })
}

/// Sort and deduplicate audiences, and check each against §3.2.
///
/// # Errors
/// An audience outside the auth v2 origin rules, or a count outside 1–8.
pub fn canonical_audiences(items: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = items.iter().map(|a| a.trim().to_owned()).collect();
    out.sort();
    out.dedup();
    if out.is_empty() || out.len() > MAX_AUDIENCES {
        return Err(format!("expected 1 to {MAX_AUDIENCES} audiences"));
    }
    for audience in &out {
        encode_audiences(std::slice::from_ref(audience))
            .map_err(|e| format!("audience `{audience}`: {e}"))?;
    }
    Ok(out)
}

/// Parse `pattern=flags` entries, put the flags in `cufd` order, merge
/// entries with the same pattern (a union, which is what §8.1 computes anyway)
/// and sort.
///
/// # Errors
/// A malformed pattern or flag, or more than 16 distinct patterns.
pub fn canonical_ref_scopes(items: &[String]) -> Result<RefScopes, String> {
    let mut merged: Vec<(RefPattern, RefFlags)> = Vec::new();
    for item in items {
        let (pattern, flags) = item
            .split_once('=')
            .ok_or_else(|| format!("--refs `{item}` must be `pattern=flags` (flags from cufd)"))?;
        let pattern = RefPattern::parse(pattern).map_err(|e| format!("--refs `{item}`: {e}"))?;
        let mut set = RefFlags::EMPTY;
        for c in flags.chars() {
            set = set.union(match c {
                'c' => RefFlags::CREATE,
                'u' => RefFlags::UPDATE,
                'f' => RefFlags::FORCE,
                'd' => RefFlags::DELETE,
                other => {
                    return Err(format!(
                        "--refs `{item}`: flag `{other}` is not one of c, u, f, d"
                    ));
                }
            });
        }
        if set.is_empty() {
            return Err(format!("--refs `{item}`: no flags"));
        }
        match merged.iter_mut().find(|(p, _)| *p == pattern) {
            Some((_, existing)) => *existing = existing.union(set),
            None => merged.push((pattern, set)),
        }
    }
    merged.sort_by_key(|(pattern, flags)| format!("{pattern}={flags}"));
    if merged.len() > MAX_REF_SCOPES {
        return Err(format!("at most {MAX_REF_SCOPES} ref scopes"));
    }
    RefScopes::new(merged).map_err(|e| format!("--refs: {e}"))
}

/// The repositories a new grant covers.
#[derive(Debug, Clone)]
pub enum RepoSelector {
    Name(String),
    All,
}

/// Everything `mkit grant create` collects before the owner is known.
#[derive(Debug, Clone)]
pub struct GrantSpec {
    pub repo: RepoSelector,
    pub grantee: [u8; 32],
    pub capabilities: Capabilities,
    pub audiences: Vec<String>,
    pub ref_scopes: Option<RefScopes>,
    pub epoch: u64,
    pub ttl_ms: i64,
}

fn nonce() -> Result<[u8; 32], String> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| format!("no entropy for the statement nonce: {e}"))?;
    Ok(nonce)
}

/// §3.3: ref scopes go with write and only with write.
///
/// # Errors
/// A read-only grant with `--refs`, or a write grant without.
pub fn check_ref_scopes(
    capabilities: Capabilities,
    ref_scopes: Option<&RefScopes>,
) -> Result<(), String> {
    match (capabilities, ref_scopes) {
        (Capabilities::Read, Some(_)) => Err(
            "a read-only grant takes no --refs (ref scopes apply to writes; SPEC-WRITE-GRANTS §3.3)"
                .to_owned(),
        ),
        (Capabilities::ReadWrite | Capabilities::Write, None) => Err(
            "a grant with write needs at least one --refs pattern=flags (for example --refs 'refs/heads/*=cuf')"
                .to_owned(),
        ),
        _ => Ok(()),
    }
}

/// Build the grant for `namespace`, created at `now_ms`.
///
/// # Errors
/// A scope, ref-scope or lifetime the statement rules refuse.
pub fn build_grant(spec: &GrantSpec, namespace: &Namespace, now_ms: i64) -> Result<Grant, String> {
    let scope = match &spec.repo {
        RepoSelector::All => RepoScope::Namespace,
        RepoSelector::Name(name) => RepoScope::Repository(
            RepositoryIdentity::parse(&format!("{namespace}/{name}"))
                .map_err(|e| format!("--repo `{name}`: {e}"))?,
        ),
    };
    check_ref_scopes(spec.capabilities, spec.ref_scopes.as_ref())?;
    Ok(Grant {
        namespace: *namespace,
        scope,
        grantee: spec.grantee,
        capabilities: spec.capabilities,
        audiences: spec.audiences.clone(),
        ref_scopes: spec.ref_scopes.clone(),
        epoch: spec.epoch,
        created_ms: now_ms,
        expiry_ms: now_ms
            .checked_add(spec.ttl_ms)
            .ok_or("lifetime out of range")?,
        nonce: nonce()?,
    })
}

/// Build an epoch statement raising `namespace` to `new_epoch`.
///
/// # Errors
/// No entropy for the nonce.
pub fn build_epoch(
    namespace: &Namespace,
    new_epoch: u64,
    audiences: &[String],
    now_ms: i64,
    lifetime_ms: i64,
) -> Result<EpochStatement, String> {
    Ok(EpochStatement {
        namespace: *namespace,
        new_epoch,
        audiences: audiences.to_vec(),
        created_ms: now_ms,
        expiry_ms: now_ms.saturating_add(lifetime_ms),
        nonce: nonce()?,
    })
}

/// Build a visibility statement for `repository`.
///
/// # Errors
/// No entropy for the nonce.
pub fn build_visibility(
    repository: &RepositoryIdentity,
    visibility: Visibility,
    audiences: &[String],
    now_ms: i64,
    lifetime_ms: i64,
) -> Result<VisibilityStatement, String> {
    Ok(VisibilityStatement {
        repository: repository.clone(),
        visibility,
        audiences: audiences.to_vec(),
        created_ms: now_ms,
        expiry_ms: now_ms.saturating_add(lifetime_ms),
        nonce: nonce()?,
    })
}

/// A statement the codec refused, phrased for a person.
#[must_use]
pub fn statement_error(error: GrantError) -> String {
    format!("invalid statement: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_canonicalized() {
        for (input, want) in [
            ("read", Capabilities::Read),
            ("write", Capabilities::Write),
            ("read,write", Capabilities::ReadWrite),
            ("write,read", Capabilities::ReadWrite),
            ("write, read", Capabilities::ReadWrite),
            ("read,read", Capabilities::Read),
        ] {
            assert_eq!(canonical_capabilities(input).unwrap(), want, "{input}");
        }
        for bad in ["", "admin", "read;write", "read,"] {
            assert!(canonical_capabilities(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            canonical_capabilities("write,read").unwrap().token(),
            "read,write"
        );
    }

    #[test]
    fn audiences_are_sorted_deduped_and_bounded() {
        let got = canonical_audiences(&[
            "https://b.example.com".to_owned(),
            "https://a.example.com".to_owned(),
            "https://b.example.com".to_owned(),
        ])
        .unwrap();
        assert_eq!(got, ["https://a.example.com", "https://b.example.com"]);
        assert!(canonical_audiences(&[]).is_err());
        assert!(canonical_audiences(&["https://*.example.com".to_owned()]).is_err());
        assert!(canonical_audiences(&["git.example.com".to_owned()]).is_err());
        let nine: Vec<String> = (0..9)
            .map(|i| format!("https://h{i}.example.com"))
            .collect();
        assert!(canonical_audiences(&nine).is_err());
    }

    #[test]
    fn ref_scopes_are_sorted_merged_and_flag_ordered() {
        let scopes = canonical_ref_scopes(&[
            "refs/heads/wip/*=dfuc".to_owned(),
            "refs/heads/main=u".to_owned(),
            "refs/heads/main=c".to_owned(),
        ])
        .unwrap();
        let text = scopes
            .entries()
            .iter()
            .map(|(p, f)| format!("{p}={f}"))
            .collect::<Vec<_>>()
            .join(";");
        assert_eq!(text, "refs/heads/main=cu;refs/heads/wip/*=cufd");
        for bad in [
            "refs/heads/main",
            "refs/heads/main=x",
            "refs/heads/main=",
            "*=c",
        ] {
            assert!(canonical_ref_scopes(&[bad.to_owned()]).is_err(), "{bad}");
        }
    }

    #[test]
    fn statement_lifetime_covers_the_wait_and_stays_in_bounds() {
        use std::time::Duration;
        assert_eq!(
            statement_lifetime_ms(Duration::from_secs(5)),
            DEFAULT_STATEMENT_TTL_MS
        );
        assert_eq!(
            statement_lifetime_ms(Duration::from_mins(5)),
            DEFAULT_STATEMENT_TTL_MS
        );
        // A 30 minute wait needs a statement that outlives it.
        assert_eq!(
            statement_lifetime_ms(Duration::from_mins(30)),
            32 * 60 * 1000
        );
        assert_eq!(
            statement_lifetime_ms(Duration::from_secs(u64::MAX / 4)),
            2_592_000_000
        );
    }

    #[test]
    fn ttl_parses_units_and_enforces_the_bound() {
        assert_eq!(parse_ttl("30d").unwrap(), 2_592_000_000);
        assert_eq!(parse_ttl("12h").unwrap(), 43_200_000);
        assert_eq!(parse_ttl("90m").unwrap(), 5_400_000);
        assert_eq!(parse_ttl("3600s").unwrap(), 3_600_000);
        assert_eq!(parse_ttl("60").unwrap(), 60_000);
        assert!(parse_ttl("31d").is_err());
        assert!(parse_ttl("0d").is_err());
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("abc").is_err());
    }
}
