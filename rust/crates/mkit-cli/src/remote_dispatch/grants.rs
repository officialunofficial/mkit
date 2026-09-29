//! Local grant choice for the Connect client. WP-2.13 supplies the user store.

use std::time::{SystemTime, UNIX_EPOCH};

use mkit_attest::grant::{
    Capabilities, Capability, Grant, RefFlags, RepoScope, SignedHeader, packmap_head,
};
use mkit_core::hash::from_hex;
use mkit_core::repo_identity::RepositoryIdentity;
use mkit_transport_connect::{GrantCondition, GrantOperation, GrantRequest, GrantSource};

struct Candidate {
    header: String,
    grant: Grant,
}

fn permits(flags: RefFlags, condition: GrantCondition) -> bool {
    match condition {
        GrantCondition::Missing => flags.contains(RefFlags::CREATE),
        GrantCondition::Match => {
            flags.contains(RefFlags::UPDATE) || flags.contains(RefFlags::FORCE)
        }
        GrantCondition::Any => flags.contains(RefFlags::FORCE),
        GrantCondition::Delete => flags.contains(RefFlags::DELETE),
        _ => false,
    }
}

/// A snapshot of encoded, owner-signed grant headers. The store in WP-2.13
/// will populate it after checking owner signatures on import.
#[allow(dead_code)] // Constructed by the WP-2.13 user grant store.
pub(crate) struct LocalGrants(Vec<Candidate>);

impl LocalGrants {
    #[allow(dead_code)] // Constructed by the WP-2.13 user grant store.
    pub(crate) fn from_headers(headers: impl IntoIterator<Item = String>) -> Self {
        Self(
            headers
                .into_iter()
                .filter_map(|header| {
                    let signed = SignedHeader::parse(&header).ok()?;
                    let grant = Grant::parse(&signed.statement).ok()?;
                    Some(Candidate { header, grant })
                })
                .collect(),
        )
    }

    fn select_at(&self, request: &GrantRequest<'_>, now: i64) -> Option<String> {
        let repository = RepositoryIdentity::parse_bare_allowed(request.repository).ok()?;
        let namespace = repository.namespace()?;
        let key = from_hex(request.public_key_hex).ok()?;
        self.0
            .iter()
            .filter_map(|candidate| {
                let grant = &candidate.grant;
                if grant.namespace != *namespace
                    || !grant.scope.covers(namespace, &repository)
                    || grant.grantee != key
                    || !grant.audiences.iter().any(|a| a == request.audience)
                    || grant.created_ms > now.saturating_add(30_000)
                    || now >= grant.expiry_ms
                {
                    return None;
                }
                let (capability_rank, ref_rank) = match request.operation {
                    GrantOperation::Read => {
                        let rank = match grant.capabilities {
                            Capabilities::ReadWrite => 3,
                            Capabilities::Read => 2,
                            Capabilities::Write => 1,
                        };
                        (rank, 0)
                    }
                    GrantOperation::BeginUpload { ref_name } => {
                        if !grant.capabilities.allows(Capability::Write) {
                            return None;
                        }
                        let scopes = grant.ref_scopes.as_ref()?;
                        if scopes.effective_flags(ref_name).is_empty() {
                            return None;
                        }
                        let specificity = scopes
                            .entries()
                            .iter()
                            .filter_map(|(pattern, flags)| {
                                (pattern.matches(ref_name) && !flags.is_empty()).then_some(
                                    match pattern {
                                        mkit_attest::grant::RefPattern::Exact(_) => usize::MAX,
                                        mkit_attest::grant::RefPattern::Prefix(prefix) => {
                                            prefix.len()
                                        }
                                    },
                                )
                            })
                            .max()
                            .unwrap_or(0);
                        (0, specificity)
                    }
                    GrantOperation::Write { refs } => {
                        if !grant.capabilities.allows(Capability::Write) {
                            return None;
                        }
                        let scopes = grant.ref_scopes.as_ref()?;
                        let mut rank = usize::MAX;
                        for reference in refs {
                            // Packmap refs are covered through the head ref. Their own
                            // condition does not impose a second flag requirement, but
                            // the head must be in the same request (§8.3: the server
                            // denies a packmap write without its head).
                            if let Some(head) = packmap_head(reference.name) {
                                if !refs.iter().any(|other| other.name == head) {
                                    return None;
                                }
                                continue;
                            }
                            let name = reference.name;
                            if !permits(scopes.effective_flags(name), reference.condition) {
                                return None;
                            }
                            let specificity = scopes
                                .entries()
                                .iter()
                                .filter_map(|(pattern, flags)| {
                                    (pattern.matches(name) && permits(*flags, reference.condition))
                                        .then_some(match pattern {
                                            mkit_attest::grant::RefPattern::Exact(_) => usize::MAX,
                                            mkit_attest::grant::RefPattern::Prefix(prefix) => {
                                                prefix.len()
                                            }
                                        })
                                })
                                .max()
                                .unwrap_or(0);
                            rank = rank.min(specificity);
                        }
                        (0, if refs.is_empty() { 0 } else { rank })
                    }
                    // Part and any future operation are ineligible.
                    _ => return None,
                };
                let repo_rank = usize::from(matches!(grant.scope, RepoScope::Repository(_)));
                Some((
                    candidate,
                    (capability_rank, repo_rank, ref_rank, grant.expiry_ms),
                ))
            })
            // Equal capability, scope, specificity and expiry fall back to the
            // greater header bytes, so the choice never depends on the store's
            // iteration order.
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.header.cmp(&b.0.header)))
            .map(|(candidate, _)| candidate.header.clone())
    }
}

impl GrantSource for LocalGrants {
    fn select(&self, request: &GrantRequest<'_>) -> Option<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())?;
        self.select_at(request, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_attest::grant::OwnerScheme;
    use mkit_transport_connect::GrantRef;

    const NS: &str = "0x8ba1f109551bd432803012645ac136ddd64dba72";
    const KEY: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    const NOW: i64 = 1_700_000_000_000;

    fn header(
        scope: &str,
        cap: &str,
        refs: &str,
        created: i64,
        expiry: i64,
        audience: &str,
        key: &str,
    ) -> String {
        let statement = format!(
            "mkit-write-grant:v1\n{NS}\n{scope}\n{key}\n{cap}\n{audience}\n{refs}\n0\n{created}\n{expiry}\n{}",
            "ab".repeat(32)
        );
        SignedHeader {
            statement: statement.into_bytes(),
            scheme: OwnerScheme::Ed25519,
            blob: vec![1; 64],
        }
        .encode()
        .unwrap()
    }

    fn request(operation: GrantOperation<'_>) -> GrantRequest<'_> {
        GrantRequest::new(
            "https://git.example.com",
            "0x8ba1f109551bd432803012645ac136ddd64dba72/photos",
            KEY,
            operation,
        )
    }

    #[test]
    fn filters_namespace_repo_audience_grantee_and_window() {
        let good = header(
            &format!("{NS}/photos"),
            "read",
            "-",
            NOW,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        );
        let mut foreign = SignedHeader::parse(&good).unwrap();
        foreign.statement = String::from_utf8(foreign.statement)
            .unwrap()
            .replace(NS, "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            .into_bytes();
        let candidates = vec![
            foreign.encode().unwrap(),
            header(
                &format!("{NS}/other"),
                "read",
                "-",
                NOW,
                NOW + 100_000,
                "https://git.example.com",
                KEY,
            ),
            header(
                &format!("{NS}/photos"),
                "read",
                "-",
                NOW,
                NOW + 100_000,
                "https://other.example.com",
                KEY,
            ),
            header(
                &format!("{NS}/photos"),
                "read",
                "-",
                NOW,
                NOW + 100_000,
                "https://git.example.com",
                &"cd".repeat(32),
            ),
            header(
                &format!("{NS}/photos"),
                "read",
                "-",
                NOW + 30_001,
                NOW + 100_000,
                "https://git.example.com",
                KEY,
            ),
            header(
                &format!("{NS}/photos"),
                "read",
                "-",
                NOW - 100_000,
                NOW,
                "https://git.example.com",
                KEY,
            ),
        ];
        assert!(
            LocalGrants::from_headers(candidates.clone())
                .select_at(&request(GrantOperation::Read), NOW)
                .is_none()
        );
        let mut candidates = candidates;
        candidates.push(good.clone());
        assert_eq!(
            LocalGrants::from_headers(candidates).select_at(&request(GrantOperation::Read), NOW),
            Some(good)
        );
        let boundary = header(
            &format!("{NS}/photos"),
            "read",
            "-",
            NOW + 30_000,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        );
        assert_eq!(
            LocalGrants::from_headers(vec![boundary.clone()])
                .select_at(&request(GrantOperation::Read), NOW),
            Some(boundary)
        );
    }

    #[test]
    fn read_preference_and_scope_ranking() {
        let write = header(
            &format!("{NS}/photos"),
            "write",
            "refs/*=cufd",
            NOW,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        );
        let read = header(
            &format!("{NS}/*"),
            "read",
            "-",
            NOW,
            NOW + 80_000,
            "https://git.example.com",
            KEY,
        );
        let both = header(
            &format!("{NS}/photos"),
            "read,write",
            "refs/*=cufd",
            NOW,
            NOW + 60_000,
            "https://git.example.com",
            KEY,
        );
        assert_eq!(
            LocalGrants::from_headers(vec![write.clone()])
                .select_at(&request(GrantOperation::Read), NOW),
            Some(write.clone())
        );
        assert_eq!(
            LocalGrants::from_headers(vec![write, read.clone()])
                .select_at(&request(GrantOperation::Read), NOW),
            Some(read.clone())
        );
        assert_eq!(
            LocalGrants::from_headers(vec![read, both.clone()])
                .select_at(&request(GrantOperation::Read), NOW),
            Some(both)
        );
        let earlier = header(
            &format!("{NS}/photos"),
            "read",
            "-",
            NOW,
            NOW + 40_000,
            "https://git.example.com",
            KEY,
        );
        let later = header(
            &format!("{NS}/photos"),
            "read",
            "-",
            NOW,
            NOW + 50_000,
            "https://git.example.com",
            KEY,
        );
        assert_eq!(
            LocalGrants::from_headers(vec![later.clone(), earlier])
                .select_at(&request(GrantOperation::Read), NOW),
            Some(later)
        );
    }

    #[test]
    fn write_flags_packmap_coverage_and_specificity() {
        let broad = header(
            &format!("{NS}/*"),
            "write",
            "refs/heads/*=cufd",
            NOW,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        );
        let exact = header(
            &format!("{NS}/photos"),
            "write",
            "refs/heads/main=cu",
            NOW,
            NOW + 60_000,
            "https://git.example.com",
            KEY,
        );
        let source = LocalGrants::from_headers(vec![broad.clone(), exact.clone()]);
        for (condition, expected) in [
            (GrantCondition::Missing, exact.as_str()),
            (GrantCondition::Match, exact.as_str()),
            (GrantCondition::Any, broad.as_str()),
            (GrantCondition::Delete, broad.as_str()),
        ] {
            let refs = [GrantRef::new("refs/heads/main", condition)];
            assert_eq!(
                source
                    .select_at(&request(GrantOperation::Write { refs: &refs }), NOW)
                    .as_deref(),
                Some(expected)
            );
        }
        let refs = [GrantRef::new(
            "refs/mkit/packmap/main",
            GrantCondition::Match,
        )];
        // A packmap write without its head is never sent with a grant (§8.3).
        assert_eq!(
            source.select_at(&request(GrantOperation::Write { refs: &refs }), NOW),
            None
        );
        let refs = [
            GrantRef::new("refs/heads/main", GrantCondition::Match),
            GrantRef::new("refs/mkit/packmap/main", GrantCondition::Match),
        ];
        assert_eq!(
            source.select_at(&request(GrantOperation::Write { refs: &refs }), NOW),
            Some(exact)
        );
        let irrelevant_exact = header(
            &format!("{NS}/photos"),
            "write",
            "refs/*=f;refs/heads/main=c",
            NOW,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        );
        let relevant_prefix = header(
            &format!("{NS}/photos"),
            "write",
            "refs/heads/*=f",
            NOW,
            NOW + 50_000,
            "https://git.example.com",
            KEY,
        );
        let refs = [GrantRef::new("refs/heads/main", GrantCondition::Any)];
        assert_eq!(
            LocalGrants::from_headers(vec![irrelevant_exact, relevant_prefix.clone()])
                .select_at(&request(GrantOperation::Write { refs: &refs }), NOW),
            Some(relevant_prefix),
        );
        assert!(
            source
                .select_at(&request(GrantOperation::Part), NOW)
                .is_none()
        );
    }

    #[test]
    fn packmap_condition_does_not_add_a_flag_requirement() {
        for (flag, head_condition, packmap_condition) in [
            ("u", GrantCondition::Match, GrantCondition::Missing),
            ("c", GrantCondition::Missing, GrantCondition::Match),
        ] {
            let grant = header(
                &format!("{NS}/photos"),
                "write",
                &format!("refs/heads/main={flag}"),
                NOW,
                NOW + 100_000,
                "https://git.example.com",
                KEY,
            );
            let refs = [
                GrantRef::new("refs/heads/main", head_condition),
                GrantRef::new("refs/mkit/packmap/main", packmap_condition),
            ];
            assert_eq!(
                LocalGrants::from_headers(vec![grant.clone()])
                    .select_at(&request(GrantOperation::Write { refs: &refs }), NOW),
                Some(grant),
            );
        }
    }

    #[test]
    fn write_ranking_expiry_then_header_bytes_on_full_tie() {
        let earlier = header(
            &format!("{NS}/photos"),
            "write",
            "refs/heads/main=u",
            NOW,
            NOW + 40_000,
            "https://git.example.com",
            KEY,
        );
        let later = header(
            &format!("{NS}/photos"),
            "write",
            "refs/heads/main=u",
            NOW,
            NOW + 50_000,
            "https://git.example.com",
            KEY,
        );
        let tied = header(
            &format!("{NS}/photos"),
            "write",
            "refs/heads/main=u",
            NOW - 1,
            NOW + 50_000,
            "https://git.example.com",
            KEY,
        );
        let refs = [GrantRef::new("refs/heads/main", GrantCondition::Match)];
        let request = request(GrantOperation::Write { refs: &refs });
        assert_eq!(
            LocalGrants::from_headers(vec![later.clone(), earlier]).select_at(&request, NOW),
            Some(later.clone()),
        );
        // A full tie picks the greater header bytes in either source order.
        let winner = std::cmp::max(later.clone(), tied.clone());
        assert_eq!(
            LocalGrants::from_headers(vec![later.clone(), tied.clone()]).select_at(&request, NOW),
            Some(winner.clone()),
        );
        assert_eq!(
            LocalGrants::from_headers(vec![tied, later]).select_at(&request, NOW),
            Some(winner),
        );
    }
}
