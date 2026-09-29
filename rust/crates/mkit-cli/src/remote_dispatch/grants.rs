//! Local grant choice for the Connect client, over the user grant store
//! (`crate::grants::store`).
//!
//! Selection (WP-2.13, R-129, D-B2): filter to the grants valid for the
//! request, rank the higher epoch first, then the P-18 rules (capability
//! preference for reads, a grant that forces for an update (R-150), repository
//! over namespace scope, the most specific ref scope, the latest expiry), then the greater header bytes so the choice
//! never depends on directory order.
//!
//! Every candidate that survives the filter lists the request's audience and
//! is in the request's namespace, so "higher epoch first, per (namespace,
//! audience)" is a plain descending epoch among the survivors: a grant at
//! another audience or namespace is never a candidate and cannot interfere.
//! Nothing is pruned on import.
//!
//! Known downside: a grant pre-issued for epoch e+1 (SPEC-WRITE-GRANTS §5,
//! informative) outranks a live epoch-e grant until the owner bumps the epoch.
//! `mkit grant add` warns about it.

use std::time::{SystemTime, UNIX_EPOCH};

use mkit_attest::grant::{Capabilities, Capability, Grant, RefFlags, RepoScope, packmap_head};
use mkit_core::hash::from_hex;
use mkit_core::repo_identity::RepositoryIdentity;
use mkit_transport_connect::{GrantCondition, GrantOperation, GrantRequest, GrantSource};

use crate::grants::store::StoredGrant;
#[cfg(test)]
use mkit_attest::grant::SignedHeader;

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

/// A snapshot of encoded, owner-signed grant headers, built from the user
/// grant store, which re-verified every owner signature when it loaded.
pub(crate) struct LocalGrants(Vec<Candidate>);

impl LocalGrants {
    pub(crate) fn from_stored(grants: impl IntoIterator<Item = StoredGrant>) -> Self {
        Self(
            grants
                .into_iter()
                .map(|stored| Candidate {
                    header: stored.header,
                    grant: stored.grant,
                })
                .collect(),
        )
    }

    #[cfg(test)]
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

    #[allow(clippy::too_many_lines)] // one filter-and-rank pass over the candidates
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
                let (capability_rank, force_rank, ref_rank) = match request.operation {
                    GrantOperation::Read => {
                        let rank = match grant.capabilities {
                            Capabilities::ReadWrite => 3,
                            Capabilities::Read => 2,
                            Capabilities::Write => 1,
                        };
                        (rank, 0, 0)
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
                        (0, 0, specificity)
                    }
                    GrantOperation::Write { refs } => {
                        if !grant.capabilities.allows(Capability::Write) {
                            return None;
                        }
                        let scopes = grant.ref_scopes.as_ref()?;
                        let mut rank = usize::MAX;
                        // A server that can't check fast-forwards (every
                        // Stage 1 deployment) applies a `MATCH` update only
                        // under `f` (R-150). Prefer a grant that forces, and
                        // fall back to a `u`-only one for a server that can.
                        let mut forces = true;
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
                            let effective = scopes.effective_flags(name);
                            if !permits(effective, reference.condition) {
                                return None;
                            }
                            if reference.condition == GrantCondition::Match
                                && !effective.contains(RefFlags::FORCE)
                            {
                                forces = false;
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
                        (
                            0,
                            usize::from(forces),
                            if refs.is_empty() { 0 } else { rank },
                        )
                    }
                    // Part and any future operation are ineligible.
                    _ => return None,
                };
                let repo_rank = usize::from(matches!(grant.scope, RepoScope::Repository(_)));
                Some((
                    candidate,
                    (
                        grant.epoch,
                        capability_rank,
                        force_rank,
                        repo_rank,
                        ref_rank,
                        grant.expiry_ms,
                    ),
                ))
            })
            // Equal epoch, capability, scope, specificity and expiry fall back
            // to the greater header bytes, so the choice never depends on the store's
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
            // An update prefers the grant that can force (R-150), whatever
            // the scope: an opaque server applies `MATCH` updates only under `f`.
            (GrantCondition::Match, broad.as_str()),
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
            Some(broad.clone())
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

    /// The same header with a different epoch (the statement bytes change;
    /// the fake signature is irrelevant to selection).
    fn at_epoch(header: &str, epoch: u64) -> String {
        let mut signed = SignedHeader::parse(header).unwrap();
        let mut grant = Grant::parse(&signed.statement).unwrap();
        grant.epoch = epoch;
        signed.statement = grant.encode().unwrap();
        signed.encode().unwrap()
    }

    #[test]
    fn a_higher_epoch_outranks_scope_and_expiry() {
        let live = header(
            &format!("{NS}/photos"),
            "write",
            "refs/heads/main=cufd",
            NOW,
            NOW + 90_000,
            "https://git.example.com",
            KEY,
        );
        let refs = [GrantRef::new("refs/heads/main", GrantCondition::Match)];
        let request = request(GrantOperation::Write { refs: &refs });
        // A broader, longer-lived grant at a lower epoch loses to a narrower
        // one at a higher epoch.
        let stale = header(
            &format!("{NS}/*"),
            "write",
            "refs/*=cufd",
            NOW,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        );
        let newer = at_epoch(&live, 3);
        let stale = at_epoch(&stale, 2);
        for order in [
            vec![newer.clone(), stale.clone()],
            vec![stale.clone(), newer.clone()],
        ] {
            assert_eq!(
                LocalGrants::from_headers(order).select_at(&request, NOW),
                Some(newer.clone())
            );
        }
        // Equal epochs fall back to the P-18 rules: the repository-scoped grant.
        let same_epoch_broad = at_epoch(&stale, 3);
        assert_eq!(
            LocalGrants::from_headers(vec![same_epoch_broad, newer.clone()])
                .select_at(&request, NOW),
            Some(newer)
        );
    }

    #[test]
    fn epochs_on_other_audiences_and_namespaces_do_not_interfere() {
        let ours = at_epoch(
            &header(
                &format!("{NS}/photos"),
                "read",
                "-",
                NOW,
                NOW + 50_000,
                "https://git.example.com",
                KEY,
            ),
            1,
        );
        let other_audience = at_epoch(
            &header(
                &format!("{NS}/photos"),
                "read",
                "-",
                NOW,
                NOW + 90_000,
                "https://other.example.com",
                KEY,
            ),
            9,
        );
        let mut foreign_namespace = SignedHeader::parse(&other_audience).unwrap();
        foreign_namespace.statement = String::from_utf8(foreign_namespace.statement)
            .unwrap()
            .replace("https://other.example.com", "https://git.example.com")
            .replace(NS, "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            .into_bytes();
        let foreign_namespace = foreign_namespace.encode().unwrap();
        assert_eq!(
            LocalGrants::from_headers(vec![other_audience, foreign_namespace, ours.clone()])
                .select_at(&request(GrantOperation::Read), NOW),
            Some(ours)
        );
    }

    #[test]
    fn an_update_prefers_a_grant_that_forces_over_a_u_only_one() {
        let update_only = header(
            &format!("{NS}/photos"),
            "write",
            "refs/heads/main=u",
            NOW,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        );
        let forcing = header(
            &format!("{NS}/*"),
            "write",
            "refs/heads/*=uf",
            NOW,
            NOW + 50_000,
            "https://git.example.com",
            KEY,
        );
        let matched = [GrantRef::new("refs/heads/main", GrantCondition::Match)];
        let request = request(GrantOperation::Write { refs: &matched });
        // The narrower, longer-lived `u` grant loses to the one that forces,
        // in either source order; alone, it is still chosen.
        for order in [
            vec![update_only.clone(), forcing.clone()],
            vec![forcing.clone(), update_only.clone()],
        ] {
            assert_eq!(
                LocalGrants::from_headers(order).select_at(&request, NOW),
                Some(forcing.clone())
            );
        }
        assert_eq!(
            LocalGrants::from_headers(vec![update_only.clone()]).select_at(&request, NOW),
            Some(update_only.clone())
        );
        // A create (MISSING) has no such preference: scope specificity decides.
        let created = [GrantRef::new("refs/heads/main", GrantCondition::Missing)];
        let create_request = self::request(GrantOperation::Write { refs: &created });
        let create_grant = header(
            &format!("{NS}/photos"),
            "write",
            "refs/heads/main=c",
            NOW,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        );
        let forcing_create = header(
            &format!("{NS}/*"),
            "write",
            "refs/heads/*=cf",
            NOW,
            NOW + 50_000,
            "https://git.example.com",
            KEY,
        );
        assert_eq!(
            LocalGrants::from_headers(vec![forcing_create, create_grant.clone()])
                .select_at(&create_request, NOW),
            Some(create_grant)
        );
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
