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

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use mkit_attest::grant::{Capabilities, Capability, Grant, RefFlags, RepoScope, packmap_head};
use mkit_core::hash::from_hex;
use mkit_core::refs::RefWriteCondition;
use mkit_core::repo_identity::RepositoryIdentity;
use mkit_transport_connect::{
    ConnectTransport, GrantCondition, GrantOperation, GrantRef, GrantRequest, GrantSource,
};

use super::StepAuthority;
use super::packmap::packmap_ref;

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

impl LocalGrants {
    /// Whether the grant with this `header` carries `f` for `ref_name`.
    fn header_forces(&self, header: &str, ref_name: &str) -> bool {
        self.0
            .iter()
            .find(|candidate| candidate.header == header)
            .and_then(|candidate| candidate.grant.ref_scopes.as_ref())
            .is_some_and(|scopes| scopes.effective_flags(ref_name).contains(RefFlags::FORCE))
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

/// The grant pre-check of a split push (WP-1.17b, B5) over a Connect client's
/// local grants: every advance must be covered before the first upload, so a
/// grantee that would be refused at a later advance never publishes a prefix.
///
/// The owner key needs no grant, and a repository without a namespace takes
/// none. Otherwise each advance's condition must have a grant that covers it,
/// and the later advances (`Match` updates) need a grant carrying `f`: no
/// server yet accepts `u` alone for them (Stage 1 refuses it, "update without
/// force needs indexed mode", and indexed mode's ancestry check is R-148's
/// TODO). The check asks for an `Any` write, which only an `f` grant covers.
pub(crate) struct ConnectAuthority {
    pub(crate) transport: Arc<ConnectTransport>,
    pub(crate) grants: Arc<LocalGrants>,
    pub(crate) signer_key: String,
}

impl StepAuthority for ConnectAuthority {
    fn authorize(
        &self,
        branch: &str,
        first: RefWriteCondition,
        later_steps: bool,
    ) -> Result<(), String> {
        let repository = self.transport.repository();
        match repository.namespace() {
            None => return Ok(()),
            Some(namespace) if namespace.to_string() == format!("ed25519-{}", self.signer_key) => {
                return Ok(());
            }
            Some(_) => {}
        }
        check_step_grants(
            self.grants.as_ref(),
            None,
            self.transport.origin(),
            &repository.to_string(),
            &self.signer_key,
            branch,
            first,
            later_steps,
        )
    }
}

/// Whether `grants` hold a grant for each advance of a split push by a
/// non-owner key: the first advance under `first`, and, with `later_steps`, the
/// `Match` updates that follow. Those are selected exactly as the transport will
/// select them (a `Match` write request), and the chosen grant must carry `f`:
/// the highest-epoch grant wins, so a newer `u`-only grant would shadow an older
/// `f` one, and a server that cannot check fast-forwards then refuses the later
/// advances. `now` is the clock (`None` for the system clock).
#[allow(clippy::too_many_arguments)]
fn check_step_grants(
    grants: &LocalGrants,
    now: Option<i64>,
    audience: &str,
    repository: &str,
    signer_key: &str,
    branch: &str,
    first: RefWriteCondition,
    later_steps: bool,
) -> Result<(), String> {
    let (first_condition, first_flag) = match first {
        RefWriteCondition::Missing => (GrantCondition::Missing, "c"),
        RefWriteCondition::Match(_) => (GrantCondition::Match, "u"),
        RefWriteCondition::Any => (GrantCondition::Any, "f"),
    };
    let mut needed = vec![(first_condition, "the first advance", first_flag, false)];
    if later_steps {
        needed.push((GrantCondition::Match, "the later advances", "f", true));
    }
    let head = format!("refs/heads/{branch}");
    let packmap = packmap_ref(branch);
    for (condition, what, flag, must_force) in needed {
        let refs = [
            GrantRef::new(&head, condition),
            GrantRef::new(&packmap, condition),
        ];
        let request = GrantRequest::new(
            audience,
            repository,
            signer_key,
            GrantOperation::Write { refs: &refs },
        );
        let chosen = match now {
            Some(now) => grants.select_at(&request, now),
            None => grants.select(&request),
        };
        if !chosen.is_some_and(|header| !must_force || grants.header_forces(&header, &head)) {
            return Err(format!(
                "this push is too large for one advance and would be published as several, but no stored write grant covers {what} on {head} (it needs the `{flag}` flag); no advance of this branch was published. Ask the repository owner for such a grant, or push with the owner key"
            ));
        }
    }
    Ok(())
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

    fn step_check(refs: &str, first: RefWriteCondition, later_steps: bool) -> Result<(), String> {
        let source = LocalGrants::from_headers([header(
            &format!("{NS}/photos"),
            "write",
            refs,
            NOW,
            NOW + 100_000,
            "https://git.example.com",
            KEY,
        )]);
        check_step_grants(
            &source,
            Some(NOW),
            "https://git.example.com",
            "0x8ba1f109551bd432803012645ac136ddd64dba72/photos",
            KEY,
            "main",
            first,
            later_steps,
        )
    }

    #[test]
    fn split_push_needs_create_for_a_new_branch_and_more_for_later_steps() {
        let missing = RefWriteCondition::Missing;
        // Create-only: the first advance is fine, the later ones are not.
        assert!(step_check("refs/heads/main=c", missing, false).is_ok());
        let refused = step_check("refs/heads/main=c", missing, true).unwrap_err();
        assert!(
            refused.contains("no advance of this branch was published"),
            "{refused}"
        );
        assert!(refused.contains("`f`"), "{refused}");
        // Create and update is not enough: the later advances need `f`.
        let refused = step_check("refs/heads/main=cu", missing, true).unwrap_err();
        assert!(refused.contains("`f`"), "{refused}");
        assert!(step_check("refs/heads/main=cuf", missing, true).is_ok());
        // No grant for the branch at all.
        assert!(step_check("refs/heads/other=cuf", missing, false).is_err());
    }

    #[test]
    fn a_pre_issued_update_only_grant_shadowing_a_forcing_one_is_refused_up_front() {
        let mk = |refs: &str| {
            header(
                &format!("{NS}/photos"),
                "write",
                refs,
                NOW,
                NOW + 100_000,
                "https://git.example.com",
                KEY,
            )
        };
        let live = mk("refs/heads/main=cuf");
        let next_epoch = at_epoch(&mk("refs/heads/main=u"), 1);
        let source = LocalGrants::from_headers([live.clone(), next_epoch]);
        let check = |source: &LocalGrants| {
            check_step_grants(
                source,
                Some(NOW),
                "https://git.example.com",
                "0x8ba1f109551bd432803012645ac136ddd64dba72/photos",
                KEY,
                "main",
                RefWriteCondition::Match([1; 32]),
                true,
            )
        };
        let refused = check(&source).unwrap_err();
        assert!(refused.contains("`f`"), "{refused}");
        // Without the shadowing grant the live one covers every advance.
        assert!(check(&LocalGrants::from_headers([live])).is_ok());
    }

    #[test]
    fn update_only_grant_cannot_create_the_first_advance() {
        let matched = RefWriteCondition::Match([1; 32]);
        assert!(step_check("refs/heads/main=u", matched, false).is_ok());
        assert!(step_check("refs/heads/main=u", RefWriteCondition::Missing, false).is_err());
        assert!(step_check("refs/heads/main=u", matched, true).is_err());
        assert!(step_check("refs/heads/main=uf", matched, true).is_ok());
    }

    #[test]
    fn the_owner_key_needs_no_grant() {
        let transport =
            ConnectTransport::connect(&format!("mkit+http://127.0.0.1:9/ed25519-{KEY}/photos"))
                .unwrap();
        let authority = ConnectAuthority {
            transport: Arc::new(transport),
            grants: Arc::new(LocalGrants::from_headers([])),
            signer_key: KEY.to_owned(),
        };
        assert!(
            authority
                .authorize("main", RefWriteCondition::Missing, true)
                .is_ok()
        );
    }
}
