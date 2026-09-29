//! Grant ref-scope authorization (SPEC-WRITE-GRANTS §§8.2–8.3).

use mkit_attest::grant::{RefFlags, VerifiedGrant, head_packmap, packmap_head};
use mkit_core::refs::RefWriteCondition;

use super::ff::FastForward;
use crate::error::ServerError;
use crate::op::{OpKind, PresenceRequirement, RefUpdate};

/// What a scope check leaves for later stages: an `ANY` change's ref-state
/// condition, or (indexed mode) the ancestry a `u`-only `MATCH` must prove.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ScopeOutcome {
    pub presence: Option<PresenceRequirement>,
    pub fast_forward: Option<FastForward>,
}

impl ScopeOutcome {
    fn presence(requirement: Option<PresenceRequirement>) -> Self {
        Self {
            presence: requirement,
            fast_forward: None,
        }
    }
}

fn denied() -> ServerError {
    ServerError::permission_denied("write grant rejected: ref scope")
}

/// Check each change under its effective flags. An `ANY` change with only
/// one of `c` or `f` carries its ref-state condition into every plan.
pub(crate) fn authorize(
    grant: &VerifiedGrant,
    kind: &OpKind,
    indexed_mode: bool,
) -> Result<ScopeOutcome, ServerError> {
    gate_with(kind, indexed_mode, |name| grant.effective_flags(name))
}

fn gate_with(
    kind: &OpKind,
    indexed_mode: bool,
    flags: impl Fn(&str) -> RefFlags,
) -> Result<ScopeOutcome, ServerError> {
    match kind {
        OpKind::UpdateRef(update) => {
            // The bare prefix is also reserved: some filesystem backends use
            // it as the directory containing packmap refs.
            if update.name == "refs/mkit/packmap" || update.name.starts_with("refs/mkit/packmap/") {
                return Err(denied());
            }
            check_change(update, flags(&update.name), indexed_mode)
        }
        OpKind::AdvanceRefs { head, packmap, .. } => {
            if head_packmap(&head.name).as_deref() != Some(packmap.name.as_str())
                || packmap_head(&packmap.name).as_deref() != Some(head.name.as_str())
            {
                return Err(denied());
            }
            // The packmap travels with its head; it has no independent flags.
            check_change(head, flags(&head.name), indexed_mode)
        }
        OpKind::BeginUpload { ref_name, .. } if !flags(ref_name).is_empty() => {
            Ok(ScopeOutcome::default())
        }
        // Ticketless UploadPack has no ref to scope. A ticketed upload bypasses
        // this authorization path after its BeginUpload check.
        _ => Err(denied()),
    }
}

fn check_change(
    update: &RefUpdate,
    flags: RefFlags,
    indexed_mode: bool,
) -> Result<ScopeOutcome, ServerError> {
    if update.new.is_none() {
        return flags
            .contains(RefFlags::DELETE)
            .then(ScopeOutcome::default)
            .ok_or_else(denied);
    }
    match (update.condition, update.new) {
        (RefWriteCondition::Missing, _) => flags
            .contains(RefFlags::CREATE)
            .then(ScopeOutcome::default)
            .ok_or_else(denied),
        (RefWriteCondition::Match(from), Some(to)) => {
            if flags.contains(RefFlags::FORCE) {
                return Ok(ScopeOutcome::default());
            }
            if flags.contains(RefFlags::UPDATE) {
                // `u` alone is a fast-forward only: opaque mode cannot
                // prove one; indexed mode proves it at stage 5 (§8.2).
                if !indexed_mode {
                    return Err(ServerError::permission_denied(
                        "update without force needs indexed mode",
                    ));
                }
                return Ok(ScopeOutcome {
                    presence: None,
                    fast_forward: Some(FastForward {
                        name: update.name.clone(),
                        from,
                        to,
                    }),
                });
            }
            Err(denied())
        }
        (RefWriteCondition::Match(_), None) => Err(denied()),
        (RefWriteCondition::Any, _) => {
            let create = flags.contains(RefFlags::CREATE);
            let force = flags.contains(RefFlags::FORCE);
            match (create, force) {
                (false, false) => Err(denied()),
                (true, true) => Ok(ScopeOutcome::default()),
                (true, false) => Ok(ScopeOutcome::presence(Some(PresenceRequirement::Absent(
                    update.name.clone(),
                )))),
                (false, true) => Ok(ScopeOutcome::presence(Some(PresenceRequirement::Present(
                    update.name.clone(),
                )))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::RefUpdate;
    use mkit_core::protocol::PackKey;

    fn change(name: &str, condition: RefWriteCondition, delete: bool) -> OpKind {
        OpKind::UpdateRef(RefUpdate {
            name: name.into(),
            condition,
            new: (!delete).then_some([1; 32]),
        })
    }

    fn advance(head: &str, packmap: &str) -> OpKind {
        let OpKind::UpdateRef(head) = change(head, RefWriteCondition::Any, false) else {
            unreachable!()
        };
        let OpKind::UpdateRef(packmap) = change(packmap, RefWriteCondition::Any, false) else {
            unreachable!()
        };
        OpKind::AdvanceRefs {
            head,
            packmap,
            tickets: vec![],
        }
    }

    #[test]
    fn opaque_required_flag_table_all_subsets() {
        let name = "refs/heads/main";
        for bits in 0..16 {
            let mut flags = RefFlags::EMPTY;
            for (bit, flag) in [
                RefFlags::CREATE,
                RefFlags::UPDATE,
                RefFlags::FORCE,
                RefFlags::DELETE,
            ]
            .into_iter()
            .enumerate()
            {
                if bits & (1 << bit) != 0 {
                    flags = flags.union(flag);
                }
            }
            let c = flags.contains(RefFlags::CREATE);
            let f = flags.contains(RefFlags::FORCE);
            let d = flags.contains(RefFlags::DELETE);
            let missing = change(name, RefWriteCondition::Missing, false);
            let matched = change(name, RefWriteCondition::Match([2; 32]), false);
            let deleted = change(name, RefWriteCondition::Match([2; 32]), true);
            let any = change(name, RefWriteCondition::Any, false);
            assert_eq!(
                gate_with(&missing, false, |_| flags).is_ok(),
                c,
                "bits={bits}"
            );
            assert_eq!(
                gate_with(&matched, false, |_| flags).is_ok(),
                f,
                "bits={bits}"
            );
            assert_eq!(
                gate_with(&deleted, false, |_| flags).is_ok(),
                d,
                "bits={bits}"
            );
            assert_eq!(
                gate_with(&any, false, |_| flags).is_ok(),
                c || f,
                "bits={bits}"
            );
            let requirement = gate_with(&any, false, |_| flags)
                .ok()
                .and_then(|o| o.presence);
            assert_eq!(
                requirement,
                match (c, f) {
                    (true, false) => Some(PresenceRequirement::Absent(name.into())),
                    (false, true) => Some(PresenceRequirement::Present(name.into())),
                    _ => None,
                },
                "bits={bits}"
            );
        }
    }

    #[test]
    fn update_only_needs_indexed_mode_and_yields_the_ancestry_requirement() {
        let matched = change("refs/heads/main", RefWriteCondition::Match([2; 32]), false);
        assert_eq!(
            gate_with(&matched, false, |_| RefFlags::UPDATE)
                .unwrap_err()
                .public_message(),
            "update without force needs indexed mode"
        );
        // Indexed mode proves the ancestry later: `u` alone yields the
        // requirement, `u` with `f` needs none, and no `u` is denied.
        assert_eq!(
            gate_with(&matched, true, |_| RefFlags::UPDATE).unwrap(),
            ScopeOutcome {
                presence: None,
                fast_forward: Some(FastForward {
                    name: "refs/heads/main".into(),
                    from: [2; 32],
                    to: [1; 32],
                }),
            }
        );
        let forced = RefFlags::UPDATE.union(RefFlags::FORCE);
        assert_eq!(
            gate_with(&matched, true, |_| forced).unwrap(),
            ScopeOutcome::default()
        );
        assert!(gate_with(&matched, true, |_| RefFlags::CREATE).is_err());
    }

    #[test]
    fn begin_upload_and_packmap_pairing() {
        let head = "refs/heads/main";
        let packmap = "refs/mkit/packmap/main";
        let begin = OpKind::BeginUpload {
            ref_name: head.into(),
            key: PackKey::new([1; 32]),
            bytes: 1,
        };
        assert!(gate_with(&begin, false, |_| RefFlags::DELETE).is_ok());
        assert!(gate_with(&begin, false, |_| RefFlags::EMPTY).is_err());
        assert!(
            gate_with(
                &change(packmap, RefWriteCondition::Any, false),
                false,
                |_| RefFlags::CREATE
            )
            .is_err()
        );
        assert!(gate_with(&advance(head, packmap), false, |_| RefFlags::CREATE).is_ok());
        assert!(
            gate_with(&advance(head, "refs/mkit/packmap/other"), false, |_| {
                RefFlags::CREATE
            })
            .is_err()
        );
        assert!(
            gate_with(&advance("refs/tags/main", packmap), false, |_| {
                RefFlags::CREATE
            })
            .is_err()
        );
    }
}
