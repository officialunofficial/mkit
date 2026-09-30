//! Read authorization for public and private repositories
//! (SPEC-WRITE-GRANTS §9.3).

use mkit_attest::grant::{Capability, GrantRequest, RepositoryIdentity, verify_grant_owner};
use mkit_core::hash::Hash;

use super::GrantConfig;
use crate::op::{CallerView, Operation, Procedure};

/// The capability checks a presented grant passed (§7 steps 1–10).
#[derive(Debug, Clone, Copy)]
pub(crate) struct GrantCheck {
    /// The grant allows `read` on this repository for this signer.
    pub read: bool,
    /// The grant allows `write` on this repository for this signer.
    pub write: bool,
    /// The grant id (§3.4).
    pub id: Hash,
    /// The grant's epoch, for the step-11 comparison with the stored epoch.
    pub epoch: u64,
}

/// §7 steps 1–10, stateless: `None` for an unsigned request, a header that
/// fails to parse or verify, or a grant passing neither capability check.
/// Step 11 is the caller's: compare [`GrantCheck::epoch`] with the stored
/// epoch.
pub(crate) fn check_grant(cfg: &GrantConfig, header: &str, op: &Operation) -> Option<GrantCheck> {
    let auth = op.auth.as_ref()?;
    let now_ms = op.business_now_ms?;
    let identity = format!("{}/{}", op.repo.namespace.as_str(), op.repo.name.as_str());
    let repository = RepositoryIdentity::parse(&identity).ok()?;
    let owner = verify_grant_owner(cfg.verifier(), header).ok()?;
    let check = |capability| {
        owner
            .check(
                cfg.verifier(),
                &GrantRequest {
                    repository: &repository,
                    signer: &auth.signer,
                    capability,
                    now_ms,
                },
            )
            .ok()
    };
    let read = check(Capability::Read);
    let write = check(Capability::Write);
    let any = read.as_ref().or(write.as_ref())?;
    Some(GrantCheck {
        read: read.is_some(),
        write: write.is_some(),
        id: *any.id(),
        epoch: any.epoch(),
    })
}

/// The §7 verdict of a presented grant, epoch check included.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GrantEval {
    /// The grant allows `read` on this repository for this signer.
    pub read: bool,
    /// The grant allows `write` on this repository for this signer.
    pub write: bool,
}

/// What consulting the authority hook yielded for a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookEval {
    /// The hook was not consulted or cannot classify this caller.
    NotConsulted,
    /// The hook allowed the read; `writer_view` reports the §6.2
    /// `writer_view` fact.
    Allow { writer_view: bool },
    /// The hook denied or errored.
    Deny,
}

/// Who calls a read, as §9.3 sees them.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // Independent authorization facts.
pub(crate) struct Caller {
    /// A fully verified URL token; authorizes only HTTP procedures.
    #[cfg(feature = "http-objects")]
    pub http_token_authorized: bool,
    /// The request carried a verified auth v2 envelope.
    pub signed: bool,
    /// The signer is the namespace's Ed25519 key and no grant was presented.
    pub owner: bool,
    /// The presented grant's verdict; `None` when no grant was presented or
    /// it failed any §7 step.
    pub grant: Option<GrantEval>,
    /// The authority hook's verdict on a signed private read.
    pub hook: HookEval,
    /// `authorizer_role` is `Authority`.
    pub authority: bool,
}

/// The read decision for a repository that exists (§9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadDecision {
    /// Serve the read, classifying the caller's view (SPEC-SERVER §10.1).
    Allow(CallerView),
    /// Answer `not_found`, indistinguishable from a missing repository.
    NotFound,
}

/// §9.3 for a repository that exists.
pub(crate) fn decide(procedure: Procedure, private: bool, c: Caller) -> ReadDecision {
    let grant = c.grant.unwrap_or(GrantEval {
        read: false,
        write: false,
    });
    let writer = c.owner
        || grant.write
        || (c.authority && matches!(c.hook, HookEval::Allow { writer_view: true }));
    let view = if !c.signed {
        CallerView::Anonymous
    } else if writer {
        CallerView::Writer
    } else {
        CallerView::Reader
    };
    if !private {
        return ReadDecision::Allow(view);
    }
    #[cfg(feature = "http-objects")]
    if c.http_token_authorized
        && matches!(
            procedure,
            Procedure::HttpGetObject | Procedure::HttpGetRefPath
        )
        && matches!(c.hook, HookEval::Allow { .. })
    {
        return ReadDecision::Allow(CallerView::Anonymous);
    }
    if !c.signed || matches!(c.hook, HookEval::Deny) {
        return ReadDecision::NotFound;
    }
    let allowed = c.owner
        || grant.read
        || (procedure == Procedure::GetReceipt && grant.write)
        || (c.authority && matches!(c.hook, HookEval::Allow { .. }));
    if allowed {
        ReadDecision::Allow(view)
    } else {
        ReadDecision::NotFound
    }
}

/// §9.3's `GetReceipt` exception: a `write` grant reads a private
/// repository's receipt but nothing else. The receipt read path (WP-5.8)
/// is not built yet.
#[allow(dead_code)]
pub(crate) fn get_receipt_read_allowed(private: bool, c: Caller) -> ReadDecision {
    decide(Procedure::GetReceipt, private, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRANT_WRITE: Option<GrantEval> = Some(GrantEval {
        read: false,
        write: true,
    });
    const GRANT_READ: Option<GrantEval> = Some(GrantEval {
        read: true,
        write: false,
    });
    const GRANT_READ_WRITE: Option<GrantEval> = Some(GrantEval {
        read: true,
        write: true,
    });

    fn caller(signed: bool, owner: bool, grant: Option<GrantEval>, hook: HookEval) -> Caller {
        Caller {
            #[cfg(feature = "http-objects")]
            http_token_authorized: false,
            signed,
            owner,
            grant,
            hook,
            authority: false,
        }
    }

    #[cfg(feature = "http-objects")]
    #[test]
    fn url_tokens_authorize_only_http_and_never_confer_writer_view() {
        let mut c = caller(false, false, None, HookEval::Allow { writer_view: true });
        c.http_token_authorized = true;
        c.authority = true;
        for procedure in [Procedure::HttpGetObject, Procedure::HttpGetRefPath] {
            assert_eq!(
                decide(procedure, true, c),
                ReadDecision::Allow(CallerView::Anonymous)
            );
        }
        assert_eq!(decide(Procedure::ReadRef, true, c), ReadDecision::NotFound);
        c.hook = HookEval::Deny;
        assert_eq!(
            decide(Procedure::HttpGetObject, true, c),
            ReadDecision::NotFound
        );
    }

    #[test]
    fn public_reads_always_allow() {
        for c in [
            caller(false, false, None, HookEval::NotConsulted),
            caller(true, true, None, HookEval::NotConsulted),
            caller(true, false, GRANT_READ, HookEval::NotConsulted),
            caller(true, false, GRANT_WRITE, HookEval::NotConsulted),
            caller(true, false, GRANT_READ_WRITE, HookEval::NotConsulted),
            caller(true, false, None, HookEval::Deny),
        ] {
            assert!(matches!(
                decide(Procedure::ReadRef, false, c),
                ReadDecision::Allow(_)
            ));
        }
    }

    #[test]
    fn private_reads_require_authorization() {
        assert_eq!(
            decide(
                Procedure::ReadRef,
                true,
                caller(false, false, None, HookEval::NotConsulted)
            ),
            ReadDecision::NotFound
        );
        assert_eq!(
            decide(
                Procedure::ReadRef,
                true,
                caller(true, false, None, HookEval::Deny)
            ),
            ReadDecision::NotFound
        );
        assert_eq!(
            decide(
                Procedure::ReadRef,
                true,
                caller(true, false, None, HookEval::Allow { writer_view: false })
            ),
            ReadDecision::NotFound
        );
        for c in [
            caller(true, true, None, HookEval::NotConsulted),
            caller(true, false, GRANT_READ, HookEval::NotConsulted),
            caller(true, false, GRANT_READ_WRITE, HookEval::NotConsulted),
        ] {
            assert!(matches!(
                decide(Procedure::ReadRef, true, c),
                ReadDecision::Allow(_)
            ));
        }
    }

    #[test]
    fn write_only_grant_reads_only_get_receipt() {
        let c = caller(true, false, GRANT_WRITE, HookEval::NotConsulted);
        for procedure in [
            Procedure::ReadRef,
            Procedure::ListRefs,
            Procedure::PackExists,
            Procedure::DownloadPack,
            Procedure::IssueObjectUrl,
        ] {
            assert_eq!(
                decide(procedure, true, c),
                ReadDecision::NotFound,
                "{procedure:?}"
            );
        }
        assert!(matches!(
            get_receipt_read_allowed(true, c),
            ReadDecision::Allow(CallerView::Writer)
        ));
    }

    #[test]
    fn authority_hook_authorizes_private_reads() {
        for hook in [
            HookEval::Allow { writer_view: false },
            HookEval::Allow { writer_view: true },
        ] {
            let mut c = caller(true, false, None, hook);
            c.authority = true;
            assert!(matches!(
                decide(Procedure::ReadRef, true, c),
                ReadDecision::Allow(_)
            ));
        }
        // A check-role hook Allow never authorizes a private read.
        assert_eq!(
            decide(
                Procedure::ReadRef,
                true,
                caller(true, false, None, HookEval::Allow { writer_view: true })
            ),
            ReadDecision::NotFound
        );
    }

    #[test]
    fn caller_view_classification() {
        let anonymous = caller(false, false, None, HookEval::NotConsulted);
        assert_eq!(
            decide(Procedure::ReadRef, false, anonymous),
            ReadDecision::Allow(CallerView::Anonymous)
        );
        let reader = caller(true, false, GRANT_READ, HookEval::NotConsulted);
        assert_eq!(
            decide(Procedure::ReadRef, false, reader),
            ReadDecision::Allow(CallerView::Reader)
        );
        for c in [
            caller(true, true, None, HookEval::NotConsulted),
            caller(true, false, GRANT_WRITE, HookEval::NotConsulted),
            caller(true, false, GRANT_READ_WRITE, HookEval::NotConsulted),
        ] {
            assert_eq!(
                decide(Procedure::ReadRef, false, c),
                ReadDecision::Allow(CallerView::Writer)
            );
        }
        // Only an Authority-role hook confers the writer view.
        let mut c = caller(true, false, None, HookEval::Allow { writer_view: true });
        c.authority = true;
        assert_eq!(
            decide(Procedure::ReadRef, false, c),
            ReadDecision::Allow(CallerView::Writer)
        );
        assert_eq!(
            decide(
                Procedure::ReadRef,
                false,
                caller(true, false, None, HookEval::Allow { writer_view: true })
            ),
            ReadDecision::Allow(CallerView::Reader)
        );
    }
}
