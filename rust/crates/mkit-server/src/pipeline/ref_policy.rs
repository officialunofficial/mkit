//! Stage 2–5 ref policy (SPEC-SERVER §9.7): allowed signers, deployment
//! fast-forward-only rules, `u`-only ancestry (SPEC-WRITE-GRANTS §8.2) and
//! ticketless head membership. Built in, before the user's `PreReceive`.

use mkit_core::refs::{PACKMAP_REF_PREFIX, RefWriteCondition};

use super::{
    Authenticated, HookSet, Pipeline, internal,
    plan::{Snapshot, WriteKind, WriteRequest},
    stored_mismatch, upload,
};
use crate::error::{AbortCause, ServerError};
use crate::indexed::verify::{StagedCommits, verify_member_head};
use crate::op::{OpKind, Operation, RefUpdate};
use crate::policy::ff::{FastForward, Verdict, Walk};
use crate::replay::{StoredRejection, StoredResult};
use crate::store::{MultipartBlobStore, NamespaceStore, Partition};

const NON_FAST_FORWARD: &str = "non-fast-forward update not allowed on this ref";

impl<B: MultipartBlobStore, N: NamespaceStore, H: HookSet> Pipeline<B, N, H> {
    /// Store only final built-in policy denials, without ref, ticket or
    /// admission effects. The usual replay guard preserves a racing winner.
    /// `denial_ref` is the ref value an ancestry denial was decided on; the
    /// stored refusal commits only while the ref still holds it. The membership
    /// rows an ancestry or closure check read live in the paged, sharded object
    /// index and cannot be compared in one batch: they stay covered by the
    /// membership-lag window and the proof-time denial window (SPEC-SERVER §9.4).
    pub(super) async fn store_policy_denial(
        &self,
        op: &Operation,
        a: &Authenticated,
        p: &Partition,
        ahead: Option<Snapshot>,
        error: ServerError,
        (reserved, denial_ref): (bool, Option<(String, Option<mkit_core::hash::Hash>)>),
    ) -> Result<StoredResult, ServerError> {
        let Some(rejection) = StoredRejection::new(error.code(), error.public_message())
            .filter(|_| error.details().is_empty())
        else {
            return Err(error);
        };
        let Some(replay) = upload::replay_guard(op) else {
            return Err(error);
        };
        let req = WriteRequest {
            denial_ids: None,
            denial_packs: &[],
            fork_barrier: false,
            authority_store: super::plan::AuthorityStore::from_capabilities(
                self.meta.capabilities(),
            ),
            authority_generation: None,
            namespace: op.repo.namespace.clone(),
            repo: &op.repo.name,
            kind: WriteKind::UpdateRef,
            refs: &[],
            resolved_ref_updates: &[],
            ref_index: None,
            replay: Some(replay),
            charges: &[],
            namespace_charge: None,
            grant: None,
            lease: None,
            layout_version: false,
            mark_repo_known: false,
            rejection: Some(&rejection),
            denial_ref: denial_ref
                .as_ref()
                .map(|(name, value)| (name.as_str(), *value)),
            publication: None,
            pending: None,
            begin: None,
            advance: None,
            implicit: None,
        };
        match self
            .apply_atomic(
                op,
                a,
                p,
                &req,
                ahead,
                (None, &super::ReplacedSession::default()),
            )
            .await?
        {
            rejected @ StoredResult::Rejected(_) => Err(stored_mismatch(&rejected)),
            _ if reserved => Err(ServerError::aborted_retryable(
                "operation already in flight; retry",
            )
            .with_abort_cause(AbortCause::ReplayRace)),
            winner => Ok(winner),
        }
    }

    /// The authenticated operation signer must be allowed on every ref the
    /// write moves (a packmap through its head). It runs in both modes right
    /// after authorization, before any verification, and covers
    /// `BeginUpload`, so a disallowed signer gets no ticket (§9.7).
    pub(super) fn check_ref_signers(&self, op: &Operation) -> Result<(), ServerError> {
        let Some(policy) = &self.cfg.ref_policy else {
            return Ok(());
        };
        let names = match &op.kind {
            OpKind::UpdateRef(update) => vec![update.name.as_str()],
            OpKind::AdvanceRefs { head, packmap, .. } => {
                vec![head.name.as_str(), packmap.name.as_str()]
            }
            OpKind::BeginUpload { ref_name, .. } => vec![ref_name.as_str()],
            _ => return Ok(()),
        };
        let signer = op.auth.as_ref().map(|auth| &auth.signer);
        if names.iter().all(|name| policy.signer_allowed(name, signer)) {
            Ok(())
        } else {
            Err(ServerError::permission_denied(
                "signer not allowed for this ref",
            ))
        }
    }

    /// When the client signed: the ticketless §9.4 lag window opens here,
    /// never later than now.
    fn signed_at_ms(&self, op: &Operation) -> u64 {
        let now = u64::try_from(self.clock.now_ms()).unwrap_or(0);
        op.auth
            .as_ref()
            .map_or(0, |auth| u64::try_from(auth.created_at_ms).unwrap_or(0))
            .min(now)
    }

    /// Indexed mode: a ticketless non-delete head must be a commit, remix
    /// or tag member of this repository (`open closure` otherwise).
    pub(super) async fn check_ticketless_head(&self, op: &Operation) -> Result<(), ServerError> {
        let Some(indexed) = self.cfg.indexed else {
            return Ok(());
        };
        let head = match &op.kind {
            OpKind::UpdateRef(update) if !update.name.starts_with(PACKMAP_REF_PREFIX) => update,
            OpKind::AdvanceRefs { head, tickets, .. } if tickets.is_empty() => head,
            _ => return Ok(()),
        };
        let Some(new) = head.new else {
            return Ok(());
        };
        let denial_reads = crate::store::DenialReads::new(&self.meta, self.cfg.takedown_denial);
        verify_member_head(
            &self.blobs,
            &denial_reads,
            self.shards.as_ref(),
            &op.repo,
            new,
            self.signed_at_ms(op),
            (indexed, self.clock.as_ref(), self.metrics.as_ref()),
        )
        .await
    }

    /// Stage 5, before the user's `PreReceive`: prove the ancestry a `u`-only
    /// grant or a fast-forward-only rule needs. `ticket_ms` is the consumed
    /// ticket's creation time (the lag window), and an `ANY` change to a
    /// present fast-forward-only ref is rewritten to `MATCH(observed)` so
    /// its compare-and-swap guards what was checked.
    pub(super) async fn check_fast_forward(
        &self,
        op: &Operation,
        refs: &mut [RefUpdate],
        ahead: Option<&Snapshot>,
        grant: Option<&FastForward>,
        (staged, ticket_ms): (&StagedCommits, Option<u64>),
    ) -> Result<(), ServerError> {
        let subject = match &op.kind {
            OpKind::UpdateRef(update) => &update.name,
            OpKind::AdvanceRefs { head, .. } => &head.name,
            _ => return Ok(()),
        };
        let rule = self
            .cfg
            .ref_policy
            .as_ref()
            .is_some_and(|policy| policy.fast_forward_only(subject));
        if !rule && grant.is_none() {
            return Ok(());
        }
        let denied = || {
            if rule {
                ServerError::permission_denied(NON_FAST_FORWARD)
            } else {
                ServerError::permission_denied("write grant rejected: ref scope")
            }
        };
        let Some(indexed) = self.cfg.indexed else {
            return Err(internal("fast-forward check needs indexed mode"));
        };
        let update = refs
            .iter_mut()
            .find(|update| update.name == *subject)
            .ok_or_else(|| internal("fast-forward subject missing from the write"))?;
        let Some(to) = update.new else {
            return Err(denied());
        };
        // The carried requirement must still describe this very change.
        if grant.is_some_and(|ff| {
            ff.name != *subject
                || ff.to != to
                || update.condition != RefWriteCondition::Match(ff.from)
        }) {
            return Err(internal(
                "fast-forward requirement does not match the write",
            ));
        }
        let from = match update.condition {
            RefWriteCondition::Match(from) => from,
            RefWriteCondition::Missing => return Ok(()),
            RefWriteCondition::Any => {
                let Some(current) = self.current_ref(op, subject, ahead).await? else {
                    update.condition = RefWriteCondition::Missing;
                    return Ok(());
                };
                update.condition = RefWriteCondition::Match(current);
                current
            }
        };
        let denial_reads = crate::store::DenialReads::new(&self.meta, self.cfg.takedown_denial);
        let walk = Walk {
            blobs: &self.blobs,
            store: &denial_reads,
            shards: self.shards.as_ref(),
            repo: &op.repo,
            cfg: indexed,
            clock: self.clock.as_ref(),
            metrics: self.metrics.as_ref(),
        };
        let created = ticket_ms.unwrap_or_else(|| self.signed_at_ms(op));
        match walk.is_descendant(to, from, staged, created).await? {
            Verdict::Descendant => Ok(()),
            Verdict::NotDescendant | Verdict::Unchecked => Err(denied()),
        }
    }
}

/// The fast-forward subject of `op`, when the write moves one.
fn fast_forward_subject(op: &Operation) -> Option<&str> {
    match &op.kind {
        OpKind::UpdateRef(update) => Some(update.name.as_str()),
        OpKind::AdvanceRefs { head, .. } => Some(head.name.as_str()),
        _ => None,
    }
}

/// Whether the subject's expectation is `ANY` before the ancestry check pins it.
pub(super) fn subject_is_any(op: &Operation, refs: &[RefUpdate]) -> bool {
    fast_forward_subject(op)
        .and_then(|subject| refs.iter().find(|update| update.name == subject))
        .is_some_and(|update| update.condition == RefWriteCondition::Any)
}

/// The exact ref value an ancestry denial was decided on. An explicit
/// `MATCH`/`MISSING` expectation decides from the expectation alone, so the
/// stored refusal needs no ref guard. An `ANY` expectation is decided from the
/// value the check observed and pinned, and the stored refusal must not outlive
/// it (the portable decision guards that value the same way).
pub(super) fn pinned_ref_value(
    op: &Operation,
    refs: &[RefUpdate],
    was_any: bool,
) -> Option<(String, Option<mkit_core::hash::Hash>)> {
    if !was_any {
        return None;
    }
    let subject = fast_forward_subject(op)?;
    let update = refs.iter().find(|update| update.name == subject)?;
    match update.condition {
        RefWriteCondition::Match(from) => Some((subject.to_owned(), Some(from))),
        RefWriteCondition::Missing => Some((subject.to_owned(), None)),
        RefWriteCondition::Any => None,
    }
}
