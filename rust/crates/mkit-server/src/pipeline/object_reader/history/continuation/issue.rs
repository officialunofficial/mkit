//! Memo-only continuation issuance from a selected-ref session.
//!
//! Issuance authenticates the memoized page-1 state of an existing session —
//! the selected-ref checkpoint, decoded history rows and the embedder's sealed
//! [`TimestampDiscovery`] — without an object read, a proof revalidation or a
//! history scan. Supplied reducer timestamp keys are never trusted: a pending
//! id whose memo row has a different key, or no decoded commit/remix row at
//! all, refuses the token.
use super::super::{
    AtomicBool, BTreeSet, Budgeted, Code, HookSet, MultipartBlobStore, NamespaceStore,
    OBJECT_READER_CALLS, ObjectReader, ReaderSession, ReaderView, ServerError, SliceBudget,
    exhausted, ms, reserve_output, settle,
};
use super::{HistoryContinuation, absent};
use crate::Redacted;
use crate::history_token::{ClaimState, Claims};
use crate::pipeline::read_proofs::{CaptureCheckpoint, WitnessError};
use mkit_core::history_order::TimestampDiscovery;
use std::sync::Arc;

/// Page-1 walk state handed to [`ObjectReader::issue_history_continuation_in`].
#[derive(Debug, Clone)]
pub struct HistoryContinuationState {
    /// Selected-ref checkpoint captured by `selected_capture_in` on this
    /// reader and session; a checkpoint from another reader refuses issuance.
    pub checkpoint: CaptureCheckpoint,
    /// The embedder's page-1 reducer, sealed by at least one emission and
    /// holding no selected-but-unemitted candidate.
    pub walk: TimestampDiscovery,
}

impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet>
    ObjectReader<'_, B, N, H>
{
    /// Mint a version-2 all-parents continuation from this session's memoized
    /// page-1 state, for redemption by
    /// [`ObjectReader::walk_history_page_with_options_in`].
    ///
    /// The call performs no object, blob, index, membership or denial reads
    /// and no proof revalidation: it checks the captured checkpoint, the
    /// memo's decoded commit/remix rows against `state.walk`, the fresh
    /// credential and the ref/publication/security fence, then MACs the
    /// sealed reducer snapshot with a provenance witness rooted at the
    /// checkpoint tip. The token expires at the minimum of the token TTL, the
    /// session proof expiry and the credential expiry, and is never extended.
    /// A complete walk returns `Ok(None)` — no continuation exists to mint.
    /// # Errors
    /// `invalid_argument` for caller misuse: an unselected reader, a walk that
    /// is unsealed or holds an outstanding selected candidate, or a reader
    /// whose selected ref differs from the checkpoint's ref. Refusals —
    /// pending ids the memo never proved, memo keys disagreeing with supplied
    /// keys, a checkpoint this session does not still hold, a changed ref —
    /// return `Ok(None)` in either view. A witness or token exceeding its cap
    /// reports a typed [`HistoryStateLimit`](crate::HistoryStateLimit);
    /// backend faults remain typed.
    pub async fn issue_history_continuation_in(
        &self,
        session: &mut ReaderSession,
        state: &HistoryContinuationState,
    ) -> Result<Option<HistoryContinuation>, ServerError> {
        let config = self
            .pipe
            .cfg
            .history_tokens
            .as_ref()
            .ok_or_else(|| ServerError::unimplemented("history tokens not configured"))?;
        self.check_selected(&state.checkpoint.0.reference)?;
        if self.selected.is_none() {
            return Err(ServerError::invalid_argument(
                "issuance requires a selected-ref reader",
            ));
        }
        if !state.walk.sealed() || state.walk.selected().is_some() {
            return Err(ServerError::invalid_argument(
                "issuance requires a sealed walk with no outstanding candidate",
            ));
        }
        if state.walk.is_complete() {
            return Ok(None);
        }
        if let Ok(mkit_core::repo_identity::Namespace::Ed25519(key)) =
            mkit_core::repo_identity::Namespace::parse(self.repo.namespace.as_str())
            && config.check_public_roles(&[key]).is_err()
        {
            return Ok(None);
        }
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        let admission = crate::store::read_io::ReadIo::new();
        let capped = AtomicBool::new(false);
        let result = self
            .issue_continuation(session, state, config, &calls, &admission, &capped)
            .await;
        let result = settle(result, &capped);
        match result {
            Err(e)
                if matches!(
                    e.code(),
                    Code::NotFound | Code::PermissionDenied | Code::Unauthenticated
                ) =>
            {
                Ok(None)
            }
            other => self.discovery_result(other),
        }
    }

    /// Mint after the checkpoint fence: memo checks, witness, token, closing
    /// fence and closing re-authorization, with no object I/O anywhere.
    #[allow(clippy::too_many_lines)] // The memo checks, witness and fences share one lifecycle.
    async fn issue_continuation(
        &self,
        session: &mut ReaderSession,
        state: &HistoryContinuationState,
        config: &crate::history_token::HistoryTokenConfig,
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
        capped: &AtomicBool,
    ) -> Result<Option<HistoryContinuation>, ServerError> {
        let Some((checkpoint, authority)) = self
            .checkpoint_fence(session, &state.checkpoint, calls, admission, capped)
            .await?
        else {
            return Ok(None);
        };
        let (credential, credential_expiry) = self.history_credential(authority.as_ref())?;
        // Memo-only consistency checks: every emitted id must be a decoded
        // commit/remix row and every pending id a proven history edge of this
        // session. A supplied reducer key must equal the memo's key.
        for id in state.walk.emitted() {
            if session
                .proofs
                .history_link(id)
                .is_none_or(|link| link.decoded.is_none())
            {
                return Ok(None);
            }
        }
        let mut carry = state.walk.clone();
        let mut targets = Vec::new();
        let mut seen = BTreeSet::new();
        for candidate in carry.pending().to_vec() {
            let Some(link) = session.proofs.history_link(&candidate.id) else {
                return Ok(None);
            };
            match (
                candidate.timestamp,
                link.decoded.map(|(_, timestamp)| timestamp),
            ) {
                (Some(supplied), Some(memo)) if supplied == memo => {}
                (Some(_), _) => return Ok(None),
                (None, Some(memo)) => {
                    if carry.provide_timestamp(candidate.id, memo).is_err() {
                        return Ok(None);
                    }
                }
                (None, None) => {}
            }
            if seen.insert(candidate.id) {
                targets.push(candidate.id);
            }
        }
        let witness = match session.proofs.history_witness(&targets, true) {
            Ok(witness) => witness,
            Err(WitnessError::Limit) => {
                return Err(ServerError::history_state_limit_exceeded(
                    crate::HistoryStateLimit::Provenance,
                ));
            }
            Err(WitnessError::Unproven) => return Ok(None),
        };
        if witness.iter().filter_map(|node| node.predecessor).any(|p| {
            self.seams
                .takedown
                .stops_descent(&self.repo, &witness[usize::from(p)].id)
        }) {
            return Ok(None);
        }
        let now = ms(self.pipe.clock.now_ms());
        let expires = now
            .saturating_add(config.ttl_ms())
            .min(session.proofs.expiry())
            .min(credential_expiry);
        if now >= expires {
            return Ok(None);
        }
        let claims = Claims {
            realm: config.realm().into(),
            namespace: self.repo.namespace.as_str().into(),
            repository: self.repo.name.as_str().into(),
            reference: checkpoint.reference.clone(),
            writer: matches!(self.view, ReaderView::Owner(_)),
            credential,
            anchor: checkpoint.tip,
            publication: checkpoint.publication.clone(),
            security: checkpoint.security,
            issued: now,
            expires,
            state: ClaimState::TimestampDiscovery(carry),
            witness,
        };
        let token = config
            .mint(&claims)
            .map_err(ServerError::history_state_limit_exceeded)?;
        reserve_output(session, token.len() as u64)?;
        let meta = Budgeted::new(&self.pipe.meta, calls)
            .with_session(&session.io.calls)
            .flagging(capped)
            .with_io(admission);
        self.closing_fence(
            &meta,
            &checkpoint.reference,
            &checkpoint.raw,
            &checkpoint.publication,
            checkpoint.tip,
            checkpoint.security,
            expires,
        )
        .await?;
        // Closing re-authorization: fresh authority must still satisfy the
        // minted credential scope, the checkpoint must still be this session's
        // held and current capture, and no witness ancestor may have become
        // denied.
        session.io.calls.charge_many(2).map_err(|_| exhausted())?;
        let authority = self.authorize(calls).await?;
        let (current, _) = self.history_credential(authority.as_ref())?;
        if current != credential {
            return Ok(None);
        }
        let now = ms(self.pipe.clock.now_ms());
        session
            .proofs
            .bind(&self.identity, authority, now, self.cfg)
            .map_err(|_| absent())?;
        let held = session.proofs.checkpoint().cloned();
        if !held.is_some_and(|held| Arc::ptr_eq(&held, &checkpoint))
            || !session.proofs.current(now)
            || now >= expires
        {
            return Ok(None);
        }
        if claims
            .witness
            .iter()
            .filter_map(|node| node.predecessor)
            .any(|predecessor| {
                self.seams
                    .takedown
                    .stops_descent(&self.repo, &claims.witness[usize::from(predecessor)].id)
            })
        {
            return Ok(None);
        }
        Ok(Some(HistoryContinuation {
            token: Redacted::new(token),
            expires_at_ms: expires,
        }))
    }
}
