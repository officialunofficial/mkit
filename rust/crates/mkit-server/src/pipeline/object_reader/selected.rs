//! Selected-ref capture: one authoritative anchor read pins a session's roots.
use super::{
    AtomicBool, Budgeted, Code, HookSet, MultipartBlobStore, NamespaceStore, OBJECT_READER_CALLS,
    ObjectReader, ReaderSession, ReaderView, ServerError, SliceBudget, exhausted, ms, settle,
};
use crate::pipeline::read_proofs::{CaptureCheckpoint, Checkpoint, ReadProofs};
use std::sync::Arc;

impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet>
    ObjectReader<'_, B, N, H>
{
    /// Capture the selected ref's authoritative anchor and security digest as
    /// `memo`'s only root set. `false` installs nothing: the ledger is
    /// missing or empty, or the tip could not be memoized, so the session is
    /// uniformly absent.
    pub(super) async fn install_selected(
        &self,
        meta: &impl NamespaceStore,
        memo: &mut ReadProofs,
        reference: &str,
    ) -> Result<bool, ServerError> {
        let anchor = match self.continuation_anchor(meta, reference).await {
            Ok(anchor) => anchor,
            Err(error) if error.code() == Code::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        // Activation precedes capture so the digest covers the revision row.
        let security = match self.history_security(meta, true).await {
            Ok(security) => security,
            Err(error) if error.code() == Code::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if !memo.current(ms(self.pipe.clock.now_ms())) {
            return Err(exhausted());
        }
        Ok(memo.capture_checkpoint(Checkpoint {
            reference: reference.to_owned(),
            tip: anchor.tip,
            publication: anchor.publication,
            raw: anchor.raw,
            security,
            expires: memo.expiry(),
        }))
    }

    /// Capture this reader's selected ref for `session`, or reuse the live
    /// capture. A page-1 loop learns the tip from the returned handle; a
    /// recapture after expiry or any proofs reset returns a different handle.
    /// # Errors
    /// `invalid_argument` on an unselected reader; other failures map as
    /// session reads'. `not_found` is `Ok(None)` in either view, and so are
    /// refused, unauthenticated and exhausted public reads. An owner keeps
    /// typed `PermissionDenied`, `Unauthenticated` and `ResourceExhausted`.
    pub async fn selected_capture_in(
        &self,
        session: &mut ReaderSession,
    ) -> Result<Option<CaptureCheckpoint>, ServerError> {
        let Some(reference) = self.selected.clone() else {
            return Err(ServerError::invalid_argument("reader has no selected ref"));
        };
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        let admission = crate::store::read_io::ReadIo::new();
        let capped = AtomicBool::new(false);
        let result = async {
            let started = ms(self.pipe.clock.now_ms());
            session.io.calls.charge_many(2).map_err(|_| exhausted())?;
            let authority = self.authorize(&calls).await?;
            session
                .proofs
                .bind(&self.identity, authority, started, self.cfg)?;
            let now = ms(self.pipe.clock.now_ms());
            if session.proofs.current(now)
                && let Some(checkpoint) = session.proofs.checkpoint()
            {
                return Ok(Some(CaptureCheckpoint(checkpoint.clone())));
            }
            let meta = Budgeted::new(&self.pipe.meta, &calls)
                .with_session(&session.io.calls)
                .flagging(&capped)
                .with_io(&admission);
            if !self
                .install_selected(&meta, &mut session.proofs, &reference)
                .await?
            {
                return Ok(None);
            }
            Ok(session
                .proofs
                .checkpoint()
                .map(|checkpoint| CaptureCheckpoint(checkpoint.clone())))
        }
        .await;
        match settle(result, &capped) {
            Err(error)
                if error.code() == Code::NotFound
                    || (matches!(self.view, ReaderView::Public)
                        && matches!(
                            error.code(),
                            Code::ResourceExhausted
                                | Code::PermissionDenied
                                | Code::Unauthenticated
                        )) =>
            {
                Ok(None)
            }
            other => other,
        }
    }

    /// Continuation issuance's opening fence: whether `session` still holds this
    /// exact capture and the ref, publication and security state are
    /// unchanged. Never installs or replaces a checkpoint and never clears
    /// the memo beyond what `bind` does. Unlike `selected_capture_in`, refused
    /// and unauthenticated failures are `false` in either view, as H5
    /// redemption requires; public caps are `false` and owner exhaustion
    /// stays typed.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "consumed by history continuation issuance")
    )]
    pub(crate) async fn verify_checkpoint_in(
        &self,
        session: &mut ReaderSession,
        checkpoint: &CaptureCheckpoint,
    ) -> Result<bool, ServerError> {
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        let admission = crate::store::read_io::ReadIo::new();
        let capped = AtomicBool::new(false);
        let result = async {
            session.io.calls.charge_many(2).map_err(|_| exhausted())?;
            let authority = self.authorize(&calls).await?;
            session.proofs.bind(
                &self.identity,
                authority,
                ms(self.pipe.clock.now_ms()),
                self.cfg,
            )?;
            let Some(reference) = self.selected.as_deref() else {
                return Ok(false);
            };
            let now = ms(self.pipe.clock.now_ms());
            let Some(held) = session.proofs.checkpoint() else {
                return Ok(false);
            };
            if !Arc::ptr_eq(held, &checkpoint.0)
                || held.reference != reference
                || !session.proofs.current(now)
            {
                return Ok(false);
            }
            let meta = Budgeted::new(&self.pipe.meta, &calls)
                .with_session(&session.io.calls)
                .flagging(&capped)
                .with_io(&admission);
            let anchor = match self.continuation_anchor(&meta, reference).await {
                Ok(anchor) => anchor,
                Err(error) if error.code() == Code::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            let security = match self.history_security(&meta, false).await {
                Ok(security) => security,
                Err(error) if error.code() == Code::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            Ok(anchor.raw == held.raw
                && anchor.publication == held.publication
                && anchor.tip == held.tip
                && security == held.security)
        }
        .await;
        match settle(result, &capped) {
            Err(error)
                if matches!(
                    error.code(),
                    Code::NotFound | Code::PermissionDenied | Code::Unauthenticated
                ) || (matches!(self.view, ReaderView::Public)
                    && error.code() == Code::ResourceExhausted) =>
            {
                Ok(false)
            }
            other => other,
        }
    }
}
