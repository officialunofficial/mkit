//! Recover every page of the retained ordered frame chain before progress.
use super::{
    Acquisition, EvidenceBinding, EvidenceLimits, Failure, FailureCode, FrameRecord, FramingDriver,
    FramingStep, INDEXED_RULESET, PageCommitment, PageKind, Phase, ProfileId, Request, RequestId,
    Response, RulesetBinding, failure,
};
use crate::evidence::pages::PageView;

#[derive(Debug)]
pub(super) struct Recovery {
    pub page: PageCommitment,
    pub remaining: u64,
    pub end: u64,
}

impl FramingDriver {
    pub(super) fn recovery_request(&mut self) -> Result<FramingStep<'_>, Failure> {
        let page = self
            .recovery
            .as_ref()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?
            .page;
        let request = if let Some(id) = self.pending_page {
            id
        } else {
            let id = RequestId {
                generation: self.generation,
                sequence: self.sequence,
            };
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
            self.pending_page = Some(id);
            id
        };
        Ok(FramingStep::Request(Request::EvidencePage {
            request,
            page,
        }))
    }

    pub(super) fn supply_recovery(&mut self, response: Response<'_>) -> Result<(), Failure> {
        let Response::EvidencePage {
            request,
            page,
            value,
        } = response
        else {
            return Err(failure(FailureCode::InvalidResponse));
        };
        let recovery = self
            .recovery
            .as_ref()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        if self.pending_page != Some(request) || recovery.page != page {
            return Err(failure(FailureCode::InvalidResponse));
        }
        let Acquisition::Present(bytes) = value else {
            return Err(failure(FailureCode::UnavailableInput));
        };
        if bytes.len() as u64 != page.len {
            return Err(failure(FailureCode::InvalidResponse));
        }
        if let Err(error) = self.resources.work(
            page.len
                .checked_mul(4)
                .and_then(|n| n.checked_add(512))
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
        ) {
            self.phase = Phase::Failed;
            self.pending_page = None;
            self.recovery = None;
            return Err(error);
        }
        let result = self.validate_recovery(bytes, page, recovery);
        match result {
            Ok((remaining, end, digest)) => {
                self.pending_page = None;
                self.recovery = if remaining == 0 {
                    None
                } else {
                    Some(Recovery {
                        page: PageCommitment {
                            digest,
                            kind: PageKind::Occurrences,
                            len: 217,
                            items: 1,
                        },
                        remaining,
                        end,
                    })
                };
                Ok(())
            }
            Err(error) => {
                self.phase = Phase::Failed;
                self.pending_page = None;
                self.recovery = None;
                Err(error)
            }
        }
    }
    fn validate_recovery(
        &self,
        bytes: &[u8],
        page: PageCommitment,
        recovery: &Recovery,
    ) -> Result<(u64, u64, mkit_core::hash::Hash), Failure> {
        let view = PageView::from_bytes(
            bytes,
            EvidenceBinding {
                source: self.source,
                repository: self.repository,
                ruleset: RulesetBinding {
                    ruleset: INDEXED_RULESET,
                    profile: ProfileId::Indexed,
                },
            },
            EvidenceLimits {
                page_bytes: self.limits.page_bytes,
                value_bytes: 58,
                allocated_bytes: 0,
                ..EvidenceLimits::indexed()
            },
        )?;
        if view.commitment() != page || view.height() != 0 || page.items != 1 || page.len != 217 {
            return Err(failure(FailureCode::EvidenceMismatch));
        }
        let record = view
            .records()?
            .next()
            .ok_or_else(|| failure(FailureCode::InvalidEvidence))?;
        let ordinal = recovery
            .remaining
            .checked_sub(1)
            .ok_or_else(|| failure(FailureCode::InvalidEvidence))?;
        let mut expected_key = [0; 32];
        expected_key[24..].copy_from_slice(&ordinal.to_be_bytes());
        let frame = FrameRecord::from_bytes(record.value)?;
        if record.key != expected_key
            || frame.offset().checked_add(frame.length()) != Some(recovery.end)
            || (ordinal == 0 && (frame.offset() != 12 || frame.previous() != [0; 32]))
            || (self.header.is_some_and(|(version, _)| version == 1)
                && matches!(frame.wire_type(), 3 | 4))
        {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        Ok((ordinal, frame.offset(), frame.previous()))
    }
}
