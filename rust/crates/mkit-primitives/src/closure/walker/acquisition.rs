//! Exact request/answer validation; acquisition never implies acceptance.
use super::{
    Acquisition, CanonicalSource, ClosureRequest, ClosureResponse, ClosureWalker, Failure,
    FailureCode, InPackObjectView, Phase, Record, State, answer_bytes, charge, failure, present,
};

impl<V: InPackObjectView> ClosureWalker<V> {
    pub(super) fn answer_inner(&mut self, response: ClosureResponse<'_>) -> Result<(), Failure> {
        match (self.request.as_ref(), response) {
            (Some(ClosureRequest::Membership(expected)), ClosureResponse::Membership(response)) => {
                if expected.request != response.request
                    || expected.repository != response.repository
                    || expected.view != response.view
                    || expected.objects.len() != response.answers.len()
                {
                    return Err(failure(FailureCode::InvalidResponse));
                }
                for (id, answer) in expected.objects.iter().zip(&response.answers) {
                    if *id != answer.object {
                        return Err(failure(FailureCode::InvalidResponse));
                    }
                    match &answer.value {
                        Acquisition::Present(fact) => {
                            if fact.object != *id
                                || fact.repository != self.repository
                                || fact.incarnation != self.revision
                            {
                                return Err(failure(FailureCode::InvalidResponse));
                            }
                        }
                        Acquisition::Absent => {}
                        Acquisition::Unavailable => {
                            return Err(failure(FailureCode::UnavailableInput));
                        }
                    }
                }
                // The incoming and previously retained vectors coexist until
                // replacement; spare capacity is memory, not protocol identity.
                self.resident(answer_bytes(response.answers.capacity())?)?;
                self.charge(response.answers.len() as u64)?;
                self.answers = response.answers;
                self.request = None;
                self.phase = Phase::StoreAnswers(0);
                Ok(())
            }
            (
                Some(ClosureRequest::Page {
                    request: expected,
                    page: commitment,
                }),
                ClosureResponse::Page {
                    request,
                    page,
                    value,
                },
            ) if *expected == request && *commitment == page => {
                let bytes = present(value)?;
                if bytes.len() as u64 != page.len {
                    return Err(failure(FailureCode::InvalidResponse));
                }
                self.charge(bytes.len() as u64)?;
                self.journal.supply(bytes)?;
                self.request = None;
                Ok(())
            }
            (
                Some(ClosureRequest::Canonical {
                    request: expected,
                    source: bound,
                }),
                ClosureResponse::Canonical {
                    request,
                    source,
                    value,
                },
            ) if *expected == request && *bound == source => {
                let bytes = present(value)?;
                if bytes.len() as u64 != source.len() {
                    return Err(failure(FailureCode::InvalidResponse));
                }
                charge(
                    &mut self.decoded,
                    bytes.len() as u64,
                    self.limits.decoded_bytes,
                )?;
                self.charge(bytes.len() as u64)?;
                let CanonicalSource::Member(fact) = source;
                let verified = verify_blob(fact.object, bytes);
                if !matches!(self.phase, Phase::Visit(_)) {
                    return Err(failure(FailureCode::InvalidResponse));
                }
                self.request = None;
                // A bad chunk is a file-integrity fault: deferred behind any
                // absent object, and recorded without a payload length.
                let len = match verified {
                    Ok(len) => {
                        self.chunk(len as u64);
                        Some(len as u64)
                    }
                    Err(fault) => {
                        self.defer(fault);
                        None
                    }
                };
                self.complete_visit();
                self.put(
                    fact.object,
                    &Record {
                        kind: fact.kind,
                        canonical_len: fact.canonical_len,
                        state: State::Member(fact),
                        blob_payload_len: len,
                    },
                )
            }
            _ => Err(failure(FailureCode::InvalidResponse)),
        }
    }
}

fn verify_blob(expected: super::Hash, bytes: &[u8]) -> Result<usize, Failure> {
    let len = bytes
        .len()
        .checked_sub(10)
        .ok_or_else(|| failure(FailureCode::NonCanonicalObject))?;
    let prologue = mkit_core::serialize::blob_prologue(len)
        .map_err(|_| failure(FailureCode::NonCanonicalObject))?;
    if bytes.get(..10) != Some(prologue.as_slice()) {
        return Err(failure(FailureCode::NonCanonicalObject));
    }
    if mkit_core::hash::hash(bytes) != expected {
        return Err(failure(FailureCode::ObjectHashMismatch));
    }
    Ok(len)
}
