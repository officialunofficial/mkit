//! Graph traversal transitions and bounded frontier scheduling.
use super::{
    Acquisition, CanonicalSource, ClosureCheck, ClosureFailureContext, ClosureRequest,
    ClosureWalker, Failure, FailureCode, Frame, InPackObject, InPackObjectView, Lookup,
    MembershipRequest, MissingObject, MissingReason, ObjectType, Phase, Record, Retention, State,
    Visit, charge, check_kind, encode_missing, encode_witness, failure,
};
use crate::closure::EdgeKind;

impl<V: InPackObjectView> ClosureWalker<V> {
    pub(super) fn advance(&mut self) -> Result<(), Failure> {
        self.context = match self.phase {
            Phase::Visit(visit) => Some(ClosureFailureContext {
                object: visit.id,
                check: if visit.head {
                    ClosureCheck::Head
                } else if visit.chunk {
                    let reason = visit
                        .reason
                        .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
                    ClosureCheck::Chunk {
                        manifest: reason
                            .source
                            .ok_or_else(|| failure(FailureCode::InvalidResponse))?,
                        ordinal: reason.ordinal,
                    }
                } else {
                    ClosureCheck::Reference
                },
            }),
            Phase::FinishFrame => self.frames.last().and_then(|frame| {
                frame.object.map(|object| ClosureFailureContext {
                    object: object.object,
                    check: if frame.total.is_some() {
                        ClosureCheck::Manifest
                    } else {
                        ClosureCheck::Reference
                    },
                })
            }),
            _ => None,
        };
        self.charge(3)?;
        if self.view.object_set_root() != self.object_set_root
            || self.view.object_count() != self.object_count
        {
            return Err(failure(FailureCode::SourceChanged));
        }
        let resident = self.view.retained_bytes();
        if resident > self.view_bytes {
            self.resident(resident - self.view_bytes)?;
        }
        self.view_bytes = resident;
        match self.phase {
            Phase::Fill => self.fill(),
            Phase::Prefetch => self.prefetch(),
            Phase::StoreAnswers(index) => self.store_answer(index),
            Phase::Witness(index) => {
                let Acquisition::Present(fact) = &self.answers[index].value else {
                    return Err(failure(FailureCode::InvalidResponse));
                };
                let (page, bytes) = encode_witness(self.witnesses, fact)?;
                self.phase = Phase::StoreAnswers(index + 1);
                self.retain(page, bytes, Retention::Witness)
            }
            Phase::Process => {
                let frame = self
                    .frames
                    .last_mut()
                    .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
                if let Some(visit) = frame.window.get(frame.processed).copied() {
                    self.phase = Phase::Visit(visit);
                } else {
                    frame.window.clear();
                    frame.processed = 0;
                    frame.prefetch = 0;
                    self.phase = Phase::Fill;
                }
                Ok(())
            }
            Phase::Visit(visit) => self.visit(visit),
            Phase::FinishFrame => self.finish_frame(),
            Phase::FinishMissing => {
                if let Some(missing) = self.missing.last() {
                    let bytes = (missing.reasons.len() as u64)
                        .checked_mul(43)
                        .and_then(|n| n.checked_add(82))
                        .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
                    self.charge(bytes)?;
                    self.resident(bytes)?;
                }
                if let Some(missing) = self.missing.pop() {
                    let (page, bytes) = encode_missing(self.missing_root, &missing)?;
                    self.retain(page, bytes, Retention::Missing)
                } else {
                    Ok(())
                }
            }
        }
    }
    pub(super) fn fill(&mut self) -> Result<(), Failure> {
        let frame = self
            .frames
            .last()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        if frame.window.len() >= self.limits.membership_batch as usize {
            self.phase = Phase::Prefetch;
            return Ok(());
        }
        let visit = if frame.object.is_some() {
            let cursor = frame.cursor;
            let depth = frame.depth;
            self.charge(1)?;
            let object = self
                .frames
                .last()
                .and_then(|f| f.object.as_ref())
                .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
            match self.view.edge(&object.object, cursor)? {
                Some(edge) if edge.ordinal != cursor => {
                    return Err(failure(FailureCode::InvalidResponse));
                }
                Some(edge) => Some(Visit {
                    id: edge.target,
                    head: false,
                    depth: depth
                        .checked_add(1)
                        .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
                    reason: Some(MissingReason {
                        source: Some(object.object),
                        kind: Some(edge.kind),
                        ordinal: edge.ordinal,
                    }),
                    expected: edge.expected_kind,
                    chunk: edge.kind == EdgeKind::Chunk,
                }),
                None => None,
            }
        } else {
            let cursor = frame.cursor;
            if let Some(head) = usize::try_from(cursor).ok().and_then(|n| self.heads.get(n)) {
                Some(Visit {
                    id: *head,
                    head: true,
                    depth: 0,
                    reason: None,
                    expected: None,
                    chunk: false,
                })
            } else {
                let ordinal = cursor
                    .checked_sub(self.heads.len() as u64)
                    .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
                let object = self.view.object_at(ordinal)?;
                if (ordinal < self.object_count) != object.is_some() {
                    return Err(failure(FailureCode::InvalidResponse));
                }
                object.map(|object| Visit {
                    id: object.object,
                    head: false,
                    depth: 0,
                    reason: None,
                    expected: None,
                    chunk: false,
                })
            }
        };
        if let Some(frame) = self.frames.last()
            && let Some(count) = frame.chunks
            && ((visit.is_some() && (frame.cursor >= count || !visit.is_some_and(|v| v.chunk)))
                || (visit.is_none() && frame.cursor != count))
        {
            return Err(failure(FailureCode::InvalidResponse));
        }
        if let Some(visit) = visit {
            if visit.reason.is_some() {
                charge(&mut self.edges, 1, self.limits.edges)?;
            }
            self.resident(256)?;
            let frame = self
                .frames
                .last_mut()
                .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
            frame
                .window
                .try_reserve_exact(1)
                .map_err(|_| failure(FailureCode::ResourceLimit))?;
            frame.window.push(visit);
            frame.cursor += 1;
        } else if self.frames.last().is_some_and(|f| !f.window.is_empty()) {
            self.phase = Phase::Prefetch;
        } else {
            self.phase = Phase::FinishFrame;
        }
        Ok(())
    }
    pub(super) fn prefetch(&mut self) -> Result<(), Failure> {
        let frame = self
            .frames
            .last()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        let Some(visit) = frame.window.get(frame.prefetch).copied() else {
            if self.wanted.is_empty() {
                self.phase = Phase::Process;
            } else {
                let request = self.id()?;
                let objects = std::mem::take(&mut self.wanted);
                self.request = Some(ClosureRequest::Membership(MembershipRequest {
                    request,
                    repository: self.repository,
                    view: self.revision,
                    objects,
                }));
            }
            return Ok(());
        };
        self.charge(1)?;
        if self.view.object(&visit.id)?.is_none() {
            let Lookup::Found(record) = self.lookup(&visit.id)? else {
                return Ok(());
            };
            if record.is_none() {
                self.charge(self.wanted.len() as u64 + 1)?;
                if let Err(index) = self.wanted.binary_search(&visit.id) {
                    self.wanted
                        .try_reserve_exact(1)
                        .map_err(|_| failure(FailureCode::ResourceLimit))?;
                    self.wanted.insert(index, visit.id);
                }
            }
        }
        self.frames
            .last_mut()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?
            .prefetch += 1;
        Ok(())
    }
    pub(super) fn store_answer(&mut self, index: usize) -> Result<(), Failure> {
        let Some(answer) = self.answers.get(index) else {
            self.answers.clear();
            self.phase = Phase::Process;
            return Ok(());
        };
        // A held or unpublished member is absent for closure, as in the pack
        // verifier: neither can satisfy a reference.
        let (record, present) = match &answer.value {
            Acquisition::Present(fact) if fact.held || !fact.published => (
                &Record {
                    kind: ObjectType::Blob,
                    canonical_len: 0,
                    state: State::Absent,
                    blob_payload_len: None,
                },
                false,
            ),
            Acquisition::Present(fact) => (
                &Record {
                    kind: fact.kind,
                    canonical_len: fact.canonical_len,
                    state: State::Member(fact.clone()),
                    blob_payload_len: None,
                },
                true,
            ),
            Acquisition::Absent => (
                &Record {
                    kind: ObjectType::Blob,
                    canonical_len: 0,
                    state: State::Absent,
                    blob_payload_len: None,
                },
                false,
            ),
            Acquisition::Unavailable => return Err(failure(FailureCode::UnavailableInput)),
        };
        let id = answer.object;
        charge(&mut self.items, 1, self.limits.items)?;
        self.phase = if present {
            Phase::Witness(index)
        } else {
            Phase::StoreAnswers(index + 1)
        };
        self.put(id, record)
    }
    pub(super) fn visit(&mut self, visit: Visit) -> Result<(), Failure> {
        let metadata = self.view.object(&visit.id)?;
        let Lookup::Found(record) = self.lookup(&visit.id)? else {
            return Ok(());
        };
        if let Some(object) = &metadata {
            if object.object != visit.id {
                return Err(failure(FailureCode::InvalidResponse));
            }
            self.diagnose(visit, object.kind);
            match check_kind(visit, object.kind) {
                Ok(()) => {
                    if visit.chunk {
                        self.chunk_len(object.canonical_len.checked_sub(10))?;
                    }
                }
                Err(fault) if visit.head => return Err(fault),
                Err(fault) => self.defer(fault),
            }
            if let Some(record) = record {
                if record.kind != object.kind || record.canonical_len != object.canonical_len {
                    return Err(failure(FailureCode::InvalidResponse));
                }
                if matches!(record.state, State::Gray) {
                    self.diagnostics.cycles += 1;
                }
                self.complete_visit();
                return Ok(());
            }
            if visit.depth > self.limits.depth {
                return Err(failure(FailureCode::ResourceLimit));
            }
            charge(&mut self.items, 1, self.limits.items)?;
            if object.kind == ObjectType::ChunkedBlob {
                let summary = self
                    .view
                    .chunked_blob(&object.object)?
                    .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
                self.enter(
                    *object,
                    visit.depth,
                    Some(summary.total_size),
                    Some(summary.chunks),
                )
            } else {
                self.enter(*object, visit.depth, None, None)
            }
        } else {
            let Some(record) = record else {
                return Err(failure(FailureCode::InvalidResponse));
            };
            match &record.state {
                State::Absent => {
                    self.add_missing(visit)?;
                    if visit.chunk {
                        self.frames
                            .last_mut()
                            .ok_or_else(|| failure(FailureCode::InvalidResponse))?
                            .missing_chunk = true;
                    }
                    self.complete_visit();
                    Ok(())
                }
                State::Member(fact) => {
                    self.diagnose(visit, fact.kind);
                    if let Err(fault) = check_kind(visit, fact.kind) {
                        if visit.head {
                            return Err(fault);
                        }
                        self.defer(fault);
                        self.complete_visit();
                        return Ok(());
                    }
                    if visit.chunk {
                        if let Some(len) = record.blob_payload_len {
                            self.chunk(len);
                            self.complete_visit();
                            Ok(())
                        } else {
                            self.acquire(CanonicalSource::Member(fact.clone()))
                        }
                    } else {
                        self.complete_visit();
                        Ok(())
                    }
                }
                _ => Err(failure(FailureCode::InvalidResponse)),
            }
        }
    }
    pub(super) fn enter(
        &mut self,
        object: InPackObject,
        depth: u64,
        total: Option<u64>,
        chunks: Option<u64>,
    ) -> Result<(), Failure> {
        self.resident(512)?;
        self.frames
            .try_reserve_exact(1)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        self.frames
            .push(Frame::object(object, depth, total, chunks));
        self.phase = Phase::Fill;
        self.put(
            object.object,
            &Record {
                kind: object.kind,
                canonical_len: object.canonical_len,
                state: State::Gray,
                blob_payload_len: None,
            },
        )
    }
    pub(super) fn diagnose(&mut self, visit: Visit, actual: ObjectType) {
        if visit.expected.is_some_and(|expected| expected != actual) && !visit.chunk {
            self.diagnostics.kind_mismatches += 1;
        }
    }
    pub(super) fn complete_visit(&mut self) {
        if let Some(frame) = self.frames.last_mut() {
            frame.processed += 1;
        }
        self.phase = Phase::Process;
    }
    /// Account one chunk's payload length, or defer a fault when the manifest
    /// cannot hold it.
    pub(super) fn chunk(&mut self, len: u64) {
        let Some(frame) = self.frames.last_mut() else {
            return;
        };
        let sum = frame
            .total
            .and_then(|total| frame.chunk_sum.checked_add(len).filter(|n| *n <= total));
        match sum {
            Some(sum) => frame.chunk_sum = sum,
            None => self.defer(failure(FailureCode::NonCanonicalObject)),
        }
    }
    pub(super) fn chunk_len(&mut self, len: Option<u64>) -> Result<(), Failure> {
        if self.frames.last().is_none_or(|f| f.total.is_none()) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        match len {
            Some(len) => self.chunk(len),
            None => self.defer(failure(FailureCode::NonCanonicalObject)),
        }
        Ok(())
    }
    pub(super) fn add_missing(&mut self, visit: Visit) -> Result<(), Failure> {
        self.charge(self.missing.len() as u64 + 1)?;
        let index = match self.missing.binary_search_by_key(&visit.id, |m| m.object) {
            Ok(index) => index,
            Err(index) => {
                if self.missing.len() as u64 >= self.limits.missing_items {
                    return Err(failure(FailureCode::ResourceLimit));
                }
                self.resident(128)?;
                self.missing
                    .try_reserve_exact(1)
                    .map_err(|_| failure(FailureCode::ResourceLimit))?;
                self.missing.insert(
                    index,
                    MissingObject {
                        object: visit.id,
                        reasons: Vec::new(),
                    },
                );
                self.missing_count += 1;
                index
            }
        };
        let reason = visit.reason.unwrap_or(MissingReason {
            source: None,
            kind: None,
            ordinal: 0,
        });
        self.resident(128)?;
        self.charge(self.missing[index].reasons.len() as u64 + 1)?;
        let reasons = &mut self.missing[index].reasons;
        // Canonical ordering retains every distinct source/role/occurrence.
        if let Err(index) = reasons.binary_search(&reason) {
            reasons
                .try_reserve_exact(1)
                .map_err(|_| failure(FailureCode::ResourceLimit))?;
            reasons.insert(index, reason);
        }
        Ok(())
    }
    pub(super) fn finish_frame(&mut self) -> Result<(), Failure> {
        let frame = self
            .frames
            .pop()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        if let Some(total) = frame.total
            && !frame.missing_chunk
            && !frame.faulted
            && frame.chunk_sum != total
        {
            self.defer_only(failure(FailureCode::NonCanonicalObject));
        }
        self.finish_popped(frame)
    }
    fn finish_popped(&mut self, frame: Frame) -> Result<(), Failure> {
        if let Some(object) = frame.object {
            self.phase = Phase::Process;
            self.frames
                .last_mut()
                .ok_or_else(|| failure(FailureCode::InvalidResponse))?
                .processed += 1;
            self.put(
                object.object,
                &Record {
                    kind: object.kind,
                    canonical_len: object.canonical_len,
                    state: State::Black,
                    blob_payload_len: None,
                },
            )
        } else {
            self.phase = Phase::FinishMissing;
            Ok(())
        }
    }
}
