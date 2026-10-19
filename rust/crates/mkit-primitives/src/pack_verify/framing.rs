//! Two-pass bounded framing over the public core window reader.
mod checkpoints;
mod record;
mod recovery;
use super::{Acquisition, ByteRange, ByteSource, EvidencePage, Request, RequestId, Response};
use super::{
    integrity::{IntegrityPass, MAX_PACK_BYTES},
    resources::{ResourceUsage, Resources},
};
use crate::{
    codec::failure,
    error::{Failure, FailureCode, Location},
    evidence::{
        PackSource, PageCommitment, PageKind, ProfileId, RepositoryId, RulesetBinding,
        pages::{EncodedPage, EvidenceBinding, INDEXED_RULESET, LeafRecord, encode_leaf},
    },
    limits::{EvidenceLimits, IndexedProfile, VerifyLimits},
};
use mkit_core::{
    hash::Hash,
    pack::{
        DecodeLimits, PackEntry, PackError,
        window::{FrameInfo, Step as CoreStep, WindowReader},
    },
};
pub use record::FrameRecord;

pub(super) const CANONICAL_BYTES: u64 = 1_048_586;
pub(super) const FRAME_BYTES: u64 = 16 << 20;
pub(super) const DELTA_BYTES: u64 = CANONICAL_BYTES + CANONICAL_BYTES.div_ceil(127) + 9;
pub(super) const DECODER_SCRATCH: u64 = 28 << 20;

/// A decoded frame. Canonical validation, delta resolution, and signatures
/// belong to all-entry verification; this event establishes none of them.
#[derive(Debug)]
#[non_exhaustive]
pub enum FramedEntry<'a> {
    /// Decoded raw payload, not yet validated as a canonical object.
    Raw(&'a [u8]),
    /// Base identity and decoded delta instructions, not yet resolved.
    Delta {
        /// Type-dependent base identity from the wire.
        base: Hash,
        /// Bounded decoded instruction bytes.
        stream: &'a [u8],
    },
}

/// One frame event borrowed until the next mutable driver call.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Wire-order ordinal.
    pub ordinal: u64,
    /// Exact encoded frame placement.
    pub info: FrameInfo,
    /// Decoded payload; no trusted object is constructed.
    pub entry: FramedEntry<'a>,
}

/// Framing-only completion, distinct from all-entry `VerifiedPack` evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct FramedPack {
    source: PackSource,
    version: u32,
    entries: u32,
    wire_payload: u64,
    trailer: Hash,
    frame_evidence: Option<PageCommitment>,
}

impl FramedPack {
    /// Exact immutable source whose integrity and framing succeeded.
    #[must_use]
    pub const fn source(&self) -> PackSource {
        self.source
    }
    /// Established pack wire version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }
    /// Declared and consumed frame count.
    #[must_use]
    pub const fn entries(&self) -> u32 {
        self.entries
    }
    /// Cumulative encoded payload length, excluding frame headers.
    #[must_use]
    pub const fn wire_payload_bytes(&self) -> u64 {
        self.wire_payload
    }
    /// Verified digest of the pre-trailer bytes.
    #[must_use]
    pub const fn trailer(&self) -> Hash {
        self.trailer
    }
    /// Last page of the ordered frame-evidence chain; each record commits its
    /// predecessor. Empty packs have no frame pages.
    #[must_use]
    pub const fn frame_evidence(&self) -> Option<PageCommitment> {
        self.frame_evidence
    }
}

/// Cooperative framing transition. Frame payloads remain provisional.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum FramingStep<'a> {
    /// Acquire exactly this immutable byte range.
    Request(Request),
    /// One provisional decoded frame.
    Frame(Frame<'a>),
    /// Retain this evidence page before dependent progress.
    RetainEvidence(EvidencePage<'a>),
    /// A bounded transition completed; call again.
    Progress,
    /// Source integrity and all frame decoding succeeded.
    Complete(FramedPack),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Header,
    Integrity,
    Decode,
    Complete,
    Failed,
}

/// Bounded pull driver. It authenticates the entire immutable source before
/// decoding entries, and never creates a trusted all-entry artifact.
#[derive(Debug)]
pub struct FramingDriver {
    source: PackSource,
    repository: RepositoryId,
    profile: IndexedProfile,
    limits: VerifyLimits,
    generation: u64,
    sequence: u64,
    pending: Option<(RequestId, ByteRange)>,
    phase: Phase,
    integrity: Option<IntegrityPass>,
    reader: Option<WindowReader>,
    resources: Resources,
    active: Option<PackEntry<'static>>,
    ordinal: u64,
    payload: u64,
    trailer: Hash,
    header: Option<(u32, u32)>,
    integrity_reservation: u64,
    decoder_reservation: u64,
    complete: Option<FramedPack>,
    pending_frame: Option<(u64, FrameInfo, u64)>,
    retained: Option<EncodedPage>,
    retention_count: u64,
    last_retained: Option<PageCommitment>,
    checkpoint: Option<crate::evidence::checkpoint::Checkpoint>,
    recovery: Option<recovery::Recovery>,
    pending_page: Option<RequestId>,
}

impl FramingDriver {
    /// Starts an indexed framing run with a caller-assigned generation.
    ///
    /// # Errors
    /// Refuses short/oversized sources, impossible execution budgets, and
    /// arithmetic overflow before acquiring bytes or allocating decoder state.
    pub fn new(
        source: PackSource,
        repository: RepositoryId,
        profile: IndexedProfile,
        limits: VerifyLimits,
        generation: u64,
    ) -> Result<Self, Failure> {
        if source.len < 44 {
            return Err(failure(FailureCode::PackfileTooShort));
        }
        if source.len > MAX_PACK_BYTES || source.len > profile.pack_bytes {
            return Err(failure(FailureCode::PackfileTooLarge));
        }
        let mut resources = Resources::new(limits)?;
        let integrity_reservation = IntegrityPass::reservation(source.len)?;
        let decoder_reservation = limits
            .acquisition_bytes
            .checked_mul(2)
            .and_then(|n| n.checked_add(FRAME_BYTES))
            .and_then(|n| n.checked_add(DELTA_BYTES + 32))
            .and_then(|n| n.checked_add(DECODER_SCRATCH))
            .and_then(|n| n.checked_add(64 << 10))
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        // Both passes must be feasible before doing any input work.
        resources.reserve(
            u64::try_from(std::mem::size_of::<Self>())
                .map_err(|_| failure(FailureCode::ResourceLimit))?,
        )?;
        resources.reserve(decoder_reservation)?;
        resources.release(decoder_reservation)?;
        resources.reserve(integrity_reservation)?;
        let integrity = IntegrityPass::new(source)?;
        Ok(Self {
            source,
            repository,
            profile,
            limits,
            generation,
            sequence: 0,
            pending: None,
            phase: Phase::Header,
            integrity: Some(integrity),
            reader: None,
            resources,
            active: None,
            ordinal: 0,
            payload: 0,
            trailer: [0; 32],
            header: None,
            integrity_reservation,
            decoder_reservation,
            complete: None,
            pending_frame: None,
            retained: None,
            retention_count: 0,
            last_retained: None,
            checkpoint: None,
            recovery: None,
            pending_page: None,
        })
    }

    /// Cumulative and peak accounting, including conservative decoder scratch.
    #[must_use]
    pub const fn usage(&self) -> ResourceUsage {
        self.resources.usage()
    }

    /// Effective indexed content profile, retained for checkpoint binding.
    #[must_use]
    pub const fn profile(&self) -> IndexedProfile {
        self.profile
    }

    fn request(&mut self, range: ByteRange) -> Result<FramingStep<'_>, Failure> {
        let id = RequestId {
            generation: self.generation,
            sequence: self.sequence,
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        self.pending = Some((id, range));
        Ok(FramingStep::Request(Request::Bytes {
            request: id,
            source: ByteSource::Pack(self.source),
            range,
        }))
    }

    /// Advances one bounded framing transition.
    ///
    /// # Errors
    /// Preserves core framing/decompression failures. Resource exhaustion or a
    /// terminal content failure makes the driver inert. Acquisition requests
    /// remain stable until a matching reply is supplied.
    pub fn step(&mut self) -> Result<FramingStep<'_>, Failure> {
        self.release_checkpoint()?;
        if self.recovery.is_some() {
            return self.recovery_request();
        }
        if self.retained.is_some() {
            return self.retention_event();
        }
        if let Some((request, range)) = self.pending {
            return Ok(FramingStep::Request(Request::Bytes {
                request,
                source: ByteSource::Pack(self.source),
                range,
            }));
        }
        self.active = None;
        if let Some(frame) = self.pending_frame.take() {
            self.phase = Phase::Failed;
            self.retain_frame(frame)?;
            self.phase = Phase::Decode;
            return self.retention_event();
        }
        match self.phase {
            Phase::Failed => Err(failure(FailureCode::InvalidResponse)),
            Phase::Header => self.request(ByteRange { offset: 0, len: 12 }),
            Phase::Integrity => self.advance_integrity(),
            Phase::Complete => Ok(FramingStep::Complete(
                self.complete
                    .ok_or_else(|| failure(FailureCode::InvalidResponse))?,
            )),
            Phase::Decode => self.advance_decode(),
        }
    }

    fn decode_limits() -> DecodeLimits {
        DecodeLimits::default()
            .with_max_decoded_bytes(CANONICAL_BYTES)
            .with_entry_geometry(FRAME_BYTES, DELTA_BYTES)
    }

    fn advance_integrity(&mut self) -> Result<FramingStep<'_>, Failure> {
        let pass = self
            .integrity
            .as_ref()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        if let Some(range) = pass.next(self.limits.acquisition_bytes) {
            return self.request(range);
        }
        self.phase = Phase::Failed;
        self.trailer = pass.verify()?;
        self.integrity = None;
        self.resources.release(self.integrity_reservation)?;
        self.resources.reserve(self.decoder_reservation)?;
        self.reader = Some(
            WindowReader::new(
                self.source.len,
                self.limits.acquisition_bytes,
                Self::decode_limits(),
                Some(self.source.id),
            )
            .map_err(|error| map_core(&error))?,
        );
        self.phase = Phase::Decode;
        Ok(FramingStep::Progress)
    }

    fn advance_decode(&mut self) -> Result<FramingStep<'_>, Failure> {
        self.phase = Phase::Failed;
        let reader = self
            .reader
            .as_mut()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        let permit = FRAME_BYTES + DELTA_BYTES + self.limits.acquisition_bytes * 2;
        self.resources.work(permit)?;
        let next = match reader.step() {
            Ok(step) => step,
            Err(error) => {
                self.phase = Phase::Failed;
                return Err(map_core(&error));
            }
        };
        match next {
            CoreStep::NeedWindow(range) => {
                self.resources.finish_work(permit, range.len)?;
                self.phase = Phase::Decode;
                self.request(ByteRange {
                    offset: range.offset,
                    len: range.len,
                })
            }
            CoreStep::Entry(entry) => {
                let info = reader
                    .last_frame()
                    .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
                let bytes = match &entry {
                    PackEntry::Raw { bytes } => bytes.len(),
                    PackEntry::Delta { stream, .. } => stream.len(),
                };
                let used = u64::try_from(bytes)
                    .map_err(|_| failure(FailureCode::ResourceLimit))?
                    .checked_add(info.length)
                    .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
                self.resources.finish_work(permit, used)?;
                self.payload = self
                    .payload
                    .checked_add(
                        info.length
                            .checked_sub(5)
                            .ok_or_else(|| failure(FailureCode::InvalidResponse))?,
                    )
                    .ok_or_else(|| failure(FailureCode::PackfileTooLarge))?;
                let ordinal = self.ordinal;
                self.ordinal += 1;
                self.pending_frame = Some((ordinal, info, bytes as u64));
                self.active = Some(entry);
                self.phase = Phase::Decode;
                let entry = match self
                    .active
                    .as_ref()
                    .ok_or_else(|| failure(FailureCode::InvalidResponse))?
                {
                    PackEntry::Raw { bytes } => FramedEntry::Raw(bytes),
                    PackEntry::Delta { base, stream } => FramedEntry::Delta {
                        base: *base,
                        stream,
                    },
                };
                Ok(FramingStep::Frame(Frame {
                    ordinal,
                    info,
                    entry,
                }))
            }
            CoreStep::Done(summary) => {
                self.resources.finish_work(permit, 1)?;
                if self.header != Some((summary.version, summary.entry_count))
                    || self.ordinal != u64::from(summary.entry_count)
                {
                    return Err(failure(FailureCode::SourceChanged));
                }
                let complete = FramedPack {
                    source: self.source,
                    version: summary.version,
                    entries: summary.entry_count,
                    wire_payload: self.payload,
                    trailer: self.trailer,
                    frame_evidence: self.last_retained,
                };
                self.complete = Some(complete);
                self.reader = None;
                self.resources.release(self.decoder_reservation)?;
                self.phase = Phase::Complete;
                Ok(FramingStep::Complete(complete))
            }
            _ => Err(failure(FailureCode::InvalidResponse)),
        }
    }

    /// Supplies exactly the outstanding immutable range.
    ///
    /// # Errors
    /// Wrong identities/ranges, stale/duplicate replies, and wrong lengths are
    /// `InvalidResponse` and leave the request pending. Missing bytes are
    /// `UnavailableInput`; they never stand in for an empty source.
    pub fn supply(&mut self, response: Response<'_>) -> Result<(), Failure> {
        self.release_checkpoint()?;
        if matches!(response, Response::EvidencePage { .. }) {
            return self.supply_recovery(response);
        }
        let Response::Bytes {
            request,
            source,
            range,
            value,
        } = response
        else {
            return Err(failure(FailureCode::InvalidResponse));
        };
        if self.pending != Some((request, range)) || source != ByteSource::Pack(self.source) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        let Acquisition::Present(bytes) = value else {
            return Err(failure(FailureCode::UnavailableInput));
        };
        if u64::try_from(bytes.len()).ok() != Some(range.len) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        // Decoder feeds copy and commit the window. Prepay one additional
        // prefix pass: cold resume hashes the consumed prefix once, and live
        // checkpoints hash only its remaining suffix across entry boundaries.
        let passes = if self.phase == Phase::Decode { 4 } else { 3 };
        let charge = range
            .len
            .checked_mul(passes)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        if let Err(error) = self.resources.work(charge) {
            self.pending = None;
            self.phase = Phase::Failed;
            return Err(error);
        }
        let result = match self.phase {
            Phase::Header => self.accept_header(bytes),
            Phase::Integrity => self
                .integrity
                .as_mut()
                .ok_or_else(|| failure(FailureCode::InvalidResponse))?
                .feed(range.offset, bytes),
            Phase::Decode => self
                .reader
                .as_mut()
                .ok_or_else(|| failure(FailureCode::InvalidResponse))?
                .feed(range.offset, bytes)
                .map_err(|error| map_core(&error)),
            _ => Err(failure(FailureCode::InvalidResponse)),
        };
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        self.pending = None;
        result
    }

    fn accept_header(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        if bytes.get(..4) != Some(b"MKIT") {
            return Err(failure(FailureCode::InvalidMagic));
        }
        let version = u32::from_le_bytes(
            bytes
                .get(4..8)
                .ok_or_else(|| failure(FailureCode::UnexpectedEof))?
                .try_into()
                .map_err(|_| failure(FailureCode::UnexpectedEof))?,
        );
        if !matches!(version, 1 | 2) {
            return Err(failure(FailureCode::UnsupportedPackVersion));
        }
        let count = u32::from_le_bytes(
            bytes
                .get(8..12)
                .ok_or_else(|| failure(FailureCode::UnexpectedEof))?
                .try_into()
                .map_err(|_| failure(FailureCode::UnexpectedEof))?,
        );
        // Count validation belongs after integrity in the two-pass precedence.
        self.header = Some((version, count));
        self.phase = Phase::Integrity;
        Ok(())
    }

    fn retain_frame(
        &mut self,
        (ordinal, info, decoded): (u64, FrameInfo, u64),
    ) -> Result<(), Failure> {
        self.resources.reserve(self.limits.page_bytes)?;
        let mut key = [0; 32];
        key[24..].copy_from_slice(&ordinal.to_be_bytes());
        let mut value = [0; 58];
        value[0] = 1;
        value[1..9].copy_from_slice(&info.offset.to_le_bytes());
        value[9..17].copy_from_slice(&info.length.to_le_bytes());
        value[17] = info.wire_type;
        value[18..26].copy_from_slice(&decoded.to_le_bytes());
        if let Some(previous) = self.last_retained {
            value[26..].copy_from_slice(&previous.digest);
        }
        let limits = EvidenceLimits {
            page_bytes: self.limits.page_bytes,
            allocated_bytes: self.limits.page_bytes,
            ..EvidenceLimits::indexed()
        };
        // The finite page bound is reserved before the encoder allocates.
        self.resources.work(
            self.limits
                .page_bytes
                .checked_mul(4)
                .ok_or_else(|| failure(FailureCode::ResourceLimit))?,
        )?;
        let page = encode_leaf(
            EvidenceBinding {
                source: self.source,
                repository: self.repository,
                ruleset: RulesetBinding {
                    ruleset: INDEXED_RULESET,
                    profile: ProfileId::Indexed,
                },
            },
            PageKind::Occurrences,
            &[LeafRecord { key, value: &value }],
            limits,
        )?;
        let len = page.bytes().len() as u64;
        self.resources
            .finish_work(self.limits.page_bytes * 4, len * 4)?;
        self.resources.evidence(len)?;
        self.retained = Some(page);
        Ok(())
    }

    fn retention_event(&self) -> Result<FramingStep<'_>, Failure> {
        let page = self
            .retained
            .as_ref()
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        Ok(FramingStep::RetainEvidence(EvidencePage {
            commitment: page.commitment(),
            bytes: page.bytes(),
        }))
    }

    /// Acknowledges exactly the outstanding page. Dependent progress and
    /// completion remain blocked until this succeeds.
    ///
    /// # Errors
    /// Wrong, unsolicited, and duplicate acknowledgments are `InvalidResponse`
    /// and preserve the outstanding retention request.
    pub fn acknowledge_retention(&mut self, commitment: PageCommitment) -> Result<(), Failure> {
        self.release_checkpoint()?;
        if self.retained.as_ref().map(EncodedPage::commitment) != Some(commitment) {
            return Err(failure(FailureCode::InvalidResponse));
        }
        self.retained = None;
        self.resources.release(self.limits.page_bytes)?;
        self.retention_count = self
            .retention_count
            .checked_add(1)
            .ok_or_else(|| failure(FailureCode::ResourceLimit))?;
        self.last_retained = Some(commitment);
        Ok(())
    }
}

pub(super) fn map_core(error: &PackError) -> Failure {
    let code = match error {
        PackError::PackfileTooShort => FailureCode::PackfileTooShort,
        PackError::InvalidMagic => FailureCode::InvalidMagic,
        PackError::UnsupportedVersion(_) => FailureCode::UnsupportedPackVersion,
        PackError::InvalidEntryType(_) => FailureCode::InvalidEntryType,
        PackError::TooManyObjects(_) => FailureCode::TooManyObjects,
        PackError::PackfileTooLarge => FailureCode::PackfileTooLarge,
        PackError::UnexpectedEof => FailureCode::UnexpectedEof,
        PackError::PackfileCorrupted => FailureCode::PackfileCorrupted,
        PackError::DeltaBaseMissing(_) => FailureCode::ExternalBaseAbsent,
        PackError::DeltaEntryTruncated => FailureCode::DeltaEntryTruncated,
        PackError::DeltaApply(_) => FailureCode::InvalidDelta,
        PackError::InvalidObject(_) => FailureCode::NonCanonicalObject,
        PackError::NonStorableObject => FailureCode::NonStorableObject,
        PackError::TrailingData => FailureCode::TrailingData,
        PackError::Store(_) => FailureCode::InvalidResponse,
        PackError::ZstdEntryTruncated => FailureCode::ZstdEntryTruncated,
        PackError::DecompressedSizeOverCap(_) => FailureCode::DecompressionLimitExceeded,
        PackError::DecompressedSizeMismatch(_, _) => FailureCode::DecompressedSizeMismatch,
        PackError::ZstdDecompress(_) => {
            if cfg!(any(feature = "pack-zstd", feature = "pack-ruzstd")) {
                FailureCode::DecompressionFailed
            } else {
                FailureCode::UnsupportedCapability
            }
        }
        PackError::RawOnly => FailureCode::UnsupportedCapability,
    };
    Failure {
        location: Location::default(),
        ..failure(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::SourceBinding;
    use mkit_core::hash;

    fn driver(bytes: &[u8]) -> FramingDriver {
        FramingDriver::new(
            PackSource {
                id: hash::hash(bytes),
                len: u64::try_from(bytes.len()).unwrap(),
                binding: SourceBinding([3; 32]),
            },
            RepositoryId([9; 32]),
            IndexedProfile {
                pack_bytes: MAX_PACK_BYTES,
                decoded_bytes: 4 << 30,
                delta_depth: 50,
            },
            VerifyLimits::indexed(),
            7,
        )
        .unwrap()
    }

    fn run(bytes: &[u8]) -> Result<(FramedPack, u64), Failure> {
        let mut machine = driver(bytes);
        loop {
            match machine.step()? {
                FramingStep::Request(Request::Bytes {
                    request,
                    source,
                    range,
                }) => {
                    let begin = usize::try_from(range.offset).unwrap();
                    let end = begin + usize::try_from(range.len).unwrap();
                    machine.supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value: Acquisition::Present(&bytes[begin..end]),
                    })?;
                }
                FramingStep::RetainEvidence(page) => {
                    let commitment = page.commitment;
                    machine.acknowledge_retention(commitment)?;
                }
                FramingStep::Frame(_) | FramingStep::Progress => {}
                FramingStep::Complete(pack) => {
                    return Ok((pack, machine.usage().peak_resident_bytes));
                }
                FramingStep::Request(_) => panic!("unexpected framing transition"),
            }
        }
    }

    #[test]
    fn integrity_precedes_framing_and_every_decoded_frame_is_provisional() {
        let bytes = include_bytes!("../../fixtures/framing/earlier-delta-base.bin");
        let (pack, peak) = run(bytes).unwrap();
        assert_eq!(pack.entries(), 3);
        assert_eq!(pack.version(), 1);
        assert_eq!(pack.source().id, hash::hash(bytes));
        assert!(peak <= VerifyLimits::indexed().resident_bytes);
        let mut malformed = bytes.to_vec();
        malformed[12] = 1;
        assert_eq!(
            run(&malformed).unwrap_err().code,
            FailureCode::PackfileCorrupted
        );
        let split = malformed.len() - 32;
        let trailer = hash::hash(&malformed[..split]);
        malformed[split..].copy_from_slice(&trailer);
        assert_eq!(
            run(&malformed).unwrap_err().code,
            FailureCode::InvalidEntryType
        );
    }

    #[test]
    fn wrong_short_stale_missing_and_duplicate_replies_never_advance() {
        let bytes = include_bytes!("../../fixtures/framing/earlier-delta-base.bin");
        let mut machine = driver(bytes);
        let FramingStep::Request(Request::Bytes {
            request,
            source,
            range,
        }) = machine.step().unwrap()
        else {
            panic!()
        };
        for value in [
            Acquisition::Present(&bytes[..11]),
            Acquisition::Absent,
            Acquisition::Unavailable,
        ] {
            assert!(
                machine
                    .supply(Response::Bytes {
                        request,
                        source,
                        range,
                        value
                    })
                    .is_err()
            );
            assert!(matches!(machine.step().unwrap(), FramingStep::Request(_)));
        }
        assert_eq!(
            machine
                .supply(Response::Bytes {
                    request: RequestId {
                        generation: 6,
                        ..request
                    },
                    source,
                    range,
                    value: Acquisition::Present(&bytes[..12])
                })
                .unwrap_err()
                .code,
            FailureCode::InvalidResponse
        );
        machine
            .supply(Response::Bytes {
                request,
                source,
                range,
                value: Acquisition::Present(&bytes[..12]),
            })
            .unwrap();
        assert_eq!(
            machine
                .supply(Response::Bytes {
                    request,
                    source,
                    range,
                    value: Acquisition::Present(&bytes[..12])
                })
                .unwrap_err()
                .code,
            FailureCode::InvalidResponse
        );
    }

    #[test]
    fn retention_applies_backpressure_and_acknowledgments_are_exact() {
        let bytes = include_bytes!("../../fixtures/framing/earlier-delta-base.bin");
        let mut machine = driver(bytes);
        loop {
            match machine.step().unwrap() {
                FramingStep::Request(Request::Bytes {
                    request,
                    source,
                    range,
                }) => {
                    let begin = usize::try_from(range.offset).unwrap();
                    let end = begin + usize::try_from(range.len).unwrap();
                    machine
                        .supply(Response::Bytes {
                            request,
                            source,
                            range,
                            value: Acquisition::Present(&bytes[begin..end]),
                        })
                        .unwrap();
                }
                FramingStep::RetainEvidence(page) => {
                    let commitment = page.commitment;
                    let copy = page.bytes.to_vec();
                    let mut wrong = commitment;
                    wrong.digest[0] ^= 1;
                    assert_eq!(
                        machine.acknowledge_retention(wrong).unwrap_err().code,
                        FailureCode::InvalidResponse
                    );
                    let FramingStep::RetainEvidence(repeated) = machine.step().unwrap() else {
                        panic!()
                    };
                    assert_eq!(repeated.commitment, commitment);
                    assert_eq!(repeated.bytes, copy);
                    machine.acknowledge_retention(commitment).unwrap();
                    assert_eq!(
                        machine.acknowledge_retention(commitment).unwrap_err().code,
                        FailureCode::InvalidResponse
                    );
                    break;
                }
                FramingStep::Frame(_) | FramingStep::Progress => {}
                _ => panic!("completion before retaining frame evidence"),
            }
        }
        assert_eq!(machine.usage().evidence_pages, 1);
    }
}
