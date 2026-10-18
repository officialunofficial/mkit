//! Windowed, resumable, sans-IO pack decoding (SPEC-PACKFILE §11).
//!
//! Entries are provisional until normal [`WindowReader::step`] verification returns
//! [`Step::Done`]. Integrity-only draining never clears an earlier content refusal.
//! On any error the caller must
//! discard everything staged by this run, including entries from earlier slices.
//! This reader does not validate objects, resolve deltas, or write to a store.
//!
//! Wrong feed ranges, invalid window geometry, bad cursors, and checksum or
//! pack-id mismatches use [`PackError::PackfileCorrupted`]. Budget or allocation
//! failures use [`PackError::PackfileTooLarge`]. Framing and trailing-data errors
//! match [`super::PackEntries`]; zstd uses `ZstdEntryTruncated`,
//! `DecompressedSizeOverCap`, `DecompressedSizeMismatch`, and `ZstdDecompress`.
//! The decoded budget includes owned entry buffers, including carried wire bytes
//! plus decoded output when both are live. Decoder-internal memory is additional
//! (in particular the ruzstd ring buffer; see the parent module).
//!
//! A resumed run re-fetches its current window and checks the checkpoint's
//! prefix commitment before yielding entries. Completed windows are not re-read.
//! Exact version-2 cursors instead fetch only the remaining suffix and authenticate
//! it against a saved digest; already-acquired subtree values are retained.
//! Without a requested pack id, the initial run first fetches the trailer
//! window(s), retaining that anchor in its cursor to bind even an unseen suffix.

use super::{
    DecodeLimits, MAGIC, MAX_ENTRIES, MAX_TOTAL_PAYLOAD, PackEntry, PackError, decode_payload,
    zstd_claim,
};
use crate::hash::Hash;
use std::borrow::Cow;
mod cursor;
mod residency;
mod tree;
use cursor::ExactWindow;
pub use cursor::{WindowCursor, WindowCursorMetadata};
use tree::Tree;

/// A range which must be supplied in full to [`WindowReader::feed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WindowRequest {
    pub offset: u64,
    pub len: u64,
}

/// Process-local entry-boundary token for batching provisional entries.
/// It has no encoded form and must be bound to the retained acquisition window
/// with [`WindowReader::checkpoint_exact_at`] before it can be persisted.
#[derive(Debug, Clone)]
pub struct WindowBoundary {
    cursor: WindowCursor,
    acquired_trailer: Tree,
    acquired_id: Tree,
}

/// Where the entry a reader last yielded sat in the pack: its complete
/// frame, type and length prefix included, exactly as `DecodedEntry` reports
/// it for the buffered decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrameInfo {
    /// Offset of the complete frame in the pack.
    pub offset: u64,
    /// Length of the complete frame, including its five header bytes.
    pub length: u64,
    /// Encoded frame type (`0x00`, `0x02`, `0x03` or `0x04`).
    pub wire_type: u8,
}

/// The next action for a window-reader driver.
#[derive(Debug)]
#[non_exhaustive]
pub enum Step {
    /// Fetch exactly this range, then call `feed`.
    NeedWindow(WindowRequest),
    /// An owned entry, provisional until normal [`WindowReader::step`] completion.
    Entry(PackEntry<'static>),
    /// Normal [`WindowReader::step`] completion verifies framing, trailer, and
    /// requested pack id. From [`WindowReader::integrity_step`], only trailer and
    /// requested pack id are verified; any earlier content refusal still applies.
    Done(WindowSummary),
}

/// Observed pack metadata; normal reader completion verifies framing as well as
/// integrity. An integrity-only drain does not confer entry or framing acceptance.
/// Raw-only means every observed wire type was `0x00`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WindowSummary {
    pub version: u32,
    pub entry_count: u32,
    pub raw_only: bool,
    pub first_non_raw: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Anchor,
    Header,
    Boundary,
    Frame,
    Payload,
    Finish,
    Done,
    Failed,
}

/// An I/O-free decoder retaining only the current window and current entry.
///
/// **Binding.** `Done` from normal [`Self::step`] verification means every entry yielded across the whole run chain (the original run and every resume
/// through its cursors) is an entry, in order, of the one pack whose bytes hash to the verified pack id: the trailer,
/// and `expected_pack_id` when set. A cursor from pack A used on a source that yields different bytes for any
/// not-yet-verified range fails with `PackfileCorrupted`, never `Done`. The reader does not re-read ranges it has
/// already verified. **Keeping the source immutable across resumes is the caller's job** (informative: WP-4.8 binds
/// R2 range reads to the object's etag). A source whose already-verified prefix changed after verification can still
/// reach `Done`, but only with entries of the verified pack.
#[derive(Debug)]
pub struct WindowReader {
    state: WindowCursor,
    limits: DecodeLimits,
    phase: Phase,
    window: Vec<u8>,
    start: u64,
    end: u64,
    before: (Tree, Tree),
    boundary: Option<WindowCursor>,
    request: Option<WindowRequest>,
    header: [u8; 5],
    header_used: usize,
    kind: u8,
    payload_len: u64,
    carry: Vec<u8>,
    trailer: [u8; 32],
    resume_prefix: Option<Hash>,
    // Fixed-size live state, never serialized. Length is relative to `start`
    // and bounded by the current window (at most 64 MiB).
    prefix: LivePrefix,
    last_frame: Option<FrameInfo>,
    exact_resume: Option<ExactWindow>,
    integrity_only: bool,
    one_pass: bool,
    #[cfg(test)]
    peak: usize,
}

// Preserve Send + Sync and checkpoint(&self) without a lock allocation. The
// once-cell memoizes one boundary; advancing the reader moves its incremental
// state forward. Both hasher slots are fixed-size and never serialized.
#[derive(Debug, Default)]
struct LivePrefix {
    previous: Prefix,
    checkpoint: std::sync::OnceLock<Prefix>,
}

#[derive(Clone, Debug, Default)]
struct Prefix {
    hasher: crate::hash::Hasher,
    len: usize,
}

impl LivePrefix {
    fn digest(&self, bytes: &[u8]) -> Option<Hash> {
        let remaining = bytes.get(self.previous.len..)?;
        let prefix = self.checkpoint.get_or_init(|| {
            let mut prefix = self.previous.clone();
            prefix.hasher.update(remaining);
            prefix.len = bytes.len();
            prefix
        });
        if prefix.len != bytes.len() {
            return None;
        }
        Some(prefix.hasher.finalize())
    }

    fn advance(&mut self) {
        if let Some(prefix) = self.checkpoint.take() {
            self.previous = prefix;
        }
    }
}

fn us(n: u64) -> Result<usize, PackError> {
    usize::try_from(n).map_err(|_| PackError::PackfileTooLarge)
}
fn geometry(pack_len: u64, window: u64) -> Result<(), PackError> {
    if pack_len < 44 {
        return Err(PackError::PackfileTooShort);
    }
    if !(64 << 10..=64 << 20).contains(&window) || !window.is_power_of_two() {
        return Err(PackError::PackfileCorrupted);
    }
    if pack_len > MAX_TOTAL_PAYLOAD + u64::from(MAX_ENTRIES) * 5 + 44 {
        return Err(PackError::PackfileTooLarge);
    }
    Ok(())
}
fn copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, PackError> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| PackError::PackfileTooLarge)?;
    out.extend_from_slice(bytes);
    Ok(out)
}

impl WindowReader {
    /// Start a pack with power-of-two windows between 64 KiB and 64 MiB.
    ///
    /// # Errors
    /// Short pack lengths give `PackfileTooShort`; invalid geometry gives
    /// `PackfileCorrupted`.
    pub fn new(
        pack_len: u64,
        window_size: u64,
        limits: DecodeLimits,
        expected_pack_id: Option<Hash>,
    ) -> Result<Self, PackError> {
        geometry(pack_len, window_size)?;
        Ok(Self::from_state(
            WindowCursor::initial(pack_len, window_size, expected_pack_id),
            limits,
            if expected_pack_id.is_some() {
                Phase::Header
            } else {
                Phase::Anchor
            },
        ))
    }

    /// Start a reader that retains its acquired window through carried-frame
    /// decoding. Successful sequential reads never reacquire that window merely
    /// to release decoder memory. Hosts must budget the retained window alongside
    /// decoder scratch, using [`Self::memory_bound`] before advancing.
    ///
    /// # Errors
    /// Uses the same geometry checks as [`Self::new`].
    pub fn new_one_pass(
        pack_len: u64,
        window_size: u64,
        limits: DecodeLimits,
        expected_pack_id: Option<Hash>,
    ) -> Result<Self, PackError> {
        let mut reader = Self::new(pack_len, window_size, limits, expected_pack_id)?;
        reader.one_pass = true;
        Ok(reader)
    }

    /// Restore a trusted entry boundary for the same immutable pack source.
    /// The first request contains the next entry and authenticates its consumed
    /// window prefix once, rebuilding the live incremental digest. Completed
    /// ranges remain bound by the cursor's explicit tree frontier.
    ///
    /// # Errors
    /// Inconsistent cursors give `PackfileCorrupted`.
    pub fn resume(cursor: &WindowCursor, limits: DecodeLimits) -> Result<Self, PackError> {
        cursor.validate()?;
        let mut reader = Self::from_state(cursor.clone(), limits, Phase::Boundary);
        reader.boundary = Some(cursor.clone());
        reader.resume_prefix = cursor.window_prefix;
        if let Some(exact) = &cursor.exact {
            reader.one_pass = true;
            reader.trailer = exact.trailer;
            reader.integrity_only = exact.integrity_only;
            if exact.integrity_only {
                reader.start = exact.end;
                reader.end = exact.end;
            } else {
                reader.start = cursor.pos;
                reader.end = cursor.pos;
                if exact.end > cursor.pos {
                    reader.exact_resume = Some(exact.clone());
                }
            }
        }
        Ok(reader)
    }

    fn from_state(state: WindowCursor, limits: DecodeLimits, phase: Phase) -> Self {
        let start = state.completed * state.window_size; // validated cursor geometry
        let before = (state.trailer_tree.clone(), state.id_tree.clone());
        Self {
            state,
            limits,
            phase,
            window: Vec::new(),
            start,
            end: start,
            before,
            boundary: None,
            request: None,
            header: [0; 5],
            header_used: 0,
            kind: 0,
            payload_len: 0,
            carry: Vec::new(),
            trailer: [0; 32],
            resume_prefix: None,
            prefix: LivePrefix::default(),
            last_frame: None,
            exact_resume: None,
            integrity_only: false,
            one_pass: false,
            #[cfg(test)]
            peak: 0,
        }
    }

    fn need(&mut self, offset: u64) -> Result<Step, PackError> {
        let len = self
            .state
            .pack_len
            .checked_sub(offset)
            .ok_or(PackError::PackfileCorrupted)?
            .min(
                self.exact_resume
                    .as_ref()
                    .map_or(self.state.window_size, |exact| exact.end - offset),
            );
        if len == 0 {
            return Err(PackError::UnexpectedEof);
        }
        self.window = Vec::new();
        let request = WindowRequest { offset, len };
        self.request = Some(request);
        Ok(Step::NeedWindow(request))
    }

    /// Advance to a request, an entry, or verified completion.
    ///
    /// # Errors
    /// Malformed packs, resource limits, and failed integrity checks use the
    /// errors documented at module level. A parsing error makes the reader inert.
    pub fn step(&mut self) -> Result<Step, PackError> {
        if self.integrity_only {
            return self.integrity_step();
        }
        if let Some(request) = self.request {
            return Ok(Step::NeedWindow(request));
        }
        let result = self.advance();
        if result.is_err() {
            self.phase = Phase::Failed;
        }
        result
    }

    fn advance(&mut self) -> Result<Step, PackError> {
        loop {
            match self.phase {
                Phase::Failed => return Err(PackError::PackfileCorrupted),
                Phase::Done => return Ok(Step::Done(self.summary())),
                Phase::Anchor => {
                    if self.end == self.state.pack_len {
                        self.state.anchor = Some(self.trailer);
                        self.trailer = [0; 32];
                        self.start = 0;
                        self.end = 0;
                        self.phase = Phase::Header;
                    } else {
                        let offset = if self.end == 0 {
                            (self.state.split() / self.state.window_size) * self.state.window_size
                        } else {
                            self.end
                        };
                        return self.need(offset);
                    }
                }
                Phase::Header => {
                    if let Some(step) = self.advance_header()? {
                        return Ok(step);
                    }
                }
                Phase::Boundary => {
                    // Resume must fetch the containing window, even at EOF.
                    if self.window.is_empty() {
                        return self.need(self.start);
                    }
                    if self.state.index == self.state.count {
                        self.phase = Phase::Finish;
                        continue;
                    }
                    self.header_used = 0;
                    self.phase = Phase::Frame;
                }
                Phase::Frame => {
                    if let Some(step) = self.advance_frame()? {
                        return Ok(step);
                    }
                }
                Phase::Payload => {
                    if let Some(step) = self.advance_payload()? {
                        return Ok(step);
                    }
                }
                Phase::Finish => {
                    if self.state.pos != self.state.split() {
                        return Err(PackError::TrailingData);
                    }
                    if self.end < self.state.pack_len {
                        return self.need(self.end);
                    }
                    self.verify_integrity()?;
                    self.phase = Phase::Done;
                }
            }
        }
    }

    /// Continue only acquisition and integrity verification, even after a framing
    /// or decoding error. No further entries are parsed or allocated. Hosts may
    /// defer that earlier refusal until this verifies the trailer and requested id.
    /// `Done` from this method confers no framing or entry acceptance. Subsequent
    /// [`Self::step`] calls remain in integrity-only mode with the same contract.
    ///
    /// # Errors
    /// Invalid ranges, allocation failures, and final integrity mismatches use the
    /// same errors as [`Self::step`]. A content error does not prevent this drain.
    pub fn integrity_step(&mut self) -> Result<Step, PackError> {
        self.integrity_only = true;
        self.carry = Vec::new();
        if let Some(exact) = self.exact_resume.take() {
            // Parsing no longer needs this already-hashed suffix.
            self.end = exact.end;
            self.request = None;
            self.state.exact = None;
        }
        if let Some(request) = self.request {
            return Ok(Step::NeedWindow(request));
        }
        // Anchor-only acquisition has not entered the sequential hash stream.
        if self.phase == Phase::Anchor {
            if self.end == self.state.pack_len {
                self.state.anchor = Some(self.trailer);
            }
            self.trailer = [0; 32];
            self.start = 0;
            self.end = 0;
            self.phase = Phase::Finish;
        }
        if self.end < self.state.pack_len {
            return self.need(self.end);
        }
        self.verify_integrity()?;
        self.phase = Phase::Done;
        Ok(Step::Done(self.summary()))
    }

    fn verify_integrity(&self) -> Result<(), PackError> {
        if self
            .state
            .anchor
            .is_some_and(|anchor| anchor != self.trailer)
            || self.state.trailer_tree.root != Some(self.trailer)
            || self
                .state
                .expected
                .is_some_and(|id| self.state.id_tree.root != Some(id))
        {
            return Err(PackError::PackfileCorrupted);
        }
        Ok(())
    }

    /// The source trailer, available only after final integrity acceptance.
    #[must_use]
    pub fn trailer(&self) -> Option<Hash> {
        (self.phase == Phase::Done).then_some(self.trailer)
    }

    fn advance_header(&mut self) -> Result<Option<Step>, PackError> {
        if self.window.is_empty() {
            return self.need(0).map(Some);
        }
        if &self.window[..4] != MAGIC {
            return Err(PackError::InvalidMagic);
        }
        self.state.version = u32::from_le_bytes(
            self.window[4..8]
                .try_into()
                .map_err(|_| PackError::UnexpectedEof)?,
        );
        if !matches!(self.state.version, 1 | 2) {
            return Err(PackError::UnsupportedVersion(self.state.version));
        }
        self.state.count = u32::from_le_bytes(
            self.window[8..12]
                .try_into()
                .map_err(|_| PackError::UnexpectedEof)?,
        );
        if self.state.count > MAX_ENTRIES {
            return Err(PackError::TooManyObjects(self.state.count));
        }
        self.phase = Phase::Boundary;
        self.prefix.advance();
        self.boundary = Some(self.boundary_state());
        Ok(None)
    }

    fn advance_frame(&mut self) -> Result<Option<Step>, PackError> {
        if self
            .state
            .pos
            .checked_add(
                u64::try_from(5 - self.header_used).map_err(|_| PackError::PackfileTooLarge)?,
            )
            .is_none_or(|end| end > self.state.split())
        {
            return Err(PackError::UnexpectedEof);
        }
        if self.state.pos == self.end {
            return self.need(self.end).map(Some);
        }
        let begin = us(self
            .state
            .pos
            .checked_sub(self.start)
            .ok_or(PackError::PackfileCorrupted)?)?;
        let n = (5 - self.header_used).min(self.window.len() - begin);
        self.header[self.header_used..self.header_used + n]
            .copy_from_slice(&self.window[begin..begin + n]);
        self.header_used += n;
        self.state.pos = self
            .state
            .pos
            .checked_add(u64::try_from(n).map_err(|_| PackError::PackfileTooLarge)?)
            .ok_or(PackError::PackfileTooLarge)?;
        if self.header_used != 5 {
            return Ok(None);
        }
        self.kind = self.header[0];
        self.payload_len = u64::from(u32::from_le_bytes(
            self.header[1..]
                .try_into()
                .map_err(|_| PackError::UnexpectedEof)?,
        ));
        self.state.payload_sum = self
            .state
            .payload_sum
            .checked_add(self.payload_len)
            .ok_or(PackError::PackfileTooLarge)?;
        if self
            .limits
            .entry_geometry
            .is_some_and(|(frame, _)| self.payload_len > frame)
            || self.state.payload_sum > MAX_TOTAL_PAYLOAD
        {
            return Err(PackError::PackfileTooLarge);
        }
        if self.payload_len
            > self
                .state
                .split()
                .checked_sub(self.state.pos)
                .ok_or(PackError::UnexpectedEof)?
        {
            return Err(PackError::UnexpectedEof);
        }
        match self.kind {
            0 => {}
            2 | 4 if self.kind == 2 || self.state.version == 2 => {
                if self.payload_len < 32 {
                    return Err(PackError::DeltaEntryTruncated);
                }
            }
            3 if self.state.version == 2 => {}
            other => return Err(PackError::InvalidEntryType(other)),
        }
        if self.one_pass {
            let cap = match self.kind {
                0 => Some(self.limits.max_decoded_bytes),
                2 => self
                    .limits
                    .entry_geometry
                    .map(|(_, stream)| stream.saturating_add(32)),
                _ => None,
            };
            if cap.is_some_and(|cap| self.payload_len > cap) {
                return Err(PackError::PackfileTooLarge);
            }
        }
        if self.kind != 0 && self.state.first_non_raw.is_none() {
            self.state.first_non_raw = Some(self.state.index);
        }
        self.phase = Phase::Payload;
        Ok(None)
    }

    fn advance_payload(&mut self) -> Result<Option<Step>, PackError> {
        let carried = u64::try_from(self.carry.len()).map_err(|_| PackError::PackfileTooLarge)?;
        let remaining = self
            .payload_len
            .checked_sub(carried)
            .ok_or(PackError::PackfileCorrupted)?;
        if self.state.pos == self.end && remaining != 0 {
            return self.need(self.end).map(Some);
        }
        let begin = us(self
            .state
            .pos
            .checked_sub(self.start)
            .ok_or(PackError::PackfileCorrupted)?)?;
        let available =
            u64::try_from(self.window.len() - begin).map_err(|_| PackError::PackfileTooLarge)?;
        if self.carry.is_empty() && remaining <= available {
            let end = begin
                .checked_add(us(remaining)?)
                .ok_or(PackError::PackfileTooLarge)?;
            let payload = &self.window[begin..end];
            self.check_budget(payload, 0)?;
            let entry = own_entry(decode_payload(self.kind, self.state.version, payload)?)?;
            self.record_peak(entry_len(&entry));
            self.state.pos = self
                .state
                .pos
                .checked_add(remaining)
                .ok_or(PackError::PackfileTooLarge)?;
            self.entry_finished()?;
            return Ok(Some(Step::Entry(entry)));
        }
        if self.carry.is_empty() {
            if self.payload_len
                > self
                    .limits
                    .entry_geometry
                    .map_or(self.limits.max_decoded_bytes, |(frame, _)| frame)
            {
                return Err(PackError::PackfileTooLarge);
            }
            self.carry
                .try_reserve_exact(us(self.payload_len)?)
                .map_err(|_| PackError::PackfileTooLarge)?;
        }
        let n = remaining.min(available);
        let end = begin
            .checked_add(us(n)?)
            .ok_or(PackError::PackfileTooLarge)?;
        self.carry.extend_from_slice(&self.window[begin..end]);
        self.state.pos = self
            .state
            .pos
            .checked_add(n)
            .ok_or(PackError::PackfileTooLarge)?;
        self.record_peak(0);
        // Check a zstd claim as soon as its prefix has arrived.
        let prefix = if self.kind == 4 { 36 } else { 4 };
        if matches!(self.kind, 3 | 4) && self.carry.len() >= prefix {
            self.check_budget(&self.carry, self.payload_len)?;
        }
        if u64::try_from(self.carry.len()).map_err(|_| PackError::PackfileTooLarge)?
            == self.payload_len
        {
            self.check_budget(&self.carry, self.payload_len)?;
            let released = self.release_carried_window()?;
            let entry = if matches!(self.kind, 0 | 2) {
                let mut bytes = std::mem::take(&mut self.carry);
                if self.kind == 0 {
                    PackEntry::Raw {
                        bytes: Cow::Owned(bytes),
                    }
                } else {
                    let base = bytes[..32]
                        .try_into()
                        .map_err(|_| PackError::DeltaEntryTruncated)?;
                    bytes.drain(..32);
                    PackEntry::Delta {
                        base,
                        stream: Cow::Owned(bytes),
                    }
                }
            } else {
                let entry = own_entry(decode_payload(self.kind, self.state.version, &self.carry)?)?;
                self.record_peak(entry_len(&entry));
                self.carry = Vec::new();
                entry
            };
            if let Some(cursor) = released {
                let frame = self.last_frame;
                *self = Self::resume(&cursor, self.limits)?;
                self.last_frame = frame;
            } else {
                self.entry_finished()?;
            }
            return Ok(Some(Step::Entry(entry)));
        }
        Ok(None)
    }

    // Authenticate the post-entry prefix before releasing the carried frame's window.
    fn release_carried_window(&mut self) -> Result<Option<WindowCursor>, PackError> {
        if self.one_pass || self.limits.entry_geometry.is_none() || !matches!(self.kind, 3 | 4) {
            return Ok(None);
        }
        self.entry_finished()?;
        let cursor = self.checkpoint().ok_or(PackError::PackfileCorrupted)?;
        self.window = Vec::new();
        Ok(Some(cursor))
    }

    fn check_budget(&self, payload: &[u8], carried: u64) -> Result<(), PackError> {
        if let Some((frame, stream)) = self.limits.entry_geometry {
            let claim = match self.kind {
                3 => zstd_claim(payload)?.0 as u64,
                4 => zstd_claim(payload.get(32..).ok_or(PackError::DeltaEntryTruncated)?)?.0 as u64,
                _ => self.payload_len,
            };
            let cap = match self.kind {
                2 => stream.saturating_add(32),
                4 => stream,
                _ => self.limits.max_decoded_bytes,
            };
            return if self.payload_len <= frame && claim <= cap {
                Ok(())
            } else {
                Err(PackError::PackfileTooLarge)
            };
        }
        let charge = if matches!(self.kind, 3 | 4) {
            let prefix = if self.kind == 4 { 32 } else { 0 };
            let (claim, _) = zstd_claim(
                payload
                    .get(prefix..)
                    .ok_or(PackError::DeltaEntryTruncated)?,
            )?;
            carried
                .checked_add(u64::try_from(claim).map_err(|_| PackError::PackfileTooLarge)?)
                .ok_or(PackError::PackfileTooLarge)?
        } else {
            self.payload_len
        };
        if charge > self.limits.max_decoded_bytes {
            Err(PackError::PackfileTooLarge)
        } else {
            Ok(())
        }
    }

    fn entry_finished(&mut self) -> Result<(), PackError> {
        let length = self
            .payload_len
            .checked_add(5)
            .ok_or(PackError::PackfileTooLarge)?;
        self.last_frame = Some(FrameInfo {
            offset: self
                .state
                .pos
                .checked_sub(length)
                .ok_or(PackError::PackfileCorrupted)?,
            length,
            wire_type: self.kind,
        });
        self.state.index = self
            .state
            .index
            .checked_add(1)
            .ok_or(PackError::PackfileTooLarge)?;
        self.phase = Phase::Boundary;
        self.prefix.advance();
        self.boundary = Some(self.boundary_state());
        Ok(())
    }

    /// Supply exactly the outstanding range. Wrong ranges leave it pending.
    ///
    /// # Errors
    /// Wrong ranges or changed consumed prefixes give `PackfileCorrupted`.
    /// Failed allocations give `PackfileTooLarge`.
    pub fn feed(&mut self, offset: u64, bytes: &[u8]) -> Result<(), PackError> {
        self.validate_feed(offset, bytes)?;
        let retain = self.retains_window();
        let buffer = if retain {
            copy_bytes(bytes)?
        } else {
            Vec::new()
        };
        self.feed_data(offset, bytes)?;
        if retain {
            self.window = buffer;
            self.record_peak(0);
        }
        Ok(())
    }

    /// Supply a range by transferring its buffer, avoiding two full-window copies.
    ///
    /// # Errors
    /// Wrong ranges or changed consumed prefixes give `PackfileCorrupted`;
    /// allocation failure gives `PackfileTooLarge`.
    pub fn feed_owned(&mut self, offset: u64, bytes: Vec<u8>) -> Result<(), PackError> {
        self.validate_feed(offset, &bytes)?;
        let retain = self.retains_window();
        let bytes = if retain && bytes.capacity() > us(self.state.window_size)? {
            copy_bytes(&bytes)?
        } else {
            bytes
        };
        self.feed_data(offset, &bytes)?;
        if retain {
            self.window = bytes;
            self.record_peak(0);
        }
        Ok(())
    }

    fn retains_window(&self) -> bool {
        !(self.integrity_only
            || (self.phase == Phase::Anchor && self.state.pack_len > self.state.window_size))
    }

    fn validate_feed(&self, offset: u64, bytes: &[u8]) -> Result<WindowRequest, PackError> {
        let request = self.request.ok_or(PackError::PackfileCorrupted)?;
        if request.offset != offset
            || u64::try_from(bytes.len()).map_err(|_| PackError::PackfileTooLarge)? != request.len
        {
            return Err(PackError::PackfileCorrupted);
        }
        Ok(request)
    }

    fn feed_data(&mut self, offset: u64, bytes: &[u8]) -> Result<(), PackError> {
        let request = self.validate_feed(offset, bytes)?;
        if let Some(exact) = self.exact_resume.as_ref() {
            if crate::hash::hash(bytes) != exact.suffix.ok_or(PackError::PackfileCorrupted)? {
                return Err(PackError::PackfileCorrupted);
            }
            // This suffix was already part of the persisted subtree frontier.
            // Authenticate its bytes, without absorbing that subtree twice.
            self.start = offset;
            self.end = exact.end;
            self.collect_trailer(offset, bytes)?;
            self.exact_resume = None;
            self.state.exact = None;
            self.request = None;
            self.prefix = LivePrefix::default();
            return Ok(());
        }
        self.state.exact = None;
        let mut prefix_hasher = crate::hash::Hasher::new();
        let mut prefix_len = 0;
        if let Some(expected) = self.resume_prefix {
            let consumed = self
                .state
                .pos
                .checked_sub(offset)
                .ok_or(PackError::PackfileCorrupted)?;
            let prefix = bytes
                .get(..us(consumed)?)
                .ok_or(PackError::PackfileCorrupted)?;
            prefix_hasher.update(prefix);
            prefix_len = prefix.len();
            if prefix_hasher.finalize() != expected {
                return Err(PackError::PackfileCorrupted);
            }
            self.resume_prefix = None;
        }
        if self.phase == Phase::Anchor && self.state.pack_len > self.state.window_size {
            self.end = offset
                .checked_add(request.len)
                .ok_or(PackError::PackfileCorrupted)?;
            self.collect_trailer(offset, bytes)?;
        } else {
            self.before = (self.state.trailer_tree.clone(), self.state.id_tree.clone());
            self.state.trailer_tree.absorb(
                offset,
                bytes,
                self.state.split(),
                self.state.window_size,
            )?;
            if self.state.expected.is_some() {
                self.state.id_tree.absorb(
                    offset,
                    bytes,
                    self.state.pack_len,
                    self.state.window_size,
                )?;
            }
            self.start = offset;
            self.end = offset
                .checked_add(request.len)
                .ok_or(PackError::PackfileCorrupted)?;
            self.collect_trailer(offset, bytes)?;
            if self.phase == Phase::Anchor {
                // A single-window pack already supplies the trailer and all
                // stream bytes. Reuse its buffer and hashes for header parsing.
                self.state.anchor = Some(self.trailer);
                self.phase = Phase::Header;
            }
        }
        self.prefix = LivePrefix {
            previous: Prefix {
                hasher: prefix_hasher,
                len: prefix_len,
            },
            checkpoint: std::sync::OnceLock::new(),
        };
        self.request = None;
        Ok(())
    }

    fn collect_trailer(&mut self, offset: u64, bytes: &[u8]) -> Result<(), PackError> {
        let from = self.state.split().max(offset);
        if from < self.end {
            let src = us(from
                .checked_sub(offset)
                .ok_or(PackError::PackfileCorrupted)?)?;
            let dst = us(from
                .checked_sub(self.state.split())
                .ok_or(PackError::PackfileCorrupted)?)?;
            let n = us(self
                .end
                .checked_sub(from)
                .ok_or(PackError::PackfileCorrupted)?)?;
            self.trailer[dst..dst + n].copy_from_slice(&bytes[src..src + n]);
        }
        Ok(())
    }

    /// The frame of the entry the latest [`Step::Entry`] returned, or `None`
    /// before the first one. A resumed reader starts with `None`.
    #[must_use]
    pub fn last_frame(&self) -> Option<FrameInfo> {
        self.last_frame
    }

    /// A compact checkpoint only at an entry boundary, never within an entry.
    ///
    /// Absorbs only bytes consumed since the previous checkpoint, then finalizes
    /// the live incremental prefix digest. Cold resume verifies
    /// and rebuilds the prefix once from the supplied immutable source window.
    /// Completed ranges retain explicit subtree commitments. This does not
    /// replace the final trailer or requested whole-pack identity checks.
    /// Returns `None` if
    /// the reader has released the bytes needed for that prefix, including while
    /// fetching a split trailer or awaiting a resumed window. Keep the previous
    /// cursor in that case. No bytes are needed when the boundary is exactly at
    /// a window start. Mid-entry states, including carried straddling entries,
    /// never produce a checkpoint.
    ///
    /// # Examples
    /// ```
    /// use mkit_core::{hash, pack::{DecodeLimits, PackWriter, window::{Step, WindowReader}}};
    /// let mut writer = PackWriter::new_raw_only();
    /// writer.push_raw(hash::hash(b"entry"), b"entry")?;
    /// let pack = writer.finish()?;
    /// let mut reader = WindowReader::new(pack.len() as u64, 64 << 10,
    ///     DecodeLimits::default(), Some(hash::hash(&pack)))?;
    /// assert!(matches!(reader.step()?, Step::NeedWindow(_)));
    /// reader.feed(0, &pack)?;
    /// assert!(matches!(reader.step()?, Step::Entry(_)));
    /// let cursor = reader.checkpoint().unwrap();
    /// assert_eq!(cursor.to_bytes(), reader.checkpoint().unwrap().to_bytes());
    /// # Ok::<(), mkit_core::pack::PackError>(())
    /// ```
    #[must_use]
    pub fn checkpoint(&self) -> Option<WindowCursor> {
        if !matches!(self.phase, Phase::Boundary | Phase::Finish | Phase::Done) {
            return None;
        }
        let mut cursor = self.boundary.clone()?;
        if cursor.exact.is_some() || !self.start.is_multiple_of(self.state.window_size) {
            return None;
        }
        if self.window.is_empty()
            && self.limits.entry_geometry.is_some()
            && self.resume_prefix.is_some()
        {
            return Some(cursor);
        }
        let start = cursor.completed.checked_mul(cursor.window_size)?;
        let prefix_len = cursor.pos.checked_sub(start)?;
        cursor.window_prefix = if prefix_len == 0 {
            None
        } else {
            if self.start != start {
                return None;
            }
            let end = usize::try_from(prefix_len).ok()?;
            self.prefix.digest(self.window.get(..end)?)
        };
        Some(cursor)
    }

    /// Capture a process-local boundary without hashing its remaining suffix.
    /// Batches retain this token until they choose their committed boundary.
    /// It can be checkpointed only while its acquisition window remains retained.
    #[must_use]
    pub fn checkpoint_boundary(&self) -> Option<WindowBoundary> {
        if !matches!(self.phase, Phase::Boundary | Phase::Finish | Phase::Done) {
            return None;
        }
        Some(WindowBoundary {
            cursor: self.boundary.clone()?,
            acquired_trailer: self.state.trailer_tree.clone(),
            acquired_id: self.state.id_tree.clone(),
        })
    }

    /// Whether the next complete entry is available in the retained window.
    /// Hosts can use this to bound batching before another acquisition is needed.
    #[must_use]
    pub fn next_entry_fits_window(&self) -> bool {
        if self.phase != Phase::Boundary || self.state.index == self.state.count {
            return false;
        }
        let Some(begin) = self
            .state
            .pos
            .checked_sub(self.start)
            .and_then(|n| usize::try_from(n).ok())
        else {
            return false;
        };
        let Some(header) = self.window.get(begin..).and_then(|bytes| bytes.get(..5)) else {
            return false;
        };
        let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        self.window.len().saturating_sub(begin + 5) >= len
    }

    /// Number of suffix bytes hashed by the next [`Self::checkpoint_exact`].
    /// Cursor encoding and its bounded checksum are charged separately.
    #[must_use]
    pub fn exact_checkpoint_work(&self) -> u64 {
        if self.integrity_only || self.exact_resume.is_some() {
            return 0;
        }
        self.boundary
            .as_ref()
            .map_or(0, |cursor| self.end.saturating_sub(cursor.pos))
    }

    /// Number of source bytes hashed to bind a batching boundary's suffix.
    /// Returns zero for a token that is no longer in the retained window.
    #[must_use]
    pub fn exact_checkpoint_work_at(&self, boundary: &WindowBoundary) -> u64 {
        if self.boundary_is_retained(boundary) {
            self.end.saturating_sub(boundary.cursor.pos)
        } else {
            0
        }
    }

    /// Checkpoint at the exact entry offset, retaining documented BLAKE3 subtree
    /// frontiers through the acquired window and a digest of its remaining suffix.
    /// Cold resume fetches only that suffix, authenticates it, and never absorbs
    /// it into the frontier twice. No consumed prefix is acquired again.
    ///
    /// This produces cursor encoding version 2. An integrity-only drain retains
    /// the last entry boundary and resumes at the completed acquisition frontier.
    #[must_use]
    pub fn checkpoint_exact(&self) -> Option<WindowCursor> {
        if let Some(exact) = &self.exact_resume {
            let mut cursor = self.boundary.clone()?;
            cursor.exact = Some(exact.clone());
            return Some(cursor);
        }
        if !self.integrity_only
            && !matches!(self.phase, Phase::Boundary | Phase::Finish | Phase::Done)
        {
            return None;
        }
        self.exact_cursor(self.boundary.clone()?)
    }

    /// Bind an earlier process-local boundary to the currently retained window.
    /// Tokens from another source, or windows already released, return `None`.
    /// The host charges [`Self::exact_checkpoint_work_at`] before this operation.
    #[must_use]
    pub fn checkpoint_exact_at(&self, boundary: &WindowBoundary) -> Option<WindowCursor> {
        if !self.boundary_is_retained(boundary) || self.integrity_only {
            return None;
        }
        self.exact_cursor(boundary.cursor.clone())
    }

    fn boundary_is_retained(&self, boundary: &WindowBoundary) -> bool {
        let cursor = &boundary.cursor;
        boundary.acquired_trailer == self.state.trailer_tree
            && boundary.acquired_id == self.state.id_tree
            && cursor.pack_len == self.state.pack_len
            && cursor.window_size == self.state.window_size
            && cursor.expected == self.state.expected
            && cursor.anchor == self.state.anchor
            && cursor.version == self.state.version
            && cursor.count == self.state.count
            && cursor.pos >= self.start
            && cursor.pos <= self.state.pos
            && cursor.pos <= self.end
            && !self.window.is_empty()
    }

    fn exact_cursor(&self, mut cursor: WindowCursor) -> Option<WindowCursor> {
        cursor.trailer_tree = self.state.trailer_tree.clone();
        cursor.id_tree = self.state.id_tree.clone();
        cursor.window_prefix = None;
        let suffix = if !self.integrity_only && self.end > cursor.pos {
            if cursor.pos == cursor.split()
                && self.end == cursor.pack_len
                && self.start > cursor.pos
            {
                Some(crate::hash::hash(&self.trailer))
            } else {
                let begin = usize::try_from(cursor.pos.checked_sub(self.start)?).ok()?;
                Some(crate::hash::hash(self.window.get(begin..)?))
            }
        } else {
            None
        };
        cursor.exact = Some(ExactWindow {
            end: self.end,
            suffix,
            trailer: self.trailer,
            integrity_only: self.integrity_only,
        });
        cursor.validate().ok()?;
        Some(cursor)
    }

    fn boundary_state(&self) -> WindowCursor {
        let mut state = self.state.clone();
        state.completed = state.pos / state.window_size;
        if state.completed == self.start / state.window_size {
            state.trailer_tree = self.before.0.clone();
            state.id_tree = self.before.1.clone();
        }
        state
    }

    fn summary(&self) -> WindowSummary {
        WindowSummary {
            version: self.state.version,
            entry_count: self.state.count,
            raw_only: self.state.first_non_raw.is_none(),
            first_non_raw: self.state.first_non_raw,
        }
    }

    #[cfg_attr(not(test), allow(clippy::unused_self))] // counter exists only in tests
    fn record_peak(&mut self, extra: usize) {
        #[cfg(test)]
        {
            self.peak = self
                .peak
                .max(self.window.capacity() + self.carry.capacity() + extra);
        }
        #[cfg(not(test))]
        let _ = extra;
    }
}

fn own_entry(entry: PackEntry<'_>) -> Result<PackEntry<'static>, PackError> {
    fn own(bytes: Cow<'_, [u8]>) -> Result<Cow<'static, [u8]>, PackError> {
        Ok(Cow::Owned(match bytes {
            Cow::Owned(bytes) => bytes,
            Cow::Borrowed(bytes) => copy_bytes(bytes)?,
        }))
    }
    Ok(match entry {
        PackEntry::Raw { bytes } => PackEntry::Raw { bytes: own(bytes)? },
        PackEntry::Delta { base, stream } => PackEntry::Delta {
            base,
            stream: own(stream)?,
        },
    })
}
fn entry_len(entry: &PackEntry<'_>) -> usize {
    let bytes = match entry {
        PackEntry::Raw { bytes } => bytes,
        PackEntry::Delta { stream, .. } => stream,
    };
    match bytes {
        Cow::Borrowed(bytes) => bytes.len(),
        Cow::Owned(bytes) => bytes.capacity(),
    }
}

/// A synchronous source serving exact ranges, without retaining earlier windows.
pub trait WindowSource {
    /// Read exactly `len` bytes beginning at `offset`.
    ///
    /// # Errors
    /// Return a pack error for a short read or source failure.
    fn read_window(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, PackError>;
}
impl WindowSource for &[u8] {
    fn read_window(&mut self, offset: u64, len: u64) -> Result<Vec<u8>, PackError> {
        let end = offset.checked_add(len).ok_or(PackError::UnexpectedEof)?;
        copy_bytes(
            self.get(us(offset)?..us(end)?)
                .ok_or(PackError::UnexpectedEof)?,
        )
    }
}

/// Drive a reader synchronously, dropping each window after feeding it.
///
/// # Errors
/// Propagates reader, source, or sink errors. All previously delivered entries
/// must be discarded on error, including a final integrity failure.
pub fn read_all<S: WindowSource>(
    source: &mut S,
    pack_len: u64,
    window_size: u64,
    limits: DecodeLimits,
    expected_pack_id: Option<Hash>,
    mut sink: impl FnMut(PackEntry<'static>) -> Result<(), PackError>,
) -> Result<WindowSummary, PackError> {
    let mut reader = WindowReader::new(pack_len, window_size, limits, expected_pack_id)?;
    loop {
        match reader.step()? {
            Step::NeedWindow(request) => {
                let bytes = source.read_window(request.offset, request.len)?;
                reader.feed_owned(request.offset, bytes)?;
            }
            Step::Entry(entry) => sink(entry)?,
            Step::Done(summary) => return Ok(summary),
        }
    }
}

#[cfg(test)]
mod tests;
