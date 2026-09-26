//! Windowed, resumable, sans-IO pack decoding (SPEC-PACKFILE §11).
//!
//! Entries are provisional until [`Step::Done`]. On any error the caller must
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
//! A resumed run re-fetches its current window, then verifies skipped windows
//! before returning `Done`. That extra prefix pass binds the cursor even to a
//! source with a changed prefix and an unchanged, stale trailer. Without a
//! requested pack id, the initial run first fetches the trailer window(s),
//! retaining that anchor in its cursor to bind even an unseen suffix.

use super::{
    DecodeLimits, MAGIC, MAX_ENTRIES, MAX_TOTAL_PAYLOAD, PackEntry, PackError, decode_payload,
    zstd_claim,
};
use crate::hash::Hash;
use std::borrow::Cow;
mod cursor;
mod tree;
pub use cursor::WindowCursor;
use tree::Tree;

/// A range which must be supplied in full to [`WindowReader::feed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WindowRequest {
    pub offset: u64,
    pub len: u64,
}

/// The next action for a window-reader driver.
#[derive(Debug)]
#[non_exhaustive]
pub enum Step {
    /// Fetch exactly this range, then call `feed`.
    NeedWindow(WindowRequest),
    /// An owned entry, provisional until `Done`.
    Entry(PackEntry<'static>),
    /// Framing, trailer, and optional requested pack id are verified.
    Done(WindowSummary),
}

/// Verified pack metadata; raw-only means every wire type was `0x00`.
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
    Verify,
    Done,
    Failed,
}

/// An I/O-free decoder retaining only the current window and current entry.
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
    guard: Option<WindowCursor>,
    verify_count: u64,
    verify_trees: (Tree, Tree),
    #[cfg(test)]
    peak: usize,
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

    /// Restore an entry boundary. The first request contains the next entry.
    ///
    /// # Errors
    /// Inconsistent cursors give `PackfileCorrupted`.
    pub fn resume(cursor: &WindowCursor, limits: DecodeLimits) -> Result<Self, PackError> {
        cursor.validate()?;
        let mut reader = Self::from_state(cursor.clone(), limits, Phase::Boundary);
        reader.boundary = Some(cursor.clone());
        if cursor.completed != 0 {
            reader.guard = Some(cursor.clone());
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
            guard: None,
            verify_count: 0,
            verify_trees: (Tree::new(), Tree::new()),
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
            .min(self.state.window_size);
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
                    self.phase = if self.guard.is_some() {
                        Phase::Verify
                    } else {
                        Phase::Done
                    };
                }
                Phase::Verify => {
                    let guard = self.guard.as_ref().ok_or(PackError::PackfileCorrupted)?;
                    if self.verify_count == guard.completed {
                        if self.verify_trees.0 != guard.trailer_tree
                            || self.verify_trees.1 != guard.id_tree
                        {
                            return Err(PackError::PackfileCorrupted);
                        }
                        self.guard = None;
                        self.phase = Phase::Done;
                    } else {
                        let offset = self
                            .verify_count
                            .checked_mul(self.state.window_size)
                            .ok_or(PackError::PackfileCorrupted)?;
                        return self.need(offset);
                    }
                }
            }
        }
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
        if self.state.payload_sum > MAX_TOTAL_PAYLOAD {
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
            if self.payload_len > self.limits.max_decoded_bytes {
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
            self.entry_finished()?;
            return Ok(Some(Step::Entry(entry)));
        }
        Ok(None)
    }

    fn check_budget(&self, payload: &[u8], carried: u64) -> Result<(), PackError> {
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
        self.state.index = self
            .state
            .index
            .checked_add(1)
            .ok_or(PackError::PackfileTooLarge)?;
        self.phase = Phase::Boundary;
        self.boundary = Some(self.boundary_state());
        Ok(())
    }

    /// Supply exactly the outstanding range. Wrong ranges leave it pending.
    ///
    /// # Errors
    /// Wrong ranges give `PackfileCorrupted`; failed allocations give
    /// `PackfileTooLarge`.
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

    // The synchronous driver transfers its source allocation instead of
    // briefly retaining two copies of a window.
    fn feed_owned(&mut self, offset: u64, bytes: Vec<u8>) -> Result<(), PackError> {
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
        self.phase != Phase::Verify
            && !(self.phase == Phase::Anchor && self.state.pack_len > self.state.window_size)
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
        if self.phase == Phase::Anchor && self.state.pack_len > self.state.window_size {
            self.end = offset
                .checked_add(request.len)
                .ok_or(PackError::PackfileCorrupted)?;
            self.collect_trailer(offset, bytes)?;
        } else if self.phase == Phase::Verify {
            self.verify_trees.0.absorb(
                offset,
                bytes,
                self.state.split(),
                self.state.window_size,
            )?;
            if self.state.expected.is_some() {
                self.verify_trees.1.absorb(
                    offset,
                    bytes,
                    self.state.pack_len,
                    self.state.window_size,
                )?;
            }
            self.verify_count = self
                .verify_count
                .checked_add(1)
                .ok_or(PackError::PackfileCorrupted)?;
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

    /// A compact checkpoint only at an entry boundary, never within an entry.
    #[must_use]
    pub fn checkpoint(&self) -> Option<WindowCursor> {
        if !matches!(self.phase, Phase::Boundary | Phase::Finish | Phase::Done) {
            return None;
        }
        self.boundary.clone()
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
