//! Canonical v1 cursor: version byte; four u64s (pack length, window size,
//! position, payload sum); u32 version/count/index; optional first-non-raw u32;
//! completed-window u64; optional expected id, trailer anchor, and current-window
//! prefix commitment; two trees (u8 depth, CVs, optional root); checksum. Optional
//! fields have a 0/1 tag. All integers LE. The tagged prefix adds at most 33 bytes;
//! the complete encoding remains bounded by 4 KiB. Version 2 adds acquisition-end
//! u64, optional remaining-suffix digest, 32 saved trailer bytes, and an
//! integrity-only 0/1 flag before the two trees. Its trees cover acquired bytes
//! through acquisition-end, rather than only completed consumed windows.
use super::{MAX_ENTRIES, MAX_TOTAL_PAYLOAD, PackError, Tree, geometry};
use crate::hash::{self, Hash};

/// Trusted-at-rest, checksummed entry-boundary state (at most 4 KiB encoded).
///
/// Cursor state stays private; inspect validated bindings through [`Self::metadata`].
///
/// ```compile_fail
/// use mkit_core::pack::window::WindowCursor;
/// fn change(mut cursor: WindowCursor) {
///     cursor.pack_len = 0;
/// }
/// ```
#[derive(Debug, Clone)]
pub struct WindowCursor {
    pub(super) pack_len: u64,
    pub(super) window_size: u64,
    pub(super) pos: u64,
    pub(super) payload_sum: u64,
    pub(super) version: u32,
    pub(super) count: u32,
    pub(super) index: u32,
    pub(super) first_non_raw: Option<u32>,
    pub(super) completed: u64,
    pub(super) expected: Option<Hash>,
    pub(super) anchor: Option<Hash>,
    pub(super) window_prefix: Option<Hash>,
    pub(super) trailer_tree: Tree,
    pub(super) id_tree: Tree,
    pub(super) exact: Option<ExactWindow>,
}

/// Acquisition frontier and binding for an exact resume. The CVs are documented
/// BLAKE3 subtree values, never an encoding of an opaque Hasher.
#[derive(Debug, Clone)]
pub(super) struct ExactWindow {
    pub end: u64,
    pub suffix: Option<Hash>,
    pub trailer: Hash,
    pub integrity_only: bool,
}

/// Validated cursor bindings for comparison with a caller-owned checkpoint.
///
/// This immutable snapshot establishes cursor consistency, not source authenticity
/// or verified-object authority. It has no encoded representation or constructor.
///
/// ```compile_fail
/// use mkit_core::pack::window::WindowCursorMetadata;
/// let _ = WindowCursorMetadata {
///     pack_len: 44, window_size: 65_536, position: 12, payload_sum: 0,
///     pack_version: 1, entry_count: 0, entry_index: 0, expected_pack_id: None,
/// };
/// ```
///
/// ```compile_fail
/// use mkit_core::pack::window::WindowCursorMetadata;
/// fn change(mut metadata: WindowCursorMetadata) {
///     metadata.position = 0;
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowCursorMetadata {
    pack_len: u64,
    window_size: u64,
    position: u64,
    payload_sum: u64,
    pack_version: u32,
    entry_count: u32,
    entry_index: u32,
    expected_pack_id: Option<Hash>,
    exact: bool,
    integrity_only: bool,
    acquired_end: Option<u64>,
}

impl WindowCursorMetadata {
    /// Whether the cursor uses exact-offset acquisition frontiers (encoding v2).
    #[must_use]
    pub const fn exact(&self) -> bool {
        self.exact
    }

    /// End of the bytes already absorbed into the integrity frontier.
    /// Exact version-2 cursors return `Some`; legacy cursors return `None`.
    /// This can exceed the entry position because an acquired window includes
    /// bytes of subsequent entries. Resume does not hash those bytes twice.
    #[must_use]
    pub const fn acquired_end(&self) -> Option<u64> {
        self.acquired_end
    }

    /// Whether resume continues only integrity acquisition, without entry parsing.
    #[must_use]
    pub const fn integrity_only(&self) -> bool {
        self.integrity_only
    }

    /// Pack length, including its trailer.
    #[must_use]
    pub const fn pack_len(&self) -> u64 {
        self.pack_len
    }

    /// Configured acquisition window size.
    #[must_use]
    pub const fn window_size(&self) -> u64 {
        self.window_size
    }

    /// Absolute logical position at the entry boundary.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Cumulative encoded payload bytes before this boundary.
    #[must_use]
    pub const fn payload_sum(&self) -> u64 {
        self.payload_sum
    }

    /// Declared pack wire version.
    #[must_use]
    pub const fn pack_version(&self) -> u32 {
        self.pack_version
    }

    /// Declared total number of entries.
    #[must_use]
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }

    /// Number of entries consumed before this boundary.
    #[must_use]
    pub const fn entry_index(&self) -> u32 {
        self.entry_index
    }

    /// Requested whole-pack identity, when supplied by the caller.
    #[must_use]
    pub const fn expected_pack_id(&self) -> Option<Hash> {
        self.expected_pack_id
    }
}

impl WindowCursor {
    /// Validates existing cursor geometry and frontiers, then copies its bindings.
    ///
    /// This performs no allocation, encoding, source read, or state mutation.
    /// Callers compare these fields with their outer checkpoint before resuming;
    /// the reader still authenticates reacquired bytes during restoration.
    ///
    /// # Errors
    /// Inconsistent cursor state returns [`PackError::PackfileCorrupted`], using
    /// the same validation as cursor decoding and reader restoration.
    pub fn metadata(&self) -> Result<WindowCursorMetadata, PackError> {
        self.validate()?;
        Ok(WindowCursorMetadata {
            pack_len: self.pack_len,
            window_size: self.window_size,
            position: self.pos,
            payload_sum: self.payload_sum,
            pack_version: self.version,
            entry_count: self.count,
            entry_index: self.index,
            expected_pack_id: self.expected,
            exact: self.exact.is_some(),
            acquired_end: self.exact.as_ref().map(|exact| exact.end),
            integrity_only: self
                .exact
                .as_ref()
                .is_some_and(|exact| exact.integrity_only),
        })
    }

    pub(super) fn initial(pack_len: u64, window_size: u64, expected: Option<Hash>) -> Self {
        Self {
            pack_len,
            window_size,
            pos: 12,
            payload_sum: 0,
            version: 0,
            count: 0,
            index: 0,
            first_non_raw: None,
            completed: 0,
            expected,
            anchor: None,
            window_prefix: None,
            trailer_tree: Tree::new(),
            id_tree: Tree::new(),
            exact: None,
        }
    }
    pub(super) fn split(&self) -> u64 {
        self.pack_len - 32
    } // validated geometry
    pub(super) fn validate(&self) -> Result<(), PackError> {
        let bad = PackError::PackfileCorrupted;
        geometry(self.pack_len, self.window_size).map_err(|_| PackError::PackfileCorrupted)?;
        let framing = u64::from(self.index)
            .checked_mul(5)
            .and_then(|n| n.checked_add(12))
            .and_then(|n| n.checked_add(self.payload_sum));
        let max_len = MAX_TOTAL_PAYLOAD
            .checked_add(u64::from(self.count) * 5)
            .and_then(|n| n.checked_add(44));
        let window_start = self.completed.checked_mul(self.window_size);
        let frontier = if let Some(exact) = &self.exact {
            if exact.end < self.pos
                || exact.end > self.pack_len
                || (exact.end != self.pack_len && !exact.end.is_multiple_of(self.window_size))
                || self.window_prefix.is_some()
                || (!exact.integrity_only
                    && exact.end
                        != (self.pos.div_ceil(self.window_size) * self.window_size)
                            .min(self.pack_len)
                    && !(self.pos == self.split()
                        && self.index == self.count
                        && exact.end == self.pack_len))
                || exact.suffix.is_some() != (!exact.integrity_only && exact.end > self.pos)
            {
                return Err(bad);
            }
            let trailer_bytes = usize::try_from(exact.end.saturating_sub(self.split()).min(32))
                .map_err(|_| PackError::PackfileCorrupted)?;
            if exact.trailer[trailer_bytes..].iter().any(|byte| *byte != 0) {
                return Err(bad);
            }
            exact.end.div_ceil(self.window_size)
        } else {
            if window_start.is_none_or(|start| self.window_prefix.is_some() != (self.pos > start)) {
                return Err(bad);
            }
            self.completed
        };
        if (self.expected.is_none() && self.anchor.is_none())
            || !matches!(self.version, 1 | 2)
            || self.count > MAX_ENTRIES
            || self.index > self.count
            || !(12..=self.split()).contains(&self.pos)
            || framing != Some(self.pos)
            || (self.index == 0 && self.payload_sum != 0)
            || self.payload_sum > MAX_TOTAL_PAYLOAD
            || max_len.is_none_or(|n| self.pack_len > n)
            || self.completed != self.pos / self.window_size
            || self.first_non_raw.is_some_and(|i| i >= self.index)
            || !self
                .trailer_tree
                .validate(frontier, self.split(), self.window_size)
            || (self.expected.is_some()
                && !self
                    .id_tree
                    .validate(frontier, self.pack_len, self.window_size))
            || (self.expected.is_none() && self.id_tree != Tree::new())
        {
            return Err(bad);
        }
        Ok(())
    }

    /// Encode canonical versioned little-endian fields followed by BLAKE3 checksum.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![if self.exact.is_some() { 2 } else { 1 }];
        for n in [self.pack_len, self.window_size, self.pos, self.payload_sum] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        for n in [self.version, self.count, self.index] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.push(u8::from(self.first_non_raw.is_some()));
        if let Some(index) = self.first_non_raw {
            out.extend_from_slice(&index.to_le_bytes());
        }
        out.extend_from_slice(&self.completed.to_le_bytes());
        write_option(&mut out, self.expected);
        write_option(&mut out, self.anchor);
        write_option(&mut out, self.window_prefix);
        if let Some(exact) = &self.exact {
            out.extend_from_slice(&exact.end.to_le_bytes());
            write_option(&mut out, exact.suffix);
            out.extend_from_slice(&exact.trailer);
            out.push(u8::from(exact.integrity_only));
        }
        for tree in [&self.trailer_tree, &self.id_tree] {
            // Full pack geometry needs fewer than 64 CVs (and at most 17 under
            // the format caps), so this is lossless for every internal cursor.
            out.push(u8::try_from(tree.stack.len()).unwrap_or(u8::MAX));
            for cv in &tree.stack {
                out.extend_from_slice(cv);
            }
            write_option(&mut out, tree.root);
        }
        out.extend_from_slice(&hash::hash(&out));
        out
    }

    /// Decode a canonical cursor and validate its checksum and field geometry.
    ///
    /// # Errors
    /// Oversized, truncated, unsupported, corrupt, or inconsistent encodings
    /// return `PackfileCorrupted`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PackError> {
        if bytes.len() > 4096 || bytes.len() < 32 {
            return Err(PackError::PackfileCorrupted);
        }
        let (body, checksum) = bytes.split_at(bytes.len() - 32);
        if hash::hash(body).as_slice() != checksum {
            return Err(PackError::PackfileCorrupted);
        }
        let mut r = Input(body);
        let encoding = r.byte()?;
        if !matches!(encoding, 1 | 2) {
            return Err(PackError::PackfileCorrupted);
        }
        let mut state = Self {
            pack_len: r.u64()?,
            window_size: r.u64()?,
            pos: r.u64()?,
            payload_sum: r.u64()?,
            version: r.u32()?,
            count: r.u32()?,
            index: r.u32()?,
            first_non_raw: None,
            completed: 0,
            expected: None,
            anchor: None,
            window_prefix: None,
            trailer_tree: Tree::new(),
            id_tree: Tree::new(),
            exact: None,
        };
        state.first_non_raw = if r.tag()? { Some(r.u32()?) } else { None };
        state.completed = r.u64()?;
        state.expected = r.optional_hash()?;
        state.anchor = r.optional_hash()?;
        state.window_prefix = r.optional_hash()?;
        if encoding == 2 {
            state.exact = Some(ExactWindow {
                end: r.u64()?,
                suffix: r.optional_hash()?,
                trailer: r.array()?,
                integrity_only: r.tag()?,
            });
        }
        state.trailer_tree = r.tree()?;
        state.id_tree = r.tree()?;
        if !r.0.is_empty() {
            return Err(PackError::PackfileCorrupted);
        }
        state.validate()?;
        Ok(state)
    }
}
fn write_option(out: &mut Vec<u8>, value: Option<Hash>) {
    out.push(u8::from(value.is_some()));
    if let Some(hash) = value {
        out.extend_from_slice(&hash);
    }
}
struct Input<'a>(&'a [u8]);
impl Input<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], PackError> {
        let bytes = self.0.get(..N).ok_or(PackError::PackfileCorrupted)?;
        let out = bytes.try_into().map_err(|_| PackError::PackfileCorrupted)?;
        self.0 = &self.0[N..];
        Ok(out)
    }
    fn byte(&mut self) -> Result<u8, PackError> {
        Ok(self.array::<1>()?[0])
    }
    fn tag(&mut self) -> Result<bool, PackError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(PackError::PackfileCorrupted),
        }
    }
    fn u64(&mut self) -> Result<u64, PackError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, PackError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn optional_hash(&mut self) -> Result<Option<Hash>, PackError> {
        if self.tag()? {
            Ok(Some(self.array()?))
        } else {
            Ok(None)
        }
    }
    fn tree(&mut self) -> Result<Tree, PackError> {
        let depth = usize::from(self.byte()?);
        if depth > 64 {
            return Err(PackError::PackfileCorrupted);
        }
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(depth)
            .map_err(|_| PackError::PackfileTooLarge)?;
        for _ in 0..depth {
            stack.push(self.array()?);
        }
        Ok(Tree {
            stack,
            root: self.optional_hash()?,
        })
    }
}
