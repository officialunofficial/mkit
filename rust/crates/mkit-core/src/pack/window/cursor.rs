//! Canonical v1 cursor: version byte; four u64s (pack length, window size,
//! position, payload sum); u32 version/count/index; optional first-non-raw u32;
//! completed-window u64; optional expected id and trailer anchor; two trees (u8 depth, CVs,
//! optional root); checksum. Optional fields have a 0/1 tag. All integers LE.
use super::{MAX_ENTRIES, MAX_TOTAL_PAYLOAD, PackError, Tree, geometry};
use crate::hash::{self, Hash};

/// Trusted-at-rest, checksummed entry-boundary state (at most 4 KiB encoded).
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
    pub(super) trailer_tree: Tree,
    pub(super) id_tree: Tree,
}

impl WindowCursor {
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
            trailer_tree: Tree::new(),
            id_tree: Tree::new(),
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
                .validate(self.completed, self.split(), self.window_size)
            || (self.expected.is_some()
                && !self
                    .id_tree
                    .validate(self.completed, self.pack_len, self.window_size))
            || (self.expected.is_none() && self.id_tree != Tree::new())
        {
            return Err(bad);
        }
        Ok(())
    }

    /// Encode canonical little-endian v1 fields followed by BLAKE3 checksum.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![1];
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
        if r.byte()? != 1 {
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
            trailer_tree: Tree::new(),
            id_tree: Tree::new(),
        };
        state.first_non_raw = if r.tag()? { Some(r.u32()?) } else { None };
        state.completed = r.u64()?;
        state.expected = r.optional_hash()?;
        state.anchor = r.optional_hash()?;
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
