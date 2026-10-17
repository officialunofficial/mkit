//! Strict occurrence-page values for provisional frame evidence.
use super::{CANONICAL_BYTES, DELTA_BYTES, FRAME_BYTES};
use crate::{
    codec::{Budget, Cursor, failure},
    error::{Failure, FailureCode},
};
use mkit_core::hash::Hash;

/// A framing record establishes placement, never canonical object validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRecord {
    offset: u64,
    length: u64,
    wire_type: u8,
    decoded: u64,
    previous: Hash,
}

impl FrameRecord {
    /// Strictly decodes one fixed-size versioned occurrence value.
    ///
    /// # Errors
    /// Refuses unsupported versions, impossible frame geometry or wire types,
    /// truncated input, and trailing data. This operation allocates nothing.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Failure> {
        let mut budget = Budget::new(16, 0);
        let mut input = Cursor::new(bytes, &mut budget);
        if input.byte()? != 1 {
            return Err(failure(FailureCode::UnsupportedEvidenceVersion));
        }
        let offset = input.u64()?;
        let length = input.u64()?;
        let wire_type = input.byte()?;
        let decoded = input.u64()?;
        let previous = input.array()?;
        input.finish()?;
        let cap = match wire_type {
            0 | 3 => CANONICAL_BYTES,
            2 | 4 => DELTA_BYTES,
            _ => return Err(failure(FailureCode::InvalidEvidence)),
        };
        let consistent = match wire_type {
            0 => Some(length) == decoded.checked_add(5),
            2 => Some(length) == decoded.checked_add(37),
            3 => length >= 9,
            4 => length >= 41,
            _ => false,
        };
        if !consistent
            || offset < 12
            || !(5..=FRAME_BYTES + 5).contains(&length)
            || offset.checked_add(length).is_none()
            || decoded > cap
        {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        Ok(Self {
            offset,
            length,
            wire_type,
            decoded,
            previous,
        })
    }
    /// Starting offset of the five-byte frame header.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }
    /// Encoded frame length, including its header.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }
    /// Exact wire entry type.
    #[must_use]
    pub const fn wire_type(&self) -> u8 {
        self.wire_type
    }
    /// Bounded decompressed payload length, before canonical validation.
    #[must_use]
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded
    }
    /// Preceding occurrence-page digest, or zero for the first frame.
    #[must_use]
    pub const fn previous(&self) -> Hash {
        self.previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn record_geometry_version_and_every_truncation_are_strict() {
        let mut value = [0; 58];
        value[0] = 1;
        value[1..9].copy_from_slice(&12_u64.to_le_bytes());
        value[9..17].copy_from_slice(&5_u64.to_le_bytes());
        assert_eq!(FrameRecord::from_bytes(&value).unwrap().decoded_bytes(), 0);
        for end in 0..58 {
            assert!(FrameRecord::from_bytes(&value[..end]).is_err());
        }
        value[17] = 1;
        assert_eq!(
            FrameRecord::from_bytes(&value).unwrap_err().code,
            FailureCode::InvalidEvidence
        );
        value[0] = 2;
        assert_eq!(
            FrameRecord::from_bytes(&value).unwrap_err().code,
            FailureCode::UnsupportedEvidenceVersion
        );
    }
}
