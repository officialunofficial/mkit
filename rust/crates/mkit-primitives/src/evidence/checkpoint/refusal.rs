//! Fixed-size content refusal state. Numeric tags are local checkpoint syntax.
use super::{Cursor, Failure, FailureCode, Output, invalid};
use crate::error::{BoundedDetail, Location};

#[derive(Debug, Clone, Copy)]
pub(crate) struct DeferredFailure {
    code: FailureCode,
    location: Location,
    detail: BoundedDetail,
}

const CODES: &[FailureCode] = &[
    FailureCode::UnexpectedEof,
    FailureCode::InvalidEntryType,
    FailureCode::TooManyObjects,
    FailureCode::PackfileTooLarge,
    FailureCode::ZstdEntryTruncated,
    FailureCode::DeltaEntryTruncated,
    FailureCode::NonStorableObject,
    FailureCode::TrailingData,
    FailureCode::DecompressionFailed,
    FailureCode::DecompressedSizeMismatch,
    FailureCode::DecompressionLimitExceeded,
    FailureCode::InvalidDelta,
    FailureCode::DeltaBaseMismatch,
    FailureCode::DeltaSizeMismatch,
    FailureCode::NonCanonicalObject,
    FailureCode::ObjectHashMismatch,
    FailureCode::DeltaChainTooDeep,
    FailureCode::ExternalBaseAbsent,
    FailureCode::ResourceLimit,
    FailureCode::UnsupportedCapability,
];

impl From<&Failure> for DeferredFailure {
    fn from(failure: &Failure) -> Self {
        Self {
            code: failure.code,
            location: failure.location,
            detail: failure.detail,
        }
    }
}
impl DeferredFailure {
    pub(crate) fn failure(self) -> Failure {
        Failure {
            code: self.code,
            location: self.location,
            detail: self.detail,
        }
    }
    pub(super) fn validate(self, len: u64, ordinal: u64) -> Result<(), Failure> {
        if !CODES.contains(&self.code)
            || self.location.offset.is_some_and(|n| n > len)
            || self.location.ordinal.is_some_and(|n| n > ordinal)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn optional_u64(c: &mut Cursor<'_, '_>) -> Result<Option<u64>, Failure> {
    match c.byte()? {
        0 => Ok(None),
        1 => Ok(Some(c.u64()?)),
        _ => Err(invalid()),
    }
}

pub(super) fn read(c: &mut Cursor<'_, '_>) -> Result<Option<DeferredFailure>, Failure> {
    match c.byte()? {
        0 => Ok(None),
        1 => {
            let code = *CODES.get(usize::from(c.byte()?)).ok_or_else(invalid)?;
            let location = Location {
                ordinal: optional_u64(c)?,
                offset: optional_u64(c)?,
            };
            let detail = match c.byte()? {
                0 => BoundedDetail::None,
                1 => BoundedDetail::Bounds {
                    expected: c.u64()?,
                    actual: c.u64()?,
                },
                _ => return Err(invalid()),
            };
            Ok(Some(DeferredFailure {
                code,
                location,
                detail,
            }))
        }
        _ => Err(invalid()),
    }
}

pub(super) fn encoded_len(value: Option<DeferredFailure>) -> u64 {
    1 + value.map_or(0, |v| {
        4 + u64::from(v.location.ordinal.is_some()) * 8
            + u64::from(v.location.offset.is_some()) * 8
            + if matches!(v.detail, BoundedDetail::Bounds { .. }) {
                16
            } else {
                0
            }
    })
}

pub(super) fn write(out: &mut Output, value: Option<DeferredFailure>) -> Result<(), Failure> {
    out.byte(u8::from(value.is_some()))?;
    if let Some(v) = value {
        let code = CODES
            .iter()
            .position(|code| *code == v.code)
            .ok_or_else(invalid)?;
        out.byte(u8::try_from(code).map_err(|_| invalid())?)?;
        for value in [v.location.ordinal, v.location.offset] {
            out.byte(u8::from(value.is_some()))?;
            if let Some(value) = value {
                out.u64(value)?;
            }
        }
        match v.detail {
            BoundedDetail::None => out.byte(0)?,
            BoundedDetail::Bounds { expected, actual } => {
                out.byte(1)?;
                out.u64(expected)?;
                out.u64(actual)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Budget;

    fn decode(bytes: &[u8]) -> Result<Option<DeferredFailure>, Failure> {
        let mut budget = Budget::new(1024, 1024);
        let mut cursor = Cursor::new(bytes, &mut budget);
        let result = read(&mut cursor)?;
        cursor.finish()?;
        Ok(result)
    }

    #[test]
    fn refusal_roundtrip_preserves_bounded_diagnostics_and_rejects_truncation() {
        let original = Failure {
            code: FailureCode::ExternalBaseAbsent,
            location: Location {
                ordinal: Some(4),
                offset: Some(100),
            },
            detail: BoundedDetail::Bounds {
                expected: 10,
                actual: 11,
            },
        };
        let value = Some(DeferredFailure::from(&original));
        let mut output = Output {
            bytes: Vec::new(),
            cap: 37,
            budget: Budget::new(1024, 1024),
        };
        write(&mut output, value).unwrap();
        assert_eq!(output.bytes.len() as u64, encoded_len(value));
        assert_eq!(decode(&output.bytes).unwrap().unwrap().failure(), original);
        for end in 0..output.bytes.len() {
            assert!(decode(&output.bytes[..end]).is_err());
        }
        let mut unknown = output.bytes.clone();
        unknown[1] = 255;
        assert_eq!(
            decode(&unknown).unwrap_err().code,
            FailureCode::InvalidCheckpoint
        );
        let mut invalid_flag = output.bytes.clone();
        invalid_flag[2] = 2;
        assert_eq!(
            decode(&invalid_flag).unwrap_err().code,
            FailureCode::InvalidCheckpoint
        );
        let mut trailing = output.bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode(&trailing).unwrap_err().code,
            FailureCode::TrailingData
        );
        let value = DeferredFailure::from(&original);
        assert!(value.validate(99, 4).is_err());
        assert!(value.validate(100, 3).is_err());
        assert!(value.validate(100, 4).is_ok());
        assert!(
            DeferredFailure::from(&super::super::failure(FailureCode::UnavailableInput))
                .validate(100, 4)
                .is_err()
        );
    }
}
