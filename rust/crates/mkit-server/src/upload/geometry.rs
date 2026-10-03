//! Bounded indexed-entry preflight before upload chunks reach the sink.
use crate::ServerError;
use crate::indexed::geometry::{CANONICAL_BYTES, DELTA_STREAM_BYTES, FRAME_BYTES};

pub(crate) const OVERSIZED_ENTRY_MESSAGE: &str =
    "canonical entry exceeds indexed limit of 1048586 bytes; split very large flat directories";
fn oversized() -> ServerError {
    ServerError::invalid_argument(OVERSIZED_ENTRY_MESSAGE)
}
fn malformed() -> ServerError {
    ServerError::invalid_argument("invalid indexed pack entry framing")
}

#[derive(Debug)]
enum Stage {
    Header,
    Frame,
    Prefix { kind: u8, payload: usize },
    CompressedDelta { payload: usize },
    Skip(usize),
    Done,
}
#[derive(Debug)]
pub(crate) struct GeometryCheck {
    stage: Stage,
    buffer: Vec<u8>,
    entries: u32,
    version: u32,
}
impl Default for GeometryCheck {
    fn default() -> Self {
        Self {
            stage: Stage::Header,
            buffer: Vec::new(),
            entries: 0,
            version: 0,
        }
    }
}
impl GeometryCheck {
    pub(crate) fn push(&mut self, mut bytes: &[u8]) -> Result<(), ServerError> {
        while !bytes.is_empty() {
            if let Stage::Skip(left) = &mut self.stage {
                let take = (*left).min(bytes.len());
                *left -= take;
                bytes = &bytes[take..];
                if *left == 0 {
                    self.next_entry();
                }
                continue;
            }
            let need = match self.stage {
                Stage::Header => 12,
                Stage::Frame => 5,
                Stage::Prefix { kind: 2, .. } => 41,
                Stage::Prefix { kind: 3, .. } => 4,
                Stage::Prefix { kind: 4, .. } => 36,
                Stage::CompressedDelta { payload } => payload,
                Stage::Done => return Ok(()),
                _ => return Err(malformed()),
            };
            let take = (need - self.buffer.len()).min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() < need {
                continue;
            }
            self.advance()?;
        }
        Ok(())
    }
    fn next_entry(&mut self) {
        self.buffer.clear();
        self.stage = if self.entries == 0 {
            Stage::Done
        } else {
            Stage::Frame
        };
    }
    fn skip(&mut self, bytes: usize) {
        self.stage = Stage::Skip(bytes);
        self.buffer.clear();
        if bytes == 0 {
            self.next_entry();
        }
    }
    fn advance(&mut self) -> Result<(), ServerError> {
        match self.stage {
            Stage::Header => {
                // Other upload types retain their existing advance-time validation.
                if &self.buffer[..4] != b"MKIT" {
                    self.stage = Stage::Done;
                    return Ok(());
                }
                self.version =
                    u32::from_le_bytes(self.buffer[4..8].try_into().map_err(|_| malformed())?);
                if !matches!(self.version, 1 | 2) {
                    self.stage = Stage::Done;
                    return Ok(());
                }
                self.entries =
                    u32::from_le_bytes(self.buffer[8..12].try_into().map_err(|_| malformed())?);
                self.next_entry();
            }
            Stage::Frame => {
                let kind = self.buffer[0];
                let payload =
                    u32::from_le_bytes(self.buffer[1..5].try_into().map_err(|_| malformed())?)
                        as usize;
                if payload as u64 + 5 > FRAME_BYTES {
                    return Err(ServerError::invalid_argument(
                        "encoded entry exceeds indexed frame limit",
                    ));
                }
                self.entries -= 1;
                if kind == 0 {
                    if payload as u64 > CANONICAL_BYTES {
                        return Err(oversized());
                    }
                    self.skip(payload);
                } else {
                    let prefix = match kind {
                        2 => 41,
                        3 if self.version == 2 => 4,
                        4 if self.version == 2 => 36,
                        _ => {
                            self.skip(payload);
                            return Ok(());
                        }
                    };
                    if payload < prefix {
                        self.skip(payload);
                        return Ok(());
                    }
                    self.stage = Stage::Prefix { kind, payload };
                    self.buffer.clear();
                }
            }
            Stage::Prefix { kind, payload } => {
                let claim = match kind {
                    2 => {
                        u32::from_le_bytes(self.buffer[37..41].try_into().map_err(|_| malformed())?)
                    }
                    3 => u32::from_le_bytes(self.buffer[..4].try_into().map_err(|_| malformed())?),
                    4 => {
                        u32::from_le_bytes(self.buffer[32..36].try_into().map_err(|_| malformed())?)
                    }
                    _ => return Err(malformed()),
                };
                if u64::from(claim)
                    > if kind == 4 {
                        DELTA_STREAM_BYTES
                    } else {
                        CANONICAL_BYTES
                    }
                {
                    return Err(oversized());
                }
                if kind == 4 {
                    self.stage = Stage::CompressedDelta { payload };
                } else {
                    self.skip(payload - self.buffer.len());
                }
            }
            Stage::CompressedDelta { .. } => {
                // Geometry preflight does not replace indexed pack validation:
                // malformed or unsupported compression remains an advance error.
                let result = mkit_core::pack::peek_delta_header(&self.buffer[36..]);
                if result.is_ok_and(|(_, result)| u64::from(result) > CANONICAL_BYTES) {
                    return Err(oversized());
                }
                self.next_entry();
            }
            _ => return Err(malformed()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = b"MKIT".to_vec();
        bytes.extend_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }
    #[test]
    fn compressed_raw_and_delta_claims_are_checked_across_chunk_boundaries() {
        let oversized = u32::try_from(CANONICAL_BYTES + 1).unwrap();
        let mut delta = vec![0; 32];
        delta.push(1);
        delta.extend_from_slice(&0_u32.to_le_bytes());
        delta.extend_from_slice(&oversized.to_le_bytes());
        for bytes in [entry(3, &oversized.to_le_bytes()), entry(2, &delta)] {
            for chunk in [1, 3, bytes.len()] {
                let mut check = GeometryCheck::default();
                let error = bytes
                    .chunks(chunk)
                    .try_for_each(|part| check.push(part))
                    .unwrap_err();
                assert_eq!(error.code(), crate::Code::InvalidArgument);
                assert_eq!(error.public_message(), OVERSIZED_ENTRY_MESSAGE);
            }
        }
    }
    #[test]
    fn writer_delta_result_claim_is_refused_without_resolving_the_base() {
        let mut stream = vec![1];
        stream.extend_from_slice(&0_u32.to_le_bytes());
        stream.extend_from_slice(&(u32::try_from(CANONICAL_BYTES + 1).unwrap()).to_le_bytes());
        stream.extend_from_slice(&[0; 512]);
        let mut writer = mkit_core::pack::PackWriter::new();
        writer.push_delta(&[9; 32], &stream).unwrap();
        let bytes = writer.finish().unwrap();
        for chunk in [1, 7, bytes.len()] {
            let mut check = GeometryCheck::default();
            let error = bytes
                .chunks(chunk)
                .try_for_each(|part| check.push(part))
                .unwrap_err();
            assert_eq!(error.public_message(), OVERSIZED_ENTRY_MESSAGE);
        }
    }
    #[test]
    fn unrelated_pack_validation_remains_at_advance() {
        for bytes in [entry(1, &[0; 3]), entry(2, &[0; 32]), entry(4, &[0; 40])] {
            GeometryCheck::default().push(&bytes).unwrap();
        }
        let mut unsupported = entry(0, &[]);
        unsupported[4..8].copy_from_slice(&99_u32.to_le_bytes());
        GeometryCheck::default().push(&unsupported).unwrap();
    }
    #[test]
    fn canonical_limit_is_inclusive_and_multiple_entry_boundaries_are_preserved() {
        let mut bytes = entry(0, &vec![0; usize::try_from(CANONICAL_BYTES).unwrap()]);
        bytes[8..12].copy_from_slice(&2_u32.to_le_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&(u32::try_from(CANONICAL_BYTES + 1).unwrap()).to_le_bytes());
        let mut check = GeometryCheck::default();
        check.push(&bytes[..bytes.len() - 5]).unwrap();
        assert_eq!(
            check
                .push(&bytes[bytes.len() - 5..])
                .unwrap_err()
                .public_message(),
            OVERSIZED_ENTRY_MESSAGE
        );
    }
}
