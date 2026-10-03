//! Incremental, bounded inspection of compressed delta length claims.
use super::PackError;
#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
use super::require_zstd_frame_magic;

/// Inspect a compressed delta header across arbitrarily split input chunks.
///
/// Feed only the zstd frame, without its pack/base/length prefixes. Each
/// block is processed incrementally. The Rust backend buffers at most 16 MiB
/// of encoded prefix and replays that prefix at most nine times; empty blocks
/// do not trigger replays. Decode windows are bounded to 8 MiB. Processing stops after the nine-byte
/// delta header, and does not validate the remaining frame or instructions.
/// Callers must still perform full budgeted decoding and verification.
#[non_exhaustive]
pub struct DeltaHeaderProbe {
    decoder: Decoder,
    header: [u8; 9],
    filled: usize,
}
impl std::fmt::Debug for DeltaHeaderProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeltaHeaderProbe")
            .field("filled", &self.filled)
            .finish_non_exhaustive()
    }
}
impl DeltaHeaderProbe {
    /// Start an empty probe using the configured compression backend.
    /// # Errors
    /// Unsupported compression or failure to initialize the decoder.
    pub fn new() -> Result<Self, PackError> {
        #[cfg(feature = "pack-ruzstd")]
        let decoder = Decoder::new();
        #[cfg(not(feature = "pack-ruzstd"))]
        let decoder = Decoder::new()?;
        Ok(Self {
            decoder,
            header: [0; 9],
            filled: 0,
        })
    }
    /// Feed the next compressed bytes. `Some((base_length, result_length))`
    /// reports both lengths in bytes; `None` means the header is not yet available.
    /// Subsequent calls return the same lengths without decoding more input.
    /// # Errors
    /// Malformed compression, an excessive window, or an unsupported delta version.
    /// The Rust backend also refuses encoded prefixes larger than 16 MiB.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<(u32, u32)>, PackError> {
        if self.filled < self.header.len() {
            self.filled += self.decoder.push(bytes, &mut self.header[self.filled..])?;
        }
        if self.filled != self.header.len() {
            return Ok(None);
        }
        if self.header[0] != crate::delta::STREAM_VERSION {
            return Err(PackError::DeltaApply(
                crate::MkitError::UnsupportedObjectVersion,
            ));
        }
        Ok(Some((
            u32::from_le_bytes(
                self.header[1..5]
                    .try_into()
                    .map_err(|_| PackError::UnexpectedEof)?,
            ),
            u32::from_le_bytes(
                self.header[5..9]
                    .try_into()
                    .map_err(|_| PackError::UnexpectedEof)?,
            ),
        )))
    }
}
fn error(e: impl std::fmt::Display) -> PackError {
    PackError::ZstdDecompress(e.to_string())
}

#[cfg(feature = "pack-ruzstd")]
struct Decoder {
    frame: ruzstd::decoding::FrameDecoder,
    buffer: Vec<u8>,
    stage: Stage,
    checksum: bool,
    prefix: Vec<u8>,
    copied: usize,
    replays: u8,
}
#[cfg(feature = "pack-ruzstd")]
enum Stage {
    Header,
    BlockHeader,
    Block(usize),
    Finished,
}
#[cfg(feature = "pack-ruzstd")]
impl Decoder {
    fn new() -> Self {
        let mut frame = ruzstd::decoding::FrameDecoder::new();
        frame.set_max_window_size(8 << 20);
        Self {
            frame,
            buffer: Vec::new(),
            stage: Stage::Header,
            checksum: false,
            prefix: Vec::new(),
            copied: 0,
            replays: 0,
        }
    }
    fn need(&self) -> usize {
        match self.stage {
            Stage::Header if self.buffer.len() < 5 => 5,
            Stage::Header => {
                let descriptor = self.buffer[4];
                let single = descriptor & 32 != 0;
                let content = match descriptor >> 6 {
                    0 => usize::from(single),
                    1 => 2,
                    2 => 4,
                    _ => 8,
                };
                5 + usize::from(!single) + [0, 1, 2, 4][usize::from(descriptor & 3)] + content
            }
            Stage::BlockHeader => 3,
            Stage::Block(n) => n,
            Stage::Finished => 0,
        }
    }
    fn advance(&mut self, out: &mut [u8]) -> Result<usize, PackError> {
        match self.stage {
            Stage::Header => {
                require_zstd_frame_magic(&self.buffer)?;
                self.checksum = self.buffer[4] & 4 != 0;
                self.frame.init(self.buffer.as_slice()).map_err(error)?;
                // Complete-prefix replays have no content-size claim or checksum.
                // Keep dictionary identity, and allow the original admitted window.
                let descriptor = self.buffer[4];
                let dictionary_start = 5 + usize::from(descriptor & 32 == 0);
                let dictionary_bytes = [0, 1, 2, 4][usize::from(descriptor & 3)];
                self.prefix.extend_from_slice(&self.buffer[..4]);
                self.prefix.extend_from_slice(&[descriptor & 3, 104]);
                self.prefix.extend_from_slice(
                    &self.buffer[dictionary_start..dictionary_start + dictionary_bytes],
                );
                self.buffer.clear();
                self.stage = Stage::BlockHeader;
            }
            Stage::BlockHeader => {
                let claim = u32::from_le_bytes([self.buffer[0], self.buffer[1], self.buffer[2], 0]);
                let size = usize::try_from(claim >> 3).map_err(error)?;
                let kind = (claim >> 1) & 3;
                if size > 128 * 1024 || kind == 3 {
                    return Err(error("invalid zstd block geometry"));
                }
                let payload = if kind == 1 { 1 } else { size };
                self.stage = Stage::Block(3 + payload);
            }
            Stage::Block(_) => {
                let last = self.buffer[0] & 1 != 0;
                let block_start = self.prefix.len();
                if self.buffer.len() > (16 << 20) - self.prefix.len() {
                    return Err(PackError::PackfileTooLarge);
                }
                self.prefix.extend_from_slice(&self.buffer);
                if last && self.checksum {
                    // Prefix inspection does not validate the trailing checksum.
                    self.buffer.extend_from_slice(&[0; 4]);
                }
                let produced_output = self.decode_block(last)?;
                self.buffer.clear();
                self.stage = if last {
                    Stage::Finished
                } else {
                    Stage::BlockHeader
                };
                if produced_output || last {
                    return self.inspect_prefix(block_start, out);
                }
            }
            Stage::Finished => return Ok(0),
        }
        Ok(0)
    }
    fn decode_block(&mut self, last: bool) -> Result<bool, PackError> {
        use ruzstd::decoding::errors::{BlockHeaderReadError, FrameDecoderError};
        let before = self.frame.blocks_decoded();
        let mut input = BlockInput {
            bytes: &self.buffer,
            consumed: 0,
            boundary: false,
        };
        let result = self.frame.decode_blocks(
            &mut input,
            ruzstd::decoding::BlockDecodingStrategy::UptoBytes(1),
        );
        match result {
            Ok(_) => Ok(true),
            Err(FrameDecoderError::FailedToReadBlockHeader(BlockHeaderReadError::ReadError(e)))
                if !last
                    && e.kind() == std::io::ErrorKind::UnexpectedEof
                    && input.boundary
                    && input.consumed == self.buffer.len()
                    && self.frame.blocks_decoded() == before + 1 =>
            {
                // UptoBytes(1) attempted the next header only because this
                // complete block produced no bytes. Its history is intact.
                Ok(false)
            }
            Err(e) => Err(error(e)),
        }
    }
    fn inspect_prefix(&mut self, block_start: usize, out: &mut [u8]) -> Result<usize, PackError> {
        use std::io::Read as _;
        self.replays = self
            .replays
            .checked_add(1)
            .filter(|n| *n <= 9)
            .ok_or(PackError::PackfileTooLarge)?;
        // A fresh decoder sees a complete frame ending at the current block.
        // The live decoder never finishes early or drains retained history.
        let original = self.prefix[block_start];
        self.prefix[block_start] |= 1;
        let result = (|| {
            let mut frame = ruzstd::decoding::FrameDecoder::new();
            frame.set_max_window_size(8 << 20);
            let mut input = self.prefix.as_slice();
            frame.init(&mut input).map_err(error)?;
            frame
                .decode_blocks(&mut input, ruzstd::decoding::BlockDecodingStrategy::All)
                .map_err(error)?;
            let mut header = [0; 9];
            let n = frame.read(&mut header).map_err(error)?;
            if n < self.copied {
                return Err(error("inconsistent decoded prefix"));
            }
            let written = (n - self.copied).min(out.len());
            out[..written].copy_from_slice(&header[self.copied..self.copied + written]);
            self.copied += written;
            Ok(written)
        })();
        self.prefix[block_start] = original;
        result
    }
    fn push(&mut self, mut bytes: &[u8], out: &mut [u8]) -> Result<usize, PackError> {
        let mut written = 0;
        while !bytes.is_empty() && written < out.len() && !matches!(self.stage, Stage::Finished) {
            let need = self.need();
            let take = (need - self.buffer.len()).min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() < need {
                continue;
            }
            // Five bytes reveal a variable-size frame header, not necessarily all of it.
            if matches!(self.stage, Stage::Header) && self.buffer.len() < self.need() {
                continue;
            }
            written += self.advance(&mut out[written..])?;
        }
        // A zero-sized block can complete exactly at a chunk boundary.
        if matches!(self.stage, Stage::Block(n) if self.buffer.len() == n) && written < out.len() {
            written += self.advance(&mut out[written..])?;
        }
        Ok(written)
    }
}

#[cfg(feature = "pack-ruzstd")]
struct BlockInput<'a> {
    bytes: &'a [u8],
    consumed: usize,
    boundary: bool,
}
#[cfg(feature = "pack-ruzstd")]
impl std::io::Read for BlockInput<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.bytes.is_empty() && !out.is_empty() {
            self.boundary = true;
        }
        let n = self.bytes.len().min(out.len());
        out[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        self.consumed += n;
        Ok(n)
    }
}

#[cfg(all(feature = "pack-zstd", not(feature = "pack-ruzstd")))]
struct Decoder {
    frame: zstd::stream::raw::Decoder<'static>,
    magic: Vec<u8>,
}
#[cfg(all(feature = "pack-zstd", not(feature = "pack-ruzstd")))]
impl Decoder {
    fn new() -> Result<Self, PackError> {
        let mut frame = zstd::stream::raw::Decoder::new().map_err(error)?;
        frame
            .set_parameter(zstd::stream::raw::DParameter::WindowLogMax(23))
            .map_err(error)?;
        Ok(Self {
            frame,
            magic: Vec::new(),
        })
    }
    fn feed(&mut self, mut bytes: &[u8], out: &mut [u8]) -> Result<usize, PackError> {
        use zstd::stream::raw::Operation as _;
        let mut written = 0;
        while written < out.len() {
            let status = self
                .frame
                .run_on_buffers(bytes, &mut out[written..])
                .map_err(error)?;
            written += status.bytes_written;
            bytes = &bytes[status.bytes_read..];
            if status.bytes_read == 0 && status.bytes_written == 0 {
                break;
            }
        }
        Ok(written)
    }
    fn push(&mut self, mut bytes: &[u8], out: &mut [u8]) -> Result<usize, PackError> {
        let mut written = 0;
        if self.magic.len() < 4 {
            let take = (4 - self.magic.len()).min(bytes.len());
            self.magic.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.magic.len() < 4 {
                return Ok(0);
            }
            require_zstd_frame_magic(&self.magic)?;
            let magic: [u8; 4] = self
                .magic
                .as_slice()
                .try_into()
                .map_err(|_| PackError::UnexpectedEof)?;
            written += self.feed(&magic, out)?;
        }
        written += self.feed(bytes, &mut out[written..])?;
        Ok(written)
    }
}
#[cfg(not(any(feature = "pack-zstd", feature = "pack-ruzstd")))]
struct Decoder;
#[cfg(not(any(feature = "pack-zstd", feature = "pack-ruzstd")))]
impl Decoder {
    fn new() -> Result<Self, PackError> {
        Err(error("zstd support is disabled"))
    }
    #[expect(
        clippy::unused_self,
        reason = "The disabled backend retains the streaming decoder interface."
    )]
    fn push(&mut self, _: &[u8], _: &mut [u8]) -> Result<usize, PackError> {
        Self::new().map(|_| 0)
    }
}

#[cfg(all(test, feature = "pack-ruzstd"))]
mod tests {
    use super::DeltaHeaderProbe;

    #[test]
    fn incremental_delta_probe_skips_zero_output_replays() {
        let mut probe = DeltaHeaderProbe::new().unwrap();
        probe.push(&[0x28, 0xb5, 0x2f, 0xfd, 0, 104]).unwrap();
        let mut header = vec![crate::delta::STREAM_VERSION];
        header.extend_from_slice(&512_u32.to_le_bytes());
        header.extend_from_slice(&1_048_587_u32.to_le_bytes());
        for byte in header {
            // Raw and compressed empty blocks can surround every header byte.
            for _ in 0..100 {
                probe.push(&[0, 0, 0]).unwrap();
                probe.push(&[20, 0, 0, 0, 0]).unwrap();
            }
            probe.push(&[8, 0, 0, byte]).unwrap();
        }
        assert_eq!(probe.push(&[]).unwrap(), Some((512, 1_048_587)));
        assert_eq!(probe.decoder.replays, 9);
    }
}
