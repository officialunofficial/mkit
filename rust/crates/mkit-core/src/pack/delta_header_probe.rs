//! Incremental, bounded inspection of compressed delta length claims.
use super::PackError;
#[cfg(any(feature = "pack-zstd", feature = "pack-ruzstd"))]
use super::require_zstd_frame_magic;

/// Inspect a compressed delta header across arbitrarily split input chunks.
///
/// Feed only the zstd frame, without its pack/base/length prefixes. Each
/// compressed block is processed once; at most one 128-KiB block is buffered.
/// The decode window is bounded to 8 MiB. Processing stops after the nine-byte
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
    /// Feed the next compressed bytes and return lengths once available.
    /// Subsequent calls return the same lengths without decoding more input.
    /// # Errors
    /// Malformed compression, an excessive window, or an unsupported delta version.
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
        use std::io::Read as _;
        match self.stage {
            Stage::Header => {
                require_zstd_frame_magic(&self.buffer)?;
                self.checksum = self.buffer[4] & 4 != 0;
                self.frame.init(self.buffer.as_slice()).map_err(error)?;
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
                if self.buffer[0] & 1 != 0 && self.checksum {
                    // Prefix inspection must not wait for or validate a trailing checksum.
                    // FrameDecoder consumes four bytes here without verifying their value.
                    self.buffer.extend_from_slice(&[0; 4]);
                }
                self.frame
                    .decode_blocks(
                        self.buffer.as_slice(),
                        ruzstd::decoding::BlockDecodingStrategy::UptoBlocks(1),
                    )
                    .map_err(error)?;
                self.buffer.clear();
                self.stage = if self.frame.is_finished() {
                    Stage::Finished
                } else {
                    Stage::BlockHeader
                };
                return self.frame.read(out).map_err(error);
            }
            Stage::Finished => return Ok(0),
        }
        Ok(0)
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
