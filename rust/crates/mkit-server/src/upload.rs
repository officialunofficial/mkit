//! `UploadPack` stream framing (SPEC-TRANSPORT-CONNECT §6.1,
//! SPEC-TRANSPORT §4.2).
//!
//! [`UploadValidator`] checks framing only: a 32-byte `pack_id`, a declared
//! size within the binding's cap, chunks that repeat the header's `pack_id`
//! at contiguous offsets without overrunning it, a bounded chunk count, and a
//! `last` chunk at exactly the declared size. It never hashes: the pack sink
//! verifies BLAKE3 before the pack becomes visible, and hashing here too
//! would double the CPU cost of a 4 GiB upload.
//!
//! The canonical copy of `mkit serve`'s `UploadDrain`,
//! `mkit-transport-connect` 0.4's `drain_upload` and the chunk loop of
//! `vcs-worker`'s `upload_pack`. Each [`UploadError`] keeps today's text for
//! both wire families: [`UploadError::ssh_message`] is `mkit serve`'s and
//! [`UploadError::connect_message`] is `mkit-transport-connect`'s (the server
//! it had until WP-M0-15, behind `mkit serve --http`). The old copies are
//! gone: `mkit serve`'s in WP-M0-13, `vcs-worker`'s in WP-M0-17.

use std::borrow::Cow;

use mkit_core::protocol::PackKey;

use crate::error::{Code, ServerError};

/// Caps a binding applies to one upload. Each binding supplies its own:
/// the native Connect server uses `PACK_BODY_LIMIT` and no chunk cap,
/// `mkit serve` its per-connection byte and frame caps, and the Workers
/// server its 64 MiB buffer cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadLimits {
    /// Largest `total_bytes` a header may declare.
    pub max_total_bytes: u64,
    /// Most chunks accepted before the `last` one, inclusive.
    pub max_chunks: u32,
}

/// Where an upload stands after a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Progress {
    /// The `last` chunk arrived and the byte count matches the header.
    pub complete: bool,
}

/// A completely framed upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadDone {
    /// The pack id the header declared.
    pub key: PackKey,
    /// Bytes received, equal to the declared `total_bytes`.
    pub total: u64,
}

/// Why an upload stream was rejected.
///
/// The stream-shape variants ([`Self::HeaderMissing`],
/// [`Self::UnexpectedMessage`]) and [`Self::DigestMismatch`] are raised by
/// the binding, which decodes messages and owns the sink; the validator
/// raises every other variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UploadError {
    /// The stream did not start with a header. `stream_empty` when it ended
    /// before any message.
    HeaderMissing {
        /// No message arrived at all.
        stream_empty: bool,
    },
    /// A message after the header was not a chunk. `header` when it was a
    /// second header, otherwise a message with no body.
    UnexpectedMessage {
        /// The message was a second header.
        header: bool,
    },
    /// A `pack_id` that is absent (`len: None`) or not 32 bytes long.
    /// `chunk` when it was a chunk's rather than the header's.
    BadPackId {
        /// The id came from a chunk.
        chunk: bool,
        /// Its length, or `None` when absent.
        len: Option<usize>,
    },
    /// A chunk's `pack_id` differs from the header's.
    PackIdMismatch,
    /// The header has no `total_bytes`.
    TotalMissing,
    /// The declared `total_bytes` is over the binding's cap.
    TotalTooLarge {
        /// Declared size.
        total: u64,
        /// The binding's cap.
        cap: u64,
    },
    /// More chunks than the binding's cap arrived without `last`.
    TooManyChunks,
    /// A chunk has no `offset`.
    OffsetMissing,
    /// A chunk's `offset` is not the running byte count.
    OffsetGap {
        /// The chunk's offset.
        offset: u64,
        /// The running byte count.
        expected: u64,
    },
    /// The running byte count overflowed `u64`.
    ByteCountOverflow,
    /// The chunks carry more bytes than the header declared.
    Overrun,
    /// A chunk arrived after the `last` one.
    AfterLast,
    /// The stream ended without a `last` chunk.
    NoLast,
    /// The `last` chunk arrived before the declared byte count.
    LengthMismatch {
        /// Bytes received.
        received: u64,
        /// Bytes the header declared.
        declared: u64,
    },
    /// The received bytes do not hash to the header's `pack_id`.
    DigestMismatch,
}

impl UploadError {
    /// The Connect-side code: [`Code::ResourceExhausted`] for an oversized
    /// declared total, [`Code::InvalidArgument`] for everything else.
    #[must_use]
    pub const fn code(self) -> Code {
        match self {
            Self::TotalTooLarge { .. } => Code::ResourceExhausted,
            _ => Code::InvalidArgument,
        }
    }

    /// `mkit serve`'s message, verbatim. Every one is sent with
    /// `ERROR_CODE_INVALID_REQUEST`; the ssh binding maps codes itself.
    #[must_use]
    pub const fn ssh_message(self) -> &'static str {
        match self {
            Self::HeaderMissing { .. } => "PackChunk arrived without UploadPack header",
            Self::UnexpectedMessage { .. } => "expected PackChunk after UploadPack",
            Self::BadPackId { len: None, .. } => "pack_id missing",
            Self::BadPackId { len: Some(_), .. } => "pack_id must be 32 bytes",
            Self::PackIdMismatch => "PackChunk.pack_id does not match UploadPack",
            Self::TotalMissing => "UploadPack.total_bytes is required",
            Self::TotalTooLarge { .. } => "UploadPack.total_bytes exceeds server cap",
            Self::TooManyChunks => "too many PackChunk frames before last=true",
            Self::OffsetMissing => "PackChunk.offset is required",
            Self::OffsetGap { .. } => "PackChunk.offset is not the expected next offset",
            Self::ByteCountOverflow => "PackChunk byte count overflow",
            Self::Overrun => "PackChunk data exceeds declared total_bytes",
            // New: `mkit serve` stops reading at `last`, so it never sent this.
            Self::AfterLast => "PackChunk after last=true",
            // `mkit serve` reports a stream that ends early as a failed read.
            Self::NoLast => "pack chunk read failed",
            Self::LengthMismatch { .. } => "PackChunk stream ended before declared total_bytes",
            Self::DigestMismatch => "uploaded pack bytes do not match UploadPack.pack_id",
        }
    }

    /// `mkit-transport-connect`'s message, verbatim. `TotalMissing`,
    /// `OffsetMissing`, `TooManyChunks` and `AfterLast` are new: that server
    /// reads an absent `total_bytes` or `offset` as 0, has no chunk cap and
    /// stops reading at `last`.
    #[must_use]
    pub fn connect_message(self) -> Cow<'static, str> {
        Cow::Borrowed(match self {
            Self::HeaderMissing { stream_empty: true } => "UploadPack: empty request stream",
            Self::HeaderMissing {
                stream_empty: false,
            } => "UploadPack: first message MUST be `header`",
            Self::UnexpectedMessage { header: true } => "UploadPack: saw a second `header` message",
            Self::UnexpectedMessage { header: false } => {
                "UploadPack: message with neither `header` nor `chunk` set"
            }
            Self::BadPackId { chunk: false, len } => {
                return format!(
                    "expected a 32-byte digest, got {} bytes",
                    len.unwrap_or_default()
                )
                .into();
            }
            Self::BadPackId { chunk: true, .. } | Self::PackIdMismatch => {
                "UploadPack: chunk.pack_id does not match header.pack_id"
            }
            Self::TotalMissing => "UploadPack: header.total_bytes is required",
            Self::TotalTooLarge { total, cap } => {
                return format!("UploadPack: total_bytes {total} exceeds the {cap}-byte cap")
                    .into();
            }
            Self::TooManyChunks => {
                "UploadPack: too many `chunk` messages before `chunk.last = true`"
            }
            Self::OffsetMissing => "UploadPack: chunk.offset is required",
            Self::OffsetGap { offset, expected } => {
                return format!(
                    "UploadPack: chunk.offset {offset} does not match the expected offset {expected}"
                )
                .into();
            }
            Self::ByteCountOverflow | Self::Overrun => {
                "UploadPack: received bytes exceed header.total_bytes"
            }
            Self::AfterLast => "UploadPack: message after `chunk.last = true`",
            Self::NoLast => "UploadPack: stream ended without a `chunk.last = true` message",
            Self::LengthMismatch { received, declared } => {
                return format!(
                    "UploadPack: received {received} bytes, header declared {declared}"
                )
                .into();
            }
            Self::DigestMismatch => {
                "UploadPack: BLAKE3(received bytes) does not equal header.pack_id"
            }
        })
    }
}

impl From<UploadError> for ServerError {
    /// The Connect code and message.
    fn from(err: UploadError) -> Self {
        Self::new(err.code(), err.connect_message())
    }
}

/// Validates one `UploadPack` stream's framing, chunk by chunk, without
/// buffering or hashing. After any error the stream is dead: every later
/// call returns that same error.
#[derive(Debug, Clone)]
pub struct UploadValidator {
    key: PackKey,
    declared: u64,
    received: u64,
    chunks: u32,
    max_chunks: u32,
    complete: bool,
    failed: Option<UploadError>,
}

impl UploadValidator {
    /// Start validating from the header's `pack_id` and `total_bytes`
    /// (`None` when absent).
    ///
    /// # Errors
    /// [`UploadError::BadPackId`], [`UploadError::TotalMissing`] or
    /// [`UploadError::TotalTooLarge`].
    pub fn new(
        pack_id: Option<&[u8]>,
        total_bytes: Option<u64>,
        limits: UploadLimits,
    ) -> Result<Self, UploadError> {
        let key = pack_key(pack_id, false)?;
        let declared = total_bytes.ok_or(UploadError::TotalMissing)?;
        if declared > limits.max_total_bytes {
            return Err(UploadError::TotalTooLarge {
                total: declared,
                cap: limits.max_total_bytes,
            });
        }
        Ok(Self {
            key,
            declared,
            received: 0,
            chunks: 0,
            max_chunks: limits.max_chunks,
            complete: false,
            failed: None,
        })
    }

    /// Account for one chunk carrying `data_len` bytes.
    ///
    /// # Errors
    /// [`UploadError::AfterLast`], [`UploadError::TooManyChunks`],
    /// [`UploadError::BadPackId`], [`UploadError::PackIdMismatch`],
    /// [`UploadError::OffsetMissing`], [`UploadError::OffsetGap`],
    /// [`UploadError::ByteCountOverflow`], [`UploadError::Overrun`] or, on the
    /// `last` chunk, [`UploadError::LengthMismatch`]. After any error, this
    /// and every later call return that same error, and nothing the failed
    /// chunk carried is counted.
    pub fn push(
        &mut self,
        chunk_pack_id: Option<&[u8]>,
        offset: Option<u64>,
        data_len: usize,
        last: bool,
    ) -> Result<Progress, UploadError> {
        if let Some(err) = self.failed {
            return Err(err);
        }
        let result = self.accept(chunk_pack_id, offset, data_len, last);
        if let Err(err) = result {
            self.failed = Some(err);
        }
        result
    }

    fn accept(
        &mut self,
        chunk_pack_id: Option<&[u8]>,
        offset: Option<u64>,
        data_len: usize,
        last: bool,
    ) -> Result<Progress, UploadError> {
        if self.complete {
            return Err(UploadError::AfterLast);
        }
        self.chunks = self.chunks.saturating_add(1);
        if self.chunks > self.max_chunks {
            return Err(UploadError::TooManyChunks);
        }
        if pack_key(chunk_pack_id, true)? != self.key {
            return Err(UploadError::PackIdMismatch);
        }
        let offset = offset.ok_or(UploadError::OffsetMissing)?;
        if offset != self.received {
            return Err(UploadError::OffsetGap {
                offset,
                expected: self.received,
            });
        }
        let received = u64::try_from(data_len)
            .ok()
            .and_then(|len| self.received.checked_add(len))
            .ok_or(UploadError::ByteCountOverflow)?;
        if received > self.declared {
            return Err(UploadError::Overrun);
        }
        if last && received != self.declared {
            return Err(UploadError::LengthMismatch {
                received,
                declared: self.declared,
            });
        }
        self.received = received;
        self.complete = last;
        Ok(Progress { complete: last })
    }

    /// End of stream.
    ///
    /// # Errors
    /// The error that killed the stream, if any; otherwise
    /// [`UploadError::NoLast`] if the `last` chunk never arrived.
    pub fn finish(self) -> Result<UploadDone, UploadError> {
        if let Some(err) = self.failed {
            return Err(err);
        }
        if !self.complete {
            return Err(UploadError::NoLast);
        }
        Ok(UploadDone {
            key: self.key,
            total: self.received,
        })
    }

    /// The pack id the header declared.
    #[must_use]
    pub const fn key(&self) -> PackKey {
        self.key
    }

    /// The `total_bytes` the header declared.
    #[must_use]
    pub const fn declared(&self) -> u64 {
        self.declared
    }

    /// Bytes accepted so far.
    #[must_use]
    pub const fn received(&self) -> u64 {
        self.received
    }
}

fn pack_key(id: Option<&[u8]>, chunk: bool) -> Result<PackKey, UploadError> {
    let id = id.ok_or(UploadError::BadPackId { chunk, len: None })?;
    <[u8; 32]>::try_from(id)
        .map(PackKey::new)
        .map_err(|_| UploadError::BadPackId {
            chunk,
            len: Some(id.len()),
        })
}

#[cfg(test)]
mod tests;
