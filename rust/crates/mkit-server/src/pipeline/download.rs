//! `DownloadPack` as a stream of chunks (SPEC-TRANSPORT-CONNECT §6.2).
//!
//! The chunks follow [`chunk_plan`]: every chunk but the last is exactly
//! `download_chunk_max` bytes (800 KiB by default, overview Q17), and an
//! empty pack is one empty `last` chunk. The stream re-chunks the blob
//! store's body as it arrives, holding at most one chunk plus one store
//! piece, never the pack.

use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;

use super::outcome::Outcome;
use crate::download::{ChunkSpan, chunk_plan};
use crate::error::ServerError;
use crate::rt::BoxStream;
use crate::storage_error::{StorageOp, describe_and_map};
use crate::store::{BlobBody, StoreError};

/// One `PackChunk` of a download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadChunk {
    /// Byte offset of `data` in the pack.
    pub offset: u64,
    /// The bytes.
    pub data: Bytes,
    /// Whether this is the final chunk.
    pub last: bool,
}

/// A pack download: its length, for the header message, then its chunks.
/// The stream owns its data (`'static`), so a binding can hand it to
/// Connect's `Response::stream_ok` without borrowing the pipeline.
pub struct DownloadStream {
    /// The pack's length in bytes.
    pub total_bytes: u64,
    /// The chunks, contiguous from offset 0; only the final one is `last`.
    pub chunks: BoxStream<'static, Result<DownloadChunk, ServerError>>,
}

impl fmt::Debug for DownloadStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownloadStream")
            .field("total_bytes", &self.total_bytes)
            .finish_non_exhaustive()
    }
}

impl DownloadStream {
    /// Chunk `body` into pieces of at most `max` bytes; `outcome` records
    /// the request at the stream's end or first failure.
    pub(crate) fn new(body: BlobBody, max: usize, outcome: Option<Outcome>) -> Self {
        let (total, rest, source) = match body {
            BlobBody::Bytes(bytes) => (bytes.len() as u64, bytes, None),
            BlobBody::Stream { len, stream } => (len, Bytes::new(), Some(stream)),
        };
        let chunks = Rechunk {
            spans: chunk_plan(total, max),
            span: None,
            source,
            rest,
            buf: BytesMut::new(),
            done: false,
            outcome,
        };
        Self {
            total_bytes: total,
            chunks: Box::pin(chunks),
        }
    }
}

/// A failed body read: a redacted `internal`, its detail logged.
fn read_error(detail: impl fmt::Display) -> ServerError {
    let (line, err) = describe_and_map(StorageOp::BlobRead, detail);
    tracing::warn!(detail = %line, "storage failure");
    err
}

/// Re-chunks a blob body along [`chunk_plan`]'s spans.
struct Rechunk<I> {
    spans: I,
    span: Option<ChunkSpan>,
    source: Option<BoxStream<'static, Result<Bytes, StoreError>>>,
    /// The unread rest of the current store piece.
    rest: Bytes,
    /// The chunk being assembled when it spans store pieces.
    buf: BytesMut,
    done: bool,
    outcome: Option<Outcome>,
}

impl<I: Iterator<Item = ChunkSpan> + Unpin> Rechunk<I> {
    fn fail(&mut self, err: ServerError) -> Poll<Option<Result<DownloadChunk, ServerError>>> {
        self.done = true;
        if let Some(outcome) = &mut self.outcome {
            outcome.record(Err(&err));
        }
        Poll::Ready(Some(Err(err)))
    }
}

impl<I: Iterator<Item = ChunkSpan> + Unpin> Stream for Rechunk<I> {
    type Item = Result<DownloadChunk, ServerError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        loop {
            let Some(span) = this.span.or_else(|| this.spans.next()) else {
                this.done = true;
                if let Some(outcome) = &mut this.outcome {
                    outcome.record(Ok(()));
                }
                return Poll::Ready(None);
            };
            this.span = Some(span);
            let need = span.len - this.buf.len();
            let data = if need == 0 {
                Some(this.buf.split().freeze())
            } else if this.buf.is_empty() && this.rest.len() >= need {
                Some(this.rest.split_to(need))
            } else {
                None
            };
            if let Some(data) = data {
                this.span = None;
                // Success is recorded when the `last` chunk is yielded: a
                // binding may stop polling there (its client has the
                // whole pack), and that must not count as `canceled`.
                if span.last
                    && let Some(outcome) = &mut this.outcome
                {
                    outcome.record(Ok(()));
                }
                return Poll::Ready(Some(Ok(DownloadChunk {
                    offset: span.offset,
                    data,
                    last: span.last,
                })));
            }
            if !this.rest.is_empty() {
                let piece = this.rest.split_to(need.min(this.rest.len()));
                this.buf.extend_from_slice(&piece);
                continue;
            }
            let next = match this.source.as_mut() {
                Some(source) => ready!(source.as_mut().poll_next(cx)),
                None => None,
            };
            match next {
                Some(Ok(piece)) => this.rest = piece,
                Some(Err(e)) => return this.fail(read_error(e)),
                None => return this.fail(read_error("blob body ended before its length")),
            }
        }
    }
}
