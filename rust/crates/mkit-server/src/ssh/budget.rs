//! Per-connection resource caps (SPEC-TRANSPORT §4.4).
//!
//! A session is driven by one remote client: an ssh forced command or an
//! enc peer. Bounding its cumulative work stops a misbehaving client from
//! pinning the serving process. The numbers are the ones SPEC-TRANSPORT
//! §4.4 cites.

use mkit_rpc::mkit::rpc::v1::ssh::{SshFrame, ssh_frame};

use crate::upload::UploadLimits;

/// Most top-level frames a session reads after `Hello`. The chunk frames an
/// upload reads are not counted here; [`UploadLimits::max_chunks`] caps
/// them instead.
pub const MAX_FRAMES_PER_CONN: u32 = 10_000;

/// Most estimated request bytes per session (1 GiB); see
/// [`frame_byte_estimate`]. It also caps an upload's declared size.
pub const MAX_BYTES_PER_CONN: u64 = 1024 * 1024 * 1024;

/// The upload caps of the ssh wire: a declared size of at most
/// [`MAX_BYTES_PER_CONN`] and at most [`MAX_FRAMES_PER_CONN`] chunks. A
/// binding builds its pipeline's `PipelineConfig` with these.
#[must_use]
pub const fn upload_limits() -> UploadLimits {
    UploadLimits {
        max_total_bytes: MAX_BYTES_PER_CONN,
        max_chunks: MAX_FRAMES_PER_CONN,
    }
}

/// A frame's cost against [`MAX_BYTES_PER_CONN`], without re-encoding: a
/// chunk's data length, the `total_bytes` a header declares, or 64 for a
/// small control frame. An upload is charged its declared size once, by its
/// header; the chunks it then reads are not charged again.
#[must_use]
pub fn frame_byte_estimate(f: &SshFrame) -> u64 {
    use ssh_frame::Body;
    match &f.body {
        Some(Body::PackChunk(c)) => c.data.as_ref().map_or(0, Vec::len) as u64,
        Some(Body::UploadPack(h)) => h.total_bytes.unwrap_or(0),
        Some(Body::DownloadPackHeader(h)) => h.total_bytes.unwrap_or(0),
        _ => 64,
    }
}

/// The running totals of one session.
#[derive(Debug, Default)]
pub(super) struct Budget {
    frames: u32,
    bytes: u64,
}

impl Budget {
    /// Charge one top-level frame.
    ///
    /// # Errors
    /// The message of the cap it exceeds.
    pub(super) fn charge(&mut self, frame: &SshFrame) -> Result<(), &'static str> {
        self.frames = self.frames.saturating_add(1);
        if self.frames > MAX_FRAMES_PER_CONN {
            return Err("per-connection frame budget exceeded");
        }
        self.bytes = self.bytes.saturating_add(frame_byte_estimate(frame));
        if self.bytes > MAX_BYTES_PER_CONN {
            return Err("per-connection byte budget exceeded");
        }
        Ok(())
    }
}
