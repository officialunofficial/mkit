//! The `mkit.rpc.v1.ssh` session over the pipeline (PRD §6.9, D23;
//! SPEC-TRANSPORT §4.2): the `Hello` handshake, per-verb dispatch, the
//! streaming upload and download, the per-connection budgets and the CAS
//! conflict reply of `mkit serve`, moved here from `mkit-cli` so the ssh
//! stdio path and the enc listener share one implementation.
//!
//! [`serve_session`] is transport-agnostic: it reads frames from a
//! [`FrameSource`] and writes them to a [`FrameSink`], and never spawns or
//! sleeps, so it runs under a blocking executor (`mkit serve` over stdio)
//! as well as under tokio (the enc listener). [`ReadFrames`] and
//! [`WriteFrames`] adapt blocking `std::io` streams. The wire is frozen:
//! responses and error frames are `mkit serve`'s byte for byte, pinned by
//! `rust/tests/golden/ssh-serve/`.
//!
//! The pipeline runs in `AuthMode::TransportIdentity` with the principal
//! the transport established (`SshForcedCommand` for stdio,
//! `TransportPeer` for enc), so no replay record or quota is written.

mod budget;
mod io;
mod session;
#[cfg(test)]
mod tests;
mod verbs;

pub use budget::{MAX_BYTES_PER_CONN, MAX_FRAMES_PER_CONN, frame_byte_estimate, upload_limits};
pub use io::{ReadFrames, WriteFrames};
pub use session::{
    FrameIoError, FrameSink, FrameSource, SessionConfig, SessionEnd, handshake, serve_session,
};
pub use verbs::cas_conflict_body;
