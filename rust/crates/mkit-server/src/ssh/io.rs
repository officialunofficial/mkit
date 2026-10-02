//! Blocking [`std::io`] frame adapters: `mkit-rpc`'s length-prefixed
//! framing (`read_frame`, `write_frame`) over a reader and a writer.
//!
//! Each call does its blocking I/O inside the future and never yields, like
//! the `fs` stores: correct under a blocking executor (the CLI's stdio
//! path). They have no read deadline, so they never return
//! [`FrameIoError::Timeout`].
//!
//! On native targets the stream must be `Send` (the session future is),
//! and `std::io::StdinLock`/`StdoutLock` are not: pass `std::io::Stdin` and
//! `std::io::Stdout` themselves, which lock per call; `write_frame`
//! flushes after every frame.

use std::io::{Read, Write};

use mkit_rpc::mkit::rpc::v1::ssh::SshFrame;

use super::session::{FrameIoError, FrameSink, FrameSource};
use crate::rt::MaybeSend;

/// A [`FrameSource`] over a blocking reader.
#[derive(Debug)]
pub struct ReadFrames<R>(pub R);

impl<R: Read + MaybeSend> FrameSource for ReadFrames<R> {
    async fn next_frame(&mut self) -> Result<SshFrame, FrameIoError> {
        mkit_rpc::read_frame(&mut self.0).map_err(FrameIoError::from)
    }
}

/// A [`FrameSink`] over a blocking writer; each frame is flushed.
#[derive(Debug)]
pub struct WriteFrames<W>(pub W);

impl<W: Write + MaybeSend> FrameSink for WriteFrames<W> {
    async fn send(&mut self, frame: &SshFrame) -> Result<(), FrameIoError> {
        mkit_rpc::write_frame(&mut self.0, frame).map_err(FrameIoError::from)
    }
}
