#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod client;
mod connect;
mod plan;
mod push;
mod read;

pub use client::{Client, NamedRef, NoClock, NoSigner, RefPage};
pub use connect::{
    Clock, Destination, Detail, Error, HttpTransport, Identity, RemoteError, Reply, Signer,
};
/// Challenge types carried by [`Error::PaymentRequired`].
pub use mkit_core::protocol::{AdmissionChallengeEntry, AdmissionRequired};
/// Canonical messages, shared with the native client and server.
pub use mkit_rpc::transport::mkit::transport::v1 as proto;
pub use plan::{Entry, Limits, Plan};
pub use push::{Outcome, PackmapMode, Push};
pub use read::{MemorySink, ObjectSink, UnpackOptions, Unpacked, Verification, unpack};
