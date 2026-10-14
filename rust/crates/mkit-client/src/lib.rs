#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

mod calls;
mod client;
mod connect;
mod plan;
mod push;
mod read;
mod receipts;
mod seams;

pub use client::{Client, NamedRef, NoClock, NoSigner, RefPage, SignedEnvelope, Visibility};
pub use connect::{
    ChannelError, Clock, Destination, Detail, Error, HttpTransport, Identity, RemoteError, Reply,
    Signer,
};
/// Challenge types carried by [`Error::PaymentRequired`].
pub use mkit_core::protocol::{AdmissionChallengeEntry, AdmissionRequired};
/// Canonical messages, shared with the native client and server.
pub use mkit_rpc::transport::mkit::transport::v1 as proto;
pub use plan::{Entry, Limits, Plan};
pub use push::{Outcome, PackmapMode, Push};
pub use read::{MemorySink, ObjectSink, UnpackOptions, Unpacked, Verification, unpack};
pub use receipts::{MemoryPartReceiptStore, PartReceiptStore, StoredPart, TicketMetadata};
pub use seams::{
    Attempt, AttemptHeaders, NoObserver, Observer, RefMove, RefTarget, RequestContext,
    RequestHeaders, RequestPolicy, SignError, SigningRequest, UnsignedRequestContext, Veto,
    WriteIntent, is_reserved_header, procedures,
};
