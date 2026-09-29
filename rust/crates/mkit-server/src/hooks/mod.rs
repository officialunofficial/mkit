//! Remote hooks: the `mkit.server.hooks.v1` adapter (SPEC-SERVER §§6-8),
//! behind the `remote-hooks` feature.
//!
//! A deployment can run authorization, admission and outcome delivery in a
//! separate service, such as a payment layer. This module holds the whole
//! protocol except the transport:
//!
//! - [`HookChannel`] moves one Connect unary call (`POST <base>/<procedure>`,
//!   `application/json`, `Connect-Protocol-Version: 1`). The native HTTPS
//!   channel (WP-3.8) and the Workers binding (WP-3.9) will implement it.
//! - [`HookSigner`] signs every request over its exact body bytes with the
//!   `mkit-hook:v1` domain, a fresh 32-byte nonce and a validity of at most
//!   300 s. Only a channel that reports [`HookChannel::isolated`] (a service
//!   binding, §7.3) may go unsigned, and [`HookClient::new`] refuses anything
//!   else.
//! - [`RemoteAuthorizer`], [`RemoteAdmission`] and [`RemoteOutcomes`] share
//!   one [`HookClient`] and implement the stage traits, so any subset plugs
//!   into [`Hooks`](crate::pipeline::Hooks).
//!
//! # Failure semantics
//!
//! Authorize and Admit fail closed (§8): a transport error, timeout, non-2xx
//! status, Connect error body, non-JSON content type, body over 64 KiB,
//! malformed JSON, absent decision or a failed §6.6 check all answer
//! retryable `unavailable` and write nothing. There is no retry inside a call.
//! A deliberate `deny` in a 2xx answer is a decision, sanitised per §6.2. An
//! Outcome is acknowledged by any 2xx; every other result is a
//! [`DeliveryError`](crate::pipeline::DeliveryError) that kind 8 retries with
//! backoff, signing each attempt afresh.
//!
//! # Credential safety
//!
//! Admit bodies carry admission credentials. Requests and responses are never
//! logged or `Debug`-printed (the generated messages would print values), the
//! request body is serialised once into an exactly sized `Zeroizing` buffer,
//! the credential values of the message are wiped after the call, and every
//! failure reason is a fixed string.
//!
//! # Not here
//!
//! Inspect, Event and `CachePurge` belong to later work (5.5, 5.2, 5.10), and a
//! core-profile server must not accept inspector configuration (§18).
//! `AuthorizeAllow.writer_view` becomes `AuthzFacts::caller_view`, which the
//! pipeline honours only under the `authority` role (§10.1). Reservation-id
//! uniqueness is enforced per partition by the pipeline, while §6.6 asks for
//! it per audience: uniqueness across partitions is the hook's obligation.

mod channel;
mod client;
mod map;
mod roles;
mod sign;

#[allow(
    missing_docs,
    missing_debug_implementations,
    unreachable_pub,
    clippy::all,
    clippy::pedantic,
    clippy::cargo
)]
mod proto {
    include!(concat!(env!("OUT_DIR"), "/hooks/_hooks.rs"));
    pub(super) use mkit::server::hooks::v1;
}

pub use channel::{ChannelError, HookChannel, HookRequest, HookResponse};
pub use client::{DEFAULT_TIMEOUT, HookClient, HookConfigError, MAX_RESPONSE_BYTES};
pub use roles::{RemoteAdmission, RemoteAuthorizer, RemoteOutcomes};
pub use sign::{
    DEFAULT_VALIDITY, DOMAIN, HookSigner, MAX_VALIDITY, NonceSource, OsNonces, SignerError,
};

#[cfg(test)]
pub(crate) mod tests;
