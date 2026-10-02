//! The native remote-hook channel and its flags (WP-3.8): `mkit.server.hooks.v1`
//! over signed HTTPS, wired into `mkit-server serve` through
//! `--hook-authorize-url`, `--hook-admit-url` and `--hook-outcome-url`
//! (SPEC-SERVER §§6-8). Core (`mkit_server::hooks`) holds the protocol; this
//! module holds the transport ([`HttpChannel`]), the flags ([`config`]) and
//! the assembly of the hooks and the outcome sink ([`build`]).

pub mod build;
pub mod config;
mod http;

pub use http::{HttpChannel, HttpChannelError};
