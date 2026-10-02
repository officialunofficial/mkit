//! Remote hooks on Workers (WP-3.9; SPEC-SERVER §§6-8): the hook service is
//! another Worker reached over a **service binding**, which is not reachable
//! from the public internet, so requests go unsigned (§7.3). Core
//! (`mkit_server::hooks`) holds the protocol and the fail-closed adapter.
//!
//! - [`binding`]: `BindingChannel` over
//!   `env.service("ADMISSION_HOOK")`, and the pure URL and response-cap
//!   helpers behind it.
//! - [`config`]: the `HOOK_ROLES`, `HOOK_TIMEOUT_MS` and `AUTHORIZER_ROLE`
//!   vars, and the cross-check with the binding.
//! - [`build`]: the hooks and the kind-8 sink over one shared client.

pub mod binding;
pub mod build;
pub mod config;

/// Signed HTTPS hook transport (WP-3.9c).
pub mod fetch;

#[cfg(all(target_arch = "wasm32", feature = "test-faults"))]
#[doc(hidden)]
pub mod fetch_probe;
