#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![deny(missing_docs, unused_must_use)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::missing_errors_doc
    )
)]

// Each module owns its section. Append only within the owned section.
// error
commonware_macros::stability_mod!(ALPHA, pub mod error);
// limits
commonware_macros::stability_mod!(ALPHA, pub mod limits);
// evidence
commonware_macros::stability_mod!(ALPHA, pub mod evidence);
// pack_verify
commonware_macros::stability_mod!(ALPHA, pub mod pack_verify);
// closure
commonware_macros::stability_mod!(ALPHA, pub mod closure);
// decision
commonware_macros::stability_mod!(ALPHA, pub mod decision);
// fork
commonware_macros::stability_mod!(ALPHA, pub mod fork);
// auth
commonware_macros::stability_mod!(ALPHA, pub mod auth);
// replay
commonware_macros::stability_mod!(ALPHA, pub mod replay);
// Private shared decode infrastructure, activated by encoded implementations.
#[cfg(any(
    test,
    not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    ))
))]
#[allow(dead_code)]
mod codec;
