//! Inert lean denial and durable, unresolved takedown intent foundation.
pub mod denial;
mod intent;
pub mod inventory;
#[cfg(test)]
mod tests;
pub use intent::{Record, Service};
