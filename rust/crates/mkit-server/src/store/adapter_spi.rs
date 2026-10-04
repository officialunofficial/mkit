//! Adapter-only storage layout, codecs and maintenance primitives.
//! These details are outside the supported embedder API.

pub(crate) use super::*;

#[path = "codec.rs"]
pub mod codec;
#[path = "index.rs"]
pub mod index;
#[path = "keys.rs"]
pub mod keys;
#[path = "outbox.rs"]
pub mod outbox;
#[path = "publication.rs"]
pub mod publication;
#[path = "tickets.rs"]
pub mod tickets;
#[path = "watermark.rs"]
pub mod watermark;
