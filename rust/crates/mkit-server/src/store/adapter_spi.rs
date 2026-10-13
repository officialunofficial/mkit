//! Adapter-only storage layout, codecs and maintenance primitives.
//! These details are for storage adapter implementations only.
//! They are outside the supported embedder API and may change with the layout.
//! Embedding business logic uses [`crate::reads::ReadAccess`] instead.
//! Reference adapters retain these primitives for storage maintenance.

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
