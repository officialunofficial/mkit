// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The `/watch` WebSocket wire frame — shared by the RefStore DO (producer,
// `worker_impl/refstore.rs::broadcast`) and the WatchRefs Connect-streaming
// bridge (consumer, `worker_impl/service.rs::watch_refs`). Declared once,
// host+wasm target-independent (like `envelope.rs`/`refs.rs`/`chat.rs`), so a
// field rename can't silently desync the two sides, and the `Commit ->
// RefEvent` translation the streaming bridge depends on is a plain function
// this module's tests exercise on the host — no wasm32 target or running
// Worker required to check that it round-trips.
//
// See README "WatchRefs / streaming" for the fallback this frame originally
// only served, and the doc comment on `worker_impl::service::watch_refs` for
// the Connect-streaming bridge this module now also feeds.

use serde::{Deserialize, Serialize};

use crate::proto::mkit::repo::v1::RefEvent;

/// A live frame broadcast to every `/watch` subscriber. The SAME socket
/// carries commit / chat / reaction frames so the lobby renders one merged
/// feed; the `kind` discriminator is the serde tag (set by the enum, not by
/// hand), so a variant and its tag can't drift. Hex fields are decoded back
/// to raw bytes where a consumer needs them (the DO never does; the streaming
/// bridge does, via [`WatchFrame::decode_ref_event`]). Wire shape is
/// `{"kind":"commit"|"chat"|"reaction", …variant fields}` — matched 1:1 by
/// the web client's `parseActivityFrame`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WatchFrame {
    Commit {
        name: String,
        object_id: String,             // 64-hex
        author_pubkey: Option<String>, // 64-hex
    },
    Chat {
        message_id: String, // 64-hex content address
        author_pubkey: String,
        text: String,
        created_at: i64,
        seq: u64,
    },
    Reaction {
        target_id: String,
        emoji: String,
        author_pubkey: String,
        active: bool,
        count: u32,
    },
}

impl WatchFrame {
    /// Decode a raw `/watch` JSON frame and, if (and only if) it is a
    /// `Commit` frame, translate it into the `RefEvent` proto message
    /// `WatchRefs` streams to Connect clients.
    ///
    /// Everything else returns `None`, not an error — a malformed frame,
    /// a `Chat`/`Reaction` frame, or the untyped `"presence"` frame this enum
    /// deliberately doesn't model (see `refstore::PresenceJson`) must not
    /// tear down the whole `WatchRefs` stream over one skippable item. This
    /// is also today's schema boundary the issue's Implementation Notes flag
    /// as unresolved drift: `WatchRefs` only ever emits `Commit` frames as
    /// `RefEvent`s, so a Connect client sees ref advances only, never chat /
    /// reaction / presence — those still require the raw `/watch` WebSocket
    /// fallback until `RefEvent` (or a sibling stream type) grows a
    /// `Commit`/`Chat`/`Reaction`/`Presence` oneof.
    #[must_use]
    pub fn decode_ref_event(raw: &str) -> Option<RefEvent> {
        let WatchFrame::Commit {
            name,
            object_id,
            author_pubkey,
        } = serde_json::from_str(raw).ok()?
        else {
            return None;
        };
        Some(RefEvent {
            name: Some(name),
            object_id: hex::decode(&object_id).ok(),
            author_pubkey: author_pubkey.and_then(|s| hex::decode(s).ok()),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn decodes_commit_frame_into_ref_event() {
        let oid = hex32(0xab);
        let author = hex32(0x11);
        let raw = format!(
            r#"{{"kind":"commit","name":"refs/heads/main","object_id":"{oid}","author_pubkey":"{author}"}}"#
        );
        let event = WatchFrame::decode_ref_event(&raw).expect("commit frame decodes");
        assert_eq!(event.name.as_deref(), Some("refs/heads/main"));
        assert_eq!(event.object_id, Some(hex::decode(&oid).unwrap()));
        assert_eq!(event.author_pubkey, Some(hex::decode(&author).unwrap()));
    }

    #[test]
    fn decodes_commit_frame_with_absent_author() {
        let oid = hex32(0x02);
        let raw = format!(r#"{{"kind":"commit","name":"refs/heads/x","object_id":"{oid}"}}"#);
        let event = WatchFrame::decode_ref_event(&raw).expect("commit frame decodes");
        assert_eq!(event.author_pubkey, None);
    }

    #[test]
    fn skips_chat_frame() {
        let raw = r#"{"kind":"chat","message_id":"aa","author_pubkey":"bb","text":"hi","created_at":1,"seq":1}"#;
        assert_eq!(WatchFrame::decode_ref_event(raw), None);
    }

    #[test]
    fn skips_reaction_frame() {
        let raw = r#"{"kind":"reaction","target_id":"aa","emoji":"👍","author_pubkey":"bb","active":true,"count":1}"#;
        assert_eq!(WatchFrame::decode_ref_event(raw), None);
    }

    #[test]
    fn skips_untyped_presence_frame() {
        // `WatchFrame` deliberately doesn't model "presence" (see
        // `refstore::PresenceJson`) — an unknown `kind` tag must be skipped,
        // not propagated as a stream-ending decode error.
        let raw = r#"{"kind":"presence","members":[],"viewers":1}"#;
        assert_eq!(WatchFrame::decode_ref_event(raw), None);
    }

    #[test]
    fn malformed_hex_degrades_the_field_not_the_frame() {
        // A corrupt hex field degrades to `None` on that field rather than
        // failing the whole frame — the frame otherwise decoded fine, and
        // dropping the entire event over one bad field would be a worse
        // failure mode than a client seeing a ref name with no object id.
        let raw = r#"{"kind":"commit","name":"refs/heads/main","object_id":"not-hex"}"#;
        let event = WatchFrame::decode_ref_event(raw).expect("frame still decodes");
        assert_eq!(event.object_id, None);
    }

    #[test]
    fn skips_malformed_json() {
        assert_eq!(WatchFrame::decode_ref_event("not json"), None);
    }
}
