// SPDX-License-Identifier: MIT OR Apache-2.0
//
// The canonical `/watch` wire encoding — a `RoomEvent` proto-JSON payload —
// shared by the RefStore DO (producer, `worker_impl/refstore.rs::broadcast`)
// and the WatchRefs Connect-streaming bridge (consumer,
// `worker_impl/service.rs::bridge_watch_socket`). Declared once, host+wasm
// target-independent (like `envelope.rs`/`refs.rs`/`chat.rs`), so a field
// rename can't silently desync the two sides, and the hex<->bytes
// translation this module owns is exercised by this module's tests on the
// host — no wasm32 target or running Worker required.
//
// Replaces the old ad hoc, hand-tagged `WatchFrame` enum + separate untyped
// `PresenceJson` struct: every event kind (commit/chat/reaction/presence)
// the DO broadcasts is now ONE proto-JSON `RoomEvent`, so the raw
// `/watch/<room>` WebSocket fallback and the Connect `WatchRefs` stream see
// the exact same schema instead of two hand-parsed dialects — see mkit#705.
// `bytes` fields (object/message ids, pubkeys) are base64 on the wire (proto3
// JSON canonical mapping via buffa's `json_helpers::opt_bytes`), NOT the hex
// the old `WatchFrame` used — callers on both sides go through this module's
// hex<->bytes conversions rather than assuming either encoding.

use crate::proto::mkit::repo::v1::room_event::Event;
use crate::proto::mkit::repo::v1::{
    ChatMessage, PresenceEvent, PresenceMember, ReactionEvent, RefEvent, RoomEvent,
};

/// Build the `commit` variant of `RoomEvent` from the DO's hex-string fields
/// (SQLite stores ref values as hex; the wire proto field is raw `bytes`).
/// `object_id_hex`/`author_pubkey_hex` that fail to decode become an absent
/// field rather than failing the whole event — a client seeing a ref name
/// with no object id is a smaller failure than dropping the event entirely.
#[must_use]
pub fn commit_event(
    name: String,
    object_id_hex: &str,
    author_pubkey_hex: Option<&str>,
) -> RoomEvent {
    RoomEvent {
        event: Some(Event::Commit(Box::new(RefEvent {
            name: Some(name),
            object_id: hex::decode(object_id_hex).ok(),
            author_pubkey: author_pubkey_hex.and_then(|s| hex::decode(s).ok()),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

/// Build the `chat` variant of `RoomEvent`. `created_at` is epoch-ms; populates
/// both the deprecated `created_at` field and its unambiguous
/// `created_at_unix_ms` sibling (mkit#795) so old and new clients alike
/// decode the right value during the migration.
#[must_use]
pub fn chat_event(
    message_id_hex: &str,
    author_pubkey_hex: &str,
    text: String,
    created_at: i64,
    seq: u64,
) -> RoomEvent {
    RoomEvent {
        event: Some(Event::Chat(Box::new(ChatMessage {
            message_id: hex::decode(message_id_hex).ok(),
            author_pubkey: hex::decode(author_pubkey_hex).ok(),
            text: Some(text),
            created_at: Some(created_at),
            seq: Some(seq),
            created_at_unix_ms: Some(created_at),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

/// Build the `reaction` variant of `RoomEvent` — the live on/off toggle, NOT
/// the stored-row shape `ListReactions` returns.
#[must_use]
pub fn reaction_event(
    target_id: String,
    emoji: String,
    author_pubkey_hex: &str,
    active: bool,
    count: u32,
) -> RoomEvent {
    RoomEvent {
        event: Some(Event::Reaction(Box::new(ReactionEvent {
            target_id: Some(target_id),
            emoji: Some(emoji),
            author_pubkey: hex::decode(author_pubkey_hex).ok(),
            active: Some(active),
            count: Some(count),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

/// Build the `presence` variant of `RoomEvent`. `members` is `(pubkey_hex,
/// since_epoch_ms)`; a member whose pubkey fails to decode is dropped from
/// the roster rather than failing the whole presence broadcast. Populates
/// both the deprecated `since` field and its unambiguous `since_unix_ms`
/// sibling (mkit#795) so old and new clients alike decode the right value
/// during the migration.
#[must_use]
pub fn presence_event(members: Vec<(String, i64)>, viewers: u32) -> RoomEvent {
    RoomEvent {
        event: Some(Event::Presence(Box::new(PresenceEvent {
            members: members
                .into_iter()
                .filter_map(|(pubkey_hex, since)| {
                    Some(PresenceMember {
                        author_pubkey: Some(hex::decode(&pubkey_hex).ok()?),
                        since: Some(since),
                        since_unix_ms: Some(since),
                        ..Default::default()
                    })
                })
                .collect(),
            viewers: Some(viewers),
            ..Default::default()
        }))),
        ..Default::default()
    }
}

/// Serialize a `RoomEvent` to its canonical proto-JSON wire form. `None` on a
/// (practically unreachable, since every field is plain owned data)
/// serialize failure — callers must skip the frame rather than fan out an
/// empty/partial payload.
#[must_use]
pub fn to_json(event: &RoomEvent) -> Option<String> {
    serde_json::to_string(event).ok()
}

/// Decode one raw `/watch` text frame into a `RoomEvent`. Returns `None` (not
/// an error) for malformed JSON — the caller (the WatchRefs Connect bridge)
/// must skip an unparseable frame rather than tear down the whole stream.
#[must_use]
pub fn decode(raw: &str) -> Option<RoomEvent> {
    serde_json::from_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn commit_event_round_trips_through_json() {
        let oid = hex32(0xab);
        let author = hex32(0x11);
        let event = commit_event("refs/heads/main".to_owned(), &oid, Some(&author));
        let json = to_json(&event).expect("serializes");
        let decoded = decode(&json).expect("decodes");
        let Some(Event::Commit(commit)) = decoded.event else {
            panic!("expected Commit variant, got {:?}", decoded.event);
        };
        assert_eq!(commit.name.as_deref(), Some("refs/heads/main"));
        assert_eq!(commit.object_id, Some(hex::decode(&oid).unwrap()));
        assert_eq!(commit.author_pubkey, Some(hex::decode(&author).unwrap()));
    }

    #[test]
    fn commit_event_with_absent_author() {
        let oid = hex32(0x02);
        let event = commit_event("refs/heads/x".to_owned(), &oid, None);
        let Some(Event::Commit(commit)) = event.event else {
            panic!("expected Commit variant");
        };
        assert_eq!(commit.author_pubkey, None);
    }

    #[test]
    fn commit_event_malformed_hex_degrades_the_field_not_the_event() {
        // A corrupt hex field degrades to `None` on that field rather than
        // failing the whole event.
        let event = commit_event("refs/heads/main".to_owned(), "not-hex", None);
        let Some(Event::Commit(commit)) = event.event else {
            panic!("expected Commit variant");
        };
        assert_eq!(commit.object_id, None);
    }

    #[test]
    fn chat_event_round_trips_through_json() {
        let msg_id = hex32(0xcc);
        let author = hex32(0x22);
        let event = chat_event(&msg_id, &author, "hi room".to_owned(), 1_700_000_000_000, 7);
        let json = to_json(&event).expect("serializes");
        let decoded = decode(&json).expect("decodes");
        let Some(Event::Chat(chat)) = decoded.event else {
            panic!("expected Chat variant, got {:?}", decoded.event);
        };
        assert_eq!(chat.message_id, Some(hex::decode(&msg_id).unwrap()));
        assert_eq!(chat.author_pubkey, Some(hex::decode(&author).unwrap()));
        assert_eq!(chat.text.as_deref(), Some("hi room"));
        assert_eq!(chat.created_at, Some(1_700_000_000_000));
        assert_eq!(chat.created_at_unix_ms, Some(1_700_000_000_000));
        assert_eq!(chat.seq, Some(7));
    }

    #[test]
    fn reaction_event_round_trips_through_json() {
        let author = hex32(0x33);
        let event = reaction_event("targethex".to_owned(), "👍".to_owned(), &author, true, 3);
        let json = to_json(&event).expect("serializes");
        let decoded = decode(&json).expect("decodes");
        let Some(Event::Reaction(reaction)) = decoded.event else {
            panic!("expected Reaction variant, got {:?}", decoded.event);
        };
        assert_eq!(reaction.target_id.as_deref(), Some("targethex"));
        assert_eq!(reaction.emoji.as_deref(), Some("👍"));
        assert_eq!(reaction.author_pubkey, Some(hex::decode(&author).unwrap()));
        assert_eq!(reaction.active, Some(true));
        assert_eq!(reaction.count, Some(3));
    }

    #[test]
    fn presence_event_round_trips_through_json() {
        let a = hex32(0x44);
        let b = hex32(0x55);
        let event = presence_event(vec![(a.clone(), 100), (b.clone(), 200)], 4);
        let json = to_json(&event).expect("serializes");
        let decoded = decode(&json).expect("decodes");
        let Some(Event::Presence(presence)) = decoded.event else {
            panic!("expected Presence variant, got {:?}", decoded.event);
        };
        assert_eq!(presence.members.len(), 2);
        assert_eq!(
            presence.members[0].author_pubkey,
            Some(hex::decode(&a).unwrap())
        );
        assert_eq!(presence.members[0].since, Some(100));
        assert_eq!(presence.members[0].since_unix_ms, Some(100));
        assert_eq!(
            presence.members[1].author_pubkey,
            Some(hex::decode(&b).unwrap())
        );
        assert_eq!(presence.viewers, Some(4));
    }

    #[test]
    fn presence_event_drops_members_with_malformed_pubkey() {
        let event = presence_event(vec![("not-hex".to_owned(), 1)], 0);
        let Some(Event::Presence(presence)) = event.event else {
            panic!("expected Presence variant");
        };
        assert!(presence.members.is_empty());
    }

    #[test]
    fn decode_rejects_malformed_json() {
        assert!(decode("not json").is_none());
    }
}
