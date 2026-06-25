// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Pure chat logic for the signed lobby — the parts that carry the contract and
// run under `cargo test` on the host (no R2 / DO / wasm). The DO owns ordering
// (`seq`), the server clock (`created_at`), storage, and the broadcast; this
// module owns the rules they apply:
//
//   - `canonical_message` / `message_id`: a chat message is content-addressed
//     by BLAKE3 of its canonical bytes, exactly like a commit object — so a
//     message is a first-class object in the room's store, not a side table.
//     The author signs `{ room, text }` (the PostMessage body); the canonical
//     bytes fold in the VERIFIED author pubkey so two players can't mint the
//     same id for the same text (and so the id attributes the signer).
//   - `validate_text`: the length cap + non-empty rule (the abuse floor; the
//     passkey-gated write is the other half).
//   - `is_rate_limited`: the per-author min-interval decision, evaluated in the
//     DO's serial execution against the author's last post time.

use crate::hashing::blake3;

/// Max message length in Unicode scalar values (not bytes) — a tweet-ish cap.
pub const MAX_MESSAGE_CHARS: usize = 280;

/// Minimum gap between two posts from the SAME author, in milliseconds. The DO
/// enforces it serially per room, so it is a true per-author floor.
pub const MIN_POST_INTERVAL_MS: i64 = 2_000;

/// Domain prefix for the canonical chat-message bytes. Distinct from the
/// `mkit-write:v1` envelope prefix and from any mkit object prologue, so a
/// chat id can never collide with a commit/remix/envelope digest.
pub const CHAT_CANONICAL_PREFIX: &str = "mkit-chat:v1";

/// Validate + normalize message text. Trims surrounding ASCII whitespace,
/// rejects empty/blank, and caps the length by CHARACTER count (so a multi-byte
/// emoji counts as one). Returns the trimmed text to store on success.
pub fn validate_text(text: &str) -> Result<&str, &'static str> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("message is empty");
    }
    if trimmed.chars().count() > MAX_MESSAGE_CHARS {
        return Err("message exceeds the length cap");
    }
    Ok(trimmed)
}

/// Canonical bytes a chat message is content-addressed by. `author_hex` is the
/// 64-hex VERIFIED Ed25519 pubkey; `text` should already be the trimmed value
/// from [`validate_text`]. `text` is last so its (possibly newline-bearing)
/// content can't desync the earlier fields — `room` and `author_hex` are from
/// restricted alphabets that contain no newline.
#[must_use]
pub fn canonical_message(room: &str, author_hex: &str, text: &str) -> Vec<u8> {
    format!("{CHAT_CANONICAL_PREFIX}\n{room}\n{author_hex}\n{text}").into_bytes()
}

/// BLAKE3 content address (32 raw bytes) of a chat message.
///
/// This is a CONTENT hash, exactly like a commit hash: identical (room, author,
/// text) → identical id, stored once. It is NOT a unique per-post identifier —
/// the same author legitimately posting the same text twice yields two log rows
/// with the SAME id but distinct `seq`. Consumers MUST key the timeline on `seq`
/// (the monotonic per-room order), not on the id alone. Replays of a captured
/// signature are deduped separately on (author, idempotency-key) in the DO.
#[must_use]
pub fn message_id(room: &str, author_hex: &str, text: &str) -> [u8; 32] {
    blake3(&canonical_message(room, author_hex, text))
}

/// Whether a new post from an author should be refused for posting too soon.
/// `last_created_at` is the author's most recent stored post time (epoch-ms),
/// or None if they have never posted; `now` is the server clock (epoch-ms).
#[must_use]
pub fn is_rate_limited(last_created_at: Option<i64>, now: i64) -> bool {
    match last_created_at {
        None => false,
        Some(last) => now - last < MIN_POST_INTERVAL_MS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHOR: &str = "11"; // stand-in; canonicalization doesn't parse it
    const OTHER: &str = "22";

    #[test]
    fn canonical_is_prefixed_four_fields() {
        let bytes = canonical_message("lobby", AUTHOR, "gm");
        assert_eq!(String::from_utf8(bytes).unwrap(), "mkit-chat:v1\nlobby\n11\ngm");
    }

    #[test]
    fn id_is_deterministic_and_content_addressed() {
        assert_eq!(message_id("lobby", AUTHOR, "gm"), message_id("lobby", AUTHOR, "gm"));
        // distinct text, author, or room each change the id
        assert_ne!(message_id("lobby", AUTHOR, "gm"), message_id("lobby", AUTHOR, "gn"));
        assert_ne!(message_id("lobby", AUTHOR, "gm"), message_id("lobby", OTHER, "gm"));
        assert_ne!(message_id("lobby", AUTHOR, "gm"), message_id("other", AUTHOR, "gm"));
    }

    #[test]
    fn validate_trims_and_rejects_blank() {
        assert_eq!(validate_text("  hello  "), Ok("hello"));
        assert!(validate_text("").is_err());
        assert!(validate_text("   \t\n ").is_err());
    }

    #[test]
    fn validate_caps_by_char_count_not_bytes() {
        // exactly the cap is accepted; one over is rejected
        let at_cap = "a".repeat(MAX_MESSAGE_CHARS);
        assert!(validate_text(&at_cap).is_ok());
        let over = "a".repeat(MAX_MESSAGE_CHARS + 1);
        assert!(validate_text(&over).is_err());
        // a 4-byte emoji is ONE character: 280 of them fit, 281 don't
        let emoji_at_cap = "🚀".repeat(MAX_MESSAGE_CHARS);
        assert!(validate_text(&emoji_at_cap).is_ok());
        let emoji_over = "🚀".repeat(MAX_MESSAGE_CHARS + 1);
        assert!(validate_text(&emoji_over).is_err());
    }

    #[test]
    fn rate_limit_window() {
        // never posted -> allowed
        assert!(!is_rate_limited(None, 10_000));
        // posted just now -> refused
        assert!(is_rate_limited(Some(10_000), 10_000));
        // within the window -> refused
        assert!(is_rate_limited(Some(10_000), 10_000 + MIN_POST_INTERVAL_MS - 1));
        // exactly at the window edge -> allowed
        assert!(!is_rate_limited(Some(10_000), 10_000 + MIN_POST_INTERVAL_MS));
        // well after -> allowed
        assert!(!is_rate_limited(Some(10_000), 60_000));
    }
}
