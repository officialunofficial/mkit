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
/// `mkit-write:v2` envelope prefix and from any mkit object prologue, so a
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
/// 64-hex VERIFIED Ed25519 pubkey; `text` is the trimmed value from
/// [`validate_text`]; `nonce` is the write envelope's per-post idempotency key
/// (unique per send, already signed). Folding the nonce in makes each post a
/// DISTINCT object — the same author posting the same text twice gets two
/// different ids — the same trick Makechain's signed message envelope uses (a
/// per-post timestamp in the hashed data). `text` is LAST so its (possibly
/// newline-bearing) content can't desync the earlier fields; `room`,
/// `author_hex`, and `nonce` are from restricted alphabets with no newline.
#[must_use]
pub fn canonical_message(room: &str, author_hex: &str, text: &str, nonce: &str) -> Vec<u8> {
    format!("{CHAT_CANONICAL_PREFIX}\n{room}\n{author_hex}\n{nonce}\n{text}").into_bytes()
}

/// BLAKE3 content address (32 raw bytes) of a chat message — UNIQUE per post.
///
/// The `nonce` (the send's idempotency key) is folded into the canonical bytes,
/// so the same author posting the same text twice yields two DISTINCT ids: each
/// message is its own object and a reaction can key on the plain 64-hex id (no
/// per-post disambiguator needed). A REPLAY of one captured envelope reuses its
/// nonce, so it recomputes the SAME id and collapses to the original (the DO
/// also dedupes a replay on (author, idempotency-key)).
#[must_use]
pub fn message_id(room: &str, author_hex: &str, text: &str, nonce: &str) -> [u8; 32] {
    blake3(&canonical_message(room, author_hex, text, nonce))
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

// --- Reactions --------------------------------------------------------------

/// Minimum gap between two reaction toggles from the SAME author, in ms. Far
/// smaller than the chat floor (reacting is meant to be snappy) — it exists only
/// to stop a scripted toggle flood, not to pace a human clicking a few emoji.
pub const REACT_MIN_INTERVAL_MS: i64 = 150;

/// The closed set of emoji a client may react with — MUST match the web client's
/// picker (`REACTION_EMOJI` in signed-lobby.tsx). An allowlist (rather than a
/// length cap) bounds the per-target cardinality and stops an arbitrary string
/// being persisted + broadcast to every viewer as a "reaction".
pub const REACTION_EMOJI: &[&str] = &["👍", "❤️", "😂", "🎉", "🚀", "👀", "✅", "🔥"];

/// Whether `emoji` is one of the allowed reaction emoji.
#[must_use]
pub fn is_allowed_emoji(emoji: &str) -> bool {
    REACTION_EMOJI.contains(&emoji)
}

/// A reaction target must be a 64-char lowercase-hex id (a 32-byte feed-item id:
/// a chat message id or a commit hash — both unique now that `message_id` folds
/// in the per-post nonce). Rejecting anything else keeps the reactions table's
/// cardinality bounded to real feed items.
#[must_use]
pub fn is_valid_target_id(target: &str) -> bool {
    target.len() == 64
        && target
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHOR: &str = "11"; // stand-in; canonicalization doesn't parse it
    const OTHER: &str = "22";

    #[test]
    fn canonical_is_prefixed_five_fields() {
        // prefix, room, author, NONCE, text — nonce before text so newline-bearing
        // text stays last.
        let bytes = canonical_message("lobby", AUTHOR, "gm", "n1");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "mkit-chat:v1\nlobby\n11\nn1\ngm"
        );
    }

    #[test]
    fn id_is_unique_per_nonce_and_content_addressed() {
        // Same (room, author, text, nonce) → same id (a replay recomputes it).
        assert_eq!(
            message_id("lobby", AUTHOR, "gm", "n1"),
            message_id("lobby", AUTHOR, "gm", "n1")
        );
        // SAME text, DIFFERENT nonce → DIFFERENT id: the exact fix — two distinct
        // posts of identical text no longer collide (so reactions can't leak across them).
        assert_ne!(
            message_id("lobby", AUTHOR, "gm", "n1"),
            message_id("lobby", AUTHOR, "gm", "n2")
        );
        // distinct text, author, or room each change the id too
        assert_ne!(
            message_id("lobby", AUTHOR, "gm", "n1"),
            message_id("lobby", AUTHOR, "gn", "n1")
        );
        assert_ne!(
            message_id("lobby", AUTHOR, "gm", "n1"),
            message_id("lobby", OTHER, "gm", "n1")
        );
        assert_ne!(
            message_id("lobby", AUTHOR, "gm", "n1"),
            message_id("other", AUTHOR, "gm", "n1")
        );
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
        assert!(is_rate_limited(
            Some(10_000),
            10_000 + MIN_POST_INTERVAL_MS - 1
        ));
        // exactly at the window edge -> allowed
        assert!(!is_rate_limited(
            Some(10_000),
            10_000 + MIN_POST_INTERVAL_MS
        ));
        // well after -> allowed
        assert!(!is_rate_limited(Some(10_000), 60_000));
    }

    #[test]
    fn emoji_allowlist() {
        assert!(is_allowed_emoji("👍"));
        assert!(is_allowed_emoji("🔥"));
        // not in the set, arbitrary text, empty, or a long string -> rejected
        assert!(!is_allowed_emoji("🦀"));
        assert!(!is_allowed_emoji("aaaa"));
        assert!(!is_allowed_emoji(""));
        assert!(!is_allowed_emoji(&"👍".repeat(4)));
    }

    #[test]
    fn target_id_must_be_64_lowercase_hex() {
        assert!(is_valid_target_id(&"a".repeat(64)));
        assert!(is_valid_target_id(&"0123456789abcdef".repeat(4)));
        assert!(!is_valid_target_id(&"a".repeat(63))); // too short
        assert!(!is_valid_target_id(&"a".repeat(65))); // too long
        assert!(!is_valid_target_id(&"A".repeat(64))); // uppercase
        assert!(!is_valid_target_id(&"g".repeat(64))); // non-hex
        assert!(!is_valid_target_id("0")); // a counter, not a real id
        assert!(!is_valid_target_id(""));
        assert!(!is_valid_target_id(&format!("{}:1", "a".repeat(64)))); // no seq suffix — ids are unique now
    }
}
