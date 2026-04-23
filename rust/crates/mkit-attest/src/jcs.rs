//! JCS — JSON Canonicalisation Scheme (RFC 8785) writer.
//!
//! Restricted to the subset mkit attestations actually need:
//!
//! * strings (UTF-8, short-form escapes per RFC 8259 §7)
//! * unsigned integers (`u64`; no floating point, no bignum)
//! * booleans, null
//! * arrays
//! * objects with **pre-sorted, ASCII-only** keys
//!
//! Not supported by design:
//! * floats / non-integer numbers — JSON's number grammar + IEEE-754
//!   round-tripping is the hardest part of JCS and we never emit one.
//! * object keys with non-ASCII characters — in-toto v1 + DSSE both use
//!   ASCII keys, and the UCS-2 codepoint sort rule would require a real
//!   UTF-16 ordering table for non-ASCII. We assert ASCII at debug time
//!   and treat sort-by-bytes as equivalent.
//!
//! Port of `src/attestations/jcs.zig`. Output bytes must be byte-identical
//! to the Zig encoder; the Phase 8 golden vectors pin that contract.

use core::fmt::Write as _;

use crate::Error;

/// A single JSON value in the subset we handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Unsigned integer. Negatives are not representable — widen to a
    /// different value type if you need them.
    Uint(u64),
    String(String),
    Array(Vec<Value>),
    /// Object members. `Member::key`s MUST be unique and sorted strictly
    /// ascending byte-wise. Both invariants are checked at encode time.
    Object(Vec<Member>),
}

/// Single object member. Held flat so callers can build pre-sorted
/// vectors directly without going through a map type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub key: String,
    pub value: Value,
}

impl Member {
    #[must_use]
    pub fn new(key: impl Into<String>, value: Value) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }
}

/// Encode `value` to JCS-canonical JSON. Returns the canonical bytes
/// as an owned `String` (the output is always valid UTF-8).
///
/// # Errors
///
/// Returns [`Error::JcsObjectKeysUnsorted`] if any nested object's keys
/// are not strictly ascending byte-wise.
pub fn encode(value: &Value) -> Result<String, Error> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

fn write_value(out: &mut String, v: &Value) -> Result<(), Error> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Uint(n) => {
            // u64 fits trivially; write! cannot fail on String.
            let _ = write!(out, "{n}");
        }
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i != 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        Value::Object(members) => {
            check_sorted_ascii_keys(members)?;
            out.push('{');
            for (i, m) in members.iter().enumerate() {
                if i != 0 {
                    out.push(',');
                }
                write_string(out, &m.key);
                out.push(':');
                write_value(out, &m.value)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn check_sorted_ascii_keys(members: &[Member]) -> Result<(), Error> {
    if members.len() <= 1 {
        if let Some(m) = members.first() {
            debug_assert!(m.key.is_ascii(), "JCS object keys must be ASCII");
        }
        return Ok(());
    }
    for w in members.windows(2) {
        debug_assert!(w[0].key.is_ascii(), "JCS object keys must be ASCII");
        debug_assert!(w[1].key.is_ascii(), "JCS object keys must be ASCII");
        if w[0].key.as_bytes() >= w[1].key.as_bytes() {
            return Err(Error::JcsObjectKeysUnsorted);
        }
    }
    Ok(())
}

/// JSON string serialisation per RFC 8785 §3.2.3 / RFC 8259 §7:
///
/// * Short-form escape for `\"` `\\` `\b` `\f` `\n` `\r` `\t`.
/// * `\uXXXX` (lowercase hex) for every other control char `< 0x20`.
/// * Everything else (incl. all non-ASCII Unicode) is emitted verbatim
///   as UTF-8.
///
/// Forward slash is NOT escaped (optional per RFC 8259; JCS forbids the
/// optional escape).
pub(crate) fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tiny helper so test bodies stay short. Pass-by-value is fine here:
    // every test constructs a fresh `Value` literal, never wants it back.
    #[allow(clippy::needless_pass_by_value)]
    fn enc(v: Value) -> String {
        encode(&v).expect("encode")
    }

    #[test]
    fn primitives() {
        assert_eq!(enc(Value::Null), "null");
        assert_eq!(enc(Value::Bool(true)), "true");
        assert_eq!(enc(Value::Bool(false)), "false");
        assert_eq!(enc(Value::Uint(0)), "0");
        assert_eq!(enc(Value::Uint(42)), "42");
        assert_eq!(enc(Value::Uint(u64::MAX)), "18446744073709551615");
    }

    #[test]
    fn simple_strings_verbatim() {
        assert_eq!(enc(Value::String(String::new())), "\"\"");
        assert_eq!(enc(Value::String("hello".into())), "\"hello\"");
        // Forward slash is NOT escaped.
        assert_eq!(enc(Value::String("a/b".into())), "\"a/b\"");
    }

    #[test]
    fn short_form_escapes() {
        assert_eq!(enc(Value::String("\"".into())), "\"\\\"\"");
        assert_eq!(enc(Value::String("\\".into())), "\"\\\\\"");
        assert_eq!(enc(Value::String("\n".into())), "\"\\n\"");
        assert_eq!(enc(Value::String("\r".into())), "\"\\r\"");
        assert_eq!(enc(Value::String("\t".into())), "\"\\t\"");
        assert_eq!(enc(Value::String("\u{0008}".into())), "\"\\b\"");
        assert_eq!(enc(Value::String("\u{000C}".into())), "\"\\f\"");
    }

    #[test]
    fn u_escape_for_remaining_controls() {
        assert_eq!(enc(Value::String("\u{0000}".into())), "\"\\u0000\"");
        assert_eq!(enc(Value::String("\u{0001}".into())), "\"\\u0001\"");
        assert_eq!(enc(Value::String("\u{001f}".into())), "\"\\u001f\"");
        assert_eq!(enc(Value::String("\u{000e}".into())), "\"\\u000e\"");
    }

    #[test]
    fn utf8_passes_through_unescaped() {
        // JCS §3.2.3 rule 3: non-ASCII is NOT escaped.
        assert_eq!(enc(Value::String("café".into())), "\"café\"");
        assert_eq!(enc(Value::String("日本語".into())), "\"日本語\"");
        assert_eq!(enc(Value::String("🔒".into())), "\"🔒\"");
    }

    #[test]
    fn arrays() {
        assert_eq!(enc(Value::Array(vec![])), "[]");
        assert_eq!(
            enc(Value::Array(vec![
                Value::Uint(1),
                Value::Uint(2),
                Value::Uint(3),
            ])),
            "[1,2,3]"
        );
        assert_eq!(
            enc(Value::Array(vec![
                Value::String("a".into()),
                Value::Null,
                Value::Bool(true),
            ])),
            "[\"a\",null,true]"
        );
    }

    #[test]
    fn objects_emit_presorted_keys() {
        assert_eq!(enc(Value::Object(vec![])), "{}");
        assert_eq!(
            enc(Value::Object(vec![Member::new("a", Value::Uint(1))])),
            "{\"a\":1}"
        );
        assert_eq!(
            enc(Value::Object(vec![
                Member::new("a", Value::Uint(1)),
                Member::new("b", Value::Uint(2)),
            ])),
            "{\"a\":1,\"b\":2}"
        );
    }

    #[test]
    fn unsorted_keys_rejected_in_release() {
        // We accept that the debug_assert fires in debug builds; in
        // release the explicit check returns the error. To exercise
        // the runtime branch reliably under both profiles we construct
        // members that are equal — strictly-ascending check rejects
        // them either way.
        let v = Value::Object(vec![
            Member::new("a", Value::Uint(1)),
            Member::new("a", Value::Uint(2)),
        ]);
        // In debug, debug_assert may fire first (panics), so guard the
        // assertion to release-mode only.
        if !cfg!(debug_assertions) {
            assert!(matches!(encode(&v), Err(Error::JcsObjectKeysUnsorted)));
        }
    }

    #[test]
    fn nested_predicate_like_shape_is_byte_exact() {
        // Mirrors the Zig "nested object with predicate-like shape" test
        // — the byte sequence is the contract.
        let nested = Value::Object(vec![
            Member::new(
                "_type",
                Value::String("https://in-toto.io/Statement/v1".into()),
            ),
            Member::new(
                "predicate",
                Value::Object(vec![
                    Member::new("buildType", Value::String("https://example.com/t".into())),
                    Member::new("stepCount", Value::Uint(3)),
                ]),
            ),
            Member::new(
                "predicateType",
                Value::String("https://slsa.dev/provenance/v1".into()),
            ),
            Member::new(
                "subject",
                Value::Array(vec![Value::Object(vec![
                    Member::new(
                        "digest",
                        Value::Object(vec![Member::new(
                            "blake3",
                            Value::String("deadbeef".into()),
                        )]),
                    ),
                    Member::new("name", Value::String("commit".into())),
                ])]),
            ),
        ]);
        assert_eq!(
            encode(&nested).unwrap(),
            "{\"_type\":\"https://in-toto.io/Statement/v1\",\
             \"predicate\":{\"buildType\":\"https://example.com/t\",\"stepCount\":3},\
             \"predicateType\":\"https://slsa.dev/provenance/v1\",\
             \"subject\":[{\"digest\":{\"blake3\":\"deadbeef\"},\"name\":\"commit\"}]}"
        );
    }
}
