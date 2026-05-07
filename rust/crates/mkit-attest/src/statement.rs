//! in-toto v1 Statement — payload of every DSSE envelope mkit produces.
//!
//! See `docs/SPEC-ATTESTATIONS.md` §4.2 and the upstream
//! <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>.
//!
//! Statement shape (JCS-canonical key order shown):
//!
//! ```json
//! {
//!   "_type":         "https://in-toto.io/Statement/v1",
//!   "predicate":     { ... arbitrary JSON object ... },
//!   "predicateType": "<URI>",
//!   "subject":       [ { "digest": { "blake3": "<hex>" }, "name": <optional> } ]
//! }
//! ```
//!
//! mkit never parses `predicate`. Producers hand us a byte slice that is
//! already a JCS-canonical JSON object; we pass it through verbatim
//! inside the enclosing Statement's canonicalisation. This keeps mkit
//! predicate-type-agnostic.

use crate::Error;
use crate::jcs::{self, Member, Value};
use mkit_core::Hash;

/// `_type` URI required for every in-toto v1 Statement.
pub const IN_TOTO_TYPE: &str = "https://in-toto.io/Statement/v1";

/// Single subject entry. `name` is optional per the in-toto spec; mkit
/// emits one subject with `name = "commit"` pointing at the commit's
/// BLAKE3 hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub name: Option<String>,
    pub digest_blake3_hex: String,
}

/// Builder input for [`encode`]. Holds borrowed predicate bytes so the
/// caller does not have to clone an already-canonicalised payload.
#[derive(Debug, Clone)]
pub struct Statement<'a> {
    pub subjects: Vec<Subject>,
    pub predicate_type: String,
    /// Predicate body as already-canonicalised JSON bytes (an OBJECT,
    /// starting with `{` and ending with `}`). mkit does not validate
    /// the internal structure — that's the predicate type's job.
    pub predicate_jcs: &'a [u8],
}

/// Build a JCS-canonical in-toto Statement. Returns the canonical bytes.
///
/// # Errors
///
/// * [`Error::PredicateMustBeJsonObject`] if `predicate_jcs` doesn't
///   start with `{` and end with `}` (cheap boundary check).
/// * [`Error::PredicateNotUtf8`] if `predicate_jcs` is not valid UTF-8.
/// * [`Error::PredicateNotJsonObject`] if `predicate_jcs` passes the
///   boundary check but fails a full JSON parse — covers `{garbage}`,
///   trailing-comma objects, unterminated strings, and other shapes
///   that would slip past a pure-boundary test. We parse-and-discard
///   via `serde_json::Value` (already a dep) and verify the top-level
///   is `Value::Object`.
pub fn encode(stmt: &Statement<'_>) -> Result<String, Error> {
    let pj = stmt.predicate_jcs;
    if pj.len() < 2 || pj[0] != b'{' || pj[pj.len() - 1] != b'}' {
        return Err(Error::PredicateMustBeJsonObject);
    }
    let predicate_str = core::str::from_utf8(pj).map_err(|_| Error::PredicateNotUtf8)?;
    // Full parse-and-discard. Keeps mkit predicate-type-agnostic (we
    // don't inspect the contents) but rejects malformed JSON that the
    // boundary check alone would pass through to the signer.
    match serde_json::from_slice::<serde_json::Value>(pj) {
        Ok(serde_json::Value::Object(_)) => {}
        _ => return Err(Error::PredicateNotJsonObject),
    }

    let mut out = String::new();
    out.push('{');

    // "_type"
    jcs::write_string(&mut out, "_type");
    out.push(':');
    jcs::write_string(&mut out, IN_TOTO_TYPE);
    out.push(',');

    // "predicate" — verbatim pass-through of caller-provided JCS bytes.
    jcs::write_string(&mut out, "predicate");
    out.push(':');
    out.push_str(predicate_str);
    out.push(',');

    // "predicateType"
    jcs::write_string(&mut out, "predicateType");
    out.push(':');
    jcs::write_string(&mut out, &stmt.predicate_type);
    out.push(',');

    // "subject"
    jcs::write_string(&mut out, "subject");
    out.push(':');
    out.push('[');
    for (i, subj) in stmt.subjects.iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        out.push('{');
        // Subject keys in JCS order: digest, (name)
        jcs::write_string(&mut out, "digest");
        out.push(':');
        // {"blake3": "<hex>"}
        let digest_obj = Value::Object(vec![Member::new(
            "blake3",
            Value::String(subj.digest_blake3_hex.clone()),
        )]);
        out.push_str(&jcs::encode(&digest_obj)?);
        if let Some(name) = &subj.name {
            out.push(',');
            jcs::write_string(&mut out, "name");
            out.push(':');
            jcs::write_string(&mut out, name);
        }
        out.push('}');
    }
    out.push(']');

    out.push('}');
    Ok(out)
}

/// Convenience: build a single-subject Statement from a commit hash +
/// predicate. `name` defaults to `"commit"`.
///
/// # Errors
/// Same as [`encode`].
pub fn for_commit(
    commit: &Hash,
    predicate_type: impl Into<String>,
    predicate_jcs: &[u8],
) -> Result<String, Error> {
    let hex = mkit_core::hash::to_hex(commit);
    let stmt = Statement {
        subjects: vec![Subject {
            name: Some("commit".into()),
            digest_blake3_hex: hex,
        }],
        predicate_type: predicate_type.into(),
        predicate_jcs,
    };
    encode(&stmt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_subject_empty_predicate() {
        let got = encode(&Statement {
            subjects: vec![Subject {
                name: Some("commit".into()),
                digest_blake3_hex: "deadbeef".into(),
            }],
            predicate_type: "https://example.com/x".into(),
            predicate_jcs: b"{}",
        })
        .unwrap();
        assert_eq!(
            got,
            "{\"_type\":\"https://in-toto.io/Statement/v1\",\
             \"predicate\":{},\
             \"predicateType\":\"https://example.com/x\",\
             \"subject\":[{\"digest\":{\"blake3\":\"deadbeef\"},\"name\":\"commit\"}]}"
        );
    }

    #[test]
    fn subject_without_name_emits_digest_only() {
        let got = encode(&Statement {
            subjects: vec![Subject {
                name: None,
                digest_blake3_hex: "abcd".into(),
            }],
            predicate_type: "https://example.com/x".into(),
            predicate_jcs: b"{}",
        })
        .unwrap();
        assert_eq!(
            got,
            "{\"_type\":\"https://in-toto.io/Statement/v1\",\
             \"predicate\":{},\
             \"predicateType\":\"https://example.com/x\",\
             \"subject\":[{\"digest\":{\"blake3\":\"abcd\"}}]}"
        );
    }

    #[test]
    fn predicate_body_passes_through_verbatim() {
        let predicate = "{\"buildType\":\"https://ex.com/b\",\"stepCount\":7}";
        let got = encode(&Statement {
            subjects: vec![Subject {
                name: Some("commit".into()),
                digest_blake3_hex: "00".into(),
            }],
            predicate_type: "https://slsa.dev/provenance/v1".into(),
            predicate_jcs: predicate.as_bytes(),
        })
        .unwrap();
        assert!(got.contains(predicate));
    }

    #[test]
    fn rejects_predicate_that_isnt_json_object() {
        let mk = |body: &[u8]| {
            encode(&Statement {
                subjects: vec![Subject {
                    name: None,
                    digest_blake3_hex: "00".into(),
                }],
                predicate_type: "x".into(),
                predicate_jcs: body,
            })
        };
        assert!(matches!(
            mk(b"[1,2,3]"),
            Err(Error::PredicateMustBeJsonObject)
        ));
        assert!(matches!(mk(b""), Err(Error::PredicateMustBeJsonObject)));
        assert!(matches!(mk(b"{"), Err(Error::PredicateMustBeJsonObject)));
    }

    /// Finding H5: the boundary check (`pj[0]=='{'` && `pj[last]=='}'`)
    /// accepted arbitrary junk between the braces. Parsing via
    /// `serde_json` tightens this: object-in-syntax-only (e.g. `{garbage}`
    /// or `{"unterminated":...`) must now be rejected.
    #[test]
    fn rejects_predicate_with_braces_but_invalid_json() {
        let mk = |body: &[u8]| {
            encode(&Statement {
                subjects: vec![Subject {
                    name: None,
                    digest_blake3_hex: "00".into(),
                }],
                predicate_type: "x".into(),
                predicate_jcs: body,
            })
        };
        // Starts `{`, ends `}`, but body is garbage.
        assert!(matches!(
            mk(b"{garbage}"),
            Err(Error::PredicateNotJsonObject)
        ));
        // Trailing comma — invalid JSON even though it boundary-checks.
        assert!(matches!(
            mk(b"{\"a\":1,}"),
            Err(Error::PredicateNotJsonObject)
        ));
    }

    /// JSON array wrapped in an object-shaped envelope must still be
    /// rejected — the top-level JSON VALUE must be an object. A
    /// forward-parsed `[1,2,3]` is a JSON array, not an object, so it
    /// now goes through the stricter (`PredicateMustBeJsonObject`)
    /// path above.
    #[test]
    fn rejects_non_object_top_level() {
        // A valid JSON number wrapped as an "object-like" string
        // (`{42}`) isn't legal JSON; it will hit PredicateNotJsonObject.
        let got = encode(&Statement {
            subjects: vec![Subject {
                name: None,
                digest_blake3_hex: "00".into(),
            }],
            predicate_type: "x".into(),
            predicate_jcs: b"{42}",
        });
        assert!(matches!(got, Err(Error::PredicateNotJsonObject)));
    }

    #[test]
    fn accepts_canonical_object_predicate() {
        let got = encode(&Statement {
            subjects: vec![Subject {
                name: None,
                digest_blake3_hex: "00".into(),
            }],
            predicate_type: "x".into(),
            predicate_jcs: b"{\"k\":\"v\"}",
        })
        .unwrap();
        assert!(got.contains("\"predicate\":{\"k\":\"v\"}"));
    }

    #[test]
    fn for_commit_helper() {
        let commit: Hash = [0xAB; 32];
        let got = for_commit(&commit, "https://example.com/predicate/v1", b"{\"x\":1}").unwrap();
        assert!(got.contains("abababababababababababababababababababababababababababababababab"));
        assert!(got.contains("\"x\":1"));
    }
}
