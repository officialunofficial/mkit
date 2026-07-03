//! Ref-protocol endpoints and DTOs for [`HttpTransport`] (mkit #423).
//!
//! Extracted out of `lib.rs`, which had grown to pack together unrelated
//! concerns (low-level plumbing, blob/pack verbs, and the ref mini-protocol)
//! in one file. The ref verbs (`read_ref`, `list_refs`, `update_ref`,
//! `advance_refs`) share ref-name validation, CAS-condition encoding,
//! capped-JSON-body parsing, and error mapping — this module is where that
//! shared shape lives so it structurally can't be skipped.
//!
//! Origin: during the #421/#422 review, a newly added ref endpoint
//! (`advance_refs`) skipped a shared boundary in two different ways — an
//! unbounded `resp.json()` instead of the capped reader, and a missing
//! `validate_ref_name` before the request was sent. Both were fixed
//! per-callsite in #422; this module exists so a *future* ref endpoint
//! can't reintroduce either bug by hand-rolling the checks.
//!
//! Every `*_impl` method below MUST uphold two invariants:
//!
//! 1. **Validate first.** `mkit_core::refs::validate_ref_name` (or
//!    `validate_ref_prefix`) is the first statement of every method,
//!    before any URL is built or request sent.
//! 2. **Capped parse only.** Every response body is read through
//!    [`HttpTransport::parse_json_body`] with an explicit named cap
//!    constant — never `resp.json()`, never an uncapped read.
//!
//! If you add an endpoint here, both invariants apply; see #421/#422 for
//! the bug class.

use mkit_core::hash::{Hash, from_hex, to_hex};
use mkit_core::protocol::{AdvanceOutcome, RefWriteCondition, TransportError, TransportResult};
use mkit_core::refs::{Ref, validate_ref_name, validate_ref_prefix};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{CONTROL_BODY_LIMIT, HttpTransport, REF_LIST_BODY_LIMIT, cas_headers, map_status};

// ---------------------------------------------------------------------------
// JSON request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct RefPayload {
    hash: String,
}

/// JSON body for `POST <base>/refs/advance` (mkit #408): the two ref specs
/// the server commits atomically. Mirrors the makechain vcs endpoint.
#[derive(Debug, Serialize)]
struct AdvanceBody {
    head: RefAdvanceJson,
    packmap: RefAdvanceJson,
}

#[derive(Debug, Serialize)]
struct RefAdvanceJson {
    #[serde(rename = "ref")]
    ref_name: String,
    value: String,
    condition: CondJson,
}

/// CAS precondition in the advance body. `Any` has no representation — the
/// server's ref API has no unconditional write — so callers fall back to the
/// ordered two-CAS for that case ([`cond_to_json`] returns `None`).
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum CondJson {
    Missing,
    Match { expected: String },
}

/// 412 response body: which precondition failed.
#[derive(Debug, Deserialize)]
struct AdvanceConflictBody {
    conflict: String,
}

/// Map a CAS condition to its advance-body JSON. `Any` → `None` (not
/// expressible on the atomic endpoint; caller uses the ordered fallback).
fn cond_to_json(cond: RefWriteCondition) -> Option<CondJson> {
    match cond {
        RefWriteCondition::Missing => Some(CondJson::Missing),
        RefWriteCondition::Match(h) => Some(CondJson::Match {
            expected: to_hex(&h),
        }),
        RefWriteCondition::Any => None,
    }
}

#[derive(Debug, Deserialize)]
struct RefListEntry {
    name: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct RefListResponse {
    refs: Vec<RefListEntry>,
}

impl HttpTransport {
    fn ref_url(&self, name: &str) -> TransportResult<Url> {
        let mut u = self.base.clone();
        {
            let mut seg = u
                .path_segments_mut()
                .map_err(|()| TransportError::InvalidResponse)?;
            seg.pop_if_empty().push("refs");
            // Ref names contain `/` separators (`refs/heads/main`). We've
            // already validated via `validate_ref_name` — push each
            // segment so the url crate percent-encodes safely without
            // collapsing the slashes.
            for part in name.split('/') {
                seg.push(part);
            }
        }
        Ok(u)
    }

    /// URL for the atomic two-ref advance endpoint: `<base>/refs/advance`.
    fn advance_url(&self) -> TransportResult<Url> {
        let mut u = self.base.clone();
        u.path_segments_mut()
            .map_err(|()| TransportError::InvalidResponse)?
            .pop_if_empty()
            .push("refs")
            .push("advance");
        Ok(u)
    }

    fn refs_list_url(&self, prefix: &str) -> TransportResult<Url> {
        let mut u = self.base.clone();
        u.path_segments_mut()
            .map_err(|()| TransportError::InvalidResponse)?
            .pop_if_empty()
            .push("refs");
        // Always set `prefix=`, even when empty, so the Worker can
        // distinguish "list all refs" from a missing query parameter.
        u.query_pairs_mut().clear().append_pair("prefix", prefix);
        Ok(u)
    }

    /// Ordered non-atomic fallback (packmap first, then head) — identical to
    /// the [`mkit_core::protocol::Transport::advance_refs`] default. Used
    /// when a precondition is `Any`, which the atomic endpoint can't express.
    fn advance_refs_ordered(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        match self.update_ref_impl(packmap_ref, packmap_condition, packmap_value) {
            Ok(()) => {}
            Err(TransportError::RefConflict) => return Ok(AdvanceOutcome::PackmapConflict),
            Err(e) => return Err(e),
        }
        match self.update_ref_impl(head_ref, head_condition, head_value) {
            Ok(()) => Ok(AdvanceOutcome::Committed),
            Err(TransportError::RefConflict) => Ok(AdvanceOutcome::HeadConflict),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn update_ref_impl(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_string()));
        }
        let url = self.ref_url(name)?;
        let body = RefPayload { hash: to_hex(hash) };
        let body_json = serde_json::to_vec(&body).map_err(|_| TransportError::InvalidResponse)?;
        let headers = cas_headers(condition);

        let resp = self.retrying(|| {
            let mut r = self
                .client
                .put(url.clone())
                .header("Content-Type", "application/json")
                .headers(headers.clone())
                .body(body_json.clone());
            r = self.apply_auth(r);
            r
        })?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            // On a write, 404 should not normally happen — the server
            // creates refs on PUT. Treat as InvalidRef for clarity.
            Err(map_status(
                status,
                TransportError::InvalidRef(name.to_string()),
            ))
        }
    }

    /// Atomic two-ref advance (#408): one `POST <base>/refs/advance` carrying
    /// both ref specs, which the makechain vcs endpoint commits in a single
    /// Durable-Object transaction. Auth mirrors `update_ref` (the same bearer
    /// `apply_auth`). A `412` body names which precondition failed. `Any`
    /// conditions aren't expressible on the endpoint, so they fall back to the
    /// ordered two-CAS.
    pub(crate) fn advance_refs_impl(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<AdvanceOutcome> {
        // Same client-side ref-name boundary `update_ref` enforces — an
        // invalid ref must not reach the wire.
        if !validate_ref_name(head_ref) {
            return Err(TransportError::InvalidRef(head_ref.to_string()));
        }
        if !validate_ref_name(packmap_ref) {
            return Err(TransportError::InvalidRef(packmap_ref.to_string()));
        }

        let (Some(head_cond), Some(packmap_cond)) = (
            cond_to_json(head_condition),
            cond_to_json(packmap_condition),
        ) else {
            return self.advance_refs_ordered(
                head_ref,
                head_condition,
                head_value,
                packmap_ref,
                packmap_condition,
                packmap_value,
            );
        };

        let url = self.advance_url()?;
        let body = AdvanceBody {
            head: RefAdvanceJson {
                ref_name: head_ref.to_string(),
                value: to_hex(head_value),
                condition: head_cond,
            },
            packmap: RefAdvanceJson {
                ref_name: packmap_ref.to_string(),
                value: to_hex(packmap_value),
                condition: packmap_cond,
            },
        };
        let body_json = serde_json::to_vec(&body).map_err(|_| TransportError::InvalidResponse)?;

        let resp = self.retrying(|| {
            let r = self
                .client
                .post(url.clone())
                .header("Content-Type", "application/json")
                .body(body_json.clone());
            self.apply_auth(r)
        })?;

        let status = resp.status();
        if status.is_success() {
            return Ok(AdvanceOutcome::Committed);
        }
        if status == StatusCode::PRECONDITION_FAILED {
            let parsed: AdvanceConflictBody = Self::parse_json_body(resp, CONTROL_BODY_LIMIT)?;
            return match parsed.conflict.as_str() {
                "head" => Ok(AdvanceOutcome::HeadConflict),
                "packmap" => Ok(AdvanceOutcome::PackmapConflict),
                _ => Err(TransportError::InvalidResponse),
            };
        }
        Err(map_status(status, TransportError::InvalidResponse))
    }

    pub(crate) fn read_ref_impl(&self, name: &str) -> TransportResult<Option<Hash>> {
        if !validate_ref_name(name) {
            return Err(TransportError::InvalidRef(name.to_string()));
        }
        let url = self.ref_url(name)?;
        let resp = self.retrying(|| self.apply_auth(self.client.get(url.clone())))?;
        let status = resp.status();

        if status.as_u16() == 404 {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(map_status(
                status,
                TransportError::InvalidRef(name.to_string()),
            ));
        }

        // Bounded parse — a hostile remote can't OOM us with a giant body in
        // place of the tiny `{"hash": "<hex>"}` payload.
        let parsed: RefPayload = Self::parse_json_body(resp, CONTROL_BODY_LIMIT)?;
        let h = from_hex(&parsed.hash).map_err(|_| TransportError::InvalidResponse)?;
        Ok(Some(h))
    }

    pub(crate) fn list_refs_impl(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        if !validate_ref_prefix(prefix) {
            return Err(TransportError::InvalidRef(prefix.to_string()));
        }
        let url = self.refs_list_url(prefix)?;
        let resp = self.retrying(|| self.apply_auth(self.client.get(url.clone())))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_status(
                status,
                TransportError::InvalidRef(prefix.to_string()),
            ));
        }

        // Bounded parse at the list limit — a hostile remote can't OOM us
        // with an unbounded ref-list body (never trusting Content-Length).
        let parsed: RefListResponse = Self::parse_json_body(resp, REF_LIST_BODY_LIMIT)?;

        let mut out: Vec<Ref> = Vec::with_capacity(parsed.refs.len());
        let full_prefix = prefix.trim_end_matches('/');
        let full_prefix_with_slash = if full_prefix.is_empty() {
            String::new()
        } else {
            format!("{full_prefix}/")
        };
        for entry in parsed.refs {
            // Strip the query prefix if the server included it — keeps
            // the list_refs contract identical to the memory / file
            // transports.
            let stripped = if full_prefix_with_slash.is_empty() {
                entry.name.as_str()
            } else if let Some(relative) = entry.name.strip_prefix(&full_prefix_with_slash) {
                relative
            } else if entry.name.starts_with("refs/") {
                return Err(TransportError::InvalidRef(entry.name));
            } else {
                entry.name.as_str()
            }
            .to_string();
            if !validate_ref_name(&stripped) {
                return Err(TransportError::InvalidRef(entry.name));
            }
            let hash = from_hex(&entry.hash).map_err(|_| TransportError::InvalidResponse)?;
            out.push(Ref {
                name: stripped,
                hash: Some(hash),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)] // `env::remove_var` is unsafe in edition 2024.
mod tests {
    use super::*;
    use crate::TOKEN_ENV;
    use crate::tests::{make_transport, sample_hash};
    use mkit_core::protocol::Transport;
    use mockito::{Matcher, Server};
    use std::env;

    // -- advance_refs (#408) -----------------------------------------------

    #[test]
    fn advance_refs_posts_both_specs_and_commits() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/myproj/refs/advance")
            .match_header("content-type", "application/json")
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex(r#""ref":"refs/heads/main""#.into()),
                Matcher::Regex(r#""ref":"refs/mkit/packmap/main""#.into()),
                Matcher::Regex(r#""kind":"missing""#.into()),
            ]))
            .with_status(200)
            .with_body(r#"{"ok":true}"#)
            .create();
        let t = make_transport(&server, Some("tok"));
        let out = t
            .advance_refs(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &sample_hash(1),
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                &sample_hash(2),
            )
            .unwrap();
        assert_eq!(out, AdvanceOutcome::Committed);
    }

    #[test]
    fn advance_refs_412_head_conflict() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/myproj/refs/advance")
            .with_status(412)
            .with_body(r#"{"ok":false,"conflict":"head"}"#)
            .create();
        let t = make_transport(&server, Some("tok"));
        let out = t
            .advance_refs(
                "refs/heads/main",
                RefWriteCondition::Match(sample_hash(9)),
                &sample_hash(1),
                "refs/mkit/packmap/main",
                RefWriteCondition::Match(sample_hash(2)),
                &sample_hash(3),
            )
            .unwrap();
        assert_eq!(out, AdvanceOutcome::HeadConflict);
    }

    #[test]
    fn advance_refs_412_packmap_conflict() {
        let mut server = Server::new();
        let _m = server
            .mock("POST", "/myproj/refs/advance")
            .with_status(412)
            .with_body(r#"{"ok":false,"conflict":"packmap"}"#)
            .create();
        let t = make_transport(&server, Some("tok"));
        let out = t
            .advance_refs(
                "refs/heads/main",
                RefWriteCondition::Match(sample_hash(1)),
                &sample_hash(4),
                "refs/mkit/packmap/main",
                RefWriteCondition::Match(sample_hash(9)),
                &sample_hash(5),
            )
            .unwrap();
        assert_eq!(out, AdvanceOutcome::PackmapConflict);
    }

    #[test]
    fn advance_refs_any_condition_falls_back_to_ordered_two_cas() {
        // `Any` (force) isn't expressible on the atomic endpoint, so the
        // override must NOT hit /refs/advance — it writes packmap then head.
        let mut server = Server::new();
        let _pm = server
            .mock("PUT", "/myproj/refs/refs/mkit/packmap/main")
            .with_status(200)
            .create();
        let _head = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .with_status(200)
            .create();
        let t = make_transport(&server, Some("tok"));
        let out = t
            .advance_refs(
                "refs/heads/main",
                RefWriteCondition::Any,
                &sample_hash(1),
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                &sample_hash(2),
            )
            .unwrap();
        assert_eq!(out, AdvanceOutcome::Committed);
    }

    #[test]
    fn advance_refs_oversized_412_body_is_payload_too_large() {
        // A hostile remote can't OOM us with a giant body in place of the
        // tiny `{"conflict": "..."}` payload — the control body is capped.
        let mut server = Server::new();
        let huge = vec![b'a'; CONTROL_BODY_LIMIT + 1];
        let _m = server
            .mock("POST", "/myproj/refs/advance")
            .with_status(412)
            .with_body(huge)
            .create();
        let t = make_transport(&server, Some("tok"));
        let err = t
            .advance_refs(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &sample_hash(1),
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                &sample_hash(2),
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::PayloadTooLarge(_)));
    }

    #[test]
    fn advance_refs_rejects_invalid_ref_name_without_sending() {
        // No mock is registered — an invalid ref name must be rejected
        // client-side before any request is sent.
        let server = Server::new();
        let t = make_transport(&server, Some("tok"));
        let err = t
            .advance_refs(
                "refs/heads/..", // `..` segment is invalid per validate_ref_name
                RefWriteCondition::Missing,
                &sample_hash(1),
                "refs/mkit/packmap/main",
                RefWriteCondition::Missing,
                &sample_hash(2),
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    // -- read_ref ------------------------------------------------------------

    #[test]
    fn read_ref_200_returns_hash() {
        let mut server = Server::new();
        let expected = sample_hash(0xEE);
        let body = format!(r#"{{"hash":"{}"}}"#, to_hex(&expected));
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(200)
            .with_body(body)
            .create();
        let t = make_transport(&server, None);
        assert_eq!(t.read_ref("refs/heads/main").unwrap(), Some(expected));
    }

    #[test]
    fn read_ref_oversized_body_is_payload_too_large() {
        // A multi-MB body in place of the tiny `{"hash":...}` payload
        // must be rejected by the running cap, not buffered to OOM.
        let mut server = Server::new();
        let huge = vec![b'a'; CONTROL_BODY_LIMIT + 1];
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(200)
            .with_body(huge)
            .create();
        let t = make_transport(&server, None);
        assert!(matches!(
            t.read_ref("refs/heads/main"),
            Err(TransportError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn list_refs_oversized_body_is_payload_too_large() {
        let mut server = Server::new();
        let huge = vec![b'a'; REF_LIST_BODY_LIMIT + 1];
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(200)
            .with_body(huge)
            .create();
        let t = make_transport(&server, None);
        assert!(matches!(
            t.list_refs("refs/heads/"),
            Err(TransportError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn read_ref_404_returns_none() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/missing")
            .with_status(404)
            .create();
        let t = make_transport(&server, None);
        assert_eq!(t.read_ref("refs/heads/missing").unwrap(), None);
    }

    #[test]
    fn read_ref_rejects_invalid_name() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+https://example.com/p").unwrap();
        let err = t.read_ref("../escape").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn read_ref_401_is_access_denied() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(401)
            .create();
        let t = make_transport(&server, None);
        let err = t.read_ref("refs/heads/main").unwrap_err();
        assert!(matches!(err, TransportError::AccessDenied));
    }

    #[test]
    fn read_ref_malformed_json_is_invalid_response() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", "/myproj/refs/refs/heads/main")
            .with_status(200)
            .with_body("not json")
            .create();
        let t = make_transport(&server, None);
        let err = t.read_ref("refs/heads/main").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    // -- update_ref / write_ref ----------------------------------------------

    #[test]
    fn update_ref_200_with_if_none_match_on_missing() {
        let mut server = Server::new();
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .match_header("if-none-match", "*")
            .match_header("content-type", "application/json")
            .with_status(200)
            .create();
        let t = make_transport(&server, Some("tok"));
        t.update_ref(
            "refs/heads/main",
            RefWriteCondition::Missing,
            &sample_hash(1),
        )
        .unwrap();
    }

    #[test]
    fn update_ref_412_is_ref_conflict() {
        let mut server = Server::new();
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .with_status(412)
            .create();
        let t = make_transport(&server, Some("tok"));
        let err = t
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Missing,
                &sample_hash(1),
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
    }

    #[test]
    fn update_ref_409_is_ref_conflict() {
        let mut server = Server::new();
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .with_status(409)
            .create();
        let t = make_transport(&server, Some("tok"));
        let err = t
            .update_ref(
                "refs/heads/main",
                RefWriteCondition::Match(sample_hash(2)),
                &sample_hash(1),
            )
            .unwrap_err();
        assert!(matches!(err, TransportError::RefConflict));
    }

    #[test]
    fn update_ref_sends_if_match_quoted_hex_on_match() {
        let mut server = Server::new();
        let expected = sample_hash(0x99);
        let quoted = format!(r#""{}""#, to_hex(&expected));
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/main")
            .match_header("if-match", Matcher::Exact(quoted))
            .with_status(200)
            .create();
        let t = make_transport(&server, Some("tok"));
        t.update_ref(
            "refs/heads/main",
            RefWriteCondition::Match(expected),
            &sample_hash(0xAA),
        )
        .unwrap();
    }

    #[test]
    fn write_ref_delegates_to_any_and_no_conditional_header() {
        let mut server = Server::new();
        let _m = server
            .mock("PUT", "/myproj/refs/refs/heads/dev")
            .match_header("if-none-match", Matcher::Missing)
            .match_header("if-match", Matcher::Missing)
            .with_status(200)
            .create();
        let t = make_transport(&server, Some("tok"));
        t.write_ref("refs/heads/dev", &sample_hash(0xCC)).unwrap();
    }

    // -- list_refs -------------------------------------------------------

    #[test]
    fn list_refs_200_parses_and_sorts() {
        let mut server = Server::new();
        let h1 = sample_hash(0x01);
        let h2 = sample_hash(0x02);
        let body = format!(
            r#"{{"refs":[{{"name":"zulu","hash":"{}"}},{{"name":"alpha","hash":"{}"}}]}}"#,
            to_hex(&h1),
            to_hex(&h2),
        );
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(200)
            .with_body(body)
            .create();
        let t = make_transport(&server, None);
        let refs = t.list_refs("refs/heads/").unwrap();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].name, "alpha");
        assert_eq!(refs[1].name, "zulu");
        assert_eq!(refs[0].hash, Some(h2));
    }

    #[test]
    fn list_refs_500_is_server_error() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(500)
            .expect_at_least(2)
            .create();
        let t = make_transport(&server, None);
        let err = t.list_refs("refs/heads/").unwrap_err();
        assert!(matches!(err, TransportError::ServerError { status: 500 }));
    }

    #[test]
    fn list_refs_rejects_invalid_prefix() {
        unsafe { env::remove_var(TOKEN_ENV) };
        let t = HttpTransport::connect("mkit+https://example.com/p").unwrap();
        let err = t.list_refs("bad//prefix").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn list_refs_rejects_invalid_response_ref_name() {
        let mut server = Server::new();
        let body = format!(
            r#"{{"refs":[{{"name":"bad//name","hash":"{}"}}]}}"#,
            to_hex(&sample_hash(0xAB)),
        );
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(200)
            .with_body(body)
            .create();
        let t = make_transport(&server, None);
        let err = t.list_refs("refs/heads/").unwrap_err();
        assert!(matches!(err, TransportError::InvalidRef(_)));
    }

    #[test]
    fn list_refs_rejects_invalid_response_hash() {
        let mut server = Server::new();
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(200)
            .with_body(r#"{"refs":[{"name":"main","hash":"not-hex"}]}"#)
            .create();
        let t = make_transport(&server, None);
        let err = t.list_refs("refs/heads/").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    #[test]
    fn list_refs_accepts_full_names_with_prefix_without_trailing_slash() {
        let mut server = Server::new();
        let h = sample_hash(0xB0);
        let body = format!(
            r#"{{"refs":[{{"name":"refs/heads/main","hash":"{}"}}]}}"#,
            to_hex(&h),
        );
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(200)
            .with_body(body)
            .create();
        let t = make_transport(&server, None);
        let refs = t.list_refs("refs/heads").unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "main");
        assert_eq!(refs[0].hash, Some(h));
    }

    #[test]
    fn list_refs_rejects_full_names_outside_requested_prefix() {
        let mut server = Server::new();
        let body = format!(
            r#"{{"refs":[{{"name":"refs/tags/v1","hash":"{}"}}]}}"#,
            to_hex(&sample_hash(0xB1)),
        );
        let _m = server
            .mock("GET", Matcher::Regex(r"^/myproj/refs\?prefix=".to_string()))
            .with_status(200)
            .with_body(body)
            .create();
        let t = make_transport(&server, None);
        let err = t.list_refs("refs/heads/").unwrap_err();

        assert!(matches!(err, TransportError::InvalidRef(_)));
    }
}
