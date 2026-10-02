//! The SPEC-HTTP-OBJECTS §2 URL grammar. Pure and URL-only: every failure is
//! a 400 that depends on the request text and the route grammar alone, never
//! on stored state (§2, §3 step 3).

use mkit_core::hash::{Hash, from_hex};
use mkit_core::object::TreeEntry;
use mkit_core::repo_identity::RepositoryIdentity;

use crate::Redacted;

/// Longest ref name a route may carry, in bytes (§2).
const MAX_REF_BYTES: usize = 512;
/// Longest joined decoded file path, in bytes (§2).
const MAX_PATH_BYTES: usize = 1024;

/// Whether a repository prefix must be present. The handler always uses
/// [`Self::Required`] (indexed mode implies Multi addressing); `Omitted`
/// exists so the parser runs every single-repository golden vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoPrefix {
    /// `/<namespace>/<name>/-/...` only.
    Required,
    /// A bare name or a namespaced identity, or no prefix at all.
    Omitted,
}

/// The URL is not valid under §2. Carries no detail: a 400 is URL-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadUrl;

/// What the URL selects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `objects/<64hex>`.
    Object(Hash),
    /// A ref and the decoded entry names below its tree; empty selects the
    /// root tree.
    Ref {
        /// The full ref name, e.g. `refs/heads/main`.
        name: String,
        /// One decoded (non-UTF-8 allowed) name per path segment.
        path: Vec<Vec<u8>>,
    },
}

/// The parsed query (§2). The token is opaque here and never printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    /// `proof=1` was present.
    pub proof: bool,
    /// The inclusive proof range `a-b`.
    pub range: Option<(u64, u64)>,
    /// The proof context commit.
    pub commit: Option<Hash>,
    /// The proof context path; `Some(vec![])` is the root.
    pub path: Option<Vec<Vec<u8>>>,
    /// The URL token, held redacted (§6).
    pub token: Option<Redacted>,
}

/// A URL that satisfied §2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    /// The repository prefix; `None` only under [`RepoPrefix::Omitted`].
    pub repository: Option<RepositoryIdentity>,
    /// The object or ref selected.
    pub target: Target,
    /// The query parameters.
    pub query: Query,
}

/// Whether `raw_path` belongs to the HTTP object namespace: it contains the
/// mandatory `/-/` segment that RPC service paths never do (§2). Routers
/// dispatch on this, never on a `/grpc.*` prefix glob.
#[must_use]
pub fn is_http_object_path(raw_path: &str) -> bool {
    raw_path.contains("/-/")
}

fn lower_hex_id(text: &str) -> Option<Hash> {
    let lowercase = text
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    (text.len() == 64 && lowercase)
        .then(|| from_hex(text).ok())
        .flatten()
}

/// Decode a `file-path` (or `pct-path`): each segment is unreserved or
/// percent-escaped, decoded exactly once, and one valid entry name; `+` and
/// raw reserved bytes are rejected. The joined length is 1..=1024, or the
/// path is empty (the root).
fn decode_path(text: &str) -> Result<Vec<Vec<u8>>, BadUrl> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    let mut total = 0_usize;
    for segment in text.split('/') {
        let raw = segment.as_bytes();
        let mut name = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' {
                let digits = raw.get(i + 1..i + 3).ok_or(BadUrl)?;
                if !digits.iter().all(u8::is_ascii_hexdigit) {
                    return Err(BadUrl);
                }
                let text = core::str::from_utf8(digits).map_err(|_| BadUrl)?;
                name.push(u8::from_str_radix(text, 16).map_err(|_| BadUrl)?);
                i += 3;
            } else if raw[i].is_ascii_alphanumeric() || b"-._~".contains(&raw[i]) {
                name.push(raw[i]);
                i += 1;
            } else {
                return Err(BadUrl);
            }
        }
        if !TreeEntry::validate_name(&name) {
            return Err(BadUrl);
        }
        total += name.len() + 1;
        names.push(name);
    }
    // `total` counted one separator too many.
    if total - 1 > MAX_PATH_BYTES {
        return Err(BadUrl);
    }
    Ok(names)
}

fn parse_range(value: &str) -> Result<(u64, u64), BadUrl> {
    let (a, b) = value.split_once('-').ok_or(BadUrl)?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(a) || !digits(b) {
        return Err(BadUrl);
    }
    let (a, b) = (
        a.parse::<u64>().map_err(|_| BadUrl)?,
        b.parse::<u64>().map_err(|_| BadUrl)?,
    );
    if a > b {
        return Err(BadUrl);
    }
    Ok((a, b))
}

fn parse_query(raw: Option<&str>) -> Result<Query, BadUrl> {
    let mut query = Query::default();
    let Some(raw) = raw else {
        return Ok(query);
    };
    if raw.is_empty() {
        return Err(BadUrl);
    }
    let mut seen = [false; 5];
    for param in raw.split('&') {
        let (name, value) = param.split_once('=').ok_or(BadUrl)?;
        let slot = match name {
            "proof" => 0,
            "range" => 1,
            "commit" => 2,
            "path" => 3,
            "token" => 4,
            _ => return Err(BadUrl),
        };
        if core::mem::replace(&mut seen[slot], true) {
            return Err(BadUrl);
        }
        match slot {
            0 if value == "1" => query.proof = true,
            1 => query.range = Some(parse_range(value)?),
            2 => query.commit = Some(lower_hex_id(value).ok_or(BadUrl)?),
            3 => query.path = Some(decode_path(value)?),
            4 => query.token = Some(Redacted::new(value)),
            _ => return Err(BadUrl),
        }
    }
    if query.range.is_some() && !query.proof {
        return Err(BadUrl);
    }
    Ok(query)
}

/// Parse a binding's request, exposing the redacted query only here.
pub(crate) fn parse_request(request: &super::HttpObjectRequest<'_>) -> Result<ParsedUrl, BadUrl> {
    parse(
        request.raw_path,
        request.raw_query.map(|query| query.0),
        RepoPrefix::Required,
    )
}

/// Parse a request's escaped path and query per §2. The caller passes the
/// path exactly as received: framework decoding must not reinterpret
/// delimiters. A `#` anywhere is invalid.
///
/// # Errors
/// [`BadUrl`] for any §2 violation.
pub fn parse(
    raw_path: &str,
    raw_query: Option<&str>,
    prefix: RepoPrefix,
) -> Result<ParsedUrl, BadUrl> {
    if raw_path.contains(['#', '?']) || raw_query.is_some_and(|q| q.contains('#')) {
        return Err(BadUrl);
    }
    let (head, form) = raw_path.split_once("/-/").ok_or(BadUrl)?;
    let repository = if head.is_empty() {
        match prefix {
            RepoPrefix::Required => return Err(BadUrl),
            RepoPrefix::Omitted => None,
        }
    } else {
        let identity = head.strip_prefix('/').ok_or(BadUrl)?;
        Some(
            match prefix {
                RepoPrefix::Required => RepositoryIdentity::parse(identity),
                RepoPrefix::Omitted => RepositoryIdentity::parse_bare_allowed(identity),
            }
            .map_err(|_| BadUrl)?,
        )
    };
    let query = parse_query(raw_query)?;
    let target = if let Some(id) = form.strip_prefix("objects/") {
        if query.proof && (query.commit.is_none() || query.path.is_none()) {
            return Err(BadUrl);
        }
        Target::Object(lower_hex_id(id).ok_or(BadUrl)?)
    } else {
        // The ref ends at the first segment exactly `-`; the second `/-/` is
        // mandatory even for the root tree.
        let (name, file) = form.split_once("/-/").ok_or(BadUrl)?;
        if !name.starts_with("refs/")
            || name.len() > MAX_REF_BYTES
            || name.contains('%')
            || !crate::refs::validate_ref_name(name)
        {
            return Err(BadUrl);
        }
        Target::Ref {
            name: name.to_owned(),
            path: decode_path(file)?,
        }
    };
    Ok(ParsedUrl {
        repository,
        target,
        query,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::collections::BTreeSet;

    use mkit_core::hash::to_hex;
    use proptest::prelude::*;
    use serde_json::Value;

    use super::*;

    const VECTORS: &str = include_str!("../../../../tests/golden/http-objects/url-parse.json");

    fn hex(bytes: &[u8]) -> String {
        mkit_core::hash::to_hex_bytes(bytes)
    }

    /// Every row of `url-parse.json` against the product parser: accepted
    /// rows parse to the pinned selection, every other row is a 400.
    #[test]
    fn all_url_vectors() {
        let table: Value = serde_json::from_str(VECTORS).unwrap();
        let cases = table["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 75);
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let url = case["request"]["url"].as_str().unwrap();
            let single = case["request"]["single_repository"].as_bool().unwrap();
            let (path, query) = url
                .split_once('?')
                .map_or((url, None), |(path, query)| (path, Some(query)));
            let mode = if single {
                RepoPrefix::Omitted
            } else {
                RepoPrefix::Required
            };
            let got = parse(path, query, mode);
            let expect = &case["expect"];
            if expect["status"] != 200 {
                assert_eq!(got, Err(BadUrl), "{name}");
                continue;
            }
            let got = got.unwrap_or_else(|_| panic!("{name} must parse"));
            let want = &expect["parsed"];
            assert_eq!(
                got.repository.as_ref().map(ToString::to_string),
                want["repository"].as_str().map(str::to_owned),
                "{name}: repository"
            );
            match &got.target {
                Target::Object(id) => {
                    assert_eq!(want["kind"], "object", "{name}");
                    assert_eq!(want["object"].as_str().unwrap(), to_hex(id), "{name}");
                }
                Target::Ref { name: r, path } => {
                    assert_eq!(want["kind"], "ref", "{name}");
                    assert_eq!(want["ref"].as_str().unwrap(), r, "{name}");
                    let names: Vec<_> = path.iter().map(|n| hex(n)).collect();
                    let pinned: Vec<_> = want["path_hex"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_owned())
                        .collect();
                    assert_eq!(names, pinned, "{name}: path");
                }
            }
            assert_eq!(got.query.proof, want["proof"].as_bool().unwrap(), "{name}");
            let pinned_query = want["query"].as_object().unwrap();
            let present: BTreeSet<&str> = [
                ("proof", got.query.proof),
                ("range", got.query.range.is_some()),
                ("commit", got.query.commit.is_some()),
                ("path", got.query.path.is_some()),
                ("token", got.query.token.is_some()),
            ]
            .into_iter()
            .filter_map(|(key, on)| on.then_some(key))
            .collect();
            let pinned_keys: BTreeSet<&str> = pinned_query.keys().map(String::as_str).collect();
            assert_eq!(present, pinned_keys, "{name}: query keys");
            if let Some((a, b)) = got.query.range {
                let text = pinned_query["range"].as_str().unwrap();
                let (pa, pb) = text.split_once('-').unwrap();
                assert_eq!((a, b), (pa.parse().unwrap(), pb.parse().unwrap()), "{name}");
            }
            if let Some(commit) = got.query.commit {
                assert_eq!(pinned_query["commit"].as_str().unwrap(), to_hex(&commit));
            }
            if let Some(names) = &got.query.path {
                let joined: Vec<u8> = names.join(&b'/');
                assert_eq!(
                    pinned_query["path"].as_str().unwrap().replace('%', ""),
                    String::from_utf8_lossy(&joined).replace('%', ""),
                    "{name}: context path"
                );
            }
        }
    }

    #[test]
    fn a_token_is_opaque_redacted_and_never_a_400() {
        let base = "/ed25519-b0145b689c72cfb1b8b1e7ec756c2c4a1e0b4f0469393e4ff4a30d8c3d6a0d6f/r/-/refs/heads/main/-/";
        for token in ["", "not-a-token", "%zz", "a=b=c", "AAAA.BBBB"] {
            let query = format!("token={token}");
            let parsed = parse(base, Some(&query), RepoPrefix::Required).unwrap();
            let secret = parsed.query.token.unwrap();
            assert_eq!(secret.expose(), token);
            assert!(!format!("{secret:?}").contains(token) || token.is_empty());
        }
        assert!(parse(base, Some("token=a&token=b"), RepoPrefix::Required).is_err());
        assert!(parse(base, Some("token=a#b"), RepoPrefix::Required).is_err());
    }

    #[test]
    fn dispatch_is_on_the_dash_segment() {
        assert!(is_http_object_path("/ns/repo/-/objects/x"));
        assert!(is_http_object_path("/-/refs/heads/main/-/"));
        for rpc in [
            "/mkit.transport.v1.TransportService/ReadRef",
            "/grpc.health.v1.Health/Check",
            "/.well-known/mkit-url-token-keys.json",
            "/",
        ] {
            assert!(!is_http_object_path(rpc), "{rpc}");
        }
    }

    fn escape(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, b| {
            write!(out, "%{b:02X}").unwrap();
            out
        })
    }

    #[test]
    fn path_names_after_the_delimiter_obey_entry_name_rules() {
        for reserved in ["con", "nul", "prn", "aux"] {
            let url = format!("/-/refs/heads/a/-/{reserved}");
            assert_eq!(parse(&url, None, RepoPrefix::Omitted), Err(BadUrl));
        }
        let parsed = parse("/-/refs/heads/con/-/a/-/b", None, RepoPrefix::Omitted).unwrap();
        assert_eq!(
            parsed.target,
            Target::Ref {
                name: "refs/heads/con".into(),
                path: vec![b"a".to_vec(), b"-".to_vec(), b"b".to_vec()],
            }
        );
    }

    proptest! {
        /// Every name is percent-decoded exactly once, whatever it holds.
        #[test]
        fn a_decoded_name_round_trips(name in proptest::collection::vec(any::<u8>(), 1..40)) {
            let url = format!("/-/refs/heads/main/-/{}", escape(&name));
            let parsed = parse(&url, None, RepoPrefix::Omitted);
            if mkit_core::object::TreeEntry::validate_name(&name) {
                let Target::Ref { path, .. } = parsed.unwrap().target else { panic!() };
                prop_assert_eq!(path, vec![name]);
            } else {
                prop_assert_eq!(parsed, Err(BadUrl));
            }
        }

        /// The first `/-/` ends the ref: whatever follows is path text, and a
        /// `-` in the path is an ordinary entry name.
        #[test]
        fn the_first_dash_segment_delimits_the_ref(
            branch in "[a-z]{1,8}",
            rest in proptest::collection::vec("[a-z]{1,5}|-", 0..4),
        ) {
            let file = rest.join("/");
            let url = format!("/-/refs/heads/{branch}/-/{file}");
            let parsed = parse(&url, None, RepoPrefix::Omitted);
            if rest.iter().all(|segment| TreeEntry::validate_name(segment.as_bytes())) {
                let Target::Ref { name, path } = parsed.unwrap().target else { panic!() };
                prop_assert_eq!(name, format!("refs/heads/{branch}"));
                let expected: Vec<_> = rest.iter().map(|segment| segment.as_bytes().to_vec()).collect();
                prop_assert_eq!(path, expected);
            } else {
                prop_assert_eq!(parsed, Err(BadUrl));
            }
        }

        /// A 400 depends on the URL text alone: parsing twice agrees, and no
        /// input panics.
        #[test]
        fn syntax_is_pure(path in "\\PC{0,60}", query in proptest::option::of("\\PC{0,40}")) {
            for mode in [RepoPrefix::Required, RepoPrefix::Omitted] {
                prop_assert_eq!(
                    parse(&path, query.as_deref(), mode),
                    parse(&path, query.as_deref(), mode)
                );
            }
        }
    }
}
