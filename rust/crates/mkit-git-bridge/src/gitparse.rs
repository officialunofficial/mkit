//! Tolerant parsers for ARBITRARY git object bytes
//! (SPEC-GIT-IMPORT §2, §3).
//!
//! This is the import direction's untrusted-input boundary, and its
//! contract is the opposite of [`crate::reconstruct`]'s: reconstruct
//! is strict by design (it proves bridge shape and MUST stay that
//! way); these parsers accept everything git itself accepts —
//! multi-line continuation headers (`gpgsig`, `mergetag`), unknown
//! headers, the `encoding` header, historic malformed person lines —
//! and either parse faithfully or refuse loudly. They never crash on
//! malformed input and never silently alter bytes (fuzzed; see
//! FUZZ.md).
//!
//! Parsers stop at structure: policy (mode normalization vs fork-mode
//! refusal, name legality, timestamp range) lives in the import
//! driver, which maps [`GitParseError`] / parsed values onto
//! [`crate::error::Refusal`].

use crate::gitobj::{Sha1Id, sha1_from_hex};
use std::fmt;

/// Hard cap on a commit/tag header block (everything before the blank
/// line). Real gpgsig/mergetag blocks are a few KiB; 10 MiB refuses
/// pathological input before any allocation amplification.
pub const MAX_HEADER_BLOCK: usize = 10 * 1024 * 1024;

/// Structural parse failure (not policy — see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitParseError {
    /// No `\n\n` header/message separator, or header block over the cap.
    Malformed(&'static str),
    /// A required header (`tree`, `object`, `type`, `tag`) is missing
    /// or duplicated.
    Header(&'static str),
    /// A hash-valued header is not 40 lowercase/uppercase hex chars.
    BadId(&'static str),
    /// A person line has no parseable timestamp where one is required.
    PersonTimestamp,
}

impl fmt::Display for GitParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(d) => write!(f, "malformed git object: {d}"),
            Self::Header(d) => write!(f, "git header: {d}"),
            Self::BadId(d) => write!(f, "git id field: {d}"),
            Self::PersonTimestamp => write!(f, "person line has no parseable timestamp"),
        }
    }
}

impl std::error::Error for GitParseError {}

/// A parsed git person line (`author` / `committer` / `tagger`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    /// The SPEC-GIT-IMPORT §3.2 identity payload: a verbatim byte
    /// slice of the line — through the closing `>` of the LAST
    /// `<...>` group, or the bracket-less rule.
    pub identity: Vec<u8>,
    /// Epoch seconds. `i64` because git timestamps are signed —
    /// negative values are the import driver's refusal, not ours.
    pub timestamp: i64,
    /// Timezone suffix as written (e.g. `+0200`), when present.
    pub timezone: Option<Vec<u8>>,
}

/// Parse a person-line VALUE (the bytes after `author ` etc.).
///
/// Tolerances, per SPEC-GIT-IMPORT §3.2:
/// - identity = bytes through the closing `>` of the last `<...>`
///   group, verbatim (interior malformations preserved);
/// - bracket-less lines: identity = remainder with one trailing
///   `␣<decimal>␣[+-]NNNN` match stripped;
/// - timestamp = first whitespace-separated decimal (optionally
///   `-`-signed) after the identity; missing → error (commits/tags
///   need one);
/// - timezone = the following token when it looks like `[+-]NNNN`.
pub fn parse_person(value: &[u8]) -> Result<Person, GitParseError> {
    // Identity boundary: closing '>' of the LAST '<...>' group.
    let identity_end = value
        .iter()
        .rposition(|&b| b == b'>')
        .filter(|&gt| value[..gt].contains(&b'<'))
        .map(|gt| gt + 1);

    if let Some(end) = identity_end {
        let identity = value[..end].to_vec();
        let rest = &value[end..];
        let (timestamp, timezone) = parse_ts_tz(rest).ok_or(GitParseError::PersonTimestamp)?;
        return Ok(Person {
            identity,
            timestamp,
            timezone,
        });
    }

    // Bracket-less rule: strip one trailing `␣secs␣[+-]NNNN` match.
    if let Some((cut, timestamp, timezone)) = trailing_ts_tz(value) {
        return Ok(Person {
            identity: value[..cut].to_vec(),
            timestamp,
            timezone: Some(timezone),
        });
    }
    Err(GitParseError::PersonTimestamp)
}

/// Parse ` <secs> [<tz>]` after the identity. Returns the timestamp
/// and optional timezone token.
fn parse_ts_tz(rest: &[u8]) -> Option<(i64, Option<Vec<u8>>)> {
    let mut tokens = rest.split(|&b| b == b' ').filter(|t| !t.is_empty());
    let ts_tok = tokens.next()?;
    let ts = parse_i64(ts_tok)?;
    let tz = tokens.next().filter(|t| is_tz(t)).map(<[u8]>::to_vec);
    Some((ts, tz))
}

/// Match one trailing `␣<decimal>␣[+-]NNNN` group. Returns
/// (identity-end, timestamp, timezone).
fn trailing_ts_tz(value: &[u8]) -> Option<(usize, i64, Vec<u8>)> {
    let last_sp = value.iter().rposition(|&b| b == b' ')?;
    let tz = &value[last_sp + 1..];
    if !is_tz(tz) {
        return None;
    }
    let prev_sp = value[..last_sp].iter().rposition(|&b| b == b' ')?;
    let secs = &value[prev_sp + 1..last_sp];
    let ts = parse_i64(secs)?;
    Some((prev_sp, ts, tz.to_vec()))
}

fn is_tz(t: &[u8]) -> bool {
    t.len() == 5 && (t[0] == b'+' || t[0] == b'-') && t[1..].iter().all(u8::is_ascii_digit)
}

fn parse_i64(t: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(t).ok()?;
    // Reject Rust's leading-`+` tolerance: git timestamps are bare
    // decimals with an optional `-`.
    if s.starts_with('+') {
        return None;
    }
    s.parse::<i64>().ok()
}

/// A header line after continuation folding: `(key, value-bytes)`.
/// Continuation lines (leading space) re-join with `\n` so a folded
/// value round-trips to the original block minus the fold markers —
/// faithful for carrying, never re-serialized by the importer.
type Headers = Vec<(Vec<u8>, Vec<u8>)>;

/// Split an arbitrary git commit/tag body into folded headers + the
/// verbatim message bytes.
fn split_headers(body: &[u8]) -> Result<(Headers, &[u8]), GitParseError> {
    let sep = body
        .windows(2)
        .position(|w| w == b"\n\n")
        .ok_or(GitParseError::Malformed("no header/message separator"))?;
    if sep + 1 > MAX_HEADER_BLOCK {
        return Err(GitParseError::Malformed("header block over cap"));
    }
    let (head, message) = (&body[..sep], &body[sep + 2..]);
    let mut headers: Headers = Vec::new();
    for line in head.split(|&b| b == b'\n') {
        if let Some(cont) = line.strip_prefix(b" ") {
            // Continuation: belongs to the previous header.
            match headers.last_mut() {
                Some((_, v)) => {
                    v.push(b'\n');
                    v.extend_from_slice(cont);
                }
                None => return Err(GitParseError::Malformed("leading continuation line")),
            }
            continue;
        }
        let sp = line
            .iter()
            .position(|&b| b == b' ')
            .ok_or(GitParseError::Malformed("header line without value"))?;
        headers.push((line[..sp].to_vec(), line[sp + 1..].to_vec()));
    }
    Ok((headers, message))
}

fn one(headers: &Headers, key: &[u8], what: &'static str) -> Result<Vec<u8>, GitParseError> {
    let mut found = None;
    for (k, v) in headers {
        if k == key {
            if found.is_some() {
                return Err(GitParseError::Header(what));
            }
            found = Some(v.clone());
        }
    }
    found.ok_or(GitParseError::Header(what))
}

fn id_of(value: &[u8], what: &'static str) -> Result<Sha1Id, GitParseError> {
    std::str::from_utf8(value)
        .ok()
        .map(str::to_ascii_lowercase)
        .as_deref()
        .and_then(sha1_from_hex)
        .ok_or(GitParseError::BadId(what))
}

/// A parsed (arbitrary) git commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommit {
    pub tree: Sha1Id,
    pub parents: Vec<Sha1Id>,
    pub author: Person,
    pub committer: Person,
    /// Verbatim message bytes (may be any encoding).
    pub message: Vec<u8>,
    /// `true` when a `gpgsig`/`gpgsig-sha256` header was present
    /// (carried via retained raw bytes, surfaced for UX/provenance).
    pub has_gpgsig: bool,
}

/// Parse arbitrary git commit body bytes (after the object header).
pub fn parse_commit(body: &[u8]) -> Result<GitCommit, GitParseError> {
    let (headers, message) = split_headers(body)?;
    let tree = id_of(
        &one(&headers, b"tree", "tree missing or duplicated")?,
        "tree",
    )?;
    let mut parents = Vec::new();
    for (k, v) in &headers {
        if k == b"parent" {
            parents.push(id_of(v, "parent")?);
        }
    }
    let author = parse_person(&one(&headers, b"author", "author missing or duplicated")?)?;
    let committer = parse_person(&one(
        &headers,
        b"committer",
        "committer missing or duplicated",
    )?)?;
    let has_gpgsig = headers
        .iter()
        .any(|(k, _)| k == b"gpgsig" || k == b"gpgsig-sha256");
    Ok(GitCommit {
        tree,
        parents,
        author,
        committer,
        message: message.to_vec(),
        has_gpgsig,
    })
}

/// A parsed (arbitrary) git annotated tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTag {
    pub object: Sha1Id,
    /// The `type` header value (`commit`, `tree`, `blob`, `tag`).
    pub target_type: Vec<u8>,
    pub name: Vec<u8>,
    /// `None` for historic tagger-less tags (git v0.99 era).
    pub tagger: Option<Person>,
    pub message: Vec<u8>,
    /// `true` when the message carries a PGP signature block.
    pub has_signature: bool,
}

/// Parse arbitrary git tag body bytes.
pub fn parse_tag(body: &[u8]) -> Result<GitTag, GitParseError> {
    let (headers, message) = split_headers(body)?;
    let object = id_of(
        &one(&headers, b"object", "object missing or duplicated")?,
        "object",
    )?;
    let target_type = one(&headers, b"type", "type missing or duplicated")?;
    let name = one(&headers, b"tag", "tag name missing or duplicated")?;
    let tagger = match headers.iter().find(|(k, _)| k == b"tagger") {
        Some((_, v)) => Some(parse_person(v)?),
        None => None,
    };
    let has_signature = message
        .windows(b"-----BEGIN PGP SIGNATURE-----".len())
        .any(|w| w == b"-----BEGIN PGP SIGNATURE-----");
    Ok(GitTag {
        object,
        target_type,
        name,
        tagger,
        message: message.to_vec(),
        has_signature,
    })
}

/// One raw git tree entry: mode string verbatim, name bytes, child id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitTreeEntry {
    pub mode: Vec<u8>,
    pub name: Vec<u8>,
    pub id: Sha1Id,
}

/// Parse arbitrary git tree body bytes. Purely structural — mode
/// policy (canonical/normalize/refuse) is the driver's.
pub fn parse_tree(body: &[u8]) -> Result<Vec<GitTreeEntry>, GitParseError> {
    let mut entries = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let sp = rest
            .iter()
            .position(|&b| b == b' ')
            .ok_or(GitParseError::Malformed(
                "tree entry missing mode terminator",
            ))?;
        let mode = rest[..sp].to_vec();
        if mode.is_empty() || mode.len() > 7 || !mode.iter().all(u8::is_ascii_digit) {
            return Err(GitParseError::Malformed("tree entry mode not octal"));
        }
        rest = &rest[sp + 1..];
        let nul = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(GitParseError::Malformed("tree entry missing NUL"))?;
        let name = rest[..nul].to_vec();
        if name.is_empty() {
            return Err(GitParseError::Malformed("tree entry with empty name"));
        }
        rest = &rest[nul + 1..];
        if rest.len() < 20 {
            return Err(GitParseError::Malformed("tree entry truncated id"));
        }
        let mut id = [0u8; 20];
        id.copy_from_slice(&rest[..20]);
        rest = &rest[20..];
        entries.push(GitTreeEntry { mode, name, id });
    }
    Ok(entries)
}

/// SPEC-GIT-IMPORT §3.3 mode policy outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeMapping {
    /// A canonical git mode.
    Canonical(mkit_core::object::EntryMode),
    /// A historic spelling, normalized to its canonical equivalent
    /// (declared-lossy; refused in fork-mode state dirs).
    Normalized(mkit_core::object::EntryMode),
    /// Submodule gitlink — always refused.
    Gitlink,
    /// Not a mode the mapping covers.
    Unknown,
}

/// Classify a git tree-entry mode string per the pinned §3.3 table.
#[must_use]
pub fn map_mode(mode: &[u8]) -> ModeMapping {
    use mkit_core::object::EntryMode;
    match mode {
        b"100644" => ModeMapping::Canonical(EntryMode::Blob),
        b"40000" => ModeMapping::Canonical(EntryMode::Tree),
        b"120000" => ModeMapping::Canonical(EntryMode::Symlink),
        b"100755" => ModeMapping::Canonical(EntryMode::Executable),
        b"100664" | b"100640" | b"100600" => ModeMapping::Normalized(EntryMode::Blob),
        b"040000" => ModeMapping::Normalized(EntryMode::Tree),
        b"160000" => ModeMapping::Gitlink,
        _ => ModeMapping::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mkit_core::object::EntryMode;

    #[test]
    fn person_plain() {
        let p = parse_person(b"Alice Example <alice@example.com> 1700000000 +0200").unwrap();
        assert_eq!(p.identity, b"Alice Example <alice@example.com>");
        assert_eq!(p.timestamp, 1_700_000_000);
        assert_eq!(p.timezone.as_deref(), Some(b"+0200".as_slice()));
    }

    #[test]
    fn person_malformations_preserved_verbatim() {
        // Doubled space, no space before '<', nested '<' in name: the
        // last '>' rule slices verbatim.
        let p = parse_person(b"Weird  Name<a@b> 5 +0000").unwrap();
        assert_eq!(p.identity, b"Weird  Name<a@b>");
        let p = parse_person(b"A <b> C <d@e> 5 +0000").unwrap();
        assert_eq!(p.identity, b"A <b> C <d@e>");
    }

    #[test]
    fn person_negative_timestamp_parses() {
        // Policy (refusal) is the driver's; the parser is faithful.
        let p = parse_person(b"Old Soul <o@s> -86400 +0000").unwrap();
        assert_eq!(p.timestamp, -86400);
    }

    #[test]
    fn person_bracketless_rules() {
        let p = parse_person(b"Just A Name 1700000000 +0000").unwrap();
        assert_eq!(p.identity, b"Just A Name");
        assert_eq!(p.timestamp, 1_700_000_000);
        // No trailing pattern → no timestamp → error.
        assert_eq!(
            parse_person(b"no timestamp here"),
            Err(GitParseError::PersonTimestamp)
        );
    }

    #[test]
    fn commit_with_gpgsig_continuation() {
        // Built line-by-line: Rust string-literal continuations would
        // eat the load-bearing leading spaces of the fold lines.
        let lines: &[&[u8]] = &[
            b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            b"parent ce013625030ba8dba906f756967f9e9ca394464a",
            b"author A <a@x> 1700000000 +0000",
            b"committer B <b@x> 1700000001 -0500",
            b"gpgsig -----BEGIN SSH SIGNATURE-----",
            b" U1NIU0lHbGluZTI=",
            b" -----END SSH SIGNATURE-----",
            b"",
            b"msg body",
            b"",
            b"with blank line",
        ];
        let mut body = lines.join(&b"\n"[..]);
        body.push(b'\n');
        let c = parse_commit(&body).unwrap();
        assert_eq!(c.parents.len(), 1);
        assert!(c.has_gpgsig);
        assert_eq!(c.author.identity, b"A <a@x>");
        assert_eq!(c.committer.timestamp, 1_700_000_001);
        assert_eq!(c.message, b"msg body\n\nwith blank line\n");
    }

    #[test]
    fn commit_rejects_missing_or_duplicate_required() {
        assert!(parse_commit(b"author A <a@x> 5 +0000\ncommitter A <a@x> 5 +0000\n\nx").is_err());
        let dup = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
author A <a@x> 5 +0000\ncommitter A <a@x> 5 +0000\n\nx";
        assert!(parse_commit(dup).is_err());
    }

    #[test]
    fn commit_tolerates_unknown_and_encoding_headers() {
        let body = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
author A <a@x> 5 +0000\n\
committer A <a@x> 5 +0000\n\
encoding ISO-8859-1\n\
x-custom whatever\n\
\n\
caf\xe9\n";
        let c = parse_commit(body).unwrap();
        assert_eq!(c.message, b"caf\xe9\n");
    }

    #[test]
    fn tag_with_and_without_tagger() {
        let body = b"object ce013625030ba8dba906f756967f9e9ca394464a\n\
type commit\ntag v1.0.0\ntagger T <t@x> 5 +0000\n\nrelease\n";
        let t = parse_tag(body).unwrap();
        assert_eq!(t.name, b"v1.0.0");
        assert!(t.tagger.is_some());
        // git v0.99-era tagger-less tag.
        let body = b"object ce013625030ba8dba906f756967f9e9ca394464a\n\
type commit\ntag old\n\nancient\n";
        let t = parse_tag(body).unwrap();
        assert!(t.tagger.is_none());
    }

    #[test]
    fn tree_parses_and_modes_classify() {
        let mut body = Vec::new();
        for (mode, name) in [
            (&b"100644"[..], &b"a.txt"[..]),
            (b"040000", b"olddir"),
            (b"160000", b"sub"),
        ] {
            body.extend_from_slice(mode);
            body.push(b' ');
            body.extend_from_slice(name);
            body.push(0);
            body.extend_from_slice(&[7u8; 20]);
        }
        let entries = parse_tree(&body).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            map_mode(&entries[0].mode),
            ModeMapping::Canonical(EntryMode::Blob)
        );
        assert_eq!(
            map_mode(&entries[1].mode),
            ModeMapping::Normalized(EntryMode::Tree)
        );
        assert_eq!(map_mode(&entries[2].mode), ModeMapping::Gitlink);
        assert_eq!(map_mode(b"777777"), ModeMapping::Unknown);
    }

    #[test]
    fn parsers_never_panic_on_junk() {
        for junk in [
            &b""[..],
            b"\n\n",
            b" leading continuation\n\nx",
            b"tree short\n\nx",
            b"\x00\xff\xfe",
        ] {
            let _ = parse_commit(junk);
            let _ = parse_tag(junk);
            let _ = parse_tree(junk);
            let _ = parse_person(junk);
        }
    }
}
