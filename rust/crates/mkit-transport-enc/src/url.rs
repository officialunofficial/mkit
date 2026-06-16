//! Strict `mkit+enc://` URL parser.
//!
//! Accepted form:
//!
//! ```text
//! mkit+enc://[user@]host[:port]/[path]?pubkey=<base64-or-hex>
//! ```
//!
//! - `user@` is OPTIONAL. The encrypted transport does not (today) use
//!   the user component for any authentication step — the static
//!   ed25519 keypair on each side is what authenticates the handshake.
//!   We accept it so the URL surface stays symmetrical with
//!   `mkit+ssh://` and lets `mkit remote add` round-trip without
//!   mangling.
//! - `host` is REQUIRED and validated to the same conservative ASCII
//!   subset used by `mkit-transport-ssh::url::validate_host`.
//! - `port` is OPTIONAL. Defaults to [`DEFAULT_PORT`] (9418, same as
//!   git's daemon, recycled for symmetry with operator expectations).
//! - `path` is OPTIONAL. If absent, the parser returns `None`; the
//!   server side picks its repo root from its own CLI flag and ignores
//!   the URL path.
//! - `?pubkey=` is REQUIRED. SPEC-TRANSPORT-ENC §1: there is no TOFU
//!   cache, no CA chain. The server's static `ed25519` public key
//!   travels with the URL as a 32-byte payload, encoded as either
//!   hex (64 chars) or unpadded base64 url-safe (43 chars). Both
//!   forms are accepted to keep the on-disk config compact and to
//!   match the encoding mkit-keystore emits.

use mkit_core::protocol::TransportError;

/// Mandatory strict-namespace prefix for every encrypted-transport URL.
/// Forbidding bare `enc://` keeps the scheme parser from accidentally
/// accepting URLs intended for an unrelated tool.
pub const MKIT_ENC_PREFIX: &str = "mkit+enc://";

/// Default TCP port for the mkit encrypted transport when the URL
/// omits one. Chosen to match git's traditional daemon port — same
/// rationale as `mkit-transport-ssh`'s reuse of 22.
pub const DEFAULT_PORT: u16 = 9418;

/// Required length (in bytes) of the static ed25519 public key bound
/// into the URL via `?pubkey=`. Matches
/// `commonware_cryptography::ed25519::PublicKey` on the wire.
pub const PUBKEY_LEN: usize = 32;

/// A resolved `mkit+enc://` target. All fields are owned so the struct
/// outlives the caller's input buffer — the TCP dial happens on a
/// background tokio runtime that we cannot tie to URL-borrow lifetimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncTarget {
    /// Optional `user@` component. Carried for round-tripping; the
    /// encrypted transport does not consult it during the handshake.
    pub user: Option<String>,
    /// Remote host. Validated to the same charset as the SSH transport.
    pub host: String,
    /// Resolved TCP port (defaulted to [`DEFAULT_PORT`] when the URL
    /// omits one).
    pub port: u16,
    /// Optional repository path. `None` when the URL has no path
    /// component or only a bare slash.
    pub path: Option<String>,
    /// Server's static ed25519 public key, decoded from the
    /// `?pubkey=<…>` query parameter. Exactly 32 bytes.
    pub server_pubkey: [u8; PUBKEY_LEN],
}

/// Parse a `mkit+enc://…?pubkey=<…>` URL into an [`EncTarget`].
///
/// Returns [`TransportError::InvalidRef`] with a human-readable reason
/// for any validation failure. SPEC-TRANSPORT-ENC §1 is the authority
/// for what is (and isn't) a legal URL.
pub fn parse_enc_url(url: &str) -> Result<EncTarget, TransportError> {
    // Fast reject for control characters before we start slicing.
    // CRLF / NUL would let argv-injection attempts ride into log
    // output even though the encrypted transport doesn't spawn a
    // child. Charge a uniform validation cost up front.
    if url
        .as_bytes()
        .iter()
        .any(|&b| b == 0 || b == b'\r' || b == b'\n')
    {
        return Err(TransportError::InvalidRef(
            "enc url contains NUL or CRLF".into(),
        ));
    }

    let rest = url.strip_prefix(MKIT_ENC_PREFIX).ok_or_else(|| {
        TransportError::InvalidRef(format!("enc url must start with {MKIT_ENC_PREFIX}"))
    })?;
    if rest.is_empty() {
        return Err(TransportError::InvalidRef("enc url has no body".into()));
    }

    // Split off the query string (`?pubkey=…`). Required.
    let (authority_and_path, query) = rest
        .split_once('?')
        .ok_or_else(|| TransportError::InvalidRef("enc url missing ?pubkey= query".into()))?;
    if query.is_empty() {
        return Err(TransportError::InvalidRef("enc url has empty query".into()));
    }

    // Find pubkey= within the query. We accept it as the only
    // parameter — future params (e.g. `?ttl=`) would be ignored or
    // rejected here; for now we reject extras so a typo'd query
    // doesn't silently lose its pubkey.
    let pubkey_str = parse_pubkey_query(query)?;
    let server_pubkey = decode_pubkey(pubkey_str)?;

    // Optional `user@` prefix.
    let (user, host_port_path) = if let Some(at) = authority_and_path.find('@') {
        let user = &authority_and_path[..at];
        if user.is_empty() {
            return Err(TransportError::InvalidRef("enc url has empty user".into()));
        }
        validate_user(user)?;
        (Some(user.to_string()), &authority_and_path[at + 1..])
    } else {
        (None, authority_and_path)
    };

    if host_port_path.is_empty() {
        return Err(TransportError::InvalidRef("enc url has no host".into()));
    }

    // Split into `host[:port]` and optional `/path`.
    let (host_port, path_opt) = if let Some(slash) = host_port_path.find('/') {
        let p = &host_port_path[slash..];
        // Bare `/` is treated as no path — symmetric with how a missing
        // slash is treated, so `mkit remote add mkit+enc://h/?pubkey=..`
        // and `mkit+enc://h?pubkey=..` parse identically.
        let path_opt = if p.len() <= 1 { None } else { Some(p) };
        (&host_port_path[..slash], path_opt)
    } else {
        (host_port_path, None)
    };

    if host_port.is_empty() {
        return Err(TransportError::InvalidRef("enc url has empty host".into()));
    }

    let (host, port) = if let Some(colon) = host_port.find(':') {
        let h = &host_port[..colon];
        let p = &host_port[colon + 1..];
        if h.is_empty() {
            return Err(TransportError::InvalidRef(
                "enc url host:port has empty host".into(),
            ));
        }
        if p.is_empty() {
            return Err(TransportError::InvalidRef("enc url has empty port".into()));
        }
        let port = p
            .parse::<u16>()
            .map_err(|_| TransportError::InvalidRef("enc url port is not u16".into()))?;
        (h, port)
    } else {
        (host_port, DEFAULT_PORT)
    };

    validate_host(host)?;
    if let Some(p) = path_opt {
        validate_path(p)?;
    }

    Ok(EncTarget {
        user,
        host: host.to_string(),
        port,
        path: path_opt.map(str::to_string),
        server_pubkey,
    })
}

/// Pull the `pubkey=` value out of a query string. We deliberately do
/// **not** accept any other parameters — a typo'd query (`?pubkey =`
/// vs `?pubkey=`) must fail loudly because the pubkey is the trust
/// anchor. Phase 3 may extend this if a real second param is added.
fn parse_pubkey_query(query: &str) -> Result<&str, TransportError> {
    let mut found: Option<&str> = None;
    for kv in query.split('&') {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| TransportError::InvalidRef("enc url query lacks '='".into()))?;
        if k == "pubkey" {
            if found.is_some() {
                return Err(TransportError::InvalidRef(
                    "enc url has duplicate pubkey= params".into(),
                ));
            }
            found = Some(v);
        } else {
            return Err(TransportError::InvalidRef(format!(
                "enc url has unsupported query parameter '{k}'"
            )));
        }
    }
    let v =
        found.ok_or_else(|| TransportError::InvalidRef("enc url missing pubkey= query".into()))?;
    if v.is_empty() {
        return Err(TransportError::InvalidRef(
            "enc url pubkey= is empty".into(),
        ));
    }
    Ok(v)
}

/// Decode a 32-byte ed25519 public key from either hex (64 chars,
/// lowercase or uppercase) or url-safe base64 (43 chars, unpadded). Two
/// encodings are accepted because (a) the keystore emits unpadded
/// url-safe base64 by default and (b) hex pastes are easier to inspect
/// on the command line. Anything else is rejected.
fn decode_pubkey(s: &str) -> Result<[u8; PUBKEY_LEN], TransportError> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return decode_hex(s);
    }
    if s.len() == 43 && s.bytes().all(is_b64url_byte) {
        return decode_b64url(s);
    }
    Err(TransportError::InvalidRef(
        "enc url pubkey must be 64 hex chars or 43 url-safe base64 chars".into(),
    ))
}

fn decode_hex(s: &str) -> Result<[u8; PUBKEY_LEN], TransportError> {
    let mut out = [0u8; PUBKEY_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[i * 2])?;
        let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, TransportError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(TransportError::InvalidRef("invalid hex digit".into())),
    }
}

const fn is_b64url_byte(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

fn decode_b64url(s: &str) -> Result<[u8; PUBKEY_LEN], TransportError> {
    // 43 base64 chars -> 32 bytes + 2 leftover bits (the
    // last char encodes 6 bits of which only 4 are
    // significant). We assemble manually so we don't pull in a
    // base64 crate just for one fixed-length payload.
    let bytes = s.as_bytes();
    let mut buf = [0u8; 44];
    buf[..43].copy_from_slice(bytes);
    buf[43] = b'A'; // pad to 44 chars (= a multiple of 4) with the zero-bit char.
    let mut out = [0u8; PUBKEY_LEN];
    let mut out_pos = 0usize;
    for chunk in buf.chunks_exact(4) {
        let v0 = b64url_nibble(chunk[0])?;
        let v1 = b64url_nibble(chunk[1])?;
        let v2 = b64url_nibble(chunk[2])?;
        let v3 = b64url_nibble(chunk[3])?;
        let triple =
            (u32::from(v0) << 18) | (u32::from(v1) << 12) | (u32::from(v2) << 6) | u32::from(v3);
        if out_pos < PUBKEY_LEN {
            out[out_pos] = (triple >> 16) as u8;
        }
        if out_pos + 1 < PUBKEY_LEN {
            out[out_pos + 1] = (triple >> 8) as u8;
        }
        if out_pos + 2 < PUBKEY_LEN {
            out[out_pos + 2] = triple as u8;
        }
        out_pos += 3;
    }
    // Verify the unused-bit constraint: the last input char's two
    // low bits must be zero, otherwise an attacker could synthesise
    // a different 32-byte payload that decodes to the same prefix.
    let last = b64url_nibble(bytes[42])?;
    if last & 0b0000_0011 != 0 {
        return Err(TransportError::InvalidRef(
            "enc url pubkey b64 has non-zero trailing bits".into(),
        ));
    }
    Ok(out)
}

fn b64url_nibble(b: u8) -> Result<u8, TransportError> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(26 + b - b'a'),
        b'0'..=b'9' => Ok(52 + b - b'0'),
        b'-' => Ok(62),
        b'_' => Ok(63),
        _ => Err(TransportError::InvalidRef(
            "invalid base64 url-safe digit".into(),
        )),
    }
}

fn validate_user(u: &str) -> Result<(), TransportError> {
    for &c in u.as_bytes() {
        let ok = c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-' || c == b'+';
        if !ok {
            return Err(TransportError::InvalidRef(
                "enc url user has disallowed character".into(),
            ));
        }
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), TransportError> {
    if host.is_empty() {
        return Err(TransportError::InvalidRef("enc host empty".into()));
    }
    // Same conservative ASCII subset as the SSH transport. We allow
    // `[` / `]` so bracketed IPv6 literals survive; callers responsible
    // for bracketing them.
    for &c in host.as_bytes() {
        let ok = c.is_ascii_alphanumeric()
            || c == b'.'
            || c == b'-'
            || c == b'_'
            || c == b':'
            || c == b'['
            || c == b']';
        if !ok {
            return Err(TransportError::InvalidRef(
                "enc host has disallowed character".into(),
            ));
        }
    }
    Ok(())
}

fn validate_path(p: &str) -> Result<(), TransportError> {
    // Path must start with `/` (we sliced it that way) and contain only
    // safe ASCII path bytes. `.` and `..` segments are forbidden so a
    // future server that consults the path can't be tricked into path
    // traversal.
    if !p.starts_with('/') {
        return Err(TransportError::InvalidRef(
            "enc path is not absolute".into(),
        ));
    }
    let tail = &p[1..];
    if tail.is_empty() {
        // Bare slash already filtered by the caller, but be defensive.
        return Err(TransportError::InvalidRef("enc path is bare slash".into()));
    }
    for seg in tail.split('/') {
        if seg.is_empty() {
            return Err(TransportError::InvalidRef(
                "enc path has empty segment".into(),
            ));
        }
        if seg == "." || seg == ".." {
            return Err(TransportError::InvalidRef(
                "enc path has . or .. segment".into(),
            ));
        }
        for &c in seg.as_bytes() {
            let ok = c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-';
            if !ok {
                return Err(TransportError::InvalidRef(
                    "enc path has disallowed character".into(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference pubkey used across positive tests. All-zero is fine —
    /// the parser doesn't check semantic validity of the key, only the
    /// encoding shape.
    const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    /// Url-safe base64 of 32 zero bytes (43 chars, unpadded). The
    /// trailing `A` carries the two zero bits that base64's 4-char
    /// block requires.
    const ZERO_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn parses_full_url_with_path_and_port() {
        let url = format!("mkit+enc://alice@host.example.com:7777/repos/proj?pubkey={ZERO_HEX}");
        let t = parse_enc_url(&url).unwrap();
        assert_eq!(t.user.as_deref(), Some("alice"));
        assert_eq!(t.host, "host.example.com");
        assert_eq!(t.port, 7777);
        assert_eq!(t.path.as_deref(), Some("/repos/proj"));
        assert_eq!(t.server_pubkey, [0u8; 32]);
    }

    #[test]
    fn parses_url_no_user_no_port_no_path() {
        let url = format!("mkit+enc://h.example?pubkey={ZERO_HEX}");
        let t = parse_enc_url(&url).unwrap();
        assert_eq!(t.user, None);
        assert_eq!(t.host, "h.example");
        assert_eq!(t.port, DEFAULT_PORT);
        assert_eq!(t.path, None);
    }

    #[test]
    fn parses_bare_slash_as_no_path() {
        let url = format!("mkit+enc://h.example/?pubkey={ZERO_HEX}");
        let t = parse_enc_url(&url).unwrap();
        assert_eq!(t.path, None);
    }

    #[test]
    fn parses_b64_pubkey() {
        let url = format!("mkit+enc://h.example?pubkey={ZERO_B64}");
        let t = parse_enc_url(&url).unwrap();
        assert_eq!(t.server_pubkey, [0u8; 32]);
    }

    #[test]
    fn parses_uppercase_hex_pubkey() {
        let url = format!("mkit+enc://h.example?pubkey={}", "FF".repeat(32));
        let t = parse_enc_url(&url).unwrap();
        assert_eq!(t.server_pubkey, [0xFFu8; 32]);
    }

    #[test]
    fn rejects_missing_prefix() {
        let url = format!("enc://h.example?pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_empty_url() {
        assert!(parse_enc_url("").is_err());
    }

    #[test]
    fn rejects_missing_query() {
        assert!(parse_enc_url("mkit+enc://h.example/").is_err());
    }

    #[test]
    fn rejects_missing_pubkey_param() {
        assert!(parse_enc_url("mkit+enc://h.example?other=x").is_err());
    }

    #[test]
    fn rejects_empty_pubkey() {
        assert!(parse_enc_url("mkit+enc://h.example?pubkey=").is_err());
    }

    #[test]
    fn rejects_short_hex_pubkey() {
        // 62 chars — neither 64-hex nor 43-b64.
        let short = "0".repeat(62);
        let url = format!("mkit+enc://h.example?pubkey={short}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_non_hex_pubkey_at_hex_length() {
        // 64 chars but with a non-hex digit in the middle.
        let bad = format!("{}Z{}", "0".repeat(31), "0".repeat(32));
        assert_eq!(bad.len(), 64);
        let url = format!("mkit+enc://h.example?pubkey={bad}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_b64_with_padding_chars() {
        // 43-char b64 plus '=' padding is 44 chars; our length check
        // already rejects that, and so does the charset (we don't
        // allow '=').
        let url = format!("mkit+enc://h.example?pubkey={ZERO_B64}=");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_b64_with_nonzero_trailing_bits() {
        // Take the all-zero b64 and bump the last char by one. The
        // low two bits of the final input char encode bits that have
        // no destination byte — those MUST be zero to avoid two
        // distinct b64 strings decoding to the same 32-byte payload.
        let mut bad = ZERO_B64.to_string();
        bad.pop();
        bad.push('B'); // 'B' = 1, low bits 01
        let url = format!("mkit+enc://h.example?pubkey={bad}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_port_too_large() {
        let url = format!("mkit+enc://h.example:99999?pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_empty_port() {
        let url = format!("mkit+enc://h.example:?pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_crlf_in_url() {
        let url = format!("mkit+enc://h.\rexample?pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_nul_in_url() {
        let url = format!("mkit+enc://h.example\0?pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_empty_user() {
        let url = format!("mkit+enc://@h.example?pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_user_with_meta_char() {
        let url = format!("mkit+enc://al;ice@h.example?pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_dot_dot_path() {
        let url = format!("mkit+enc://h.example/repos/../etc?pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_unknown_query_param() {
        // We reject extras so a typo'd pubkey doesn't silently lose
        // the trust anchor.
        let url = format!("mkit+enc://h.example?ttl=60&pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_duplicate_pubkey() {
        let url = format!("mkit+enc://h.example?pubkey={ZERO_HEX}&pubkey={ZERO_HEX}");
        assert!(parse_enc_url(&url).is_err());
    }

    #[test]
    fn rejects_query_without_equals() {
        let url = "mkit+enc://h.example?pubkeyzero";
        assert!(parse_enc_url(url).is_err());
    }

    #[test]
    fn pubkey_roundtrips_hex_and_b64_to_same_bytes() {
        // FF repeats in hex.
        let hex_url = format!("mkit+enc://h?pubkey={}", "ff".repeat(32));
        let hex_t = parse_enc_url(&hex_url).unwrap();
        // Same key in url-safe base64 (32 bytes of 0xFF):
        //   each pair of 0xFF (16 bits) = 'P' '_' (0x3F 0x3F => base64 P, _ ...)
        // Easier: encode at runtime.
        let bytes = [0xFFu8; 32];
        let b64 = encode_b64url_for_test(&bytes);
        let b64_url = format!("mkit+enc://h?pubkey={b64}");
        let b64_t = parse_enc_url(&b64_url).unwrap();
        assert_eq!(hex_t.server_pubkey, b64_t.server_pubkey);
        assert_eq!(hex_t.server_pubkey, [0xFFu8; 32]);
    }

    /// Minimal base64 url-safe encoder for the round-trip test. Same
    /// "no padding, 43 chars" output our parser accepts. Kept inside
    /// the test module so the production crate doesn't ship an
    /// encoder it doesn't need at runtime.
    fn encode_b64url_for_test(input: &[u8; 32]) -> String {
        const ALPHA: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        // Pad input to 33 bytes so the 4-byte block loop is uniform;
        // we'll trim the dangling 'A' at the end.
        let mut buf = [0u8; 33];
        buf[..32].copy_from_slice(input);
        let mut out = String::with_capacity(44);
        for chunk in buf.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk[1];
            let b2 = chunk[2];
            let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
            out.push(char::from(ALPHA[((triple >> 18) & 0x3F) as usize]));
            out.push(char::from(ALPHA[((triple >> 12) & 0x3F) as usize]));
            out.push(char::from(ALPHA[((triple >> 6) & 0x3F) as usize]));
            out.push(char::from(ALPHA[(triple & 0x3F) as usize]));
        }
        // Drop the last char that encodes only padding bits (the 33rd
        // input byte is zero).
        out.pop();
        out
    }
}
