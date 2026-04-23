//! Strict `mkit+ssh://` URL parser.
//!
//! This is the Rust port of the parts of `src/protocol.zig` that the
//! PROTOCOL agent deferred to the SSH transport agent:
//! `validateSshPath` and `parseStrictSsh`. SPEC-TRANSPORT §7 and
//! SSH-SECURITY.md §2 are the authority for what is (and isn't) a
//! legal `mkit+ssh://` URL.
//!
//! Accepted forms (all with the mandatory `mkit+` prefix):
//!
//! ```text
//! mkit+ssh://user@host/path
//! mkit+ssh://user@host:port/path
//! mkit+ssh://user@host:path           (legacy SCP-style, no port)
//! mkit+ssh://user@host:port:path      (legacy SCP-style, explicit port)
//! ```
//!
//! The `user@` prefix is REQUIRED. The `mkit+` prefix is REQUIRED. Paths
//! are restricted to a conservative ASCII subset (`[A-Za-z0-9._-/]`) with
//! no empty / `.` / `..` segments so neither the on-disk config nor the
//! remote-shell transport can be confused by shell meta-characters, NUL
//! bytes, CRLF, or path traversal.

use mkit_core::protocol::TransportError;

/// Mandatory strict-namespace prefix for every mkit remote URL
/// (`mkit+ssh://…`). Forbidding bare `ssh://…` is deliberate: the Zig
/// CLI's strict parser (`parseRemoteUrl`) enforces the same thing, and
/// we do not want the Rust port to silently accept a looser superset.
pub const MKIT_SSH_PREFIX: &str = "mkit+ssh://";

/// A resolved `mkit+ssh://` target. All fields are owned so the struct
/// outlives the caller's input buffer — the SSH child process is spawned
/// asynchronously and we cannot rely on borrows from the URL string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTarget {
    /// Remote account (the `user` in `user@host`). Never empty — the
    /// parser rejects missing-user URLs.
    pub user: String,
    /// Remote hostname. Never empty.
    pub host: String,
    /// Optional explicit TCP port. `None` means "use ssh(1)'s default".
    pub port: Option<u16>,
    /// Remote repository path. Always passes [`validate_ssh_path`] — no
    /// empty / `.` / `..` segments, no shell meta-characters, no NUL,
    /// no CRLF.
    pub path: String,
}

/// Validate the repository-path portion of an SSH remote.
///
/// SSH-SECURITY.md §2: paths are restricted to the ASCII subset
/// `[A-Za-z0-9._-/]`, MUST be non-empty, and MUST NOT contain empty /
/// `.` / `..` segments. This blocks:
///
/// - Path traversal (`..`, `/etc/passwd` via percent-encoded `..`).
/// - Shell meta-character injection (`;`, `&`, `|`, `$`, backticks,
///   spaces, newlines).
/// - NUL-byte injection (`%00`-style splices).
/// - CRLF injection in any component that might be echoed back.
///
/// A leading `/` is accepted (absolute repo path) as long as the rest of
/// the path satisfies the segment rules. We intentionally do NOT special-
/// case `/etc/…`: the segment-level charset already forbids bytes like
/// `:` that appear in typical traversal attempts, and the `..`-rejection
/// rule forbids climbing out of an arbitrary chroot.
pub fn validate_ssh_path(path: &str) -> Result<(), TransportError> {
    if path.is_empty() {
        return Err(TransportError::InvalidRef("empty ssh path".into()));
    }
    // Fast reject for NUL / CR / LF — these aren't in the allowed ASCII
    // subset below, but failing loudly with a distinct message makes
    // injection attempts obvious in logs.
    if path
        .as_bytes()
        .iter()
        .any(|&b| b == 0 || b == b'\r' || b == b'\n')
    {
        return Err(TransportError::InvalidRef(
            "ssh path contains NUL or CRLF".into(),
        ));
    }

    let tail = if let Some(stripped) = path.strip_prefix('/') {
        if stripped.is_empty() {
            return Err(TransportError::InvalidRef("ssh path is bare slash".into()));
        }
        stripped
    } else {
        path
    };

    for part in tail.split('/') {
        if part.is_empty() {
            return Err(TransportError::InvalidRef(
                "ssh path has empty segment".into(),
            ));
        }
        if part == "." || part == ".." {
            return Err(TransportError::InvalidRef(
                "ssh path has . or .. segment".into(),
            ));
        }
        for &c in part.as_bytes() {
            let allowed = c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-';
            if !allowed {
                return Err(TransportError::InvalidRef(
                    "ssh path has disallowed character".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Parse a `mkit+ssh://…` URL into a [`SshTarget`].
///
/// Returns [`TransportError::InvalidRef`] with a human-readable reason
/// for any validation failure. (`InvalidRef` is reused here as the
/// "caller fed bad input" bucket — SPEC-TRANSPORT §1 does not reserve a
/// dedicated `InvalidUrl` variant, and the wire protocol never sees a
/// URL directly.)
pub fn parse_mkit_ssh_url(url: &str) -> Result<SshTarget, TransportError> {
    // SSH-SECURITY.md §2: reject NUL / CR / LF anywhere in the URL
    // before we start slicing.
    if url
        .as_bytes()
        .iter()
        .any(|&b| b == 0 || b == b'\r' || b == b'\n')
    {
        return Err(TransportError::InvalidRef(
            "ssh url contains NUL or CRLF".into(),
        ));
    }

    let rest = url.strip_prefix(MKIT_SSH_PREFIX).ok_or_else(|| {
        TransportError::InvalidRef(format!("ssh url must start with {MKIT_SSH_PREFIX}"))
    })?;
    if rest.is_empty() {
        return Err(TransportError::InvalidRef("ssh url has no body".into()));
    }

    // `user@` is REQUIRED (SPEC-TRANSPORT §7 `parseStrictSsh`).
    let at = rest
        .find('@')
        .ok_or_else(|| TransportError::InvalidRef("ssh url missing user".into()))?;
    let user = &rest[..at];
    let tail = &rest[at + 1..];
    if user.is_empty() {
        return Err(TransportError::InvalidRef("ssh url has empty user".into()));
    }
    if tail.is_empty() {
        return Err(TransportError::InvalidRef("ssh url has no host".into()));
    }

    // Forbid embedded slashes / colons / @ / whitespace in the user
    // field — these would escape the argv boundary when we build
    // `user@host`. Zig's `parseStrictSsh` inherits this implicitly
    // because it splits on the first `@`, but we restrict the user's
    // byte set explicitly so a CRLF or ` -oProxyCommand=...` pasted into
    // the user slot cannot reach `ssh(1)`.
    for &c in user.as_bytes() {
        let ok = c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-' || c == b'+';
        if !ok {
            return Err(TransportError::InvalidRef(
                "ssh url user has disallowed character".into(),
            ));
        }
    }

    // Two SSH URL families can contain a `/`:
    //
    //   (a) URL-style:  user@host[:port]/path
    //   (b) SCP-style:  user@host:path  where `path` itself contains `/`.
    //
    // We distinguish by looking at what's between the first `:` and the
    // first `/` after `@`. If a `:` appears BEFORE the first `/` AND
    // the token between them parses as a u16 port, it's URL-style.
    // Otherwise it's SCP-style (the colon is the SCP separator, and
    // the slash lives inside the path).
    if let Some(slash) = tail.find('/') {
        let host_port = &tail[..slash];
        let path_with_slash = &tail[slash..];
        // Reject `host:` with no port digits — ambiguous form.
        if let Some(colon) = host_port.find(':') {
            let port_str = &host_port[colon + 1..];
            if port_str.is_empty() {
                return Err(TransportError::InvalidRef("ssh url has empty port".into()));
            }
        }
        let is_url_form = match host_port.find(':') {
            None => true,
            Some(colon) => {
                let port_str = &host_port[colon + 1..];
                port_str.bytes().all(|b| b.is_ascii_digit())
            }
        };
        if is_url_form {
            if host_port.is_empty() || path_with_slash.is_empty() {
                return Err(TransportError::InvalidRef(
                    "ssh url has empty host or path".into(),
                ));
            }
            return parse_host_port(user, host_port, path_with_slash);
        }
        // Fall through to SCP-style parsing with the full tail intact.
    }

    // SCP-style: `host[:port]:path` — `path` may itself contain slashes.
    let first_colon = tail
        .find(':')
        .ok_or_else(|| TransportError::InvalidRef("ssh url missing host".into()))?;
    let host = &tail[..first_colon];
    let after = &tail[first_colon + 1..];
    if host.is_empty() || after.is_empty() {
        return Err(TransportError::InvalidRef(
            "ssh url has empty host or path".into(),
        ));
    }

    // Look for `host:port:path`. If the candidate port parses as u16
    // AND the remainder validates as a path, accept it; otherwise treat
    // the whole tail as the path.
    if let Some(second_colon) = after.find(':') {
        let port_candidate = &after[..second_colon];
        let scp_path = &after[second_colon + 1..];
        if !port_candidate.is_empty()
            && !scp_path.is_empty()
            && let Ok(port) = port_candidate.parse::<u16>()
        {
            validate_ssh_path(scp_path)?;
            validate_host(host)?;
            return Ok(SshTarget {
                user: user.to_string(),
                host: host.to_string(),
                port: Some(port),
                path: scp_path.to_string(),
            });
        }
    }

    validate_ssh_path(after)?;
    validate_host(host)?;
    Ok(SshTarget {
        user: user.to_string(),
        host: host.to_string(),
        port: None,
        path: after.to_string(),
    })
}

/// Parse a `host[:port]` token plus a `/`-prefixed path into a
/// [`SshTarget`]. Internal helper for the URL-style branch.
fn parse_host_port(user: &str, host_port: &str, path: &str) -> Result<SshTarget, TransportError> {
    let (host, port) = if let Some(colon) = host_port.find(':') {
        let h = &host_port[..colon];
        let p = &host_port[colon + 1..];
        if h.is_empty() || p.is_empty() {
            return Err(TransportError::InvalidRef(
                "ssh url host:port is empty".into(),
            ));
        }
        let parsed = p
            .parse::<u16>()
            .map_err(|_| TransportError::InvalidRef("ssh url port is not u16".into()))?;
        (h, Some(parsed))
    } else {
        (host_port, None)
    };
    if host.is_empty() {
        return Err(TransportError::InvalidRef("ssh url host empty".into()));
    }
    validate_ssh_path(path)?;
    validate_host(host)?;
    Ok(SshTarget {
        user: user.to_string(),
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

/// Restrict hostnames to a conservative ASCII subset. The Zig reference
/// parser does not enforce this — it relies on `ssh(1)` to reject bogus
/// hostnames — but a defence-in-depth check here prevents trivially
/// hostile inputs (CRLF, NUL, embedded argv separators) from reaching
/// the child process argv.
fn validate_host(host: &str) -> Result<(), TransportError> {
    if host.is_empty() {
        return Err(TransportError::InvalidRef("ssh host empty".into()));
    }
    // RFC 1123 permits digits, letters, `-`, `.` in hostnames. We also
    // permit `:` so IPv6 literals like `[::1]` survive — but then the
    // caller MUST wrap them in brackets themselves. This check is
    // deliberately permissive; tighten only if a concrete attack
    // surfaces.
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
                "ssh host has disallowed character".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Happy paths ------------------------------------------------------

    #[test]
    fn parses_url_form_no_port() {
        let t = parse_mkit_ssh_url("mkit+ssh://alice@host.example.com/repos/project").unwrap();
        assert_eq!(t.user, "alice");
        assert_eq!(t.host, "host.example.com");
        assert_eq!(t.port, None);
        assert_eq!(t.path, "/repos/project");
    }

    #[test]
    fn parses_url_form_with_port() {
        let t = parse_mkit_ssh_url("mkit+ssh://alice@host.example.com:2222/repos/project").unwrap();
        assert_eq!(t.user, "alice");
        assert_eq!(t.host, "host.example.com");
        assert_eq!(t.port, Some(2222));
        assert_eq!(t.path, "/repos/project");
    }

    #[test]
    fn parses_scp_form_no_port() {
        let t = parse_mkit_ssh_url("mkit+ssh://git@github.com:org/repo").unwrap();
        assert_eq!(t.user, "git");
        assert_eq!(t.host, "github.com");
        assert_eq!(t.port, None);
        assert_eq!(t.path, "org/repo");
    }

    #[test]
    fn parses_scp_form_with_port() {
        let t = parse_mkit_ssh_url("mkit+ssh://alice@host.example.com:2222:repos/project").unwrap();
        assert_eq!(t.user, "alice");
        assert_eq!(t.host, "host.example.com");
        assert_eq!(t.port, Some(2222));
        assert_eq!(t.path, "repos/project");
    }

    #[test]
    fn accepts_deep_nested_path() {
        let t = parse_mkit_ssh_url("mkit+ssh://deploy@internal.host/projects/deep/nested/path")
            .unwrap();
        assert_eq!(t.path, "/projects/deep/nested/path");
    }

    // --- Missing-prefix / missing-field rejections -----------------------

    #[test]
    fn rejects_missing_mkit_prefix() {
        assert!(
            parse_mkit_ssh_url("ssh://user@host/path").is_err(),
            "bare ssh:// must be rejected in strict mode"
        );
    }

    #[test]
    fn rejects_empty_url() {
        assert!(parse_mkit_ssh_url("").is_err());
    }

    #[test]
    fn rejects_missing_user() {
        // No `@` at all.
        assert!(parse_mkit_ssh_url("mkit+ssh://host.example.com/repo").is_err());
    }

    #[test]
    fn rejects_empty_user() {
        // `@` present but user is empty (`@host:...`).
        assert!(parse_mkit_ssh_url("mkit+ssh://@host.example.com/repo").is_err());
    }

    #[test]
    fn rejects_missing_host() {
        assert!(parse_mkit_ssh_url("mkit+ssh://user@").is_err());
    }

    #[test]
    fn rejects_empty_path_url_form() {
        // No `/path` and no `:path`.
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host.example.com").is_err());
    }

    #[test]
    fn rejects_missing_port_value() {
        // Bare `host:` with no port digits.
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host:/repo").is_err());
    }

    #[test]
    fn rejects_non_u16_port() {
        assert!(
            parse_mkit_ssh_url("mkit+ssh://user@host:99999/repo").is_err(),
            "99999 exceeds u16"
        );
    }

    // --- Path-escape rejections (SSH-SECURITY.md §2) ---------------------

    #[test]
    fn rejects_dot_dot_traversal() {
        assert!(
            parse_mkit_ssh_url("mkit+ssh://user@host/../../etc/passwd").is_err(),
            "../ traversal must be rejected"
        );
    }

    #[test]
    fn rejects_single_dot_segment() {
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host/repo/./x").is_err());
    }

    #[test]
    fn rejects_double_slash_empty_segment() {
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host/repo//x").is_err());
    }

    #[test]
    fn rejects_nul_byte_injection() {
        let injected = "mkit+ssh://user@host/path\0injected";
        assert!(parse_mkit_ssh_url(injected).is_err());
    }

    #[test]
    fn rejects_nul_byte_in_path_component() {
        let injected = "mkit+ssh://user@host/path\u{0}injected";
        assert!(parse_mkit_ssh_url(injected).is_err());
    }

    #[test]
    fn rejects_crlf_in_user_field() {
        // CR or LF anywhere in the URL is rejected before we split.
        assert!(parse_mkit_ssh_url("mkit+ssh://us\rer@host/repo").is_err());
        assert!(parse_mkit_ssh_url("mkit+ssh://us\ner@host/repo").is_err());
    }

    #[test]
    fn rejects_shell_meta_in_path() {
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host/repo;touch").is_err());
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host/repo$(whoami)").is_err());
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host/repo|cat").is_err());
    }

    #[test]
    fn rejects_space_in_path() {
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host/has space").is_err());
    }

    #[test]
    fn rejects_percent_encoded_path_payload() {
        // We do NOT percent-decode. A literal `%00` in the URL fails
        // the ASCII-subset check.
        assert!(parse_mkit_ssh_url("mkit+ssh://user@host/path%00injected").is_err());
    }

    #[test]
    fn rejects_disallowed_user_characters() {
        // Space / `;` / CR etc. in the user field are blocked before we
        // ever touch `ssh(1)`.
        assert!(parse_mkit_ssh_url("mkit+ssh://al ice@host/repo").is_err());
        assert!(parse_mkit_ssh_url("mkit+ssh://al;ice@host/repo").is_err());
        // A `-oProxyCommand=…` paste attempt begins with `-` which IS
        // allowed inside the user field, but `=` and space are not,
        // so it still fails.
        assert!(parse_mkit_ssh_url("mkit+ssh://-oProxyCommand=pwnd@host/repo").is_err());
    }

    #[test]
    fn rejects_uppercase_scheme() {
        // We do not lowercase — `MKIT+SSH://…` is not `mkit+ssh://…`.
        assert!(parse_mkit_ssh_url("MKIT+SSH://user@host/repo").is_err());
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(parse_mkit_ssh_url("mkit+https://user@host/repo").is_err());
    }

    // --- validate_ssh_path direct tests ----------------------------------

    #[test]
    fn validate_path_accepts_absolute() {
        assert!(validate_ssh_path("/repos/project").is_ok());
    }

    #[test]
    fn validate_path_accepts_relative() {
        assert!(validate_ssh_path("repos/project").is_ok());
    }

    #[test]
    fn validate_path_rejects_empty() {
        assert!(validate_ssh_path("").is_err());
    }

    #[test]
    fn validate_path_rejects_bare_slash() {
        assert!(validate_ssh_path("/").is_err());
    }

    #[test]
    fn validate_path_rejects_dot_dot() {
        assert!(validate_ssh_path("/../etc").is_err());
        assert!(validate_ssh_path("repo/../other").is_err());
    }

    #[test]
    fn validate_path_rejects_nul() {
        assert!(validate_ssh_path("repo\0nul").is_err());
    }
}
