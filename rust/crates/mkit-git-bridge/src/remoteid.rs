//! Canonical remote identity (SPEC-GIT-IMPORT §8).
//!
//! One normalization used by every binding, guard, and attestation
//! `remoteUrl` field, so trivially-equivalent spellings of one remote
//! compare equal. This is a safety net against accidents, not a
//! security boundary — mirrors and redirects are undetectable, and
//! the push lease remains the backstop.

use std::path::Path;

/// Compute the canonical identity of a destination/source string.
///
/// Rules (§8): scp-style rewrites to `ssh://`; scheme+host lowercase;
/// userinfo dropped; default ports stripped per scheme (`ssh` 22,
/// `https` 443, `http` 80, `git` 9418); one trailing `/` and one
/// trailing `.git` stripped; local paths and `file://` URLs collapse
/// to the symlink-resolved absolute path (falling back to the
/// lexical absolute path when the target does not exist yet).
#[must_use]
pub fn remote_identity(dest: &str) -> String {
    remote_identity_relative_to(dest, None)
}

/// As [`remote_identity`], but resolves a non-existent relative local
/// path against `base` instead of the process's current directory when
/// `base` is `Some`. Exposed (test-only) so the relative-path test can
/// absolutize deterministically instead of mutating the shared process
/// cwd via `set_current_dir` — a `set_current_dir` call races every
/// other test in the binary running in parallel (#505 PR 5/5).
fn remote_identity_relative_to(dest: &str, base: Option<&Path>) -> String {
    // file:// URLs → local path handling.
    if let Some(rest) = dest.strip_prefix("file://") {
        let path = rest.strip_prefix("localhost").unwrap_or(rest);
        return canonical_local(path, base);
    }

    // Scheme URLs.
    if let Some((scheme, rest)) = dest.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        // Drop userinfo.
        let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let (host, port) = split_host_port(host_port);
        let host = host.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "ssh" => Some("22"),
            "https" => Some("443"),
            "http" => Some("80"),
            "git" => Some("9418"),
            _ => None,
        };
        let port_part = match port {
            Some(p) if Some(p) != default_port => format!(":{p}"),
            _ => String::new(),
        };
        return format!("{scheme}://{host}{port_part}{}", strip_path(path));
    }

    // scp-style `[user@]host:path` — a colon before the first slash.
    let first_seg = dest.split('/').next().unwrap_or(dest);
    if first_seg.contains(':') && !looks_like_dos_drive(dest) {
        // Bracket-aware split: `[::1]:path` keeps the literal intact.
        let after_user = dest.rsplit_once('@').map_or(dest, |(_, rest)| rest);
        let (host, path) = if after_user.starts_with('[') {
            match after_user.find(']') {
                Some(end) => {
                    let host = &after_user[..=end];
                    let path = after_user[end + 1..].strip_prefix(':').unwrap_or("");
                    (host, path)
                }
                None => after_user.split_once(':').unwrap_or((after_user, "")),
            }
        } else {
            after_user.split_once(':').unwrap_or((after_user, ""))
        };
        let host = host.to_ascii_lowercase();
        return format!("ssh://{host}/{}", strip_path(path).trim_start_matches('/'));
    }

    // Local path.
    canonical_local(dest, base)
}

/// Split `host[:port]`, leaving IPv6 bracket literals intact.
fn split_host_port(hp: &str) -> (&str, Option<&str>) {
    if hp.starts_with('[') {
        // `[::1]` or `[::1]:2222`
        match hp.find(']') {
            Some(end) => {
                let host = &hp[..=end];
                let port = hp[end + 1..].strip_prefix(':');
                (host, port)
            }
            None => (hp, None),
        }
    } else {
        match hp.rsplit_once(':') {
            Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) && !p.is_empty() => (h, Some(p)),
            _ => (hp, None),
        }
    }
}

fn looks_like_dos_drive(dest: &str) -> bool {
    // Strip Windows' `\\?\` extended-length-path prefix first: `Path::
    // canonicalize` emits it on Windows (e.g. `\\?\C:\Users\...`), so a
    // canonicalized path doesn't start with a bare drive letter. Without
    // this strip, `remote_identity` misclassified such paths as an
    // scp-style `[user@]host:path` remote (the literal `\\?\C` segment
    // read as a "host"), corrupting local-path identity comparisons on
    // Windows — caught by the `windows-smoke` CI job added in this PR.
    let dest = dest.strip_prefix(r"\\?\").unwrap_or(dest);
    dest.len() >= 2
        && dest.as_bytes()[0].is_ascii_alphabetic()
        && dest.as_bytes()[1] == b':'
        && matches!(dest.as_bytes().get(2), None | Some(b'/' | b'\\'))
}

/// Strip exactly one trailing `/` then one trailing `.git`.
fn strip_path(path: &str) -> String {
    let p = path.strip_suffix('/').unwrap_or(path);
    let p = p.strip_suffix(".git").unwrap_or(p);
    p.to_owned()
}

fn canonical_local(path: &str, base: Option<&Path>) -> String {
    let p = strip_path(path);
    let pb = Path::new(&p);
    let abs = pb.canonicalize().unwrap_or_else(|_| {
        // Lexical fallback for paths that don't exist (yet, or after
        // the `.git` strip): absolutize against `base` (or cwd, when
        // `base` is `None`) and normalize `.`/`..` components, so
        // `/a/b` + `../up` and `/a/up` agree.
        let joined = if pb.is_absolute() {
            pb.to_path_buf()
        } else {
            match base {
                Some(b) => b.join(pb),
                None => std::env::current_dir().map_or_else(|_| pb.to_path_buf(), |c| c.join(pb)),
            }
        };
        lexical_normalize(&joined)
    });
    abs.to_string_lossy().into_owned()
}

/// Resolve `.` and `..` components lexically (no filesystem access).
fn lexical_normalize(p: &Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_equivalence_table() {
        // SPEC-GIT-IMPORT §8's worked example.
        let canonical = remote_identity("ssh://github.com/org/repo");
        for spelling in [
            "git@github.com:org/repo.git",
            "ssh://GIT@GITHUB.COM:22/org/repo/",
            "ssh://github.com/org/repo.git",
        ] {
            assert_eq!(remote_identity(spelling), canonical, "{spelling}");
        }
        // https default port + case + .git
        assert_eq!(
            remote_identity("HTTPS://GitHub.com:443/Org/Repo.git"),
            "https://github.com/Org/Repo",
            "host lowercases; path case is significant"
        );
        // Non-default port survives.
        assert_ne!(remote_identity("ssh://github.com:2222/org/repo"), canonical);
        // http port 80.
        assert_eq!(
            remote_identity("http://host:80/r"),
            remote_identity("http://HOST/r")
        );
    }

    #[test]
    fn ipv6_and_dos_paths() {
        assert_eq!(remote_identity("[::1]:path/repo"), "ssh://[::1]/path/repo");
        assert_eq!(
            remote_identity("ssh://[::A]:22/r"),
            remote_identity("ssh://[::a]/r")
        );
        // DOS drives are paths, not scp remotes.
        assert!(!remote_identity("C:/repos/x").starts_with("ssh://"));
        // Windows' `\\?\` extended-length-path prefix (what
        // `Path::canonicalize` emits on Windows) must not defeat DOS-drive
        // detection: a canonicalized Windows path is a local path, not an
        // scp-style `host:path` remote. Platform-independent: this only
        // exercises the string classifier, not real filesystem
        // canonicalization, so it runs (and must pass) on every OS.
        assert!(looks_like_dos_drive(r"C:\Users\x"));
        assert!(looks_like_dos_drive(r"\\?\C:\Users\x"));
        assert!(!remote_identity(r"\\?\C:\Users\x\repo").starts_with("ssh://"));
    }

    #[test]
    fn relative_dotdot_paths_normalize_lexically() {
        let td = tempfile::tempdir().unwrap();
        // canonicalize: macOS tempdirs live behind the /var symlink,
        // and cwd always reports the resolved spelling.
        let a = td.path().canonicalize().unwrap().join("a");
        let base = a.join("b");
        std::fs::create_dir_all(&base).unwrap();
        // `../up.git` doesn't exist: the `.git`-stripped fallback must
        // still agree with the identity seen from the absolutized
        // clone URL (`<td>/a/up.git` → `<td>/a/up`). Absolutize against
        // an explicit `base` instead of `set_current_dir` (#505 PR 5/5):
        // mutating the process cwd races every other test in this binary
        // running in parallel.
        let from_rel = remote_identity_relative_to("../up.git", Some(&base));
        let from_abs = remote_identity(&format!("{}/up.git", a.display()));
        assert_eq!(from_rel, from_abs);
    }

    #[test]
    fn local_paths_collapse_through_symlinks() {
        let td = tempfile::tempdir().unwrap();
        let real = td.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = td.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(unix)]
        assert_eq!(
            remote_identity(link.to_str().unwrap()),
            remote_identity(real.to_str().unwrap())
        );
        // file:// collapses to the same identity.
        assert_eq!(
            remote_identity(&format!("file://{}", real.display())),
            remote_identity(real.to_str().unwrap())
        );
    }
}
