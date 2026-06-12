//! git-side ref-name legality on top of the mkit grammar
//! (SPEC-GIT-BRIDGE §12.1).
//!
//! mkit ref names (SPEC-REFS §3) are already restricted to
//! `[0-9A-Za-z._-]` segments, no empty segments, no exact `.`/`..`
//! segments, no `.lock` suffix. The three residual git-illegal shapes
//! are checked here. No escaping: illegal names are refused per-ref.

use crate::error::Refusal;

/// Check a full mkit ref name (e.g. `refs/heads/main`) for git-side
/// legality. The input is assumed to already satisfy the mkit
/// grammar; this only adds git's extra rules.
pub fn check_git_legal(name: &str) -> Result<(), Refusal> {
    for segment in name.split('/') {
        if segment.starts_with('.') {
            return Err(refusal(name, "segment begins with '.'"));
        }
        if segment.ends_with('.') {
            return Err(refusal(name, "segment ends with '.'"));
        }
        if segment.contains("..") {
            return Err(refusal(name, "segment contains '..'"));
        }
    }
    Ok(())
}

/// Tag-object names ride in the git `tag` header (§7.1): they must
/// satisfy the mkit ref grammar's byte set so the header line is
/// well-formed, plus the git rules above.
// `.lock` is a literal, case-sensitive ref-suffix rule (SPEC-REFS §3),
// not a file-extension comparison.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
pub fn check_tag_name(name: &[u8]) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty");
    }
    // SPEC-OBJECTS caps tag names at 4096 bytes; over-length names
    // must refuse HERE (per-ref) — reaching serialization would turn
    // one hostile tag into a whole-run abort.
    if name.len() > 4096 {
        return Err("over the 4096-byte cap");
    }
    let Ok(s) = std::str::from_utf8(name) else {
        return Err("not UTF-8");
    };
    // SPEC-OBJECTS §6a forbids '/' in tag-object names outright; the
    // remaining charset is the mkit ref-segment grammar.
    for b in s.bytes() {
        if !(b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
            return Err("byte outside the mkit ref-segment grammar");
        }
    }
    if s == "." || s == ".." {
        return Err("'.' or '..' name");
    }
    if s == "HEAD" {
        return Err("'HEAD' is reserved");
    }
    if s.ends_with(".lock") {
        return Err("'.lock' suffix");
    }
    check_git_legal(s).map_err(|_| "git-illegal dot placement")
}

fn refusal(name: &str, reason: &'static str) -> Refusal {
    Refusal::RefName {
        name: name.to_owned(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names_pass() {
        for n in ["refs/heads/main", "refs/tags/v1.0.0", "refs/heads/a-b_c.d"] {
            assert!(check_git_legal(n).is_ok(), "{n}");
        }
    }

    #[test]
    fn git_illegal_dot_shapes_refused() {
        for n in [
            "refs/heads/.hidden",
            "refs/heads/trailing.",
            "refs/heads/a..b",
        ] {
            assert!(check_git_legal(n).is_err(), "{n}");
        }
    }

    #[test]
    fn tag_names_checked() {
        assert!(check_tag_name(b"v1.0.0").is_ok());
        assert!(check_tag_name(b"with space").is_err());
        assert!(check_tag_name(b".dot").is_err());
        assert!(
            check_tag_name(b"no/slash").is_err(),
            "SPEC-OBJECTS 6a forbids '/'"
        );
        assert!(check_tag_name(b"HEAD").is_err());
        assert!(check_tag_name(b"v1.lock").is_err());
        assert!(check_tag_name("naïve".as_bytes()).is_err());
    }
}
