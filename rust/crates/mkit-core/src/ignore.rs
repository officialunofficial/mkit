//! `.mkitignore` glob patterns — port of `src/ignore.zig`.
//!
//! Grammar (subset of `gitignore`):
//! - One pattern per line.
//! - Blank lines and `#`-prefixed lines are skipped.
//! - Leading `!` negates the match (last match wins, matching the
//!   gitignore semantics).
//! - Trailing `/` makes the pattern directory-only.
//! - `*` matches any run of characters except `/`.
//! - `?` matches a single character except `/`.
//! - All other characters match themselves literally.
//!
//! `.mkit` and `.git` are *always* ignored regardless of patterns.
//!
//! Matching is performed on the **basename** of the path, not on full
//! paths — same shape as the Zig original. Multi-segment globs (e.g.
//! `foo/**/bar`) are out of scope for v1.

use std::fs;
use std::io;
use std::path::Path;

/// Hard cap on a `.mkitignore` file (1 MiB) — matches `src/ignore.zig`.
pub const MAX_IGNORE_FILE_BYTES: u64 = 1024 * 1024;

/// Errors returned by [`load`].
#[derive(Debug, thiserror::Error)]
pub enum IgnoreError {
    /// `.mkitignore` exceeded [`MAX_IGNORE_FILE_BYTES`].
    #[error(".mkitignore too large (>{MAX_IGNORE_FILE_BYTES} bytes)")]
    FileTooLarge,
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A single ignore pattern with its modifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// Glob pattern body, with `!` and trailing `/` already stripped.
    pub pattern: String,
    /// `true` if the pattern was prefixed with `!` (un-ignore).
    pub negated: bool,
    /// `true` if the pattern ended with `/` (directory-only).
    pub dir_only: bool,
}

/// Parsed ignore-list from a `.mkitignore` file.
#[derive(Debug, Default, Clone)]
pub struct IgnoreList {
    patterns: Vec<Pattern>,
}

impl IgnoreList {
    /// Construct an empty list (matches nothing user-defined; the
    /// hard-coded `.mkit` / `.git` ignores still apply).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Borrow the parsed patterns.
    #[must_use]
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Returns `true` if `path` (a basename) should be ignored.
    /// `is_dir` controls whether directory-only patterns apply.
    #[must_use]
    pub fn is_ignored(&self, path: &str, is_dir: bool) -> bool {
        // Hard-coded ignores — always skip `.mkit` and `.git`.
        if path == ".mkit" || path == ".git" {
            return true;
        }
        // Walk patterns in order; last match wins.
        let mut ignored = false;
        for p in &self.patterns {
            if p.dir_only && !is_dir {
                continue;
            }
            if glob_match(&p.pattern, path) {
                ignored = !p.negated;
            }
        }
        ignored
    }
}

/// Load `.mkitignore` from `dir`. Returns an empty list if the file is
/// absent.
///
/// # Errors
/// - [`IgnoreError::FileTooLarge`] if the file exceeds 1 MiB.
/// - [`IgnoreError::Io`] for other filesystem failures.
pub fn load(dir: &Path) -> Result<IgnoreList, IgnoreError> {
    let path = dir.join(".mkitignore");
    let meta = match fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(IgnoreList::new()),
        Err(e) => return Err(IgnoreError::Io(e)),
    };
    if meta.len() > MAX_IGNORE_FILE_BYTES {
        return Err(IgnoreError::FileTooLarge);
    }
    let content = fs::read_to_string(&path)?;
    Ok(parse(&content))
}

/// Parse `.mkitignore` content into a list of patterns. Never fails:
/// malformed-looking lines are silently skipped (matches the Zig
/// behaviour).
#[must_use]
pub fn parse(content: &str) -> IgnoreList {
    let mut patterns = Vec::new();
    for raw in content.split('\n') {
        // Strip a single trailing `\r` for Windows-style line endings.
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let mut pat = line;
        let mut negated = false;
        let mut dir_only = false;
        if let Some(rest) = pat.strip_prefix('!') {
            negated = true;
            pat = rest;
        }
        if let Some(rest) = pat.strip_suffix('/') {
            dir_only = true;
            pat = rest;
        }
        if pat.is_empty() {
            continue;
        }
        patterns.push(Pattern {
            pattern: pat.to_string(),
            negated,
            dir_only,
        });
    }
    IgnoreList { patterns }
}

/// Match a basename `name` against a glob `pattern`. Supports `*`
/// (any run of non-`/` chars), `?` (one non-`/` char), and exact
/// literal matches. Mirrors `src/ignore.zig::globMatch`.
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let pat = pattern.as_bytes();
    let nm = name.as_bytes();
    let mut pi = 0usize;
    let mut ni = 0usize;
    let mut star_pat_idx: Option<usize> = None;
    let mut star_name_idx: usize = 0;

    while ni < nm.len() || pi < pat.len() {
        if pi < pat.len() {
            let pc = pat[pi];
            if pc == b'*' {
                star_pat_idx = Some(pi);
                star_name_idx = ni;
                pi += 1;
                continue;
            }
            if ni < nm.len() {
                if pc == b'?' {
                    if nm[ni] != b'/' {
                        pi += 1;
                        ni += 1;
                        continue;
                    }
                } else if pc == nm[ni] {
                    pi += 1;
                    ni += 1;
                    continue;
                }
            }
        }
        if let Some(sp) = star_pat_idx {
            star_name_idx += 1;
            if star_name_idx <= nm.len() {
                // `*` must not consume a `/`.
                if star_name_idx > 0 && nm[star_name_idx - 1] == b'/' {
                    return false;
                }
                pi = sp + 1;
                ni = star_name_idx;
                continue;
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_patterns_match_nothing_user_defined() {
        let il = parse("");
        assert!(!il.is_ignored("anything.txt", false));
        assert!(!il.is_ignored("somedir", true));
    }

    #[test]
    fn exact_filename_match() {
        let il = parse("secret.key");
        assert!(il.is_ignored("secret.key", false));
        assert!(!il.is_ignored("other.key", false));
    }

    #[test]
    fn glob_star_pattern() {
        let il = parse("*.log");
        assert!(il.is_ignored("debug.log", false));
        assert!(!il.is_ignored("debug.txt", false));
    }

    #[test]
    fn directory_pattern_trailing_slash() {
        let il = parse("build/");
        assert!(il.is_ignored("build", true));
        assert!(!il.is_ignored("build", false));
    }

    #[test]
    fn negation_pattern() {
        let il = parse("*.log\n!important.log");
        assert!(il.is_ignored("debug.log", false));
        assert!(!il.is_ignored("important.log", false));
    }

    #[test]
    fn comment_lines_ignored() {
        let il = parse("# this is a comment\n*.tmp");
        assert_eq!(il.patterns().len(), 1);
    }

    #[test]
    fn blank_lines_ignored() {
        let il = parse("\n\n*.tmp\n\n");
        assert_eq!(il.patterns().len(), 1);
    }

    #[test]
    fn glob_question_mark() {
        let il = parse("file?.txt");
        assert!(il.is_ignored("file1.txt", false));
        assert!(!il.is_ignored("file12.txt", false));
    }

    #[test]
    fn default_ignores() {
        let il = parse("");
        assert!(il.is_ignored(".mkit", true));
        assert!(il.is_ignored(".git", true));
        assert!(il.is_ignored(".mkit", false));
        assert!(il.is_ignored(".git", false));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*.zig", "main.zig"));
        assert!(!glob_match("*.zig", "main.txt"));
        assert!(glob_match("test*", "testing"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn windows_line_endings_stripped() {
        let il = parse("*.log\r\n*.tmp\r\n");
        assert_eq!(il.patterns().len(), 2);
        assert_eq!(il.patterns()[0].pattern, "*.log");
        assert_eq!(il.patterns()[1].pattern, "*.tmp");
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = TempDir::new().unwrap();
        let il = load(dir.path()).unwrap();
        assert!(il.patterns().is_empty());
    }

    #[test]
    fn load_with_mkitignore() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".mkitignore"), "*.log\nbuild/\n").unwrap();
        let il = load(dir.path()).unwrap();
        assert_eq!(il.patterns().len(), 2);
        assert!(il.is_ignored("test.log", false));
        assert!(il.is_ignored("build", true));
    }

    #[test]
    fn load_rejects_oversize_file() {
        let dir = TempDir::new().unwrap();
        let oversized = vec![b'#'; usize::try_from(MAX_IGNORE_FILE_BYTES + 1).unwrap()];
        std::fs::write(dir.path().join(".mkitignore"), oversized).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IgnoreError::FileTooLarge));
    }
}
