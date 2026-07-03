//! `.mkitignore` / `.gitignore` glob patterns.
//!
//! Matching is **path-relative** (git-faithful), not basename-only: callers
//! pass a path relative to the repository root and the matcher honors the
//! gitignore anchoring rules below.
//!
//! Grammar (the implemented v1 subset of `gitignore`):
//! - One pattern per line; blank lines and `#`-prefixed lines are skipped
//!   (`\#` escapes a leading `#` to a literal).
//! - A leading `!` negates (last match wins, gitignore semantics); `\!`
//!   escapes a leading `!` to a literal.
//! - A trailing `/` makes the pattern match directories only.
//! - **Anchoring:** a pattern containing a `/` anywhere other than a trailing
//!   one is *anchored* to the repo root (a leading `/` is one way; `foo/bar`
//!   is another). A pattern with no such `/` matches at **any depth** (as if
//!   prefixed with `**/`), so `*.log` matches `a/b/c.log`.
//! - `*` matches any run of non-`/`; `?` matches a single non-`/`;
//!   `[abc]` / `[a-z]` / `[!abc]` are character classes (single non-`/`).
//!   `\` escapes the next character to a literal.
//! - `**` as a whole path segment crosses `/`: leading `**/` and middle
//!   `/**/` match zero or more directories; a trailing `/**` matches one or
//!   more (everything *inside* a directory). A `**` not isolated by slashes
//!   behaves like a single `*`.
//! - Trailing unescaped spaces are trimmed.
//!
//! `.mkit` and `.git` are *always* ignored (matched on the path's basename,
//! ASCII case-insensitively, so `.MKIT` can't bypass on case-insensitive
//! filesystems — the Git CVE-2021-21300 family).
//!
//! Both `.gitignore` and `.mkitignore` are read from the repository root;
//! `.gitignore` patterns are applied first and `.mkitignore` last, so a
//! repo's own `.mkitignore` takes precedence under last-match-wins.
//!
//! **Deferred (documented non-goals for this pass):** nested per-directory
//! ignore files (only the root is read), global excludes
//! (`core.excludesFile`), and escaped trailing spaces.

use std::fs;
use std::io;
use std::path::Path;

/// Hard cap on a single ignore file (1 MiB).
pub const MAX_IGNORE_FILE_BYTES: u64 = 1024 * 1024;

/// Errors returned by [`load`].
#[derive(Debug, thiserror::Error)]
pub enum IgnoreError {
    /// An ignore file exceeded [`MAX_IGNORE_FILE_BYTES`].
    #[error("ignore file too large (>{MAX_IGNORE_FILE_BYTES} bytes)")]
    FileTooLarge,
    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// One path segment of a parsed pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// A `**` segment — matches across `/` boundaries.
    DoubleStar,
    /// A single-level glob segment (`*`/`?`/`[...]`/literals, no `/`).
    Glob(String),
}

/// A single ignore pattern with its modifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    /// Cleaned glob body, with `!`, the leading `/`, and the trailing `/`
    /// already stripped (e.g. `*.log`, `build`, `src/gen`).
    pub pattern: String,
    /// `true` if the pattern was prefixed with `!` (un-ignore).
    pub negated: bool,
    /// `true` if the pattern ended with `/` (directory-only).
    pub dir_only: bool,
    /// `true` if the pattern is anchored to the repo root (contained a
    /// non-trailing `/`); otherwise it matches at any depth.
    pub anchored: bool,
    /// Effective match segments. Non-anchored patterns carry a leading
    /// [`Segment::DoubleStar`] so they match at any depth.
    segments: Vec<Segment>,
}

impl Pattern {
    /// Match this pattern against a slice of path segments.
    fn matches(&self, path: &[&str]) -> bool {
        match_segments(&self.segments, path)
    }
}

/// Parsed ignore-list (the merged `.gitignore` + `.mkitignore` patterns).
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

    /// Returns `true` if `rel_path` (relative to the repo root, `/`-separated)
    /// should be ignored. `is_dir` controls whether directory-only patterns
    /// apply.
    ///
    /// Callers walk top-down and skip ignored directories without descending,
    /// which is what gives directory-only patterns (`build/`) their
    /// "everything inside is ignored too" behavior — the contents are simply
    /// never visited.
    #[must_use]
    pub fn is_ignored(&self, rel_path: &str, is_dir: bool) -> bool {
        let trimmed = rel_path.trim_matches('/');
        // Hard-coded ignores key off the basename at any depth.
        let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
        if base.eq_ignore_ascii_case(".mkit") || base.eq_ignore_ascii_case(".git") {
            return true;
        }
        let path: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        if path.is_empty() {
            return false;
        }
        // Walk patterns in order; last match wins.
        let mut ignored = false;
        for p in &self.patterns {
            if p.dir_only && !is_dir {
                continue;
            }
            if p.matches(&path) {
                ignored = !p.negated;
            }
        }
        ignored
    }

    /// Like [`is_ignored`](Self::is_ignored), but also returns `true` when any
    /// **ancestor directory** of `rel_path` is ignored — git treats
    /// everything under an excluded directory as excluded.
    ///
    /// Use this for one-shot path tests (an explicit `add <path>`, the restore
    /// safety gate) where there is no top-down walk to carry the
    /// ancestor-ignored bit. Walkers that descend top-down should instead
    /// thread their own ancestor flag (cheaper) and skip ignored directories.
    #[must_use]
    pub fn is_ignored_with_ancestors(&self, rel_path: &str, is_dir: bool) -> bool {
        let trimmed = rel_path.trim_matches('/');
        if trimmed.is_empty() {
            return false;
        }
        let segs: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
        // Each strict ancestor is a directory; if one is ignored, so is this.
        for i in 1..segs.len() {
            if self.is_ignored(&segs[..i].join("/"), true) {
                return true;
            }
        }
        self.is_ignored(trimmed, is_dir)
    }
}

/// Load and merge `.gitignore` then `.mkitignore` from `dir`. Returns an
/// empty list if neither file is present.
///
/// `.gitignore` patterns come first so a repo's own `.mkitignore` wins under
/// last-match-wins.
///
/// # Errors
/// - [`IgnoreError::FileTooLarge`] if either file exceeds 1 MiB.
/// - [`IgnoreError::Io`] for other filesystem failures.
pub fn load(dir: &Path) -> Result<IgnoreList, IgnoreError> {
    let mut patterns = Vec::new();
    for name in [".gitignore", ".mkitignore"] {
        if let Some(list) = load_one(&dir.join(name))? {
            patterns.extend(list.patterns);
        }
    }
    Ok(IgnoreList { patterns })
}

/// Read and parse a single ignore file, or `None` if it is absent.
fn load_one(path: &Path) -> Result<Option<IgnoreList>, IgnoreError> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(IgnoreError::Io(e)),
    };
    if meta.len() > MAX_IGNORE_FILE_BYTES {
        return Err(IgnoreError::FileTooLarge);
    }
    Ok(Some(parse(&fs::read_to_string(path)?)))
}

/// Parse ignore-file content into a list of patterns. Never fails:
/// malformed-looking lines are silently skipped.
#[must_use]
pub fn parse(content: &str) -> IgnoreList {
    let mut patterns = Vec::new();
    for raw in content.split('\n') {
        // Strip a single trailing `\r` for Windows-style line endings.
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(p) = parse_line(line) {
            patterns.push(p);
        }
    }
    IgnoreList { patterns }
}

/// Parse one cleaned line into a [`Pattern`], or `None` for blanks/comments.
fn parse_line(line: &str) -> Option<Pattern> {
    if line.is_empty() || line.starts_with('#') {
        // Blank, or a leading unescaped `#` comment.
        return None;
    }
    // Trim trailing unescaped spaces (escaped trailing spaces are deferred).
    let line = line.trim_end_matches(' ');
    if line.is_empty() {
        return None;
    }
    // Negation (`!`) and leading-escape (`\!`, `\#`) handling.
    let (negated, body) = if let Some(rest) = line.strip_prefix('!') {
        (true, rest.to_string())
    } else if let Some(rest) = line.strip_prefix("\\!") {
        (false, format!("!{rest}"))
    } else if let Some(rest) = line.strip_prefix("\\#") {
        (false, format!("#{rest}"))
    } else {
        (false, line.to_string())
    };
    finish_pattern(&body, negated)
}

/// Build a [`Pattern`] from a (possibly negated) body after `#`/`!` handling.
fn finish_pattern(body: &str, negated: bool) -> Option<Pattern> {
    // Trailing `/` ⇒ directory-only.
    let (dir_only, body) = match body.strip_suffix('/') {
        Some(rest) => (true, rest),
        None => (false, body),
    };
    if body.is_empty() {
        return None;
    }

    // Anchored if there is a `/` anywhere (after the trailing one was
    // stripped). A leading `/` is stripped; it only signals anchoring.
    let anchored = body.contains('/');
    let core = body.strip_prefix('/').unwrap_or(body);
    if core.is_empty() {
        return None;
    }

    let mut segments: Vec<Segment> = core
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s == "**" {
                Segment::DoubleStar
            } else {
                Segment::Glob(s.to_string())
            }
        })
        .collect();
    if segments.is_empty() {
        return None;
    }
    // A non-anchored pattern matches at any depth (as if prefixed `**/`).
    if !anchored {
        segments.insert(0, Segment::DoubleStar);
    }

    Some(Pattern {
        pattern: core.to_string(),
        negated,
        dir_only,
        anchored,
        segments,
    })
}

/// Match a segment list against a path-segment slice (entire-path match).
fn match_segments(pat: &[Segment], path: &[&str]) -> bool {
    match pat.split_first() {
        None => path.is_empty(),
        Some((Segment::DoubleStar, rest)) => {
            if rest.is_empty() {
                // A trailing `**` matches one or more remaining segments
                // (git's "everything inside" — not the directory itself).
                return !path.is_empty();
            }
            // Match zero or more leading segments, then the rest.
            (0..=path.len()).any(|k| match_segments(rest, &path[k..]))
        }
        Some((Segment::Glob(g), rest)) => match path.split_first() {
            Some((first, tail)) => {
                segment_match(g.as_bytes(), first.as_bytes()) && match_segments(rest, tail)
            }
            None => false,
        },
    }
}

/// Match a single path segment against a single-level glob (`*`/`?`/`[...]`,
/// `\` escapes, literals). Never crosses `/` (segments contain none).
fn segment_match(p: &[u8], s: &[u8]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((&b'*', mut rest)) => {
            while rest.first() == Some(&b'*') {
                rest = &rest[1..];
            }
            (0..=s.len()).any(|i| segment_match(rest, &s[i..]))
        }
        Some((&b'?', rest)) => !s.is_empty() && segment_match(rest, &s[1..]),
        Some((&b'[', _)) => match match_class(p, s.first().copied()) {
            Some((matched, plen)) => matched && segment_match(&p[plen..], &s[1..]),
            // Malformed class (no closing `]`) ⇒ literal `[`.
            None => s.first() == Some(&b'[') && segment_match(&p[1..], &s[1..]),
        },
        Some((&b'\\', rest)) => match rest.split_first() {
            Some((&c, rest2)) => s.first() == Some(&c) && segment_match(rest2, &s[1..]),
            None => s.first() == Some(&b'\\') && s.len() == 1,
        },
        Some((&c, rest)) => s.first() == Some(&c) && segment_match(rest, &s[1..]),
    }
}

/// Evaluate a `[...]` character class at the front of `p` against `ch`.
/// Returns `(matched, bytes_consumed_including_brackets)`, or `None` if the
/// class has no closing `]`.
fn match_class(p: &[u8], ch: Option<u8>) -> Option<(bool, usize)> {
    debug_assert_eq!(p.first(), Some(&b'['));
    let mut i = 1;
    let negate = matches!(p.get(i), Some(&b'!' | &b'^'));
    if negate {
        i += 1;
    }
    let start = i;
    let mut matched = false;
    while i < p.len() {
        // A `]` after the first class char closes it; as the first char it is
        // a literal member.
        if p[i] == b']' && i > start {
            // Negation inverts only on a real character (an empty `ch`, i.e.
            // end-of-segment, never matches).
            let result = ch.is_some() && (matched ^ negate);
            return Some((result, i + 1));
        }
        // Range `a-z` (but `-` as the last char before `]` is literal).
        if i + 2 < p.len() && p[i + 1] == b'-' && p[i + 2] != b']' {
            if let Some(c) = ch
                && p[i] <= c
                && c <= p[i + 2]
            {
                matched = true;
            }
            i += 3;
        } else {
            if ch == Some(p[i]) {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

/// Match a basename `name` against a single-level glob `pattern`. Supports
/// `*` (any run of non-`/`), `?` (one non-`/`), `[...]` classes, and `\`
/// escapes. Retained as a small public helper; the [`IgnoreList`] matcher
/// uses the richer path-aware engine above.
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    // Reject any name containing `/`, mirroring the single-level contract.
    if name.contains('/') {
        return false;
    }
    segment_match(pattern.as_bytes(), name.as_bytes())
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
        // ...at any depth.
        assert!(il.is_ignored("sub/.git", true));
    }

    // --- path-relative / anchoring -------------------------------------

    #[test]
    fn non_anchored_matches_at_any_depth() {
        let il = parse("*.log");
        assert!(il.is_ignored("a/b/c.log", false));
        assert!(il.is_ignored("c.log", false));
    }

    #[test]
    fn anchored_leading_slash_matches_root_only() {
        let il = parse("/foo.txt");
        assert!(il.is_ignored("foo.txt", false));
        assert!(!il.is_ignored("sub/foo.txt", false));
    }

    #[test]
    fn anchored_multi_segment() {
        let il = parse("src/gen");
        assert!(il.is_ignored("src/gen", true));
        assert!(!il.is_ignored("other/src/gen", true));
        assert!(!il.is_ignored("gen", true));
    }

    #[test]
    fn dir_only_matches_dir_at_any_depth() {
        let il = parse("build/");
        assert!(il.is_ignored("a/b/build", true));
        assert!(!il.is_ignored("a/b/build", false));
    }

    // --- `**` ----------------------------------------------------------

    #[test]
    fn leading_double_star() {
        let il = parse("**/foo");
        assert!(il.is_ignored("foo", false));
        assert!(il.is_ignored("a/foo", false));
        assert!(il.is_ignored("a/b/foo", false));
        assert!(!il.is_ignored("a/foobar", false));
    }

    #[test]
    fn middle_double_star() {
        let il = parse("a/**/b");
        assert!(il.is_ignored("a/b", false));
        assert!(il.is_ignored("a/x/b", false));
        assert!(il.is_ignored("a/x/y/b", false));
        assert!(!il.is_ignored("a/b/c", false));
    }

    #[test]
    fn trailing_double_star_matches_inside_not_self() {
        let il = parse("abc/**");
        assert!(il.is_ignored("abc/x", false));
        assert!(il.is_ignored("abc/x/y", false));
        // `abc` itself is not matched by a trailing `/**`.
        assert!(!il.is_ignored("abc", true));
    }

    // --- char classes / escapes ----------------------------------------

    #[test]
    fn char_class_range_and_negation() {
        let il = parse("file[0-9].txt");
        assert!(il.is_ignored("file3.txt", false));
        assert!(!il.is_ignored("filex.txt", false));
        let neg = parse("file[!0-9].txt");
        assert!(neg.is_ignored("filex.txt", false));
        assert!(!neg.is_ignored("file3.txt", false));
    }

    #[test]
    fn escaped_hash_and_bang_are_literal() {
        let il = parse("\\#notacomment\n\\!notnegated");
        assert_eq!(il.patterns().len(), 2);
        assert!(il.is_ignored("#notacomment", false));
        assert!(il.is_ignored("!notnegated", false));
    }

    #[test]
    fn trailing_spaces_trimmed() {
        let il = parse("foo.txt   ");
        assert!(il.is_ignored("foo.txt", false));
    }

    // --- negation across anchored / nested -----------------------------

    #[test]
    fn negation_reincludes_specific_file() {
        let il = parse("*.log\n!keep/important.log");
        assert!(il.is_ignored("a/debug.log", false));
        assert!(!il.is_ignored("keep/important.log", false));
    }

    // --- dual-file load / precedence -----------------------------------

    #[test]
    fn comment_lines_count() {
        let il = parse("# this is a comment\n*.tmp");
        assert_eq!(il.patterns().len(), 1);
        assert_eq!(il.patterns()[0].pattern, "*.tmp");
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
    fn load_reads_gitignore_too() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "*.log\n").unwrap();
        let il = load(dir.path()).unwrap();
        assert!(il.is_ignored("debug.log", false));
    }

    #[test]
    fn mkitignore_overrides_gitignore_last_match_wins() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".gitignore"), "*.log\n").unwrap();
        // .mkitignore is applied last, so its re-include wins.
        std::fs::write(dir.path().join(".mkitignore"), "!keep.log\n").unwrap();
        let il = load(dir.path()).unwrap();
        assert!(il.is_ignored("other.log", false));
        assert!(!il.is_ignored("keep.log", false));
    }

    #[test]
    fn load_rejects_oversize_file() {
        let dir = TempDir::new().unwrap();
        let oversized = vec![b'#'; usize::try_from(MAX_IGNORE_FILE_BYTES + 1).unwrap()];
        std::fs::write(dir.path().join(".mkitignore"), oversized).unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(matches!(err, IgnoreError::FileTooLarge));
    }

    // --- glob_match public helper --------------------------------------

    #[test]
    fn is_ignored_with_ancestors_catches_files_under_ignored_dir() {
        let il = parse("node_modules/\n");
        // The directory itself and any descendant (file or dir).
        assert!(il.is_ignored_with_ancestors("node_modules", true));
        assert!(il.is_ignored_with_ancestors("node_modules/pkg/index.js", false));
        // Unrelated paths are unaffected.
        assert!(!il.is_ignored_with_ancestors("src/main.rs", false));
        // The plain matcher does NOT catch the descendant (no walk context).
        assert!(!il.is_ignored("node_modules/pkg/index.js", false));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(!glob_match("*.rs", "main.txt"));
        assert!(glob_match("test*", "testing"));
        assert!(glob_match("*", "anything"));
        // Single-level: `*` never crosses `/`.
        assert!(!glob_match("*", "a/b"));
    }
}
