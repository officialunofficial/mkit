//! Ref scopes (SPEC-WRITE-GRANTS §3.3) and effective flags (§8.1).
//!
//! ```abnf
//! ref-scope  = pattern "=" flags
//! pattern    = ref-name / ref-name "/*"   ; ref-name: SPEC-REFS §3
//! flags      = 1*4flag                    ; a non-empty subsequence of "cufd", in that order
//! flag       = "c" / "u" / "f" / "d"
//! ```

use core::fmt;

use mkit_core::refs::validate_ref_name;

use super::text::strictly_ascending;
use super::{GrantError, MAX_REF_SCOPES};

/// No pattern may be, or begin with, this prefix (§3.3). §8.3 covers packmap
/// refs through their branch instead.
pub const PACKMAP_PREFIX: &str = "refs/mkit/packmap/";
/// The branch prefix a packmap ref travels with (§8.3).
const HEADS_PREFIX: &str = "refs/heads/";

/// §8.3: the head ref `refs/heads/<x>` whose flags cover the packmap ref
/// `refs/mkit/packmap/<x>`. `None` for anything else, including a name
/// outside SPEC-REFS §3. The server authorizes a packmap write only
/// together with this head, in one `AdvanceRefs`, under the head's
/// [`RefScopes::effective_flags`].
#[must_use]
pub fn packmap_head(ref_name: &str) -> Option<String> {
    let branch = ref_name.strip_prefix(PACKMAP_PREFIX)?;
    validate_ref_name(ref_name).then(|| format!("{HEADS_PREFIX}{branch}"))
}

/// §8.3: the packmap ref `refs/mkit/packmap/<x>` of the head ref
/// `refs/heads/<x>`, the inverse of [`packmap_head`]. `None` for anything
/// else.
#[must_use]
pub fn head_packmap(head: &str) -> Option<String> {
    let branch = head.strip_prefix(HEADS_PREFIX)?;
    validate_ref_name(head).then(|| format!("{PACKMAP_PREFIX}{branch}"))
}

/// The `cufd` flags of a ref-scope entry (§3.3, §8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RefFlags(u8);

impl RefFlags {
    /// No flags: every change is denied.
    pub const EMPTY: Self = Self(0);
    /// `c`: create the ref.
    pub const CREATE: Self = Self(1);
    /// `u`: fast-forward update.
    pub const UPDATE: Self = Self(1 << 1);
    /// `f`: non-fast-forward update.
    pub const FORCE: Self = Self(1 << 2);
    /// `d`: delete the ref.
    pub const DELETE: Self = Self(1 << 3);

    /// The canonical order, which is also the text order.
    const ORDER: [(u8, Self); 4] = [
        (b'c', Self::CREATE),
        (b'u', Self::UPDATE),
        (b'f', Self::FORCE),
        (b'd', Self::DELETE),
    ];

    /// Parse a non-empty subsequence of `cufd`, in that order.
    ///
    /// # Errors
    /// `UnknownRefFlag` for a byte outside `cufd`; `RefFlagsNotCanonical`
    /// for empty, repeated or out-of-order flags.
    pub fn parse(s: &str) -> Result<Self, GrantError> {
        if s.is_empty() {
            return Err(GrantError::RefFlagsNotCanonical);
        }
        let mut flags = Self::EMPTY;
        let mut next = 0;
        for b in s.bytes() {
            let index = Self::ORDER
                .iter()
                .position(|&(c, _)| c == b)
                .ok_or(GrantError::UnknownRefFlag)?;
            if index < next {
                return Err(GrantError::RefFlagsNotCanonical);
            }
            flags = flags.union(Self::ORDER[index].1);
            next = index + 1;
        }
        Ok(flags)
    }

    /// Whether every flag of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both sets of flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether no flag is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for RefFlags {
    /// The canonical `cufd` subsequence (empty for [`RefFlags::EMPTY`]).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (c, flag) in Self::ORDER {
            if self.contains(flag) {
                write!(f, "{}", char::from(c))?;
            }
        }
        Ok(())
    }
}

/// A ref-scope pattern.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RefPattern {
    /// A ref name (SPEC-REFS §3) that matches only itself.
    Exact(String),
    /// `P/*`, stored as `P`: matches every ref whose name begins with `P/`,
    /// at any depth.
    Prefix(String),
}

impl RefPattern {
    /// Parse a pattern.
    ///
    /// # Errors
    /// `RefPattern` if it is not a SPEC-REFS §3 ref name, optionally followed
    /// by `/*` (so a bare `*` and `refs/heads/*x` fail); `PackmapPattern` if
    /// it is or begins with [`PACKMAP_PREFIX`].
    pub fn parse(s: &str) -> Result<Self, GrantError> {
        let pattern = match s.strip_suffix("/*") {
            Some(prefix) if validate_ref_name(prefix) => Self::Prefix(prefix.to_owned()),
            None if validate_ref_name(s) => Self::Exact(s.to_owned()),
            _ => return Err(GrantError::RefPattern),
        };
        if s.starts_with(PACKMAP_PREFIX) {
            return Err(GrantError::PackmapPattern);
        }
        Ok(pattern)
    }

    /// Whether this pattern matches `ref_name` (§3.3).
    #[must_use]
    pub fn matches(&self, ref_name: &str) -> bool {
        match self {
            Self::Exact(name) => ref_name == name,
            Self::Prefix(prefix) => ref_name
                .strip_prefix(prefix.as_str())
                .is_some_and(|rest| rest.starts_with('/')),
        }
    }
}

impl fmt::Display for RefPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => f.write_str(name),
            Self::Prefix(prefix) => write!(f, "{prefix}/*"),
        }
    }
}

/// The ref scopes of a grant with `write`: 1 to 16 `pattern=flags` entries in
/// ascending byte order of the whole entry, no two sharing a pattern.
///
/// Only [`RefScopes::new`] and [`RefScopes::parse`] build one, and both
/// enforce every §3.3 rule, so a `RefScopes` always has one encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefScopes(Vec<(RefPattern, RefFlags)>);

impl RefScopes {
    /// Validate entries given in their canonical order. Never sorts.
    ///
    /// # Errors
    /// `RefScopeCount`, `RefPattern`, `PackmapPattern`,
    /// `RefFlagsNotCanonical` (empty flags), `RefScopesUnordered` or
    /// `DuplicateRefPattern`.
    pub fn new(entries: Vec<(RefPattern, RefFlags)>) -> Result<Self, GrantError> {
        if entries.is_empty() || entries.len() > MAX_REF_SCOPES {
            return Err(GrantError::RefScopeCount);
        }
        for (pattern, flags) in &entries {
            // A pattern holding a separator or `*`, or a Prefix/Exact
            // mismatch, does not survive its own text round trip.
            if RefPattern::parse(&pattern.to_string())? != *pattern {
                return Err(GrantError::RefPattern);
            }
            if flags.is_empty() {
                return Err(GrantError::RefFlagsNotCanonical);
            }
        }
        Self::check_order(entries)
    }

    /// Parse a ref-scope field other than `-`.
    ///
    /// # Errors
    /// `RefScopeCount` (checked first), then per entry `RefPattern` (also an
    /// entry without `=`), `PackmapPattern`, `UnknownRefFlag` or
    /// `RefFlagsNotCanonical`, then `RefScopesUnordered` and
    /// `DuplicateRefPattern`.
    pub fn parse(field: &str) -> Result<Self, GrantError> {
        let items: Vec<&str> = field.split(';').collect();
        if items.len() > MAX_REF_SCOPES {
            return Err(GrantError::RefScopeCount);
        }
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            let (pattern, flags) = item.split_once('=').ok_or(GrantError::RefPattern)?;
            entries.push((RefPattern::parse(pattern)?, RefFlags::parse(flags)?));
        }
        Self::check_order(entries)
    }

    fn check_order(entries: Vec<(RefPattern, RefFlags)>) -> Result<Self, GrantError> {
        let texts: Vec<String> = entries.iter().map(|(p, f)| format!("{p}={f}")).collect();
        if !strictly_ascending(&texts) {
            return Err(GrantError::RefScopesUnordered);
        }
        for (i, (pattern, _)) in entries.iter().enumerate() {
            if entries[..i].iter().any(|(earlier, _)| earlier == pattern) {
                return Err(GrantError::DuplicateRefPattern);
            }
        }
        Ok(Self(entries))
    }

    /// The entries, in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[(RefPattern, RefFlags)] {
        &self.0
    }

    /// §8.1: the union of the flags of every entry whose pattern matches
    /// `ref_name`. A ref no pattern matches, or a name outside SPEC-REFS §3,
    /// gets [`RefFlags::EMPTY`], so every change to it is denied.
    ///
    /// A packmap ref (under [`PACKMAP_PREFIX`]) always gets
    /// [`RefFlags::EMPTY`], even under `refs/*` or `refs/mkit/*`: §3.3 never
    /// matches packmap refs directly. §8.3 covers one through its head; see
    /// [`packmap_head`].
    #[must_use]
    pub fn effective_flags(&self, ref_name: &str) -> RefFlags {
        if !validate_ref_name(ref_name) || ref_name.starts_with(PACKMAP_PREFIX) {
            return RefFlags::EMPTY;
        }
        self.0
            .iter()
            .filter(|(pattern, _)| pattern.matches(ref_name))
            .fold(RefFlags::EMPTY, |acc, (_, flags)| acc.union(*flags))
    }
}

impl fmt::Display for RefScopes {
    /// The canonical field text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (pattern, flags)) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(";")?;
            }
            write!(f, "{pattern}={flags}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(field: &str) -> RefScopes {
        let s = RefScopes::parse(field).unwrap();
        assert_eq!(s.to_string(), field);
        s
    }

    #[test]
    fn flags_are_an_ordered_subsequence_of_cufd() {
        for (text, flags) in [
            ("c", RefFlags::CREATE),
            ("cu", RefFlags::CREATE.union(RefFlags::UPDATE)),
            ("ud", RefFlags::UPDATE.union(RefFlags::DELETE)),
            ("d", RefFlags::DELETE),
            (
                "cufd",
                RefFlags::CREATE
                    .union(RefFlags::UPDATE)
                    .union(RefFlags::FORCE)
                    .union(RefFlags::DELETE),
            ),
        ] {
            assert_eq!(RefFlags::parse(text), Ok(flags), "{text}");
            assert_eq!(flags.to_string(), text);
        }
        assert_eq!(RefFlags::parse("x"), Err(GrantError::UnknownRefFlag));
        assert_eq!(RefFlags::parse("cX"), Err(GrantError::UnknownRefFlag));
        assert_eq!(RefFlags::parse("C"), Err(GrantError::UnknownRefFlag));
        assert_eq!(RefFlags::parse("uc"), Err(GrantError::RefFlagsNotCanonical));
        assert_eq!(RefFlags::parse("cc"), Err(GrantError::RefFlagsNotCanonical));
        assert_eq!(
            RefFlags::parse("cufdc"),
            Err(GrantError::RefFlagsNotCanonical)
        );
        assert_eq!(RefFlags::parse(""), Err(GrantError::RefFlagsNotCanonical));
        assert!(RefFlags::EMPTY.is_empty());
        assert!(RefFlags::parse("cufd").unwrap().contains(RefFlags::FORCE));
        assert!(!RefFlags::CREATE.contains(RefFlags::UPDATE));
    }

    #[test]
    fn patterns() {
        assert_eq!(
            RefPattern::parse("refs/heads/main"),
            Ok(RefPattern::Exact("refs/heads/main".into()))
        );
        assert_eq!(
            RefPattern::parse("refs/heads/wip/*"),
            Ok(RefPattern::Prefix("refs/heads/wip".into()))
        );
        assert_eq!(RefPattern::parse("refs/*").unwrap().to_string(), "refs/*");
        // `refs/mkit/packmap` itself is not under the prefix.
        assert!(RefPattern::parse("refs/mkit/packmap").is_ok());
        for bad in [
            "*",
            "/*",
            "refs/heads/*x",
            "refs/heads/**",
            "refs/*/x",
            "refs//x",
            "refs/heads/",
            "refs/heads/main.lock",
            "refs/heads/HEAD",
            "refs/heads/.x",
            "refs/heads/a b",
            "refs/heads/a:b",
            "",
        ] {
            assert_eq!(
                RefPattern::parse(bad),
                Err(GrantError::RefPattern),
                "{bad:?}"
            );
        }
        for packmap in [
            "refs/mkit/packmap/*",
            "refs/mkit/packmap/main",
            "refs/mkit/packmap/a/*",
        ] {
            assert_eq!(RefPattern::parse(packmap), Err(GrantError::PackmapPattern));
        }
    }

    #[test]
    fn ref_scope_lists() {
        let s = scopes("refs/heads/main=cu;refs/heads/wip/*=cufd");
        assert_eq!(s.entries().len(), 2);
        // `/` (0x2F) sorts before `=` (0x3D): the prefix entry comes first.
        scopes("refs/heads/main/*=c;refs/heads/main=c");
        assert_eq!(
            RefScopes::parse("refs/heads/main=c;refs/heads/main/*=c"),
            Err(GrantError::RefScopesUnordered)
        );
        assert_eq!(
            RefScopes::parse("refs/heads/b=c;refs/heads/a=c"),
            Err(GrantError::RefScopesUnordered)
        );
        assert_eq!(
            RefScopes::parse("refs/heads/a=c;refs/heads/a=c"),
            Err(GrantError::RefScopesUnordered)
        );
        assert_eq!(
            RefScopes::parse("refs/heads/main=c;refs/heads/main=cu"),
            Err(GrantError::DuplicateRefPattern)
        );
        assert_eq!(
            RefScopes::parse("refs/heads/main"),
            Err(GrantError::RefPattern)
        );
        assert_eq!(
            RefScopes::parse("refs/heads/main="),
            Err(GrantError::RefFlagsNotCanonical)
        );
        assert_eq!(RefScopes::parse("=c"), Err(GrantError::RefPattern));
        assert_eq!(
            RefScopes::parse("refs/heads/main=c=u"),
            Err(GrantError::UnknownRefFlag)
        );
        assert_eq!(
            RefScopes::parse("refs/heads/a=c;"),
            Err(GrantError::RefPattern)
        );
        let sixteen: Vec<String> = (0..16).map(|i| format!("refs/heads/b{i:02}=c")).collect();
        assert_eq!(scopes(&sixteen.join(";")).entries().len(), 16);
        let seventeen: Vec<String> = (0..17).map(|i| format!("refs/heads/b{i:02}=c")).collect();
        assert_eq!(
            RefScopes::parse(&seventeen.join(";")),
            Err(GrantError::RefScopeCount)
        );
    }

    #[test]
    fn new_validates_like_parse() {
        let exact = |s: &str| RefPattern::Exact(s.into());
        assert!(RefScopes::new(vec![(exact("refs/heads/a"), RefFlags::CREATE)]).is_ok());
        assert_eq!(RefScopes::new(vec![]), Err(GrantError::RefScopeCount));
        assert_eq!(
            RefScopes::new(vec![(exact("refs/heads/*"), RefFlags::CREATE)]),
            Err(GrantError::RefPattern)
        );
        assert_eq!(
            RefScopes::new(vec![(exact("refs/heads/a=c;x"), RefFlags::CREATE)]),
            Err(GrantError::RefPattern)
        );
        assert_eq!(
            RefScopes::new(vec![(
                RefPattern::Prefix("refs/mkit/packmap".into()),
                RefFlags::CREATE
            )]),
            Err(GrantError::PackmapPattern)
        );
        assert_eq!(
            RefScopes::new(vec![(exact("refs/heads/a"), RefFlags::EMPTY)]),
            Err(GrantError::RefFlagsNotCanonical)
        );
        assert_eq!(
            RefScopes::new(vec![
                (exact("refs/heads/b"), RefFlags::CREATE),
                (exact("refs/heads/a"), RefFlags::CREATE),
            ]),
            Err(GrantError::RefScopesUnordered)
        );
    }

    #[test]
    fn effective_flags_exact_match() {
        let s = scopes("refs/heads/main=cu");
        assert_eq!(
            s.effective_flags("refs/heads/main"),
            RefFlags::CREATE.union(RefFlags::UPDATE)
        );
        assert_eq!(s.effective_flags("refs/heads/main2"), RefFlags::EMPTY);
        assert_eq!(s.effective_flags("refs/heads/main/x"), RefFlags::EMPTY);
    }

    #[test]
    fn effective_flags_prefix_at_any_depth() {
        let s = scopes("refs/heads/wip/*=cufd");
        let all = RefFlags::parse("cufd").unwrap();
        assert_eq!(s.effective_flags("refs/heads/wip/a"), all);
        assert_eq!(s.effective_flags("refs/heads/wip/a/b"), all);
        assert_eq!(s.effective_flags("refs/heads/wipx"), RefFlags::EMPTY);
        assert_eq!(s.effective_flags("refs/heads/wip"), RefFlags::EMPTY);
        assert_eq!(s.effective_flags("refs/heads/wipx/a"), RefFlags::EMPTY);
    }

    #[test]
    fn effective_flags_union_of_overlapping_entries() {
        let s = scopes("refs/heads/*=c;refs/heads/wip/*=d;refs/heads/wip/x=u");
        assert_eq!(
            s.effective_flags("refs/heads/wip/x"),
            RefFlags::parse("cud").unwrap()
        );
        assert_eq!(
            s.effective_flags("refs/heads/wip/y"),
            RefFlags::parse("cd").unwrap()
        );
        assert_eq!(s.effective_flags("refs/heads/main"), RefFlags::CREATE);
    }

    #[test]
    fn effective_flags_no_match_or_invalid_name_is_empty() {
        let s = scopes("refs/*=cufd");
        assert_eq!(
            s.effective_flags("refs/heads/main"),
            RefFlags::parse("cufd").unwrap()
        );
        assert_eq!(s.effective_flags("other/x"), RefFlags::EMPTY);
        assert_eq!(s.effective_flags("refs/"), RefFlags::EMPTY);
        assert_eq!(s.effective_flags("refs/heads/main.lock"), RefFlags::EMPTY);
    }

    /// §3.3: packmap refs are never matched directly, even by prefix
    /// patterns that textually cover them.
    #[test]
    fn packmap_refs_get_no_flags() {
        for field in [
            "refs/*=cufd",
            "refs/mkit/*=cufd",
            "refs/*=cufd;refs/mkit/*=u",
        ] {
            let s = scopes(field);
            assert_eq!(s.effective_flags("refs/mkit/packmap/main"), RefFlags::EMPTY);
            assert_eq!(s.effective_flags("refs/mkit/packmap/a/b"), RefFlags::EMPTY);
        }
        // Siblings of the packmap namespace are still ordinary refs.
        let s = scopes("refs/mkit/*=u");
        assert_eq!(s.effective_flags("refs/mkit/other"), RefFlags::UPDATE);
        assert_eq!(s.effective_flags("refs/mkit/packmap"), RefFlags::UPDATE);
    }

    #[test]
    fn packmap_head_maps_to_the_branch_and_back() {
        for (packmap, head) in [
            ("refs/mkit/packmap/main", "refs/heads/main"),
            ("refs/mkit/packmap/wip/a/b", "refs/heads/wip/a/b"),
        ] {
            assert_eq!(packmap_head(packmap).as_deref(), Some(head));
            assert_eq!(head_packmap(head).as_deref(), Some(packmap));
        }
        for not_packmap in [
            "refs/mkit/packmap/",
            "refs/mkit/packmap",
            "refs/mkit/packmap/.x",
            "refs/mkit/packmap/HEAD",
            "refs/heads/main",
            "refs/mkit/packmapx/main",
        ] {
            assert_eq!(packmap_head(not_packmap), None, "{not_packmap}");
        }
        for not_head in [
            "refs/heads/",
            "refs/tags/v1",
            "refs/heads/a.lock",
            "refs/headsx/a",
        ] {
            assert_eq!(head_packmap(not_head), None, "{not_head}");
        }
        // The head's flags cover the packmap (§8.3); its own flags are empty.
        let s = scopes("refs/heads/wip/*=cu");
        let head = packmap_head("refs/mkit/packmap/wip/x").unwrap();
        assert_eq!(s.effective_flags(&head), RefFlags::parse("cu").unwrap());
        assert_eq!(
            s.effective_flags("refs/mkit/packmap/wip/x"),
            RefFlags::EMPTY
        );
    }
}
