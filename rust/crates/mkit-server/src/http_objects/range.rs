//! Conditional requests and ordinary byte ranges (`SPEC-HTTP-OBJECTS` §5.1).
//! Pure functions over header text; proofs never reach them.

/// What a `Range` header selects from a representation of `len` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Serve the whole representation with 200: no `Range`, an invalid or
    /// unsupported one, a multi-range request, or an `If-Range` that does
    /// not match a strong `ETag`.
    Full,
    /// Serve the inclusive range with 206.
    Partial {
        /// First byte.
        start: u64,
        /// Last byte, already clamped to the representation.
        end: u64,
    },
    /// 416 with `Content-Range: bytes */len`.
    Unsatisfiable,
}

/// One entity-tag in an `If-None-Match` list, weak comparison: `W/` is
/// ignored. Returns whether `etag` (a quoted strong tag) matches any member
/// or the list is `*`.
#[must_use]
pub fn if_none_match(values: &[String], etag: &str) -> bool {
    for value in values {
        let mut rest = value.trim();
        while !rest.is_empty() {
            rest = rest.trim_start_matches([' ', '\t', ',']);
            if let Some(star) = rest.strip_prefix('*') {
                if star.trim().is_empty() || star.trim_start().starts_with(',') {
                    return true;
                }
                return false;
            }
            let tag = rest.strip_prefix("W/").unwrap_or(rest);
            let Some(body) = tag.strip_prefix('"') else {
                // Malformed member: skip to the next comma.
                rest = rest.find(',').map_or("", |i| &rest[i + 1..]);
                continue;
            };
            let Some(close) = body.find('"') else {
                break;
            };
            if &tag[..close + 2] == etag {
                return true;
            }
            rest = &body[close + 1..];
        }
    }
    false
}

fn parse_bound(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // A value beyond u64 is a valid but unsatisfiable position.
    Some(text.parse::<u64>().unwrap_or(u64::MAX))
}

/// Select the bytes for `Range` and `If-Range` against a representation of
/// `len` bytes whose strong validator is `etag`. An invalid `Range` is
/// ignored (never a 400), a multi-range request is a strict 200, and only a
/// matching strong `If-Range` `ETag` enables slicing.
#[must_use]
pub fn select(range: Option<&str>, if_range: Option<&str>, etag: &str, len: u64) -> Selection {
    let Some(spec) = range.map(str::trim) else {
        return Selection::Full;
    };
    if if_range.is_some_and(|validator| validator.trim() != etag) {
        return Selection::Full;
    }
    let Some(spec) = spec
        .split_once('=')
        .filter(|(unit, _)| unit.trim().eq_ignore_ascii_case("bytes"))
        .map(|(_, spec)| spec.trim())
    else {
        return Selection::Full;
    };
    if spec.contains(',') {
        return Selection::Full;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return Selection::Full;
    };
    let (first, last) = (first.trim(), last.trim());
    match (first.is_empty(), last.is_empty()) {
        // `-n`: the final n bytes.
        (true, false) => match parse_bound(last) {
            None => Selection::Full,
            Some(0) => Selection::Unsatisfiable,
            Some(_) if len == 0 => Selection::Unsatisfiable,
            Some(n) => Selection::Partial {
                start: len.saturating_sub(n),
                end: len - 1,
            },
        },
        // `a-` or `a-b`.
        (false, _) => {
            let Some(start) = parse_bound(first) else {
                return Selection::Full;
            };
            let end = if last.is_empty() {
                None
            } else if let Some(end) = parse_bound(last) {
                Some(end)
            } else {
                return Selection::Full;
            };
            if end.is_some_and(|end| end < start) {
                return Selection::Full;
            }
            if start >= len {
                return Selection::Unsatisfiable;
            }
            Selection::Partial {
                start,
                end: end.map_or(len - 1, |end| end.min(len - 1)),
            }
        }
        (true, true) => Selection::Full,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: &str = "\"abc\"";

    #[test]
    fn range_table() {
        use Selection::{Full, Partial, Unsatisfiable};
        let p = |start, end| Partial { start, end };
        for (range, len, want) in [
            (Some("bytes=10-19"), 100, p(10, 19)),
            (Some("bytes=10-"), 100, p(10, 99)),
            (Some("bytes=-10"), 100, p(90, 99)),
            (Some("bytes=-500"), 100, p(0, 99)),
            (Some("bytes=90-500"), 100, p(90, 99)),
            (Some("bytes=0-0"), 1, p(0, 0)),
            (Some("bytes=100-200"), 100, Unsatisfiable),
            (Some("bytes=100-"), 100, Unsatisfiable),
            (Some("bytes=-0"), 100, Unsatisfiable),
            (Some("bytes=0-0"), 0, Unsatisfiable),
            (Some("bytes=-1"), 0, Unsatisfiable),
            (Some("bytes=99999999999999999999-"), 100, Unsatisfiable),
            (Some("bytes=0-1,5-6"), 100, Full),
            (Some("bytes=0-1,5-6"), 0, Full),
            (Some("bytes=5-2"), 100, Full),
            (Some("bytes=a-b"), 100, Full),
            (Some("bytes=-"), 100, Full),
            (Some("bytes=5"), 100, Full),
            (Some("items=1-2"), 100, Full),
            (Some("BYTES=1-2"), 100, p(1, 2)),
            (None, 100, Full),
        ] {
            assert_eq!(select(range, None, TAG, len), want, "{range:?} {len}");
        }
    }

    #[test]
    fn if_range_needs_a_matching_strong_tag() {
        let range = Some("bytes=1-2");
        assert_eq!(
            select(range, Some(TAG), TAG, 10),
            Selection::Partial { start: 1, end: 2 }
        );
        for validator in [
            "W/\"abc\"",
            "\"other\"",
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "",
        ] {
            assert_eq!(select(range, Some(validator), TAG, 10), Selection::Full);
        }
        // An unsatisfiable range with a stale validator is a full 200.
        assert_eq!(
            select(Some("bytes=50-"), Some("\"x\""), TAG, 10),
            Selection::Full
        );
    }

    #[test]
    fn if_none_match_uses_weak_comparison() {
        let v = |s: &str| vec![s.to_owned()];
        assert!(if_none_match(&v(TAG), TAG));
        assert!(if_none_match(&v("W/\"abc\""), TAG));
        assert!(if_none_match(&v("*"), TAG));
        assert!(if_none_match(&v("\"x\", W/\"abc\" , \"y\""), TAG));
        assert!(if_none_match(
            &[v("\"x\"")[0].clone(), v(TAG)[0].clone()],
            TAG
        ));
        assert!(!if_none_match(&v("\"x\", \"y\""), TAG));
        assert!(!if_none_match(&v("\"abcd\""), TAG));
        assert!(!if_none_match(&v("abc"), TAG));
        assert!(!if_none_match(&v(""), TAG));
        assert!(!if_none_match(&[], TAG));
        assert!(!if_none_match(&v("*x"), TAG));
    }
}
