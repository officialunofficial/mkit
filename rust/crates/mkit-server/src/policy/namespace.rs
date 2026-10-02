use std::collections::BTreeSet;

use mkit_core::repo_identity::Namespace;

/// Namespaces served for writes (SPEC-TRANSPORT-CONNECT §7.5).
/// A denial cannot be overridden by an authorizer (SPEC-SERVER §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamespacePolicy {
    /// Only these owner namespaces may receive writes. The default is empty.
    Allowlist(BTreeSet<Namespace>),
    /// Every self-certifying namespace may receive writes. D27 requires
    /// non-default admission unless the operator explicitly accepts the risk.
    Any {
        /// Permit default admission despite new keys resetting namespace quotas.
        unsafe_without_admission: bool,
    },
}

impl Default for NamespacePolicy {
    fn default() -> Self {
        Self::Allowlist(BTreeSet::new())
    }
}

/// Parse a namespace allowlist file (the native `--namespace-allowlist`
/// file and the Worker `NAMESPACE_ALLOWLIST` var): namespaces separated by
/// newlines or commas, each in its canonical form (`ed25519-<64 hex>` or
/// `0x<40 hex>`). `#` starts a comment that runs to the end of its line;
/// blank entries are ignored. The file is security configuration, not a
/// secret.
///
/// # Errors
/// A message naming the 1-based line of the first malformed or duplicate
/// entry, and "namespace allowlist contains no namespaces" when nothing
/// parses.
pub fn parse_namespace_allowlist(text: &str) -> Result<BTreeSet<Namespace>, String> {
    let mut namespaces = BTreeSet::new();
    for (line, raw) in text.lines().enumerate() {
        let uncommented = raw.split('#').next().unwrap_or_default();
        for entry in uncommented.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let namespace =
                Namespace::parse(entry).map_err(|e| format!("line {}: {e}", line + 1))?;
            if !namespaces.insert(namespace) {
                return Err(format!("line {}: duplicate namespace {entry}", line + 1));
            }
        }
    }
    if namespaces.is_empty() {
        return Err("namespace allowlist contains no namespaces".to_owned());
    }
    Ok(namespaces)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(byte: u8) -> String {
        format!("ed25519-{}", "a".repeat(62) + &format!("{byte:02x}"))
    }

    #[test]
    fn parses_newlines_commas_comments_and_blanks() {
        let text = format!(
            "# deployment owners\n\n  {}\n{},{}  # the third one\n",
            ns(1),
            ns(2),
            ns(3)
        );
        let set = parse_namespace_allowlist(&text).unwrap();
        assert_eq!(set.len(), 3);
        for byte in 1..=3 {
            assert!(set.contains(&Namespace::parse(&ns(byte)).unwrap()));
        }
    }

    #[test]
    fn tolerates_crlf_and_trailing_commas() {
        let set = parse_namespace_allowlist(&format!("{},\r\n{}\r\n", ns(1), ns(2))).unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn accepts_0x_namespaces() {
        let address = format!("0x{}", "b".repeat(40));
        let set = parse_namespace_allowlist(&format!("{},{address}", ns(1))).unwrap();
        assert!(set.contains(&Namespace::Address([0xbb; 20])));
    }

    #[test]
    fn refuses_uppercase_bare_and_garbage() {
        for bad in [
            format!("ed25519-{}", "A".repeat(64)),
            "default".to_owned(),
            format!("0X{}", "b".repeat(40)),
            "not a namespace".to_owned(),
            format!("ed25519-{}/repo", "a".repeat(64)),
        ] {
            let err = parse_namespace_allowlist(&format!("{}\n{bad}", ns(1))).unwrap_err();
            assert!(err.starts_with("line 2:"), "{bad}: {err}");
        }
    }

    #[test]
    fn refuses_duplicates() {
        let err = parse_namespace_allowlist(&format!("{0},{0}", ns(1))).unwrap_err();
        assert_eq!(err, format!("line 1: duplicate namespace {}", ns(1)));
    }

    #[test]
    fn refuses_an_empty_allowlist() {
        for text in ["", "\n", "# only a comment\n", "  , \n"] {
            assert_eq!(
                parse_namespace_allowlist(text).unwrap_err(),
                "namespace allowlist contains no namespaces"
            );
        }
    }
}
