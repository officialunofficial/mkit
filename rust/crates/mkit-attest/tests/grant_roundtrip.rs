//! Canonical-form properties of the grant codec (SPEC-WRITE-GRANTS §3):
//!
//! * `parse(encode(g)) == g` for generated valid grants;
//! * for any bytes `b` near a valid statement, `parse(b)` succeeding implies
//!   `encode(parse(b)) == b`, so no two byte strings share a meaning (and a
//!   grant id);
//! * the same for `X-Write-Grant` header values.
#![cfg(feature = "grants")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use mkit_attest::grant::{
    Capabilities, GRANT_MAX_LIFETIME_MS, Grant, Namespace, OwnerScheme, RefFlags, RefPattern,
    RefScopes, RepoScope, RepositoryIdentity, SignedHeader,
};
use proptest::prelude::*;

const ORIGINS: [&str; 10] = [
    "http://127.0.0.1:8080",
    "http://[::1]:8443",
    "http://localhost:3000",
    "https://a.example",
    "https://b.example:8443",
    "https://git.example.com",
    "https://git.example.org",
    "https://mkit.example.net",
    "https://xn--bcher-kva.example",
    "https://z.example",
];

const PATTERNS: [&str; 12] = [
    "refs/*",
    "refs/heads/*",
    "refs/heads/main",
    "refs/heads/main/*",
    "refs/heads/release-1.0",
    "refs/heads/wip/*",
    "refs/heads/wip/a_b",
    "refs/mkit/*",
    "refs/mkit/packmap",
    "refs/notes/x",
    "refs/tags/*",
    "refs/tags/v1.0.0",
];

fn namespace() -> impl Strategy<Value = Namespace> {
    prop_oneof![
        any::<[u8; 32]>().prop_map(Namespace::Ed25519),
        any::<[u8; 20]>().prop_map(Namespace::Address),
    ]
}

fn scope(ns: Namespace) -> impl Strategy<Value = RepoScope> {
    prop_oneof![
        Just(RepoScope::Namespace),
        "[a-z0-9][a-z0-9._-]{0,99}".prop_map(move |name| {
            RepoScope::Repository(RepositoryIdentity::new(Some(ns), &name).unwrap())
        }),
    ]
}

fn audiences() -> impl Strategy<Value = Vec<String>> {
    proptest::sample::subsequence(ORIGINS.to_vec(), 1..=8)
        .prop_map(|v| v.into_iter().map(str::to_owned).collect())
}

fn ref_scopes() -> impl Strategy<Value = RefScopes> {
    proptest::collection::vec(
        (proptest::sample::select(PATTERNS.to_vec()), 1u8..16),
        1..=16,
    )
    .prop_map(|raw| {
        let mut entries: Vec<(RefPattern, RefFlags)> = Vec::new();
        for (pattern, bits) in raw {
            let pattern = RefPattern::parse(pattern).unwrap();
            if entries.iter().any(|(p, _)| *p == pattern) {
                continue;
            }
            let flags = ["c", "u", "f", "d"]
                .iter()
                .enumerate()
                .filter(|(i, _)| bits & (1 << i) != 0)
                .fold(RefFlags::EMPTY, |acc, (_, f)| {
                    acc.union(RefFlags::parse(f).unwrap())
                });
            entries.push((pattern, flags));
        }
        entries.sort_by_key(|(p, f)| format!("{p}={f}"));
        RefScopes::new(entries).unwrap()
    })
}

fn grant() -> impl Strategy<Value = Grant> {
    namespace().prop_flat_map(|ns| {
        (
            scope(ns),
            any::<[u8; 32]>(),
            prop_oneof![
                Just(Capabilities::Read),
                Just(Capabilities::ReadWrite),
                Just(Capabilities::Write)
            ],
            audiences(),
            ref_scopes(),
            any::<u64>(),
            0..=i64::MAX - GRANT_MAX_LIFETIME_MS,
            1..=GRANT_MAX_LIFETIME_MS,
            any::<[u8; 32]>(),
        )
            .prop_map(
                move |(
                    scope,
                    grantee,
                    capabilities,
                    audiences,
                    scopes,
                    epoch,
                    created,
                    life,
                    nonce,
                )| {
                    Grant {
                        namespace: ns,
                        scope,
                        grantee,
                        capabilities,
                        audiences,
                        ref_scopes: (capabilities != Capabilities::Read).then_some(scopes),
                        epoch,
                        created_ms: created,
                        expiry_ms: created + life,
                        nonce,
                    }
                },
            )
    })
}

/// A byte edit: overwrite, insert or delete at a position.
fn mutate(mut bytes: Vec<u8>, op: u8, pos: usize, byte: u8) -> Vec<u8> {
    if bytes.is_empty() {
        return vec![byte];
    }
    let pos = pos % bytes.len();
    match op % 3 {
        0 => bytes[pos] = byte,
        1 => bytes.insert(pos, byte),
        _ => {
            bytes.remove(pos);
        }
    }
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn grant_parse_encode_roundtrip(g in grant()) {
        let bytes = g.encode().unwrap();
        prop_assert_eq!(Grant::parse(&bytes).unwrap(), g);
    }

    #[test]
    fn grant_accepted_bytes_are_canonical(
        g in grant(),
        edits in proptest::collection::vec((any::<u8>(), any::<usize>(), any::<u8>()), 1..4),
    ) {
        let mut bytes = g.encode().unwrap();
        for (op, pos, byte) in edits {
            bytes = mutate(bytes, op, pos, byte);
        }
        if let Ok(parsed) = Grant::parse(&bytes) {
            prop_assert_eq!(parsed.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn grant_header_roundtrip_and_canonical(
        statement in proptest::collection::vec(any::<u8>(), 1..200),
        blob in proptest::collection::vec(any::<u8>(), 1..140),
        scheme in proptest::sample::select(OwnerScheme::ALL.to_vec()),
        op in any::<u8>(), pos in any::<usize>(), byte in any::<u8>(),
    ) {
        let h = SignedHeader { statement, scheme, blob };
        let text = h.encode().unwrap();
        prop_assert_eq!(SignedHeader::parse(&text).unwrap(), h);
        let mutated = mutate(text.into_bytes(), op, pos, byte);
        if let Ok(text) = String::from_utf8(mutated)
            && let Ok(parsed) = SignedHeader::parse(&text)
        {
            prop_assert_eq!(parsed.encode().unwrap(), text);
        }
    }
}
