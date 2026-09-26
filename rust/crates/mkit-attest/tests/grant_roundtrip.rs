//! Canonical-form properties of the grant, epoch and visibility codecs
//! (SPEC-WRITE-GRANTS §3, §5.1, §9.1):
//!
//! * `parse(encode(s)) == s` for generated valid statements;
//! * for any bytes `b` near a valid statement, `parse(b)` succeeding implies
//!   `encode(parse(b)) == b`, so no two byte strings share a meaning (and a
//!   statement id);
//! * the same for `X-Write-Grant` header values, and a verified signed
//!   header admits no second spelling.
#![cfg(feature = "grants")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use ed25519_dalek::{Signer as _, SigningKey};
use mkit_attest::grant::{
    AcceptedSchemes, Capabilities, EPOCH_STATEMENT_MAX_LIFETIME_MS, EpochStatement,
    GRANT_MAX_LIFETIME_MS, Grant, Namespace, OwnerScheme, RefFlags, RefPattern, RefScopes,
    RepoScope, RepositoryIdentity, SignedHeader, VerifierConfig, Visibility, VisibilityStatement,
    verify_grant_owner,
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

fn epoch_statement() -> impl Strategy<Value = EpochStatement> {
    (
        namespace(),
        any::<u64>(),
        audiences(),
        0..=i64::MAX - EPOCH_STATEMENT_MAX_LIFETIME_MS,
        1..=EPOCH_STATEMENT_MAX_LIFETIME_MS,
        any::<[u8; 32]>(),
    )
        .prop_map(
            |(namespace, new_epoch, audiences, created, life, nonce)| EpochStatement {
                namespace,
                new_epoch,
                audiences,
                created_ms: created,
                expiry_ms: created + life,
                nonce,
            },
        )
}

fn visibility_statement() -> impl Strategy<Value = VisibilityStatement> {
    (
        namespace(),
        "[a-z0-9][a-z0-9._-]{0,99}",
        prop_oneof![Just(Visibility::Public), Just(Visibility::Private)],
        audiences(),
        0..=i64::MAX - EPOCH_STATEMENT_MAX_LIFETIME_MS,
        1..=EPOCH_STATEMENT_MAX_LIFETIME_MS,
        any::<[u8; 32]>(),
    )
        .prop_map(|(ns, name, visibility, audiences, created, life, nonce)| {
            VisibilityStatement {
                repository: RepositoryIdentity::new(Some(ns), &name).unwrap(),
                visibility,
                audiences,
                created_ms: created,
                expiry_ms: created + life,
                nonce,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn epoch_statement_parse_encode_roundtrip(s in epoch_statement()) {
        let bytes = s.encode().unwrap();
        prop_assert_eq!(EpochStatement::parse(&bytes).unwrap(), s);
    }

    #[test]
    fn epoch_statement_accepted_bytes_are_canonical(
        s in epoch_statement(),
        edits in proptest::collection::vec((any::<u8>(), any::<usize>(), any::<u8>()), 1..4),
    ) {
        let mut bytes = s.encode().unwrap();
        for (op, pos, byte) in edits {
            bytes = mutate(bytes, op, pos, byte);
        }
        if let Ok(parsed) = EpochStatement::parse(&bytes) {
            prop_assert_eq!(parsed.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn visibility_statement_parse_encode_roundtrip(s in visibility_statement()) {
        let bytes = s.encode().unwrap();
        prop_assert_eq!(VisibilityStatement::parse(&bytes).unwrap(), s);
    }

    #[test]
    fn visibility_statement_accepted_bytes_are_canonical(
        s in visibility_statement(),
        edits in proptest::collection::vec((any::<u8>(), any::<usize>(), any::<u8>()), 1..4),
    ) {
        let mut bytes = s.encode().unwrap();
        for (op, pos, byte) in edits {
            bytes = mutate(bytes, op, pos, byte);
        }
        if let Ok(parsed) = VisibilityStatement::parse(&bytes) {
            prop_assert_eq!(parsed.encode().unwrap(), bytes);
        }
    }

    /// No statement parses as more than one kind: the domain field and the
    /// field count keep grants, epoch and visibility statements apart.
    #[test]
    fn grant_epoch_visibility_domains_are_disjoint(
        g in grant(), e in epoch_statement(), v in visibility_statement(),
    ) {
        let g = g.encode().unwrap();
        let e = e.encode().unwrap();
        let v = v.encode().unwrap();
        prop_assert!(EpochStatement::parse(&g).is_err() && VisibilityStatement::parse(&g).is_err());
        prop_assert!(Grant::parse(&e).is_err() && VisibilityStatement::parse(&e).is_err());
        prop_assert!(Grant::parse(&v).is_err() && EpochStatement::parse(&v).is_err());
    }
}

proptest! {
    // Each case signs and verifies once; fewer cases keep the suite fast.
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A signed header edited anywhere either fails verification or still
    /// carries exactly the signed statement and signature: the canonical
    /// base64url decoder admits no second spelling, so a verified grant
    /// cannot be varied by a third party.
    #[test]
    fn grant_verify_mutated_header_never_admits_other_bytes(
        g in grant(), op in any::<u8>(), pos in any::<usize>(), byte in any::<u8>(),
    ) {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut g = g;
        let ns = Namespace::Ed25519(key.verifying_key().to_bytes());
        g.scope = match g.scope {
            RepoScope::Namespace => RepoScope::Namespace,
            RepoScope::Repository(id) => {
                RepoScope::Repository(RepositoryIdentity::new(Some(ns), id.name()).unwrap())
            }
        };
        g.namespace = ns;
        let statement = g.encode().unwrap();
        let blob = key.sign(blake3::hash(&statement).as_bytes()).to_bytes().to_vec();
        let header = SignedHeader { statement: statement.clone(), scheme: OwnerScheme::Ed25519, blob }
            .encode()
            .unwrap();
        let cfg = VerifierConfig::new(
            "https://git.example.com",
            AcceptedSchemes::of(&[OwnerScheme::Ed25519]),
        )
        .unwrap();
        let verified = verify_grant_owner(&cfg, &header).unwrap();
        prop_assert_eq!(verified.statement(), &g);
        let mutated = mutate(header.clone().into_bytes(), op, pos, byte);
        if let Ok(text) = String::from_utf8(mutated)
            && let Ok(verified) = verify_grant_owner(&cfg, &text)
        {
            prop_assert_eq!(&text, &header);
            prop_assert_eq!(verified.statement(), &g);
        }
    }
}
