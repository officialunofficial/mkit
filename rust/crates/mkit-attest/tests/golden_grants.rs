//! Golden vectors for the grant codec and verifier (SPEC-WRITE-GRANTS §3,
//! §4, §5, §7, §9.1).
//!
//! * `MKIT_WRITE_GOLDEN=1` (re)writes `rust/tests/golden/grants/
//!   {grant-statements.json,headers.json,MANIFEST.txt}` from the vectors
//!   defined here, and the signed `ed25519` fixtures of [`signed`]
//!   (`{grant,epoch,visibility}-ed25519.json`, `reject/verify-*.json`).
//!   `MANIFEST.txt` pins every file in the directory, including the reject
//!   vectors.
//! * The codec's `reject/*.json` (all but `reject/verify-*`) are authored by
//!   the case table in `scripts/golden/grants_ref.py` (`--write-rejects`),
//!   not by this crate.
//! * The normal run reads only the committed files and checks them.
//!
//! `scripts/golden/grants_ref.py` is the independent cross-check of every
//! file here: it rebuilds each statement from its field dict and the spec
//! text, validates it, and recomputes ids and headers.
#![cfg(feature = "grants")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use mkit_attest::grant::{
    Capabilities, GRANT_MAX_LIFETIME_MS, Grant, GrantError, MAX_GRANT_HEADER_BYTES,
    MAX_STATEMENT_BYTES, Namespace, OwnerScheme, RefFlags, RefPattern, RefScopes, RepoScope,
    RepositoryIdentity, SignedHeader,
};
use serde_json::{Value, json};

#[path = "golden_grants/signed.rs"]
mod signed;

/// The §3.4 example statement (illustrative in the spec; pinned here).
const SPEC_EXAMPLE: &str = "mkit-write-grant:v1
0x8ba1f109551bd432803012645ac136ddd64dba72
0x8ba1f109551bd432803012645ac136ddd64dba72/website
3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29
read,write
https://git.example.com,https://git.example.org
refs/heads/main=cu;refs/heads/wip/*=cufd
0
1790000000000
1792592000000
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

/// The auth v2 golden public key (`rust/tests/golden/auth-v2/unary.json`).
const GRANTEE: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
/// Owner seed for the `ed25519-` namespace: the key signed goldens will use.
const OWNER_SEED: [u8; 32] = [9; 32];

fn dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.extend(["tests", "golden", "grants"]);
    d
}

fn maybe_write() {
    static WRITE: std::sync::Once = std::sync::Once::new();
    if std::env::var("MKIT_WRITE_GOLDEN").is_ok() {
        WRITE.call_once(write_all);
    }
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn key_ns() -> Namespace {
    Namespace::Ed25519(
        SigningKey::from_bytes(&OWNER_SEED)
            .verifying_key()
            .to_bytes(),
    )
}

fn addr_ns() -> Namespace {
    Namespace::parse("0x8ba1f109551bd432803012645ac136ddd64dba72").unwrap()
}

fn repo(ns: Namespace, name: &str) -> RepoScope {
    RepoScope::Repository(RepositoryIdentity::new(Some(ns), name).unwrap())
}

fn grantee() -> [u8; 32] {
    hex::decode(GRANTEE).unwrap().try_into().unwrap()
}

fn sorted(items: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = items.iter().map(|s| (*s).to_owned()).collect();
    v.sort();
    v
}

/// Ref scopes from `pattern=flags` texts, put in canonical order.
fn scopes(entries: &[String]) -> RefScopes {
    let mut entries: Vec<String> = entries.to_vec();
    entries.sort();
    RefScopes::new(
        entries
            .iter()
            .map(|e| {
                let (p, f) = e.split_once('=').unwrap();
                (RefPattern::parse(p).unwrap(), RefFlags::parse(f).unwrap())
            })
            .collect(),
    )
    .unwrap()
}

fn texts(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

const EIGHT_AUDIENCES: [&str; 8] = [
    "http://127.0.0.1:8080",
    "http://[::1]:8443",
    "http://localhost:8080",
    "https://a.example",
    "https://git.example.com",
    "https://git.example.org",
    "https://mkit.example.net:8443",
    "https://xn--bcher-kva.example",
];

/// 16 entries: prefix and exact patterns, every flag shape.
const SIXTEEN_SCOPES: [&str; 16] = [
    "refs/changes/*=cd",
    "refs/heads/*=c",
    "refs/heads/dependabot/npm_and_yarn/x=ud",
    "refs/heads/feature/X-1=cf",
    "refs/heads/main/*=ud",
    "refs/heads/main=cu",
    "refs/heads/release-1.0=d",
    "refs/heads/wip/*=cufd",
    "refs/heads/wip/a_b=u",
    "refs/mkit/*=f",
    "refs/mkit/packmap=c",
    "refs/notes/*=cu",
    "refs/notes/commits=d",
    "refs/pull/1/head=u",
    "refs/tags/*=c",
    "refs/tags/v1.0.0=cufd",
];

/// A grant with 8 audiences, 16 ref scopes and the longest identity, the
/// last ref-scope pattern padded so the statement is exactly 4096 bytes.
fn max_length_grant() -> Grant {
    let ns = key_ns();
    let base: Vec<String> = (0..16)
        .map(|i| format!("refs/heads/b{i:02}=cufd"))
        .collect();
    let build = |entries: &[String]| Grant {
        namespace: ns,
        scope: repo(ns, &format!("z{}", "0-._".repeat(33))[..100]),
        grantee: grantee(),
        capabilities: Capabilities::ReadWrite,
        audiences: sorted(&EIGHT_AUDIENCES),
        ref_scopes: Some(scopes(entries)),
        epoch: 7,
        created_ms: 1_790_000_000_000,
        expiry_ms: 1_790_000_000_000 + GRANT_MAX_LIFETIME_MS,
        nonce: [0x44; 32],
    };
    let short = build(&base).encode().unwrap().len();
    let mut entries = base;
    entries[15] = format!(
        "refs/heads/b15{}=cufd",
        "x".repeat(MAX_STATEMENT_BYTES - short)
    );
    build(&entries)
}

/// `(name, grant)` accept vectors.
fn vectors() -> Vec<(&'static str, Grant)> {
    let (key, addr) = (key_ns(), addr_ns());
    vec![
        (
            "spec-3.4-example",
            Grant::parse(SPEC_EXAMPLE.as_bytes()).unwrap(),
        ),
        (
            "read-ed25519-single-repo-created-0-max-lifetime",
            Grant {
                namespace: key,
                scope: repo(key, "website"),
                grantee: grantee(),
                capabilities: Capabilities::Read,
                audiences: texts(&["https://git.example.com"]),
                ref_scopes: None,
                epoch: 1,
                created_ms: 0,
                expiry_ms: GRANT_MAX_LIFETIME_MS,
                nonce: [0x11; 32],
            },
        ),
        (
            "write-0x-namespace-8-audiences-16-scopes-epoch-max",
            Grant {
                namespace: addr,
                scope: RepoScope::Namespace,
                grantee: grantee(),
                capabilities: Capabilities::Write,
                audiences: sorted(&EIGHT_AUDIENCES),
                ref_scopes: Some(scopes(&texts(&SIXTEEN_SCOPES))),
                epoch: u64::MAX,
                created_ms: 1_790_000_000_000,
                expiry_ms: 1_790_003_600_000,
                nonce: [0x22; 32],
            },
        ),
        (
            "read-write-0x-single-repo-max-timestamps",
            Grant {
                namespace: addr,
                scope: repo(addr, "a"),
                grantee: grantee(),
                capabilities: Capabilities::ReadWrite,
                audiences: texts(&["http://[::1]:8443"]),
                ref_scopes: Some(scopes(&texts(&["refs/*=cufd"]))),
                epoch: 0,
                created_ms: i64::MAX - GRANT_MAX_LIFETIME_MS,
                expiry_ms: i64::MAX,
                nonce: [0xff; 32],
            },
        ),
        (
            "write-ed25519-namespace-min-lifetime",
            Grant {
                namespace: key,
                scope: RepoScope::Namespace,
                grantee: grantee(),
                capabilities: Capabilities::Write,
                audiences: texts(&["https://mkit.example.net:8443"]),
                ref_scopes: Some(scopes(&texts(&["refs/heads/main=u"]))),
                epoch: 42,
                created_ms: 1,
                expiry_ms: 2,
                nonce: [0x33; 32],
            },
        ),
        ("read-write-max-length-4096", max_length_grant()),
    ]
}

fn fields_json(g: &Grant) -> Value {
    let scope = match &g.scope {
        RepoScope::Namespace => format!("{}/*", g.namespace),
        RepoScope::Repository(id) => id.to_string(),
    };
    let ref_scopes = g.ref_scopes.as_ref().map(|s| {
        s.entries()
            .iter()
            .map(|(p, f)| json!([p.to_string(), f.to_string()]))
            .collect::<Vec<_>>()
    });
    json!({
        "namespace": g.namespace.to_string(),
        "scope": scope,
        "grantee": hex(&g.grantee),
        "capabilities": g.capabilities.token(),
        "audiences": g.audiences,
        "ref_scopes": ref_scopes,
        "epoch": g.epoch,
        "created": g.created_ms,
        "expiry": g.expiry_ms,
        "nonce": hex(&g.nonce),
    })
}

fn statement_json(name: &str, g: &Grant) -> Value {
    let bytes = g.encode().unwrap();
    json!({
        "name": name,
        "fields": fields_json(g),
        "statement": String::from_utf8(bytes.clone()).unwrap(),
        "id": hex(&g.id().unwrap()),
    })
}

/// `(name, statement, scheme, blob)` header vectors. Blob contents are
/// arbitrary here: signatures are the verifier's concern.
fn header_vectors() -> Vec<(&'static str, Vec<u8>, OwnerScheme, Vec<u8>)> {
    let v = vectors();
    let blob = |n: usize, mul: usize| {
        (0..n)
            .map(|i| u8::try_from(i * mul % 256).unwrap())
            .collect()
    };
    vec![
        (
            "ed25519",
            v[1].1.encode().unwrap(),
            OwnerScheme::Ed25519,
            blob(64, 1),
        ),
        (
            "secp256k1-eip191",
            v[0].1.encode().unwrap(),
            OwnerScheme::Secp256k1Eip191,
            blob(65, 3),
        ),
        (
            "webauthn-p256",
            v[2].1.encode().unwrap(),
            OwnerScheme::WebAuthnP256,
            blob(301, 7),
        ),
        (
            "ed25519-max-length-statement",
            v[5].1.encode().unwrap(),
            OwnerScheme::Ed25519,
            blob(64, 5),
        ),
        // 6135 bytes encode to 8180 characters; ".ed25519." and a 2-byte
        // blob ("YWI") bring the value to exactly MAX_GRANT_HEADER_BYTES.
        (
            "max-length-header",
            vec![b'x'; 6135],
            OwnerScheme::Ed25519,
            b"ab".to_vec(),
        ),
    ]
}

/// `(name, header, expected error)` header rejects.
fn header_rejects() -> Vec<(&'static str, String, GrantError)> {
    let (_, statement, _, blob) = header_vectors().swap_remove(0);
    let valid = SignedHeader {
        statement,
        scheme: OwnerScheme::Ed25519,
        blob,
    }
    .encode()
    .unwrap();
    let (stmt, rest) = valid.split_once('.').unwrap();
    let (_, sig) = rest.split_once('.').unwrap();
    let over = format!("{}.ed25519.YWJj", "eHh4".repeat(6135 / 3));
    assert_eq!(over.len(), MAX_GRANT_HEADER_BYTES + 1);
    vec![
        // A 64-byte blob encodes to 86 characters; padding would add "==".
        ("padding", format!("{valid}=="), GrantError::HeaderBase64),
        (
            "standard-alphabet",
            format!("{stmt}.ed25519.+/8"),
            GrantError::HeaderBase64,
        ),
        (
            "nonzero-trailing-bits",
            format!("{stmt}.ed25519.QR"),
            GrantError::HeaderBase64,
        ),
        (
            "length-1-mod-4",
            format!("{stmt}.ed25519.QUJDR"),
            GrantError::HeaderBase64,
        ),
        (
            "one-dot",
            format!("{stmt}.ed25519"),
            GrantError::HeaderFormat,
        ),
        (
            "three-dots",
            format!("{valid}.{sig}"),
            GrantError::HeaderFormat,
        ),
        (
            "empty-scheme",
            format!("{stmt}..{sig}"),
            GrantError::HeaderFormat,
        ),
        (
            "empty-statement",
            format!(".ed25519.{sig}"),
            GrantError::HeaderFormat,
        ),
        (
            "empty-blob",
            format!("{stmt}.ed25519."),
            GrantError::HeaderFormat,
        ),
        (
            "unknown-scheme",
            format!("{stmt}.ed448.{sig}"),
            GrantError::UnknownScheme,
        ),
        (
            "uppercase-scheme",
            format!("{stmt}.ED25519.{sig}"),
            GrantError::UnknownScheme,
        ),
        ("too-long-8193", over, GrantError::HeaderTooLong),
    ]
}

fn write_json(name: &str, value: &Value) {
    fs::write(
        dir().join(name),
        serde_json::to_string_pretty(value).unwrap() + "\n",
    )
    .unwrap();
}

/// Every fixture file under `dir()` except the manifest, as sorted
/// `/`-separated relative paths.
fn fixture_files() -> Vec<String> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<String>) {
        for entry in fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap();
                let rel: Vec<_> = rel.iter().map(|c| c.to_str().unwrap()).collect();
                out.push(rel.join("/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(&dir(), &dir(), &mut out);
    out.retain(|p| p != "MANIFEST.txt");
    out.sort();
    out
}

fn write_all() {
    fs::create_dir_all(dir()).unwrap();
    let statements: Vec<Value> = vectors()
        .iter()
        .map(|(n, g)| statement_json(n, g))
        .collect();
    write_json(
        "grant-statements.json",
        &json!({ "spec": "SPEC-WRITE-GRANTS §3.2-§3.4", "vectors": statements }),
    );
    let headers: Vec<Value> = header_vectors()
        .into_iter()
        .map(|(name, statement, scheme, blob)| {
            let header = SignedHeader {
                statement: statement.clone(),
                scheme,
                blob: blob.clone(),
            };
            json!({
                "name": name,
                "statement": String::from_utf8(statement).unwrap(),
                "scheme": scheme.token(),
                "blob_hex": hex(&blob),
                "header": header.encode().unwrap(),
            })
        })
        .collect();
    let rejects: Vec<Value> = header_rejects()
        .into_iter()
        .map(|(name, header, err)| {
            json!({ "name": name, "header": header, "expected_error": err.reason() })
        })
        .collect();
    write_json(
        "headers.json",
        &json!({ "spec": "SPEC-WRITE-GRANTS §4.2", "vectors": headers, "rejects": rejects }),
    );
    signed::write_signed();
    let mut manifest = String::from(
        "# SPEC-WRITE-GRANTS grant codec and verifier golden vectors (deterministic)\n\
         # Accept, signed and reject/verify-* vectors: `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-attest --features grants --test golden_grants`\n\
         # Codec reject vectors: `python3 scripts/golden/grants_ref.py rust/tests/golden/grants --write-rejects`\n\
         # Cross-checked by `python3 scripts/golden/grants_ref.py rust/tests/golden/grants`\n\
         # eth-primitives.json: `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-attest --features grants --test golden_eth`\n\
         # Format: <path> <blake3-hex-of-file-bytes>\n",
    );
    for path in fixture_files() {
        let bytes = fs::read(dir().join(&path)).unwrap();
        writeln!(manifest, "{path} {}", hex(blake3::hash(&bytes).as_bytes())).unwrap();
    }
    fs::write(dir().join("MANIFEST.txt"), manifest).unwrap();
}

fn read(name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir().join(name)).unwrap()).unwrap()
}

#[test]
fn grant_statement_goldens() {
    maybe_write();
    let file = read("grant-statements.json");
    let fixtures = file["vectors"].as_array().unwrap();
    let expected = vectors();
    assert_eq!(fixtures.len(), expected.len());
    for (fixture, (name, grant)) in fixtures.iter().zip(&expected) {
        assert_eq!(fixture["name"], *name);
        let bytes = fixture["statement"].as_str().unwrap().as_bytes();
        let (parsed, id) = Grant::parse_with_id(bytes).unwrap();
        assert_eq!(&parsed, grant, "{name}");
        assert_eq!(
            parsed.encode().unwrap(),
            bytes,
            "{name}: encode(parse(b)) == b"
        );
        assert_eq!(fixture["id"], hex(&id), "{name}");
        assert_eq!(parsed.id().unwrap(), id, "{name}");
        assert_eq!(fixture, &statement_json(name, grant), "{name}");
    }
    assert_eq!(fixtures[0]["statement"], SPEC_EXAMPLE);
    let longest = fixtures.last().unwrap()["statement"].as_str().unwrap();
    assert_eq!(longest.len(), MAX_STATEMENT_BYTES);
}

#[test]
fn header_goldens() {
    maybe_write();
    let file = read("headers.json");
    let fixtures = file["vectors"].as_array().unwrap();
    let expected = header_vectors();
    assert_eq!(fixtures.len(), expected.len());
    for (fixture, (name, statement, scheme, blob)) in fixtures.iter().zip(expected) {
        assert_eq!(fixture["name"], name);
        assert_eq!(fixture["scheme"], scheme.token());
        assert_eq!(fixture["blob_hex"], hex(&blob));
        let text = fixture["header"].as_str().unwrap();
        let parsed = SignedHeader::parse(text).unwrap();
        assert_eq!(
            parsed,
            SignedHeader {
                statement,
                scheme,
                blob
            },
            "{name}"
        );
        assert_eq!(parsed.encode().unwrap(), text, "{name}");
    }
    assert_eq!(
        fixtures.last().unwrap()["header"].as_str().unwrap().len(),
        MAX_GRANT_HEADER_BYTES
    );
    let rejects = file["rejects"].as_array().unwrap();
    assert_eq!(rejects.len(), header_rejects().len());
    for (fixture, (name, header, err)) in rejects.iter().zip(header_rejects()) {
        assert_eq!(fixture["name"], name);
        assert_eq!(fixture["header"], header);
        assert_eq!(fixture["expected_error"], err.reason());
        assert_eq!(SignedHeader::parse(&header), Err(err), "{name}");
    }
}

/// Every §3.5 rule family has at least one reject fixture, and each fixture
/// fails with exactly its expected error. (`reject/verify-*` are
/// verification failures, checked by [`signed`].)
#[test]
fn reject_goldens() {
    maybe_write();
    let mut seen = Vec::new();
    let mut count = 0;
    for path in fixture_files()
        .iter()
        .filter(|p| p.starts_with("reject/") && !p.starts_with("reject/verify-"))
    {
        let fixture = read(path);
        let statement = fixture["statement"].as_str().unwrap();
        let expected = fixture["expected_error"].as_str().unwrap();
        let err = Grant::parse(statement.as_bytes()).unwrap_err();
        assert_eq!(err.reason(), expected, "{path}");
        assert!(!fixture["rule"].as_str().unwrap().is_empty(), "{path}");
        seen.push(err);
        count += 1;
    }
    let every_rule = [
        GrantError::StatementTooLong,
        GrantError::CarriageReturn,
        GrantError::ByteOutOfRange,
        GrantError::FinalLineFeed,
        GrantError::FieldCount,
        GrantError::EmptyField,
        GrantError::Domain,
        GrantError::Namespace,
        GrantError::RepositoryScope,
        GrantError::ScopeNamespaceMismatch,
        GrantError::Decimal,
        GrantError::DecimalOutOfRange,
        GrantError::Hex,
        GrantError::Capabilities,
        GrantError::Audience,
        GrantError::AudienceWildcard,
        GrantError::AudienceCount,
        GrantError::AudiencesUnordered,
        GrantError::RefScopesOnRead,
        GrantError::RefScopesMissing,
        GrantError::RefPattern,
        GrantError::PackmapPattern,
        GrantError::UnknownRefFlag,
        GrantError::RefFlagsNotCanonical,
        GrantError::RefScopeCount,
        GrantError::RefScopesUnordered,
        GrantError::DuplicateRefPattern,
        GrantError::ExpiryNotAfterCreated,
        GrantError::LifetimeTooLong,
    ];
    for rule in every_rule {
        assert!(seen.contains(&rule), "no reject fixture for {rule:?}");
    }
    assert!(count >= every_rule.len());
}

#[test]
fn manifest_pins_every_file() {
    maybe_write();
    let manifest = fs::read_to_string(dir().join("MANIFEST.txt")).unwrap();
    let pinned: Vec<(String, String)> = manifest
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let (p, h) = l.split_once(' ').unwrap();
            (p.to_owned(), h.to_owned())
        })
        .collect();
    let paths: Vec<String> = pinned.iter().map(|(p, _)| p.clone()).collect();
    assert_eq!(
        paths,
        fixture_files(),
        "MANIFEST.txt lists every fixture file"
    );
    for (path, digest) in pinned {
        let bytes = fs::read(dir().join(&path)).unwrap();
        assert_eq!(digest, hex(blake3::hash(&bytes).as_bytes()), "{path}");
    }
}

/// The id is the BLAKE3 of the canonical statement (§3.4), from either
/// entry point; the golden ids are cross-checked by `grants_ref.py`.
#[test]
fn grant_id_is_blake3_of_canonical_bytes() {
    let bytes = SPEC_EXAMPLE.as_bytes();
    let (grant, id) = Grant::parse_with_id(bytes).unwrap();
    assert_eq!(id, *blake3::hash(bytes).as_bytes());
    assert_eq!(grant.id().unwrap(), id);
    // A byte string that is not a canonical grant has no id.
    let with_lf = [bytes, b"\n"].concat();
    assert_eq!(
        Grant::parse_with_id(&with_lf),
        Err(GrantError::FinalLineFeed)
    );
}
