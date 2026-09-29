//! `mkit-url-token:v1` codec, key set and mint tests
//! (SPEC-WRITE-GRANTS §9.4).

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::repo_identity::Namespace;
use zeroize::Zeroizing;

use super::statement::{self, decode_token};
use super::*;
use crate::auth_v2::AuthV2Config;
use crate::error::Code;
use crate::memory::{MemoryBlobStore, MemoryKv};
use crate::pipeline::{AuthMode, Hooks, Pipeline, PipelineConfig};
use crate::repo::{Addressing, NamespaceKey, RepoId, RepoName};
use crate::rt::ManualClock;
use crate::telemetry::NoopMetrics;
use crate::upload::UploadLimits;
use crate::upload::token::TicketKeys;

const AUDIENCE: &str = "https://api.example.test";
const REPO: &str = "room-a";
const T0: i64 = 1_700_000_000_000;

fn seed(byte: u8) -> Zeroizing<[u8; 32]> {
    Zeroizing::new([byte; 32])
}

fn keys() -> UrlTokenKeys {
    UrlTokenKeys::new(seed(9), Vec::new()).unwrap()
}

fn config() -> UrlTokenConfig {
    UrlTokenConfig::new(keys(), DEFAULT_TTL_MS).unwrap()
}

fn repository() -> String {
    format!(
        "{}/room-a",
        Namespace::Ed25519(*SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes())
    )
}

fn active_key_id() -> [u8; 16] {
    statement::key_id(&SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes())
}

fn statement(target: &UrlTarget, epoch: u64, issued_ms: i64, expiry_ms: i64) -> UrlTokenStatement {
    UrlTokenStatement::new(
        AUDIENCE,
        repository(),
        target.clone(),
        epoch,
        issued_ms,
        expiry_ms,
        active_key_id(),
    )
}

fn fields(target: &str, epoch: u64, issued: i64, expiry: i64, key_id: &str) -> String {
    format!(
        "{DOMAIN}\n{AUDIENCE}\n{}\n{target}\n{epoch}\n{issued}\n{expiry}\n{key_id}",
        repository()
    )
}

fn minted_token() -> String {
    config()
        .mint(
            AUDIENCE,
            &repository(),
            &UrlTarget::Object([0xaa; 32]),
            0,
            T0,
            0,
        )
        .unwrap()
        .expose()
        .to_owned()
}

#[test]
fn statement_roundtrip() {
    for target in [
        UrlTarget::Object([0xaa; 32]),
        UrlTarget::path("refs/heads/main", "a/b/c").unwrap(),
        UrlTarget::path("refs/tags/v1", "").unwrap(),
    ] {
        let s = statement(&target, 7, T0, T0 + 900_000);
        assert_eq!(UrlTokenStatement::parse(&s.encode().unwrap()).unwrap(), s);
    }
}

#[test]
fn statement_rejects_noncanonical_fields() {
    let good = String::from_utf8(
        statement(&UrlTarget::Object([0xaa; 32]), 7, T0, T0 + 900_000)
            .encode()
            .unwrap(),
    )
    .unwrap();
    let id = to_hex_bytes(&active_key_id());
    let cases: Vec<(&str, String)> = vec![
        (
            "field count 7",
            good.rsplit_once('\n').unwrap().0.to_owned(),
        ),
        ("field count 9", format!("{good}\nx")),
        ("domain", good.replacen(DOMAIN, "mkit-url-token:v2", 1)),
        (
            "audience",
            good.replacen(AUDIENCE, "HTTPS://API.EXAMPLE.TEST", 1),
        ),
        (
            "repository",
            good.replacen(&repository(), "ed25519-nope/room-a", 1),
        ),
        ("decimal leading zero", good.replacen("\n7\n", "\n07\n", 1)),
        (
            "uppercase key id",
            good.replacen(&id, &id.to_uppercase(), 1),
        ),
        ("issued == expiry", fields("object:aaaa", 7, T0, T0, &id)),
        ("issued > expiry", fields("object:aaaa", 7, T0, T0 - 1, &id)),
        (
            "lifetime too long",
            fields(
                "object:aaaa",
                7,
                T0,
                T0 + i64::try_from(MAX_TTL_MS).unwrap() + 1,
                &id,
            ),
        ),
    ];
    for (name, text) in cases {
        assert!(UrlTokenStatement::parse(text.as_bytes()).is_err(), "{name}");
    }
}

#[test]
fn target_paths() {
    for bad in [
        ".",
        "..",
        "a/./b",
        "a//b",
        "/a",
        "a/",
        "x".repeat(1025).as_str(),
    ] {
        assert!(UrlTarget::path("refs/heads/main", bad).is_err(), "{bad}");
        let field = format!("path:refs/heads/main:{bad}");
        assert!(UrlTarget::parse_field(&field).is_err(), "{field}");
    }
    assert!(
        UrlTarget::path("refs/heads/main", "x".repeat(1024)).is_ok(),
        "1,024-byte path"
    );
    assert_eq!(
        UrlTarget::path("refs/heads/main", "").unwrap().field(),
        "path:refs/heads/main:"
    );
    for bad in ["", "refs//main", "refs/heads/a:b", "r".repeat(513).as_str()] {
        assert!(UrlTarget::path(bad, "x").is_err(), "ref {bad}");
    }
    // A bare name is a valid ref name; serving decides what it resolves to.
    assert!(UrlTarget::path("main", "x").is_ok());
    assert_eq!(
        UrlTarget::parse_field(&UrlTarget::Object([0xaa; 32]).field()).unwrap(),
        UrlTarget::Object([0xaa; 32])
    );
    assert!(UrlTarget::parse_field("object:AA").is_err());
    assert!(UrlTarget::parse_field("other:x").is_err());
}

#[test]
fn target_field_rejects_bad_path_encodings() {
    // `parse_field` decodes strict base64url, then UTF-8, then the path rules.
    for (name, encoded) in [
        ("non-UTF-8", URL_SAFE_NO_PAD.encode([0xff, 0xfe])),
        ("dotdot entry", URL_SAFE_NO_PAD.encode(b"a/../b")),
        ("empty entry", URL_SAFE_NO_PAD.encode(b"a//b")),
    ] {
        assert!(
            UrlTarget::parse_field(&format!("path:refs/heads/main:{encoded}")).is_err(),
            "{name}"
        );
    }
    assert!(UrlTarget::parse_field("path:refs/heads/main:QUJD=").is_err());
    assert!(UrlTarget::parse_field("path:refs/heads/main:+/8").is_err());
}

#[test]
fn decode_token_rejects() {
    let token = minted_token();
    let (stmt, sig) = token.split_once('.').unwrap();
    let cases: Vec<(&str, String)> = vec![
        (
            "too long",
            format!("{}{}", "A".repeat(statement::MAX_TOKEN_LEN + 1), token),
        ),
        ("no separator", token.replace('.', "")),
        ("two separators", format!("{token}.x")),
        ("empty statement", format!(".{sig}")),
        ("empty signature", format!("{stmt}.")),
        ("padding", format!("{stmt}=.{sig}")),
        ("standard alphabet", format!("{stmt}+.{sig}")),
        ("non-zero trailing bits", format!("QR.{sig}")),
        (
            "short signature",
            format!("{stmt}.{}", &sig[..sig.len() - 4]),
        ),
    ];
    for (name, bad) in cases {
        assert!(decode_token(&bad).is_err(), "{name}");
    }
    let (bytes, signature) = decode_token(&token).unwrap();
    assert_eq!(signature.len(), 64);
    assert_eq!(UrlTokenStatement::parse(&bytes).unwrap().epoch(), 0);
}

#[test]
fn key_id_is_blake3_of_public_key() {
    let public = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let expected: [u8; 16] = hash(&public)[..16].try_into().unwrap();
    assert_eq!(statement::key_id(&public), expected);
    assert_eq!(keys().active_key_id(), to_hex_bytes(&expected));
}

#[test]
fn key_set_rejects_invalid_retired_keys() {
    let active = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let retired = |public| RetiredKey {
        public,
        retired_at_ms: 0,
    };
    // Retired equal to the active key, a duplicated retired key id, a
    // non-point and a small-order public key.
    let mut identity = [0; 32];
    identity[0] = 1; // the compressed identity: a small-order point
    for set in [
        vec![retired(active)],
        vec![retired(other), retired(other)],
        vec![retired([0; 32])],
        vec![retired(identity)],
    ] {
        assert_eq!(
            UrlTokenKeys::new(seed(9), set).unwrap_err(),
            UrlTokenConfigError::Keys
        );
    }
}

#[test]
fn retired_key_window() {
    let retired_pub = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let active_pub = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let keys = UrlTokenKeys::new(
        seed(9),
        vec![RetiredKey {
            public: retired_pub,
            retired_at_ms: 1_000,
        }],
    )
    .unwrap();
    let retired_id = statement::key_id(&retired_pub);
    // Active always verifies; retired verifies only before retired_at + ttl.
    assert_eq!(
        keys.verifying_key(&active_key_id(), 61_000, 60_000)
            .map(|key| key.to_bytes()),
        Some(active_pub)
    );
    assert_eq!(
        keys.verifying_key(&retired_id, 60_999, 60_000)
            .map(|key| key.to_bytes()),
        Some(retired_pub)
    );
    assert!(keys.verifying_key(&retired_id, 61_000, 60_000).is_none());
    assert!(keys.verifying_key(&retired_id, -1, 60_000).is_none());
    assert!(keys.verifying_key(&[0xee; 16], T0, 60_000).is_none());
}

#[test]
fn key_file_parses_and_refuses() {
    let active_pub = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let retired_pub = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let text = format!(
        "# deployment keys\n\nactive {}\nretired {} 1700000000000\n",
        to_hex(&[9; 32]),
        to_hex(&retired_pub)
    );
    let keys = UrlTokenKeys::parse_key_file(&text).unwrap();
    assert_eq!(keys.retired.len(), 1);
    assert_eq!(keys.retired[0].public, retired_pub);
    assert_eq!(keys.active.verifying_key().to_bytes(), active_pub);
    let cases: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("no active", "retired aaaa 1\n".into()),
        (
            "two active",
            format!("active {0}\nactive {0}\n", to_hex(&[9; 32])),
        ),
        ("bad seed", "active aa\n".into()),
        ("bad directive", "next aaaa\n".into()),
        ("extra field", format!("active {} x\n", to_hex(&[9; 32]))),
        (
            "bad retired decimal",
            format!(
                "active {}\nretired {} 01\n",
                to_hex(&[9; 32]),
                to_hex(&retired_pub)
            ),
        ),
    ];
    for (name, text) in cases {
        assert_eq!(
            UrlTokenKeys::parse_key_file(&text).unwrap_err(),
            UrlTokenConfigError::Keys,
            "{name}"
        );
    }
    assert!(UrlTokenKeys::parse_key_file_secret(text).is_ok());
}

#[test]
fn key_set_json_shape() {
    let retired_pub = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
    let keys = UrlTokenKeys::new(
        seed(9),
        vec![RetiredKey {
            public: retired_pub,
            retired_at_ms: 1_000,
        }],
    )
    .unwrap();
    assert_eq!(
        keys.key_set_json(60_000),
        format!(
            "{{\"version\":1,\"keys\":[{{\"keyId\":\"{}\",\"alg\":\"ed25519\",\"publicKey\":\"{}\"}},{{\"keyId\":\"{}\",\"alg\":\"ed25519\",\"publicKey\":\"{}\",\"notAfterMs\":\"61000\"}}]}}",
            keys.active_key_id(),
            to_hex(&SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()),
            to_hex_bytes(&statement::key_id(&retired_pub)),
            to_hex(&retired_pub)
        )
    );
    let parsed: serde_json::Value = serde_json::from_str(&keys.key_set_json(60_000)).unwrap();
    assert_eq!(parsed["version"], 1);
    assert_eq!(parsed["keys"].as_array().unwrap().len(), 2);
}

#[test]
fn mint_binds_and_clamps() {
    let cfg = UrlTokenConfig::new(keys(), 60_000).unwrap();
    let target = UrlTarget::path("refs/heads/main", "a/b").unwrap();
    for (requested, expected_ms) in [(0, 60_000), (u32::MAX, 60_000), (30, 30_000)] {
        let minted = cfg
            .mint(AUDIENCE, &repository(), &target, 7, T0, requested)
            .unwrap();
        assert_eq!(minted.expires_at_ms, T0 + expected_ms, "ttl {requested}");
        let (bytes, signature) = decode_token(minted.expose()).unwrap();
        let parsed = UrlTokenStatement::parse(&bytes).unwrap();
        assert_eq!(parsed.audience(), AUDIENCE);
        assert_eq!(parsed.repository(), repository());
        assert_eq!(parsed.target(), &target);
        assert_eq!((parsed.epoch(), parsed.issued_ms()), (7, T0));
        assert_eq!(parsed.expiry_ms(), minted.expires_at_ms);
        assert_eq!(parsed.key_id(), active_key_id());
        SigningKey::from_bytes(&[9; 32])
            .verifying_key()
            .verify_strict(
                hash(&bytes).as_slice(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .unwrap();
    }
}

#[test]
fn config_ttl_bounds() {
    assert_eq!(
        UrlTokenConfig::new(keys(), 0).unwrap_err(),
        UrlTokenConfigError::Ttl
    );
    assert_eq!(
        UrlTokenConfig::new(keys(), MAX_TTL_MS + 1).unwrap_err(),
        UrlTokenConfigError::Ttl
    );
    assert!(UrlTokenConfig::new(keys(), MAX_TTL_MS).is_ok());
}

fn repo() -> RepoId {
    RepoId {
        namespace: NamespaceKey::deployment_default(),
        name: RepoName::new(REPO).unwrap(),
    }
}

#[test]
fn pipeline_new_refuses_bad_token_config() {
    let limits = UploadLimits {
        max_total_bytes: 1 << 20,
        max_chunks: 64,
    };
    let authv2 = AuthMode::AuthV2(AuthV2Config::new(AUDIENCE, REPO).unwrap());
    let clock = Arc::new(ManualClock::new(T0));
    let metrics = Arc::new(NoopMetrics);

    // URL tokens without auth v2 is refused before anything else runs.
    let mut cfg = PipelineConfig::new(Addressing::Single { repo: repo() }, authv2.clone(), limits);
    cfg.url_tokens = Some(config());
    let mut unsigned = cfg.clone();
    unsigned.auth = AuthMode::Open;
    assert_eq!(
        Pipeline::new(
            MemoryBlobStore::default(),
            MemoryKv::default(),
            Hooks::new(),
            unsigned,
            clock.clone(),
            metrics.clone()
        )
        .unwrap_err()
        .code(),
        Code::InvalidArgument
    );

    // A URL-token seed repeating an upload ticket secret is refused.
    let mut shared = cfg.clone();
    shared.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [9; 32])]).unwrap());
    assert_eq!(
        Pipeline::new(
            MemoryBlobStore::default(),
            MemoryKv::default(),
            Hooks::new(),
            shared,
            clock.clone(),
            metrics.clone()
        )
        .unwrap_err()
        .code(),
        Code::InvalidArgument
    );

    // Distinct ticket secrets accept.
    cfg.ticket_keys = Some(TicketKeys::new(vec![("test".into(), [7; 32])]).unwrap());
    Pipeline::new(
        MemoryBlobStore::default(),
        MemoryKv::default(),
        Hooks::new(),
        cfg,
        clock,
        metrics,
    )
    .unwrap();
}

#[test]
fn debug_never_shows_secrets() {
    let keys = keys();
    let keys_debug = format!("{keys:?}");
    let cfg = UrlTokenConfig::new(keys, DEFAULT_TTL_MS).unwrap();
    let minted = cfg
        .mint(
            AUDIENCE,
            &repository(),
            &UrlTarget::Object([0xaa; 32]),
            0,
            T0,
            0,
        )
        .unwrap();
    let seed_hex = to_hex(&[9; 32]);
    for debug in [keys_debug, format!("{cfg:?}"), format!("{minted:?}")] {
        assert!(!debug.contains(&seed_hex), "{debug}");
        assert!(!debug.contains(minted.expose()), "{debug}");
    }
}
