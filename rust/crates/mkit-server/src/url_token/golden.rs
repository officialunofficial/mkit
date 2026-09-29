//! Golden vectors for `mkit-url-token:v1` (SPEC-WRITE-GRANTS §9.4, §3.1;
//! SPEC-SERVER §7.2).
//!
//! `MKIT_WRITE_GOLDEN=1` (re)writes `rust/tests/golden/url-token/`:
//! `tokens.json` (valid tokens, each with its fields, statement text,
//! BLAKE3 and signature), `targets.json` (valid and invalid `target`
//! fields), `keyset.json` (one active and one retired key and the exact
//! §7.2 rendering), `reject/*.json` (one vector per rejection class) and
//! `MANIFEST.txt` pinning every file's BLAKE3. The normal run reads only
//! the committed files and checks them. `scripts/golden/
//! url_token_ref.py` is the independent cross-check.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use mkit_core::hash::{hash, to_hex, to_hex_bytes};
use mkit_core::repo_identity::Namespace;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::statement::{self, UrlTokenStatement};
use super::*;

/// The fixed signing seed every vector uses.
const SEED: [u8; 32] = [9; 32];
/// A seed that never signs for this deployment (`verify-*` rejects).
const OTHER_SEED: [u8; 32] = [8; 32];
/// The retired verification key's seed (only its public half is a key).
const RETIRED_SEED: [u8; 32] = [5; 32];
/// The namespace the vectors' repository lives in.
const NAMESPACE_SEED: [u8; 32] = [7; 32];
const AUDIENCE: &str = "https://api.example.test";
const ISSUED_MS: i64 = 1_700_000_000_000;
const TTL_MS: u64 = 900_000;
const RETIRED_AT_MS: u64 = 1_699_999_000_000;

fn dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // rust/
    d.extend(["tests", "golden", "url-token"]);
    d
}

fn sign(statement: &[u8], seed: [u8; 32]) -> String {
    let signature = SigningKey::from_bytes(&seed).sign(&hash(statement));
    statement::encode_token(statement, &signature.to_bytes())
}

fn public(seed: [u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(&seed).verifying_key().to_bytes()
}

fn keys() -> UrlTokenKeys {
    UrlTokenKeys::new(
        Zeroizing::new(SEED),
        vec![RetiredKey {
            public: public(RETIRED_SEED),
            retired_at_ms: RETIRED_AT_MS,
        }],
    )
    .unwrap()
}

fn config() -> UrlTokenConfig {
    UrlTokenConfig::new(keys(), TTL_MS).unwrap()
}

fn active_id() -> [u8; 16] {
    statement::key_id(&public(SEED))
}

fn expiry() -> i64 {
    ISSUED_MS + i64::try_from(TTL_MS).unwrap()
}

/// The namespaced repository every vector but `repository-bare-name` uses.
fn repository() -> String {
    format!("{}/room-a", Namespace::Ed25519(public(NAMESPACE_SEED)))
}

/// `(name, repository, target, epoch)` accept vectors.
fn vectors() -> Vec<(String, String, UrlTarget, u64)> {
    let repo = repository();
    vec![
        (
            "object-epoch-0".into(),
            repo.clone(),
            UrlTarget::Object([0xaa; 32]),
            0,
        ),
        (
            "object-epoch-max".into(),
            repo.clone(),
            UrlTarget::Object([0xbb; 32]),
            u64::MAX,
        ),
        (
            "path-nested".into(),
            repo.clone(),
            UrlTarget::path("refs/heads/main", "a/b/c.txt").unwrap(),
            3,
        ),
        (
            "path-root-empty".into(),
            repo.clone(),
            UrlTarget::path("refs/mkit/packmap/main", "").unwrap(),
            7,
        ),
        (
            "path-max-1024".into(),
            repo.clone(),
            UrlTarget::path("refs/heads/main", "x".repeat(MAX_PATH_BYTES)).unwrap(),
            1,
        ),
        (
            "repository-bare-name".into(),
            "room-a".into(),
            UrlTarget::Object([0xcc; 32]),
            0,
        ),
    ]
}

fn statement_of(repository: &str, target: &UrlTarget, epoch: u64) -> UrlTokenStatement {
    UrlTokenStatement::new(
        AUDIENCE,
        repository,
        target.clone(),
        epoch,
        ISSUED_MS,
        expiry(),
        active_id(),
    )
}

fn token_json(name: &str, repository: &str, target: &UrlTarget, epoch: u64) -> Value {
    let statement = statement_of(repository, target, epoch);
    let bytes = statement.encode().unwrap();
    let signature = SigningKey::from_bytes(&SEED).sign(&hash(&bytes));
    json!({
        "name": name,
        "fields": {
            "audience": AUDIENCE,
            "repository": repository,
            "target": target.field(),
            "epoch": epoch,
            "issued_ms": ISSUED_MS,
            "expiry_ms": expiry(),
            "key_id": to_hex_bytes(&active_id()),
        },
        "statement": String::from_utf8(bytes.clone()).unwrap(),
        "blake3": to_hex(&hash(&bytes)),
        "signature_hex": to_hex_bytes(&signature.to_bytes()),
        "token": statement::encode_token(&bytes, &signature.to_bytes()),
    })
}

/// `b64url(path)` inside a `path:<ref>:` target field.
fn path_field(reference: &str, path: &str) -> String {
    format!(
        "path:{reference}:{}",
        URL_SAFE_NO_PAD.encode(path.as_bytes())
    )
}

fn targets_json() -> Value {
    let object = to_hex(&[0xaa; 32]);
    let nested = path_field("refs/heads/main", "a/b/c.txt");
    let max = path_field("refs/heads/main", &"x".repeat(MAX_PATH_BYTES));
    let over = path_field("refs/heads/main", &"x".repeat(MAX_PATH_BYTES + 1));
    let valid = vec![
        json!({"name": "object", "field": format!("object:{object}"), "object_hex": object}),
        json!({"name": "path-nested", "field": nested, "reference": "refs/heads/main", "path": "a/b/c.txt"}),
        json!({"name": "path-empty-root", "field": "path:refs/mkit/packmap/main:", "reference": "refs/mkit/packmap/main", "path": ""}),
        json!({"name": "path-max-1024", "field": max, "reference": "refs/heads/main", "path": "x".repeat(MAX_PATH_BYTES)}),
        json!({"name": "path-multibyte", "field": path_field("refs/heads/main", "é/日"), "reference": "refs/heads/main", "path": "é/日"}),
    ];
    let target = UrlTokenError::Target.reason();
    let invalid =
        |name: &str, field: String| json!({"name": name, "field": field, "reason": target});
    let invalid = vec![
        invalid("object-63-hex", format!("object:{}", "a".repeat(63))),
        invalid("object-uppercase", format!("object:{}", "A".repeat(64))),
        invalid("unknown-kind", format!("blob:{object}")),
        invalid("path-no-separator", "path:refs/heads/main".into()),
        invalid("path-bad-ref", path_field("refs//heads", "a")),
        invalid("path-ref-head", path_field("HEAD", "a")),
        invalid("path-b64-padding", "path:refs/heads/main:YQ==".into()),
        invalid(
            "path-b64-standard-alphabet",
            "path:refs/heads/main:+/8".into(),
        ),
        invalid("path-b64-trailing-bits", "path:refs/heads/main:QR".into()),
        invalid("path-b64-non-utf8", "path:refs/heads/main:_w".into()),
        invalid("path-dot", path_field("refs/heads/main", ".")),
        invalid("path-dotdot", path_field("refs/heads/main", "..")),
        invalid("path-dot-entry", path_field("refs/heads/main", "a/./b")),
        invalid("path-double-slash", path_field("refs/heads/main", "a//b")),
        invalid("path-leading-slash", path_field("refs/heads/main", "/a")),
        invalid("path-trailing-slash", path_field("refs/heads/main", "a/")),
        invalid("path-1025-bytes", over),
    ];
    json!({
        "spec": "SPEC-WRITE-GRANTS §9.4 target field",
        "valid": valid,
        "invalid": invalid,
    })
}

fn keyset_json() -> Value {
    let keys = keys();
    let key_file = format!(
        "active {}\nretired {} {RETIRED_AT_MS}\n",
        to_hex(&SEED),
        to_hex(&public(RETIRED_SEED)),
    );
    json!({
        "spec": "SPEC-SERVER §7.2",
        "key_file": key_file,
        "active_seed": to_hex(&SEED),
        "active_public_key": to_hex(&public(SEED)),
        "active_key_id": keys.active_key_id(),
        "retired": [{
            "public_key": to_hex(&public(RETIRED_SEED)),
            "retired_at_ms": RETIRED_AT_MS,
            "key_id": to_hex_bytes(&statement::key_id(&public(RETIRED_SEED))),
        }],
        "ttl_ms": TTL_MS,
        "json": keys.key_set_json(TTL_MS),
    })
}

/// The statement of the first accept vector, as field text for editing.
fn base_fields() -> Vec<String> {
    statement_of(&repository(), &UrlTarget::Object([0xaa; 32]), 0)
        .encode()
        .unwrap()
        .split(|&b| b == b'\n')
        .map(|f| String::from_utf8(f.to_vec()).unwrap())
        .collect()
}

/// `(name, rule, token, expected reason)` reject vectors — one per
/// rejection class. `expected` is the first stage's reason: a
/// [`UrlTokenError::reason`] for decode or statement failures, and
/// [`TokenRejected`]'s display for key-id or signature failures (the
/// verification phase reports nothing finer).
fn reject_vectors() -> Vec<(String, String, String, String)> {
    let fields = base_fields();
    [token_rejects(&fields), statement_rejects(&fields)].concat()
}

/// The token-syntax rejects (§9.4 token encoding): each edits `good`'s
/// text so decode fails one rule.
fn token_rejects(fields: &[String]) -> Vec<(String, String, String, String)> {
    let good = sign(&fields.join("\n").into_bytes(), SEED);
    // `+` for the first signature character, whatever it is.
    let mut standard = good.clone();
    standard.replace_range(
        good.find('.').unwrap() + 1..good.find('.').unwrap() + 2,
        "+",
    );
    let encoding = UrlTokenError::Encoding.reason();
    vec![
        (
            "token-padding".into(),
            "a `=` anywhere in a token segment is outside the unpadded base64url alphabet".into(),
            format!("{good}="),
            encoding.into(),
        ),
        (
            "token-standard-alphabet".into(),
            "`+` and `/` are the standard base64 alphabet, not base64url".into(),
            standard,
            encoding.into(),
        ),
        (
            "token-nonzero-trailing-bits".into(),
            "the last signature character must carry zero padding bits".into(),
            nonzero_trailing_bits(&good),
            encoding.into(),
        ),
        (
            "token-segment-count".into(),
            "exactly two `.`-joined nonempty segments".into(),
            format!("{good}.{good}"),
            UrlTokenError::Format.reason().into(),
        ),
    ]
}

/// The signed rejects — §3.1/§9.4 statement rules and the §9.4 target
/// grammar, each inside an otherwise-valid statement — plus the two
/// verification rejects, which parse but fail the key set or the
/// signature so the rejection is the uniform [`TokenRejected`].
fn statement_rejects(fields: &[String]) -> Vec<(String, String, String, String)> {
    let base = fields.join("\n").into_bytes();
    let edit = |index: usize, value: String| {
        let mut f = fields.to_vec();
        f[index] = value;
        f.join("\n").into_bytes()
    };
    let mut out: Vec<(String, String, String, String)> = vec![
        (
            "statement-field-count-7".into(),
            "the statement is exactly eight fields".into(),
            sign(&fields[..7].join("\n").into_bytes(), SEED),
            "field count".into(),
        ),
        (
            "statement-field-count-9".into(),
            "the statement is exactly eight fields".into(),
            sign(&edit(7, format!("{}\nx", fields[7])), SEED),
            "field count".into(),
        ),
        (
            "statement-domain".into(),
            "the domain is exactly mkit-url-token:v1".into(),
            sign(&edit(0, "mkit-url-token:v2".into()), SEED),
            "domain".into(),
        ),
        (
            "statement-key-id-uppercase".into(),
            "the key id is 32 lowercase hex digits".into(),
            sign(&edit(7, fields[7].to_uppercase()), SEED),
            "noncanonical hex".into(),
        ),
        (
            "statement-issued-gte-expiry".into(),
            "issued is before expiry".into(),
            sign(&edit(5, fields[6].clone()), SEED),
            "expiry not after created".into(),
        ),
        (
            "statement-lifetime-over-max".into(),
            "expiry - issued is at most the 24 h statement bound".into(),
            sign(
                &edit(
                    6,
                    (ISSUED_MS + i64::try_from(MAX_TTL_MS).unwrap() + 1).to_string(),
                ),
                SEED,
            ),
            "lifetime too long".into(),
        ),
    ];
    let target = UrlTokenError::Target.reason();
    let over_limit = "x".repeat(MAX_PATH_BYTES + 1);
    for (name, path) in [
        ("target-path-dot", "."),
        ("target-path-dotdot", ".."),
        ("target-path-double-slash", "a//b"),
        ("target-path-leading-slash", "/a"),
        ("target-path-trailing-slash", "a/"),
        ("target-path-1025-bytes", over_limit.as_str()),
    ] {
        out.push((
            name.into(),
            "a nonempty path is `/`-joined entry names with no empty, `.` or `..` entry".into(),
            sign(&edit(3, path_field("refs/heads/main", path)), SEED),
            target.into(),
        ));
    }
    out.push((
        "target-path-non-utf8".into(),
        "the base64url path decodes to UTF-8".into(),
        sign(&edit(3, "path:refs/heads/main:_w".into()), SEED),
        target.into(),
    ));
    let rejected = TokenRejected.to_string();
    out.push((
        "verify-unknown-key-id".into(),
        "the key id is the active key or a still-valid retired key".into(),
        sign(&edit(7, to_hex_bytes(&[0xee; 16])), SEED),
        rejected.clone(),
    ));
    out.push((
        "verify-other-key-signature".into(),
        "the Ed25519 signature verifies strictly over blake3(statement)".into(),
        sign(&base, OTHER_SEED),
        rejected,
    ));
    out
}

/// `token` with its last signature character replaced by one with the
/// same data bits and a nonzero padding bit — the same bytes decode,
/// but the encoding is not canonical.
fn nonzero_trailing_bits(token: &str) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = token.to_owned().into_bytes();
    let index = alphabet
        .iter()
        .position(|&c| c == *out.last().unwrap())
        .unwrap();
    *out.last_mut().unwrap() = alphabet[(index & 0x30) | 1];
    String::from_utf8(out).unwrap()
}

fn reject_json(rule: &str, token: &str, expected: &str) -> Value {
    json!({"rule": rule, "token": token, "expected_error": expected})
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
    fs::create_dir_all(dir().join("reject")).unwrap();
    write_json(
        "tokens.json",
        &json!({
            "spec": "SPEC-WRITE-GRANTS §9.4",
            "seed": to_hex(&SEED),
            "public_key": to_hex(&public(SEED)),
            "key_id": to_hex_bytes(&active_id()),
            "ttl_ms": TTL_MS,
            "vectors": vectors()
                .iter()
                .map(|(name, repo, target, epoch)| token_json(name, repo, target, *epoch))
                .collect::<Vec<_>>(),
        }),
    );
    write_json("targets.json", &targets_json());
    write_json("keyset.json", &keyset_json());
    for (name, rule, token, expected) in reject_vectors() {
        write_json(
            &format!("reject/{name}.json"),
            &reject_json(&rule, &token, &expected),
        );
    }
    let mut manifest = String::from(
        "# SPEC-WRITE-GRANTS §9.4 URL token golden vectors (deterministic)\n\
         # All vectors: `MKIT_WRITE_GOLDEN=1 cargo test -p mkit-server --all-features url_token`\n\
         # Cross-checked by `python3 scripts/golden/url_token_ref.py rust/tests/golden/url-token`\n\
         # Format: <path> <blake3-hex-of-file-bytes>\n",
    );
    for path in fixture_files() {
        let bytes = fs::read(dir().join(&path)).unwrap();
        writeln!(manifest, "{path} {}", to_hex(&hash(&bytes))).unwrap();
    }
    fs::write(dir().join("MANIFEST.txt"), manifest).unwrap();
}

fn read(name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir().join(name)).unwrap()).unwrap()
}

/// The first stage's rejection reason for `token`: decode, statement, or
/// the uniform [`TokenRejected`] of the verification phase.
fn first_rejection(cfg: &UrlTokenConfig, token: &str, now_ms: i64) -> String {
    match statement::decode_token(token) {
        Err(e) => return e.reason().to_owned(),
        Ok((bytes, _)) => {
            if let Err(e) = UrlTokenStatement::parse(&bytes) {
                return e.reason().to_owned();
            }
        }
    }
    match cfg.precheck(token, now_ms) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("precheck unexpectedly accepted"),
    }
}

/// tokens.json: each vector re-encodes byte-for-byte and passes all
/// three verification phases for its own binding.
fn check_tokens(cfg: &UrlTokenConfig) {
    let file = read("tokens.json");
    assert_eq!(file["seed"], to_hex(&SEED));
    assert_eq!(file["public_key"], to_hex(&public(SEED)));
    assert_eq!(file["key_id"], to_hex_bytes(&active_id()));
    assert_eq!(file["ttl_ms"], TTL_MS);
    let fixtures = file["vectors"].as_array().unwrap();
    let expected = vectors();
    assert_eq!(fixtures.len(), expected.len());
    for (fixture, (name, repo, target, epoch)) in fixtures.iter().zip(&expected) {
        assert_eq!(fixture["name"], *name, "{name}");
        assert_eq!(fixture, &token_json(name, repo, target, *epoch), "{name}");
        let text = fixture["statement"].as_str().unwrap();
        let statement = UrlTokenStatement::parse(text.as_bytes()).unwrap();
        assert_eq!(statement.encode().unwrap(), text.as_bytes(), "{name}");
        let (bytes, signature) =
            statement::decode_token(fixture["token"].as_str().unwrap()).unwrap();
        assert_eq!(bytes, text.as_bytes(), "{name}");
        assert_eq!(fixture["signature_hex"], to_hex_bytes(&signature), "{name}");
        assert_eq!(fixture["blake3"], to_hex(&hash(&bytes)), "{name}");
        let bound = cfg
            .precheck(fixture["token"].as_str().unwrap(), ISSUED_MS)
            .unwrap()
            .check_binding(
                &Binding {
                    audience: AUDIENCE,
                    repository: repo,
                    target,
                },
                ISSUED_MS,
                TTL_MS,
            )
            .unwrap();
        assert_eq!(bound.epoch(), *epoch, "{name}");
        bound.check_epoch(*epoch).unwrap();
        assert_eq!(
            bound.check_epoch(epoch.wrapping_add(1)),
            Err(TokenRejected),
            "{name}"
        );
    }
}

/// targets.json: every valid field parses and re-encodes; every invalid
/// field fails the grammar.
fn check_targets() {
    let file = read("targets.json");
    assert_eq!(file["valid"].as_array().unwrap().len(), 5);
    assert_eq!(file["invalid"].as_array().unwrap().len(), 17);
    for v in file["valid"].as_array().unwrap() {
        let target = UrlTarget::parse_field(v["field"].as_str().unwrap()).unwrap();
        match &target {
            UrlTarget::Object(id) => {
                assert_eq!(v["object_hex"], to_hex(id), "{}", v["name"]);
            }
            UrlTarget::Path { reference, path } => {
                assert_eq!(v["reference"], *reference, "{}", v["name"]);
                assert_eq!(v["path"], *path, "{}", v["name"]);
            }
        }
        assert_eq!(
            target.field(),
            v["field"].as_str().unwrap(),
            "{}",
            v["name"]
        );
    }
    for v in file["invalid"].as_array().unwrap() {
        assert_eq!(v["reason"], UrlTokenError::Target.reason(), "{}", v["name"]);
        assert_eq!(
            UrlTarget::parse_field(v["field"].as_str().unwrap()),
            Err(TargetError),
            "{}",
            v["name"]
        );
    }
}

/// keyset.json: the key file parses to the same key set, and the
/// rendered §7.2 JSON is byte-identical.
fn check_keyset() {
    let file = read("keyset.json");
    let parsed = UrlTokenKeys::parse_key_file(file["key_file"].as_str().unwrap()).unwrap();
    assert_eq!(parsed.key_set_json(TTL_MS), file["json"], "parsed key set");
    assert_eq!(parsed.active_key_id(), file["active_key_id"]);
    assert_eq!(keys().key_set_json(TTL_MS), file["json"], "built key set");
}

/// reject/*.json: one file per case, each rejected with its stated
/// reason at its stated stage.
fn check_rejects(cfg: &UrlTokenConfig) {
    let expected_rejects: std::collections::BTreeMap<_, _> = reject_vectors()
        .into_iter()
        .map(|(name, rule, token, expected)| (name, (rule, token, expected)))
        .collect();
    let mut seen = Vec::new();
    for path in fixture_files().iter().filter(|p| p.starts_with("reject/")) {
        let fixture = read(path);
        let name = path["reject/".len()..path.len() - ".json".len()].to_owned();
        let (rule, token, expected) = expected_rejects
            .get(&name)
            .unwrap_or_else(|| panic!("unexpected reject vector {path}"));
        assert_eq!(&fixture, &reject_json(rule, token, expected), "{path}");
        assert_eq!(
            first_rejection(cfg, token, ISSUED_MS),
            expected.as_str(),
            "{path}"
        );
        seen.push(name);
    }
    seen.sort();
    let mut expected: Vec<_> = expected_rejects.into_keys().collect();
    expected.sort();
    assert_eq!(seen, expected, "reject/ must hold exactly the case table");
}

/// MANIFEST.txt pins every fixture file's BLAKE3.
fn check_manifest() {
    let text = fs::read_to_string(dir().join("MANIFEST.txt")).unwrap();
    let listed: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(listed, fixture_files());
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let (path, digest) = line.split_once(' ').unwrap();
        let bytes = fs::read(dir().join(path)).unwrap();
        assert_eq!(to_hex(&hash(&bytes)), digest, "MANIFEST pin for {path}");
    }
}

#[test]
fn url_token_goldens() {
    if std::env::var("MKIT_WRITE_GOLDEN").is_ok() {
        write_all();
    }
    let cfg = config();
    check_tokens(&cfg);
    check_targets();
    check_keyset();
    check_rejects(&cfg);
    check_manifest();
}
