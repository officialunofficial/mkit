//! Signed `ed25519` golden vectors for the verifier (SPEC-WRITE-GRANTS §4,
//! §5.1–§5.2, §7, §9.1):
//!
//! * `grant-ed25519.json`, `epoch-ed25519.json`, `visibility-ed25519.json`:
//!   statements signed by the owner seed `0909…09`, with their ids, the
//!   64-byte signature, the full `X-Write-Grant` value, and accept and
//!   reject contexts, each reject with its `GrantError::reason`;
//! * `reject/verify-*.json`: one verification failure each (wrong scheme
//!   form, unadvertised scheme, bad signature, short blob, expired at
//!   exactly `expiry`, future-dated).
//!
//! `scripts/golden/grants_ref.py` rebuilds every statement, re-signs it with
//! pycryptodome's RFC 8032 Ed25519 (deterministic, so the bytes are equal)
//! and re-runs every context through its own verifier.

use ed25519_dalek::Signer as _;
use mkit_attest::grant::{
    AcceptedSchemes, Capability, EpochStatement, EpochTransition, GrantRequest, OwnerVerified,
    VerifierConfig, Visibility, VisibilityStatement, epoch_transition, verify_epoch_statement,
    verify_grant_owner, verify_visibility_statement,
};

use super::*;

/// The deployment's own audience in every context unless it says otherwise.
const AUDIENCE: &str = "https://git.example.com";
const CREATED: i64 = 1_790_000_000_000;
const DAY_MS: i64 = 86_400_000;
/// A key that is neither the owner nor the grantee.
const OTHER_SEED: [u8; 32] = [10; 32];

fn owner_key() -> SigningKey {
    SigningKey::from_bytes(&OWNER_SEED)
}

fn sign(key: &SigningKey, statement: &[u8]) -> Vec<u8> {
    key.sign(blake3::hash(statement).as_bytes())
        .to_bytes()
        .to_vec()
}

fn header(statement: &[u8], scheme: OwnerScheme, blob: Vec<u8>) -> String {
    SignedHeader {
        statement: statement.to_vec(),
        scheme,
        blob,
    }
    .encode()
    .unwrap()
}

fn cfg(audience: &str, schemes: &[OwnerScheme]) -> VerifierConfig {
    VerifierConfig::new(audience, AcceptedSchemes::of(schemes)).unwrap()
}

fn ed_cfg(audience: &str) -> VerifierConfig {
    cfg(audience, &[OwnerScheme::Ed25519])
}

fn identity(s: &str) -> RepositoryIdentity {
    RepositoryIdentity::parse_bare_allowed(s).unwrap()
}

fn capability(s: &str) -> Capability {
    match s {
        "read" => Capability::Read,
        "write" => Capability::Write,
        _ => panic!("capability {s}"),
    }
}

fn capability_text(c: Capability) -> &'static str {
    match c {
        Capability::Read => "read",
        Capability::Write => "write",
    }
}

fn reason(result: Result<(), GrantError>) -> Value {
    match result {
        Ok(()) => Value::Null,
        Err(e) => json!(e.reason()),
    }
}

// ---- grants ------------------------------------------------------------

/// A per-request context for a grant: `(name, audience, repository, signer,
/// capability, now)`.
type GrantContext = (
    &'static str,
    &'static str,
    String,
    [u8; 32],
    Capability,
    i64,
);

fn grant_vectors() -> Vec<(&'static str, Grant)> {
    let ns = key_ns();
    vec![
        (
            "read-write-single-repo",
            Grant {
                namespace: ns,
                scope: repo(ns, "website"),
                grantee: grantee(),
                capabilities: Capabilities::ReadWrite,
                audiences: texts(&[AUDIENCE, "https://git.example.org"]),
                ref_scopes: Some(scopes(&texts(&[
                    "refs/heads/main=cu",
                    "refs/heads/wip/*=cufd",
                ]))),
                epoch: 3,
                created_ms: CREATED,
                expiry_ms: CREATED + DAY_MS,
                nonce: [0x55; 32],
            },
        ),
        (
            "write-namespace-max-lifetime",
            Grant {
                namespace: ns,
                scope: RepoScope::Namespace,
                grantee: grantee(),
                capabilities: Capabilities::Write,
                audiences: texts(&[AUDIENCE]),
                ref_scopes: Some(scopes(&texts(&["refs/heads/*=cufd"]))),
                epoch: 0,
                created_ms: CREATED,
                expiry_ms: CREATED + GRANT_MAX_LIFETIME_MS,
                nonce: [0x66; 32],
            },
        ),
        (
            "read-single-repo",
            Grant {
                namespace: ns,
                scope: repo(ns, "website"),
                grantee: grantee(),
                capabilities: Capabilities::Read,
                audiences: texts(&[AUDIENCE]),
                ref_scopes: None,
                epoch: 1,
                created_ms: CREATED,
                expiry_ms: CREATED + DAY_MS,
                nonce: [0x77; 32],
            },
        ),
    ]
}

/// `(accept, reject)` contexts per grant vector, rejects with their error.
#[allow(clippy::too_many_lines)] // a data table
fn grant_contexts(i: usize) -> (Vec<GrantContext>, Vec<(GrantContext, GrantError)>) {
    let ns = key_ns();
    let site = format!("{ns}/website");
    let (w, r) = (Capability::Write, Capability::Read);
    let g = grantee();
    let expiry = CREATED + DAY_MS;
    match i {
        0 => (
            vec![
                ("write-at-created", AUDIENCE, site.clone(), g, w, CREATED),
                ("read-at-created", AUDIENCE, site.clone(), g, r, CREATED),
                (
                    "created-30000ms-ahead",
                    AUDIENCE,
                    site.clone(),
                    g,
                    w,
                    CREATED - 30_000,
                ),
                (
                    "last-ms-before-expiry",
                    AUDIENCE,
                    site.clone(),
                    g,
                    w,
                    expiry - 1,
                ),
                (
                    "second-audience",
                    "https://git.example.org",
                    site.clone(),
                    g,
                    w,
                    CREATED,
                ),
            ],
            vec![
                (
                    (
                        "created-30001ms-ahead",
                        AUDIENCE,
                        site.clone(),
                        g,
                        w,
                        CREATED - 30_001,
                    ),
                    GrantError::NotYetValid,
                ),
                (
                    ("at-expiry", AUDIENCE, site.clone(), g, w, expiry),
                    GrantError::Expired,
                ),
                (
                    ("after-expiry", AUDIENCE, site.clone(), g, w, expiry + 1),
                    GrantError::Expired,
                ),
                (
                    (
                        "audience-not-listed",
                        "https://git.example.net",
                        site.clone(),
                        g,
                        w,
                        CREATED,
                    ),
                    GrantError::AudienceNotListed,
                ),
                (
                    (
                        "audience-port-differs",
                        "https://git.example.com:8443",
                        site.clone(),
                        g,
                        w,
                        CREATED,
                    ),
                    GrantError::AudienceNotListed,
                ),
                (
                    (
                        "other-repository",
                        AUDIENCE,
                        format!("{ns}/blog"),
                        g,
                        w,
                        CREATED,
                    ),
                    GrantError::RepositoryNotInScope,
                ),
                (
                    (
                        "other-namespace",
                        AUDIENCE,
                        "0x8ba1f109551bd432803012645ac136ddd64dba72/website".into(),
                        g,
                        w,
                        CREATED,
                    ),
                    GrantError::NamespaceMismatch,
                ),
                (
                    ("bare-repository", AUDIENCE, "website".into(), g, w, CREATED),
                    GrantError::NamespaceMismatch,
                ),
                (
                    (
                        "grantee-mismatch",
                        AUDIENCE,
                        site.clone(),
                        [1; 32],
                        w,
                        CREATED,
                    ),
                    GrantError::GranteeMismatch,
                ),
            ],
        ),
        1 => (
            vec![
                (
                    "write-any-repository",
                    AUDIENCE,
                    format!("{ns}/new-repo"),
                    g,
                    w,
                    CREATED,
                ),
                (
                    "last-ms-of-max-lifetime",
                    AUDIENCE,
                    site.clone(),
                    g,
                    w,
                    CREATED + GRANT_MAX_LIFETIME_MS - 1,
                ),
            ],
            vec![
                (
                    ("read-not-granted", AUDIENCE, site.clone(), g, r, CREATED),
                    GrantError::CapabilityNotGranted,
                ),
                (
                    (
                        "at-max-lifetime-expiry",
                        AUDIENCE,
                        site.clone(),
                        g,
                        w,
                        CREATED + GRANT_MAX_LIFETIME_MS,
                    ),
                    GrantError::Expired,
                ),
            ],
        ),
        _ => (
            vec![("private-read", AUDIENCE, site.clone(), g, r, CREATED)],
            vec![(
                ("write-not-granted", AUDIENCE, site, g, w, CREATED),
                GrantError::CapabilityNotGranted,
            )],
        ),
    }
}

fn run_grant_context(header: &str, ctx: &GrantContext) -> Result<(), GrantError> {
    let (_, audience, repository, signer, capability, now) = ctx;
    let cfg = ed_cfg(audience);
    let verified = verify_grant_owner(&cfg, header)?;
    let repository = identity(repository);
    verified
        .check(
            &cfg,
            &GrantRequest {
                repository: &repository,
                signer,
                capability: *capability,
                now_ms: *now,
            },
        )
        .map(|_| ())
}

fn grant_context_json(ctx: &GrantContext, expected: Option<GrantError>) -> Value {
    let (name, audience, repository, signer, capability, now) = ctx;
    let mut v = json!({
        "name": name,
        "audience": audience,
        "repository": repository,
        "signer": hex(signer),
        "capability": capability_text(*capability),
        "now": now,
    });
    if let Some(e) = expected {
        v["expected_error"] = json!(e.reason());
    }
    v
}

fn signed_json(name: &str, statement: &[u8], fields: &Value, id: [u8; 32]) -> Value {
    let signature = sign(&owner_key(), statement);
    json!({
        "name": name,
        "fields": fields,
        "statement": String::from_utf8(statement.to_vec()).unwrap(),
        "id": hex(&id),
        "signature_hex": hex(&signature),
        "header": header(statement, OwnerScheme::Ed25519, signature),
    })
}

fn owner_json() -> Value {
    json!({
        "owner_seed": hex(&OWNER_SEED),
        "namespace": key_ns().to_string(),
        "accepted_schemes": ["ed25519"],
    })
}

fn grant_file() -> Value {
    let vectors: Vec<Value> = grant_vectors()
        .iter()
        .enumerate()
        .map(|(i, (name, g))| {
            let bytes = g.encode().unwrap();
            let mut v = signed_json(name, &bytes, &fields_json(g), g.id().unwrap());
            let (accept, reject) = grant_contexts(i);
            v["accept_contexts"] = accept.iter().map(|c| grant_context_json(c, None)).collect();
            v["reject_contexts"] = reject
                .iter()
                .map(|(c, e)| grant_context_json(c, Some(*e)))
                .collect();
            v
        })
        .collect();
    let mut file = owner_json();
    file["spec"] = json!("SPEC-WRITE-GRANTS §4, §7");
    file["vectors"] = json!(vectors);
    file
}

// ---- epoch statements ----------------------------------------------------

fn epoch_vector() -> EpochStatement {
    EpochStatement {
        namespace: key_ns(),
        new_epoch: 4,
        audiences: texts(&[AUDIENCE, "https://git.example.org"]),
        created_ms: CREATED,
        expiry_ms: CREATED + 3_600_000,
        nonce: [0x88; 32],
    }
}

/// `(name, audience, now)`.
type EpochContext = (&'static str, &'static str, i64);

/// Epoch contexts and the expected error, if any.
fn epoch_contexts() -> Vec<(EpochContext, Option<GrantError>)> {
    let expiry = CREATED + 3_600_000;
    vec![
        (("at-created", AUDIENCE, CREATED), None),
        (("created-30000ms-ahead", AUDIENCE, CREATED - 30_000), None),
        (("last-ms-before-expiry", AUDIENCE, expiry - 1), None),
        (
            ("created-30001ms-ahead", AUDIENCE, CREATED - 30_001),
            Some(GrantError::NotYetValid),
        ),
        (("at-expiry", AUDIENCE, expiry), Some(GrantError::Expired)),
        (
            ("audience-not-listed", "https://git.example.net", CREATED),
            Some(GrantError::AudienceNotListed),
        ),
    ]
}

/// §5.2 check 7 and the retry rule: `(stored, new, outcome)`.
fn transitions() -> Vec<(u64, u64, EpochTransition)> {
    use EpochTransition::{Advance, Reject, Retry};
    vec![
        (0, 1, Advance),
        (0, 1024, Advance),
        (0, 1025, Reject),
        (5, 5, Retry),
        (5, 4, Reject),
        (u64::MAX - 10, u64::MAX, Advance),
        (u64::MAX - 1025, u64::MAX, Reject),
        (u64::MAX, u64::MAX, Retry),
    ]
}

fn transition_text(t: EpochTransition) -> &'static str {
    match t {
        EpochTransition::Advance => "advance",
        EpochTransition::Retry => "retry",
        EpochTransition::Reject => "reject",
    }
}

fn run_epoch_context(header: &str, audience: &str, now: i64) -> Result<(), GrantError> {
    verify_epoch_statement(&ed_cfg(audience), header, now).map(|_| ())
}

fn epoch_file() -> Value {
    let s = epoch_vector();
    let bytes = s.encode().unwrap();
    let fields = json!({
        "namespace": s.namespace.to_string(),
        "new_epoch": s.new_epoch,
        "audiences": s.audiences,
        "created": s.created_ms,
        "expiry": s.expiry_ms,
        "nonce": hex(&s.nonce),
    });
    let mut v = signed_json("epoch-4", &bytes, &fields, s.id().unwrap());
    v["contexts"] = epoch_contexts()
        .iter()
        .map(|((name, audience, now), e)| {
            json!({ "name": name, "audience": audience, "now": now,
                    "expected_error": e.map(GrantError::reason) })
        })
        .collect();
    let mut file = owner_json();
    file["spec"] = json!("SPEC-WRITE-GRANTS §5.1, §5.2");
    file["vectors"] = json!([v]);
    file["transitions"] = transitions()
        .iter()
        .map(|(stored, new, t)| json!({ "stored": stored, "new": new, "outcome": transition_text(*t) }))
        .collect();
    file
}

// ---- visibility statements -----------------------------------------------

fn visibility_vector() -> VisibilityStatement {
    VisibilityStatement {
        repository: RepositoryIdentity::new(Some(key_ns()), "website").unwrap(),
        visibility: Visibility::Private,
        audiences: texts(&[AUDIENCE]),
        created_ms: CREATED,
        expiry_ms: CREATED + 3_600_000,
        nonce: [0x99; 32],
    }
}

/// `(name, audience, repository, now)`.
type VisibilityContext = (&'static str, &'static str, String, i64);

/// Visibility contexts and the expected error, if any.
fn visibility_contexts() -> Vec<(VisibilityContext, Option<GrantError>)> {
    let site = format!("{}/website", key_ns());
    let expiry = CREATED + 3_600_000;
    vec![
        (("at-created", AUDIENCE, site.clone(), CREATED), None),
        (
            ("last-ms-before-expiry", AUDIENCE, site.clone(), expiry - 1),
            None,
        ),
        (
            (
                "other-repository",
                AUDIENCE,
                format!("{}/blog", key_ns()),
                CREATED,
            ),
            Some(GrantError::NamespaceMismatch),
        ),
        (
            ("at-expiry", AUDIENCE, site.clone(), expiry),
            Some(GrantError::Expired),
        ),
        (
            (
                "created-30001ms-ahead",
                AUDIENCE,
                site.clone(),
                CREATED - 30_001,
            ),
            Some(GrantError::NotYetValid),
        ),
        (
            (
                "audience-not-listed",
                "https://git.example.org",
                site,
                CREATED,
            ),
            Some(GrantError::AudienceNotListed),
        ),
    ]
}

fn run_visibility_context(
    header: &str,
    audience: &str,
    repository: &str,
    now: i64,
) -> Result<(), GrantError> {
    verify_visibility_statement(&ed_cfg(audience), header, &identity(repository), now).map(|_| ())
}

fn visibility_file() -> Value {
    let s = visibility_vector();
    let bytes = s.encode().unwrap();
    let fields = json!({
        "repository": s.repository.to_string(),
        "visibility": s.visibility.token(),
        "audiences": s.audiences,
        "created": s.created_ms,
        "expiry": s.expiry_ms,
        "nonce": hex(&s.nonce),
    });
    let mut v = signed_json("private-website", &bytes, &fields, s.id().unwrap());
    v["contexts"] = visibility_contexts()
        .iter()
        .map(|((name, audience, repository, now), e)| {
            json!({ "name": name, "audience": audience, "repository": repository, "now": now,
                    "expected_error": e.map(GrantError::reason) })
        })
        .collect();
    let mut file = owner_json();
    file["spec"] = json!("SPEC-WRITE-GRANTS §9.1");
    file["vectors"] = json!([v]);
    file
}

// ---- verify rejects --------------------------------------------------------

/// `(file stem, rule, accepted schemes, header, context, expected error)`.
type VerifyReject = (
    &'static str,
    &'static str,
    Vec<OwnerScheme>,
    String,
    GrantContext,
    GrantError,
);

fn verify_rejects() -> Vec<VerifyReject> {
    let (_, good) = grant_vectors().swap_remove(0);
    let bytes = good.encode().unwrap();
    let signed = header(&bytes, OwnerScheme::Ed25519, sign(&owner_key(), &bytes));
    let site = format!("{}/website", key_ns());
    let ctx = |now: i64| -> GrantContext {
        (
            "",
            AUDIENCE,
            site.clone(),
            grantee(),
            Capability::Write,
            now,
        )
    };
    // The same grant for a `0x` namespace, signed with `ed25519`.
    let addr = addr_ns();
    let mut foreign = good.clone();
    foreign.namespace = addr;
    foreign.scope = repo(addr, "website");
    let foreign_bytes = foreign.encode().unwrap();
    let foreign_ctx: GrantContext = (
        "",
        AUDIENCE,
        format!("{addr}/website"),
        grantee(),
        Capability::Write,
        CREATED,
    );
    let mut short = sign(&owner_key(), &bytes);
    short.pop();
    vec![
        (
            "verify-scheme-wrong-namespace-form",
            "§4: ed25519 is valid only for an ed25519- namespace",
            vec![OwnerScheme::Ed25519],
            header(
                &foreign_bytes,
                OwnerScheme::Ed25519,
                sign(&owner_key(), &foreign_bytes),
            ),
            foreign_ctx,
            GrantError::SchemeNamespaceMismatch,
        ),
        (
            "verify-scheme-not-advertised",
            "§4, §7 step 3: a scheme the deployment does not advertise fails",
            vec![OwnerScheme::Secp256k1Eip191],
            signed.clone(),
            ctx(CREATED),
            GrantError::SchemeNotAdvertised,
        ),
        (
            "verify-bad-signature",
            "§7 step 3: the owner signature does not verify (signed by another key)",
            vec![OwnerScheme::Ed25519],
            header(
                &bytes,
                OwnerScheme::Ed25519,
                sign(&SigningKey::from_bytes(&OTHER_SEED), &bytes),
            ),
            ctx(CREATED),
            GrantError::BadSignature,
        ),
        (
            "verify-signature-63-bytes",
            "§4: an ed25519 blob is exactly the 64-byte signature",
            vec![OwnerScheme::Ed25519],
            header(&bytes, OwnerScheme::Ed25519, short),
            ctx(CREATED),
            GrantError::SignatureLength,
        ),
        (
            "verify-expired-at-expiry",
            "§7 step 10: now < expiry, so now == expiry is expired",
            vec![OwnerScheme::Ed25519],
            signed.clone(),
            ctx(good.expiry_ms),
            GrantError::Expired,
        ),
        (
            "verify-future-dated",
            "§7 step 10: created <= now + MAX_CLOCK_LEAD_MS (30000 ms)",
            vec![OwnerScheme::Ed25519],
            signed,
            ctx(CREATED - 30_001),
            GrantError::NotYetValid,
        ),
    ]
}

fn run_verify_reject(r: &VerifyReject) -> Result<(), GrantError> {
    let (_, _, schemes, header, ctx, _) = r;
    let (_, audience, repository, signer, capability, now) = ctx;
    let cfg = cfg(audience, schemes);
    let repository = identity(repository);
    verify_grant_owner(&cfg, header)?
        .check(
            &cfg,
            &GrantRequest {
                repository: &repository,
                signer,
                capability: *capability,
                now_ms: *now,
            },
        )
        .map(|_| ())
}

fn verify_reject_json(r: &VerifyReject) -> Value {
    let (_, rule, schemes, header, ctx, err) = r;
    let mut context = grant_context_json(ctx, None);
    context.as_object_mut().unwrap().remove("name");
    let audience = context.as_object_mut().unwrap().remove("audience").unwrap();
    json!({
        "rule": rule,
        "kind": "grant",
        "accepted_schemes": schemes.iter().map(|s| s.token()).collect::<Vec<_>>(),
        "audience": audience,
        "header": header,
        "context": context,
        "expected_error": err.reason(),
    })
}

/// Writes the signed fixtures; the caller then rewrites `MANIFEST.txt`.
pub(super) fn write_signed() {
    write_json("grant-ed25519.json", &grant_file());
    write_json("epoch-ed25519.json", &epoch_file());
    write_json("visibility-ed25519.json", &visibility_file());
    for r in verify_rejects() {
        write_json(&format!("reject/{}.json", r.0), &verify_reject_json(&r));
    }
}

fn check_signed(fixture: &Value, statement_bytes: &[u8]) -> String {
    let header_text = fixture["header"].as_str().unwrap().to_owned();
    let parsed = SignedHeader::parse(&header_text).unwrap();
    assert_eq!(parsed.statement, statement_bytes);
    assert_eq!(parsed.scheme, OwnerScheme::Ed25519);
    assert_eq!(
        hex(&parsed.blob),
        fixture["signature_hex"].as_str().unwrap()
    );
    assert_eq!(parsed.blob, sign(&owner_key(), statement_bytes));
    assert_eq!(
        fixture["id"].as_str().unwrap(),
        hex(blake3::hash(statement_bytes).as_bytes())
    );
    header_text
}

#[test]
fn grant_ed25519_goldens() {
    maybe_write();
    let file = read("grant-ed25519.json");
    assert_eq!(file, grant_file());
    assert_eq!(file["namespace"], key_ns().to_string());
    let fixtures = file["vectors"].as_array().unwrap();
    let expected = grant_vectors();
    assert_eq!(fixtures.len(), expected.len());
    for (i, (fixture, (name, grant))) in fixtures.iter().zip(&expected).enumerate() {
        assert_eq!(fixture["name"], *name);
        let bytes = fixture["statement"].as_str().unwrap().as_bytes();
        let header_text = check_signed(fixture, bytes);
        let owner = verify_grant_owner(&ed_cfg(AUDIENCE), &header_text).unwrap();
        assert_eq!(owner.statement(), grant, "{name}");
        assert_eq!(hex(owner.id()), fixture["id"].as_str().unwrap());
        let (accept, reject) = grant_contexts(i);
        let accepts = fixture["accept_contexts"].as_array().unwrap();
        assert_eq!(accepts.len(), accept.len());
        for (json_ctx, ctx) in accepts.iter().zip(&accept) {
            assert_eq!(json_ctx["capability"], capability_text(ctx.4));
            assert_eq!(capability(json_ctx["capability"].as_str().unwrap()), ctx.4);
            assert_eq!(
                run_grant_context(&header_text, ctx),
                Ok(()),
                "{name}/{}",
                ctx.0
            );
        }
        let rejects = fixture["reject_contexts"].as_array().unwrap();
        assert_eq!(rejects.len(), reject.len());
        for (json_ctx, (ctx, err)) in rejects.iter().zip(&reject) {
            assert_eq!(json_ctx["expected_error"], err.reason());
            assert_eq!(
                reason(run_grant_context(&header_text, ctx)),
                json_ctx["expected_error"],
                "{name}/{}",
                ctx.0
            );
        }
    }
}

#[test]
fn epoch_ed25519_goldens() {
    maybe_write();
    let file = read("epoch-ed25519.json");
    assert_eq!(file, epoch_file());
    let fixture = &file["vectors"][0];
    let bytes = fixture["statement"].as_str().unwrap().as_bytes();
    assert_eq!(EpochStatement::parse(bytes).unwrap(), epoch_vector());
    let header_text = check_signed(fixture, bytes);
    for ((name, audience, now), err) in epoch_contexts() {
        assert_eq!(
            run_epoch_context(&header_text, audience, now),
            err.map_or(Ok(()), Err),
            "{name}"
        );
    }
    let verified: OwnerVerified<EpochStatement> =
        verify_epoch_statement(&ed_cfg(AUDIENCE), &header_text, CREATED).unwrap();
    assert_eq!(verified.statement(), &epoch_vector());
    for (stored, new, outcome) in transitions() {
        assert_eq!(epoch_transition(stored, new), outcome, "{stored} -> {new}");
    }
}

#[test]
fn visibility_ed25519_goldens() {
    maybe_write();
    let file = read("visibility-ed25519.json");
    assert_eq!(file, visibility_file());
    let fixture = &file["vectors"][0];
    let bytes = fixture["statement"].as_str().unwrap().as_bytes();
    assert_eq!(
        VisibilityStatement::parse(bytes).unwrap(),
        visibility_vector()
    );
    let header_text = check_signed(fixture, bytes);
    for ((name, audience, repository, now), err) in visibility_contexts() {
        assert_eq!(
            run_visibility_context(&header_text, audience, &repository, now),
            err.map_or(Ok(()), Err),
            "{name}"
        );
    }
}

/// Every `reject/verify-*.json` fails verification with exactly its
/// expected error.
#[test]
fn grant_verify_reject_goldens() {
    maybe_write();
    let expected = verify_rejects();
    let files: Vec<String> = fixture_files()
        .into_iter()
        .filter(|p| p.starts_with("reject/verify-"))
        .collect();
    let mut names: Vec<String> = expected
        .iter()
        .map(|r| format!("reject/{}.json", r.0))
        .collect();
    names.sort();
    assert_eq!(files, names);
    for r in &expected {
        let fixture = read(&format!("reject/{}.json", r.0));
        assert_eq!(fixture, verify_reject_json(r), "{}", r.0);
        assert_eq!(run_verify_reject(r), Err(r.5), "{}", r.0);
    }
}
