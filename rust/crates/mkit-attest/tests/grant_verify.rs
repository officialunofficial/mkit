//! The stateless grant verifier (SPEC-WRITE-GRANTS §7 steps 1–10, §5.2,
//! §9.1, §10), exercised through the public API with freshly signed
//! statements. The signed goldens are in `golden_grants`.
#![cfg(feature = "grants")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use ed25519_dalek::{Signer as _, SigningKey};
use mkit_attest::grant::{
    AcceptedSchemes, Capabilities, Capability, EpochStatement, Grant, GrantError, GrantRequest,
    Namespace, OwnerScheme, RefFlags, RefPattern, RefScopes, RepoScope, RepositoryIdentity,
    SignedHeader, VerifierConfig, Visibility, VisibilityStatement, packmap_head,
    verify_epoch_statement, verify_for_registration, verify_grant_owner,
    verify_visibility_statement,
};

const AUDIENCE: &str = "https://git.example.com";
const CREATED: i64 = 1_790_000_000_000;
const EXPIRY: i64 = CREATED + 3_600_000;
const GRANTEE: [u8; 32] = [0xea; 32];

fn owner() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn ns() -> Namespace {
    Namespace::Ed25519(owner().verifying_key().to_bytes())
}

fn repo(name: &str) -> RepositoryIdentity {
    RepositoryIdentity::new(Some(ns()), name).unwrap()
}

fn cfg() -> VerifierConfig {
    VerifierConfig::new(AUDIENCE, AcceptedSchemes::of(&[OwnerScheme::Ed25519])).unwrap()
}

fn cfg_with(audience: &str) -> VerifierConfig {
    VerifierConfig::new(audience, AcceptedSchemes::of(&[OwnerScheme::Ed25519])).unwrap()
}

fn scopes(entries: &[(&str, &str)]) -> RefScopes {
    RefScopes::new(
        entries
            .iter()
            .map(|(p, f)| (RefPattern::parse(p).unwrap(), RefFlags::parse(f).unwrap()))
            .collect(),
    )
    .unwrap()
}

fn grant(capabilities: Capabilities, scope: RepoScope) -> Grant {
    Grant {
        namespace: ns(),
        scope,
        grantee: GRANTEE,
        capabilities,
        audiences: vec![AUDIENCE.into(), "https://git.example.org".into()],
        ref_scopes: (capabilities != Capabilities::Read)
            .then(|| scopes(&[("refs/*", "c"), ("refs/heads/main", "cu")])),
        epoch: 7,
        created_ms: CREATED,
        expiry_ms: EXPIRY,
        nonce: [0x42; 32],
    }
}

fn sign_header(statement: &[u8], key: &SigningKey) -> String {
    SignedHeader {
        statement: statement.to_vec(),
        scheme: OwnerScheme::Ed25519,
        blob: key
            .sign(blake3::hash(statement).as_bytes())
            .to_bytes()
            .to_vec(),
    }
    .encode()
    .unwrap()
}

fn signed(g: &Grant) -> String {
    sign_header(&g.encode().unwrap(), &owner())
}

fn request(
    repository: &RepositoryIdentity,
    capability: Capability,
    now_ms: i64,
) -> GrantRequest<'_> {
    GrantRequest {
        repository,
        signer: &GRANTEE,
        capability,
        now_ms,
    }
}

fn check(header: &str, req: &GrantRequest<'_>) -> Result<(), GrantError> {
    let cfg = cfg();
    verify_grant_owner(&cfg, header)?
        .check(&cfg, req)
        .map(|_| ())
}

#[test]
fn grant_verifies_and_exposes_the_grant() {
    let g = grant(
        Capabilities::ReadWrite,
        RepoScope::Repository(repo("website")),
    );
    let header = signed(&g);
    let cfg = cfg();
    let owner = verify_grant_owner(&cfg, &header).unwrap();
    assert_eq!(owner.statement(), &g);
    assert_eq!(owner.id(), &g.id().unwrap());
    assert_eq!(owner.scheme(), OwnerScheme::Ed25519);
    let site = repo("website");
    let verified = owner
        .check(&cfg, &request(&site, Capability::Write, CREATED))
        .unwrap();
    assert_eq!(verified.grant(), &g);
    assert_eq!(verified.id(), &g.id().unwrap());
    assert_eq!(verified.epoch(), 7);
    assert_eq!(verified.repository(), &site);
    assert_eq!(verified.signer(), &GRANTEE);
    assert_eq!(verified.capability(), Capability::Write);
    assert_eq!(verified.scheme(), OwnerScheme::Ed25519);
}

#[test]
fn grant_check_steps_in_order() {
    let header = signed(&grant(
        Capabilities::Write,
        RepoScope::Repository(repo("website")),
    ));
    let site = repo("website");
    // Step 2: X-Repository in another namespace, or with no namespace.
    let foreign =
        RepositoryIdentity::parse("0x8ba1f109551bd432803012645ac136ddd64dba72/website").unwrap();
    let bare = RepositoryIdentity::parse_bare_allowed("website").unwrap();
    for r in [&foreign, &bare] {
        assert_eq!(
            check(&header, &request(r, Capability::Write, CREATED)),
            Err(GrantError::NamespaceMismatch)
        );
    }
    // Step 6: another repository in the namespace.
    assert_eq!(
        check(&header, &request(&repo("blog"), Capability::Write, CREATED)),
        Err(GrantError::RepositoryNotInScope)
    );
    // Step 7: a write-only grant for a private read.
    assert_eq!(
        check(&header, &request(&site, Capability::Read, CREATED)),
        Err(GrantError::CapabilityNotGranted)
    );
    // Step 9: another signer.
    let other = [1u8; 32];
    let req = GrantRequest {
        signer: &other,
        ..request(&site, Capability::Write, CREATED)
    };
    assert_eq!(check(&header, &req), Err(GrantError::GranteeMismatch));
    // A step-2 failure wins over a step-9 failure (spec order).
    let req = GrantRequest {
        signer: &other,
        ..request(&foreign, Capability::Write, CREATED)
    };
    assert_eq!(check(&header, &req), Err(GrantError::NamespaceMismatch));
}

#[test]
fn grant_read_capability_does_not_cover_writes() {
    let header = signed(&grant(
        Capabilities::Read,
        RepoScope::Repository(repo("website")),
    ));
    let site = repo("website");
    assert_eq!(
        check(&header, &request(&site, Capability::Read, CREATED)),
        Ok(())
    );
    assert_eq!(
        check(&header, &request(&site, Capability::Write, CREATED)),
        Err(GrantError::CapabilityNotGranted)
    );
}

#[test]
fn grant_namespace_scope_covers_every_repository_in_it() {
    let header = signed(&grant(Capabilities::Write, RepoScope::Namespace));
    for name in ["website", "blog", "not-yet-created"] {
        assert_eq!(
            check(&header, &request(&repo(name), Capability::Write, CREATED)),
            Ok(())
        );
    }
}

#[test]
fn grant_audience_is_compared_byte_for_byte() {
    let header = signed(&grant(Capabilities::Write, RepoScope::Namespace));
    let site = repo("website");
    for (audience, expected) in [
        (AUDIENCE, Ok(())),
        ("https://git.example.org", Ok(())),
        (
            "https://git.example.net",
            Err(GrantError::AudienceNotListed),
        ),
        (
            "https://git.example.com:8443",
            Err(GrantError::AudienceNotListed),
        ),
        ("http://git.example.com", Err(GrantError::AudienceNotListed)),
    ] {
        let cfg = cfg_with(audience);
        let result = verify_grant_owner(&cfg, &header)
            .unwrap()
            .check(&cfg, &request(&site, Capability::Write, CREATED))
            .map(|_| ());
        assert_eq!(result, expected, "{audience}");
    }
}

/// §3.2 bans a loopback audience for the deployment itself, not inside
/// grants: a grant may list `http://[::1]:8443`, and it verifies only at a
/// deployment explicitly built for loopback development.
#[test]
fn grant_loopback_audience_verifies_only_under_the_dev_config() {
    let mut g = grant(Capabilities::Write, RepoScope::Namespace);
    g.audiences = vec!["http://[::1]:8443".into()];
    let header = signed(&g);
    let schemes = AcceptedSchemes::of(&[OwnerScheme::Ed25519]);
    assert_eq!(
        VerifierConfig::new("http://[::1]:8443", schemes),
        Err(GrantError::LoopbackAudience)
    );
    let dev = VerifierConfig::new_allowing_loopback("http://[::1]:8443", schemes).unwrap();
    let site = repo("website");
    assert!(
        verify_grant_owner(&dev, &header)
            .unwrap()
            .check(&dev, &request(&site, Capability::Write, CREATED))
            .is_ok()
    );
    assert_eq!(
        check(&header, &request(&site, Capability::Write, CREATED)),
        Err(GrantError::AudienceNotListed)
    );
}

#[test]
fn grant_window_expiry_is_exclusive() {
    let header = signed(&grant(Capabilities::Write, RepoScope::Namespace));
    let site = repo("website");
    let at = |now| check(&header, &request(&site, Capability::Write, now));
    assert_eq!(at(EXPIRY - 1), Ok(()));
    assert_eq!(at(EXPIRY), Err(GrantError::Expired));
    assert_eq!(at(EXPIRY + 1), Err(GrantError::Expired));
    assert_eq!(at(CREATED - 30_000), Ok(()));
    assert_eq!(at(CREATED - 30_001), Err(GrantError::NotYetValid));
    assert_eq!(at(-1), Err(GrantError::NotYetValid));
}

#[test]
fn grant_owner_signature_failures() {
    let g = grant(Capabilities::Write, RepoScope::Namespace);
    let bytes = g.encode().unwrap();
    // Another key's signature.
    let forged = sign_header(&bytes, &SigningKey::from_bytes(&[10; 32]));
    assert_eq!(
        verify_grant_owner(&cfg(), &forged),
        Err(GrantError::BadSignature)
    );
    // An unadvertised scheme.
    let k1 = VerifierConfig::new(
        AUDIENCE,
        AcceptedSchemes::of(&[OwnerScheme::Secp256k1Eip191]),
    )
    .unwrap();
    assert_eq!(
        verify_grant_owner(&k1, &signed(&g)),
        Err(GrantError::SchemeNotAdvertised)
    );
    // `ed25519` on a `0x` namespace.
    let mut addr = g.clone();
    addr.namespace = Namespace::Address([7; 20]);
    assert_eq!(
        verify_grant_owner(&cfg(), &signed(&addr)),
        Err(GrantError::SchemeNamespaceMismatch)
    );
    // An ECDSA scheme on a `0x` namespace (WP-2.5 implements these).
    let ecdsa = SignedHeader {
        statement: addr.encode().unwrap(),
        scheme: OwnerScheme::Secp256k1Eip191,
        blob: vec![0; 65],
    }
    .encode()
    .unwrap();
    let both = VerifierConfig::new(
        AUDIENCE,
        AcceptedSchemes::of(&[OwnerScheme::Ed25519, OwnerScheme::Secp256k1Eip191]),
    )
    .unwrap();
    assert_eq!(
        verify_grant_owner(&both, &ecdsa),
        Err(GrantError::SchemeNotImplemented)
    );
    // A malformed header or statement fails before any signature work.
    assert_eq!(
        verify_grant_owner(&cfg(), "YQ.ed25519.YQ"),
        Err(GrantError::FieldCount)
    );
    assert_eq!(
        verify_grant_owner(&cfg(), "YQ==.ed25519.YQ"),
        Err(GrantError::HeaderBase64)
    );
}

#[test]
fn grant_owner_verified_is_cacheable_by_header_bytes() {
    let header = signed(&grant(Capabilities::Write, RepoScope::Namespace));
    let cfg = cfg();
    let a = verify_grant_owner(&cfg, &header).unwrap();
    let b = verify_grant_owner(&cfg, &header).unwrap();
    assert_eq!(a, b);
    // Changing one base64 character of the blob fails.
    let (rest, blob) = header.rsplit_once('.').unwrap();
    let mut chars: Vec<char> = blob.chars().collect();
    chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    let tampered = format!("{rest}.{}", chars.into_iter().collect::<String>());
    assert_eq!(
        verify_grant_owner(&cfg, &tampered),
        Err(GrantError::BadSignature)
    );
    // A cached value re-checks the scheme against the current config.
    let k1 = VerifierConfig::new(
        AUDIENCE,
        AcceptedSchemes::of(&[OwnerScheme::Secp256k1Eip191]),
    )
    .unwrap();
    let site = repo("website");
    assert_eq!(
        a.check(&k1, &request(&site, Capability::Write, CREATED)),
        Err(GrantError::SchemeNotAdvertised)
    );
}

#[test]
fn grant_verified_effective_flags_keep_the_packmap_rule() {
    let header = signed(&grant(Capabilities::ReadWrite, RepoScope::Namespace));
    let cfg = cfg();
    let owner = verify_grant_owner(&cfg, &header).unwrap();
    let site = repo("website");
    let write = owner
        .check(&cfg, &request(&site, Capability::Write, CREATED))
        .unwrap();
    let cu = RefFlags::parse("cu").unwrap();
    assert_eq!(write.effective_flags("refs/heads/main"), cu);
    assert_eq!(write.effective_flags("refs/tags/v1"), RefFlags::CREATE);
    // `refs/*` never reaches a packmap ref; its coverage comes from the head.
    assert_eq!(
        write.effective_flags("refs/mkit/packmap/main"),
        RefFlags::EMPTY
    );
    let head = packmap_head("refs/mkit/packmap/main").unwrap();
    assert_eq!(write.effective_flags(&head), cu);
    // A grant checked for a read yields no write flags.
    let read = owner
        .check(&cfg, &request(&site, Capability::Read, CREATED))
        .unwrap();
    assert_eq!(read.effective_flags("refs/heads/main"), RefFlags::EMPTY);
}

#[test]
fn grant_registration_checks_audience_and_principal() {
    let g = grant(Capabilities::Write, RepoScope::Namespace);
    let header = signed(&g);
    let registered = verify_for_registration(&cfg(), &header, &GRANTEE).unwrap();
    assert_eq!(registered.statement(), &g);
    // The registered grant still passes every per-request step.
    let site = repo("website");
    assert!(
        registered
            .check(&cfg(), &request(&site, Capability::Write, CREATED))
            .is_ok()
    );
    assert_eq!(
        verify_for_registration(&cfg(), &header, &[1; 32]),
        Err(GrantError::GranteeMismatch)
    );
    assert_eq!(
        verify_for_registration(&cfg_with("https://git.example.net"), &header, &GRANTEE),
        Err(GrantError::AudienceNotListed)
    );
    assert_eq!(
        verify_for_registration(
            &cfg(),
            &sign_header(&g.encode().unwrap(), &SigningKey::from_bytes(&[10; 32])),
            &GRANTEE
        ),
        Err(GrantError::BadSignature)
    );
}

fn epoch_statement() -> EpochStatement {
    EpochStatement {
        namespace: ns(),
        new_epoch: 8,
        audiences: vec![AUDIENCE.into()],
        created_ms: CREATED,
        expiry_ms: EXPIRY,
        nonce: [0x24; 32],
    }
}

#[test]
fn epoch_statement_verifies() {
    let s = epoch_statement();
    let header = sign_header(&s.encode().unwrap(), &owner());
    let verified = verify_epoch_statement(&cfg(), &header, CREATED).unwrap();
    assert_eq!(verified.statement(), &s);
    assert_eq!(verified.id(), &s.id().unwrap());
    let at = |now| verify_epoch_statement(&cfg(), &header, now).map(|_| ());
    assert_eq!(at(EXPIRY - 1), Ok(()));
    assert_eq!(at(EXPIRY), Err(GrantError::Expired));
    assert_eq!(at(CREATED - 30_000), Ok(()));
    assert_eq!(at(CREATED - 30_001), Err(GrantError::NotYetValid));
    assert_eq!(
        verify_epoch_statement(&cfg_with("https://git.example.org"), &header, CREATED).map(|_| ()),
        Err(GrantError::AudienceNotListed)
    );
    let forged = sign_header(&s.encode().unwrap(), &SigningKey::from_bytes(&[10; 32]));
    assert_eq!(
        verify_epoch_statement(&cfg(), &forged, CREATED).map(|_| ()),
        Err(GrantError::BadSignature)
    );
    // A grant is not an epoch statement, and vice versa.
    let grant_header = signed(&grant(Capabilities::Write, RepoScope::Namespace));
    assert_eq!(
        verify_epoch_statement(&cfg(), &grant_header, CREATED).map(|_| ()),
        Err(GrantError::FieldCount)
    );
    assert_eq!(
        verify_grant_owner(&cfg(), &header).map(|_| ()),
        Err(GrantError::FieldCount)
    );
}

fn visibility_statement() -> VisibilityStatement {
    VisibilityStatement {
        repository: repo("website"),
        visibility: Visibility::Private,
        audiences: vec![AUDIENCE.into()],
        created_ms: CREATED,
        expiry_ms: EXPIRY,
        nonce: [0x25; 32],
    }
}

#[test]
fn visibility_statement_verifies() {
    let s = visibility_statement();
    let header = sign_header(&s.encode().unwrap(), &owner());
    let site = repo("website");
    let verified = verify_visibility_statement(&cfg(), &header, &site, CREATED).unwrap();
    assert_eq!(verified.statement(), &s);
    let at = |repository: &RepositoryIdentity, now| {
        verify_visibility_statement(&cfg(), &header, repository, now).map(|_| ())
    };
    assert_eq!(at(&site, EXPIRY - 1), Ok(()));
    assert_eq!(at(&site, EXPIRY), Err(GrantError::Expired));
    assert_eq!(at(&site, CREATED - 30_001), Err(GrantError::NotYetValid));
    assert_eq!(
        at(&repo("blog"), CREATED),
        Err(GrantError::NamespaceMismatch)
    );
    assert_eq!(
        verify_visibility_statement(
            &cfg_with("https://git.example.org"),
            &header,
            &site,
            CREATED
        )
        .map(|_| ()),
        Err(GrantError::AudienceNotListed)
    );
    // The owner is the repository's namespace: another key's signature fails.
    let forged = sign_header(&s.encode().unwrap(), &SigningKey::from_bytes(&[10; 32]));
    assert_eq!(
        verify_visibility_statement(&cfg(), &forged, &site, CREATED).map(|_| ()),
        Err(GrantError::BadSignature)
    );
}
