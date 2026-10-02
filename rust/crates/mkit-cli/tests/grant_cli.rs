//! `mkit grant` end to end through the real binary (WP-2.13, R-155): create
//! (all three owner sources), add, list, and the config-security fences.
//! Everything runs against an isolated `XDG_CONFIG_HOME`; nothing here talks
//! to a server (see `grant_e2e.rs` for that).
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use ed25519_dalek::{Signer as _, SigningKey};
use k256::ecdsa::SigningKey as K256Key;
use mkit_attest::eth;
use mkit_attest::grant::{Capabilities, Grant, Namespace, OwnerScheme, RepoScope, SignedHeader};
use mkit_core::hash::{hash, to_hex_bytes};

const AUDIENCE: &str = "https://git.example.com";
const GRANTEE: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

struct Env {
    _root: tempfile::TempDir,
    repo: PathBuf,
    xdg: PathBuf,
}

impl Env {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let xdg = root.path().join("xdg");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        let env = Self {
            _root: root,
            repo,
            xdg,
        };
        assert!(env.run(&["init"]).status.success());
        common::install_fixed_key(&env.repo).unwrap();
        env
    }

    fn run(&self, args: &[&str]) -> Output {
        common::mkit(&self.repo, &self.xdg, args)
    }

    fn store_dir(&self) -> PathBuf {
        self.xdg.join("mkit").join("grants")
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8(out.stderr.clone()).unwrap()
}

fn ok(out: &Output) -> String {
    assert!(out.status.success(), "stderr: {}", stderr(out));
    stdout(out)
}

fn owner_key() -> SigningKey {
    SigningKey::from_bytes(&common::KEY_SEED)
}

fn owner_namespace() -> Namespace {
    Namespace::Ed25519(owner_key().verifying_key().to_bytes())
}

/// A deterministic ed25519-owned read grant with the given window and epoch.
fn fixed_grant(nonce: u8, created_ms: i64, epoch: u64) -> (Grant, String) {
    let namespace = owner_namespace();
    let grant = Grant {
        namespace,
        scope: RepoScope::Namespace,
        grantee: mkit_core::hash::from_hex(GRANTEE).unwrap(),
        capabilities: Capabilities::Read,
        audiences: vec![AUDIENCE.to_owned()],
        ref_scopes: None,
        epoch,
        created_ms,
        expiry_ms: created_ms + 2_592_000_000,
        nonce: [nonce; 32],
    };
    let statement = grant.encode().unwrap();
    let sig = owner_key().sign(&hash(&statement)).to_bytes().to_vec();
    let header = SignedHeader {
        statement,
        scheme: OwnerScheme::Ed25519,
        blob: sig,
    }
    .encode()
    .unwrap();
    (grant, header)
}

fn parse_header(text: &str) -> (SignedHeader, Grant) {
    let header = SignedHeader::parse(text.trim()).unwrap();
    let grant = Grant::parse(&header.statement).unwrap();
    (header, grant)
}

const CREATE: &[&str] = &[
    "grant",
    "create",
    "--cap",
    "read",
    "--grantee",
    GRANTEE,
    "--all",
    "--audience",
    AUDIENCE,
    "--offline",
];

fn with(base: &[&'static str], extra: &[&'static str]) -> Vec<&'static str> {
    base.iter().chain(extra).copied().collect()
}

#[test]
fn create_prints_a_canonical_verifying_header_and_stores_it() {
    let env = Env::new();
    let out = env.run(&[
        "grant",
        "create",
        "--cap",
        "write,read",
        "--grantee",
        GRANTEE,
        "--repo",
        "site",
        "--refs",
        "refs/heads/wip/*=fdc",
        "--refs",
        "refs/heads/main=u",
        "--audience",
        "https://b.example.com",
        "--audience",
        "https://a.example.com",
        "--audience",
        "https://a.example.com",
        "--ttl",
        "12h",
        "--offline",
        "--store",
    ]);
    let (header, grant) = parse_header(&ok(&out));
    assert_eq!(header.scheme, OwnerScheme::Ed25519);
    assert_eq!(grant.namespace, owner_namespace());
    assert_eq!(grant.capabilities.token(), "read,write");
    assert_eq!(
        grant.audiences,
        ["https://a.example.com", "https://b.example.com"]
    );
    let scopes = grant.ref_scopes.as_ref().unwrap();
    let text: Vec<String> = scopes
        .entries()
        .iter()
        .map(|(p, f)| format!("{p}={f}"))
        .collect();
    assert_eq!(text, ["refs/heads/main=u", "refs/heads/wip/*=cfd"]);
    assert_eq!(grant.epoch, 0);
    assert_eq!(grant.expiry_ms - grant.created_ms, 12 * 3_600_000);
    assert_eq!(
        grant.scope,
        RepoScope::Repository(
            mkit_core::repo_identity::RepositoryIdentity::parse(&format!(
                "{}/site",
                owner_namespace()
            ))
            .unwrap()
        )
    );

    // --store put exactly the header in a 0600 file in a 0700 directory.
    let file = env
        .store_dir()
        .join(format!("{}.grant", to_hex_bytes(&hash(&header.statement))));
    assert_eq!(
        std::fs::read_to_string(file.clone()).unwrap(),
        stdout(&out).trim()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&env.store_dir()), 0o700);
        assert_eq!(mode(&file), 0o600);
    }
    let listed = ok(&env.run(&["grant", "list", "--json"]));
    assert!(
        listed.contains("\"capabilities\":\"read,write\""),
        "{listed}"
    );
    assert!(listed.contains("\"status\":\"valid\""), "{listed}");
}

/// (cap, ttl, grantee, audience, refs, exit code, message fragment)
type Case = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
    i32,
    &'static str,
);

#[test]
fn create_refuses_bad_input_with_a_named_reason() {
    let env = Env::new();
    // (cap, ttl, grantee, audience, refs, exit code, message fragment)
    let cases: &[Case] = &[
        (
            "admin",
            "7d",
            GRANTEE,
            AUDIENCE,
            &[],
            64,
            "capability `admin`",
        ),
        ("read", "31d", GRANTEE, AUDIENCE, &[], 64, "30-day maximum"),
        (
            "write",
            "7d",
            GRANTEE,
            AUDIENCE,
            &[],
            64,
            "needs at least one --refs",
        ),
        (
            "read",
            "7d",
            GRANTEE,
            AUDIENCE,
            &["refs/heads/main=c"],
            64,
            "read-only grant takes no --refs",
        ),
        (
            "write",
            "7d",
            GRANTEE,
            AUDIENCE,
            &["refs/heads/main=x"],
            64,
            "flag `x` is not one of c, u, f, d",
        ),
        (
            "write",
            "7d",
            GRANTEE,
            AUDIENCE,
            &["refs/heads/main"],
            64,
            "must be `pattern=flags`",
        ),
        ("read", "7d", "zz", AUDIENCE, &[], 64, "--grantee must be"),
        (
            "read",
            "7d",
            GRANTEE,
            "http://localhost:8080",
            &[],
            64,
            "loopback",
        ),
        ("read", "7d", GRANTEE, "*.example.com", &[], 64, "audience"),
    ];
    for &(cap, ttl, grantee, audience, refs, code, fragment) in cases {
        let mut args = vec![
            "grant",
            "create",
            "--all",
            "--offline",
            "--cap",
            cap,
            "--ttl",
            ttl,
            "--grantee",
            grantee,
            "--audience",
            audience,
        ];
        for r in refs {
            args.extend(["--refs", r]);
        }
        let out = env.run(&args);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains(fragment),
            "{args:?}: wanted `{fragment}` in:\n{}",
            stderr(&out)
        );
    }
    assert!(!env.store_dir().exists(), "a refused create stores nothing");
}

#[test]
fn create_requires_repo_or_all_and_rejects_both() {
    let env = Env::new();
    let base = [
        "grant",
        "create",
        "--cap",
        "read",
        "--grantee",
        GRANTEE,
        "--audience",
        AUDIENCE,
        "--offline",
    ];
    let out = env.run(&base);
    assert_eq!(out.status.code(), Some(64));
    assert!(stderr(&out).contains("exactly one of --repo NAME or --all"));
    let mut both = base.to_vec();
    both.extend(["--repo", "site", "--all"]);
    assert_eq!(env.run(&both).status.code(), Some(64));
}

#[test]
fn a_wallet_signs_a_printed_statement_and_the_import_is_normalized() {
    let env = Env::new();
    let wallet = K256Key::from_slice(&[0x42; 32]).unwrap();
    let point = wallet.verifying_key().to_sec1_point(false);
    let xy: [u8; 64] = point.as_bytes()[1..].try_into().unwrap();
    let address = eth::address_secp256k1(&xy).unwrap();
    let namespace = format!("0x{}", eth::address_hex(&address));

    // 1. Print the statement.
    let mut args = with(CREATE, &["--namespace"]);
    args.push(&namespace);
    args.push("--print-statement");
    let printed = env.run(&args);
    assert!(printed.status.success(), "{}", stderr(&printed));
    let statement = printed.stdout.clone();
    assert!(!statement.ends_with(b"\n"), "exact bytes, no added newline");
    assert_eq!(
        Grant::parse(&statement).unwrap().namespace.to_string(),
        namespace
    );
    let digest = to_hex_bytes(&eth::eip191_hash(&statement));
    assert!(stderr(&printed).contains(&digest), "{}", stderr(&printed));

    // 2. The wallet signs: v as 0/1 and, in one case, the high-s twin.
    let (sig, recid) = wallet.sign_prehash_recoverable(&eth::eip191_hash(&statement));
    let mut wallet_sig = [0u8; 65];
    wallet_sig[..64].copy_from_slice(&sig.to_bytes());
    wallet_sig[64] = recid.to_byte();
    let file = env.repo.join("statement.txt");
    std::fs::write(&file, &statement).unwrap();
    let n =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    let mut high = wallet_sig;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(n[i]) - i16::from(wallet_sig[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        high[32 + i] = (d + 256 * borrow).to_le_bytes()[0];
    }
    high[64] ^= 1;
    for candidate in [wallet_sig, high] {
        let hex_sig = hex::encode(candidate);
        let out = env.run(&[
            "grant",
            "create",
            "--statement-file",
            file.to_str().unwrap(),
            "--signature",
            &hex_sig,
        ]);
        let (header, grant) = parse_header(&ok(&out));
        assert_eq!(header.scheme, OwnerScheme::Secp256k1Eip191);
        assert_eq!(header.blob.len(), 65);
        assert!(header.blob[64] == 27 || header.blob[64] == 28);
        assert_eq!(grant.namespace.to_string(), namespace);
    }

    // 3. Another key's signature is refused, naming the rule.
    let other = K256Key::from_slice(&[0x43; 32]).unwrap();
    let (sig, recid) = other.sign_prehash_recoverable(&eth::eip191_hash(&statement));
    let mut forged = [0u8; 65];
    forged[..64].copy_from_slice(&sig.to_bytes());
    forged[64] = recid.to_byte();
    let out = env.run(&[
        "grant",
        "create",
        "--statement-file",
        file.to_str().unwrap(),
        "--signature",
        &hex::encode(forged),
    ]);
    assert_eq!(out.status.code(), Some(65));
    assert!(stderr(&out).contains("owner mismatch"), "{}", stderr(&out));
}

#[test]
fn a_software_keystore_secp256k1_key_signs_natively() {
    let env = Env::new();
    ok(&env.run(&[
        "key",
        "generate",
        "--backend",
        "software-raw",
        "--algorithm",
        "secp256k1",
        "--label",
        "owner",
    ]));
    ok(&env.run(&["config", "key.secp256k1_ref", "software-raw:owner"]));
    let mut args = CREATE.to_vec();
    args.extend(["--scheme", "secp256k1-eip191"]);
    let (header, grant) = parse_header(&ok(&env.run(&args)));
    assert_eq!(header.scheme, OwnerScheme::Secp256k1Eip191);
    assert!(matches!(grant.namespace, Namespace::Address(_)));
    // A key that isn't set up says how to fix it.
    ok(&env.run(&["config", "key.secp256k1_ref", "software-raw:missing"]));
    let out = env.run(&args);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("mkit key generate"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn webauthn_import_is_refused_unless_a_relying_party_is_pinned() {
    let env = Env::new();
    let (_, header) = fixed_grant(1, 946_684_800_000, 0);
    let statement = SignedHeader::parse(&header).unwrap().statement;
    let statement_file = env.repo.join("s.txt");
    std::fs::write(&statement_file, &statement).unwrap();
    let assertion = env.repo.join("a.json");
    std::fs::write(&assertion, b"{}").unwrap();
    let args = [
        "grant",
        "create",
        "--statement-file",
        statement_file.to_str().unwrap(),
        "--webauthn-assertion",
        assertion.to_str().unwrap(),
    ];
    let out = env.run(&args);
    assert_eq!(out.status.code(), Some(64));
    assert!(
        stderr(&out).contains("pinned relying party"),
        "{}",
        stderr(&out)
    );
    // A pin lifts that refusal (the empty assertion then fails on its content).
    ok(&env.run(&[
        "config",
        "grant.webauthn_rp",
        "example.com https://example.com",
    ]));
    assert_eq!(
        ok(&env.run(&["config", "grant.webauthn_rp"])).trim(),
        "example.com https://example.com"
    );
    let out = env.run(&args);
    assert!(
        !stderr(&out).contains("pinned relying party"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("missing string field"),
        "{}",
        stderr(&out)
    );
    // A malformed pin is refused when it is set.
    let bad = env.run(&["config", "grant.webauthn_rp", "only-an-id"]);
    assert_eq!(bad.status.code(), Some(78));
}

#[test]
fn add_verifies_is_idempotent_and_names_the_rule_it_rejects() {
    let env = Env::new();
    let (_, header) = fixed_grant(1, 946_684_800_000, 0);
    let file = env.repo.join("g.txt");
    std::fs::write(&file, format!("{header}\n")).unwrap();
    let out = env.run(&["grant", "add", "--offline", file.to_str().unwrap()]);
    assert!(ok(&out).starts_with("added grant "));
    let out = env.run(&["grant", "add", "--offline", file.to_str().unwrap()]);
    assert!(ok(&out).contains("is already in your grant store"));
    assert_eq!(std::fs::read_dir(env.store_dir()).unwrap().count(), 1);

    // stdin works too, and a tampered header is rejected with the rule.
    let mut signed = SignedHeader::parse(&header).unwrap();
    signed.blob[0] ^= 1;
    let tampered = env.repo.join("t.txt");
    std::fs::write(&tampered, signed.encode().unwrap()).unwrap();
    let out = env.run(&["grant", "add", "--offline", tampered.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(65));
    assert!(
        stderr(&out).contains("rejected: bad signature"),
        "{}",
        stderr(&out)
    );
    for (bad, rule) in [
        ("not a header", "header format"),
        ("YQ.rsa.YQ", "unknown scheme"),
    ] {
        let path = env.repo.join("bad.txt");
        std::fs::write(&path, bad).unwrap();
        let out = env.run(&["grant", "add", "--offline", path.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(65), "{bad}");
        assert!(stderr(&out).contains(rule), "{bad}: {}", stderr(&out));
    }
    assert_eq!(std::fs::read_dir(env.store_dir()).unwrap().count(), 1);
}

#[test]
fn list_shows_status_and_is_stable() {
    let env = Env::new();
    // Created in 2000 (expired) and in 2200 (not yet valid): deterministic.
    for (nonce, created, epoch) in [(1u8, 946_684_800_000i64, 3u64), (2, 7_258_118_400_000, 0)] {
        let (_, header) = fixed_grant(nonce, created, epoch);
        let file = env.repo.join(format!("g{nonce}.txt"));
        std::fs::write(&file, header).unwrap();
        ok(&env.run(&["grant", "add", "--offline", file.to_str().unwrap()]));
    }
    insta::assert_snapshot!("grant_list_human", ok(&env.run(&["grant", "list"])));
    insta::assert_snapshot!(
        "grant_list_json",
        ok(&env.run(&["grant", "list", "--json"]))
    );
    // --check without a reachable remote marks every grant unchecked and
    // still exits 0 with the listing.
    let out = env.run(&["grant", "list", "--check", "--json"]);
    assert!(
        ok(&out).contains("\"epoch_status\":\"unchecked"),
        "{}",
        stdout(&out)
    );
    // An empty store says where it looked.
    let empty = Env::new();
    assert!(ok(&empty.run(&["grant", "list"])).starts_with("no grants in "));
    assert_eq!(ok(&empty.run(&["grant", "list", "--json"])).trim(), "[]");
}

#[test]
fn the_grant_store_and_relying_party_pins_cannot_be_set_from_a_repository() {
    let env = Env::new();
    // A grant sits in the real store; a decoy sits where a repository config
    // would like the store to be.
    let (_, header) = fixed_grant(1, 946_684_800_000, 0);
    let file = env.repo.join("g.txt");
    std::fs::write(&file, &header).unwrap();
    ok(&env.run(&["grant", "add", "--offline", file.to_str().unwrap()]));
    let (_, decoy) = fixed_grant(9, 946_684_800_000, 0);
    let decoy_dir = env.repo.join("evil-grants");
    std::fs::create_dir_all(&decoy_dir).unwrap();
    let decoy_id = to_hex_bytes(&hash(&SignedHeader::parse(&decoy).unwrap().statement));
    std::fs::write(decoy_dir.join(format!("{decoy_id}.grant")), &decoy).unwrap();
    let hostile = format!(
        "grants_dir = {dir}\ngrant.store = {dir}\ngrants.dir = {dir}\ngrant.webauthn_rp = evil.example https://evil.example\n",
        dir = decoy_dir.display()
    );
    std::fs::write(env.repo.join(".mkit").join("config"), hostile).unwrap();

    let listed = ok(&env.run(&["grant", "list", "--json"]));
    assert!(
        !listed.contains(&decoy_id),
        "decoy store was read: {listed}"
    );
    assert_eq!(listed.matches("\"id\"").count(), 1, "{listed}");
    let pin = env.run(&["config", "grant.webauthn_rp"]);
    assert_eq!(stdout(&pin).trim(), "", "the repo pinned a relying party");
    assert!(
        stderr(&pin).contains("ignoring `grant.webauthn_rp`"),
        "{}",
        stderr(&pin)
    );
    // The only place the store lives is under the XDG config directory.
    assert!(env.store_dir().is_dir());
}
