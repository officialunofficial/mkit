//! `--addressing multi`'s flags: the namespace policy and its allowlist
//! file, the auth v2 + ticket-keys + `SQLite` requirements, and that
//! single addressing stays the default (WP-1.30).

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use mkit_server::Addressing;
use mkit_server::pipeline::AuthMode;
use mkit_server::policy::NamespacePolicy;
use mkit_server_native::exit;

const TICKET_KEYS: &str = "dev 1111111111111111111111111111111111111111111111111111111111111111";

fn namespace(byte: u8) -> String {
    format!("ed25519-{}{byte:02x}", "a".repeat(62))
}

/// A fixture root with its allowlist and ticket files written; the flags
/// a valid `--addressing multi` invocation takes.
struct Fixture {
    root: tempfile::TempDir,
    allowlist: String,
    tickets: String,
    meta: String,
}

fn fixture(allowlist: &str) -> Fixture {
    let root = common::repo_root();
    let allowlist_path = root.path().join("namespaces");
    std::fs::write(&allowlist_path, allowlist).unwrap();
    let tickets_path = root.path().join("ticket.keys");
    common::secret_file(&tickets_path, format!("{TICKET_KEYS}\n").as_bytes());
    Fixture {
        meta: format!("sqlite:{}", common::s(&root.path().join("meta.sqlite3"))),
        allowlist: common::s(&allowlist_path).to_owned(),
        tickets: common::s(&tickets_path).to_owned(),
        root,
    }
}

/// The flags a working `--addressing multi` invocation needs.
fn multi(f: &Fixture) -> Vec<String> {
    [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(f.root.path()),
        "--addressing",
        "multi",
        "--namespace-allowlist",
        &f.allowlist,
        "--auth",
        "auth-v2",
        "--audience",
        "http://localhost",
        "--ticket-key-file",
        &f.tickets,
        "--meta",
        &f.meta,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

/// Drop `--flag` (and its value when `takes_value`) from `flags`.
fn drop_flag(flags: &[String], flag: &str, takes_value: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip = false;
    for s in flags {
        if skip {
            skip = false;
            continue;
        }
        if s == flag {
            skip = takes_value;
            continue;
        }
        out.push(s.clone());
    }
    out
}

fn resolve(
    flags: &[String],
) -> Result<mkit_server_native::config::ServeConfig, mkit_server_native::config::ConfigError> {
    let refs: Vec<&str> = flags.iter().map(String::as_str).collect();
    common::resolve_with(&refs, &[])
}

fn refusal(flags: &[String]) -> (u8, String) {
    let err = resolve(flags).unwrap_err();
    (err.code, err.message)
}

fn extra(flags: &[String], more: &[&str]) -> Vec<String> {
    [
        flags,
        &more.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
    ]
    .concat()
}

#[test]
fn multi_allowlist_resolves() {
    let f = fixture(&format!("{}\n# comment\n{}\n", namespace(1), namespace(2)));
    let cfg = resolve(&multi(&f)).unwrap();
    let Addressing::Multi(multi) = &cfg.pipeline.addressing else {
        panic!("--addressing multi must select multi addressing");
    };
    let NamespacePolicy::Allowlist(set) = &multi.namespace_policy else {
        panic!("the default multi policy is an allowlist");
    };
    assert_eq!(set.len(), 2);
    assert!(matches!(cfg.pipeline.auth, AuthMode::AuthV2(_)));
    assert!(cfg.pipeline.ticket_keys.is_some());
    assert_eq!(
        cfg.pipeline.write_policy,
        mkit_server::policy::WritePolicy::Owner
    );
}

#[test]
fn multi_policy_any_needs_the_unsafe_opt_in() {
    let f = fixture(&namespace(1));
    let any = drop_flag(&multi(&f), "--namespace-allowlist", true);
    let any = extra(&any, &["--namespace-policy", "any"]);
    let (code, message) = refusal(&any);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("--unsafe-open-namespaces"), "{message}");
    let open = extra(&any, &["--unsafe-open-namespaces"]);
    let cfg = resolve(&open).unwrap();
    let Addressing::Multi(multi) = &cfg.pipeline.addressing else {
        panic!("--addressing multi must select multi addressing");
    };
    assert_eq!(
        multi.namespace_policy,
        NamespacePolicy::Any {
            unsafe_without_admission: true
        }
    );
}

#[test]
fn multi_allowlist_file_is_checked_and_parsed() {
    let cases: [(String, &str); 3] = [
        ("not a namespace\n".to_owned(), "line 1:"),
        (
            format!("{}\n{}\n", namespace(1), namespace(1)),
            "duplicate namespace",
        ),
        ("# only a comment\n".to_owned(), "contains no namespaces"),
    ];
    for (contents, want) in cases {
        let f = fixture(&contents);
        let (code, message) = refusal(&multi(&f));
        assert_eq!(code, exit::CONFIG_ERROR, "{message}");
        assert!(message.contains("--namespace-allowlist"), "{message}");
        assert!(message.contains(want), "{message}");
    }
    // A missing file and a symlink are refused the same way.
    let f = fixture(&namespace(1));
    let missing = extra(
        &drop_flag(&multi(&f), "--namespace-allowlist", true),
        &[
            "--namespace-allowlist",
            common::s(&f.root.path().join("absent")),
        ],
    );
    let (code, message) = refusal(&missing);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("--namespace-allowlist"), "{message}");
    let link = f.root.path().join("link");
    std::os::unix::fs::symlink(&f.allowlist, &link).unwrap();
    let flags = extra(
        &drop_flag(&multi(&f), "--namespace-allowlist", true),
        &["--namespace-allowlist", common::s(&link)],
    );
    let (code, message) = refusal(&flags);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("symlink"), "{message}");
}

#[test]
fn multi_requires_auth_v2_tickets_and_sqlite() {
    let f = fixture(&namespace(1));
    // No ticket keys at all.
    let no_keys = drop_flag(&multi(&f), "--ticket-key-file", true);
    let (code, message) = refusal(&no_keys);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("ticket keys"), "{message}");
    // Ticket keys from the environment instead.
    let refs: Vec<&str> = no_keys.iter().map(String::as_str).collect();
    let cfg = common::resolve_with(&refs, &[("MKIT_TICKET_KEYS", TICKET_KEYS)]).unwrap();
    assert!(cfg.pipeline.ticket_keys.is_some());
    // Bearer and the open mode are refused.
    let token = f.root.path().join("token");
    common::secret_file(&token, b"t");
    for auth_flags in [
        vec![
            "--auth".to_owned(),
            "bearer".to_owned(),
            "--bearer-token-file".to_owned(),
            common::s(&token).to_owned(),
        ],
        vec!["--unsafe-allow-any-peer".to_owned()],
    ] {
        let flags = drop_flag(&multi(&f), "--auth", true);
        let flags = drop_flag(&flags, "--audience", true);
        let flags = [&flags[..], &auth_flags[..]].concat();
        let (code, message) = refusal(&flags);
        assert_eq!(code, exit::CONFIG_ERROR, "{auth_flags:?}: {message}");
        assert!(message.contains("--auth auth-v2"), "{message}");
    }
    // Without --meta (fs-layout is the default) or with it explicitly.
    for meta in [
        Vec::new(),
        vec!["--meta".to_owned(), "fs-layout".to_owned()],
    ] {
        let flags = drop_flag(&multi(&f), "--meta", true);
        let flags = [&flags[..], &meta[..]].concat();
        let (code, message) = refusal(&flags);
        assert_eq!(code, exit::CONFIG_ERROR, "{meta:?}: {message}");
        assert!(message.contains("--meta sqlite:<PATH>"), "{message}");
    }
}

#[test]
fn multi_refuses_single_and_orphaned_flags() {
    let f = fixture(&namespace(1));
    // --repository is single-only under multi.
    let flags = extra(&multi(&f), &["--repository", "room"]);
    let (code, message) = refusal(&flags);
    assert_eq!(code, exit::USAGE, "{message}");
    assert!(message.contains("X-Repository"), "{message}");
    // The namespace flags need --addressing multi.
    let single = drop_flag(&multi(&f), "--addressing", true);
    let single = drop_flag(&single, "--namespace-allowlist", true);
    for extra_flag in [
        vec!["--namespace-policy".to_owned(), "any".to_owned()],
        vec!["--namespace-allowlist".to_owned(), f.allowlist.clone()],
        vec!["--unsafe-open-namespaces".to_owned()],
    ] {
        let flags = [&single[..], &extra_flag[..]].concat();
        let (code, message) = refusal(&flags);
        assert_eq!(code, exit::USAGE, "{extra_flag:?}: {message}");
        assert!(message.contains("--addressing multi"), "{message}");
    }
    // --unsafe-open-namespaces without `--namespace-policy any`.
    let flags = extra(&multi(&f), &["--unsafe-open-namespaces"]);
    let (code, message) = refusal(&flags);
    assert_eq!(code, exit::USAGE, "{message}");
    // An allowlist with `--namespace-policy any` is a conflict.
    let flags = extra(
        &multi(&f),
        &["--namespace-policy", "any", "--unsafe-open-namespaces"],
    );
    let (code, message) = refusal(&flags);
    assert_eq!(code, exit::USAGE, "{message}");
    assert!(message.contains("mutually exclusive"), "{message}");
    // Missing --namespace-allowlist entirely.
    let flags = drop_flag(&multi(&f), "--namespace-allowlist", true);
    let (code, message) = refusal(&flags);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("--namespace-allowlist"), "{message}");
}

#[cfg(feature = "enc")]
#[test]
fn multi_enc_repository() {
    use std::fs;

    let f = fixture(&namespace(1));
    // multi + --listen-enc needs --enc-repository.
    let enc_flags = extra(&multi(&f), &["--listen-enc", "127.0.0.1:0"]);
    let (code, message) = refusal(&enc_flags);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("--enc-repository"), "{message}");
    // A bare or malformed identity is refused.
    for repository in ["default", "NS/name", "ed25519-/name"] {
        let flags = extra(&enc_flags, &["--enc-repository", repository]);
        let (code, message) = refusal(&flags);
        assert_eq!(code, exit::USAGE, "{repository}: {message}");
    }
    // --unsafe-allow-any-enc-peer is refused under multi.
    let repository = format!("ed25519-{}/packs", "ab".repeat(32));
    let flags = extra(
        &enc_flags,
        &[
            "--enc-repository",
            &repository,
            "--unsafe-allow-any-enc-peer",
        ],
    );
    let (code, message) = refusal(&flags);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("--unsafe-allow-any-enc-peer"), "{message}");
    // With an authorized-peers allowlist instead it resolves.
    let peers = f.root.path().join("peers");
    fs::write(&peers, format!("{}\n", "ab".repeat(32))).unwrap();
    let flags = extra(
        &enc_flags,
        &[
            "--enc-repository",
            &repository,
            "--enc-authorized-peers",
            common::s(&peers),
            "--enc-server-key",
            common::s(&f.root.path().join("server.key")),
        ],
    );
    let cfg = resolve(&flags).unwrap();
    let enc = cfg.enc.expect("--listen-enc resolves");
    assert_eq!(enc.repository.as_deref(), Some(repository.as_str()));
    // --enc-repository without --addressing multi, or without --listen-enc.
    let single = drop_flag(&multi(&f), "--addressing", true);
    let single = drop_flag(&single, "--namespace-allowlist", true);
    let flags = extra(
        &single,
        &[
            "--addressing",
            "single",
            "--listen-enc",
            "127.0.0.1:0",
            "--enc-repository",
            &repository,
        ],
    );
    let (code, message) = refusal(&flags);
    assert_eq!(code, exit::USAGE, "{message}");
    let flags = extra(&multi(&f), &["--enc-repository", &repository]);
    let (code, message) = refusal(&flags);
    assert_eq!(code, exit::USAGE, "{message}");
}

#[test]
fn single_is_the_default_and_unchanged() {
    let f = fixture(&namespace(1));
    for addressing in [None, Some("single")] {
        let mut flags = vec![
            "--listen".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--repo-root".to_owned(),
            common::s(f.root.path()).to_owned(),
            "--unsafe-allow-any-peer".to_owned(),
        ];
        if let Some(addressing) = addressing {
            flags.extend(["--addressing".to_owned(), addressing.to_owned()]);
        }
        let cfg = resolve(&flags).unwrap();
        let Addressing::Single { repo } = &cfg.pipeline.addressing else {
            panic!("single is the default");
        };
        assert_eq!(repo.name.as_str(), "default");
        assert_eq!(repo.namespace.as_str(), "root");
        // --repository still names the repository.
        flags.extend(["--repository".to_owned(), "room".to_owned()]);
        let cfg = resolve(&flags).unwrap();
        let Addressing::Single { repo } = &cfg.pipeline.addressing else {
            panic!("--repository names the single repository");
        };
        assert_eq!(repo.name.as_str(), "room");
    }
}

/// `--indexed` needs ticketed verification, which the enc sibling pipeline
/// (implicit consumption) cannot run, so `--indexed` + Multi + `--listen-enc`
/// is a config-time error rather than a `Pipeline::new` failure at startup.
#[cfg(all(feature = "enc", feature = "test-faults"))]
#[test]
fn indexed_with_multi_enc_is_refused_at_config_time() {
    let f = fixture(&namespace(1));
    let repository = format!("ed25519-{}/packs", "ab".repeat(32));
    let peers = f.root.path().join("peers");
    std::fs::write(&peers, format!("{}\n", "ab".repeat(32))).unwrap();
    let flags = extra(
        &multi(&f),
        &[
            "--listen-enc",
            "127.0.0.1:0",
            "--enc-repository",
            &repository,
            "--enc-authorized-peers",
            common::s(&peers),
            "--enc-server-key",
            common::s(&f.root.path().join("server.key")),
        ],
    );
    resolve(&flags).unwrap();
    let (code, message) = refusal(&extra(&flags, &["--indexed"]));
    assert_eq!(code, exit::USAGE, "{message}");
    assert!(message.contains("--indexed"), "{message}");
    assert!(message.contains("--listen-enc"), "{message}");
    // Indexed alone (no enc listener) still resolves.
    resolve(&extra(&multi(&f), &["--indexed"])).unwrap();
}

/// `multi()` with a production audience, so the loopback rules can be
/// exercised on their own.
fn production(f: &Fixture) -> Vec<String> {
    extra(
        &drop_flag(&multi(f), "--audience", true),
        &["--audience", "https://vcs.example"],
    )
}

const WEBAUTHN_RP: &str = "example.test=https://example.test";

#[test]
fn grant_flags_configure_the_verifier_and_default_to_off() {
    let f = fixture(&namespace(1));
    assert!(resolve(&production(&f)).unwrap().pipeline.grants.is_none());
    let flags = extra(
        &production(&f),
        &[
            "--grant-schemes",
            "ed25519, webauthn-p256",
            "--webauthn-rp",
            WEBAUTHN_RP,
            "--webauthn-rp",
            "other.test=https://other.test,https://app.other.test",
        ],
    );
    let cfg = resolve(&flags).unwrap();
    let grants = cfg.pipeline.grants.as_ref().unwrap();
    assert_eq!(grants.audience(), "https://vcs.example");
    assert_eq!(
        grants.schemes().tokens().collect::<Vec<_>>(),
        ["ed25519", "webauthn-p256"]
    );
    assert!(cfg.banners().is_empty(), "no loopback banner in production");
}

#[test]
fn grant_settings_fail_closed_and_never_degrade_to_off() {
    let f = fixture(&namespace(1));
    let with = |more: &[&str]| extra(&production(&f), more);
    let cases: &[(&[&str], u8)] = &[
        // An unknown scheme, a blank list and a blank entry.
        (&["--grant-schemes", "rsa"], exit::USAGE),
        (&["--grant-schemes", ""], exit::USAGE),
        (&["--grant-schemes", "ed25519,"], exit::USAGE),
        // A malformed relying-party entry, and a duplicate id.
        (
            &[
                "--grant-schemes",
                "ed25519,webauthn-p256",
                "--webauthn-rp",
                "example.test",
            ],
            exit::USAGE,
        ),
        (
            &[
                "--grant-schemes",
                "ed25519,webauthn-p256",
                "--webauthn-rp",
                WEBAUTHN_RP,
                "--webauthn-rp",
                "example.test=https://other.test",
            ],
            exit::CONFIG_ERROR,
        ),
        // `webauthn-p256` without a relying party.
        (&["--grant-schemes", "webauthn-p256"], exit::CONFIG_ERROR),
        // A relying party, or the loopback opt-in, without any scheme.
        (&["--webauthn-rp", WEBAUTHN_RP], exit::USAGE),
        (&["--unsafe-allow-loopback-grants"], exit::USAGE),
    ];
    for (more, code) in cases {
        let (got, message) = refusal(&with(more));
        assert_eq!(got, *code, "{more:?}: {message}");
    }
}

#[test]
fn grants_need_multi_and_auth_v2() {
    let f = fixture(&namespace(1));
    // Single addressing under auth v2.
    let single = extra(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(f.root.path()),
            "--auth",
            "auth-v2",
            "--audience",
            "https://vcs.example",
            "--meta",
            &f.meta,
            "--grant-schemes",
            "ed25519",
        ]
        .map(str::to_owned),
        &[],
    );
    let (code, message) = refusal(&single);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("--addressing multi"), "{message}");
    // An enc-only Multi deployment has no auth v2 audience to bind grants to.
    let no_auth = drop_flag(&production(&f), "--audience", true);
    let no_auth = drop_flag(&no_auth, "--auth", true);
    let (code, message) = refusal(&extra(
        &no_auth,
        &["--unsafe-allow-any-peer", "--grant-schemes", "ed25519"],
    ));
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    // Multi's own auth check comes first, so the grant flags never get a
    // deployment without auth v2.
    assert!(message.contains("--auth auth-v2"), "{message}");
}

#[test]
fn a_loopback_audience_or_relying_party_needs_the_opt_in_and_prints_its_banner() {
    let f = fixture(&namespace(1));
    // `multi()` serves `http://localhost`.
    let loopback_audience = extra(&multi(&f), &["--grant-schemes", "ed25519"]);
    let (code, message) = refusal(&loopback_audience);
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("loopback"), "{message}");
    // A loopback relying party under a production audience.
    let local_rp = [
        "--grant-schemes",
        "ed25519,webauthn-p256",
        "--webauthn-rp",
        "localhost=http://localhost:8787",
    ];
    let (code, message) = refusal(&extra(&production(&f), &local_rp));
    assert_eq!(code, exit::CONFIG_ERROR, "{message}");
    assert!(message.contains("loopback"), "{message}");
    // With the opt-in both resolve, and the banner is printed.
    for flags in [
        extra(&loopback_audience, &["--unsafe-allow-loopback-grants"]),
        extra(
            &extra(&production(&f), &local_rp),
            &["--unsafe-allow-loopback-grants"],
        ),
    ] {
        let cfg = resolve(&flags).unwrap();
        assert!(cfg.pipeline.grants.is_some());
        assert!(
            cfg.banners()
                .contains(&mkit_server_native::config::UNSAFE_LOOPBACK_GRANTS_BANNER)
        );
    }
}

/// The enc listener's `TransportIdentity` sibling of a grants pipeline drops
/// the grant config (a transport-identity write has no header-grant path),
/// so the deployment starts.
#[cfg(feature = "enc")]
#[test]
fn grants_and_an_enc_listener_start_together() {
    // Config files live outside the served root: `--meta sqlite` refuses a
    // root that already holds files it takes for refs.
    let aux = tempfile::tempdir().unwrap();
    let root = common::repo_root();
    let repository = format!("{}/packs", namespace(1));
    let write = |name: &str, text: &str| {
        let path = aux.path().join(name);
        std::fs::write(&path, text).unwrap();
        common::s(&path).to_owned()
    };
    let allowlist = write("namespaces", &namespace(1));
    let peers = write("peers", &format!("{}\n", "ab".repeat(32)));
    let tickets = aux.path().join("ticket.keys");
    common::secret_file(&tickets, format!("{TICKET_KEYS}\n").as_bytes());
    let meta = format!("sqlite:{}", common::s(&aux.path().join("meta.sqlite3")));
    let key = aux.path().join("server.key");
    let flags = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
        "--addressing",
        "multi",
        "--namespace-allowlist",
        &allowlist,
        "--auth",
        "auth-v2",
        "--audience",
        "https://vcs.example",
        "--ticket-key-file",
        common::s(&tickets),
        "--meta",
        &meta,
        "--grant-schemes",
        "ed25519",
        "--listen-enc",
        "127.0.0.1:0",
        "--enc-repository",
        &repository,
        "--enc-authorized-peers",
        &peers,
        "--enc-server-key",
        common::s(&key),
    ]
    .map(str::to_owned);
    let cfg = resolve(&flags).unwrap();
    let opened = mkit_server_native::server::open(&cfg).unwrap();
    assert!(opened.enc.is_some(), "the enc sibling pipeline is built");
}
