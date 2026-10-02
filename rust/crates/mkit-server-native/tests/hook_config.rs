//! The remote-hook flags (WP-3.8): what `serve` refuses before it binds,
//! the key file rules, key-role separation and the `open_with*` guards.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::path::Path;

use mkit_server_native::config::{ConfigError, ServeConfig, resolve};
use mkit_server_native::exit;
use mkit_server_native::hooks::config::{HookArgs, key_list_for};
use mkit_server_native::server::{self, SinkOptions};

const AUDIENCE: &str = "https://vcs.example";
const SEED_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const HOOK: &str = "https://hooks.example/mkit";

struct Rig {
    root: tempfile::TempDir,
    key: std::path::PathBuf,
    tickets: std::path::PathBuf,
}

impl Rig {
    fn new() -> Self {
        let root = common::repo_root();
        let key = root.path().join("hook.key");
        common::secret_file(&key, format!("hook-1 {SEED_HEX}\n").as_bytes());
        let tickets = root.path().join("ticket.keys");
        common::secret_file(&tickets, format!("t-1 {}\n", "3".repeat(64)).as_bytes());
        Self { root, key, tickets }
    }

    /// Flags for an auth-v2 deployment plus `extra`.
    fn flags(&self, extra: &[&str]) -> Vec<String> {
        let db = self.root.path().join("meta.sqlite3");
        let mut flags: Vec<String> = [
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(self.root.path()),
            "--meta",
            &format!("sqlite:{}", common::s(&db)),
            "--auth",
            "auth-v2",
            "--audience",
            AUDIENCE,
            "--ticket-key-file",
            common::s(&self.tickets),
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        flags.extend(extra.iter().map(|s| (*s).to_owned()));
        flags
    }

    fn resolve(&self, extra: &[&str], env: &[(&str, &str)]) -> Result<ServeConfig, ConfigError> {
        let flags = self.flags(extra);
        let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
        common::resolve_with(&flags, env)
    }

    fn with_key(&self, extra: &[&str]) -> Result<ServeConfig, ConfigError> {
        let mut all = vec!["--hook-key-file", common::s(&self.key)];
        all.extend_from_slice(extra);
        self.resolve(&all, &[])
    }
}

fn refused(result: Result<ServeConfig, ConfigError>, code: u8, needle: &str) {
    let err = result.expect_err(needle);
    assert_eq!(err.code, code, "{}", err.message);
    assert!(err.message.contains(needle), "{}", err.message);
}

#[test]
fn hooks_need_auth_v2() {
    let rig = Rig::new();
    let root = common::s(rig.root.path());
    let key = common::s(&rig.key);
    let result = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            root,
            "--unsafe-allow-any-peer",
            "--hook-admit-url",
            HOOK,
            "--hook-key-file",
            key,
        ],
        &[],
    );
    refused(result, exit::CONFIG_ERROR, "auth-v2");
}

#[test]
fn an_outcome_url_needs_sqlite_metadata() {
    let rig = Rig::new();
    let mut cfg = rig
        .with_key(&["--hook-outcome-url", HOOK])
        .expect("sqlite metadata resolves");
    let args = HookArgs {
        hook_outcome_url: Some(HOOK.to_owned()),
        hook_key_file: Some(rig.key.clone()),
        ..HookArgs::default()
    };
    let err = mkit_server_native::hooks::config::resolve(
        &args,
        &mut cfg.pipeline,
        &mkit_server_native::config::MetaChoice::FsLayout,
        std::time::Duration::from_secs(30),
        &|_| None,
    )
    .unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(err.message.contains("sqlite"), "{}", err.message);
}

#[test]
fn a_key_is_required_and_read_from_a_file_or_the_environment() {
    let rig = Rig::new();
    refused(
        rig.resolve(&["--hook-admit-url", HOOK], &[]),
        exit::CONFIG_ERROR,
        "signing key",
    );
    let from_env = rig
        .resolve(
            &["--hook-admit-url", HOOK],
            &[("MKIT_HOOK_KEY", &format!("env-key {SEED_HEX}"))],
        )
        .unwrap();
    assert!(from_env.hooks.is_some());
    let from_file = rig.with_key(&["--hook-admit-url", HOOK]).unwrap();
    assert!(from_file.hooks.is_some());
    // Without any hook URL there are no hooks, and a stray key file or role
    // flag is a mistake, not a silent no-op.
    assert!(rig.resolve(&[], &[]).unwrap().hooks.is_none());
    refused(
        rig.with_key(&[]),
        exit::USAGE,
        "--hook-key-file needs a hook URL",
    );
}

fn key_file_with(rig: &Rig, name: &str, contents: &str, mode: u32) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = rig.root.path().join(name);
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn an_unsafe_or_malformed_key_file_is_refused() {
    let rig = Rig::new();
    let good = format!("hook-1 {SEED_HEX}\n");
    let cases: Vec<(&str, std::path::PathBuf, &str)> = vec![
        (
            "group readable",
            key_file_with(&rig, "group.key", &good, 0o640),
            "chmod",
        ),
        (
            "bad id",
            key_file_with(&rig, "id.key", &format!("bad id! {SEED_HEX}\n"), 0o600),
            "invalid",
        ),
        (
            "short seed",
            key_file_with(&rig, "short.key", "hook-1 abcd\n", 0o600),
            "invalid",
        ),
        (
            "not hex",
            key_file_with(
                &rig,
                "hex.key",
                &format!("hook-1 {}\n", "zz".repeat(32)),
                0o600,
            ),
            "invalid",
        ),
        (
            "two lines",
            key_file_with(
                &rig,
                "two.key",
                &format!("{good}hook-2 {SEED_HEX}\n"),
                0o600,
            ),
            "invalid",
        ),
        (
            "empty",
            key_file_with(&rig, "empty.key", "", 0o600),
            "invalid",
        ),
        ("missing", rig.root.path().join("absent.key"), "absent.key"),
    ];
    for (name, path, needle) in cases {
        let err = rig
            .resolve(
                &[
                    "--hook-admit-url",
                    HOOK,
                    "--hook-key-file",
                    common::s(&path),
                ],
                &[],
            )
            .expect_err(name);
        assert_eq!(err.code, exit::CONFIG_ERROR, "{name}: {}", err.message);
        assert!(err.message.contains(needle), "{name}: {}", err.message);
        assert!(!err.message.contains(SEED_HEX), "{name}: leaked the seed");
    }
    // A symlink to a good file is refused too (`O_NOFOLLOW`).
    let link = rig.root.path().join("link.key");
    std::os::unix::fs::symlink(&rig.key, &link).unwrap();
    let err = rig
        .resolve(
            &[
                "--hook-admit-url",
                HOOK,
                "--hook-key-file",
                common::s(&link),
            ],
            &[],
        )
        .unwrap_err();
    assert!(err.message.contains("symlink"), "{}", err.message);
}

#[test]
fn urls_are_checked_at_startup() {
    let rig = Rig::new();
    for (url, needle) in [
        ("http://hooks.example", "loopback"),
        ("https://user:pw@hooks.example", "credentials"),
        ("https://hooks.example/?q=1", "query"),
    ] {
        let err = rig.with_key(&["--hook-admit-url", url]).expect_err(url);
        assert_eq!(err.code, exit::CONFIG_ERROR);
        assert!(err.message.contains("--hook-admit-url"), "{}", err.message);
        assert!(err.message.contains(needle), "{}", err.message);
        assert!(!err.message.contains("pw"), "{}", err.message);
    }
    rig.with_key(&["--hook-admit-url", "http://127.0.0.1:9"])
        .unwrap();
}

#[test]
fn timeouts_and_validity_are_bounded() {
    let rig = Rig::new();
    // The unary deadline defaults to 30 s.
    for secs in ["30", "31"] {
        refused(
            rig.with_key(&["--hook-admit-url", HOOK, "--hook-timeout-secs", secs]),
            exit::CONFIG_ERROR,
            "below --unary-timeout-secs",
        );
    }
    refused(
        rig.with_key(&["--hook-admit-url", HOOK, "--hook-timeout-secs", "0"]),
        exit::USAGE,
        "at least 1",
    );
    refused(
        rig.with_key(&[
            "--hook-admit-url",
            HOOK,
            "--hook-signature-validity-secs",
            "301",
        ]),
        exit::USAGE,
        "1 to 300",
    );
    refused(
        rig.with_key(&[
            "--hook-admit-url",
            HOOK,
            "--hook-signature-validity-secs",
            "0",
        ]),
        exit::USAGE,
        "1 to 300",
    );
    let cfg = rig
        .with_key(&[
            "--hook-admit-url",
            HOOK,
            "--hook-timeout-secs",
            "9",
            "--unary-timeout-secs",
            "10",
            "--hook-signature-validity-secs",
            "300",
        ])
        .unwrap();
    assert_eq!(
        cfg.hooks.unwrap().timeout,
        std::time::Duration::from_secs(9)
    );
}

#[test]
fn a_role_flag_needs_an_authorize_url() {
    let rig = Rig::new();
    refused(
        rig.with_key(&["--hook-admit-url", HOOK, "--authorizer-role", "authority"]),
        exit::USAGE,
        "--authorize",
    );
    refused(
        rig.resolve(&["--authorizer-role", "check"], &[]),
        exit::USAGE,
        "--hook-authorize-url",
    );
    let cfg = rig
        .with_key(&[
            "--hook-authorize-url",
            HOOK,
            "--authorizer-role",
            "authority",
        ])
        .unwrap();
    assert_eq!(
        cfg.pipeline.authorizer_role,
        mkit_server::policy::AuthorizerRole::Authority
    );
    let cfg = rig.with_key(&["--hook-authorize-url", HOOK]).unwrap();
    assert_eq!(
        cfg.pipeline.authorizer_role,
        mkit_server::policy::AuthorizerRole::Check
    );
}

#[test]
fn a_hook_seed_equal_to_a_ticket_key_is_refused() {
    let rig = Rig::new();
    // The rig's ticket key differs from the hook seed.
    rig.with_key(&["--hook-admit-url", HOOK]).unwrap();
    common::secret_file(&rig.tickets, format!("t-1 {SEED_HEX}\n").as_bytes());
    refused(
        rig.with_key(&["--hook-admit-url", HOOK]),
        exit::CONFIG_ERROR,
        "upload ticket key",
    );
    // A retired key counts too: the first signs, every listed key verifies.
    common::secret_file(
        &rig.tickets,
        format!("t-2 {}\nt-1 {SEED_HEX}\n", "4".repeat(64)).as_bytes(),
    );
    refused(
        rig.with_key(&["--hook-authorize-url", HOOK]),
        exit::CONFIG_ERROR,
        "upload ticket key",
    );
}

#[test]
fn a_remote_admission_needs_ticket_keys() {
    let rig = Rig::new();
    let db = rig.root.path().join("meta.sqlite3");
    let result = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(rig.root.path()),
            "--meta",
            &format!("sqlite:{}", common::s(&db)),
            "--auth",
            "auth-v2",
            "--audience",
            AUDIENCE,
            "--hook-admit-url",
            HOOK,
            "--hook-key-file",
            common::s(&rig.key),
        ],
        &[],
    );
    refused(result, exit::CONFIG_ERROR, "ticket keys");
}

#[test]
fn a_hook_seed_equal_to_the_enc_server_key_is_refused_when_the_server_opens() {
    let rig = Rig::new();
    // Raw 32-byte and bare 64-hex files read as ref files, so the enc key and
    // peers files live outside the served root.
    let keys = tempfile::tempdir().unwrap();
    let key_dir = keys.path().join("enc");
    std::fs::create_dir(&key_dir).unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let enc_key = key_dir.join("enc.key");
    let seed = [0x22u8; 32];
    common::secret_file(&enc_key, &seed);
    let peers = keys.path().join("peers");
    std::fs::write(&peers, format!("{}\n", "ab".repeat(32))).unwrap();
    let extra = |key: &Path| {
        vec![
            "--listen-enc".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--enc-authorized-peers".to_owned(),
            common::s(&peers).to_owned(),
            "--enc-server-key".to_owned(),
            common::s(key).to_owned(),
            "--hook-admit-url".to_owned(),
            HOOK.to_owned(),
        ]
    };
    let flags = extra(&enc_key);
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let cfg = rig.with_key(&flags).unwrap();
    let err = server::open(&cfg).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(err.message.contains("enc server key"), "{}", err.message);
    // A different enc key opens (on a fresh root: the refused open above
    // already claimed this one).
    let rig = Rig::new();
    let other = key_dir.join("enc2.key");
    common::secret_file(&other, &[0x33u8; 32]);
    let peers = keys.path().join("peers");
    std::fs::write(&peers, format!("{}\n", "ab".repeat(32))).unwrap();
    let extra = |key: &Path| {
        vec![
            "--listen-enc".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--enc-authorized-peers".to_owned(),
            common::s(&peers).to_owned(),
            "--enc-server-key".to_owned(),
            common::s(key).to_owned(),
            "--hook-admit-url".to_owned(),
            HOOK.to_owned(),
        ]
    };
    let flags = extra(&other);
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let cfg = rig.with_key(&flags).unwrap();
    drop(server::open(&cfg).unwrap());
}

struct Nothing;
impl mkit_server::pipeline::OutcomeSink for Nothing {
    async fn deliver(
        &self,
        _: &mkit_server::pipeline::Outcome,
    ) -> Result<(), mkit_server::pipeline::DeliveryError> {
        Ok(())
    }
}

#[test]
fn embedder_sinks_and_hooks_do_not_mix_with_the_hook_flags() {
    let rig = Rig::new();
    let cfg = rig.with_key(&["--hook-outcome-url", HOOK]).unwrap();
    let err = server::open_with_sink(&cfg, Nothing, SinkOptions::default()).unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    assert!(err.message.contains("--hook-*-url"), "{}", err.message);
    let err = server::open_with(
        &cfg,
        mkit_server::pipeline::Hooks::new(),
        Nothing,
        SinkOptions::default(),
    )
    .unwrap_err();
    assert_eq!(err.code, exit::CONFIG_ERROR);
    // Without hook flags both open.
    let plain = rig.resolve(&[], &[]).unwrap();
    drop(server::open_with_sink(&plain, Nothing, SinkOptions::default()).unwrap());
}

#[test]
fn settings_never_print_urls_or_keys() {
    let rig = Rig::new();
    let cfg = rig
        .with_key(&[
            "--hook-admit-url",
            "https://hooks.example/secret-path-token",
        ])
        .unwrap();
    let debug = format!("{cfg:?}");
    assert!(debug.contains("HookSettings"));
    assert!(!debug.contains("secret-path-token"), "{debug}");
    assert!(!debug.contains(SEED_HEX), "{debug}");
    assert!(!debug.contains("2222"), "{debug}");
}

#[test]
fn the_key_list_is_the_spec_shape() {
    let rig = Rig::new();
    let json = key_list_for(&rig.key).unwrap();
    let list: serde_json::Value = serde_json::from_str(&json).unwrap();
    let public = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(list["version"], 1);
    assert_eq!(list["keys"].as_array().unwrap().len(), 1);
    assert_eq!(list["keys"][0]["keyId"], "hook-1");
    assert_eq!(list["keys"][0]["alg"], "ed25519");
    assert_eq!(
        list["keys"][0]["publicKey"],
        mkit_core::hash::to_hex(&public)
    );
    // No private material in the output.
    assert!(!json.contains(SEED_HEX));
    // A bad key file is an error, not an empty list.
    let bad = key_file_with(&rig, "bad.key", "nonsense\n", 0o600);
    assert!(key_list_for(&bad).is_err());
}

#[test]
fn resolve_takes_the_same_args_type_the_binary_parses() {
    // The flags flatten into `ServeArgs`, so `common::args` parses them.
    let rig = Rig::new();
    let flags = rig.flags(&["--hook-admit-url", HOOK]);
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    let args = common::args(&flags);
    assert_eq!(args.hooks.hook_admit_url.as_deref(), Some(HOOK));
    assert_eq!(args.hooks.hook_timeout_secs, 5);
    assert_eq!(args.hooks.hook_signature_validity_secs, 60);
    assert!(args.hooks.hook_inspect_url.is_empty());
    assert_eq!(args.hooks.inspect_mode, None);
    assert_eq!(args.hooks.inspect_on_unavailable, None);
    assert_eq!(args.hooks.inspect_batch_max_objects, 10_000);
    let _ = resolve; // the entry point under test
}

#[test]
fn authority_configuration_requires_dedicated_keys_and_authority_role() {
    let rig = Rig::new();
    let ns = "ed25519-0101010101010101010101010101010101010101010101010101010101010101";
    let list = rig.root.path().join("namespaces");
    std::fs::write(&list, ns).unwrap();
    let public = mkit_core::hash::to_hex(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .as_bytes(),
    );
    let key = format!("deployment {public} {ns}");
    let flags = [
        "--addressing",
        "multi",
        "--namespace-allowlist",
        common::s(&list),
        "--hook-authorize-url",
        HOOK,
        "--authorizer-role",
        "authority",
        "--authority-fence",
        "--authority-key",
        &key,
    ];
    assert!(
        rig.with_key(&flags)
            .unwrap()
            .pipeline
            .authority_fence
            .is_some()
    );
    assert!(rig.with_key(&["--authority-fence"]).is_err());
    assert!(rig.with_key(&["--authority-key", &key]).is_err());
    let repeated_public = mkit_core::hash::to_hex(
        ed25519_dalek::SigningKey::from_bytes(&[0x22; 32])
            .verifying_key()
            .as_bytes(),
    );
    let repeated = format!("deployment {repeated_public} {ns}");
    let mut bad = flags;
    bad[10] = &repeated;
    assert!(rig.with_key(&bad).is_err());
}

#[test]
#[cfg(feature = "test-faults")]
fn inspection_configuration_requires_launch_profile_and_restricted_indexed_tickets() {
    let rig = Rig::new();
    let namespace = "ed25519-0101010101010101010101010101010101010101010101010101010101010101";
    let list = rig.root.path().join("inspection-namespaces");
    std::fs::write(&list, namespace).unwrap();
    let base = [
        "--addressing",
        "multi",
        "--namespace-allowlist",
        common::s(&list),
        "--indexed",
        "--hook-inspect-url",
        HOOK,
    ];
    let config = rig.with_key(&base).unwrap();
    let mut duplicate = base.to_vec();
    duplicate.extend(["--hook-inspect-url", HOOK]);
    refused(
        rig.with_key(&duplicate),
        exit::CONFIG_ERROR,
        "repeats an inspector",
    );
    assert_eq!(config.pipeline.begin_upload_threshold_bytes, 0);
    assert_eq!(
        config.hooks.as_ref().unwrap().inspect_batch_max_objects,
        10_000
    );
    let mut explicit = base.to_vec();
    explicit.extend([
        "--inspect-mode",
        "sync",
        "--inspect-on-unavailable",
        "fail_closed",
        "--inspect-batch-max-objects",
        "1",
    ]);
    assert_eq!(
        rig.with_key(&explicit)
            .unwrap()
            .hooks
            .unwrap()
            .inspect_batch_max_objects,
        1
    );
    let built = mkit_server_native::hooks::build::build(config.hooks.as_ref(), AUDIENCE).unwrap();
    assert_eq!(built.inspectors.len(), 1);
    assert!(!format!("{built:?}").contains(HOOK));
    for extra in [
        ["--inspect-mode", "async"],
        ["--inspect-on-unavailable", "publish"],
        ["--inspect-batch-max-objects", "0"],
        ["--inspect-batch-max-objects", "10001"],
    ] {
        let mut flags = base.to_vec();
        flags.extend(extra);
        refused(rig.with_key(&flags), exit::CONFIG_ERROR, "inspect");
    }
    refused(
        rig.with_key(&["--hook-inspect-url", HOOK]),
        exit::CONFIG_ERROR,
        "indexed mode",
    );
    refused(
        rig.with_key(&["--indexed", "--hook-inspect-url", HOOK]),
        exit::CONFIG_ERROR,
        "restricted writes",
    );
    let mut pipeline = config.pipeline.clone();
    pipeline.ticket_keys = None;
    let args = HookArgs {
        hook_inspect_url: vec![HOOK.into()],
        inspect_batch_max_objects: 10_000,
        ..HookArgs::default()
    };
    let error = mkit_server_native::hooks::config::resolve(
        &args,
        &mut pipeline,
        &config.meta,
        std::time::Duration::from_secs(30),
        &|_| None,
    )
    .unwrap_err();
    assert!(error.message.contains("ticket keys"));
}

#[test]
fn inspection_configuration_refuses_fifth_inspector() {
    let rig = Rig::new();
    let flags = [
        "--hook-inspect-url",
        "https://one.example",
        "--hook-inspect-url",
        "https://two.example",
        "--hook-inspect-url",
        "https://three.example",
        "--hook-inspect-url",
        "https://four.example",
        "--hook-inspect-url",
        "https://five.example",
    ];
    refused(rig.with_key(&flags), exit::CONFIG_ERROR, "four inspectors");
    let mut settings =
        mkit_server_native::hooks::config::HookSettings::new("test", [9; 32]).unwrap();
    settings.inspect = (1..=4)
        .map(|n| format!("https://scanner{n}.example"))
        .collect();
    assert_eq!(
        mkit_server_native::hooks::build::build(Some(&settings), AUDIENCE)
            .unwrap()
            .inspectors
            .len(),
        4
    );
    settings.inspect.push("https://scanner5.example".into());
    assert!(mkit_server_native::hooks::build::build(Some(&settings), AUDIENCE).is_err());
}

#[test]
#[cfg(feature = "test-faults")]
fn scanner_retrieval_is_explicit_and_requires_dedicated_roles() {
    use mkit_server_conformance::wire::sign::Signer;
    let rig = Rig::new();
    let list = rig.root.path().join("scanner-namespaces");
    std::fs::write(
        &list,
        "ed25519-0101010101010101010101010101010101010101010101010101010101010101",
    )
    .unwrap();
    let mut flags = vec![
        "--addressing",
        "multi",
        "--namespace-allowlist",
        common::s(&list),
        "--indexed",
        "--hook-inspect-url",
        HOOK,
        "--hook-key-file",
        common::s(&rig.key),
    ];
    let mac = format!("active retrieve-1 {}", "7".repeat(64));
    let scanner = Signer::new([8; 32], AUDIENCE, "").public_key_hex();
    let env = [
        ("SCANNER_RETRIEVAL_KEYS", mac.as_str()),
        ("SCANNER_KEYS", scanner.as_str()),
    ];
    let disabled = rig.resolve(&flags, &[]).unwrap();
    refused(
        rig.resolve(&flags, &env),
        exit::CONFIG_ERROR,
        "scanner retrieval",
    );
    assert!(disabled.pipeline.scanner_retrieval.is_none());
    flags.push("--scanner-retrieval");
    refused(
        rig.resolve(&flags, &[]),
        exit::CONFIG_ERROR,
        "scanner retrieval",
    );
    refused(
        rig.resolve(&flags, &env[..1]),
        exit::CONFIG_ERROR,
        "scanner retrieval",
    );
    let enabled = rig.resolve(&flags, &env).unwrap();
    assert!(enabled.pipeline.scanner_retrieval.is_some());
    for (mac, scanner) in [
        (format!("active retrieve-1 {SEED_HEX}"), scanner.clone()),
        (
            mac.clone(),
            Signer::new([0x22; 32], AUDIENCE, "").public_key_hex(),
        ),
        (
            format!(
                "active retrieve-1 {}",
                Signer::new([0x22; 32], AUDIENCE, "").public_key_hex()
            ),
            scanner,
        ),
    ] {
        refused(
            rig.resolve(
                &flags,
                &[("SCANNER_RETRIEVAL_KEYS", &mac), ("SCANNER_KEYS", &scanner)],
            ),
            exit::CONFIG_ERROR,
            "scanner retrieval",
        );
    }
    let absent_inspector = ["--scanner-retrieval"];
    refused(
        rig.resolve(&absent_inspector, &[]),
        exit::CONFIG_ERROR,
        "scanner retrieval",
    );
}
