//! The M0 exit gate for S3 + `SQLite`: the whole wire suite against the
//! `mkit-server serve` wiring (`config::resolve`, then `server::open`: S3
//! blobs in the in-repo `FakeS3`, `SQLite` metadata, auth v2) served
//! in-process on a loopback port. Same profile as `wire_fs_sqlite`: auth
//! v2, atomic advance, a tiny quota, health, strict gzip auth.
//!
//! Also here: how `--blob s3` resolves its flags and credentials.

#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use mkit_server::quota::QuotaLimits as ServerQuota;
use mkit_server_conformance::fake_s3::{DEFAULT_BUCKET, FakeS3};
use mkit_server_conformance::wire::{Feature, Profile, QuotaLimits, WireAuth, WireTarget, run};
use mkit_server_native::config::{
    AWS_ACCESS_KEY_ENV, AWS_SECRET_KEY_ENV, AWS_SESSION_TOKEN_ENV, BlobChoice, S3_ACCESS_KEY_ENV,
    S3_SECRET_KEY_ENV,
};
use mkit_server_native::{Shutdown, exit, server};

const REPOSITORY: &str = "default";
const MAX_PACK: u64 = 4 << 20;
const QUOTA: ServerQuota = ServerQuota {
    window_ms: 3_600_000,
    max_ops: 6,
    max_bytes: 2 << 20,
};

/// Cases the native server over S3 fails, each with the reason. Target:
/// none.
const DIVERGENCES: &[(&str, &str)] = &[];

fn creds_env(fake: &FakeS3) -> [(&'static str, String); 2] {
    let opts = fake.options();
    [
        (S3_ACCESS_KEY_ENV, opts.access_key_id.clone()),
        (S3_SECRET_KEY_ENV, opts.secret_access_key.clone()),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_suite_s3_sqlite_auth_v2() {
    let fake = FakeS3::start();
    let root = common::repo_root();
    let db = root.path().join("meta.sqlite3");
    let (listener, origin) = common::listener().await;
    let max_pack = MAX_PACK.to_string();
    let meta = format!("sqlite:{}", common::s(&db));
    let blob = format!("s3://{DEFAULT_BUCKET}/wire/run");
    let endpoint = fake.endpoint();
    let env = creds_env(&fake);
    let env: Vec<(&str, &str)> = env.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let mut cfg = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            common::s(root.path()),
            "--meta",
            &meta,
            "--blob",
            &blob,
            "--s3-endpoint",
            &endpoint,
            "--auth",
            "auth-v2",
            "--audience",
            &origin,
            "--repository",
            REPOSITORY,
            "--max-pack-bytes",
            &max_pack,
        ],
        &env,
    )
    .unwrap();
    assert!(matches!(cfg.blob, BlobChoice::S3 { .. }));
    cfg.pipeline.write_quota = Some(QUOTA);
    let opened = server::open(&cfg).unwrap();
    let shutdown = Shutdown::new();
    let served = common::spawn_serve(listener, opened.router.clone(), &shutdown);

    let mut profile = Profile::new(WireAuth::AuthV2 {
        audience: origin.clone(),
        repository: REPOSITORY.to_owned(),
        seed: [0x53; 32],
    });
    profile.atomic_advance = true;
    profile.max_pack_bytes = MAX_PACK;
    profile.list_refs = 200;
    // A server started empty for this test: whole-server listings are bounded.
    profile.fresh_target = true;
    profile.quota = Some(QuotaLimits {
        max_ops: QUOTA.max_ops,
        max_bytes: QUOTA.max_bytes,
        window_ms: QUOTA.window_ms,
    });
    profile.derive_features();
    profile.features.insert(Feature::Health);
    profile.features.insert(Feature::StrictGzipAuth);
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    let report = run(&target, None).await;
    common::judge(&report, DIVERGENCES);
    // Only the `test-faults` cases may skip, as over FS.
    for skipped in report.skips() {
        assert!(
            skipped == "advance.nonatomic_packmap_first"
                || matches!(
                    skipped,
                    "replay.expired_retry_rejected" | "growth.replay_and_quota_pruned"
                )
                || skipped.starts_with("auth.bearer"),
            "unexpected skip {skipped}"
        );
    }

    shutdown.trigger();
    served.await.unwrap().unwrap();
    // The packs live in the bucket under the prefix, none on disk; every
    // key is `<prefix>/packs/<64-hex>`.
    let keys = fake.keys(DEFAULT_BUCKET);
    assert!(!keys.is_empty());
    for key in &keys {
        let hex = key.strip_prefix("wire/run/packs/").unwrap();
        assert!(
            hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "{key}"
        );
    }
    assert!(!root.path().join("packs").exists());
    assert!(db.exists());
    // Every spooled upload is gone.
    let spool = root.path().join(".mkit").join(server::S3_SPOOL_DIR);
    assert_eq!(std::fs::read_dir(spool).unwrap().count(), 0);
    drop(opened);
}

/// The flags every S3 resolution below shares.
fn s3_flags<'a>(root: &'a str, meta: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut flags = vec![
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        root,
        "--meta",
        meta,
        "--unsafe-allow-any-peer",
        "--blob",
        "s3://bucket-a/p",
    ];
    flags.extend_from_slice(extra);
    flags
}

#[test]
#[allow(clippy::too_many_lines)] // one table of cases
fn s3_flags_and_credentials_resolve_fail_closed() {
    let root = common::repo_root();
    let root_s = common::s(root.path());
    let meta = format!("sqlite:{}", common::s(&root.path().join("m.sqlite3")));
    let endpoint = ["--s3-endpoint", "https://s3.example"];
    let resolve = |extra: &[&str], env: &[(&str, &str)]| {
        common::resolve_with(&s3_flags(root_s, &meta, extra), env)
    };
    let mkit = [
        (S3_ACCESS_KEY_ENV, "AKIDMKIT"),
        (S3_SECRET_KEY_ENV, "mkit-secret"),
    ];
    let aws = [
        (AWS_ACCESS_KEY_ENV, "AKIDAWS"),
        (AWS_SECRET_KEY_ENV, "aws-secret"),
    ];

    // The MKIT_R2_* pair wins over AWS_*; the secret never shows.
    let both = [&mkit[..], &aws[..]].concat();
    let cfg = resolve(&endpoint, &both).unwrap();
    let BlobChoice::S3 { config: s3, .. } = &cfg.blob else {
        panic!("not s3")
    };
    assert_eq!(s3.credentials.access_key_id, "AKIDMKIT");
    assert_eq!(s3.credentials.region, "auto");
    assert_eq!(s3.prefix.as_deref(), Some("p"));
    assert_eq!(
        cfg.blob.to_string(),
        "s3://bucket-a/p at https://s3.example/"
    );
    let shown = format!("{cfg:?}");
    assert!(!shown.contains("mkit-secret"), "{shown}");
    // The AWS pair alone works, but not with a session token.
    let BlobChoice::S3 { config: s3, .. } = resolve(&endpoint, &aws).unwrap().blob else {
        panic!("not s3")
    };
    assert_eq!(s3.credentials.access_key_id, "AKIDAWS");
    let with_token = [&aws[..], &[(AWS_SESSION_TOKEN_ENV, "tok")]].concat();
    let refused = |extra: &[&str], env: &[(&str, &str)], code: u8, needle: &str| {
        let e = resolve(extra, env).unwrap_err();
        assert_eq!(e.code, code, "{e}");
        assert!(e.message.contains(needle), "{e}");
        for secret in ["mkit-secret", "aws-secret"] {
            assert!(!e.message.contains(secret), "{e}");
        }
    };
    refused(
        &endpoint,
        &with_token,
        exit::CONFIG_ERROR,
        AWS_SESSION_TOKEN_ENV,
    );
    // Half a pair, no pair, no endpoint, a bad endpoint or bucket.
    refused(&endpoint, &mkit[..1], exit::CONFIG_ERROR, "only one of");
    refused(&endpoint, &[], exit::CONFIG_ERROR, "needs credentials");
    refused(&[], &mkit, exit::USAGE, "--s3-endpoint");
    refused(
        &["--s3-endpoint", "https://h/path"],
        &mkit,
        exit::CONFIG_ERROR,
        "origin",
    );
    let e = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            root_s,
            "--meta",
            &meta,
            "--unsafe-allow-any-peer",
            "--blob",
            "s3://Bad_Bucket",
            "--s3-endpoint",
            "https://s3.example",
        ],
        &mkit,
    )
    .unwrap_err();
    assert_eq!(e.code, exit::CONFIG_ERROR, "{e}");
    // S3 blobs need SQLite metadata; S3 flags need --blob s3.
    let e = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            root_s,
            "--unsafe-allow-any-peer",
            "--blob",
            "s3://bucket-a",
            "--s3-endpoint",
            "https://s3.example",
        ],
        &mkit,
    )
    .unwrap_err();
    assert!(e.message.contains("--meta sqlite"), "{e}");
    let e = common::resolve_with(
        &[
            "--listen",
            "127.0.0.1:0",
            "--repo-root",
            root_s,
            "--unsafe-allow-any-peer",
            "--s3-endpoint",
            "https://s3.example",
        ],
        &mkit,
    )
    .unwrap_err();
    assert_eq!(e.code, exit::USAGE, "{e}");
}

#[test]
fn s3_credentials_file_replaces_the_environment() {
    let root = common::repo_root();
    let root_s = common::s(root.path());
    let meta = format!("sqlite:{}", common::s(&root.path().join("m.sqlite3")));
    let file = root.path().join("s3.env");
    common::secret_file(
        &file,
        b"# R2 token\nexport MKIT_R2_ACCESS_KEY_ID=AKIDFILE\n\nMKIT_R2_SECRET_ACCESS_KEY=\"file-secret\"\n",
    );
    let flags = s3_flags(
        root_s,
        &meta,
        &[
            "--s3-endpoint",
            "https://s3.example",
            "--s3-credentials-file",
            common::s(&file),
        ],
    );
    // The environment's pair is ignored once a file is given.
    let env = [
        (S3_ACCESS_KEY_ENV, "AKIDENV"),
        (S3_SECRET_KEY_ENV, "env-secret"),
    ];
    let BlobChoice::S3 { config: s3, .. } = common::resolve_with(&flags, &env).unwrap().blob else {
        panic!("not s3")
    };
    assert_eq!(s3.credentials.access_key_id, "AKIDFILE");
    assert_eq!(s3.credentials.secret_access_key, "file-secret");
    // A malformed line is refused by number, never quoted.
    common::secret_file(&file, b"MKIT_R2_ACCESS_KEY_ID=A\nsecret-without-equals\n");
    let e = common::resolve_with(&flags, &[]).unwrap_err();
    assert!(e.message.contains("line 2"), "{e}");
    assert!(!e.message.contains("secret-without-equals"), "{e}");
    // Readable by others: refused, as for the bearer token file.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = common::resolve_with(&flags, &[]).unwrap_err();
        assert!(e.message.contains("group or others"), "{e}");
    }
}

#[test]
fn insecure_http_needs_an_explicit_opt_in() {
    let root = common::repo_root();
    let root_s = common::s(root.path());
    let meta = format!("sqlite:{}", common::s(&root.path().join("m.sqlite3")));
    let env = [(S3_ACCESS_KEY_ENV, "AKID"), (S3_SECRET_KEY_ENV, "secret")];
    let resolve = |extra: &[&str]| common::resolve_with(&s3_flags(root_s, &meta, extra), &env);
    // Plain http to a remote host: refused without the flag.
    let e = resolve(&["--s3-endpoint", "http://s3.example"]).unwrap_err();
    assert_eq!(e.code, exit::CONFIG_ERROR, "{e}");
    assert!(e.message.contains("--s3-allow-insecure-http"), "{e}");
    resolve(&[
        "--s3-endpoint",
        "http://s3.example",
        "--s3-allow-insecure-http",
    ])
    .unwrap();
    // Loopback http and https need no flag.
    for ok in [
        "http://127.0.0.1:9000",
        "http://[::1]:9000",
        "http://localhost:9000",
        "https://s3.example",
    ] {
        resolve(&["--s3-endpoint", ok]).unwrap();
    }
}

#[test]
fn spool_budget_defaults_and_must_fit_a_pack() {
    let root = common::repo_root();
    let root_s = common::s(root.path());
    let meta = format!("sqlite:{}", common::s(&root.path().join("m.sqlite3")));
    let env = [(S3_ACCESS_KEY_ENV, "AKID"), (S3_SECRET_KEY_ENV, "secret")];
    let resolve = |extra: &[&str]| common::resolve_with(&s3_flags(root_s, &meta, extra), &env);
    let spool_of = |cfg: mkit_server_native::config::ServeConfig| match cfg.blob {
        BlobChoice::S3 {
            spool_max_bytes, ..
        } => spool_max_bytes,
        _ => panic!("not s3"),
    };
    let endpoint = ["--s3-endpoint", "https://s3.example"];
    assert_eq!(
        spool_of(resolve(&endpoint).unwrap()),
        mkit_server_native::s3::DEFAULT_SPOOL_MAX_BYTES
    );
    let small = [&endpoint[..], &["--s3-spool-max-bytes", "1024"]].concat();
    let e = resolve(&small).unwrap_err();
    assert!(e.message.contains("--s3-spool-max-bytes"), "{e}");
    let fits = [
        &endpoint[..],
        &["--s3-spool-max-bytes", "2048", "--max-pack-bytes", "2048"],
    ]
    .concat();
    assert_eq!(spool_of(resolve(&fits).unwrap()), 2048);
}
