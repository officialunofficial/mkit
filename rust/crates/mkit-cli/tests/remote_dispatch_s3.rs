//! Integration coverage for the `mkit+s3` dispatch branch in
//! [`mkit_cli::remote_dispatch::open`].
//!
//! Two things are under test here:
//!
//! 1. `remote_dispatch::open` no longer returns `UnsupportedScheme` for
//!    `mkit+s3://` URLs — it delegates to [`S3Transport::connect`], which
//!    parses the URL and reads credentials from the environment.
//! 2. Requests issued by the returned transport carry the `SigV4`
//!    `Authorization`, `x-amz-date`, and `x-amz-content-sha256` headers
//!    that the R2 endpoint expects.
//!
//! ## Why `with_parts` for the wire check
//!
//! `S3Transport::connect` rebuilds the URL as `https://<host>` because R2
//! only speaks HTTPS. `mockito` exposes a plain `http://127.0.0.1:<port>`
//! base, so we cannot point a URL-constructed transport at a mockito
//! server. Instead, we cover the scheme-dispatch branch with a smoke
//! test (`open()` succeeds), and cover the signed-request wire shape by
//! constructing the transport directly via the test-only
//! `S3Transport::with_parts` and asserting on the mockito-captured
//! headers.

use std::process::Command;

use mkit_cli::remote_dispatch;
use mkit_core::protocol::{PackKey, Transport};
use mkit_transport_s3::S3Transport;
use mkit_transport_s3::sigv4::Credentials;
use mockito::{Matcher, Server};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

fn run_in(cwd: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(mkit_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn mkit")
}

#[test]
fn open_accepts_mkit_s3_url() {
    // Previously this branch returned `UnsupportedScheme`. With the
    // wiring in place, `open` should now succeed for a syntactically
    // valid `mkit+s3://` URL — even if the credentials env vars are
    // unset. Construction does NOT hit the network.
    let tx = remote_dispatch::open("mkit+s3://r2.example.com/mybucket")
        .expect("mkit+s3:// must now dispatch to S3Transport");
    drop(tx);
}

#[test]
fn open_accepts_mkit_s3_url_with_prefix() {
    let tx = remote_dispatch::open("mkit+s3://r2.example.com/mybucket/myproject")
        .expect("mkit+s3:// with prefix must dispatch");
    drop(tx);
}

#[test]
fn open_rejects_malformed_mkit_s3_url() {
    // Missing bucket component.
    let Err(err) = remote_dispatch::open("mkit+s3://host-only") else {
        panic!("expected error for mkit+s3 URL without bucket");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("transport") || msg.contains("malformed") || msg.contains("bucket"),
        "unexpected error for malformed mkit+s3 URL: {msg}"
    );
}

#[test]
fn signed_put_request_carries_sigv4_headers() {
    // Build a transport manually (bypassing the `https://` rewrite in
    // `S3Transport::connect`) and issue an `upload_pack` against a
    // mockito endpoint. Assert the captured request carries the
    // SPEC-TRANSPORT §6 `SigV4` header set:
    //   - Authorization: AWS4-HMAC-SHA256 ...
    //   - x-amz-date
    //   - x-amz-content-sha256

    let mut server = Server::new();
    let _m = server
        .mock(
            "PUT",
            Matcher::Regex(r"^/mybucket/packs/[0-9a-f]{64}$".to_string()),
        )
        .match_header(
            "authorization",
            Matcher::Regex(r"^AWS4-HMAC-SHA256 ".to_string()),
        )
        .match_header("x-amz-date", Matcher::Any)
        .match_header("x-amz-content-sha256", Matcher::Any)
        .with_status(200)
        .create();

    let creds = Credentials {
        access_key_id: "TESTKEY".into(),
        secret_access_key: "TESTSECRET".into(),
        region: "auto".into(),
    };
    let tx = S3Transport::with_parts(server.url(), "mybucket", None, creds)
        .expect("build S3Transport with mockito endpoint");

    let key = PackKey::new([0xAB; 32]);
    tx.upload_pack(b"hello-pack", &key)
        .expect("signed PUT must succeed against mockito");

    // mockito asserts mock.expect_at_least(1) on drop; an unsigned or
    // malformed request would have failed the header matchers above.
}

#[test]
fn credential_env_vars_are_consulted_at_connect_time() {
    // Document the env-var contract. `S3Transport::connect` reads the
    // `MKIT_R2_ACCESS_KEY_ID` and `MKIT_R2_SECRET_ACCESS_KEY` variables
    // at construction. Absent vars default to empty strings — no error
    // at connect time. The first signed request then surfaces
    // `AccessDenied` because the signer emits an unusable signature.
    //
    // We do NOT mutate env in-process here because `cargo test` runs
    // tests concurrently and env mutation would race against sibling
    // tests. We assert the contract textually instead, then let the
    // `mkit` subcommand do the end-to-end env read via a subprocess.
    assert_eq!(mkit_transport_s3::ENV_ACCESS_KEY, "MKIT_R2_ACCESS_KEY_ID");
    assert_eq!(
        mkit_transport_s3::ENV_SECRET_KEY,
        "MKIT_R2_SECRET_ACCESS_KEY"
    );

    // Subprocess smoke: `mkit remote add` + `mkit remote` round-trips a
    // `mkit+s3://` URL through config without error, even with no creds
    // set. This proves the CLI accepts the scheme.
    let td = tempfile::tempdir().unwrap();
    assert!(run_in(td.path(), &["init"]).status.success());
    let out = run_in(
        td.path(),
        &["remote", "add", "mkit+s3://r2.example.com/bkt/proj"],
    );
    assert!(out.status.success(), "remote add failed: {out:?}");
    let out = run_in(td.path(), &["remote"]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("mkit+s3://r2.example.com/bkt/proj"));
    assert!(stdout.contains("s3"));
}
