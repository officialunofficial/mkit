//! Baseline: the wire suite over HTTP against the real `mkit-server`
//! binary, in both storage configurations:
//!
//! - FS + fs-layout, bearer token from a file: profile bearer, non-atomic;
//! - FS + `SQLite`, auth v2: profile auth v2, atomic. The binary's write
//!   quota is the default (300 writes an hour per signer), too large to
//!   exhaust, so the profile declares none and the `quota.*` cases skip
//!   (`wire_fs_sqlite` runs them against the same wiring with a tiny
//!   quota).
//!
//! Each run ends with SIGTERM, and the binary must drain and exit 0.

#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

mod common;

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use mkit_server_conformance::wire::{Feature, Profile, WireAuth, WireTarget, run};

const BIN: &str = env!("CARGO_BIN_EXE_mkit-server");
const MAX_PACK: u64 = 4 << 20;

/// Cases the binary fails, each with the reason. Target: none.
const DIVERGENCES: &[(&str, &str)] = &[];

/// A free loopback port. The audience must name the port before the
/// binary starts, so it cannot bind `:0`; another process could take the
/// port in between, which fails the test loudly.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The running binary; killed if the test fails early.
struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Server {
    fn start(port: u16, root: &Path, flags: &[&str]) -> Self {
        Self::start_with_env(port, root, flags, &[])
    }

    fn start_with_env(port: u16, root: &Path, flags: &[&str], env: &[(&str, &str)]) -> Self {
        let listen = format!("127.0.0.1:{port}");
        let child = Command::new(BIN)
            .args(["serve", "--listen", &listen, "--repo-root"])
            .arg(root)
            .args(flags)
            .env_remove("MKIT_API_TOKEN")
            .env_remove("MKIT_SERVE_ROOT")
            .envs(env.iter().copied())
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let server = Self(child);
        let deadline = Instant::now() + Duration::from_mins(1);
        while std::net::TcpStream::connect(&listen).is_err() {
            assert!(Instant::now() < deadline, "mkit-server did not listen");
            std::thread::sleep(Duration::from_millis(50));
        }
        server
    }

    /// SIGTERM, then the exit status.
    fn stop(mut self) -> std::process::ExitStatus {
        let pid = self.0.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-TERM", &pid])
                .status()
                .unwrap()
                .success()
        );
        let status = self.0.wait().unwrap();
        std::mem::forget(self);
        status
    }
}

fn profile(auth: WireAuth, atomic: bool) -> Profile {
    let mut p = Profile::new(auth);
    p.atomic_advance = atomic;
    p.max_pack_bytes = MAX_PACK;
    p.list_refs = 200;
    p.derive_features();
    p.features.insert(Feature::Health);
    p
}

async fn check(origin: &str, profile: Profile) {
    let target = WireTarget {
        base_url: origin.parse().unwrap(),
        profile,
    };
    common::judge(&run(&target, None).await, DIVERGENCES);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_fs_layout_bearer() {
    let root = common::repo_root();
    let token_file = root.path().join("token");
    common::secret_file(&token_file, b"binary-token\n");
    let port = free_port();
    let max_pack = MAX_PACK.to_string();
    let server = Server::start(
        port,
        root.path(),
        &[
            "--meta",
            "fs-layout",
            "--bearer-token-file",
            common::s(&token_file),
            "--max-pack-bytes",
            &max_pack,
        ],
    );
    let token = "binary-token".to_owned();
    check(
        &format!("http://127.0.0.1:{port}"),
        profile(WireAuth::Bearer { token }, false),
    )
    .await;
    assert!(server.stop().success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_fs_sqlite_auth_v2() {
    let root = common::repo_root();
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let meta = format!("sqlite:{}", common::s(&root.path().join("meta.sqlite3")));
    let max_pack = MAX_PACK.to_string();
    let server = Server::start(
        port,
        root.path(),
        &[
            "--meta",
            &meta,
            "--auth",
            "auth-v2",
            "--audience",
            &origin,
            "--max-pack-bytes",
            &max_pack,
        ],
    );
    let mut profile = profile(
        WireAuth::AuthV2 {
            audience: origin.clone(),
            repository: "default".to_owned(),
            seed: [0x7a; 32],
        },
        true,
    );
    profile.features.insert(Feature::StrictGzipAuth);
    check(&origin, profile).await;
    assert!(server.stop().success());
}

/// S3 + `SQLite`, auth v2: the binary over the in-repo fake S3, with the
/// credentials in its environment.
#[cfg(feature = "s3")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_s3_sqlite_auth_v2() {
    use mkit_server_conformance::fake_s3::{DEFAULT_BUCKET, FakeS3};

    let fake = FakeS3::start();
    let root = common::repo_root();
    let port = free_port();
    let origin = format!("http://127.0.0.1:{port}");
    let meta = format!("sqlite:{}", common::s(&root.path().join("meta.sqlite3")));
    let max_pack = MAX_PACK.to_string();
    let endpoint = fake.endpoint();
    let blob = format!("s3://{DEFAULT_BUCKET}/binary");
    let opts = fake.options();
    let server = Server::start_with_env(
        port,
        root.path(),
        &[
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
            "--max-pack-bytes",
            &max_pack,
        ],
        &[
            ("MKIT_R2_ACCESS_KEY_ID", &opts.access_key_id),
            ("MKIT_R2_SECRET_ACCESS_KEY", &opts.secret_access_key),
        ],
    );
    let mut profile = profile(
        WireAuth::AuthV2 {
            audience: origin.clone(),
            repository: "default".to_owned(),
            seed: [0x3b; 32],
        },
        true,
    );
    profile.features.insert(Feature::StrictGzipAuth);
    check(&origin, profile).await;
    assert!(server.stop().success());
    assert!(!fake.keys(DEFAULT_BUCKET).is_empty());
    assert!(!root.path().join("packs").exists());
}
