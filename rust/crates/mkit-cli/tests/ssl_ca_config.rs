//! Native HTTPS CA configuration follows normal config layering and an
//! authoritative process-environment override, without disabling TLS checks.
#![allow(clippy::unwrap_used)] // assertion helpers

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Repo {
    root: tempfile::TempDir,
    user: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        let repo = Self {
            root: tempfile::tempdir().unwrap(),
            user: tempfile::tempdir().unwrap(),
        };
        repo.ok(&["init"]);
        repo
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mkit"));
        command
            .args(args)
            .current_dir(self.root.path())
            .env("XDG_CONFIG_HOME", self.user.path().join(".config"))
            .env("HOME", self.user.path())
            .env_remove("MKIT_SSL_CA_FILE")
            .env_remove("MKIT_API_TOKEN")
            .env_remove("MKIT_R2_ACCESS_KEY_ID")
            .env_remove("MKIT_R2_SECRET_ACCESS_KEY");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("spawn mkit")
    }

    fn ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        output
    }

    fn get(&self, key: &str) -> String {
        String::from_utf8(self.ok(&["config", key]).stdout)
            .unwrap()
            .trim()
            .to_owned()
    }

    fn config_file(&self) -> PathBuf {
        self.root.path().join(".mkit/config")
    }

    fn https_remote(&self) {
        self.ok(&[
            "remote",
            "add",
            "origin",
            "mkit+https://ca-fixture.example/default",
        ]);
    }
}

#[test]
fn ca_key_round_trips_case_insensitively_and_is_listed_and_unset() {
    let repo = Repo::new();
    repo.ok(&["config", "HTTP.sslCAInfo", "certs/company ca.pem"]);
    assert_eq!(repo.get("http.sslcainfo"), "certs/company ca.pem");
    assert_eq!(repo.get("HTTP.SSLCAINFO"), "certs/company ca.pem");
    let persisted = fs::read_to_string(repo.config_file()).unwrap();
    assert!(persisted.contains("http.sslcainfo = certs/company ca.pem\n"));
    let json = repo.ok(&["config", "--format=json"]);
    let listing: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(listing["http.sslcainfo"], "certs/company ca.pem");
    repo.ok(&["config", "--unset", "Http.SslCaInfo"]);
    assert_eq!(repo.get("http.sslCAInfo"), "");
    assert!(
        !fs::read_to_string(repo.config_file())
            .unwrap()
            .contains("http.sslcainfo")
    );
}

#[test]
fn ca_follows_user_repo_and_one_shot_layers_without_copying_user_value() {
    let repo = Repo::new();
    repo.ok(&["config", "--global", "http.sslCAInfo", "global.pem"]);
    assert_eq!(repo.get("http.sslcainfo"), "global.pem");
    repo.ok(&["config", "default_branch", "trunk"]);
    assert!(
        !fs::read_to_string(repo.config_file())
            .unwrap()
            .contains("global.pem")
    );
    repo.ok(&["config", "--local", "http.sslCAInfo", "local.pem"]);
    assert_eq!(repo.get("http.sslCAInfo"), "local.pem");
    let once = repo.ok(&["-c", "HTTP.sslCAInfo=once.pem", "config", "http.sslCAInfo"]);
    assert_eq!(String::from_utf8(once.stdout).unwrap().trim(), "once.pem");
    assert_eq!(repo.get("http.sslCAInfo"), "local.pem");
    repo.ok(&["config", "--local", "--unset", "http.sslCAInfo"]);
    assert_eq!(repo.get("http.sslCAInfo"), "global.pem");
    repo.ok(&["config", "--global", "--unset", "http.sslCAInfo"]);
    assert_eq!(repo.get("http.sslCAInfo"), "");
}

fn assert_ca_error(output: &Output, selected: &Path, ignored: &str) {
    assert!(!output.status.success(), "CA setup unexpectedly succeeded");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CA"), "missing CA diagnostic: {stderr}");
    assert!(
        stderr.contains(selected.to_str().unwrap()),
        "selected CA file not identified: {stderr}"
    );
    assert!(!stderr.contains(ignored), "fallback won over env: {stderr}");
}

#[test]
fn fetch_resolves_repo_relative_ca_after_explicit_directory_selection() {
    let repo = Repo::new();
    repo.https_remote();
    repo.ok(&[
        "config",
        "http.sslCAInfo",
        "certs/repo-ca-does-not-exist.pem",
    ]);
    let subdirectory = repo.root.path().join("nested");
    fs::create_dir(&subdirectory).unwrap();
    let output = repo
        .command(&["-C", "..", "fetch", "origin"])
        .current_dir(subdirectory)
        .output()
        .unwrap();
    assert_ca_error(
        &output,
        &repo.root.path().join("certs/repo-ca-does-not-exist.pem"),
        "nested/certs",
    );
}

#[test]
fn environment_ca_wins_over_repository_ca_in_real_cli_process() {
    let repo = Repo::new();
    repo.https_remote();
    repo.ok(&["config", "http.sslCAInfo", "repo-ca-does-not-exist.pem"]);
    let env_ca = repo.user.path().join("env-ca-does-not-exist.pem");
    let output = repo
        .command(&["fetch", "origin"])
        .env("MKIT_SSL_CA_FILE", &env_ca)
        .output()
        .unwrap();
    assert_ca_error(&output, &env_ca, "repo-ca-does-not-exist.pem");
}

#[test]
fn configured_tilde_path_is_expanded_only_for_https_connection() {
    let repo = Repo::new();
    repo.https_remote();
    repo.ok(&[
        "config",
        "http.sslCAInfo",
        "~/certs/tilde-ca-does-not-exist.pem",
    ]);
    assert_eq!(
        repo.get("http.sslCAInfo"),
        "~/certs/tilde-ca-does-not-exist.pem"
    );
    let output = repo.run(&["fetch", "origin"]);
    assert_ca_error(
        &output,
        &repo.user.path().join("certs/tilde-ca-does-not-exist.pem"),
        "~/certs",
    );
}

#[test]
fn environment_override_does_not_need_home_to_expand_ignored_fallback() {
    let repo = Repo::new();
    repo.https_remote();
    repo.ok(&["config", "http.sslCAInfo", "~/ignored-ca.pem"]);
    let env_ca = repo.user.path().join("env-ca-does-not-exist.pem");
    let output = repo
        .command(&["fetch", "origin"])
        .env_remove("HOME")
        .env("MKIT_SSL_CA_FILE", &env_ca)
        .output()
        .unwrap();
    assert_ca_error(&output, &env_ca, "ignored-ca.pem");
}
