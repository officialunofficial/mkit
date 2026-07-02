//! End-to-end `mkit self update` flow against a mock release origin.
//!
//! Exercises the injectable core (`run_update` + `UpdateEnv`) with a
//! mockito server standing in for the GitHub releases API, a tempdir
//! standing in for the install dir, and a test-only trust root. The
//! "binaries" are shell scripts that honor the `mkit version` output
//! contract, which is all the pre-swap self-check needs.
#![cfg(unix)]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::path::{Path, PathBuf};

use mkit_cli::commands::self_update::{Opts, Outcome, UpdateEnv, run_update};
use mkit_core::hash;
use zeroize::Zeroizing;

const TEST_TARGET: &str = "x-test-triple";
const PREDICATE_TYPE_RELEASE_V1: &str =
    "https://github.com/officialunofficial/mkit/spec/predicate/release/v1";

// ------------------------------------------------------------- fixtures

struct Install {
    _dir: tempfile::TempDir,
    exe: PathBuf,
    bin_dir: PathBuf,
    state_dir: PathBuf,
}

/// A managed install: fake binary + both installer receipts.
fn managed_install(tag: &str) -> Install {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&bin_dir).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    let exe = bin_dir.join("mkit");
    std::fs::write(&exe, script_binary(tag.trim_start_matches('v'))).unwrap();
    std::fs::write(bin_dir.join(".mkit-installed-tag"), format!("{tag}\n")).unwrap();
    std::fs::write(state_dir.join("installed-tag"), format!("{tag}\n")).unwrap();
    Install {
        _dir: dir,
        exe,
        bin_dir,
        state_dir,
    }
}

/// A fake mkit binary honoring the byte-exact `version` contract.
fn script_binary(bare: &str) -> Vec<u8> {
    format!("#!/bin/sh\nif [ \"$1\" = version ]; then printf 'mkit {bare}\\n'; fi\n").into_bytes()
}

fn tgz_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    for (path, body) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(body.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        builder.append_data(&mut h, path, *body).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// Sign a release DSSE over `(name, bytes)` subjects with the test seed.
fn signed_dsse(subjects: &[(&str, &[u8])], tag: &str) -> (Vec<u8>, [u8; 32]) {
    use mkit_attest::{Envelope, PAYLOAD_TYPE_IN_TOTO, Sig, Signer as _, jcs, statement};
    let seed = Zeroizing::new([42u8; 32]);
    let pk = mkit_core::sign::KeyPair::from_seed_zeroizing(&seed)
        .public
        .0;
    let predicate = jcs::encode(&jcs::Value::Object(vec![jcs::Member::new(
        "tag",
        jcs::Value::String(tag.to_owned()),
    )]))
    .unwrap();
    let stmt = statement::encode(&statement::Statement {
        subjects: subjects
            .iter()
            .map(|(name, body)| statement::Subject {
                name: Some((*name).to_owned()),
                digest_blake3_hex: hash::to_hex(&hash::hash(body)),
            })
            .collect(),
        predicate_type: PREDICATE_TYPE_RELEASE_V1.to_owned(),
        predicate_jcs: predicate.as_bytes(),
    })
    .unwrap()
    .into_bytes();
    let mut signer = mkit_attest::signer_repo_key::RepoKeySigner::from_seed_zeroizing(&seed);
    let pae = mkit_attest::pae_of(PAYLOAD_TYPE_IN_TOTO, &stmt);
    let sig = signer.sign(&pae).unwrap();
    let dsse = Envelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_owned(),
        payload: stmt,
        signatures: vec![Sig {
            keyid: format!(
                "{}{}",
                mkit_attest::KEYID_PREFIX,
                hash::to_hex(&hash::hash(&pk))
            ),
            sig,
        }],
    }
    .encode()
    .unwrap()
    .into_bytes();
    (dsse, pk)
}

/// Stand up a mock origin serving `latest` → `tag` plus the tag's
/// release JSON and its three assets. Returns the guard (mocks live as
/// long as it does) and the trust key.
struct Origin {
    server: mockito::ServerGuard,
    trust_key: [u8; 32],
}

fn origin_with_release(tag: &str, archive: &[u8]) -> Origin {
    origin_with_release_and_dsse_body(tag, archive, None)
}

/// `dsse_override` lets the tamper test serve an attestation that does
/// not match the served archive.
fn origin_with_release_and_dsse_body(
    tag: &str,
    archive: &[u8],
    dsse_override: Option<&[u8]>,
) -> Origin {
    use sha2::Digest as _;
    let bare = tag.trim_start_matches('v');
    let archive_name = format!("mkit-{bare}-{TEST_TARGET}.tar.gz");
    let dsse_name = format!("mkit-{bare}.release.dsse");
    let (dsse, trust_key) = signed_dsse(&[(archive_name.as_str(), archive)], tag);
    let dsse_body = dsse_override.map_or(dsse, <[u8]>::to_vec);
    let sha_body = format!(
        "{}  {archive_name}\n",
        hash::to_hex_bytes(&sha2::Sha256::digest(archive))
    );

    let mut server = mockito::Server::new();
    let url = server.url();
    let release_json = format!(
        r#"{{"tag_name":"{tag}","assets":[
            {{"name":"{archive_name}","url":"{url}/assets/archive"}},
            {{"name":"{archive_name}.sha256","url":"{url}/assets/sha256"}},
            {{"name":"{dsse_name}","url":"{url}/assets/dsse"}}
        ]}}"#
    );
    server
        .mock("GET", "/releases/latest")
        .with_body(&release_json)
        .create();
    server
        .mock("GET", format!("/releases/tags/{tag}").as_str())
        .with_body(&release_json)
        .create();
    server
        .mock("GET", "/assets/archive")
        .with_body(archive)
        .create();
    server
        .mock("GET", "/assets/sha256")
        .with_body(&sha_body)
        .create();
    server
        .mock("GET", "/assets/dsse")
        .with_body(&dsse_body)
        .create();
    Origin { server, trust_key }
}

fn env_for(origin: &Origin, install: &Install, current: &str) -> UpdateEnv {
    UpdateEnv {
        api_base: origin.server.url(),
        token: None,
        trust_keys: vec![origin.trust_key],
        exe_path: install.exe.clone(),
        state_dir: install.state_dir.clone(),
        current_version: current.to_owned(),
        target: TEST_TARGET.to_owned(),
    }
}

fn opts() -> Opts {
    Opts {
        version: None,
        check: false,
        allow_downgrade: false,
        format: "human".to_owned(),
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

// ----------------------------------------------------------------- tests

#[test]
fn full_update_swaps_binary_and_receipts() {
    let new_binary = script_binary("9.9.9");
    let archive = tgz_with(&[
        (
            &format!("mkit-9.9.9-{TEST_TARGET}/README.md"),
            b"readme".as_slice(),
        ),
        (
            &format!("mkit-9.9.9-{TEST_TARGET}/mkit"),
            new_binary.as_slice(),
        ),
    ]);
    let origin = origin_with_release("v9.9.9", &archive);
    let install = managed_install("v0.3.0");

    let outcome = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap();
    assert_eq!(
        outcome,
        Outcome::Updated {
            from: "v0.3.0".to_owned(),
            to: "v9.9.9".to_owned(),
            exe: install.exe.clone(),
        }
    );
    assert_eq!(std::fs::read(&install.exe).unwrap(), new_binary);
    assert_eq!(
        read(&install.bin_dir.join(".mkit-installed-tag")),
        "v9.9.9\n"
    );
    assert_eq!(read(&install.state_dir.join("installed-tag")), "v9.9.9\n");
    // Same-dir staging file cleaned up by the rename.
    let stray: Vec<_> = std::fs::read_dir(&install.bin_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".mkit-self-update.")
        })
        .collect();
    assert!(stray.is_empty(), "staging file left behind: {stray:?}");
}

#[test]
fn up_to_date_is_a_no_op() {
    let archive = tgz_with(&[(&format!("mkit-0.3.0-{TEST_TARGET}/mkit"), b"x".as_slice())]);
    let origin = origin_with_release("v0.3.0", &archive);
    let install = managed_install("v0.3.0");
    let before = std::fs::read(&install.exe).unwrap();

    let outcome = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap();
    assert_eq!(
        outcome,
        Outcome::UpToDate {
            current: "v0.3.0".to_owned()
        }
    );
    assert_eq!(std::fs::read(&install.exe).unwrap(), before);
}

#[test]
fn latest_downgrade_refused() {
    let archive = tgz_with(&[(&format!("mkit-0.2.0-{TEST_TARGET}/mkit"), b"x".as_slice())]);
    let origin = origin_with_release("v0.2.0", &archive);
    let install = managed_install("v0.3.0");

    let (msg, _) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("silently downgrade"), "{msg}");
    assert_eq!(
        read(&install.bin_dir.join(".mkit-installed-tag")),
        "v0.3.0\n"
    );
}

#[test]
fn pinned_downgrade_requires_allow_flag() {
    let archive = tgz_with(&[(&format!("mkit-0.2.0-{TEST_TARGET}/mkit"), b"x".as_slice())]);
    let origin = origin_with_release("v0.2.0", &archive);
    let install = managed_install("v0.3.0");

    let mut pinned = opts();
    pinned.version = Some("v0.2.0".to_owned());
    let (msg, _) = run_update(&pinned, &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("--allow-downgrade"), "{msg}");
}

#[test]
fn pinned_downgrade_with_allow_flag_proceeds() {
    let old_binary = script_binary("0.2.0");
    let archive = tgz_with(&[(
        &format!("mkit-0.2.0-{TEST_TARGET}/mkit"),
        old_binary.as_slice(),
    )]);
    let origin = origin_with_release("v0.2.0", &archive);
    let install = managed_install("v0.3.0");

    let mut pinned = opts();
    pinned.version = Some("v0.2.0".to_owned());
    pinned.allow_downgrade = true;
    let outcome = run_update(&pinned, &env_for(&origin, &install, "0.3.0")).unwrap();
    assert!(matches!(outcome, Outcome::Updated { .. }));
    assert_eq!(std::fs::read(&install.exe).unwrap(), old_binary);
    assert_eq!(
        read(&install.bin_dir.join(".mkit-installed-tag")),
        "v0.2.0\n"
    );
}

#[test]
fn tampered_archive_rejected_before_swap() {
    let new_binary = script_binary("9.9.9");
    let archive = tgz_with(&[(
        &format!("mkit-9.9.9-{TEST_TARGET}/mkit"),
        new_binary.as_slice(),
    )]);
    // Attestation signs DIFFERENT bytes than the served archive.
    let (wrong_dsse, _) = signed_dsse(
        &[(
            format!("mkit-9.9.9-{TEST_TARGET}.tar.gz").as_str(),
            b"not the served archive".as_slice(),
        )],
        "v9.9.9",
    );
    let origin = origin_with_release_and_dsse_body("v9.9.9", &archive, Some(&wrong_dsse));
    let install = managed_install("v0.3.0");
    let before = std::fs::read(&install.exe).unwrap();

    let (msg, _) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(
        msg.contains("attested subject") || msg.contains("sha256 mismatch"),
        "{msg}"
    );
    assert_eq!(
        std::fs::read(&install.exe).unwrap(),
        before,
        "binary must be untouched"
    );
    assert_eq!(
        read(&install.bin_dir.join(".mkit-installed-tag")),
        "v0.3.0\n"
    );
}

#[test]
fn unmanaged_install_refused_with_guidance() {
    let archive = tgz_with(&[(&format!("mkit-9.9.9-{TEST_TARGET}/mkit"), b"x".as_slice())]);
    let origin = origin_with_release("v9.9.9", &archive);
    let install = managed_install("v0.3.0");
    std::fs::remove_file(install.bin_dir.join(".mkit-installed-tag")).unwrap();

    let (msg, code) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("not installer-managed"), "{msg}");
    assert_eq!(code, 69, "UNAVAILABLE");
}

#[test]
fn receipt_mismatch_refused() {
    let archive = tgz_with(&[(&format!("mkit-9.9.9-{TEST_TARGET}/mkit"), b"x".as_slice())]);
    let origin = origin_with_release("v9.9.9", &archive);
    let install = managed_install("v0.3.0");
    std::fs::write(install.state_dir.join("installed-tag"), "v0.1.0\n").unwrap();

    let (msg, _) = run_update(&opts(), &env_for(&origin, &install, "0.3.0")).unwrap_err();
    assert!(msg.contains("installed-tag mismatch"), "{msg}");
}

#[test]
fn check_reports_without_touching_anything() {
    let archive = tgz_with(&[(&format!("mkit-9.9.9-{TEST_TARGET}/mkit"), b"x".as_slice())]);
    let origin = origin_with_release("v9.9.9", &archive);
    // --check needs no receipts at all: strip the whole install down to
    // a bare binary.
    let install = managed_install("v0.3.0");
    std::fs::remove_file(install.bin_dir.join(".mkit-installed-tag")).unwrap();
    let before = std::fs::read(&install.exe).unwrap();

    let mut check = opts();
    check.check = true;
    let outcome = run_update(&check, &env_for(&origin, &install, "0.3.0")).unwrap();
    assert_eq!(
        outcome,
        Outcome::UpdateAvailable {
            current: "v0.3.0".to_owned(),
            latest: "v9.9.9".to_owned(),
        }
    );
    assert_eq!(std::fs::read(&install.exe).unwrap(), before);
}

#[test]
fn release_without_attestation_refused() {
    // A release whose assets lack the .release.dsse (pre-attestation
    // releases) must be refused, not silently installed.
    let bare = "9.9.9";
    let archive_name = format!("mkit-{bare}-{TEST_TARGET}.tar.gz");
    let archive = tgz_with(&[(&format!("mkit-{bare}-{TEST_TARGET}/mkit"), b"x".as_slice())]);
    let mut server = mockito::Server::new();
    let url = server.url();
    let release_json = format!(
        r#"{{"tag_name":"v{bare}","assets":[{{"name":"{archive_name}","url":"{url}/assets/archive"}}]}}"#
    );
    server
        .mock("GET", "/releases/latest")
        .with_body(&release_json)
        .create();
    server
        .mock("GET", "/releases/tags/v9.9.9")
        .with_body(&release_json)
        .create();
    server
        .mock("GET", "/assets/archive")
        .with_body(&archive)
        .create();

    let install = managed_install("v0.3.0");
    let env = UpdateEnv {
        api_base: server.url(),
        token: None,
        trust_keys: vec![[1u8; 32]],
        exe_path: install.exe.clone(),
        state_dir: install.state_dir.clone(),
        current_version: "0.3.0".to_owned(),
        target: TEST_TARGET.to_owned(),
    };
    let (msg, _) = run_update(&opts(), &env).unwrap_err();
    assert!(
        msg.contains("predates the mkit-native release attestation"),
        "{msg}"
    );
}
