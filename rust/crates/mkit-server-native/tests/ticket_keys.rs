//! Deployment ticket-key parsing, precedence and secret-file checks.
#![allow(clippy::unwrap_used)]

mod common;

use mkit_server_native::config::TICKET_KEYS_ENV;
use mkit_server_native::exit;

const KEYS: &str = "# rotation\ncurrent 1111111111111111111111111111111111111111111111111111111111111111\nold 2222222222222222222222222222222222222222222222222222222222222222\n";

#[test]
fn ticket_keys_file_overrides_environment_and_missing_keys_disable_tickets() {
    let root = common::repo_root();
    let key_file = root.path().join("ticket.keys");
    common::secret_file(&key_file, KEYS.as_bytes());
    let flags = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
        "--unsafe-allow-any-peer",
    ];
    assert!(
        common::resolve_with(&flags, &[])
            .unwrap()
            .pipeline
            .ticket_keys
            .is_none()
    );
    let from_env = common::resolve_with(&flags, &[(TICKET_KEYS_ENV, KEYS)]).unwrap();
    assert!(from_env.pipeline.ticket_keys.is_some());
    let mut with_file = flags.to_vec();
    with_file.extend(["--ticket-key-file", common::s(&key_file)]);
    let from_file = common::resolve_with(
        &with_file,
        &[(TICKET_KEYS_ENV, "invalid-environment-secret")],
    )
    .unwrap();
    assert_eq!(
        from_file.pipeline.ticket_keys,
        from_env.pipeline.ticket_keys
    );
    assert!(!format!("{:?}", from_file.pipeline.ticket_keys).contains("111111111111"));
}

#[test]
fn invalid_ticket_keys_are_usage_errors_without_secret_contents() {
    let root = common::repo_root();
    let key_file = root.path().join("ticket.keys");
    let flags = [
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
        "--unsafe-allow-any-peer",
    ];
    for invalid in ["", "id secret-must-not-be-echoed", "bad/id 11"] {
        common::secret_file(&key_file, invalid.as_bytes());
        let mut with_file = flags.to_vec();
        with_file.extend(["--ticket-key-file", common::s(&key_file)]);
        for error in [
            common::resolve_with(&with_file, &[]).unwrap_err(),
            common::resolve_with(&flags, &[(TICKET_KEYS_ENV, invalid)]).unwrap_err(),
        ] {
            assert_eq!(error.code, exit::USAGE);
            assert!(!error.message.contains("secret-must-not-be-echoed"));
        }
    }
}

#[cfg(unix)]
#[test]
fn ticket_key_file_rejects_symlinks_and_group_access() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let root = common::repo_root();
    let key_file = root.path().join("ticket.keys");
    let link = root.path().join("ticket.link");
    common::secret_file(&key_file, KEYS.as_bytes());
    symlink(&key_file, &link).unwrap();
    let mut flags = vec![
        "--listen",
        "127.0.0.1:0",
        "--repo-root",
        common::s(root.path()),
        "--unsafe-allow-any-peer",
        "--ticket-key-file",
        common::s(&link),
    ];
    assert_eq!(
        common::resolve_with(&flags, &[]).unwrap_err().code,
        exit::USAGE
    );
    flags.pop();
    flags.push(common::s(&key_file));
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        common::resolve_with(&flags, &[]).unwrap_err().code,
        exit::USAGE
    );
}
