//! The published `mkit-transport-enc` 0.4 client against
//! `mkit-server serve --listen-enc` from this tree (`MKIT_SERVER_BIN`): the
//! handshake, the application `Hello`, every verb, the CAS conflict
//! mapping, and the allowlist.

#![cfg(unix)]

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::Signer as _;
use commonware_cryptography::ed25519::PrivateKey;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportError};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pubkey(key: &PrivateKey) -> [u8; 32] {
    key.public_key().encode().as_ref().try_into().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn private_file(path: &Path, contents: &[u8], mode: u32) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn published_enc_client_talks_to_mkit_server() {
    let bin = std::env::var("MKIT_SERVER_BIN")
        .expect("set MKIT_SERVER_BIN to a built mkit-server (`just interop-enc` does)");
    let td = tempfile::tempdir().unwrap();
    // Key files may have no symlinked ancestor (macOS /var -> /private/var).
    let root = fs::canonicalize(td.path()).unwrap();
    fs::create_dir(root.join(".mkit")).unwrap();
    let keys = root.join("keys");
    fs::create_dir(&keys).unwrap();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
    let seed = [0x5au8; 32];
    private_file(&keys.join("server.key"), &seed, 0o600);
    let server_key = PrivateKey::decode(seed.as_slice()).unwrap();
    let client_key = PrivateKey::from_seed(7);
    private_file(
        &root.join("peers"),
        format!("{}\n", hex(&pubkey(&client_key))).as_bytes(),
        0o644,
    );

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let mut server = Server(
        Command::new(bin)
            .args(["serve", "--listen-enc", &addr, "--enc-authorized-peers"])
            .arg(root.join("peers"))
            .arg("--enc-server-key")
            .arg(keys.join("server.key"))
            .arg("--repo-root")
            .arg(&root)
            .env("RUST_LOG", "warn")
            .env_remove("MKIT_SERVE_ROOT")
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_mins(1);
    while std::net::TcpStream::connect(&addr).is_err() {
        assert!(Instant::now() < deadline, "mkit-server did not listen");
        std::thread::sleep(Duration::from_millis(50));
    }

    let server_pk = pubkey(&server_key);
    let client = mkit_transport_enc::connect_tcp("127.0.0.1", port, &server_pk, client_key)
        .expect("the published client completes the handshake and Hello");
    assert!(client.list_refs("").unwrap().is_empty());
    let bytes = b"interop pack bytes".to_vec();
    let key = PackKey::new(mkit_core::hash::hash(&bytes));
    assert!(!client.pack_exists(&key).unwrap());
    client.upload_pack(&bytes, &key).unwrap();
    assert!(client.pack_exists(&key).unwrap());
    assert_eq!(client.download_pack(&key).unwrap(), bytes);
    assert!(client.upload_pack(b"wrong", &key).is_err());
    let id = *key.as_bytes();
    client
        .update_ref("refs/heads/main", RefWriteCondition::Missing, &id)
        .unwrap();
    assert_eq!(client.read_ref("refs/heads/main").unwrap(), Some(id));
    let refs = client.list_refs("refs/heads").unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].name, "main");
    let err = client
        .update_ref(
            "refs/heads/main",
            RefWriteCondition::Match([1; 32]),
            &[2; 32],
        )
        .unwrap_err();
    assert!(matches!(err, TransportError::RefConflict), "{err:?}");
    drop(client);

    let unlisted =
        mkit_transport_enc::connect_tcp("127.0.0.1", port, &server_pk, PrivateKey::from_seed(8));
    assert!(unlisted.is_err(), "an unlisted key got a session");

    let pid = server.0.id().to_string();
    assert!(
        Command::new("kill")
            .args(["-TERM", &pid])
            .status()
            .unwrap()
            .success()
    );
    let status = server.0.wait().unwrap();
    assert!(status.success(), "{status:?}");
}
