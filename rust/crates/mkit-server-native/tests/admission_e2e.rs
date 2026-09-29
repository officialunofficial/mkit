//! Leg N: real mkit-server binary, public CLI config entry and POSIX sh helper.
#![allow(clippy::unwrap_used)]
mod common;
use mkit_core::{layout::RepoLayout, protocol::RefWriteCondition, store::ObjectStore};
use mkit_server::hooks::HookSigner;
use mkit_server_conformance::stubs::{
    hook::HookKey,
    mpp::{Delivery, MppStub},
};
use mkit_server_conformance::wire::client::{Client, UNARY_JSON};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn repository(path: &std::path::Path) -> mkit_core::hash::Hash {
    use mkit_core::object::{Commit, Identity, Object, Tree};
    let layout = RepoLayout::single(path);
    let store = ObjectStore::init(&layout).unwrap();
    mkit_core::refs::init(&layout).unwrap();
    std::fs::create_dir_all(path.join(".mkit/keys")).unwrap();
    let key = mkit_core::sign::KeyPair::from_seed([9; 32]);
    mkit_core::sign::save_key(&path.join(".mkit/keys/client.key"), &key).unwrap();
    let tree = store
        .write(&mkit_core::serialize::serialize(&Object::Tree(Tree { entries: vec![] })).unwrap())
        .unwrap();
    let mut commit = Commit::new_unannotated(
        tree,
        vec![],
        Identity::ed25519(key.public.0),
        key.public.0,
        b"MPP push".to_vec(),
        1_700_000_000,
        [0; 64],
    );
    commit.signature = mkit_core::sign::sign_commit(&commit, &key).unwrap().0;
    let tip = store
        .write(&mkit_core::serialize::serialize(&Object::Commit(commit)).unwrap())
        .unwrap();
    mkit_core::refs::write_ref(&layout, "main", &tip).unwrap();
    tip
}
// This child captures real CLI eprintln receipt notes without a process-global
// stderr redirect. It is also harmless when nextest runs it independently.
#[test]
fn client_child() {
    let Ok(endpoint) = std::env::var("MKIT_MPP_ENDPOINT") else {
        return;
    };
    let dir = std::env::var("MKIT_MPP_LOCAL").unwrap();
    let path = std::path::Path::new(&dir);
    let tip = repository(path);
    let config = mkit_cli::config::Config {
        transport_auth: "envelope".into(),
        trusted_remote_endpoint: endpoint.clone(),
        admission_helper: std::env::var("MKIT_MPP_HELPER").unwrap(),
        signing_key: ".mkit/keys/client.key".into(),
        ..Default::default()
    };
    let cfg = mkit_cli::config::LayeredConfig {
        merged: config.clone(),
        user: config,
        repo: mkit_cli::config::Config::default(),
    };
    let layout = RepoLayout::single(path);
    let tx =
        mkit_cli::remote_dispatch::open_trusted(&endpoint, "origin", true, &cfg, &layout).unwrap();
    let store = ObjectStore::open(&layout).unwrap();
    let result = mkit_cli::remote_dispatch::push_branch_steps(
        tx.as_ref(),
        &store,
        "main",
        tip,
        RefWriteCondition::Missing,
        100,
        64 << 20,
        &mkit_cli::remote_dispatch::PushControl::default(),
        &mut |_| Ok(()),
    );
    match std::env::var("MKIT_MPP_SCENARIO").unwrap().as_str() {
        "commit" => {
            result.unwrap();
        }
        "reserved" => {
            let error = result.unwrap_err().to_string();
            assert!(error.to_lowercase().contains("x-mkit-ref"));
        }
        "down" => {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("503"), "{error}");
        }
        _ => {
            let error = result.unwrap_err().to_string();
            assert!(
                error.to_lowercase().contains("admission")
                    || error.to_lowercase().contains("payment"),
                "{error}"
            );
        }
    }
}
const HELPER: &str = r#"#!/bin/sh
input=$(cat)
# Values may contain a challenge list. Keep the first matching MPP fields.
id=$(printf '%s' "$input" | awk 'match($0, /Payment id=\\"[a-f0-9]+\\"/) {v=substr($0,RSTART,RLENGTH); sub(/^Payment id=\\"/,"",v); sub(/\\"$/,"",v); print v; exit}')
expires=$(printf '%s' "$input" | awk 'match($0, /expires=\\"[0-9]+\\"/) {v=substr($0,RSTART,RLENGTH); sub(/^expires=\\"/,"",v); sub(/\\"$/,"",v); print v; exit}')
[ -n "$id" ] && [ -n "$expires" ] || exit 2
proof=$(printf '{"challenge":{"id":"%s","expires":%s},"payload":{"proof":"stub"}}' "$id" "$expires" | base64 | tr '+/' '-_' | tr -d '=\n')
printf '{"Authorization":"Payment %s"}\n' "$proof"
"#;
#[test]
fn exec_helper_accepts_combined_challenges() {
    use std::io::Write as _;
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("helper.sh");
    std::fs::write(&script, HELPER).unwrap();
    let value = r#"Payment id="aabb", request="a,b", expires="1999999999", Basic realm="other,id=second", Payment id="eeff", expires="1999999998""#;
    let input = serde_json::json!({"headers":{"www-authenticate":[value]}});
    let mut child = Command::new("sh")
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let headers: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        headers["Authorization"],
        mkit_server_conformance::stubs::mpp::credential_for(value).unwrap()
    );
}

#[allow(clippy::too_many_lines)] // One subprocess lifecycle keeps cleanup and leak checks together.
fn run(scenario: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let root = common::repo_root();
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).unwrap();
    let signer = HookSigner::new("mpp", secret.into()).unwrap();
    let stub = MppStub::start(vec![HookKey::new("mpp", signer.public_key())]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let control = Client::new(&stub.origin().parse().unwrap()).unwrap();
    if matches!(scenario, "down" | "exhausted") {
        let mode = if scenario == "down" {
            "down"
        } else {
            "always-challenge"
        };
        runtime
            .block_on(control.post(
                "/__stub/mode",
                UNARY_JSON,
                &[],
                serde_json::to_vec(&serde_json::json!({"admit":mode})).unwrap(),
            ))
            .unwrap();
    }
    let hook_key = tmp.path().join("hook.key");
    common::secret_file(
        &hook_key,
        format!("mpp {}\n", mkit_core::hash::to_hex(&secret)).as_bytes(),
    );
    let ticket_key = tmp.path().join("ticket.key");
    let mut ticket_secret = [0; 32];
    getrandom::fill(&mut ticket_secret).unwrap();
    common::secret_file(
        &ticket_key,
        format!("ticket {}\n", mkit_core::hash::to_hex(&ticket_secret)).as_bytes(),
    );
    let listen = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listen.local_addr().unwrap();
    drop(listen);
    let origin = format!("http://{addr}");
    let endpoint = format!("mkit+{origin}/default");
    let log = tmp.path().join("server.log");
    let output = std::fs::File::create(&log).unwrap();
    let mut server = Process(
        Command::new(env!("CARGO_BIN_EXE_mkit-server"))
            .args([
                "serve",
                "--listen",
                &addr.to_string(),
                "--repo-root",
                common::s(root.path()),
                "--meta",
                &format!("sqlite:{}", root.path().join("meta.db").display()),
                "--sharding",
                "single",
                "--auth",
                "auth-v2",
                "--audience",
                &origin,
                "--repository",
                "default",
                "--hook-admit-url",
                &stub.origin(),
                "--hook-outcome-url",
                &stub.origin(),
                "--hook-key-file",
                common::s(&hook_key),
                "--ticket-key-file",
                common::s(&ticket_key),
                "--shutdown-drain-secs",
                "20",
            ])
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(addr).is_err() {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "server startup: {}",
            std::fs::read_to_string(&log).unwrap()
        );
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(20));
    }
    let helper = tmp.path().join("helper.sh");
    std::fs::write(
        &helper,
        if scenario == "reserved" {
            "#!/bin/sh\ncat >/dev/null\nprintf '{\"X-Mkit-Ref\":\"forbidden\"}\\n'\n"
        } else {
            HELPER
        },
    )
    .unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let local = tmp.path().join("local");
    std::fs::create_dir(&local).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "client_child", "--nocapture"])
        .env_remove("MKIT_API_TOKEN")
        .env("MKIT_MPP_ENDPOINT", endpoint)
        .env("MKIT_MPP_LOCAL", local)
        .env(
            "MKIT_MPP_HELPER",
            if scenario == "no-helper" {
                ""
            } else {
                common::s(&helper)
            },
        )
        .env("MKIT_MPP_SCENARIO", scenario)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&child.stdout);
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(child.status.success(), "client failed: {stdout}\n{stderr}");
    // Signal only our child. Its exit is the due-outcome drain barrier.
    assert!(
        Command::new("kill")
            .args(["-TERM", &server.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if server.0.try_wait().unwrap().is_some() {
            break;
        }
        assert!(Instant::now() < deadline, "SIGTERM drain timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
    let ledger: BTreeMap<String, Delivery> = serde_json::from_slice(
        &runtime
            .block_on(control.get("/__stub/outcomes"))
            .unwrap()
            .body,
    )
    .unwrap();
    let admits = stub.hook.calls_to("Admit");
    if scenario == "commit" {
        assert!(!ledger.is_empty());
        assert!(
            ledger
                .values()
                .all(|d| d.kind == "committed" && d.settled && !d.released && d.acknowledged >= 1)
        );
        assert!(
            stderr
                .to_lowercase()
                .contains("note: remote returned a payment-receipt receipt for beginupload")
        );
    } else {
        assert!(ledger.is_empty());
        if scenario == "down" {
            assert!(!admits.is_empty());
        } else {
            assert_eq!(admits.len(), if scenario == "exhausted" { 2 } else { 1 });
        }
    }
    let logged = std::fs::read_to_string(log).unwrap();
    for text in [&*stdout, &*stderr, &logged] {
        assert!(!text.contains("Payment ey"));
    }
    for (index, call) in admits.into_iter().enumerate() {
        let req: serde_json::Value = serde_json::from_slice(&call.body).unwrap();
        for h in req["credentialHeaders"].as_array().into_iter().flatten() {
            if let Some(value) = h["value"].as_str() {
                if scenario == "commit" {
                    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                    let token = value.strip_prefix("Payment ").unwrap();
                    let credential: serde_json::Value =
                        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(token).unwrap()).unwrap();
                    let receipt = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({
                        "challengeId": credential["challenge"]["id"], "reference": format!("stub:{index}"), "status":"success"
                    })).unwrap());
                    for text in [&*stdout, &*stderr, &logged] {
                        assert!(!text.contains(&receipt));
                    }
                }
                for text in [&*stdout, &*stderr, &logged] {
                    assert!(!text.contains(value));
                }
            }
        }
    }
}
#[test]
fn helper_push_commits_and_sigterm_drains() {
    run("commit");
}
#[test]
fn no_helper_fails_after_one_attempt() {
    run("no-helper");
}
#[test]
fn reserved_helper_header_is_named_without_retry() {
    run("reserved");
}
#[test]
fn second_challenge_is_terminal() {
    run("exhausted");
}
#[test]
fn down_admit_is_unavailable_with_no_outcome() {
    run("down");
}
