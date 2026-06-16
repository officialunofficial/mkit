//! Integration tests for `mkit mcp` — the stdio Model Context Protocol
//! server. We spawn the real binary and speak newline-delimited
//! JSON-RPC over its stdin/stdout, exercising the full
//! initialize → tools/list → tools/call lifecycle against temp repos.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

/// A live `mkit mcp` subprocess with helpers to exchange JSON-RPC.
struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
    _xdg: tempfile::TempDir,
}

impl McpClient {
    fn spawn(repository: Option<&Path>) -> Self {
        // Isolated XDG so the developer's real mkit config never
        // bleeds into tool subprocesses (the server passes env down).
        let xdg = tempfile::tempdir().expect("xdg tempdir");
        let mut cmd = Command::new(mkit_bin());
        cmd.arg("mcp");
        if let Some(repo) = repository {
            cmd.args(["--repository", repo.to_str().unwrap()]);
        }
        let mut child = cmd
            .env("XDG_CONFIG_HOME", xdg.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn mkit mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut client = Self {
            child,
            stdin,
            stdout,
            next_id: 0,
            _xdg: xdg,
        };
        // Standard MCP handshake.
        let init = client.request(
            "initialize",
            &json!({ "protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" } }),
        );
        assert_eq!(
            init.pointer("/result/serverInfo/name")
                .and_then(Value::as_str),
            Some("mkit-repo")
        );
        client.notify("notifications/initialized");
        client
    }

    fn request(&mut self, method: &str, params: &Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.stdin, "{msg}").expect("write request");
        self.stdin.flush().unwrap();
        // Responses are strictly ordered (sequential server), so the
        // next line is ours; assert the id to be safe.
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        let resp: Value = serde_json::from_str(&line).expect("response is JSON");
        assert_eq!(
            resp.get("id").and_then(Value::as_i64),
            Some(id),
            "id mismatch: {line}"
        );
        resp
    }

    fn notify(&mut self, method: &str) {
        let msg = json!({ "jsonrpc": "2.0", "method": method });
        writeln!(self.stdin, "{msg}").expect("write notification");
        self.stdin.flush().unwrap();
    }

    /// Call a tool; returns `(text, is_error)`.
    fn call(&mut self, tool: &str, args: &Value) -> (String, bool) {
        let resp = self.request("tools/call", &json!({ "name": tool, "arguments": args }));
        let result = resp
            .get("result")
            .unwrap_or_else(|| panic!("no result: {resp}"));
        let text = result
            .pointer("/content/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        (text, is_error)
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Closing stdin ends the serve loop; reap the child.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn ok(client: &mut McpClient, tool: &str, args: &Value) -> String {
    let (text, is_error) = client.call(tool, args);
    assert!(!is_error, "{tool} unexpectedly failed: {text}");
    text
}

fn err(client: &mut McpClient, tool: &str, args: &Value) -> String {
    let (text, is_error) = client.call(tool, args);
    assert!(is_error, "{tool} unexpectedly succeeded: {text}");
    text
}

#[test]
fn lists_all_tools_with_annotations() {
    let repo = tempfile::tempdir().unwrap();
    let mut client = McpClient::spawn(Some(repo.path()));

    let resp = client.request("tools/list", &json!({}));
    let tools = resp.pointer("/result/tools").unwrap().as_array().unwrap();
    assert_eq!(tools.len(), 18);

    let names: Vec<&str> = tools
        .iter()
        .map(|t| t.get("name").unwrap().as_str().unwrap())
        .collect();
    for expected in [
        "mkit_status",
        "mkit_diff_unstaged",
        "mkit_diff_staged",
        "mkit_diff",
        "mkit_log",
        "mkit_show",
        "mkit_branch",
        "mkit_cat_object",
        "mkit_verify",
        "mkit_verify_attest",
        "mkit_add",
        "mkit_unstage",
        "mkit_commit",
        "mkit_create_branch",
        "mkit_checkout",
        "mkit_init",
        "mkit_keygen",
        "mkit_attest",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }
    for t in tools {
        assert_eq!(t.pointer("/annotations/openWorldHint"), Some(&json!(false)));
    }
}

#[test]
fn full_workflow_init_to_log() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "mkit_init", &json!({ "repo_path": repo }));
    let pubkey = ok(
        &mut client,
        "mkit_keygen",
        &json!({ "repo_path": repo, "print_pubkey": true }),
    );
    assert!(pubkey.contains("ed25519:"), "keygen output: {pubkey}");

    std::fs::write(root.path().join("hello.txt"), "hello mcp\n").unwrap();
    ok(
        &mut client,
        "mkit_add",
        &json!({ "repo_path": repo, "files": ["hello.txt"] }),
    );

    let status = ok(&mut client, "mkit_status", &json!({ "repo_path": repo }));
    assert!(status.contains("hello.txt"), "status: {status}");

    let commit = ok(
        &mut client,
        "mkit_commit",
        &json!({ "repo_path": repo, "message": "via mcp" }),
    );
    assert!(commit.contains("committed"), "commit: {commit}");

    let log = ok(&mut client, "mkit_log", &json!({ "repo_path": repo }));
    assert!(log.contains("via mcp"), "log: {log}");

    let verify = ok(
        &mut client,
        "mkit_verify",
        &json!({ "repo_path": repo, "revision": "HEAD" }),
    );
    assert!(verify.contains("ok"), "verify: {verify}");

    // Branching round-trip.
    ok(
        &mut client,
        "mkit_create_branch",
        &json!({ "repo_path": repo, "branch_name": "feature" }),
    );
    ok(
        &mut client,
        "mkit_checkout",
        &json!({ "repo_path": repo, "branch_name": "feature" }),
    );
    let branches = ok(&mut client, "mkit_branch", &json!({ "repo_path": repo }));
    assert!(branches.contains("feature"), "branch: {branches}");

    // Unstage round-trip: stage a change, unstage everything.
    std::fs::write(root.path().join("two.txt"), "two\n").unwrap();
    ok(
        &mut client,
        "mkit_add",
        &json!({ "repo_path": repo, "files": ["two.txt"] }),
    );
    ok(&mut client, "mkit_unstage", &json!({ "repo_path": repo }));
    let status = ok(&mut client, "mkit_status", &json!({ "repo_path": repo }));
    assert!(
        !status.contains("A "),
        "after unstage, nothing staged: {status}"
    );

    // Attestation: produce one, then inspect the commit object.
    let att = ok(&mut client, "mkit_attest", &json!({ "repo_path": repo }));
    assert!(
        att.to_lowercase().contains("att") || att.len() >= 64,
        "attest: {att}"
    );
    let shown = ok(
        &mut client,
        "mkit_show",
        &json!({ "repo_path": repo, "revision": "HEAD" }),
    );
    assert!(shown.contains("via mcp"), "show: {shown}");
}

#[test]
fn commit_without_key_errors_with_guidance() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "mkit_init", &json!({ "repo_path": repo }));
    std::fs::write(root.path().join("a.txt"), "a\n").unwrap();
    ok(
        &mut client,
        "mkit_add",
        &json!({ "repo_path": repo, "files": ["a.txt"] }),
    );

    let text = err(
        &mut client,
        "mkit_commit",
        &json!({ "repo_path": repo, "message": "x" }),
    );
    assert!(
        text.contains("keygen"),
        "error should point at keygen: {text}"
    );
    assert!(
        text.contains("exited"),
        "error carries the exit code: {text}"
    );
}

#[test]
fn keygen_refuses_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "mkit_init", &json!({ "repo_path": repo }));
    ok(&mut client, "mkit_keygen", &json!({ "repo_path": repo }));
    // Second keygen must fail — the server never passes --force.
    err(&mut client, "mkit_keygen", &json!({ "repo_path": repo }));
}

#[test]
fn scope_confines_repo_path() {
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let mut client = McpClient::spawn(Some(allowed.path()));

    let text = err(
        &mut client,
        "mkit_status",
        &json!({ "repo_path": outside.path().to_str().unwrap() }),
    );
    assert!(
        text.contains("outside the allowed repository"),
        "scope error: {text}"
    );
}

#[test]
fn flag_injection_rejected_end_to_end() {
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));
    ok(&mut client, "mkit_init", &json!({ "repo_path": repo }));

    let text = err(
        &mut client,
        "mkit_diff",
        &json!({ "repo_path": repo, "target": "-R" }),
    );
    assert!(text.contains("must not start with '-'"), "{text}");
    let text = err(
        &mut client,
        "mkit_add",
        &json!({ "repo_path": repo, "files": ["-A"] }),
    );
    assert!(text.contains("must not start with '-'"), "{text}");
}

#[test]
fn unknown_tool_is_a_protocol_error() {
    let repo = tempfile::tempdir().unwrap();
    let mut client = McpClient::spawn(Some(repo.path()));
    let resp = client.request(
        "tools/call",
        &json!({ "name": "mkit_push", "arguments": { "repo_path": "." } }),
    );
    assert_eq!(
        resp.pointer("/error/code").and_then(Value::as_i64),
        Some(-32602)
    );
    let msg = resp
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap();
    assert!(msg.contains("unknown tool"), "{msg}");
}

#[test]
fn unknown_method_and_ping() {
    let repo = tempfile::tempdir().unwrap();
    let mut client = McpClient::spawn(Some(repo.path()));

    let resp = client.request("ping", &json!({}));
    assert!(resp.get("result").is_some());

    let resp = client.request("resources/list", &json!({}));
    assert_eq!(
        resp.pointer("/error/code").and_then(Value::as_i64),
        Some(-32601)
    );
}

// --- Helpers for the attestation security tests -----------------------------

/// Decode an even-length lowercase-hex string into bytes.
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The `blake3:<hex>` keyid the repo-key signer reports for `default.key`,
/// derived from the public key the same way the CLI does.
fn repo_keyid(pubkey_hex: &str) -> String {
    let pk = hex_decode(pubkey_hex);
    format!(
        "blake3:{}",
        mkit_core::hash::to_hex(&mkit_core::hash::hash(&pk))
    )
}

/// Pull the `<hex>` out of a `keygen --print-pubkey` "...ed25519:<hex>..." line.
fn pubkey_hex_from(keygen_output: &str) -> String {
    let idx = keygen_output
        .find("ed25519:")
        .expect("keygen prints ed25519:<hex>");
    keygen_output[idx + "ed25519:".len()..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect()
}

#[test]
fn verify_attest_succeeds_with_external_trust_roots() {
    // The most security-sensitive differentiator path, end-to-end through
    // JSON-RPC: attest a commit, then verify it against a trust-roots file
    // OUTSIDE the repo (the only kind the MCP accepts).
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));

    ok(&mut client, "mkit_init", &json!({ "repo_path": repo }));
    let keygen = ok(
        &mut client,
        "mkit_keygen",
        &json!({ "repo_path": repo, "print_pubkey": true }),
    );
    let pubkey_hex = pubkey_hex_from(&keygen);

    std::fs::write(root.path().join("a.txt"), "a\n").unwrap();
    ok(
        &mut client,
        "mkit_add",
        &json!({ "repo_path": repo, "files": ["a.txt"] }),
    );
    ok(
        &mut client,
        "mkit_commit",
        &json!({ "repo_path": repo, "message": "c" }),
    );
    ok(&mut client, "mkit_attest", &json!({ "repo_path": repo }));

    // Trust-roots pinned to our repo key, written OUTSIDE the repo.
    let roots_dir = tempfile::tempdir().unwrap();
    let roots = roots_dir.path().join("trust-roots.toml");
    std::fs::write(
        &roots,
        format!(
            "[[trust_root]]\nkeyid = \"{}\"\nkind = \"ed25519\"\npubkey_hex = \"{}\"\n",
            repo_keyid(&pubkey_hex),
            pubkey_hex
        ),
    )
    .unwrap();

    // Explicit "HEAD" must work (regression for the hex-only --commit trap).
    let out = ok(
        &mut client,
        "mkit_verify_attest",
        &json!({ "repo_path": repo, "commit": "HEAD", "trust_roots": roots.to_str().unwrap() }),
    );
    assert!(
        out.to_lowercase().contains("verif") || out.contains("ok"),
        "verify-attest: {out}"
    );
}

#[test]
fn verify_attest_rejects_in_repo_trust_roots() {
    // Hostile-clone defense: a repo-local trust-roots can never be selected
    // through the MCP, even though the CLI would honor an explicit path.
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));
    ok(&mut client, "mkit_init", &json!({ "repo_path": repo }));
    // Plant an attacker trust-roots inside the repo.
    std::fs::write(root.path().join(".mkit/attest-trust-roots.toml"), "x").unwrap();

    let text = err(
        &mut client,
        "mkit_verify_attest",
        &json!({ "repo_path": repo, "trust_roots": ".mkit/attest-trust-roots.toml" }),
    );
    assert!(text.contains("inside the repository"), "{text}");
}

#[test]
fn attest_rejects_predicate_file_outside_repo() {
    // Scope escape: a scoped MCP must not read an outside file into a
    // signed attestation, even though --repository only confines repo_path.
    let root = tempfile::tempdir().unwrap();
    let repo = root.path().to_str().unwrap().to_string();
    let mut client = McpClient::spawn(Some(root.path()));
    ok(&mut client, "mkit_init", &json!({ "repo_path": repo }));
    ok(&mut client, "mkit_keygen", &json!({ "repo_path": repo }));
    std::fs::write(root.path().join("a.txt"), "a\n").unwrap();
    ok(
        &mut client,
        "mkit_add",
        &json!({ "repo_path": repo, "files": ["a.txt"] }),
    );
    ok(
        &mut client,
        "mkit_commit",
        &json!({ "repo_path": repo, "message": "c" }),
    );

    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("outside.json");
    std::fs::write(&secret, "{}").unwrap();

    let text = err(
        &mut client,
        "mkit_attest",
        &json!({ "repo_path": repo, "predicate_file": secret.to_str().unwrap() }),
    );
    assert!(text.contains("outside the repository"), "{text}");
}

#[test]
fn batch_requests_get_a_single_array_response() {
    // JSON-RPC 2.0: a batch request is answered with ONE array response;
    // a batch of only notifications is answered with nothing at all.
    let repo = tempfile::tempdir().unwrap();
    let mut child = Command::new(mkit_bin())
        .args(["mcp", "--repository", repo.path().to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mkit mcp");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // A notification-only batch first: must produce NO response line.
    writeln!(
        stdin,
        r#"[{{"jsonrpc":"2.0","method":"notifications/initialized"}}]"#
    )
    .unwrap();
    // Then a request batch: initialize + tools/list in one line.
    writeln!(
        stdin,
        r#"[{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18"}}}},{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}]"#
    )
    .unwrap();
    stdin.flush().unwrap();

    // The first line out must be the array for the second batch (the
    // notification-only batch yields nothing).
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    let resp: Value = serde_json::from_str(&line).expect("batch response is JSON");
    let arr = resp
        .as_array()
        .expect("batch response must be a single JSON array");
    assert_eq!(arr.len(), 2);
    assert_eq!(
        arr[0]
            .pointer("/result/serverInfo/name")
            .and_then(Value::as_str),
        Some("mkit-repo")
    );
    assert_eq!(
        arr[1]
            .pointer("/result/tools")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        18
    );

    drop(stdin);
    let _ = child.wait();
}
