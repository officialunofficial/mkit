//! Integration test for `mkit mcp --http` under `--features mcp-v2`: spawns
//! the real binary listening on an OS-assigned port and drives it with a
//! plain HTTP client (`reqwest`, already an unconditional dependency via
//! `mkit self update` — no new supply chain for this test), speaking the
//! MCP 2026-07-28 per-request envelope directly (no `initialize` handshake:
//! SEP-2567 dropped sessions for this era, so a self-declaring request is
//! the whole story — see `mcp_v2.rs`'s module doc). This is the HTTP-transport
//! counterpart to `tests/mcp_server.rs`'s stdio coverage: same shared tool
//! catalog (`mcp.rs::TOOLS`/`call_tool`), different wire transport.
#![cfg(feature = "mcp-v2")]
#![allow(clippy::unwrap_used)] // unwrap is the assertion in test helpers

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn mkit_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mkit")
}

struct HttpMcp {
    child: Child,
    base_url: String,
    /// Extra headers (e.g. `Authorization`) sent on every [`HttpMcp::request`]
    /// call — empty for the plain [`HttpMcp::spawn`] helper.
    headers: Vec<(String, String)>,
}

impl Drop for HttpMcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl HttpMcp {
    /// Spawn `mkit mcp --repository <repo> --http 127.0.0.1:0
    /// --unsafe-allow-any-http-peer` and block until its "listening on
    /// `http://ADDR`" stderr line reveals the OS-assigned port (see
    /// `mcp_v2.rs::serve_http`'s `local_addr()` doc comment — this test is
    /// exactly why that logs the resolved address rather than the requested
    /// one). The unsafe flag opts out of the fail-closed bearer-token gate
    /// (`mcp_v2.rs::resolve_http_auth`) so these tool-catalog tests don't
    /// have to carry a token — see `mod auth` below for gate coverage.
    fn spawn(repo: &std::path::Path) -> Self {
        Self::spawn_with_args(repo, &["--unsafe-allow-any-http-peer"], &[])
    }

    /// [`Self::spawn`], but with `extra_args` appended to the `mkit mcp`
    /// invocation and `headers` sent on every [`Self::request`] call — the
    /// hook `mod auth`'s tests use to pass `--http-token`/exercise the
    /// `Authorization` header without duplicating the spawn/address-parsing
    /// dance.
    fn spawn_with_args(repo: &std::path::Path, extra_args: &[&str], headers: &[(&str, &str)]) -> Self {
        let mut child = Command::new(mkit_bin())
            .args([
                "mcp",
                "--repository",
                repo.to_str().unwrap(),
                "--http",
                "127.0.0.1:0",
            ])
            .args(extra_args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mkit mcp --http");
        let stderr = child.stderr.take().unwrap();
        let mut lines = BufReader::new(stderr).lines();
        let deadline = Instant::now() + Duration::from_secs(10);
        let addr = loop {
            assert!(
                Instant::now() < deadline,
                "server did not report a listening address in time"
            );
            let line = lines
                .next()
                .expect("stderr closed before reporting an address")
                .unwrap();
            if let Some(addr) = line.strip_prefix("mkit mcp: listening on http://") {
                break addr.to_string();
            }
        };
        // Keep draining stderr in the background so a full pipe buffer can
        // never stall the server.
        std::thread::spawn(move || for _ in lines {});
        Self {
            child,
            base_url: format!("http://{addr}/"),
            headers: headers
                .iter()
                .map(|&(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// Try to spawn `mkit mcp --http` with `extra_args` and NO listening
    /// address reported within a short grace period — for the fail-closed
    /// gate tests, where the process is expected to print a config error
    /// and exit before ever binding. Returns the process's exit status and
    /// captured stderr.
    fn spawn_expect_refusal(repo: &std::path::Path, extra_args: &[&str]) -> (std::process::ExitStatus, String) {
        let output = Command::new(mkit_bin())
            .args([
                "mcp",
                "--repository",
                repo.to_str().unwrap(),
                "--http",
                "127.0.0.1:0",
            ])
            .args(extra_args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("spawn mkit mcp --http");
        (
            output.status,
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    /// Send one modern (2026-07-28) request: the per-request envelope lives
    /// in `params._meta`, not a prior `initialize` call. Returns the parsed
    /// JSON-RPC response body, whether the server answered with a plain
    /// JSON body or a single-event SSE stream (both are valid per
    /// `StreamableHttpServerConfig`'s `auto` framing — see the module doc).
    ///
    /// Also sends the SEP-2243 standard headers rmcp enforces once a request
    /// declares protocol version 2026-07-28: `MCP-Protocol-Version` always,
    /// `Mcp-Method` always, and — for `tools/call` specifically — `Mcp-Name`
    /// (the bare tool name; rmcp's `mcp_headers::encode_header_value` only
    /// wraps a value in its `=?base64?...?=` sentinel when it can't travel
    /// as a bare header — never true for mkit's plain-ASCII tool names, so
    /// the raw name is the correct wire value). Omitting any of these is a
    /// documented `-32020` rejection, not a body/shape problem — confirmed
    /// against the real server before wiring this up.
    fn request(&self, id: i64, method: &str, params: Value) -> Value {
        let mut params = params;
        params["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2026-07-28");
        params["_meta"]["io.modelcontextprotocol/clientInfo"] =
            json!({ "name": "mkit-mcp-http-tests", "version": "0" });
        params["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });

        let mut request = reqwest::blocking::Client::new()
            .post(&self.base_url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if method == "tools/call"
            && let Some(name) = params.get("name").and_then(Value::as_str)
        {
            request = request.header("mcp-name", name);
        }
        for (k, v) in &self.headers {
            request = request.header(k, v);
        }
        let response = request.body(body.to_string()).send().expect("http request");
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let text = response.text().expect("response body");

        let parsed: Value = if content_type.contains("text/event-stream") {
            // Single-exchange SSE: the response is complete after one
            // `data:` line, so a plain line scan is enough — no streaming
            // parser needed for a request/response test like this one.
            let data_line = text
                .lines()
                .find_map(|l| l.strip_prefix("data:"))
                .unwrap_or_else(|| panic!("no 'data:' line in SSE body: {text}"));
            serde_json::from_str(data_line.trim())
                .unwrap_or_else(|e| panic!("SSE data is not JSON: {e}: {data_line}"))
        } else {
            serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("response is not JSON (status {status}): {e}: {text}"))
        };
        // A JSON-RPC-level protocol error (e.g. `unknown tool`) rides HTTP
        // 400 with a valid `error` body — that's a legitimate MCP answer,
        // not a broken request; only a status the parsed body doesn't
        // explain is a real failure.
        assert!(
            status.is_success() || parsed.get("error").is_some(),
            "status: {status}, body: {parsed}"
        );
        assert_eq!(
            parsed.get("id").and_then(Value::as_i64),
            Some(id),
            "id mismatch: {parsed}"
        );
        parsed
    }
}

#[test]
fn tools_list_over_http_matches_the_stdio_catalog() {
    let repo = tempfile::tempdir().unwrap();
    let server = HttpMcp::spawn(repo.path());

    let resp = server.request(1, "tools/list", json!({}));
    let tools = resp
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{resp}"));
    assert_eq!(tools.len(), 18, "tool count is part of the public surface");
    assert!(
        tools
            .iter()
            .any(|t| t.get("name").and_then(Value::as_str) == Some("mkit_status"))
    );
}

#[test]
fn tool_call_round_trip_over_http_operates_the_real_repo() {
    let repo = tempfile::tempdir().unwrap();
    let server = HttpMcp::spawn(repo.path());
    let repo_path = repo.path().to_str().unwrap();

    let init = server.request(
        1,
        "tools/call",
        json!({ "name": "mkit_init", "arguments": { "repo_path": repo_path } }),
    );
    assert!(!is_tool_error(&init), "{init}");

    let keygen = server.request(
        2,
        "tools/call",
        json!({ "name": "mkit_keygen", "arguments": { "repo_path": repo_path } }),
    );
    assert!(!is_tool_error(&keygen), "{keygen}");

    let status = server.request(
        3,
        "tools/call",
        json!({ "name": "mkit_status", "arguments": { "repo_path": repo_path } }),
    );
    assert!(!is_tool_error(&status), "{status}");
    assert!(
        repo.path().join(".mkit").is_dir(),
        "mkit_init actually created .mkit/ on disk"
    );
}

/// rmcp always serializes `isError` (`Some(false)` on success), unlike the
/// hand-rolled stdio server's serde default-omits-false shape — check the
/// value, not its presence.
fn is_tool_error(resp: &Value) -> bool {
    resp.pointer("/result/isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[test]
fn unknown_tool_is_a_protocol_error_over_http() {
    let repo = tempfile::tempdir().unwrap();
    let server = HttpMcp::spawn(repo.path());

    let resp = server.request(
        1,
        "tools/call",
        json!({ "name": "mkit_push", "arguments": { "repo_path": "." } }),
    );
    assert!(resp.get("error").is_some(), "{resp}");
}

/// Coverage for `mcp_v2.rs`'s fail-closed `--http` bearer-token gate
/// (`resolve_http_auth`/`BearerAuthHttp`) — mirrors `mkit serve --http`'s
/// own gate tests, adapted to the streamable-HTTP transport's plain
/// request/response shape instead of connect-rpc.
mod auth {
    use super::{HttpMcp, mkit_bin};
    use std::process::{Command, Stdio};

    #[test]
    fn refuses_to_bind_without_a_token_or_the_unsafe_flag() {
        let repo = tempfile::tempdir().unwrap();
        let (status, stderr) = HttpMcp::spawn_expect_refusal(repo.path(), &[]);
        assert!(!status.success(), "should refuse to bind: {stderr}");
        assert!(
            stderr.contains("refusing to bind without a bearer token"),
            "{stderr}"
        );
    }

    #[test]
    fn refuses_an_empty_token() {
        let repo = tempfile::tempdir().unwrap();
        let (status, stderr) =
            HttpMcp::spawn_expect_refusal(repo.path(), &["--http-token", ""]);
        assert!(!status.success(), "should refuse to bind: {stderr}");
        assert!(stderr.contains("MUST NOT be empty"), "{stderr}");
    }

    #[test]
    fn refuses_token_and_unsafe_flag_together() {
        let repo = tempfile::tempdir().unwrap();
        let (status, stderr) = HttpMcp::spawn_expect_refusal(
            repo.path(),
            &["--http-token", "s3cr3t", "--unsafe-allow-any-http-peer"],
        );
        assert!(!status.success(), "should refuse to bind: {stderr}");
        assert!(stderr.contains("mutually exclusive"), "{stderr}");
    }

    #[test]
    fn rejects_requests_with_no_or_wrong_bearer_token() {
        let repo = tempfile::tempdir().unwrap();
        let server = HttpMcp::spawn_with_args(repo.path(), &["--http-token", "right-token"], &[]);

        let no_auth = reqwest::blocking::Client::new()
            .post(&server.base_url)
            .header("content-type", "application/json")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
            .send()
            .expect("http request");
        assert_eq!(no_auth.status(), reqwest::StatusCode::UNAUTHORIZED);

        let wrong_auth = reqwest::blocking::Client::new()
            .post(&server.base_url)
            .header("content-type", "application/json")
            .header("authorization", "Bearer wrong-token")
            .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
            .send()
            .expect("http request");
        assert_eq!(wrong_auth.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn accepts_requests_with_the_right_bearer_token() {
        let repo = tempfile::tempdir().unwrap();
        let server = HttpMcp::spawn_with_args(
            repo.path(),
            &["--http-token", "right-token"],
            &[("authorization", "Bearer right-token")],
        );

        let resp = server.request(1, "tools/list", serde_json::json!({}));
        assert!(
            resp.pointer("/result/tools").is_some(),
            "authorized request should reach the tool catalog: {resp}"
        );
    }

    #[test]
    fn mkit_mcp_token_env_var_is_accepted_as_a_fallback() {
        let repo = tempfile::tempdir().unwrap();
        let mut child = Command::new(mkit_bin())
            .args([
                "mcp",
                "--repository",
                repo.path().to_str().unwrap(),
                "--http",
                "127.0.0.1:0",
            ])
            .env("MKIT_MCP_TOKEN", "env-token")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mkit mcp --http");
        let stderr = child.stderr.take().unwrap();
        use std::io::{BufRead, BufReader};
        let mut lines = BufReader::new(stderr).lines();
        let addr = loop {
            let line = lines
                .next()
                .expect("stderr closed before reporting an address")
                .unwrap();
            if let Some(addr) = line.strip_prefix("mkit mcp: listening on http://") {
                break addr.to_string();
            }
        };
        std::thread::spawn(move || for _ in lines {});
        let server = HttpMcp {
            child,
            base_url: format!("http://{addr}/"),
            headers: vec![("authorization".to_string(), "Bearer env-token".to_string())],
        };

        let resp = server.request(1, "tools/list", serde_json::json!({}));
        assert!(
            resp.pointer("/result/tools").is_some(),
            "MKIT_MCP_TOKEN should authorize the request: {resp}"
        );
    }
}
