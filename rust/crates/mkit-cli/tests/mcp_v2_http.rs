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
}

impl Drop for HttpMcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl HttpMcp {
    /// Spawn `mkit mcp --repository <repo> --http 127.0.0.1:0` and block
    /// until its "listening on http://ADDR" stderr line reveals the
    /// OS-assigned port (see `mcp_v2.rs::serve_http`'s `local_addr()` doc
    /// comment — this test is exactly why that logs the resolved address
    /// rather than the requested one).
    fn spawn(repo: &std::path::Path) -> Self {
        let mut child = Command::new(mkit_bin())
            .args(["mcp", "--repository", repo.to_str().unwrap(), "--http", "127.0.0.1:0"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mkit mcp --http");
        let stderr = child.stderr.take().unwrap();
        let mut lines = BufReader::new(stderr).lines();
        let deadline = Instant::now() + Duration::from_secs(10);
        let addr = loop {
            assert!(Instant::now() < deadline, "server did not report a listening address in time");
            let line = lines.next().expect("stderr closed before reporting an address").unwrap();
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
        }
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
        params["_meta"]["io.modelcontextprotocol/clientInfo"] = json!({ "name": "mkit-mcp-http-tests", "version": "0" });
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
            serde_json::from_str(data_line.trim()).unwrap_or_else(|e| panic!("SSE data is not JSON: {e}: {data_line}"))
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
        assert_eq!(parsed.get("id").and_then(Value::as_i64), Some(id), "id mismatch: {parsed}");
        parsed
    }
}

#[test]
fn tools_list_over_http_matches_the_stdio_catalog() {
    let repo = tempfile::tempdir().unwrap();
    let server = HttpMcp::spawn(repo.path());

    let resp = server.request(1, "tools/list", json!({}));
    let tools = resp.pointer("/result/tools").and_then(Value::as_array).unwrap_or_else(|| panic!("{resp}"));
    assert_eq!(tools.len(), 18, "tool count is part of the public surface");
    assert!(tools.iter().any(|t| t.get("name").and_then(Value::as_str) == Some("mkit_status")));
}

#[test]
fn tool_call_round_trip_over_http_operates_the_real_repo() {
    let repo = tempfile::tempdir().unwrap();
    let server = HttpMcp::spawn(repo.path());
    let repo_path = repo.path().to_str().unwrap();

    let init = server.request(1, "tools/call", json!({ "name": "mkit_init", "arguments": { "repo_path": repo_path } }));
    assert!(!is_tool_error(&init), "{init}");

    let keygen = server.request(
        2,
        "tools/call",
        json!({ "name": "mkit_keygen", "arguments": { "repo_path": repo_path } }),
    );
    assert!(!is_tool_error(&keygen), "{keygen}");

    let status = server.request(3, "tools/call", json!({ "name": "mkit_status", "arguments": { "repo_path": repo_path } }));
    assert!(!is_tool_error(&status), "{status}");
    assert!(repo.path().join(".mkit").is_dir(), "mkit_init actually created .mkit/ on disk");
}

/// rmcp always serializes `isError` (`Some(false)` on success), unlike the
/// hand-rolled stdio server's serde default-omits-false shape — check the
/// value, not its presence.
fn is_tool_error(resp: &Value) -> bool {
    resp.pointer("/result/isError").and_then(Value::as_bool).unwrap_or(false)
}

#[test]
fn unknown_tool_is_a_protocol_error_over_http() {
    let repo = tempfile::tempdir().unwrap();
    let server = HttpMcp::spawn(repo.path());

    let resp = server.request(1, "tools/call", json!({ "name": "mkit_push", "arguments": { "repo_path": "." } }));
    assert!(resp.get("error").is_some(), "{resp}");
}
