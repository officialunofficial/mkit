//! `mkit mcp`'s modern serving path — MCP 2026-07-28, via the official
//! `rmcp` Rust SDK. Compiled in only under `--features mcp-v2` (see
//! `mcp.rs`'s module doc for why the hand-rolled implementation stays the
//! default). This module is protocol plumbing only: the tool catalog,
//! argv-building, path confinement, and injection defenses all live in
//! `mcp.rs` and are reused unchanged via its `pub(crate)` surface
//! (`TOOLS`, `call_tool`, `INSTRUCTIONS`) — a compiled-in security boundary
//! (path confinement, no-force-flag guarantee) can never drift between the
//! two protocol layers because there is only one copy of it.
//!
//! MCP 2026-07-28 dropped the `initialize` handshake and session concept
//! entirely (see the spec's `basic` overview: "an open connection ... is
//! not a conversation or session"), so unlike `mcp.rs`'s hand-rolled loop
//! there is no `initialized` gate to track here — `rmcp` owns protocol
//! framing and version negotiation, including serving 2025-era clients
//! that still send the legacy handshake.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorData, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::stdio;
use rmcp::{RoleServer, ServerHandler, ServiceExt};
use serde_json::Value;

use super::mcp::{INSTRUCTIONS, TOOLS, ToolSpec, call_tool};
use crate::exit;

struct MkitServer {
    allowed: Option<PathBuf>,
}

impl ServerHandler for MkitServer {
    fn get_info(&self) -> ServerInfo {
        // `Implementation` is `#[non_exhaustive]` in rmcp: build via
        // `Default` and mutate fields rather than a struct literal.
        let mut server_info = Implementation::default();
        server_info.name = "mkit-repo".to_string();
        server_info.version = crate::cli::CLI_VERSION.to_string();

        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(server_info)
            .with_instructions(INSTRUCTIONS)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let args = Value::Object(request.arguments.unwrap_or_default());
        match call_tool(&request.name, &args, self.allowed.as_deref()) {
            Ok(outcome) => {
                let content = vec![ContentBlock::text(outcome.text)];
                let result = if outcome.is_error {
                    CallToolResult::error(content)
                } else {
                    CallToolResult::success(content)
                };
                Ok(result.into())
            }
            // Unknown tool / malformed request shape: unroutable, so this is
            // a protocol-level error rather than a tool-level one — see
            // `ServerHandler::call_tool`'s doc on the two failure modes.
            Err(message) => Err(ErrorData::invalid_params(message, None)),
        }
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: TOOLS.iter().map(tool_from_spec).collect(),
            ..Default::default()
        })
    }
}

/// Map one `mcp.rs::ToolSpec` onto an `rmcp::model::Tool` — same name,
/// description, JSON-Schema input shape, and read-only/destructive/
/// idempotent hints the hand-rolled server advertises, so a client sees the
/// same tool surface regardless of which protocol layer served it.
fn tool_from_spec(spec: &ToolSpec) -> Tool {
    let input_schema = (spec.schema)().as_object().cloned().unwrap_or_default();
    let (read_only, destructive, idempotent) = spec.hints;
    let mut tool = Tool::new(spec.name, spec.description, Arc::new(input_schema));
    // `ToolAnnotations` is also `#[non_exhaustive]`: same fix as `get_info`.
    let mut annotations = ToolAnnotations::default();
    annotations.read_only_hint = Some(read_only);
    annotations.destructive_hint = Some(destructive);
    annotations.idempotent_hint = Some(idempotent);
    annotations.open_world_hint = Some(false);
    tool.annotations = Some(annotations);
    tool
}

/// Entry point for `mkit mcp` under `--features mcp-v2`: serve over stdio
/// using `rmcp`. `mcp.rs::dispatch` is the only caller.
pub(crate) fn serve(allowed: Option<&Path>) -> u8 {
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mkit mcp: failed to start async runtime: {e}");
            return exit::UNAVAILABLE;
        }
    };

    let server = MkitServer {
        allowed: allowed.map(Path::to_path_buf),
    };
    // `serve()` and `waiting()` fail with different error types
    // (`ServerInitializeError` vs. the join error `waiting()` surfaces), so
    // `?` can't unify them in one block — map each to a message explicitly.
    let result: Result<(), String> = runtime.block_on(async move {
        let running = server
            .serve(stdio())
            .await
            .map_err(|e| format!("failed to start: {e}"))?;
        running.waiting().await.map_err(|e| format!("server error: {e}"))?;
        Ok(())
    });

    match result {
        Ok(()) => exit::OK,
        Err(e) => {
            eprintln!("mkit mcp: {e}");
            1
        }
    }
}
