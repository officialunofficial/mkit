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
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ErrorData,
    Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::transport::stdio;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{RoleServer, ServerHandler, ServiceExt};
use serde_json::Value;

use super::mcp::{INSTRUCTIONS, TOOLS, ToolSpec, call_tool};
use crate::exit;

#[derive(Clone)]
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

/// Environment-variable fallback for `--http-token`, checked when the flag
/// is omitted — mirrors `mkit serve --http`'s `--http-token`/
/// `mkit_transport_http::TOKEN_ENV` sourcing, but under a name of its own:
/// `mkit mcp --http` and `mkit serve --http` are different threat models
/// (a high-privilege, agent-facing tool catalog including `mkit_checkout`,
/// versus a Git transport) and MUST NOT share a secret — a token leaked to
/// one surface would otherwise also grant the other.
const MCP_TOKEN_ENV: &str = "MKIT_MCP_TOKEN";

/// Entry point for `mkit mcp` under `--features mcp-v2`: serve over stdio,
/// or over streamable HTTP when `--http <addr>` was given. `mcp.rs::dispatch`
/// is the only caller.
pub(crate) fn serve(
    allowed: Option<&Path>,
    http: Option<&str>,
    http_token: Option<&str>,
    unsafe_allow_any_http_peer: bool,
) -> u8 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mkit mcp: failed to start async runtime: {e}");
            return exit::UNAVAILABLE;
        }
    };
    let allowed = allowed.map(Path::to_path_buf);

    let result = match http {
        Some(addr) => {
            let auth = match resolve_http_auth(http_token, unsafe_allow_any_http_peer) {
                Ok(a) => a,
                Err(code) => return code,
            };
            runtime.block_on(serve_http(allowed, addr, auth))
        }
        None => runtime.block_on(serve_stdio(allowed)),
    };

    match result {
        Ok(()) => exit::OK,
        Err(e) => {
            eprintln!("mkit mcp: {e}");
            1
        }
    }
}

/// The bearer token `serve_http`'s `BearerAuthHttp` wrapper requires on
/// every request, or `None` under the explicit `--unsafe-allow-any-http-peer`
/// escape hatch (in which case every request is accepted unchecked).
type HttpAuth = Option<Arc<str>>;

/// Resolve `--http`'s fail-closed auth gate — FAIL-CLOSED, mirroring `mkit
/// serve --http`'s `--http-token`/`--unsafe-allow-any-http-peer` gate
/// (`commands/serve/http.rs`): refuses to report a usable auth
/// configuration unless either a non-empty token is available (flag or
/// [`MCP_TOKEN_ENV`]) or the operator explicitly opted into the unsafe
/// escape. Exit-code side effects (printing + returning early) live here
/// rather than in `serve_http` so the async listener never starts without
/// a resolved auth decision.
fn resolve_http_auth(token: Option<&str>, unsafe_allow_any: bool) -> Result<HttpAuth, u8> {
    let env_token = std::env::var(MCP_TOKEN_ENV).ok();
    let token = token.map(str::to_owned).or(env_token);
    match (token, unsafe_allow_any) {
        (Some(_), true) => {
            eprintln!(
                "mkit mcp --http: --http-token (or MKIT_MCP_TOKEN) and \
                 --unsafe-allow-any-http-peer are mutually exclusive"
            );
            Err(exit::USAGE)
        }
        (Some(t), false) if t.is_empty() => {
            eprintln!("mkit mcp --http: bearer token MUST NOT be empty; refusing to bind");
            Err(exit::CONFIG_ERROR)
        }
        (Some(t), false) => Ok(Some(Arc::from(t))),
        (None, true) => {
            eprintln!(
                "============================================================\n\
                 WARNING: mkit mcp --http --unsafe-allow-any-http-peer\n\
                 This HTTP listener accepts ANY caller with NO authentication.\n\
                 Every tool call — including mutating ones like mkit_checkout —\n\
                 is open. Use this only for local development, NEVER in production.\n\
                 ============================================================"
            );
            Ok(None)
        }
        (None, false) => {
            eprintln!(
                "mkit mcp --http: refusing to bind without a bearer token.\n\
                 Pass --http-token <TOKEN> (or set MKIT_MCP_TOKEN) to require it on \
                 every request, or --unsafe-allow-any-http-peer to accept any caller \
                 (development only)."
            );
            Err(exit::CONFIG_ERROR)
        }
    }
}

/// `serve()` and `waiting()` fail with different error types
/// (`ServerInitializeError` vs. the join error `waiting()` surfaces), so `?`
/// can't unify them in one block — map each to a message explicitly.
async fn serve_stdio(allowed: Option<PathBuf>) -> Result<(), String> {
    let server = MkitServer { allowed };
    let running = server
        .serve(stdio())
        .await
        .map_err(|e| format!("failed to start: {e}"))?;
    running
        .waiting()
        .await
        .map(|_quit_reason| ())
        .map_err(|e| format!("server error: {e}"))
}

/// Serve over rmcp's streamable-HTTP transport, hyper-direct (no axum — see
/// the `hyper`/`hyper-util` Cargo.toml entries' doc comment): `StreamableHttpService`
/// already implements `tower::Service`, so `TowerToHyperService` is all the
/// glue this needs (plus [`BearerAuthHttp`] wrapped around it — see that
/// type's doc). One fresh `MkitServer` per session (`LocalSessionManager`,
/// the documented default), same `allowed` scope for every session — this
/// process serves one repository, not a multi-tenant fleet. `Ctrl-C` is the
/// only shutdown path, matching rmcp's own documented example
/// (`examples/servers/src/counter_hyper_streamable_http.rs` upstream).
async fn serve_http(allowed: Option<PathBuf>, addr: &str, auth: HttpAuth) -> Result<(), String> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;

    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| format!("invalid --http address '{addr}': {e}"))?;
    let listener = tokio::net::TcpListener::bind(socket_addr)
        .await
        .map_err(|e| format!("failed to bind {socket_addr}: {e}"))?;
    // `local_addr()`, not the input `socket_addr`: `--http <host>:0` asks the
    // OS to pick a free port, and this is the only way to learn which one it
    // chose (tests rely on parsing this line for exactly that reason).
    let bound = listener
        .local_addr()
        .map_err(|e| format!("failed to read bound address: {e}"))?;
    eprintln!("mkit mcp: listening on http://{bound}");

    let service = TowerToHyperService::new(BearerAuthHttp {
        inner: StreamableHttpService::new(
            move || {
                Ok(MkitServer {
                    allowed: allowed.clone(),
                })
            },
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default(),
        ),
        expected: auth,
    });

    loop {
        let (stream, _peer) = tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            accepted = listener.accept() => accepted.map_err(|e| format!("accept failed: {e}"))?,
        };
        let io = TokioIo::new(stream);
        let service = service.clone();
        tokio::spawn(async move {
            let _ = Builder::new(TokioExecutor::default())
                .serve_connection(io, service)
                .await;
        });
    }
}

/// Constant-time `Authorization: Bearer <token>` gate wrapped around
/// `StreamableHttpService`, applied to every request before it reaches
/// `rmcp`'s handler — mirrors `mkit serve --http`'s `BearerAuth`
/// interceptor (`commands/serve/http.rs`), reimplemented against
/// `tower_service::Service` directly rather than `connectrpc::Interceptor`
/// since this transport is raw hyper/tower, not connect-rpc.
///
/// `expected: None` is the explicit `--unsafe-allow-any-http-peer` escape
/// hatch (every request accepted unchecked); `resolve_http_auth` is the
/// only place that constructs this type, and it never returns `Ok(None)`
/// without first printing the loud unsafe-mode warning.
#[derive(Clone)]
struct BearerAuthHttp<S> {
    inner: S,
    expected: HttpAuth,
}

impl<S> BearerAuthHttp<S> {
    /// `false` when `expected` is `Some` and `headers` lacks a matching
    /// `Authorization: Bearer <token>` value. Constant-time comparison:
    /// an HTTP-timing side channel on a bearer-token check is a real
    /// attack (the whole point of the check is to gate write access,
    /// including `mkit_checkout`), so this is not a place to reach for
    /// `==` — same reasoning as `serve/http.rs`'s `BearerAuth::check`.
    fn authorized(&self, headers: &http::HeaderMap) -> bool {
        let Some(expected) = &self.expected else {
            return true;
        };
        let got = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let want = format!("Bearer {expected}");
        got.len() == want.len()
            && subtle::ConstantTimeEq::ct_eq(got.as_bytes(), want.as_bytes()).into()
    }
}

/// `401 Unauthorized` in exactly [`StreamableHttpService`]'s response type
/// (`Response<BoxBody<Bytes, Infallible>>`, `rmcp`'s `BoxResponse` — not
/// nameable here since that alias is private to `rmcp`, but Rust type
/// aliases are structural, so writing the same type out works) — returned
/// instead of ever calling into `inner` for a request that fails
/// [`BearerAuthHttp::authorized`].
fn unauthorized_response()
-> http::Response<http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>> {
    use http_body_util::BodyExt;

    let body = http_body_util::Full::new(bytes::Bytes::from_static(
        b"missing or invalid Authorization: Bearer <token>",
    ))
    .map_err(|never: std::convert::Infallible| match never {});
    http::Response::builder()
        .status(http::StatusCode::UNAUTHORIZED)
        .body(http_body_util::combinators::BoxBody::new(body))
        .expect("static status + boxed body always build a valid response")
}

impl<S> tower_service::Service<http::Request<hyper::body::Incoming>> for BearerAuthHttp<S>
where
    S: tower_service::Service<
            http::Request<hyper::body::Incoming>,
            Response = http::Response<
                http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>,
            >,
            Error = std::convert::Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<hyper::body::Incoming>) -> Self::Future {
        if self.authorized(req.headers()) {
            let fut = self.inner.call(req);
            Box::pin(fut)
        } else {
            Box::pin(std::future::ready(Ok(unauthorized_response())))
        }
    }
}
