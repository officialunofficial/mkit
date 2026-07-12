//! `--http <addr>` entry point — hosts `mkit.transport.v1.TransportService`
//! (SPEC-TRANSPORT-CONNECT) over axum/HTTP via `mkit-transport-connect`,
//! backed by the same `FileTransport` the SSH-frame server uses.
//!
//! This is issue #700: a self-hostable `mkit+https://` remote that needs
//! neither SSH access nor a cloud object store. Without the
//! `http-transport` cargo feature this prints a helpful error and exits
//! with `UNAVAILABLE`, mirroring `--listen-enc`'s feature gate.

use std::path::PathBuf;

use crate::exit;

#[cfg(not(feature = "http-transport"))]
pub(super) fn run_listen_http(
    _addr: &str,
    _repo_root: PathBuf,
    _token: Option<&str>,
    _unsafe_allow_any: bool,
) -> u8 {
    eprintln!(
        "mkit serve --http requires the `http-transport` cargo feature; \
         rebuild with `--features http-transport` to enable it."
    );
    exit::UNAVAILABLE
}

#[cfg(feature = "http-transport")]
#[allow(
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value
)]
pub(super) fn run_listen_http(
    addr: &str,
    repo_root: PathBuf,
    token: Option<&str>,
    unsafe_allow_any: bool,
) -> u8 {
    use std::sync::Arc;

    use connectrpc::{ConnectError, Interceptor, Next, NextStream, PayloadStream};
    use mkit_transport_file::FileTransport;

    // --- Fail-closed gate, mirroring --listen-enc's peer-authorization
    // gate: refuse to bind unless a bearer token is configured (flag or
    // MKIT_API_TOKEN env var — the same variable
    // `mkit-transport-http`'s client already sends, SPEC-TRANSPORT
    // §5.2) or the operator explicitly opts into the unsafe escape.
    let env_token = std::env::var(mkit_transport_http::TOKEN_ENV).ok();
    let token = token.map(str::to_owned).or(env_token);
    let auth = match (token, unsafe_allow_any) {
        (Some(_), true) => {
            eprintln!(
                "mkit serve --http: --http-token (or MKIT_API_TOKEN) and \
                 --unsafe-allow-any-http-peer are mutually exclusive"
            );
            return exit::USAGE;
        }
        (Some(t), false) if t.is_empty() => {
            eprintln!("mkit serve --http: bearer token MUST NOT be empty; refusing to bind");
            return exit::CONFIG_ERROR;
        }
        (Some(t), false) => Some(t),
        (None, true) => {
            eprintln!(
                "============================================================\n\
                 WARNING: mkit serve --http --unsafe-allow-any-http-peer\n\
                 This HTTP listener accepts ANY caller with NO authentication.\n\
                 Every RPC — including ref writes and pack uploads — is open.\n\
                 Use this only for local development, NEVER in production.\n\
                 ============================================================"
            );
            None
        }
        (None, false) => {
            eprintln!(
                "mkit serve --http: refusing to bind without a bearer token.\n\
                 Pass --http-token <TOKEN> (or set MKIT_API_TOKEN) to require it on \
                 every RPC, or --unsafe-allow-any-http-peer to accept any caller \
                 (development only)."
            );
            return exit::CONFIG_ERROR;
        }
    };

    let socket_addr: std::net::SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("mkit serve --http: invalid address {addr:?}: {e}");
            return exit::USAGE;
        }
    };

    /// Constant-time `Authorization: Bearer <token>` check, applied to
    /// every unary AND streaming RPC (UploadPack/DownloadPack included) —
    /// `connectrpc::Interceptor` covers both surfaces in one impl. See
    /// `interceptor.rs`'s module docs: this runs once per call, before any
    /// message (streaming or otherwise) reaches the handler.
    struct BearerAuth {
        expected: String,
    }

    impl BearerAuth {
        fn check(&self, headers: &http::HeaderMap) -> Result<(), ConnectError> {
            let got = headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            // Constant-time comparison: an HTTP-timing side channel on a
            // bearer-token check is a real attack (the whole point of the
            // check is to gate write access), so this is not a place to
            // reach for `==`.
            let expected = format!("Bearer {}", self.expected);
            let matches = got.len() == expected.len()
                && subtle::ConstantTimeEq::ct_eq(got.as_bytes(), expected.as_bytes()).into();
            if matches {
                Ok(())
            } else {
                Err(ConnectError::unauthenticated(
                    "missing or invalid Authorization: Bearer <token>",
                ))
            }
        }
    }

    #[connectrpc::async_trait]
    impl Interceptor for BearerAuth {
        async fn intercept_unary(
            &self,
            req: connectrpc::interceptor::UnaryRequest,
            next: Next<'_>,
        ) -> Result<connectrpc::interceptor::UnaryResponse, ConnectError> {
            self.check(req.ctx.headers())?;
            next.run(req).await
        }

        async fn intercept_streaming(
            &self,
            req: connectrpc::interceptor::StreamRequest,
            inbound: PayloadStream,
            next: NextStream<'_>,
        ) -> Result<connectrpc::interceptor::StreamResponse, ConnectError> {
            self.check(req.ctx.headers())?;
            next.run(req, inbound).await
        }
    }

    let transport = Arc::new(FileTransport::new(&repo_root));
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mkit serve --http: failed to start async runtime: {e}");
            return exit::UNAVAILABLE;
        }
    };

    let result = runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(socket_addr).await?;
        let connect_router = mkit_transport_connect::router(transport);
        let app = match auth {
            Some(expected) => {
                let service = connectrpc::ConnectRpcService::new(connect_router)
                    .with_interceptor(BearerAuth { expected });
                axum::Router::new().fallback_service(service)
            }
            None => connect_router.into_axum_router(),
        };
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                // Poll the same cooperative shutdown flag SIGINT/SIGTERM
                // set for the rest of the CLI (`crate::signal`), so
                // Ctrl-C drains in-flight requests instead of dropping
                // connections mid-response.
                loop {
                    if crate::signal::is_shutdown() {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            })
            .await
    });

    match result {
        Ok(()) => exit::OK,
        Err(e) => {
            eprintln!("mkit serve --http: {e}");
            exit::UNAVAILABLE
        }
    }
}
