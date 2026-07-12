//! [`ConnectTransport`] — the native `mkit.transport.v1.TransportService`
//! ConnectRPC client, implementing [`Transport`] for the `mkit+https://`
//! (and loopback-only `mkit+http://`) remote scheme.

use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use connectrpc::client::{ClientConfig, HttpClient};
use http::Uri;
use http::header::AUTHORIZATION;
use mkit_core::hash::Hash;
use mkit_core::protocol::async_shim::Executor as _;
use mkit_core::protocol::{
    AdvanceOutcome as CoreAdvanceOutcome, PACK_BODY_LIMIT, PACK_BODY_LIMIT_USIZE, PackKey,
    RefWriteCondition, Transport, TransportError, TransportResult,
};
use mkit_core::refs::Ref;
use url::{Host, Url};

use crate::error::{ErrorContext, map_connect_error};
use crate::executor::TokioExecutor;
use crate::proto::mkit::transport::v1::__buffa::oneof::download_pack_response::Body as DownloadBody;
use crate::proto::mkit::transport::v1::{
    AdvanceOutcome as ProtoAdvanceOutcome, AdvanceRefsRequest, DownloadPackRequest,
    ListRefsRequest, PackChunk, PackExistsRequest, ReadRefRequest, RefExpectation,
    TransportServiceClient, UpdateRefRequest, UploadPackHeader, UploadPackRequest,
};

/// Environment variable consulted at [`ConnectTransport::connect`] time for
/// an optional Bearer token — same name `mkit-transport-http` used
/// (`MKIT_API_TOKEN`), so switching a deployment from the retired JSON
/// dialect to this Connect client needs no operator-facing config change.
pub const TOKEN_ENV: &str = "MKIT_API_TOKEN";

/// Default per-call timeout. Matches `mkit-transport-http::DEFAULT_TIMEOUT`
/// — generous enough for a large pack transfer over a slow link, bounded
/// enough that a hung peer can't wedge a caller indefinitely.
#[allow(clippy::duration_suboptimal_units)]
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// Per-`UploadPack`-chunk data cap. Mirrors
/// `mkit_rpc::helpers::CHUNK_DATA_MAX` (the SSH/enc wire's per-frame pack
/// segment size) — not a shared constant because this crate deliberately
/// does not depend on `mkit-rpc` (a proto crate tied to the SSH wire), but
/// the value is kept in lockstep so pack chunking behaves identically
/// across every mkit transport.
const CHUNK_SIZE: usize = 800 * 1024;

/// Native ConnectRPC client for `mkit.transport.v1.TransportService` — the
/// implementation behind `mkit+https://` (SPEC-TRANSPORT-CONNECT).
///
/// Unlike `mkit-transport-http`, this transport does **not** implement its
/// own retry/backoff ladder: SPEC-TRANSPORT-CONNECT §7.3 defers that to a
/// shared Connect interceptor (mkit#703) wrapping the generated client, so
/// every call here is a single attempt. Callers that need SPEC-TRANSPORT
/// §7 retry semantics today get them from `mkit_core::protocol::
/// is_retryable` / `BackoffIterator` applied to this transport's returned
/// [`TransportError`], exactly as any other transport-agnostic caller
/// would.
pub struct ConnectTransport {
    client: TransportServiceClient<HttpClient>,
    executor: TokioExecutor,
    /// See [`Self::with_atomic_advance`].
    atomic_advance: bool,
}

// Manual Debug: `HttpClient` doesn't implement it, and a bearer token (if
// any) rides inside `client`'s `ClientConfig` default headers — never
// surface it via `{:?}`.
impl std::fmt::Debug for ConnectTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectTransport")
            .field("atomic_advance", &self.atomic_advance)
            .finish_non_exhaustive()
    }
}

/// Validate that `url` uses either `https://` (always allowed) or plain
/// `http://` pointing at a loopback host (`127.0.0.1`, `::1`, or
/// `localhost`). Mirrors `mkit-transport-http::validate_http_scheme` byte
/// for byte — both transports enforce the same "plaintext only to
/// loopback" policy (SPEC-TRANSPORT §3).
fn validate_http_scheme(url: &Url) -> TransportResult<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let ok = match url.host() {
                Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
                Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
                Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
                None => false,
            };
            if ok {
                Ok(())
            } else {
                Err(TransportError::InsecureScheme)
            }
        }
        _ => Err(TransportError::InvalidResponse),
    }
}

/// Install a process-wide default `rustls` `CryptoProvider` if one isn't
/// already installed.
///
/// rustls 0.23 requires exactly one crypto backend to be the installed
/// default before `ClientConfig::builder()` can run; it does NOT
/// auto-select one when a consuming binary's dependency graph links more
/// than one backend crate (which `mkit-cli`'s does: `ring` arrives via
/// this crate's own explicit dependency below, `aws-lc-rs` via `rustls`'s
/// own default feature pulled in transitively by `connectrpc`/other
/// dependents) — calling `ClientConfig::builder()` in that situation
/// panics with "Could not automatically determine the process-level
/// CryptoProvider" rather than picking one silently. We therefore install
/// one explicitly. `install_default` returns `Err` if a provider (ours or
/// another crate's, e.g. an AWS SDK client's) is already installed
/// process-wide; either outcome is fine here — we only need SOME provider
/// installed before building a `ClientConfig`, not specifically ours.
fn ensure_crypto_provider() {
    let _ = connectrpc::rustls::crypto::ring::default_provider().install_default();
}

/// Build a default `rustls::ClientConfig` trusting the Mozilla root
/// program via `webpki-roots` — pure-Rust, no OS trust-store dependency
/// (portable across CI images and minimal containers, matching this
/// crate's zero-system-dependency posture for the vendored codegen path).
fn default_tls_config() -> Arc<connectrpc::rustls::ClientConfig> {
    ensure_crypto_provider();
    let mut roots = connectrpc::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        connectrpc::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

impl ConnectTransport {
    /// Parse `mkit+https://host/project` (or loopback-only
    /// `mkit+http://…`), strip the `mkit+` prefix, and build the transport.
    ///
    /// The token is sourced from `MKIT_API_TOKEN` at connect time (same
    /// variable `mkit-transport-http` reads). A missing variable is fine —
    /// public read endpoints remain accessible.
    ///
    /// Per SPEC-TRANSPORT-CONNECT §2, every RPC resolves to the FIXED path
    /// `/mkit.transport.v1.TransportService/<Method>` — the proto carries
    /// no project field, unlike the retired JSON dialect's
    /// `/<project>/packs` convention. Any path component on the URL (e.g.
    /// `mkit+https://host/project`) is therefore discarded when building
    /// the Connect base URI: only the scheme, host, and port are used. A
    /// deployment that needs to distinguish projects does so by host
    /// (subdomain) or a separate deployment entirely, not a URL path — the
    /// path segment is accepted (for URL-shape consistency with the
    /// `mkit+file://`/`mkit+s3://` schemes, which DO use it) but currently
    /// has no effect on the wire.
    ///
    /// # Errors
    ///
    /// - [`TransportError::InvalidResponse`] — URL has no `mkit+` prefix,
    ///   is otherwise unparseable, or uses a scheme other than `http`/`https`.
    /// - [`TransportError::InsecureScheme`] — plain `http://` to a
    ///   non-loopback host.
    /// - [`TransportError::ConnectionFailed`] — the local tokio runtime
    ///   could not be constructed (resource exhaustion).
    pub fn connect(url: &str) -> TransportResult<Self> {
        let stripped = url
            .strip_prefix("mkit+")
            .ok_or(TransportError::InvalidResponse)?;
        let parsed = Url::parse(stripped).map_err(|_| TransportError::InvalidResponse)?;
        validate_http_scheme(&parsed)?;

        // Authority only — see the doc comment above for why the path is
        // deliberately dropped.
        let authority = format!(
            "{}://{}",
            parsed.scheme(),
            parsed
                .host_str()
                .map(|h| match parsed.port() {
                    Some(p) => format!("{h}:{p}"),
                    None => h.to_owned(),
                })
                .ok_or(TransportError::InvalidResponse)?
        );
        let uri: Uri = authority
            .parse()
            .map_err(|_| TransportError::InvalidResponse)?;

        let token = env::var(TOKEN_ENV).ok().filter(|s| !s.is_empty());
        let transport = if parsed.scheme() == "https" {
            HttpClient::with_tls(default_tls_config())
        } else {
            HttpClient::plaintext()
        };

        let mut config = ClientConfig::new(uri).with_default_timeout(DEFAULT_TIMEOUT);
        if let Some(token) = &token
            && let Ok(value) = http::HeaderValue::from_str(&format!("Bearer {token}"))
        {
            config = config.with_default_header(AUTHORIZATION, value);
        }

        let executor = TokioExecutor::new().map_err(|_| TransportError::ConnectionFailed)?;
        Ok(Self {
            client: TransportServiceClient::new(transport, config),
            executor,
            atomic_advance: false,
        })
    }

    /// Test-only constructor pointing at a plaintext base URI with no
    /// `mkit+` prefix stripping (mirrors
    /// `HttpTransport::new_for_test`) — used by the in-process
    /// integration test to target a locally bound server.
    #[doc(hidden)]
    #[must_use]
    pub fn connect_for_test(base_uri: Uri) -> Self {
        let config = ClientConfig::new(base_uri).with_default_timeout(Duration::from_secs(10));
        Self {
            client: TransportServiceClient::new(HttpClient::plaintext(), config),
            executor: TokioExecutor::new().expect("tokio runtime for test transport"),
            atomic_advance: false,
        }
    }

    /// Declare that the remote deployment's `AdvanceRefs` commits the
    /// head-and-packmap write as one indivisible transaction, so
    /// [`Transport::supports_atomic_advance`] should report `true`.
    ///
    /// Per SPEC-TRANSPORT-CONNECT §4, the wire itself carries no
    /// "is this deployment transactional?" negotiation — either the
    /// deployment documents its guarantee out-of-band, or (as here) the
    /// caller records it via configuration. Defaults to `false`: an
    /// unconfigured transport never claims atomicity it cannot verify,
    /// which per `Transport::supports_atomic_advance`'s doc comment is the
    /// safe default (callers must never request a packmap reset against a
    /// transport that returns `false`).
    #[must_use]
    pub fn with_atomic_advance(mut self, atomic: bool) -> Self {
        self.atomic_advance = atomic;
        self
    }
}

fn bytes_to_hash(bytes: &[u8]) -> TransportResult<Hash> {
    <[u8; 32]>::try_from(bytes).map_err(|_| TransportError::InvalidResponse)
}

/// Encode a [`RefWriteCondition`] into the wire `(expectation, expected_id)`
/// pair. Shared by every CAS-carrying request this client builds.
fn condition_to_wire(c: RefWriteCondition) -> (RefExpectation, Option<Vec<u8>>) {
    match c {
        RefWriteCondition::Any => (RefExpectation::Any, None),
        RefWriteCondition::Missing => (RefExpectation::Missing, None),
        RefWriteCondition::Match(h) => (RefExpectation::Match, Some(h.to_vec())),
    }
}

/// Build the `UploadPackRequest` stream for one pack: one `header` message
/// followed by `ceil(len / CHUNK_SIZE)` `chunk` messages (or exactly one
/// empty `last = true` chunk for a zero-byte pack), matching
/// SPEC-TRANSPORT-CONNECT §6.1.
fn build_upload_requests(bytes: &[u8], key: &PackKey) -> Vec<UploadPackRequest> {
    let pack_id = key.as_bytes().to_vec();
    let mut requests = Vec::with_capacity(2 + bytes.len() / CHUNK_SIZE);
    requests.push(UploadPackRequest {
        body: Some(
            UploadPackHeader {
                pack_id: Some(pack_id.clone()),
                total_bytes: Some(bytes.len() as u64),
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    });

    if bytes.is_empty() {
        requests.push(UploadPackRequest {
            body: Some(
                PackChunk {
                    pack_id: Some(pack_id),
                    offset: Some(0),
                    data: Some(Vec::new()),
                    last: Some(true),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        });
        return requests;
    }

    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = (offset + CHUNK_SIZE).min(bytes.len());
        let last = end == bytes.len();
        requests.push(UploadPackRequest {
            body: Some(
                PackChunk {
                    pack_id: Some(pack_id.clone()),
                    #[allow(clippy::cast_possible_truncation)]
                    offset: Some(offset as u64),
                    data: Some(bytes[offset..end].to_vec()),
                    last: Some(last),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        });
        offset = end;
    }
    requests
}

impl Transport for ConnectTransport {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        if bytes.len() as u64 > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(bytes.len()));
        }
        let requests = build_upload_requests(bytes, key);
        self.executor.block_on(async {
            self.client
                .upload_pack(requests)
                .await
                .map(|_| ())
                .map_err(|e| map_connect_error(e, ErrorContext::Upload))
        })
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        // `block_on_local`, not `block_on`: see its doc comment — the
        // server-streaming `.message()` read here hits a rustc HRTB/GAT
        // limitation against the `Send`-bound trait method, not an actual
        // thread-safety issue.
        self.executor.block_on_local(async {
            let mut stream = self
                .client
                .download_pack(DownloadPackRequest {
                    pack_id: Some(key.as_bytes().to_vec()),
                    ..Default::default()
                })
                .await
                .map_err(|e| map_connect_error(e, ErrorContext::Ref))?;

            let first = stream
                .message()
                .await
                .map_err(|e| map_connect_error(e, ErrorContext::Ref))?
                .ok_or(TransportError::InvalidResponse)?;
            let total_bytes = match first.to_owned_message().body {
                Some(DownloadBody::Header(h)) => h.total_bytes.unwrap_or(0),
                _ => return Err(TransportError::InvalidResponse),
            };
            if total_bytes > PACK_BODY_LIMIT {
                return Err(TransportError::PayloadTooLarge(
                    usize::try_from(total_bytes).unwrap_or(usize::MAX),
                ));
            }

            let mut buf: Vec<u8> =
                Vec::with_capacity(usize::try_from(total_bytes).unwrap_or(PACK_BODY_LIMIT_USIZE));
            loop {
                let next = stream
                    .message()
                    .await
                    .map_err(|e| map_connect_error(e, ErrorContext::Ref))?
                    .ok_or(TransportError::InvalidResponse)?;
                match next.to_owned_message().body {
                    Some(DownloadBody::Chunk(c)) => {
                        let offset = c.offset.unwrap_or(0);
                        if offset != buf.len() as u64 {
                            return Err(TransportError::InvalidResponse);
                        }
                        let data = c.data.unwrap_or_default();
                        if buf.len().saturating_add(data.len()) > PACK_BODY_LIMIT_USIZE {
                            return Err(TransportError::PayloadTooLarge(buf.len() + data.len()));
                        }
                        buf.extend_from_slice(&data);
                        if c.last.unwrap_or(false) {
                            break;
                        }
                    }
                    _ => return Err(TransportError::InvalidResponse),
                }
            }
            if buf.len() as u64 != total_bytes {
                return Err(TransportError::InvalidResponse);
            }
            Ok(buf)
        })
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.executor.block_on(async {
            let resp = self
                .client
                .pack_exists(PackExistsRequest {
                    pack_id: Some(key.as_bytes().to_vec()),
                    ..Default::default()
                })
                .await
                .map_err(|e| map_connect_error(e, ErrorContext::Ref))?
                .into_owned();
            Ok(resp.exists.unwrap_or(false))
        })
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        let (expectation, expected_id) = condition_to_wire(condition);
        self.executor.block_on(async {
            self.client
                .update_ref(UpdateRefRequest {
                    name: Some(name.to_owned()),
                    expectation: Some(expectation.into()),
                    expected_id,
                    new_id: Some(hash.to_vec()),
                    ..Default::default()
                })
                .await
                .map(|_| ())
                .map_err(|e| map_connect_error(e, ErrorContext::Ref))
        })
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.executor.block_on(async {
            let resp = self
                .client
                .read_ref(ReadRefRequest {
                    name: Some(name.to_owned()),
                    ..Default::default()
                })
                .await
                .map_err(|e| map_connect_error(e, ErrorContext::Ref))?
                .into_owned();
            if resp.exists.unwrap_or(false) {
                let id = resp.object_id.ok_or(TransportError::InvalidResponse)?;
                Ok(Some(bytes_to_hash(&id)?))
            } else {
                Ok(None)
            }
        })
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.executor.block_on(async {
            let resp = self
                .client
                .list_refs(ListRefsRequest {
                    prefix: Some(prefix.to_owned()),
                    ..Default::default()
                })
                .await
                .map_err(|e| map_connect_error(e, ErrorContext::Ref))?
                .into_owned();
            resp.refs
                .into_iter()
                .map(|e| {
                    let name = e.name.ok_or(TransportError::InvalidResponse)?;
                    let object_id = e.object_id.ok_or(TransportError::InvalidResponse)?;
                    Ok(Ref {
                        name,
                        hash: Some(bytes_to_hash(&object_id)?),
                    })
                })
                .collect()
        })
    }

    fn advance_refs(
        &self,
        head_ref: &str,
        head_condition: RefWriteCondition,
        head_value: &Hash,
        packmap_ref: &str,
        packmap_condition: RefWriteCondition,
        packmap_value: &Hash,
    ) -> TransportResult<CoreAdvanceOutcome> {
        let (head_expectation, head_expected_id) = condition_to_wire(head_condition);
        let (packmap_expectation, packmap_expected_id) = condition_to_wire(packmap_condition);
        self.executor.block_on(async {
            let resp = self
                .client
                .advance_refs(AdvanceRefsRequest {
                    head_ref: Some(head_ref.to_owned()),
                    head_expectation: Some(head_expectation.into()),
                    head_expected_id,
                    head_new_id: Some(head_value.to_vec()),
                    packmap_ref: Some(packmap_ref.to_owned()),
                    packmap_expectation: Some(packmap_expectation.into()),
                    packmap_expected_id,
                    packmap_new_id: Some(packmap_value.to_vec()),
                    ..Default::default()
                })
                .await
                .map_err(|e| map_connect_error(e, ErrorContext::Ref))?
                .into_owned();
            match resp.outcome.and_then(|o| o.as_known()) {
                Some(ProtoAdvanceOutcome::Committed) => Ok(CoreAdvanceOutcome::Committed),
                Some(ProtoAdvanceOutcome::HeadConflict) => Ok(CoreAdvanceOutcome::HeadConflict),
                Some(ProtoAdvanceOutcome::PackmapConflict) => {
                    Ok(CoreAdvanceOutcome::PackmapConflict)
                }
                _ => Err(TransportError::InvalidResponse),
            }
        })
    }

    fn supports_atomic_advance(&self) -> bool {
        self.atomic_advance
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- connect() + URL parsing --------------------------------------

    #[test]
    fn connect_rejects_missing_mkit_prefix() {
        let err = ConnectTransport::connect("https://example.com/proj").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    #[test]
    fn connect_rejects_unknown_scheme() {
        let err = ConnectTransport::connect("mkit+ftp://example.com/proj").unwrap_err();
        assert!(matches!(err, TransportError::InvalidResponse));
    }

    #[test]
    fn connect_rejects_plain_http_to_non_loopback_host() {
        let err = ConnectTransport::connect("mkit+http://example.com/proj").unwrap_err();
        assert!(matches!(err, TransportError::InsecureScheme));
    }

    #[test]
    fn connect_accepts_plain_http_for_loopback() {
        let t = ConnectTransport::connect("mkit+http://127.0.0.1:9/proj").unwrap();
        assert!(!t.atomic_advance);
    }

    #[test]
    fn connect_accepts_https_and_does_not_panic_building_tls_config() {
        // Regression test: rustls 0.23 panics building a `ClientConfig` if
        // no crypto provider is installed and more than one backend
        // feature is linked in the process (mkit#701) — this exercises
        // exactly that path. Construction does not make a network call.
        let t = ConnectTransport::connect("mkit+https://example.invalid/proj").unwrap();
        assert!(!t.atomic_advance);
    }

    #[test]
    fn connect_strips_url_path_from_the_connect_base_uri() {
        // SPEC-TRANSPORT-CONNECT §2: every RPC resolves to the FIXED path
        // `/mkit.transport.v1.TransportService/<Method>` — a `/project`
        // path segment on the `mkit+https://` URL must NOT become a
        // prefix on the Connect base URI (mkit#701 regression: an earlier
        // version of this code folded the path in, breaking every call
        // against a server mounted at the standard root path).
        let t =
            ConnectTransport::connect("mkit+https://example.invalid/some/project/path").unwrap();
        assert_eq!(
            t.client.config().base_uri().to_string(),
            "https://example.invalid/"
        );
    }

    #[test]
    fn with_atomic_advance_sets_the_flag() {
        let t = ConnectTransport::connect("mkit+http://127.0.0.1:9/proj")
            .unwrap()
            .with_atomic_advance(true);
        assert!(t.supports_atomic_advance());
    }

    // -- condition_to_wire() --------------------------------------------

    #[test]
    fn condition_to_wire_any_has_no_expected_id() {
        let (exp, id) = condition_to_wire(RefWriteCondition::Any);
        assert_eq!(exp, RefExpectation::Any);
        assert_eq!(id, None);
    }

    #[test]
    fn condition_to_wire_missing_has_no_expected_id() {
        let (exp, id) = condition_to_wire(RefWriteCondition::Missing);
        assert_eq!(exp, RefExpectation::Missing);
        assert_eq!(id, None);
    }

    #[test]
    fn condition_to_wire_match_carries_the_hash() {
        let h = [0x42u8; 32];
        let (exp, id) = condition_to_wire(RefWriteCondition::Match(h));
        assert_eq!(exp, RefExpectation::Match);
        assert_eq!(id, Some(h.to_vec()));
    }

    // -- build_upload_requests() -----------------------------------------

    #[test]
    fn build_upload_requests_empty_pack_is_header_plus_one_empty_last_chunk() {
        let key = PackKey::new([0x11u8; 32]);
        let reqs = build_upload_requests(b"", &key);
        assert_eq!(reqs.len(), 2, "header + one empty last=true chunk");
    }

    #[test]
    fn build_upload_requests_chunks_at_chunk_size_boundary() {
        let key = PackKey::new([0x22u8; 32]);
        let data = vec![0u8; CHUNK_SIZE * 2 + 1];
        let reqs = build_upload_requests(&data, &key);
        // 1 header + 3 chunks (CHUNK_SIZE, CHUNK_SIZE, 1 byte).
        assert_eq!(reqs.len(), 4);
    }
}
