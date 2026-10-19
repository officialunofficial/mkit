//! Optional incremental HTTP exchange, with buffered defaults for existing hosts.

use buffa::Message as _;
use http::{HeaderMap, HeaderValue, Request, Response};
use mkit_core::hash::Hash;

use crate::connect::{Error, decode_response_diagnosed, end_error_diagnosed};
use crate::{FailureDiagnostic, FailureKind, FailureObserver, ResponseProfile};
pub(crate) struct NoDiagnostics;
impl FailureObserver for NoDiagnostics {}
use crate::proto::{DownloadPackResponse, download_pack_response::Body};

/// A request body pulled one owned chunk at a time. The caller may borrow its
/// input; channels must not retain this source after the exchange returns.
pub trait RequestStream {
    /// Produce the next chunk, or `None` at the end of the body.
    ///
    /// # Errors
    /// Returns a local encoding or input failure before sending that chunk.
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, Error>;
}

/// Receives decoded HTTP body chunks. A channel calls `start` once before any
/// `chunk`, then `finish` once on clean EOF. Failure aborts the exchange; partial
/// output must not be published or reused on a retry.
pub trait ResponseStream {
    /// Receive the HTTP status and headers after content decoding is selected.
    ///
    /// # Errors
    /// Returns a refusal when the response head cannot be accepted.
    fn start(&mut self, response: Response<()>) -> Result<(), Error>;
    /// Receive the next decoded body segment, without retaining the segment.
    ///
    /// # Errors
    /// Returns a framing, content or resource-bound failure.
    fn chunk(&mut self, bytes: &[u8]) -> Result<(), Error>;
    /// Receive a chunk with optional failure mapping. Existing sinks retain
    /// their normal chunk callback.
    ///
    /// # Errors
    /// Returns the chunk callback's error, optionally mapped by the observer.
    fn chunk_diagnosed(
        &mut self,
        bytes: &[u8],
        _observer: &dyn FailureObserver,
    ) -> Result<(), Error> {
        self.chunk(bytes)
    }
    /// Finish only after the HTTP body and its content decoder reach clean EOF.
    ///
    /// # Errors
    /// Returns an incomplete-stream or content-verification failure.
    fn finish(&mut self) -> Result<(), Error>;
    /// Finish with optional failure mapping. The callback is synchronous and
    /// existing sinks retain their normal finish behavior.
    ///
    /// # Errors
    /// Returns the finish callback's error, optionally mapped by the observer.
    fn finish_diagnosed(&mut self, _observer: &dyn FailureObserver) -> Result<(), Error> {
        self.finish()
    }
}

pub(crate) async fn buffered<
    T: crate::HttpTransport + ?Sized,
    B: RequestStream + ?Sized,
    S: ResponseStream + ?Sized,
>(
    transport: &T,
    request: Request<()>,
    body: &mut B,
    limit: usize,
    sink: &mut S,
) -> Result<(), Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next_chunk()? {
        bytes.extend_from_slice(&chunk);
    }
    let (parts, ()) = request.into_parts();
    let response = transport
        .send_classified(Request::from_parts(parts, bytes), limit)
        .await
        .map_err(|error| match error {
            crate::ChannelError::Transient(cause) => Error::Connection(cause),
            crate::ChannelError::TimedOut(cause) => Error::RequestTimeout(cause),
            crate::ChannelError::Refused(cause) => Error::Transport(cause),
        })?;
    if response.body().len() > limit {
        return Err(Error::Limit("RPC response"));
    }
    let (parts, body) = response.into_parts();
    sink.start(Response::from_parts(parts, ()))?;
    sink.chunk(&body)?;
    sink.finish()
}

pub(crate) struct Chunks<I>(pub(crate) I);
impl<I: Iterator<Item = Result<Vec<u8>, Error>>> RequestStream for Chunks<I> {
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, Error> {
        self.0.next().transpose()
    }
}

struct HeadObserver<'a, D: FailureObserver + ?Sized> {
    inner: &'a D,
    head: &'a Response<()>,
}
impl<D: FailureObserver + ?Sized> FailureObserver for HeadObserver<'_, D> {
    fn map_failure(&self, failure: &FailureDiagnostic<'_>) -> Option<Error> {
        self.inner.map_failure(&FailureDiagnostic {
            status: Some(self.head.status()),
            headers: Some(self.head.headers()),
            ..*failure
        })
    }
    fn response_profile(&self) -> ResponseProfile {
        self.inner.response_profile()
    }
}

/// HTTP validation surrounds the incremental Connect parser, so error JSON is
/// never treated as a successful pack. The HTTP error body stays size-bounded.
pub(crate) struct Checked<'a, S, D: FailureObserver + ?Sized = NoDiagnostics> {
    diagnostics: &'a D,
    pub(crate) sink: S,
    expected_type: Option<HeaderValue>,
    limit: usize,
    response: Option<Response<()>>,
    error_body: Vec<u8>,
    received: usize,
}
impl<S> Checked<'_, S> {
    #[cfg(test)]
    pub(crate) fn new(request: &Request<()>, sink: S, limit: usize) -> Self {
        Self::diagnosed(request, sink, limit, &NoDiagnostics)
    }
}
impl<'a, S, D: FailureObserver + ?Sized> Checked<'a, S, D> {
    pub(crate) fn diagnosed(
        request: &Request<()>,
        sink: S,
        limit: usize,
        diagnostics: &'a D,
    ) -> Self {
        Self {
            diagnostics,
            sink,
            expected_type: request.headers().get("content-type").cloned(),
            limit,
            response: None,
            error_body: Vec::new(),
            received: 0,
        }
    }
    pub(crate) fn status(&self) -> Result<http::StatusCode, Error> {
        self.response
            .as_ref()
            .map(Response::status)
            .ok_or(Error::Invalid("missing HTTP response"))
    }
    pub(crate) fn headers(&self) -> Result<&HeaderMap, Error> {
        self.response
            .as_ref()
            .map(Response::headers)
            .ok_or(Error::Invalid("missing HTTP response"))
    }
}
impl<S: ResponseStream, D: FailureObserver + ?Sized> ResponseStream for Checked<'_, S, D> {
    fn start(&mut self, response: Response<()>) -> Result<(), Error> {
        if self.response.is_some() {
            return Err(Error::Invalid("duplicate HTTP response"));
        }
        if response.status().is_success() {
            let mut head = Response::new(Vec::new());
            *head.status_mut() = response.status();
            *head.headers_mut() = response.headers().clone();
            decode_response_diagnosed(
                head,
                self.expected_type.as_ref(),
                self.limit,
                self.diagnostics,
            )?;
            let mut inner_head = Response::new(());
            *inner_head.status_mut() = response.status();
            *inner_head.headers_mut() = response.headers().clone();
            self.sink.start(inner_head)?;
        }
        self.response = Some(response);
        Ok(())
    }
    fn chunk(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let response = self
            .response
            .as_ref()
            .ok_or(Error::Invalid("missing HTTP response"))?;
        self.received = self.received.saturating_add(bytes.len());
        if self.received > self.limit {
            let failure = FailureDiagnostic {
                procedure: "",
                kind: FailureKind::WireLimit,
                status: Some(response.status()),
                headers: Some(response.headers()),
                body: None,
                parsed_error: None,
                cause: "RPC response exceeds limit",
                limit: Some(self.limit),
            };
            return Err(self
                .diagnostics
                .map_failure(&failure)
                .unwrap_or(Error::Limit("RPC response")));
        }
        if response.status().is_success() {
            self.sink.chunk_diagnosed(
                bytes,
                &HeadObserver {
                    inner: self.diagnostics,
                    head: response,
                },
            )
        } else {
            self.error_body.extend_from_slice(bytes);
            Ok(())
        }
    }
    fn finish(&mut self) -> Result<(), Error> {
        let response = self
            .response
            .as_ref()
            .ok_or(Error::Invalid("missing HTTP response"))?;
        if response.status().is_success() {
            self.sink.finish_diagnosed(&HeadObserver {
                inner: self.diagnostics,
                head: response,
            })
        } else {
            let mut error = Response::new(std::mem::take(&mut self.error_body));
            *error.status_mut() = response.status();
            *error.headers_mut() = response.headers().clone();
            decode_response_diagnosed(
                error,
                self.expected_type.as_ref(),
                self.limit,
                self.diagnostics,
            )
            .map(|_| ())
        }
    }
}

pub(crate) trait FrameSink {
    fn frame(&mut self, bytes: &[u8]) -> Result<(), Error>;
    fn finish(&mut self) -> Result<(), Error>;
}

/// Retain one frame, rather than a complete framed pack alongside its output.
/// There is no protocol chunk-size ceiling: a frame is bounded by the same
/// response cap as the complete exchange.
pub(crate) struct Decoder<S> {
    pub(crate) sink: S,
    limit: usize,
    end_limit: usize,
    header: [u8; 5],
    header_bytes: usize,
    payload: Vec<u8>,
    end: Option<Vec<u8>>,
    response: Option<Response<()>>,
    profile: ResponseProfile,
}
impl<S> Decoder<S> {
    #[cfg(test)]
    pub(crate) fn new(sink: S, limit: usize) -> Self {
        Self::profiled(sink, limit, ResponseProfile::default())
    }
    pub(crate) fn profiled(sink: S, response_limit: usize, profile: ResponseProfile) -> Self {
        Self {
            sink,
            limit: profile
                .frame_limit
                .unwrap_or(response_limit)
                .min(response_limit),
            end_limit: profile
                .end_frame_limit
                .unwrap_or(response_limit)
                .min(response_limit),
            header: [0; 5],
            header_bytes: 0,
            payload: Vec::new(),
            end: None,
            response: None,
            profile,
        }
    }
}
impl<S: FrameSink> Decoder<S> {
    fn receive(
        &mut self,
        mut bytes: &[u8],
        observer: Option<&dyn FailureObserver>,
    ) -> Result<(), Error> {
        while !bytes.is_empty() {
            if self.end.is_some() {
                return Err(Error::Invalid("Connect frame flags/order"));
            }
            let take = (5 - self.header_bytes).min(bytes.len());
            self.header[self.header_bytes..self.header_bytes + take]
                .copy_from_slice(&bytes[..take]);
            self.header_bytes += take;
            bytes = &bytes[take..];
            if self.header_bytes < 5 {
                break;
            }
            let size = u32::from_be_bytes([
                self.header[1],
                self.header[2],
                self.header[3],
                self.header[4],
            ]) as usize;
            let limit = if self.header[0] == 2 {
                self.end_limit
            } else {
                self.limit
            };
            if size > limit {
                let cause = format!("Connect frame size {size} exceeds limit {limit}");
                let mapped = observer.and_then(|observer| {
                    observer.map_failure(&FailureDiagnostic {
                        procedure: "",
                        kind: FailureKind::WireLimit,
                        status: None,
                        headers: None,
                        body: None,
                        parsed_error: None,
                        cause: &cause,
                        limit: Some(limit),
                    })
                });
                return Err(mapped.unwrap_or(Error::Limit("Connect frame")));
            }
            if !matches!(self.header[0], 0 | 2) {
                return Err(Error::Invalid("Connect frame flags/order"));
            }
            let take = (size - self.payload.len()).min(bytes.len());
            self.payload.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.payload.len() < size {
                break;
            }
            if self.header[0] == 2 {
                self.end = Some(std::mem::take(&mut self.payload));
            } else {
                self.sink.frame(&self.payload)?;
                self.payload.clear();
            }
            self.header_bytes = 0;
        }
        Ok(())
    }
}
impl<S: FrameSink> Decoder<S> {
    fn finish_context(&mut self, observer: &dyn FailureObserver) -> Result<(), Error> {
        if self.header_bytes > 0 {
            return Err(Error::Invalid(if self.header_bytes < 5 {
                "Connect frame header"
            } else {
                "truncated Connect frame"
            }));
        }
        let end = self
            .end
            .as_deref()
            .ok_or(Error::Invalid("missing Connect end frame"))?;
        let empty_headers = HeaderMap::new();
        let (status, headers) = self
            .response
            .as_ref()
            .map_or((http::StatusCode::OK, &empty_headers), |response| {
                (response.status(), response.headers())
            });
        end_error_diagnosed(end, status, headers, self.profile, observer)?;
        self.sink.finish()
    }
}
impl<S: FrameSink> ResponseStream for Decoder<S> {
    fn start(&mut self, response: Response<()>) -> Result<(), Error> {
        self.response = Some(response);
        Ok(())
    }
    fn chunk(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.receive(bytes, None)
    }
    fn chunk_diagnosed(
        &mut self,
        bytes: &[u8],
        observer: &dyn FailureObserver,
    ) -> Result<(), Error> {
        self.receive(bytes, Some(observer))
    }
    fn finish(&mut self) -> Result<(), Error> {
        self.finish_context(&NoDiagnostics)
    }
    fn finish_diagnosed(&mut self, observer: &dyn FailureObserver) -> Result<(), Error> {
        self.finish_context(observer)
    }
}

#[derive(Default)]
pub(crate) struct SingleFrame {
    pub(crate) bytes: Option<Vec<u8>>,
}
impl FrameSink for SingleFrame {
    fn frame(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.bytes.is_some() {
            return Err(Error::Invalid("stream response count"));
        }
        self.bytes = Some(bytes.to_vec());
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Error> {
        self.bytes
            .as_ref()
            .map(|_| ())
            .ok_or(Error::Invalid("stream response count"))
    }
}

pub(crate) struct Pack {
    key: Hash,
    cap: u64,
    expected: Option<u64>,
    last: bool,
    verify_hash: bool,
    pub(crate) bytes: Vec<u8>,
    accept_location: bool,
    pub(crate) location: Option<crate::proto::DownloadPackLocation>,
}
impl Pack {
    #[cfg(test)]
    pub(crate) fn new(key: Hash, cap: u64) -> Self {
        Self::profiled(key, cap, ResponseProfile::default())
    }
    pub(crate) fn profiled(key: Hash, cap: u64, profile: ResponseProfile) -> Self {
        Self {
            key,
            cap,
            expected: None,
            last: false,
            verify_hash: !profile.skip_download_hash_verification,
            accept_location: false,
            location: None,
            bytes: Vec::new(),
        }
    }
}
impl Pack {
    pub(crate) fn accept_locations(mut self, accept: bool) -> Self {
        self.accept_location = accept;
        self
    }
}
impl FrameSink for Pack {
    fn frame(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let response = DownloadPackResponse::decode_from_slice(bytes)
            .map_err(|_| Error::Invalid("download protobuf"))?;
        if self.location.is_some() {
            return Err(Error::Invalid("message after pack location"));
        }
        match response.body {
            Some(Body::Location(location)) if self.accept_location && self.expected.is_none() => {
                self.location = Some(*location);
            }
            Some(Body::Header(header)) if self.expected.is_none() && self.bytes.is_empty() => {
                let size = header.total_bytes.ok_or(Error::Invalid("download size"))?;
                if size > self.cap {
                    return Err(Error::Limit("pack download"));
                }
                self.expected = Some(size);
                self.bytes
                    .try_reserve_exact(
                        usize::try_from(size).map_err(|_| Error::Limit("pack download"))?,
                    )
                    .map_err(|_| Error::Limit("pack download allocation"))?;
            }
            Some(Body::Chunk(chunk)) if self.expected.is_some() && !self.last => {
                if chunk.pack_id.as_deref() != Some(self.key.as_slice())
                    || chunk.offset != Some(self.bytes.len() as u64)
                {
                    return Err(Error::Invalid("download chunk identity"));
                }
                let data = chunk
                    .data
                    .as_deref()
                    .ok_or(Error::Invalid("download chunk"))?;
                if (self.bytes.len() as u64).saturating_add(data.len() as u64)
                    > self.expected.unwrap_or(0)
                {
                    return Err(Error::Invalid("download exceeds declared size"));
                }
                self.bytes.extend_from_slice(data);
                self.last = chunk.last.ok_or(Error::Invalid("download last marker"))?;
            }
            _ => return Err(Error::Invalid("download order")),
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), Error> {
        if self.location.is_some() {
            return Ok(());
        }
        if !self.last
            || self.expected != Some(self.bytes.len() as u64)
            || (self.verify_hash && mkit_core::pack::pack_key(&self.bytes) != self.key)
        {
            return Err(Error::Invalid("pack content commitment"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::{frame, framed};

    #[derive(Default)]
    struct Frames(Vec<Vec<u8>>);
    impl FrameSink for Frames {
        fn frame(&mut self, bytes: &[u8]) -> Result<(), Error> {
            self.0.push(bytes.to_vec());
            Ok(())
        }
        fn finish(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    struct BufferedChannel(std::cell::RefCell<Vec<u8>>);
    impl crate::HttpTransport for BufferedChannel {
        async fn send(
            &self,
            request: Request<Vec<u8>>,
            _: usize,
        ) -> Result<Response<Vec<u8>>, String> {
            *self.0.borrow_mut() = request.into_body();
            let mut wire = framed(b"reply").unwrap();
            wire.extend_from_slice(b"\x02\0\0\0\x02{}");
            Ok(Response::builder()
                .header("content-type", "application/connect+proto")
                .body(wire)
                .unwrap())
        }
    }

    #[test]
    fn existing_buffered_channels_compose_with_pulled_bodies_and_incremental_sinks() {
        use crate::HttpTransport as _;
        use std::future::Future as _;
        let channel = BufferedChannel(std::cell::RefCell::new(Vec::new()));
        let request = Request::post("https://example.invalid/")
            .header("content-type", "application/connect+proto")
            .body(())
            .unwrap();
        let mut body = Chunks([Ok(b"first".to_vec()), Ok(b"second".to_vec())].into_iter());
        let mut reply = Checked::new(&request, Decoder::new(Frames::default(), 1024), 1024);
        let result = std::pin::pin!(channel.send_stream(request, &mut body, 1024, &mut reply))
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()));
        assert!(matches!(result, std::task::Poll::Ready(Ok(()))));
        assert_eq!(*channel.0.borrow(), b"firstsecond");
        assert_eq!(reply.sink.sink.0, [b"reply".to_vec()]);
    }

    #[test]
    fn frames_decode_across_every_header_and_payload_boundary() {
        let mut wire = framed(b"first").unwrap();
        frame(&mut wire, b"second").unwrap();
        wire.extend_from_slice(b"\x02\0\0\0\x02{}");
        for split in 0..=wire.len() {
            let mut decoder = Decoder::new(Frames::default(), 1024);
            decoder.chunk(&wire[..split]).unwrap();
            decoder.chunk(&wire[split..]).unwrap();
            decoder.finish().unwrap();
            assert_eq!(decoder.sink.0, [b"first".to_vec(), b"second".to_vec()]);
        }
        let mut decoder = Decoder::new(Frames::default(), 1024);
        for byte in &wire {
            decoder.chunk(&[*byte]).unwrap();
        }
        decoder.finish().unwrap();
        assert_eq!(decoder.sink.0.len(), 2);
    }

    #[test]
    fn incremental_frames_fail_closed_on_missing_ends_flags_and_truncation() {
        for wire in [
            b"\0".as_slice(),
            b"\0\0\0\0\x05abc",
            b"\x01\0\0\0\0",
            b"\0\0\0\0\0",
            b"\x02\0\0\0\x02{}extra",
            b"\x02\0\0\0\x05{",
        ] {
            for split in 0..=wire.len() {
                let mut decoder = Decoder::new(Frames::default(), 1024);
                let result = decoder
                    .chunk(&wire[..split])
                    .and_then(|()| decoder.chunk(&wire[split..]))
                    .and_then(|()| decoder.finish());
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn framed_remote_errors_and_response_limits_survive_incremental_decoding() {
        let json = br#"{"error":{"code":"failed_precondition","message":"moved"}}"#;
        let mut wire = vec![2];
        wire.extend_from_slice(&u32::try_from(json.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(json);
        let mut decoder = Decoder::new(Frames::default(), 1024);
        for byte in wire {
            decoder.chunk(&[byte]).unwrap();
        }
        assert!(
            matches!(decoder.finish(), Err(Error::Remote(error)) if error.code == "failed_precondition")
        );
        let mut decoder = Decoder::new(Frames::default(), 16);
        assert!(matches!(
            decoder.chunk(b"\0\0\0\0\x20"),
            Err(Error::Limit("Connect frame"))
        ));
    }

    #[test]
    fn incremental_pack_checks_chunk_identity_and_declared_size() {
        let key = mkit_core::pack::pack_key(b"pack bytes");
        let header = DownloadPackResponse {
            body: Some(
                crate::proto::DownloadPackHeader {
                    total_bytes: Some(10),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        let chunk = DownloadPackResponse {
            body: Some(
                crate::proto::PackChunk {
                    pack_id: Some(key.to_vec()),
                    offset: Some(0),
                    data: Some(b"pack bytes".to_vec()),
                    last: Some(true),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        let mut pack = Pack::new(key, 10);
        pack.frame(&header).unwrap();
        pack.frame(&chunk).unwrap();
        pack.finish().unwrap();
        assert_eq!(pack.bytes, b"pack bytes");
        let mut pack = Pack::new(key, 9);
        assert!(matches!(
            pack.frame(&header),
            Err(Error::Limit("pack download"))
        ));
        let mut pack = Pack::new([1; 32], 10);
        pack.frame(&header).unwrap();
        assert!(matches!(
            pack.frame(&chunk),
            Err(Error::Invalid("download chunk identity"))
        ));
    }
    #[test]
    fn hash_verification_can_only_be_deferred_by_explicit_host_profile() {
        let key = [1; 32];
        let header = DownloadPackResponse {
            body: Some(
                crate::proto::DownloadPackHeader {
                    total_bytes: Some(4),
                    ..Default::default()
                }
                .into(),
            ),
            ..Default::default()
        }
        .encode_to_vec();
        let chunk = |offset| {
            DownloadPackResponse {
                body: Some(
                    crate::proto::PackChunk {
                        pack_id: Some(key.to_vec()),
                        offset: Some(offset),
                        data: Some(b"pack".to_vec()),
                        last: Some(true),
                        ..Default::default()
                    }
                    .into(),
                ),
                ..Default::default()
            }
            .encode_to_vec()
        };
        let mut strict = Pack::new(key, 4);
        strict.frame(&header).unwrap();
        strict.frame(&chunk(0)).unwrap();
        assert!(matches!(
            strict.finish(),
            Err(Error::Invalid("pack content commitment"))
        ));
        let profile = ResponseProfile {
            skip_download_hash_verification: true,
            ..ResponseProfile::default()
        };
        let mut deferred = Pack::profiled(key, 4, profile);
        deferred.frame(&header).unwrap();
        deferred.frame(&chunk(0)).unwrap();
        deferred.finish().unwrap();
        assert_eq!(deferred.bytes, b"pack");
        let mut wrong_offset = Pack::profiled(key, 4, profile);
        wrong_offset.frame(&header).unwrap();
        assert!(matches!(
            wrong_offset.frame(&chunk(1)),
            Err(Error::Invalid("download chunk identity"))
        ));
        let mut too_large = Pack::profiled(key, 3, profile);
        assert!(matches!(
            too_large.frame(&header),
            Err(Error::Limit("pack download"))
        ));
    }
}
