//! Bounded Connect streaming with acceptance and terminal failure audits.
use super::{BodyCapture, Engine, Headers, READ_PRESERVED_PATH, Response, auth::Verified};
use crate::{BoxStream, Code, NamespaceStore, ServerError};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures::stream;
use serde_json::{Value, json};
use std::sync::Arc;

/// One verified canonical slice. No instance is stored in the admin ledger.
pub struct PreservedPiece {
    /// Canonical payload; bounded by the preservation piece size.
    pub data: Bytes,
    /// Exact requested offset of this slice.
    pub offset: u64,
    /// True only after the final piece passes current retention/ownership checks.
    pub last: bool,
}
impl std::fmt::Debug for PreservedPiece {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreservedPiece")
            .field("length", &self.data.len())
            .field("offset", &self.offset)
            .field("last", &self.last)
            .finish()
    }
}
/// An admin response whose streaming bytes never enter replay storage.
pub enum Reply {
    /// Bounded unary JSON or a pre-stream Connect error.
    Unary(Response),
    /// Framed Connect JSON, including an end-stream success or error envelope.
    Stream(BoxStream<'static, Result<Bytes, ServerError>>),
}
impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unary(response) => response.fmt(f),
            Self::Stream(_) => f.write_str("AdminStream"),
        }
    }
}
fn frame(flags: u8, value: &Value) -> Result<Bytes, ServerError> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_| ServerError::new(Code::Internal, "admin stream encoding failed"))?;
    let length = u32::try_from(encoded.len())
        .map_err(|_| ServerError::new(Code::Internal, "admin stream overflow"))?;
    let mut out = Vec::with_capacity(encoded.len() + 5);
    out.push(flags);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend(encoded);
    Ok(Bytes::from(out))
}
impl<S: NamespaceStore + 'static> Engine<S> {
    /// Dispatch signed bytes and return a bounded verified stream for `ReadPreserved`.
    /// Adapters must send streaming responses with `Cache-Control: no-store`.
    pub async fn handle_streamed(
        self: Arc<Self>,
        path: &str,
        headers: &Headers,
        wire: &BodyCapture,
        decoded: Option<Result<Vec<u8>, ServerError>>,
        now_ms: i64,
    ) -> Reply {
        let verified = match self.config.verify(path, headers, wire, now_ms) {
            Ok(verified) => verified,
            Err(error) => return Reply::Unary(Response::error(&error)),
        };
        let result = match self
            .dispatch(path, headers, wire, decoded, now_ms, true)
            .await
        {
            Ok(response) => response,
            Err(error) => return Reply::Unary(Response::error(&error)),
        };
        if path != READ_PRESERVED_PATH || result.status != 200 {
            return Reply::Unary(result);
        }
        let Ok(descriptor) = serde_json::from_slice::<Value>(&result.body) else {
            let error = ServerError::new(Code::DataLoss, "invalid read descriptor");
            let result = self
                .record_result(&verified, now_ms, Response::error(&error))
                .await
                .unwrap_or_else(|error| Response::error(&error));
            return Reply::Unary(result);
        };
        // Each poll retains at most one verified piece and one encoded message.
        Reply::Stream(Box::pin(stream::unfold(
            (self, verified, descriptor, 0u8),
            |(engine, verified, mut descriptor, stage)| async move {
                if stage == 2 {
                    return None;
                }
                if stage == 1 {
                    return Some((
                        frame(2, &json!({"metadata":{}})),
                        (engine, verified, descriptor, 2),
                    ));
                }
                let result = engine.next_piece(&descriptor).await;
                let (message, next_stage) = match result {
                    Ok(piece) => match piece.offset.checked_add(piece.data.len() as u64) {
                        Some(next) => {
                            descriptor["offset"] = json!(next.to_string());
                            (
                                frame(
                                    0,
                                    &json!({"data":STANDARD.encode(&piece.data), "offset":piece.offset.to_string(), "last":piece.last}),
                                ),
                                u8::from(piece.last),
                            )
                        }
                        None => (
                            engine
                                .stream_error(
                                    &verified,
                                    &ServerError::new(Code::DataLoss, "invalid preserved offset"),
                                )
                                .await,
                            2,
                        ),
                    },
                    Err(error) => (engine.stream_error(&verified, &error).await, 2),
                };
                Some((message, (engine, verified, descriptor, next_stage)))
            },
        )))
    }
    async fn next_piece(&self, descriptor: &Value) -> Result<PreservedPiece, ServerError> {
        let service = self
            .operations
            .as_ref()
            .ok_or_else(|| ServerError::unavailable("preservation service unavailable"))?;
        service.preserved_piece(descriptor).await
    }
    async fn stream_error(
        &self,
        verified: &Verified,
        error: &ServerError,
    ) -> Result<Bytes, ServerError> {
        self.record_result(
            verified,
            self.operations
                .as_ref()
                .ok_or_else(|| ServerError::unavailable("preservation service unavailable"))?
                .preserved_now_ms()?,
            Response::error(error),
        )
        .await?;
        frame(
            2,
            &json!({"metadata":{}, "error":{"code":error.code().as_str(),"message":error.public_message()}}),
        )
    }
}
