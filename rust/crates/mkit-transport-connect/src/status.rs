//! Preserve the one HTTP status ConnectRPC discards when constructing errors.
use connectrpc::client::{ClientBody, ClientTransport};
use futures::future::BoxFuture;
use http::{Request, Response, StatusCode};

pub(crate) const STATUS_MARKER: &str = "x-mkit-client-status";

#[derive(Clone)]
pub(crate) struct StatusTransport<T>(pub T);

impl<T: ClientTransport> ClientTransport for StatusTransport<T> {
    type ResponseBody = T::ResponseBody;
    type Error = T::Error;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let inner = self.0.clone();
        Box::pin(async move {
            let mut response = inner.send(request).await?;
            response.headers_mut().remove(STATUS_MARKER);
            if response.status() == StatusCode::PAYMENT_REQUIRED {
                response
                    .headers_mut()
                    .insert(STATUS_MARKER, http::HeaderValue::from_static("402"));
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use connectrpc::client::full_body;
    use http_body_util::Full;
    use std::convert::Infallible;

    #[derive(Clone)]
    struct Fake(StatusCode);
    impl ClientTransport for Fake {
        type ResponseBody = Full<Bytes>;
        type Error = Infallible;
        fn send(
            &self,
            _: Request<ClientBody>,
        ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
            let status = self.0;
            Box::pin(async move {
                let mut response = Response::new(Full::new(Bytes::new()));
                *response.status_mut() = status;
                response
                    .headers_mut()
                    .insert(STATUS_MARKER, "spoofed".parse().unwrap());
                Ok(response)
            })
        }
    }

    #[tokio::test]
    async fn strips_spoofed_marker_and_stamps_only_402() {
        for (status, marker) in [
            (StatusCode::OK, None),
            (StatusCode::FORBIDDEN, None),
            (StatusCode::PAYMENT_REQUIRED, Some("402")),
        ] {
            let request = Request::new(full_body(Bytes::new()));
            let response = StatusTransport(Fake(status)).send(request).await.unwrap();
            assert_eq!(
                response
                    .headers()
                    .get(STATUS_MARKER)
                    .map(|v| v.to_str().unwrap()),
                marker
            );
        }
    }
}
