//! Default policy-free clients retain their conditional thread-safety traits.
#![allow(clippy::expect_used)]
use http::{Request, Response};
use mkit_client::{Client, Clock, Destination, HttpTransport, NoObserver, Signer};
use std::time::Duration;

struct Host;
impl HttpTransport for Host {
    async fn send(&self, _: Request<Vec<u8>>, _: usize) -> Result<Response<Vec<u8>>, String> {
        Ok(Response::new(Vec::new()))
    }
}
impl Signer for Host {
    fn public_key(&self) -> [u8; 32] {
        [1; 32]
    }
    async fn sign(&self, _: &[u8; 32]) -> Result<[u8; 64], String> {
        Ok([0; 64])
    }
}
impl Clock for Host {
    fn now_ms(&self) -> i64 {
        0
    }
    fn nonce(&self) -> Result<[u8; 32], String> {
        Ok([0; 32])
    }
    async fn wait(&self, _: Duration) {}
}
fn assert_send_sync<T: Send + Sync>(_: T) {}
#[test]
fn default_clients_remain_send_and_sync() {
    let host = Host;
    let destination = || {
        Destination::new("https://example.test".into(), "repo".into()).expect("test destination")
    };
    assert_send_sync(Client::anonymous(&host, destination()));
    assert_send_sync(Client::signed(&host, destination(), &host, &host));
    assert_send_sync(Client::signed(&host, destination(), &host, &host).with_observer(&NoObserver));
}

struct LocalPolicy(std::cell::Cell<usize>);
impl mkit_client::RequestPolicy for LocalPolicy {
    fn headers(
        &self,
        _: &mkit_client::RequestContext<'_>,
    ) -> Result<mkit_client::RequestHeaders, mkit_client::Veto> {
        self.0.set(self.0.get() + 1);
        Ok(mkit_client::RequestHeaders::new())
    }
}
#[test]
fn explicitly_configured_local_and_erased_policies_remain_supported() {
    let host = Host;
    let policy = LocalPolicy(std::cell::Cell::new(0));
    let destination = || {
        Destination::new("https://example.test".into(), "repo".into()).expect("test destination")
    };
    let client = Client::signed(&host, destination(), &host, &host)
        .with_request_policy(&policy)
        .with_observer(&NoObserver);
    assert_eq!(client.public_key(), Some([1; 32]));
    let erased: &dyn mkit_client::RequestPolicy = &policy;
    let client = Client::anonymous(&host, destination()).with_request_policy(erased);
    assert_eq!(client.public_key(), None);
    assert_send_sync(
        Client::anonymous(&host, destination()).with_request_policy(&mkit_client::NoRequestPolicy),
    );
}
