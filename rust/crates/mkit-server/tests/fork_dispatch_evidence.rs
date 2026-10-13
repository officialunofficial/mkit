//! The completed-replay evidence of `Pipeline::completed_fork` fails closed:
//! a stored job that disagrees with the request on any field it binds, or
//! that is missing, is `unavailable` and never lets a policy stand aside.
//! (These tests tamper with the stored job, so they use the storage keys and
//! the job codec; the embedder-facing tests are in `fork_dispatch.rs`.)
#![cfg(feature = "memory")]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod fork_support;
use fork_support::*;
use mkit_attest::grant::Visibility;
use mkit_server::fork::{Failure, ForkJobV1, ForkRequest, Phase, decode_job, encode_job};
use mkit_server::pipeline::{Authenticated, EmbeddedGate};
use mkit_server::store::adapter_spi::keys;
use mkit_server::{
    Batch, BoxFuture, Code, NamespaceStore, Partition, Procedure, ServerError, Write,
};
use std::sync::atomic::{AtomicU32, Ordering};

fn request(source: &Source) -> ForkRequest {
    ForkRequest {
        source: source.repo.clone(),
        source_ref: "refs/heads/main".into(),
        expected_tip: source.head,
        dest_visibility: Visibility::Public,
    }
}

#[derive(Default)]
struct CountPolicy(AtomicU32);
impl EmbeddedGate<ForkRequest> for CountPolicy {
    fn policy<'a>(
        &'a self,
        _: &'a Authenticated,
        _: &'a ForkRequest,
    ) -> BoxFuture<'a, Result<(), ServerError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }
}

type Tamper = (&'static str, fn(&mut ForkJobV1));

const TAMPERS: &[Tamper] = &[
    ("phase", |j| j.phase = Phase::Publish),
    ("failure", |j| j.failure = Some(Failure::NotFound)),
    ("binding", |j| j.binding = [9; 32]),
    ("destination", |j| j.dest_repo = "elsewhere".into()),
    ("destination namespace", |j| j.dest_ns = "0xdead".into()),
    ("source", |j| j.source_repo = "another".into()),
    ("source namespace", |j| j.source_ns = "0xdead".into()),
    ("ref", |j| j.source_ref = "refs/heads/other".into()),
    ("tip", |j| j.tip = [9; 32]),
    ("packmap", |j| j.packmap = [9; 32]),
    ("source sequence", |j| j.source_sequence += 1),
    ("result missing", |j| j.result = None),
    ("result source", |j| {
        j.result.as_mut().unwrap().source = "another".into();
    }),
    ("result ref", |j| {
        j.result.as_mut().unwrap().source_ref = "refs/heads/other".into();
    }),
    ("result tip", |j| j.result.as_mut().unwrap().tip = [9; 32]),
    ("result packmap", |j| {
        j.result.as_mut().unwrap().packmap = [9; 32];
    }),
    ("result sequence", |j| {
        j.result.as_mut().unwrap().source_sequence += 1;
    }),
];

#[tokio::test]
async fn every_inconsistent_job_field_and_a_missing_job_fail_closed() {
    let source = Source::build_with("source", 6, |mut cfg| {
        cfg.takedown_denial = true;
        cfg
    })
    .await;
    let mut dest = source.at("forked");
    let req = request(&source);
    let registry = dest.fork_registry(true);
    let coordinator = Partition::Coordinator(dest.repo.namespace.clone());
    let nonce = dest.next_nonce();
    let body = req.canonical_body();
    let auth = |d: &Source| d.authenticate_body(Procedure::Fork, nonce, &body);
    for _ in 0..40 {
        match Box::pin(source.pipe.fork_repo(&auth(&dest), req.clone())).await {
            Err(error) if error.public_message() == "fork in progress" => {
                dest.drain(&registry, &coordinator).await;
            }
            other => {
                other.unwrap();
                break;
            }
        }
    }
    let key = keys::fork_job(&dest.repo.name);
    let stored = source
        .store
        .inner
        .get(&coordinator, &key)
        .await
        .unwrap()
        .unwrap();
    let original = decode_job(&stored).unwrap();
    let put = |value: Option<mkit_server::Value>| {
        let batch = if let Some(value) = value {
            Batch::new().put(key.clone(), value)
        } else {
            let mut batch = Batch::new();
            batch.writes.push(Write::Delete(key.clone()));
            batch
        };
        let store = source.store.inner.clone();
        let coordinator = coordinator.clone();
        async move { store.apply(&coordinator, batch).await.unwrap() }
    };
    // The untouched evidence is accepted.
    let a = auth(&dest);
    assert!(
        source
            .pipe
            .completed_fork(&a, &req)
            .await
            .unwrap()
            .is_some()
    );

    for (field, tamper) in TAMPERS {
        let mut job = original.clone();
        tamper(&mut job);
        put(Some(encode_job(&job).unwrap())).await;
        let error = source.pipe.completed_fork(&a, &req).await.unwrap_err();
        assert_eq!(error.code(), Code::Unavailable, "{field}");
        assert_eq!(
            error.public_message(),
            "fork evidence inconsistent",
            "{field}"
        );
        // Through the entry: no policy stands aside, and none runs.
        let policy = CountPolicy::default();
        let headers = dest.signed_headers(Procedure::Fork, nonce, &body);
        let header = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let error = source
            .pipe
            .dispatch_fork(&header, &body, &policy)
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::Unavailable, "{field}");
        assert_eq!(policy.0.load(Ordering::SeqCst), 0, "{field}");
    }

    // A missing job under a committed replay record, and a corrupt one.
    for row in [
        None,
        Some(mkit_server::Value::new(b"\x01not a job".to_vec())),
    ] {
        put(row).await;
        let error = source.pipe.completed_fork(&a, &req).await.unwrap_err();
        assert!(
            matches!(error.code(), Code::Unavailable | Code::Internal),
            "{error:?}"
        );
        // Through the entry the policy neither runs nor is skipped.
        let policy = CountPolicy::default();
        let body = req.canonical_body();
        let headers = dest.signed_headers(Procedure::Fork, nonce, &body);
        let header = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let error = source
            .pipe
            .dispatch_fork(&header, &body, &policy)
            .await
            .unwrap_err();
        assert!(
            matches!(error.code(), Code::Unavailable | Code::Internal),
            "{error:?}"
        );
        assert_eq!(policy.0.load(Ordering::SeqCst), 0);
    }

    // Restored, the evidence is accepted again.
    put(Some(stored)).await;
    assert!(
        source
            .pipe
            .completed_fork(&a, &req)
            .await
            .unwrap()
            .is_some()
    );
}
