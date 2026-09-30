//! Native CPU builder with one canonical read outstanding at a time.
use mkit_core::hash::Hash;
use mkit_core::store::{ObjectSource, StoreError, StoreResult};
use mkit_core::verify::span::{RangeProof, build_range_proof_from};
use mkit_core::verify::{Selector, build_disclosure_from};
use mkit_server::http_objects::{PreparedProof, ProofServer, ProofSource};
use mkit_server::{BoxFuture, ServerError};
use std::sync::mpsc;

/// Builds on tokio's blocking pool; the async driver supplies only verified
/// repository-local canonical objects. Cancellation closes both channels,
/// releasing a builder blocked on a source read.
#[derive(Debug, Default)]
pub struct NativeProofs;

struct Read {
    id: Hash,
    reply: mpsc::Sender<StoreResult<Vec<u8>>>,
}
struct Source(tokio::sync::mpsc::UnboundedSender<Read>);
fn unavailable() -> StoreError {
    StoreError::Io(std::io::Error::other("proof source unavailable"))
}
impl ObjectSource for Source {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        let (reply, result) = mpsc::channel();
        self.0
            .send(Read { id: *id, reply })
            .map_err(|_| unavailable())?;
        result.recv().map_err(|_| unavailable())?
    }
}
impl ProofServer for NativeProofs {
    fn build<'a>(
        &'a self,
        request: &'a PreparedProof,
        source: &'a mut dyn ProofSource,
    ) -> BoxFuture<'a, Result<Vec<u8>, ServerError>> {
        Box::pin(async move {
            let request = request.clone();
            let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
            let task = tokio::task::spawn_blocking(move || {
                let source = Source(send);
                let path: Vec<_> = request.path.iter().map(Vec::as_slice).collect();
                match request.range {
                    None => {
                        build_disclosure_from(&source, &request.commit, &path, Selector::Object)
                            .map_err(|_| ())
                    }
                    Some((a, b)) => match build_range_proof_from(
                        &source,
                        &request.commit,
                        &path,
                        a,
                        b.checked_sub(a).and_then(|n| n.checked_add(1)).ok_or(())?,
                        None,
                    )
                    .map_err(|_| ())?
                    {
                        RangeProof::Mkdp(bytes) | RangeProof::Mkds(bytes) => Ok(bytes),
                        _ => Err(()),
                    },
                }
            });
            while let Some(read) = receive.recv().await {
                let answer = source.read(read.id).await.map_err(|_| unavailable());
                // A canceled builder no longer needs this answer.
                let _ = read.reply.send(answer);
            }
            task.await
                .map_err(|_| ServerError::unavailable("proof build failed"))?
                .map_err(|()| ServerError::unavailable("proof build failed"))
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct PendingSource(Option<tokio::sync::oneshot::Sender<()>>);
    impl ProofSource for PendingSource {
        fn read(&mut self, _: Hash) -> BoxFuture<'_, Result<Vec<u8>, ServerError>> {
            Box::pin(async move {
                self.0.take().unwrap().send(()).unwrap();
                core::future::pending().await
            })
        }
    }

    #[test]
    fn native_proof_cancellation_releases_the_blocking_source_reader() {
        // One blocking slot makes a leaked receiver observable: the sentinel
        // cannot run until the canceled proof releases its worker.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async {
                let (started, wait) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(async move {
                    let request = PreparedProof {
                        commit: [1; 32],
                        leaf: [2; 32],
                        path: vec![],
                        range: None,
                        encoded_len: 1,
                        span: false,
                    };
                    NativeProofs
                        .build(&request, &mut PendingSource(Some(started)))
                        .await
                });
                tokio::time::timeout(std::time::Duration::from_secs(5), wait)
                    .await
                    .unwrap()
                    .unwrap();
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                let sentinel = tokio::task::spawn_blocking(|| 42);
                assert_eq!(
                    tokio::time::timeout(std::time::Duration::from_secs(5), sentinel)
                        .await
                        .unwrap()
                        .unwrap(),
                    42
                );
            });
        }));
        // Runtime drop waits for blocking tasks. Even a failed assertion
        // must use bounded shutdown before propagating its panic.
        runtime.shutdown_timeout(std::time::Duration::from_secs(1));
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
    }
}
