//! Bounded overlap of independent storage reads.

use futures::future::join_all;

/// Most independent reads in flight at once. A Worker queues connections past
/// its own small limit, so a wider fan-out only adds queueing and memory.
pub(crate) const MAX_IN_FLIGHT: usize = 16;

/// Run `futures` in waves of at most [`MAX_IN_FLIGHT`], returning their
/// outputs in input order. The first error in input order wins, as in a
/// sequential loop, and later waves are never started.
pub(crate) async fn try_overlap<T, E, F>(mut futures: Vec<F>) -> Result<Vec<T>, E>
where
    F: Future<Output = Result<T, E>>,
{
    let mut out = Vec::with_capacity(futures.len());
    while !futures.is_empty() {
        let wave: Vec<F> = futures.drain(..futures.len().min(MAX_IN_FLIGHT)).collect();
        for reply in join_all(wave).await {
            out.push(reply?);
        }
    }
    Ok(out)
}
