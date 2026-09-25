//! In-memory reference backends: the template third-party backends copy,
//! and the stores under the core's own tests. Not durable.

mod blob;
mod kv;

use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::store::StoreError;

pub use blob::{MemoryBlobStore, MemoryPackSink};
pub use kv::MemoryKv;

/// A one-shot failure a memory store injects, for tests of the layers
/// above. Each store fires only the faults that apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryFault {
    /// The next `apply` fails before it checks anything; nothing is
    /// written.
    ApplyBefore,
    /// The next `apply` commits, then reports an error: the ambiguous
    /// outcome of a connection lost after commit.
    ApplyAfterCommit,
    /// The `n`th (0-based) `PackSink::write` of the next upload fails.
    BlobWrite(u32),
    /// The next `PackSink::commit` fails before anything becomes visible.
    BlobCommit,
}

/// Lock `mutex`, recovering from poisoning: every critical section leaves
/// the data consistent (normative rule 4), so a panic elsewhere never
/// makes the store unusable.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Fire `fault` if it is the armed one.
fn take_fault(armed: &Mutex<Option<MemoryFault>>, fault: MemoryFault) -> Result<(), StoreError> {
    let mut armed = lock(armed);
    if *armed == Some(fault) {
        *armed = None;
        return Err(StoreError::unavailable(format!("injected fault {fault:?}")));
    }
    Ok(())
}
