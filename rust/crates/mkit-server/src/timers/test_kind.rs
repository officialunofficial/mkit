//! Ref-deleting test timer; absent from release builds.
use super::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind, registry::kinds};
use crate::store::keys;
use crate::{Batch, BoxFuture, NamespaceStore, RepoName, StoreError};

/// Deletes the ref named by `<repo> 00 <refname>`.
#[derive(Debug)]
pub struct TestTimer;
impl<S: NamespaceStore> TimerHandler<S> for TestTimer {
    fn kind(&self) -> TimerKind {
        kinds::TEST
    }
    fn fire<'a>(
        &'a self,
        _ctx: &'a TimerCtx<'a, S>,
        timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(async move {
            let reference = &timer.reference;
            let Some(sep) = reference.iter().position(|&b| b == 0) else {
                return Ok(Fired::Retry);
            };
            let (Ok(repo), Ok(name)) = (
                core::str::from_utf8(&reference[..sep]),
                core::str::from_utf8(&reference[sep + 1..]),
            ) else {
                return Ok(Fired::Retry);
            };
            let Ok(repo) = RepoName::new(repo) else {
                return Ok(Fired::Retry);
            };
            if !crate::refs::validate_ref_name(name) {
                return Ok(Fired::Retry);
            }
            Ok(Fired::Done(Batch::new().delete(keys::ref_key(&repo, name))))
        })
    }
}
