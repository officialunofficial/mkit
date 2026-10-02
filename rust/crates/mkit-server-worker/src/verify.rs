//! Kind 7 on a Worker: scheduled indexed verification (WP-4.8, R-171).
//!
//! A ticketed pack verifies in checkpointed alarm slices
//! ([`mkit_server::indexed::job`]): each fire reads at most two 16 MiB R2
//! windows, decodes them, and checkpoints. This module is the Worker's half:
//! [`R2Windows`], the etag-bound range reads a slice resumes on, and
//! [`with_verification_timers`], the one registration of the handler.
//!
//! **Plan.** A slice makes up to 256 subrequests (R2 ranges and index or
//! membership shard calls), counted per fire; one kind-7 fire runs per alarm.
//! With the relay's 512, the outcome sink's 64 and the rollup's 32 that is
//! about 865 of a Paid alarm's 1,000. Free cannot run indexed mode (every one
//! of its 50 subrequests is already assigned, R-147), so nothing is
//! registered there. Raise `limits.cpu_ms` on a Paid deployment that verifies
//! large packs; a slice the runtime kills is counted and shrinks its own work.
//!
//! **Launch.** The explicit Paid indexed Workers profile selects this handler
//! with the real R2 extraction driver. Without the opt-in, indexed mode stays
//! off and no verification job or kind-7 timer is created.

use crate::classes::ShardClass;
use crate::log_failure;
use crate::r2::{ObjectBucket, PACKS_KEYSPACE, RangeRead};
use mkit_core::hash::Hash;
use mkit_server::indexed::IndexedConfig;
use mkit_server::indexed::VerificationMode;
use mkit_server::indexed::budget::{PackWindows, Window, WindowError};
use mkit_server::indexed::job::{FailClosedExtraction, SliceExtension, SliceLimits, VerifyTimer};
use mkit_server::pipeline::{D34Shards, LeaseParams};
use mkit_server::timers::TimerRegistry;
use mkit_server::{BlobKey, BlobStore, BoxFuture, Clock, Metrics, NamespaceStore};
use std::sync::Arc;

/// Existing extraction extension backed by R-192's root-pinned R2 uploads.
#[derive(Debug, Clone)]
pub struct R2Extraction<B>(pub crate::r2::R2BlobStore<B>);

fn reserve(
    budget: &mkit_server::indexed::budget::SliceBudget,
    count: u32,
) -> Result<(), mkit_server::StoreError> {
    for _ in 0..count {
        budget.charge()?;
    }
    Ok(())
}

impl<B: ObjectBucket> SliceExtension for R2Extraction<B> {
    fn needs_extraction(&self, object: &mkit_core::object::Object, cfg: &IndexedConfig) -> bool {
        FailClosedExtraction.needs_extraction(object, cfg)
    }
    fn extraction_enabled(&self) -> bool {
        true
    }
    fn begin_object<'a>(
        &'a self,
        key: BlobKey,
        plan: &'a mkit_core::upload_parts::PartPlan,
        root: Hash,
        cvs: &'a [Hash],
        operation: Hash,
        budget: &'a mkit_server::indexed::budget::SliceBudget,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, mkit_server::StoreError>> {
        Box::pin(async move {
            reserve(budget, 8)?;
            self.0
                .begin_verified_object(key, plan, root, cvs, operation)
                .await
                .map(Some)
        })
    }
    fn put_object_part<'a>(
        &'a self,
        key: BlobKey,
        session: &'a [u8],
        plan: &'a mkit_core::upload_parts::PartPlan,
        index: u32,
        cv: Hash,
        bytes: Vec<u8>,
        budget: &'a mkit_server::indexed::budget::SliceBudget,
    ) -> BoxFuture<'a, Result<Option<Vec<u8>>, mkit_server::StoreError>> {
        use mkit_server::PartSink;
        Box::pin(async move {
            reserve(budget, 3)?;
            let mut sink = self
                .0
                .begin_verified_object_part(key, session, plan, index, cv)
                .await?;
            for piece in bytes.chunks(mkit_server::store::MAX_BLOB_PIECE_BYTES) {
                if let Err(error) = sink.write(bytes::Bytes::copy_from_slice(piece)).await {
                    sink.abort().await;
                    return Err(error);
                }
            }
            sink.commit().await.map(Some)
        })
    }
    fn complete_object<'a>(
        &'a self,
        key: BlobKey,
        session: &'a [u8],
        plan: &'a mkit_core::upload_parts::PartPlan,
        parts: Vec<mkit_server::PartRef>,
        root: Hash,
        budget: &'a mkit_server::indexed::budget::SliceBudget,
    ) -> BoxFuture<'a, Result<Option<mkit_server::CommitOutcome>, mkit_server::StoreError>> {
        Box::pin(async move {
            reserve(budget, 7)?;
            // Move receipt tags: cloning the maximum receipt vector would add
            // eleven MiB to the bounded finalization allowance.
            let parts: Vec<_> = parts
                .into_iter()
                .map(|p| crate::r2::VerifiedObjectPartRef {
                    index: p.index,
                    len: p.len,
                    tag: p.tag,
                })
                .collect();
            self.0
                .complete_verified_object(key, session, plan, &parts, root)
                .await
                .map(Some)
        })
    }
    fn abort_object<'a>(
        &'a self,
        key: BlobKey,
        session: &'a [u8],
        plan: &'a mkit_core::upload_parts::PartPlan,
        budget: &'a mkit_server::indexed::budget::SliceBudget,
    ) -> BoxFuture<'a, Result<(), mkit_server::StoreError>> {
        Box::pin(async move {
            reserve(budget, 2)?;
            self.0.abort_verified_object(key, session, plan).await
        })
    }
}

/// Range reads of a pack in the `STORAGE` bucket, bound to its etag.
#[derive(Debug, Clone)]
pub struct R2Windows<B>(pub B);

impl<B: ObjectBucket> PackWindows for R2Windows<B> {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        Box::pin(async move {
            let key = BlobKey::pack(*pack)
                .relative_path(PACKS_KEYSPACE)
                .map_err(|_| WindowError::Unavailable)?;
            let end = offset.checked_add(len).ok_or(WindowError::Unavailable)?;
            match self.0.get_range_etag(&key, offset..end, etag).await {
                Ok(RangeRead::Bytes { bytes, etag }) if bytes.len() as u64 == len => {
                    Ok(Window { bytes, etag })
                }
                Ok(RangeRead::Bytes { .. }) => Err(WindowError::Unavailable),
                Ok(RangeRead::Absent) => Err(WindowError::Missing),
                Ok(RangeRead::EtagChanged) => Err(WindowError::EtagChanged),
                Err(detail) => {
                    log_failure(&format!("pack window read failed: {detail}"));
                    Err(WindowError::Unavailable)
                }
            }
        })
    }
}

/// Test-faults only: the fourth pack read of the isolate fails once, as a
/// slice the runtime kills mid-pack does. With 16 MiB windows that is the
/// second slice of a three-window pack, so the job must resume from the
/// checkpoint the first slice left.
#[cfg(feature = "test-faults")]
#[derive(Debug, Clone)]
pub struct MidPackCrash<W>(pub W);

#[cfg(feature = "test-faults")]
impl<W: PackWindows> PackWindows for MidPackCrash<W> {
    fn read<'a>(
        &'a self,
        pack: &'a Hash,
        offset: u64,
        len: u64,
        etag: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Window, WindowError>> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static READS: AtomicU32 = AtomicU32::new(0);
        if READS.fetch_add(1, Ordering::SeqCst) + 1 == 4 {
            return Box::pin(async { Err(WindowError::Unavailable) });
        }
        self.0.read(pack, offset, len, etag)
    }
}

/// Register the kind-7 handler on a Paid deployment's ref shards when
/// `indexed` asks for scheduled verification; on every other class or plan,
/// and when `indexed` is `None` (every release build), `registry` comes back
/// as it was. `remote` reaches the other partitions, `blobs` the member packs
/// and `windows` the ticketed pack itself.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn with_verification_timers<S, T, B, W>(
    registry: TimerRegistry<'static, S>,
    class: ShardClass,
    indexed: Option<IndexedConfig>,
    authority_fence: bool,
    plan: Option<&str>,
    remote: T,
    blobs: B,
    windows: W,
    clock: Arc<dyn Clock>,
    metrics: Arc<dyn Metrics>,
) -> TimerRegistry<'static, S>
where
    S: NamespaceStore,
    T: NamespaceStore + 'static,
    B: BlobStore + 'static,
    W: PackWindows + 'static,
{
    with_verification_timers_budgeted(
        registry,
        class,
        indexed,
        authority_fence,
        plan,
        remote,
        blobs,
        windows,
        clock,
        metrics,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn with_verification_timers_budgeted<S, T, B, W>(
    registry: TimerRegistry<'static, S>,
    class: ShardClass,
    indexed: Option<IndexedConfig>,
    authority_fence: bool,
    plan: Option<&str>,
    remote: T,
    blobs: B,
    windows: W,
    clock: Arc<dyn Clock>,
    metrics: Arc<dyn Metrics>,
    alarm_budget: Option<mkit_server::purge::SliceBudget>,
) -> TimerRegistry<'static, S>
where
    S: NamespaceStore,
    T: NamespaceStore + 'static,
    B: BlobStore + 'static,
    W: PackWindows + 'static,
{
    let paid = plan.is_some_and(|plan| plan.trim().eq_ignore_ascii_case("paid"));
    let Some(cfg) = indexed.filter(|cfg| cfg.verification == VerificationMode::Scheduled) else {
        return registry;
    };
    if class != ShardClass::RefShard || !paid {
        return registry;
    }
    registry.register(crate::purge::Budgeted {
        handler: VerifyTimer {
            remote,
            blobs,
            windows,
            shards: Arc::new(D34Shards),
            cfg,
            // Default slices use indexed::geometry, shared with inline and preservation.
            limits: SliceLimits::default(),
            lease: LeaseParams {
                authority_fence,
                ..LeaseParams::default()
            },
            clock,
            metrics,
            extension: FailClosedExtraction,
        },
        budget: alarm_budget,
        calls: 256,
    })
}

/// [`with_verification_timers`] for a Durable Object of `env`: the handler's
/// stores are the deployment's namespace client and R2 bucket. A deployment
/// whose vars ask for no indexed mode gets `registry` back untouched.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn register_from_env<S: NamespaceStore>(
    registry: TimerRegistry<'static, S>,
    env: &worker::Env,
    class: ShardClass,
    plan: Option<&str>,
) -> TimerRegistry<'static, S> {
    register_from_env_budgeted(registry, env, class, plan, None)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn register_from_env_budgeted<S: NamespaceStore>(
    registry: TimerRegistry<'static, S>,
    env: &worker::Env,
    class: ShardClass,
    plan: Option<&str>,
    alarm_budget: Option<mkit_server::purge::SliceBudget>,
) -> TimerRegistry<'static, S> {
    let Ok(cfg) = crate::adapter::WorkerConfig::from_env(env) else {
        return registry;
    };
    register_configured_budgeted(registry, env, class, plan, alarm_budget, &cfg)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn register_configured_budgeted<S: NamespaceStore>(
    registry: TimerRegistry<'static, S>,
    env: &worker::Env,
    class: ShardClass,
    plan: Option<&str>,
    alarm_budget: Option<mkit_server::purge::SliceBudget>,
    cfg: &crate::adapter::WorkerConfig,
) -> TimerRegistry<'static, S> {
    use crate::clock::WorkerClock;
    use crate::ns_client::{StubTransport, WorkerNamespaceStore};
    use crate::r2::{EnvBucket, R2BlobStore};
    use crate::telemetry::ConsoleMetrics;

    let bucket = || EnvBucket::new(env.clone(), cfg.blob_binding);
    let probe = cfg.probe_partition();
    #[cfg(feature = "test-faults")]
    let windows = MidPackCrash(R2Windows(bucket()));
    #[cfg(not(feature = "test-faults"))]
    let windows = R2Windows(bucket());
    let Some(indexed) = cfg
        .indexed
        .filter(|c| c.verification == VerificationMode::Scheduled)
    else {
        return registry;
    };
    if class != ShardClass::RefShard || !plan.is_some_and(|p| p.trim().eq_ignore_ascii_case("paid"))
    {
        return registry;
    }
    let blobs = R2BlobStore::new(bucket(), PACKS_KEYSPACE);
    registry.register(crate::purge::Budgeted {
        handler: VerifyTimer {
            remote: WorkerNamespaceStore::new(
                StubTransport::new(env.clone(), cfg.placement.clone()),
                probe,
            ),
            extension: R2Extraction(blobs.clone()),
            blobs,
            windows,
            shards: Arc::new(D34Shards),
            cfg: indexed,
            // Default slices use indexed::geometry, shared with inline and preservation.
            limits: SliceLimits::default(),
            lease: LeaseParams {
                authority_fence: cfg.authority_fence.is_some(),
                ..LeaseParams::default()
            },
            clock: Arc::new(WorkerClock),
            metrics: Arc::new(ConsoleMetrics::default()),
        },
        budget: alarm_budget,
        calls: 256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r2::{ObjectPage, ObjectStream, PutBody, PutResult};
    use futures::channel::oneshot;
    use futures::executor::block_on;
    use mkit_core::hash::hash;
    use mkit_server::telemetry::NoopMetrics;
    use mkit_server::{ManualClock, MemoryBlobStore, MemoryKv};
    use std::ops::Range;
    use std::sync::Mutex;

    type Read = (Range<u64>, Option<String>);

    /// One object with an etag that changes when `replace` is called.
    #[derive(Clone, Default)]
    struct Bucket {
        object: Arc<Mutex<(Vec<u8>, u32)>>,
        reads: Arc<Mutex<Vec<Read>>>,
    }

    impl Bucket {
        fn replace(&self, bytes: Vec<u8>) {
            let mut object = self.object.lock().unwrap();
            *object = (bytes, object.1 + 1);
        }
    }

    impl ObjectBucket for Bucket {
        fn spawn_put(&self, _: String, _: u64, _: PutBody) -> oneshot::Receiver<PutResult> {
            oneshot::channel().1
        }
        async fn head(&self, _: &str) -> Result<Option<u64>, String> {
            Ok(None)
        }
        async fn get(
            &self,
            _: &str,
            _: Option<Range<u64>>,
        ) -> Result<Option<(u64, ObjectStream)>, String> {
            Ok(None)
        }
        async fn get_range_etag(
            &self,
            key: &str,
            range: Range<u64>,
            etag: Option<&str>,
        ) -> Result<RangeRead, String> {
            self.reads
                .lock()
                .unwrap()
                .push((range.clone(), etag.map(str::to_owned)));
            let (bytes, generation) = self.object.lock().unwrap().clone();
            if bytes.is_empty() || !key.starts_with("packs/") {
                return Ok(RangeRead::Absent);
            }
            let current = format!("etag-{generation}");
            if etag.is_some_and(|expected| expected != current) {
                return Ok(RangeRead::EtagChanged);
            }
            let (start, end) = (
                usize::try_from(range.start).unwrap(),
                usize::try_from(range.end).unwrap(),
            );
            Ok(RangeRead::Bytes {
                bytes: bytes[start..end.min(bytes.len())].to_vec(),
                etag: current,
            })
        }
        async fn delete(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
        async fn list(&self, _: &str, _: Option<&str>) -> Result<ObjectPage, String> {
            Ok(ObjectPage {
                keys: Vec::new(),
                cursor: None,
            })
        }
        async fn delete_many(&self, _: Vec<String>) -> Result<(), String> {
            Ok(())
        }
        async fn probe(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn windows_are_bound_to_the_first_etag() {
        let bucket = Bucket::default();
        let pack = (0..=255_u8).cycle().take(1_000).collect::<Vec<u8>>();
        bucket.replace(pack.clone());
        let windows = R2Windows(bucket.clone());
        let id = hash(&pack);
        let first = block_on(windows.read(&id, 0, 400, None)).unwrap();
        assert_eq!(
            (first.bytes.as_slice(), first.etag.as_str()),
            (&pack[..400], "etag-1")
        );
        // The same etag reads on; the request carries it and the exact range.
        let second = block_on(windows.read(&id, 400, 600, Some(&first.etag))).unwrap();
        assert_eq!(second.bytes, pack[400..]);
        assert_eq!(
            bucket.reads.lock().unwrap()[1],
            (400..1000, Some("etag-1".to_owned()))
        );
        // A replaced object is never served under the old etag.
        bucket.replace(vec![9; 1_000]);
        assert_eq!(
            block_on(windows.read(&id, 0, 400, Some(&first.etag))).unwrap_err(),
            WindowError::EtagChanged
        );
        // A range the object cannot fill is a failure, not a short window.
        assert_eq!(
            block_on(windows.read(&id, 900, 400, None)).unwrap_err(),
            WindowError::Unavailable
        );
        bucket.replace(Vec::new());
        assert_eq!(
            block_on(windows.read(&id, 0, 4, None)).unwrap_err(),
            WindowError::Missing
        );
    }

    #[test]
    fn a_bucket_without_conditional_reads_fails_closed() {
        #[derive(Clone)]
        struct Plain;
        impl ObjectBucket for Plain {
            fn spawn_put(&self, _: String, _: u64, _: PutBody) -> oneshot::Receiver<PutResult> {
                oneshot::channel().1
            }
            async fn head(&self, _: &str) -> Result<Option<u64>, String> {
                Ok(None)
            }
            async fn get(
                &self,
                _: &str,
                _: Option<Range<u64>>,
            ) -> Result<Option<(u64, ObjectStream)>, String> {
                Ok(None)
            }
            async fn delete(&self, _: &str) -> Result<(), String> {
                Ok(())
            }
            async fn list(&self, _: &str, _: Option<&str>) -> Result<ObjectPage, String> {
                Ok(ObjectPage {
                    keys: Vec::new(),
                    cursor: None,
                })
            }
            async fn delete_many(&self, _: Vec<String>) -> Result<(), String> {
                Ok(())
            }
            async fn probe(&self) -> Result<(), String> {
                Ok(())
            }
        }
        assert_eq!(
            block_on(R2Windows(Plain).read(&[1; 32], 0, 4, None)).unwrap_err(),
            WindowError::Unavailable
        );
    }

    fn scheduled() -> IndexedConfig {
        IndexedConfig::scheduled(1 << 30)
    }

    fn kinds(class: ShardClass, indexed: Option<IndexedConfig>, plan: Option<&str>) -> String {
        let registry = with_verification_timers(
            TimerRegistry::<MemoryKv>::new(),
            class,
            indexed,
            false,
            plan,
            MemoryKv::default(),
            MemoryBlobStore::default(),
            R2Windows(Bucket::default()),
            Arc::new(ManualClock::new(0)),
            Arc::new(NoopMetrics),
        );
        format!("{registry:?}")
    }

    #[test]
    fn kind_7_is_registered_on_paid_ref_shards_of_scheduled_deployments_only() {
        let seven = "TimerKind(7)";
        assert!(kinds(ShardClass::RefShard, Some(scheduled()), Some("paid")).contains(seven));
        assert!(kinds(ShardClass::RefShard, Some(scheduled()), Some(" Paid ")).contains(seven));
        // Free cannot run indexed mode: R-147 assigned every subrequest.
        for plan in [None, Some("free"), Some("bogus")] {
            assert!(
                !kinds(ShardClass::RefShard, Some(scheduled()), plan).contains(seven),
                "{plan:?}"
            );
        }
        for class in [
            ShardClass::RefStore,
            ShardClass::NsCoordinator,
            ShardClass::RepoIndexShard,
            ShardClass::ContentIndexShard,
        ] {
            assert!(
                !kinds(class, Some(scheduled()), Some("paid")).contains(seven),
                "{class:?}"
            );
        }
        // No indexed config (every release build) or an inline one: unchanged.
        assert!(!kinds(ShardClass::RefShard, None, Some("paid")).contains(seven));
        assert!(
            !kinds(
                ShardClass::RefShard,
                Some(IndexedConfig::default()),
                Some("paid")
            )
            .contains(seven)
        );
    }
}
