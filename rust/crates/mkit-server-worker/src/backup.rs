//! Per-Durable-Object portable snapshots. The read phase polls only synchronous
//! `SqlKvStore` futures; the first external await is the R2 upload.

use core::future::Future;
use mkit_core::hash::{hash, to_hex_bytes};
use mkit_server::store::codec::{BackupStateV1, decode_backup_state, encode_backup_state};
use mkit_server::store::keys::{self, ParsedKey};
use mkit_server::store::{
    EXPORT_END, encode_export_header, encode_export_record, export_header, export_page,
};
use mkit_server::timers::registry::kinds;
use mkit_server::timers::{DueTimer, Fired, TimerCtx, TimerHandler, TimerKind};
use mkit_server::{
    Batch, BoxFuture, MaybeSend, MaybeSync, NamespaceStore, Partition, Precondition, StoreError,
    Value,
};

/// Optional Worker R2 binding for snapshots.
pub const BACKUPS_BINDING: &str = "BACKUPS";
/// One snapshot per partition per day by default.
pub const DEFAULT_INTERVAL_MS: u64 = 24 * 60 * 60 * 1000;
/// Maximum encoded snapshot buffered in an isolate.
pub const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Force a new R2 object before the default 35-day retention expires.
pub const DEFAULT_FORCE_REUPLOAD_MS: u64 = 28 * 24 * 60 * 60 * 1000;
const PAGE_SIZE: u32 = 256;
const HEADER_EXPORTED_AT_OFFSET: usize = 8 + 1 + 4;

/// A bucket capable of uploading a complete snapshot with custom metadata.
pub trait BackupBucket: Clone + MaybeSend + MaybeSync + 'static {
    /// Put one complete object. A repeated put of the same key is idempotent.
    fn put<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
        partition_hex: &'a str,
    ) -> impl Future<Output = Result<(), String>> + MaybeSend;
}

/// Runtime settings, parsed in the Worker adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupConfig {
    /// Milliseconds between attempts; zero disables backups.
    pub interval_ms: u64,
    /// Encoded-byte cap.
    pub max_bytes: usize,
    /// Maximum age of the most recent upload when content is unchanged.
    pub force_reupload_ms: u64,
    /// R2 key component identifying the deployment.
    pub prefix: String,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            interval_ms: DEFAULT_INTERVAL_MS,
            max_bytes: DEFAULT_MAX_BYTES,
            force_reupload_ms: DEFAULT_FORCE_REUPLOAD_MS,
            prefix: "mkit-vcs-worker".into(),
        }
    }
}

impl BackupConfig {
    /// Parse optional environment variables. The prefix stays one safe key
    /// component and is bounded independently of the partition hash.
    pub fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        fn number<T: core::str::FromStr>(
            var: &impl Fn(&str) -> Option<String>,
            name: &str,
            default: T,
        ) -> Result<T, String> {
            var(name).map_or(Ok(default), |v| {
                v.parse()
                    .map_err(|_| format!("{name} must be a nonnegative integer"))
            })
        }
        let mut config = Self::default();
        config.interval_ms = number(&var, "BACKUP_INTERVAL_MS", config.interval_ms)?;
        config.max_bytes = number(&var, "BACKUP_MAX_BYTES", config.max_bytes)?;
        config.force_reupload_ms =
            number(&var, "BACKUP_FORCE_REUPLOAD_MS", config.force_reupload_ms)?;
        if let Some(prefix) = var("BACKUP_PREFIX") {
            if prefix.is_empty()
                || prefix.len() > 128
                || !prefix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                return Err("BACKUP_PREFIX must be 1..128 ASCII letters, digits, dots, underscores or hyphens".into());
            }
            config.prefix = prefix;
        }
        if config.max_bytes == 0 || config.max_bytes > 64 * 1024 * 1024 {
            return Err("BACKUP_MAX_BYTES must be in 1..=67108864".into());
        }
        if config.force_reupload_ms == 0 {
            return Err("BACKUP_FORCE_REUPLOAD_MS must be positive".into());
        }
        Ok(config)
    }
}

/// Seed state and a timer after a committed Put. The caller bypasses its own
/// post-commit hook by applying this batch directly to the underlying store.
#[must_use]
pub fn seed_batch(now_ms: u64, interval_ms: u64) -> Batch {
    let state = BackupStateV1 {
        last_export_ms: 0,
        digest: [0; 32],
        r2_key: String::new(),
        last_upload_ms: 0,
    };
    Batch::new()
        .require(Precondition::Absent(keys::backup_state()))
        .put(keys::backup_state(), encode_backup_state(&state))
        .put(
            keys::timer(now_ms.saturating_add(interval_ms), kinds::BACKUP.get(), b""),
            Value::new(Vec::new()),
        )
}

/// The scheduled-time key of the first backup after `now_ms`.
#[must_use]
pub fn seeded_due(now_ms: u64, interval_ms: u64) -> u64 {
    now_ms.saturating_add(interval_ms)
}

/// R2 object key. The partition bytes live both in metadata and each record.
pub fn object_key(
    prefix: &str,
    partition: &Partition,
    at_ms: u64,
    digest: &[u8; 32],
) -> Result<String, StoreError> {
    let partition_hash = hash(&partition.encode()?);
    let digest_hex = to_hex_bytes(digest);
    let key = format!(
        "backups/v1/{prefix}/{}/{}/{at_ms:013}-{}.kvlog",
        partition.kind(),
        to_hex_bytes(&partition_hash),
        &digest_hex[..16],
    );
    if key.len() > 1024 {
        return Err(StoreError::Invalid(
            "backup R2 key exceeds 1024 bytes".into(),
        ));
    }
    Ok(key)
}

enum Snapshot {
    Bytes(Vec<u8>),
    Oversize(usize),
}

/// Read every page in one uninterrupted poll chain. No R2 call or JS promise
/// is made until the entire encoded partition is in memory.
async fn snapshot<S: NamespaceStore>(
    store: &S,
    p: &Partition,
    header_ms: u64,
    cap: usize,
) -> Result<Snapshot, StoreError> {
    let header = export_header(store, p, header_ms).await?;
    let mut out = encode_export_header(&header).to_vec();
    if out.len() + EXPORT_END.len() > cap {
        return Ok(Snapshot::Oversize(out.len() + EXPORT_END.len()));
    }
    let mut after = None;
    loop {
        let page = export_page(store, p, after.as_ref(), PAGE_SIZE).await?;
        for record in page.records {
            if record.key == keys::backup_state()
                || matches!(keys::parse(&record.key), Some(ParsedKey::Timer { kind, .. }) if kind == kinds::BACKUP.get())
            {
                continue;
            }
            let encoded = encode_export_record(&record)?;
            let next = out
                .len()
                .saturating_add(encoded.len())
                .saturating_add(EXPORT_END.len());
            if next > cap {
                return Ok(Snapshot::Oversize(next));
            }
            out.extend_from_slice(&encoded);
        }
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    out.extend_from_slice(&EXPORT_END);
    Ok(Snapshot::Bytes(out))
}

/// Test-only single-DO export, using the same uninterrupted read as the timer.
#[cfg(feature = "test-faults")]
pub async fn test_snapshot<S: NamespaceStore>(
    store: &S,
    p: &Partition,
) -> Result<Vec<u8>, StoreError> {
    match snapshot(store, p, 0, DEFAULT_MAX_BYTES).await? {
        Snapshot::Bytes(bytes) => Ok(bytes),
        Snapshot::Oversize(_) => Err(StoreError::Invalid(
            "test snapshot exceeds backup cap".into(),
        )),
    }
}

/// One partition's daily backup timer.
/// A repeated fire after an uploaded object's state commit loses a race may
/// create another immutable snapshot. Only the guarded state row selects the
/// committed object; the `backups/` lifecycle removes unreferenced extras.
#[derive(Debug, Clone)]
pub struct BackupHandler<B> {
    bucket: B,
    config: BackupConfig,
}

impl<B: BackupBucket> BackupHandler<B> {
    /// Bind the bucket and settings at Durable Object construction.
    #[must_use]
    pub fn new(bucket: B, config: BackupConfig) -> Self {
        Self { bucket, config }
    }

    async fn fire_inner<S: NamespaceStore>(
        &self,
        ctx: &TimerCtx<'_, S>,
    ) -> Result<Fired, StoreError> {
        let state_key = keys::backup_state();
        let old_value = ctx.store.get(ctx.partition, &state_key).await?;
        let old = old_value.as_ref().map(decode_backup_state).transpose()?;
        let header_ms = old
            .as_ref()
            .map_or(ctx.now_ms, |state| state.last_export_ms);
        let mut bytes =
            match snapshot(ctx.store, ctx.partition, header_ms, self.config.max_bytes).await? {
                Snapshot::Bytes(bytes) => bytes,
                Snapshot::Oversize(size) => {
                    tracing::warn!(
                        kind = ctx.partition.kind(),
                        bytes = size,
                        "backup_skipped_oversize"
                    );
                    return Ok(self.reschedule(Batch::new(), ctx.now_ms));
                }
            };
        let candidate = hash(&bytes);
        if old.as_ref().is_some_and(|state| {
            !state.r2_key.is_empty()
                && state.digest == candidate
                && ctx.now_ms.saturating_sub(state.last_upload_ms) < self.config.force_reupload_ms
        }) {
            return Ok(self.reschedule(Batch::new(), ctx.now_ms));
        }
        bytes[HEADER_EXPORTED_AT_OFFSET..HEADER_EXPORTED_AT_OFFSET + 8]
            .copy_from_slice(&ctx.now_ms.to_be_bytes());
        let digest = hash(&bytes);
        let r2_key = object_key(&self.config.prefix, ctx.partition, ctx.now_ms, &digest)?;
        let partition_hex = to_hex_bytes(&ctx.partition.encode()?);
        if let Err(error) = self.bucket.put(&r2_key, &bytes, &partition_hex).await {
            tracing::warn!(detail = %error, "backup R2 upload failed");
            return Ok(Fired::Retry);
        }
        let state = BackupStateV1 {
            last_export_ms: ctx.now_ms,
            digest,
            r2_key,
            last_upload_ms: ctx.now_ms,
        };
        let guard = match old_value {
            Some(value) => Precondition::Equals(state_key.clone(), value),
            None => Precondition::Absent(state_key.clone()),
        };
        let batch = Batch::new()
            .require(guard)
            .put(state_key, encode_backup_state(&state));
        Ok(self.reschedule(batch, ctx.now_ms))
    }

    fn reschedule(&self, batch: Batch, now_ms: u64) -> Fired {
        Fired::Reschedule {
            due_at_ms: seeded_due(now_ms, self.config.interval_ms),
            value: Value::new(Vec::new()),
            batch,
        }
    }
}

impl<S: NamespaceStore, B: BackupBucket> TimerHandler<S> for BackupHandler<B> {
    fn kind(&self) -> TimerKind {
        kinds::BACKUP
    }

    fn fire<'a>(
        &'a self,
        ctx: &'a TimerCtx<'a, S>,
        _timer: &'a DueTimer,
    ) -> BoxFuture<'a, Result<Fired, StoreError>> {
        Box::pin(self.fire_inner(ctx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::channel::oneshot;
    use futures::executor::block_on;
    use futures::task::noop_waker;
    use mkit_server::store::ExportReader;
    use mkit_server::timers::{TickBudget, TimerRegistry, run_due};
    use mkit_server::{ManualClock, MemoryKv, NamespaceKey};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Instant;

    type Uploaded = (String, Vec<u8>, String);

    #[derive(Clone, Default)]
    struct Bucket {
        objects: Arc<Mutex<Vec<Uploaded>>>,
        pause: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
    }

    impl BackupBucket for Bucket {
        async fn put(&self, key: &str, bytes: &[u8], partition_hex: &str) -> Result<(), String> {
            self.objects
                .lock()
                .unwrap()
                .push((key.into(), bytes.to_vec(), partition_hex.into()));
            let paused = self.pause.lock().unwrap().take();
            if let Some(receiver) = paused {
                receiver.await.map_err(|_| "put canceled".to_owned())?;
            }
            Ok(())
        }
    }

    fn part() -> Partition {
        Partition::Namespace(NamespaceKey::deployment_default())
    }

    fn put(store: &MemoryKv, key: &[u8], value: Vec<u8>) {
        block_on(store.apply(
            &part(),
            Batch::new().put(mkit_server::Key::new(key.to_vec()), Value::new(value)),
        ))
        .unwrap();
    }

    fn due(store: &MemoryKv, at: u64) {
        put(
            store,
            keys::timer(at, kinds::BACKUP.get(), b"").as_bytes(),
            Vec::new(),
        );
    }

    fn registry(bucket: Bucket, config: BackupConfig) -> TimerRegistry<MemoryKv> {
        TimerRegistry::new().register(BackupHandler::new(bucket, config))
    }

    fn tick(store: &MemoryKv, registry: &TimerRegistry<MemoryKv>, clock: &ManualClock, now: u64) {
        assert_eq!(
            block_on(run_due(
                store,
                &part(),
                registry,
                clock,
                now,
                &TickBudget::default()
            ))
            .unwrap()
            .fired,
            1
        );
    }

    #[test]
    fn snapshot_finishes_before_r2_await_and_excludes_backup_rows() {
        let store = MemoryKv::default();
        put(&store, b"r\0old", b"before".to_vec());
        put(
            &store,
            keys::backup_state().as_bytes(),
            encode_backup_state(&BackupStateV1 {
                last_export_ms: 0,
                digest: [0; 32],
                r2_key: String::new(),
                last_upload_ms: 0,
            })
            .as_bytes()
            .to_vec(),
        );
        due(&store, 100);
        let (release, receiver) = oneshot::channel();
        let bucket = Bucket::default();
        *bucket.pause.lock().unwrap() = Some(receiver);
        let registry = registry(bucket.clone(), BackupConfig::default());
        let clock = ManualClock::new(100);
        let partition = part();
        let budget = TickBudget::default();
        let mut running = Box::pin(run_due(&store, &partition, &registry, &clock, 100, &budget));
        let waker = noop_waker();
        assert!(matches!(
            running.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Pending
        ));
        assert_eq!(
            bucket.objects.lock().unwrap().len(),
            1,
            "upload begins only after the complete read"
        );
        put(&store, b"r\0new", b"after".to_vec());
        release.send(()).unwrap();
        assert_eq!(block_on(running).unwrap().fired, 1);
        let uploaded = &bucket.objects.lock().unwrap()[0].1;
        let (_, records) = ExportReader::new(uploaded).unwrap();
        let keys: Vec<_> = records
            .map(|row| row.unwrap().key.into_bytes().to_vec())
            .collect();
        assert!(keys.contains(&b"r\0old".to_vec()));
        assert!(!keys.contains(&b"r\0new".to_vec()));
        assert!(!keys.contains(&keys::backup_state().as_bytes().to_vec()));
        assert!(!keys.iter().any(|key| key.starts_with(b"w\0")));
    }

    #[test]
    fn unchanged_digest_skips_until_force_reupload() {
        let store = MemoryKv::default();
        put(&store, b"r\0a", b"value".to_vec());
        due(&store, 100);
        let bucket = Bucket::default();
        let config = BackupConfig {
            interval_ms: 10,
            force_reupload_ms: 25,
            ..BackupConfig::default()
        };
        let registry = registry(bucket.clone(), config);
        let clock = ManualClock::new(100);
        tick(&store, &registry, &clock, 100);
        assert_eq!(bucket.objects.lock().unwrap().len(), 1);
        clock.set(110);
        tick(&store, &registry, &clock, 110);
        assert_eq!(bucket.objects.lock().unwrap().len(), 1);
        clock.set(120);
        tick(&store, &registry, &clock, 120);
        assert_eq!(bucket.objects.lock().unwrap().len(), 1);
        clock.set(130);
        tick(&store, &registry, &clock, 130);
        assert_eq!(bucket.objects.lock().unwrap().len(), 2);
    }

    #[test]
    fn oversize_reschedules_without_upload() {
        let store = MemoryKv::default();
        put(&store, b"r\0a", vec![3; 2000]);
        due(&store, 100);
        let bucket = Bucket::default();
        let registry = registry(
            bucket.clone(),
            BackupConfig {
                max_bytes: 1024,
                interval_ms: 10,
                ..BackupConfig::default()
            },
        );
        let clock = ManualClock::new(100);
        tick(&store, &registry, &clock, 100);
        assert!(bucket.objects.lock().unwrap().is_empty());
        let next =
            block_on(store.get(&part(), &keys::timer(110, kinds::BACKUP.get(), b""))).unwrap();
        assert!(next.is_some());
    }

    #[test]
    fn longest_partition_uses_a_short_r2_key() {
        let encoded = format!(
            "r{}\0{}\0{}\0",
            "n".repeat(72),
            "r".repeat(255),
            "x".repeat(mkit_server::refs::MAX_REF_NAME_BYTES)
        );
        let p = Partition::decode(encoded.as_bytes()).unwrap();
        assert!(
            object_key(&"p".repeat(128), &p, u64::MAX, &[0xff; 32])
                .unwrap()
                .len()
                <= 1024
        );
    }

    #[test]
    fn sixteen_megabyte_host_snapshot_under_five_seconds() {
        let store = MemoryKv::default();
        for n in 0..32u8 {
            put(&store, &[b'r', 0, n], vec![n; 500 * 1024]);
        }
        due(&store, 100);
        let bucket = Bucket::default();
        let registry = registry(bucket.clone(), BackupConfig::default());
        let clock = ManualClock::new(100);
        let start = Instant::now();
        tick(&store, &registry, &clock, 100);
        let elapsed = start.elapsed();
        let bytes = bucket.objects.lock().unwrap()[0].1.len();
        eprintln!("16 MiB backup host fire: {bytes} bytes in {elapsed:?}");
        assert!(bytes > 15 * 1024 * 1024);
        assert!(
            elapsed.as_secs_f64() < 5.0,
            "backup fire exceeded ~5 s budget: {elapsed:?}"
        );
    }
}
