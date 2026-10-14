//! Durable publication invalidation before source writes, with proven completion.
//!
//! Default factories and readers do not enable this core. Bootstrap readiness is an
//! integration-owned assertion: reconciliation must fence every legacy writer
//! and relay before writing it. Incarnations must come from authority outside an
//! imported snapshot; incrementing a restored generation alone cannot prevent ABA.
use mkit_core::hash::{Hash, hash};
use serde::{Deserialize, Serialize};

use super::{
    Batch, BatchOutcome, Key, NamespaceStore, Partition, Precondition, StoreError, Value, codec,
    keys,
};
use crate::repo::RepoId;

/// Maximum distinct projection destinations in one intent.
pub const MAX_TARGETS: usize = 16;
const MAX_ROW_BYTES: usize = 32 * 1024;
const MAX_PARTITION_BYTES: usize = 1024;

/// Recovery identity. The incarnation is never reused, including after restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generation {
    /// Allocated outside restored state; callers must guarantee uniqueness.
    pub incarnation: Hash,
    /// Strictly increasing within an incarnation.
    pub number: u64,
}

/// Equality token for a complete, sealed publication observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StableToken {
    /// Recovery identity.
    pub generation: Generation,
    /// Never wraps or decreases within this recovery identity.
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    generation: Generation,
    revision: u64,
    pending: u64,
    sealed: bool,
}

/// A projection watermark allocated in the guarded source transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    partition: Vec<u8>,
    watermark: u64,
}
impl Target {
    /// Projection destination bound into the source publication plan.
    pub fn partition(&self) -> Result<Partition, StoreError> {
        Partition::decode(&self.partition)
    }
    /// Source relay sequence whose target transaction must commit.
    #[must_use]
    pub fn watermark(&self) -> u64 {
        self.watermark
    }
    /// Bind an exact target partition and its required source relay watermark.
    pub fn new(partition: &Partition, watermark: u64) -> Result<Self, StoreError> {
        if watermark == 0 {
            return Err(invalid("zero publication target watermark"));
        }
        let partition = partition.encode()?.to_vec();
        if partition.len() > MAX_PARTITION_BYTES {
            return Err(invalid("publication target too long"));
        }
        Ok(Self {
            partition,
            watermark,
        })
    }
}

/// Exact durable identity returned only after coordinator invalidation commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    generation: Generation,
    source: Vec<u8>,
    attempt: u64,
    digest: Hash,
    targets: Vec<Target>,
}
impl Intent {
    /// Source attempt; this never resets when generations rotate.
    #[must_use]
    pub fn attempt(&self) -> u64 {
        self.attempt
    }
    /// Recovery identity bound to this intent.
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }
    /// Proposed paired publication plan digest.
    #[must_use]
    pub fn digest(&self) -> Hash {
        self.digest
    }
    /// Source partition that must contain the guarded terminal marker.
    pub fn source(&self) -> Result<Partition, StoreError> {
        Partition::decode(&self.source)
    }
    /// Exact required projection destinations and watermarks.
    #[must_use]
    pub fn targets(&self) -> &[Target] {
        &self.targets
    }
    fn validate(&self) -> Result<(), StoreError> {
        if self.attempt == 0
            || self.source.len() > MAX_PARTITION_BYTES
            || self.targets.len() > MAX_TARGETS
        {
            return Err(invalid("unbounded publication intent"));
        }
        Partition::decode(&self.source)?;
        for (index, target) in self.targets.iter().enumerate() {
            if target.watermark == 0
                || target.partition.len() > MAX_PARTITION_BYTES
                || self.targets[..index]
                    .iter()
                    .any(|old| old.partition == target.partition)
            {
                return Err(invalid("invalid publication targets"));
            }
            Partition::decode(&target.partition)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Disposition {
    Armed,
    Committed,
    Aborted,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceMarker {
    intent: Intent,
    disposition: Disposition,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    intent: Intent,
    source: Option<Disposition>,
    receipts: u16,
    complete: bool,
}
impl Row {
    fn validate(&self) -> Result<(), StoreError> {
        self.intent.validate()?;
        let mask = mask(self.intent.targets.len());
        if self.receipts & !mask != 0
            || self.source == Some(Disposition::Armed)
            || self.complete
                != (self.source == Some(Disposition::Aborted)
                    || self.source == Some(Disposition::Committed) && self.receipts == mask)
        {
            return Err(invalid("inconsistent publication disposition"));
        }
        Ok(())
    }
}

/// Typed status observed from the durable local source marker.
/// This observation is not a completion receipt or permission to mutate it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    /// Publication or irreversible abort must still win the guarded source CAS.
    Armed,
    /// The exact publication transaction committed with its terminal marker.
    Committed,
    /// Every prepared commit using the old armed marker is irreversibly fenced.
    Aborted,
}
impl From<Disposition> for SourceStatus {
    fn from(value: Disposition) -> Self {
        match value {
            Disposition::Armed => Self::Armed,
            Disposition::Committed => Self::Committed,
            Disposition::Aborted => Self::Aborted,
        }
    }
}
/// Latest coordinator record for one source, including an older generation.
/// Read it freshly before selecting a monotonic source attempt; the observation
/// is not a lock and the existing begin CAS still resolves concurrent writers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorIntent {
    intent: Intent,
    complete: bool,
}
impl CoordinatorIntent {
    /// Exact binding needed to recover a crash before local arming.
    #[must_use]
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    /// Whether this coordinator record accepted proven terminal completion.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.complete
    }
}
/// Durable local source observation, distinct from a verified receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSourceMarker {
    intent: Intent,
    status: SourceStatus,
}
impl LocalSourceMarker {
    /// Exact binding recorded in the local guarded transaction.
    #[must_use]
    pub fn intent(&self) -> &Intent {
        &self.intent
    }
    /// Current durable local disposition.
    #[must_use]
    pub fn status(&self) -> SourceStatus {
        self.status
    }
}

/// Receipt verified by reading an immutable terminal source marker.
/// Fields are private: an arbitrary boolean cannot complete an intent.
#[derive(Debug, Clone)]
pub struct SourceReceipt {
    intent: Intent,
    disposition: Disposition,
}
impl SourceReceipt {
    /// Read the terminal marker written in the same transaction as publication,
    /// or by the irreversible guarded abort. Never accepts an armed marker.
    pub async fn verify<S: NamespaceStore>(store: &S, intent: &Intent) -> Result<Self, StoreError> {
        let source = Partition::decode(&intent.source)?;
        let value = store
            .get(&source, &source_key())
            .await?
            .ok_or_else(|| invalid("missing source receipt"))?;
        let marker: SourceMarker = decode(&value)?;
        marker.intent.validate()?;
        if marker.intent != *intent || marker.disposition == Disposition::Armed {
            return Err(invalid("unproven source disposition"));
        }
        Ok(Self {
            intent: intent.clone(),
            disposition: marker.disposition,
        })
    }
}
/// Receipt verified against the SDK target's durable source relay watermark.
#[derive(Debug, Clone)]
pub struct TargetReceipt {
    intent: Intent,
    index: usize,
}
impl TargetReceipt {
    /// The watermark and target are bound by the proposed publication digest
    /// and the exact committed source marker. Targets may arrive before that
    /// source receipt is delivered to the coordinator, but cannot finish alone.
    pub async fn verify<S: NamespaceStore>(
        store: &S,
        intent: &Intent,
        index: usize,
    ) -> Result<Self, StoreError> {
        intent.validate()?;
        if SourceReceipt::verify(store, intent).await?.disposition != Disposition::Committed {
            return Err(invalid("aborted source cannot prove projection delivery"));
        }
        let target = intent
            .targets
            .get(index)
            .ok_or_else(|| invalid("unknown publication target"))?;
        let source = Partition::decode(&intent.source)?;
        let partition = Partition::decode(&target.partition)?;
        let value = store
            .get(&partition, &keys::relay_high_water(&source)?)
            .await?
            .ok_or_else(|| invalid("missing projection receipt"))?;
        if codec::decode_u64(&value)? < target.watermark {
            return Err(invalid("projection not delivered"));
        }
        Ok(Self {
            intent: intent.clone(),
            index,
        })
    }
}
/// Explicit integration-owned bootstrap evidence, read from durable storage.
/// Writing readiness is not proof that reconciliation actually ran.
#[derive(Debug, Clone)]
pub struct BootstrapReceipt {
    generation: Generation,
    revision: u64,
    coordinator: Partition,
    scope: Hash,
    ready: Value,
}

struct BeginRequest {
    attempt: u64,
    digest: Hash,
    targets: Vec<Target>,
    recovery_due_at_ms: Option<u64>,
}

/// One repository's coordinator authority; each source has a separate row.
#[derive(Debug)]
pub struct PublicationFence {
    coordinator: Partition,
    scope: Hash,
    repo: RepoId,
}
impl PublicationFence {
    /// Construct a repository-scoped authority in its namespace coordinator.
    #[must_use]
    pub fn new(repo: &RepoId) -> Self {
        Self {
            coordinator: Partition::Coordinator(repo.namespace.clone()),
            scope: hash(repo.name.as_str().as_bytes()),
            repo: repo.clone(),
        }
    }
    fn key(&self, tag: &[u8], suffix: &[u8]) -> Key {
        let mut bytes = tag.to_vec();
        bytes.extend_from_slice(&self.scope);
        bytes.extend_from_slice(suffix);
        Key::new(bytes)
    }
    fn root_key(&self) -> Key {
        self.key(b"pf\0", &[])
    }
    fn row_key(&self, source: &[u8]) -> Key {
        self.key(b"pi\0", &hash(source))
    }
    fn ready_key(&self) -> Key {
        self.key(b"pb\0", &[])
    }
    async fn root<S: NamespaceStore>(&self, store: &S) -> Result<(Value, Root), StoreError> {
        let value = store
            .get(&self.coordinator, &self.root_key())
            .await?
            .ok_or_else(|| invalid("publication fence not initialized"))?;
        let root: Root = decode(&value)?;
        Ok((value, root))
    }
    /// Read the current coordinator recovery identity, even while unsealed.
    ///
    /// # Errors
    /// Refuses an absent, corrupt or unavailable authority.
    pub async fn generation<S: NamespaceStore>(&self, store: &S) -> Result<Generation, StoreError> {
        Ok(self.root(store).await?.1.generation)
    }
    fn check_source(&self, source: &Partition) -> Result<(), StoreError> {
        if matches!(source, Partition::Ref { ns, repo, .. } if *ns == self.repo.namespace && *repo == self.repo.name)
        {
            Ok(())
        } else {
            Err(invalid("publication source outside repository"))
        }
    }
    /// Read one source's latest coordinator intent without scanning a manifest.
    /// Previous generations are intentionally returned for restore reconciliation
    /// and attempt discovery; they must not be treated as current active authority.
    ///
    /// # Errors
    /// Refuses a source outside this repository or malformed/rebound records.
    pub async fn latest_intent<S: NamespaceStore>(
        &self,
        store: &S,
        source: &Partition,
    ) -> Result<Option<CoordinatorIntent>, StoreError> {
        self.check_source(source)?;
        let Some(raw) = store
            .get(&self.coordinator, &self.row_key(&source.encode()?))
            .await?
        else {
            return Ok(None);
        };
        let row: Row = decode(&raw)?;
        row.validate()?;
        if row.intent.source()? != *source {
            return Err(StoreError::Corrupt(
                "coordinator publication source rebound".into(),
            ));
        }
        Ok(Some(CoordinatorIntent {
            intent: row.intent,
            complete: row.complete,
        }))
    }
    /// Read this source's actual durable marker, including prior generations.
    /// Merely observing `Committed` or `Aborted` does not construct a receipt:
    /// callers still use `SourceReceipt::verify` against their exact intent.
    ///
    /// # Errors
    /// Refuses a source outside this repository or malformed/rebound markers.
    pub async fn source_marker<S: NamespaceStore>(
        &self,
        store: &S,
        source: &Partition,
    ) -> Result<Option<LocalSourceMarker>, StoreError> {
        self.check_source(source)?;
        let Some(raw) = store.get(source, &source_key()).await? else {
            return Ok(None);
        };
        let marker: SourceMarker = decode(&raw)?;
        marker.intent.validate()?;
        if marker.intent.source()? != *source {
            return Err(StoreError::Corrupt(
                "local publication source rebound".into(),
            ));
        }
        Ok(Some(LocalSourceMarker {
            intent: marker.intent,
            status: marker.disposition.into(),
        }))
    }
    async fn apply<S: NamespaceStore>(&self, store: &S, batch: Batch) -> Result<(), StoreError> {
        match store.apply(&self.coordinator, batch).await? {
            BatchOutcome::Committed => Ok(()),
            _ => Err(StoreError::unavailable("publication fence changed; retry")),
        }
    }
    /// Create an unsealed authority. Initialization never grants a stable token.
    pub async fn initialize<S: NamespaceStore>(
        &self,
        store: &S,
        generation: Generation,
    ) -> Result<(), StoreError> {
        self.apply(
            store,
            Batch::new()
                .require(Precondition::Absent(self.root_key()))
                .put(
                    self.root_key(),
                    encode(&Root {
                        generation,
                        revision: 0,
                        pending: 0,
                        sealed: false,
                    })?,
                ),
        )
        .await
    }
    /// Rotate only under integration's external restore/writer fence. Old rows
    /// remain for monotonic attempts; callbacks from old generations are rejected.
    /// New incarnations must never have been issued previously, even on another
    /// deployment or before a restored snapshot. This cannot be proven locally.
    pub async fn rotate<S: NamespaceStore>(
        &self,
        store: &S,
        generation: Generation,
    ) -> Result<(), StoreError> {
        let (raw, old) = self.root(store).await?;
        if generation == old.generation
            || generation.incarnation == old.generation.incarnation
                && generation.number <= old.generation.number
        {
            return Err(invalid("publication generation did not advance"));
        }
        self.apply(
            store,
            Batch::new()
                .require(Precondition::Equals(self.root_key(), raw))
                .delete(self.ready_key())
                .put(
                    self.root_key(),
                    encode(&Root {
                        generation,
                        revision: 0,
                        pending: 0,
                        sealed: false,
                    })?,
                ),
        )
        .await
    }
    /// Integration writes this fragment only after fencing and reconciling old
    /// sources/relays. Guarding the root makes readiness specific to this cut.
    pub async fn bootstrap_ready_batch<S: NamespaceStore>(
        &self,
        store: &S,
    ) -> Result<Batch, StoreError> {
        let (raw, root) = self.root(store).await?;
        if root.sealed || root.pending != 0 {
            return Err(invalid("bootstrap not quiescent"));
        }
        Ok(Batch::new()
            .require(Precondition::Equals(self.root_key(), raw))
            .put(self.ready_key(), encode(&(root.generation, root.revision))?))
    }
    /// Read the exact durable readiness marker; this is an explicit trusted
    /// integration handoff, not automatic discovery of legacy publications.
    pub async fn verify_bootstrap<S: NamespaceStore>(
        &self,
        store: &S,
    ) -> Result<BootstrapReceipt, StoreError> {
        let (_, root) = self.root(store).await?;
        let value = store
            .get(&self.coordinator, &self.ready_key())
            .await?
            .ok_or_else(|| invalid("bootstrap not ready"))?;
        let (generation, revision): (Generation, u64) = decode(&value)?;
        if generation != root.generation || revision != root.revision {
            return Err(invalid("stale bootstrap readiness"));
        }
        Ok(BootstrapReceipt {
            generation,
            revision,
            coordinator: self.coordinator.clone(),
            scope: self.scope,
            ready: value,
        })
    }
    /// Seal only the proven readiness cut; any intervening begin invalidates it.
    pub async fn seal<S: NamespaceStore>(
        &self,
        store: &S,
        receipt: &BootstrapReceipt,
    ) -> Result<(), StoreError> {
        let (raw, mut root) = self.root(store).await?;
        if receipt.coordinator != self.coordinator
            || receipt.scope != self.scope
            || root.generation != receipt.generation
            || root.revision != receipt.revision
            || root.pending != 0
            || root.sealed
        {
            return Err(invalid("bootstrap readiness changed"));
        }
        root.sealed = true;
        root.revision = increment(root.revision)?;
        self.apply(
            store,
            Batch::new()
                .require(Precondition::Equals(self.root_key(), raw))
                .require(Precondition::Equals(
                    self.ready_key(),
                    receipt.ready.clone(),
                ))
                .delete(self.ready_key())
                .put(self.root_key(), encode(&root)?),
        )
        .await
    }
    /// Fresh read; a pending or unsealed authority never returns a token.
    pub async fn stable<S: NamespaceStore>(
        &self,
        store: &S,
    ) -> Result<Option<StableToken>, StoreError> {
        let (_, root) = self.root(store).await?;
        Ok((root.sealed && root.pending == 0).then_some(StableToken {
            generation: root.generation,
            revision: root.revision,
        }))
    }
    /// Invalidate before publication. Retrying the exact attempt/binding is
    /// idempotent; rebinding, older attempts and overlapping source intents fail.
    pub async fn begin<S: NamespaceStore>(
        &self,
        store: &S,
        source: &Partition,
        attempt: u64,
        digest: Hash,
        targets: Vec<Target>,
    ) -> Result<Intent, StoreError> {
        self.begin_inner(
            store,
            source,
            BeginRequest {
                attempt,
                digest,
                targets,
                recovery_due_at_ms: None,
            },
        )
        .await
    }
    /// Invalidate and durably schedule recovery in the same coordinator CAS.
    /// The due time comes from the driver's actual clock. It schedules work;
    /// elapsed time never proves abort, delivery or completion.
    ///
    /// # Errors
    /// Refuses rebound/overlapping attempts and loses atomically on concurrent CAS.
    #[allow(clippy::too_many_arguments)] // Extends the existing begin contract with its one wake deadline.
    pub async fn begin_with_recovery<S: NamespaceStore>(
        &self,
        store: &S,
        source: &Partition,
        attempt: u64,
        digest: Hash,
        targets: Vec<Target>,
        due_at_ms: u64,
    ) -> Result<Intent, StoreError> {
        self.begin_inner(
            store,
            source,
            BeginRequest {
                attempt,
                digest,
                targets,
                recovery_due_at_ms: Some(due_at_ms),
            },
        )
        .await
    }
    /// Decode an exact versioned recovery intent before selecting its repository.
    /// This is an observation, not a receipt or permission to recover the newest
    /// source attempt. Handlers must also check coordinator namespace and match
    /// the current durable coordinator intent before taking recovery action.
    ///
    /// # Errors
    /// Refuses malformed, noncanonical, oversized or non-ref source payloads.
    pub fn decode_recovery_intent(payload: &Value) -> Result<Intent, StoreError> {
        let intent: Intent = decode(payload)?;
        intent.validate()?;
        let source = intent.source()?;
        if !matches!(source, Partition::Ref { .. })
            || source.encode()?.as_ref() != intent.source.as_slice()
            || encode(&intent)? != *payload
        {
            return Err(invalid("publication recovery intent not canonical"));
        }
        Ok(intent)
    }
    /// Decode the exact recovery intent and additionally verify repository scope.
    /// A wake never authorizes recovery of a different or newer source attempt.
    ///
    /// # Errors
    /// Refuses invalid or foreign intent payloads.
    pub fn recovery_intent(&self, payload: &Value) -> Result<Intent, StoreError> {
        let intent = Self::decode_recovery_intent(payload)?;
        self.check_source(&intent.source()?)?;
        Ok(intent)
    }
    /// Decode the source from an exact intent payload, retaining the same checks.
    ///
    /// # Errors
    /// Refuses invalid recovery intents; callers must use `recovery_intent` when
    /// deciding which attempt to recover rather than selecting the newest one.
    pub fn recovery_source(&self, payload: &Value) -> Result<Partition, StoreError> {
        self.recovery_intent(payload)?.source()
    }
    /// Deterministic source identity for initial wakes and timer reschedules.
    ///
    /// # Errors
    /// Refuses sources outside this repository or the durable payload bound.
    pub fn recovery_reference(&self, source: &Partition) -> Result<Hash, StoreError> {
        self.check_source(source)?;
        let encoded = source.encode()?;
        if encoded.len() > MAX_PARTITION_BYTES {
            return Err(invalid("publication recovery source too long"));
        }
        Ok(hash(&encoded))
    }
    fn recovery_timer(&self, intent: &Intent, due_at_ms: u64) -> Result<(Key, Value), StoreError> {
        intent.validate()?;
        let reference = self.recovery_reference(&intent.source()?)?;
        Ok((
            keys::timer(
                due_at_ms,
                crate::timers::registry::kinds::PUBLICATION_FENCE_RECOVERY.get(),
                &reference,
            ),
            encode(intent)?,
        ))
    }
    async fn begin_inner<S: NamespaceStore>(
        &self,
        store: &S,
        source: &Partition,
        request: BeginRequest,
    ) -> Result<Intent, StoreError> {
        let BeginRequest {
            attempt,
            digest,
            targets,
            recovery_due_at_ms,
        } = request;
        if !matches!(source, Partition::Ref { ns, repo, .. } if *ns == self.repo.namespace && *repo == self.repo.name)
        {
            return Err(invalid("publication source outside repository"));
        }
        let (root_raw, mut root) = self.root(store).await?;
        let intent = Intent {
            generation: root.generation,
            source: source.encode()?.to_vec(),
            attempt,
            digest,
            targets,
        };
        intent.validate()?;
        let key = self.row_key(&intent.source);
        let prior = store.get(&self.coordinator, &key).await?;
        if let Some(raw) = &prior {
            let row: Row = decode(raw)?;
            row.validate()?;
            if row.intent == intent {
                if let Some(due_at_ms) = recovery_due_at_ms
                    && !row.complete
                {
                    let (timer, payload) = self.recovery_timer(&intent, due_at_ms)?;
                    self.apply(
                        store,
                        Batch::new()
                            .require(Precondition::Equals(self.root_key(), root_raw))
                            .require(Precondition::Equals(key, raw.clone()))
                            .put(timer, payload),
                    )
                    .await?;
                }
                return Ok(intent);
            }
            if attempt != increment(row.intent.attempt)?
                || row.intent.generation == root.generation && !row.complete
            {
                return Err(invalid("publication attempt is old, rebound or active"));
            }
        } else if attempt != 1 {
            return Err(invalid("publication first attempt must be one"));
        }
        root.revision = increment(root.revision)?;
        root.pending = increment(root.pending)?;
        let row = Row {
            intent: intent.clone(),
            source: None,
            receipts: 0,
            complete: false,
        };
        let mut batch = Batch::new()
            .require(Precondition::Equals(self.root_key(), root_raw))
            .require(guard(key.clone(), prior))
            .put(key, encode(&row)?)
            .put(self.root_key(), encode(&root)?);
        if let Some(due_at_ms) = recovery_due_at_ms {
            let (timer, payload) = self.recovery_timer(&intent, due_at_ms)?;
            batch = batch.put(timer, payload);
        }
        self.apply(store, batch).await?;
        Ok(intent)
    }
    /// Arm after durable begin. The source marker is the local CAS guard for
    /// publication and abort; never apply a publication batch without it.
    pub async fn arm<S: NamespaceStore>(
        &self,
        store: &S,
        intent: &Intent,
    ) -> Result<(), StoreError> {
        let (_, root) = self.root(store).await?;
        if root.generation != intent.generation {
            return Err(invalid("old publication generation"));
        }
        let raw = store
            .get(&self.coordinator, &self.row_key(&intent.source))
            .await?
            .ok_or_else(|| invalid("missing publication intent"))?;
        let row: Row = decode(&raw)?;
        row.validate()?;
        if row.intent != *intent || row.complete {
            return Err(invalid("inactive publication intent"));
        }
        let source = Partition::decode(&intent.source)?;
        let prior = store.get(&source, &source_key()).await?;
        if let Some(raw) = &prior {
            let marker: SourceMarker = decode(raw)?;
            if marker.intent == *intent {
                return Ok(());
            }
            if marker.disposition == Disposition::Armed || marker.intent.attempt >= intent.attempt {
                return Err(invalid("source has an unresolved publication attempt"));
            }
        }
        let batch = Batch::new().require(guard(source_key(), prior)).put(
            source_key(),
            encode(&SourceMarker {
                intent: intent.clone(),
                disposition: Disposition::Armed,
            })?,
        );
        match store.apply(&source, batch).await? {
            BatchOutcome::Committed => Ok(()),
            _ => Err(StoreError::unavailable("publication source changed; retry")),
        }
    }
    /// Append to the SAME source transaction as pr/pp and allocated relays.
    /// The caller must bind digest and targets to that actual publication plan.
    pub fn source_commit_fragment(intent: &Intent, batch: &mut Batch) -> Result<(), StoreError> {
        let source = intent.source()?;
        let plan = super::publication_fence_plan::publication_batch(&source, batch)?
            .ok_or_else(|| invalid("source commit lacks publication effects"))?;
        let targets = plan
            .targets
            .iter()
            .map(|(partition, watermark)| Target::new(partition, *watermark))
            .collect::<Result<Vec<_>, _>>()?;
        if plan.digest != intent.digest || targets != intent.targets {
            return Err(invalid(
                "publication transaction rebound after invalidation",
            ));
        }
        terminal_fragment(intent, Disposition::Committed, batch)
    }
    /// Irreversible local abort: invalidates every previously prepared commit.
    /// Apply this fragment in the source partition before verifying its receipt.
    pub fn source_abort_fragment(intent: &Intent, batch: &mut Batch) -> Result<(), StoreError> {
        for write in &batch.writes {
            let key = match write {
                super::Write::Put(key, _) | super::Write::Delete(key) => key,
            };
            if matches!(
                keys::parse(key),
                Some(keys::ParsedKey::PublishedRef { .. } | keys::ParsedKey::PublishedIndex { .. })
            ) || matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_)))
            {
                return Err(invalid(
                    "source abort contains publication or relay effects",
                ));
            }
        }
        terminal_fragment(intent, Disposition::Aborted, batch)
    }
    /// Record a verified source disposition, without trusting an RPC success bit.
    pub async fn source_receipt<S: NamespaceStore>(
        &self,
        store: &S,
        receipt: &SourceReceipt,
    ) -> Result<(), StoreError> {
        self.update(store, &receipt.intent, Some(receipt.disposition), None)
            .await
    }
    /// Reconcile after durable relay cleanup, avoiding target fanout. The SDK
    /// removes source relays only after their target transactions commit. The
    /// terminal marker binds the exact allocated target sequences. A crashed
    /// source with remaining rows remains pending; no time estimate is used.
    pub async fn reconcile_delivered<S: NamespaceStore>(
        &self,
        store: &S,
        intent: &Intent,
    ) -> Result<(), StoreError> {
        let receipt = SourceReceipt::verify(store, intent).await?;
        self.source_receipt(store, &receipt).await?;
        if receipt.disposition == Disposition::Aborted {
            return Ok(());
        }
        let source = Partition::decode(&intent.source)?;
        let max = intent
            .targets
            .iter()
            .map(|target| target.watermark)
            .max()
            .unwrap_or(0);
        if max != 0 && !crate::relay::relay_delivered_through(store, &source, max).await? {
            return Err(StoreError::unavailable("publication relay still pending"));
        }
        for index in 0..intent.targets.len() {
            self.target_receipt(
                store,
                &TargetReceipt {
                    intent: intent.clone(),
                    index,
                },
            )
            .await?;
        }
        Ok(())
    }
    /// Record one verified target; split/reordered/duplicate delivery is safe.
    pub async fn target_receipt<S: NamespaceStore>(
        &self,
        store: &S,
        receipt: &TargetReceipt,
    ) -> Result<(), StoreError> {
        self.update(store, &receipt.intent, None, Some(receipt.index))
            .await
    }
    async fn update<S: NamespaceStore>(
        &self,
        store: &S,
        intent: &Intent,
        disposition: Option<Disposition>,
        target: Option<usize>,
    ) -> Result<(), StoreError> {
        let (root_raw, mut root) = self.root(store).await?;
        if root.generation != intent.generation {
            return Err(invalid("old publication generation"));
        }
        let key = self.row_key(&intent.source);
        let raw = store
            .get(&self.coordinator, &key)
            .await?
            .ok_or_else(|| invalid("missing publication intent"))?;
        let mut row: Row = decode(&raw)?;
        row.validate()?;
        if row.intent != *intent {
            return Err(invalid("rebound publication receipt"));
        }
        if let Some(disposition) = disposition {
            if row.source.is_some_and(|old| old != disposition) {
                return Err(invalid("contradictory source receipt"));
            }
            row.source = Some(disposition);
        }
        if let Some(index) = target {
            row.receipts |= 1_u16
                .checked_shl(u32::try_from(index).map_err(|_| invalid("invalid target"))?)
                .ok_or_else(|| invalid("invalid target"))?;
        }
        row.complete = row.source == Some(Disposition::Aborted)
            || row.source == Some(Disposition::Committed)
                && row.receipts == mask(row.intent.targets.len());
        row.validate()?;
        let encoded = encode(&row)?;
        if encoded == raw {
            return Ok(());
        }
        let old: Row = decode(&raw)?;
        if row.complete && !old.complete {
            root.pending = root
                .pending
                .checked_sub(1)
                .ok_or_else(|| invalid("publication pending underflow"))?;
        }
        root.revision = increment(root.revision)?;
        self.apply(
            store,
            Batch::new()
                .require(Precondition::Equals(self.root_key(), root_raw))
                .require(Precondition::Equals(key.clone(), raw))
                .put(key, encoded)
                .put(self.root_key(), encode(&root)?),
        )
        .await
    }
}
/// Validate publication bookkeeping against the final guarded source transaction.
///
/// Storage adapters call this after original preconditions hold, before writing
/// any effects, using reads from that same transaction. Remove only the exact
/// fence guard/write when comparing the original plan; later added effects and
/// guards therefore cannot silently rebind a completed publication receipt.
/// A source without a marker remains compatible with legacy writers. Once
/// enrolled, a publication must have its exact armed-to-committed transition.
///
/// # Errors
/// Refuses unguarded/rebound publication, marker deletion or orphan terminal
/// writes. Receipt records and all planned effects must match this partition.
pub fn validate_source_transaction(
    source: &Partition,
    batch: &Batch,
    get: impl Fn(&Key) -> Result<Option<Value>, StoreError>,
) -> Result<(), StoreError> {
    let key = source_key();
    let marker_writes: Vec<_> = batch
        .writes
        .iter()
        .filter(
            |write| matches!(write, super::Write::Put(k, _) | super::Write::Delete(k) if *k == key),
        )
        .collect();
    if !matches!(source, Partition::Ref { .. }) && marker_writes.is_empty() {
        return Ok(());
    }
    let prior_raw = get(&key)?;
    if marker_writes.is_empty() && prior_raw.is_none() {
        return Ok(());
    }
    let published = has_publication_effects(batch)?;
    if marker_writes.is_empty() {
        return if published {
            Err(invalid("enrolled publication lacks fence transition"))
        } else {
            Ok(())
        };
    }
    if marker_writes.len() != 1 {
        return Err(invalid("duplicate source fence effects"));
    }
    let super::Write::Put(_, next_raw) = marker_writes[0] else {
        return Err(invalid("source fence marker cannot be deleted"));
    };
    let next: SourceMarker = decode(next_raw)?;
    next.intent.validate()?;
    if next.intent.source()? != *source {
        return Err(invalid("source fence marker partition rebound"));
    }
    let guards: Vec<_> = batch.preconditions.iter().filter(|pre| {
        matches!(pre, Precondition::Absent(k) | Precondition::Present(k) | Precondition::Equals(k, _) if *k == key)
    }).collect();
    let expected = guard(key.clone(), prior_raw.clone());
    if guards.len() != 1 || *guards[0] != expected {
        return Err(invalid("source fence lacks exact prior guard"));
    }
    let prior: Option<SourceMarker> = prior_raw.as_ref().map(decode).transpose()?;
    if let Some(prior) = &prior {
        prior.intent.validate()?;
        if prior.intent.source()? != *source {
            return Err(invalid("stored source fence partition rebound"));
        }
    }
    if next.disposition == Disposition::Armed {
        if published
            || prior.as_ref().is_some_and(|old| {
                old.disposition == Disposition::Armed || old.intent.attempt >= next.intent.attempt
            })
        {
            return Err(invalid("invalid source fence arm transition"));
        }
        return Ok(());
    }
    let Some(prior) = prior else {
        return Err(invalid("orphan source terminal receipt"));
    };
    if prior.disposition != Disposition::Armed || prior.intent != next.intent {
        return Err(invalid(
            "source terminal receipt lacks matching armed intent",
        ));
    }
    let mut original = batch.clone();
    original
        .preconditions
        .retain(|pre| !matches!(pre, Precondition::Equals(k, _) if *k == key));
    original
        .writes
        .retain(|write| !matches!(write, super::Write::Put(k, _) if *k == key));
    match next.disposition {
        Disposition::Committed => {
            let plan = super::publication_fence_plan::publication_batch(source, &original)?
                .ok_or_else(|| invalid("terminal receipt lacks publication effects"))?;
            let targets = plan.targets.iter().map(|(p, n)| Target::new(p, *n)).collect::<Result<Vec<_>, _>>()?;
            if plan.digest != next.intent.digest || targets != next.intent.targets { return Err(invalid("final publication transaction rebound")); }
        }
        Disposition::Aborted => {
            if published || original.writes.iter().any(|write| {
                matches!(write, super::Write::Put(k, _) | super::Write::Delete(k) if matches!(keys::parse(k), Some(keys::ParsedKey::Relay(_))))
            }) { return Err(invalid("source abort contains publication or relay effects")); }
        }
        Disposition::Armed => unreachable!("arm transition handled above"),
    }
    Ok(())
}
fn has_publication_effects(batch: &Batch) -> Result<bool, StoreError> {
    for write in &batch.writes {
        let key = match write {
            super::Write::Put(key, _) | super::Write::Delete(key) => key,
        };
        if matches!(
            keys::parse(key),
            Some(keys::ParsedKey::PublishedRef { .. } | keys::ParsedKey::PublishedIndex { .. })
        ) {
            return Ok(true);
        }
        if matches!(keys::parse(key), Some(keys::ParsedKey::Relay(_)))
            && let super::Write::Put(_, raw) = write
        {
            let relay = codec::decode_relay(raw)?;
            if relay
                .puts
                .iter()
                .map(|(key, _)| key)
                .chain(relay.deletes.iter())
                .any(|key| {
                    matches!(
                        keys::parse(key),
                        Some(
                            keys::ParsedKey::PublishedRef { .. }
                                | keys::ParsedKey::PublishedIndex { .. }
                        )
                    )
                })
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn source_key() -> Key {
    Key::new(b"pc\0".to_vec())
}
fn terminal_fragment(
    intent: &Intent,
    disposition: Disposition,
    batch: &mut Batch,
) -> Result<(), StoreError> {
    intent.validate()?;
    batch.preconditions.push(Precondition::Equals(
        source_key(),
        encode(&SourceMarker {
            intent: intent.clone(),
            disposition: Disposition::Armed,
        })?,
    ));
    batch.writes.push(super::Write::Put(
        source_key(),
        encode(&SourceMarker {
            intent: intent.clone(),
            disposition,
        })?,
    ));
    Ok(())
}
fn mask(len: usize) -> u16 {
    if len == MAX_TARGETS {
        u16::MAX
    } else {
        (1_u16 << len) - 1
    }
}
fn increment(value: u64) -> Result<u64, StoreError> {
    value
        .checked_add(1)
        .ok_or_else(|| invalid("publication counter overflow"))
}
fn guard(key: Key, value: Option<Value>) -> Precondition {
    match value {
        Some(raw) => Precondition::Equals(key, raw),
        None => Precondition::Absent(key),
    }
}
fn invalid(message: &str) -> StoreError {
    StoreError::Invalid(message.to_owned().into())
}
fn encode<T: Serialize>(row: &T) -> Result<Value, StoreError> {
    let mut bytes = vec![1];
    bytes.extend(serde_json::to_vec(row).map_err(|_| invalid("publication fence encoding"))?);
    if bytes.len() > MAX_ROW_BYTES {
        return Err(invalid("publication fence row too large"));
    }
    Ok(Value::new(bytes))
}
fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, StoreError> {
    let bytes = value.as_bytes();
    if bytes.len() > MAX_ROW_BYTES || bytes.first() != Some(&1) {
        return Err(StoreError::Corrupt(
            "invalid publication fence encoding".into(),
        ));
    }
    serde_json::from_slice(&bytes[1..])
        .map_err(|_| StoreError::Corrupt("invalid publication fence row".into()))
}

#[cfg(all(test, feature = "memory"))]
#[path = "publication_fence_tests.rs"]
mod tests;
