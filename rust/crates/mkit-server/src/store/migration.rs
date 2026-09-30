//! Bounded legacy publication initialization. A permanent seal distinguishes
//! missing managed state from a store that has never entered publication mode.
use super::{
    Batch, Cursor, Key, NamespaceStore, Partition, Precondition, StoreError, Value, Write,
};
use crate::RepoName;

const VERSION: u8 = 1;
const INITIALIZING: u8 = 1;
const MANAGED: u8 = 2;
/// A backfill page reserves room for its timer and progress guards.
pub const PAGE_ROWS: u32 = 16;

/// Per-repository state, scoped by the physical metadata partition.
#[must_use]
pub fn key(repo: &RepoName) -> Key {
    Key::new([b"pv\0".as_slice(), repo.as_str().as_bytes()].concat())
}
/// Permanent managed-era evidence; it is never deleted by initialization.
#[must_use]
pub fn seal_key(repo: &RepoName) -> Key {
    Key::new([key(repo).as_bytes(), b"\0seal"].concat())
}
/// A validated captured discriminator. Initializing still serves legacy rows;
/// publication-era writers cannot install data until the state becomes Managed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// No publication-era mutation has occurred in this partition.
    Legacy,
    /// Validate managed metadata and membership history before backfilling legacy rows.
    Initializing { phase: u8, after: Option<Cursor> },
    /// All legacy rows were guardedly projected before publication-era writes.
    Managed,
}
impl State {
    /// Decode both markers. Loss of either managed-era marker fails closed.
    pub fn decode(raw: Option<&Value>, seal: Option<&Value>) -> Result<Self, StoreError> {
        let corrupt = || StoreError::Corrupt("inconsistent publication migration state".into());
        match raw.map(Value::as_bytes) {
            None if seal.is_none() => Ok(Self::Legacy),
            Some([VERSION, MANAGED]) if seal.map(Value::as_bytes) == Some(&[VERSION][..]) => {
                Ok(Self::Managed)
            }
            Some(bytes)
                if bytes.len() >= 3
                    && bytes[0] == VERSION
                    && bytes[1] == INITIALIZING
                    && bytes[2] < 9
                    && seal.is_none() =>
            {
                Ok(Self::Initializing {
                    phase: bytes[2],
                    after: (bytes.len() > 3).then(|| Cursor::new(bytes[3..].to_vec())),
                })
            }
            _ => Err(corrupt()),
        }
    }
    pub(crate) fn encode(&self) -> Value {
        match self {
            Self::Legacy => Value::default(),
            Self::Managed => Value::new(vec![VERSION, MANAGED]),
            Self::Initializing { phase, after } => {
                let mut bytes = vec![VERSION, INITIALIZING, *phase];
                if let Some(after) = after {
                    bytes.extend_from_slice(after.as_bytes());
                }
                Value::new(bytes)
            }
        }
    }
}
/// Read after every candidate row has been captured. No live row may be fetched
/// after this validation when returning the legacy view. Sequential defaults
/// are safe: a transition between marker reads is rejected rather than trusted.
pub async fn observe<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    repo: &RepoName,
) -> Result<State, StoreError> {
    let rows = store
        .get_many(partition, &[key(repo), seal_key(repo)])
        .await?;
    if rows.len() != 2 {
        return Err(StoreError::Corrupt(
            "short publication migration observation".into(),
        ));
    }
    State::decode(rows[0].as_ref(), rows[1].as_ref())
}
pub(crate) fn range(repo: &RepoName, tag: &[u8]) -> (Key, Key) {
    let mut start = [tag, b"\0", repo.as_str().as_bytes(), b"\0"].concat();
    let mut end = start.clone();
    *end.last_mut().expect("range delimiter") = 1;
    // All prefixes include a delimiter; retaining it excludes adjacent repos.
    (Key::new(std::mem::take(&mut start)), Key::new(end))
}
/// Guard a captured state, never treating malformed marker bytes as legacy.
pub fn guards(
    repo: &RepoName,
    raw: Option<&Value>,
    seal: Option<&Value>,
) -> Result<Vec<Precondition>, StoreError> {
    State::decode(raw, seal)?;
    Ok([(key(repo), raw), (seal_key(repo), seal)]
        .into_iter()
        .map(|(key, raw)| {
            raw.map_or(Precondition::Absent(key.clone()), |value| {
                Precondition::Equals(key, value.clone())
            })
        })
        .collect())
}
/// Plan one bounded, idempotent page. The caller adds the timer's own guards.
pub async fn page<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    repo: &RepoName,
    raw: &Value,
    now_ms: u64,
) -> Result<(Batch, bool), StoreError> {
    let seal = store.get(partition, &seal_key(repo)).await?;
    let State::Initializing { phase, after } = State::decode(Some(raw), seal.as_ref())? else {
        return Err(StoreError::Corrupt(
            "publication migration timer without initialization".into(),
        ));
    };
    let tags = [
        b"pp".as_slice(),
        b"av",
        b"pr",
        b"py",
        b"pm",
        b"m",
        b"r",
        b"x",
        b"m",
    ];
    let published = [
        b"pm".as_slice(),
        b"pm",
        b"pm",
        b"pm",
        b"pm",
        b"pm",
        b"pr",
        b"py",
        b"pm",
    ];
    let (start, end) = range(repo, tags[usize::from(phase)]);
    let rows = store
        .scan(partition, &start, &end, after.as_ref(), PAGE_ROWS)
        .await?;
    let mut batch = Batch::new().require(Precondition::NotAfter(now_ms.saturating_add(10_000)));
    batch
        .preconditions
        .extend(guards(repo, Some(raw), seal.as_ref())?);
    if phase < 5 && (!rows.entries.is_empty() || rows.next.is_some()) {
        return Err(StoreError::Corrupt(
            "publication history without era discriminator".into(),
        ));
    }
    for (live, value) in rows.entries {
        if (phase == 5 || phase == 8) && !value.as_bytes().is_empty() {
            return Err(StoreError::Corrupt(
                "managed membership during legacy initialization".into(),
            ));
        }
        if phase == 5 {
            batch.preconditions.push(Precondition::Equals(live, value));
            continue;
        }
        let destination = Key::new(
            [
                published[usize::from(phase)],
                &live.as_bytes()[tags[usize::from(phase)].len()..],
            ]
            .concat(),
        );
        batch.preconditions.extend([
            Precondition::Equals(live, value.clone()),
            Precondition::Absent(destination.clone()),
        ]);
        batch.writes.push(Write::Put(destination, value));
    }
    let done = rows.next.is_none() && phase == 8;
    let state = if done {
        State::Managed
    } else {
        State::Initializing {
            phase: phase + u8::from(rows.next.is_none()),
            after: rows.next,
        }
    };
    batch.writes.push(Write::Put(key(repo), state.encode()));
    if done {
        batch
            .writes
            .push(Write::Put(seal_key(repo), Value::new(vec![VERSION])));
    }
    Ok((batch, done))
}

/// Refuse ambiguous existing publication evidence before legacy backfill.
/// An absent marker never authorizes copying already-managed live values.
pub async fn validate_legacy<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    repo: &RepoName,
) -> Result<(), StoreError> {
    for tag in [b"pp".as_slice(), b"av", b"pr", b"py", b"pm"] {
        let (start, end) = range(repo, tag);
        let rows = store.scan(partition, &start, &end, None, 1).await?;
        if !rows.entries.is_empty() || rows.next.is_some() {
            return Err(StoreError::Corrupt(
                "publication history without era discriminator".into(),
            ));
        }
    }
    Ok(())
}

/// Marker effects included in the caller's existing atomic publication apply.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// Exact discriminator observations, including absence during initialization.
    pub preconditions: Vec<Precondition>,
    /// Empty-partition initial markers; managed partitions need no marker writes.
    pub writes: Vec<Write>,
}
impl Prepared {
    pub(crate) fn empty(repo: &RepoName) -> Self {
        Self {
            preconditions: vec![
                Precondition::Absent(key(repo)),
                Precondition::Absent(seal_key(repo)),
            ],
            writes: vec![
                Write::Put(key(repo), State::Managed.encode()),
                Write::Put(seal_key(repo), Value::new(vec![VERSION])),
            ],
        }
    }
}
/// Prepare from markers already included in the pipeline's normal read-ahead.
/// Nonempty legacy initialization is durably scheduled, then the write retries
/// after bounded background pages. No pending live data is written here.
pub async fn prepare<S: NamespaceStore>(
    store: &S,
    partition: &Partition,
    repo: &RepoName,
    raw: Option<&Value>,
    seal: Option<&Value>,
    now_ms: u64,
) -> Result<Prepared, StoreError> {
    let preconditions = guards(repo, raw, seal)?;
    match State::decode(raw, seal)? {
        State::Managed => {
            return Ok(Prepared {
                preconditions,
                writes: vec![],
            });
        }
        State::Initializing { .. } => {
            return Err(StoreError::unavailable("publication migration in progress"));
        }
        State::Legacy => {}
    }
    validate_legacy(store, partition, repo).await?;
    let mut empty = true;
    for tag in [b"r".as_slice(), b"x", b"m"] {
        let (start, end) = range(repo, tag);
        let page = store.scan(partition, &start, &end, None, 1).await?;
        empty &= page.entries.is_empty() && page.next.is_none();
    }
    if empty {
        return Ok(Prepared::empty(repo));
    }
    let mut batch = Batch::new().require(Precondition::NotAfter(now_ms.saturating_add(10_000)));
    batch.preconditions.extend(preconditions);
    batch.writes.extend([
        Write::Put(
            key(repo),
            State::Initializing {
                phase: 0,
                after: None,
            }
            .encode(),
        ),
        Write::Put(
            super::keys::timer(
                now_ms,
                crate::timers::registry::kinds::PUBLICATION_MIGRATION.get(),
                key(repo).as_bytes(),
            ),
            Value::default(),
        ),
    ]);
    store.apply(partition, batch).await?;
    Err(StoreError::unavailable("publication migration in progress"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BatchOutcome, MemoryKv, NamespaceKey};
    use futures_executor::block_on;
    #[test]
    fn managed_marker_loss_and_malformed_state_are_never_legacy() {
        let managed = State::Managed.encode();
        let seal = Value::new(vec![VERSION]);
        assert_eq!(State::decode(None, None).unwrap(), State::Legacy);
        assert_eq!(
            State::decode(Some(&managed), Some(&seal)).unwrap(),
            State::Managed
        );
        assert!(State::decode(None, Some(&seal)).is_err());
        assert!(State::decode(Some(&managed), None).is_err());
        assert!(State::decode(Some(&Value::new(vec![99, MANAGED])), Some(&seal)).is_err());
        assert!(
            State::decode(
                Some(
                    &State::Initializing {
                        phase: 0,
                        after: None
                    }
                    .encode()
                ),
                Some(&seal)
            )
            .is_err()
        );
    }
    #[test]
    fn bounded_backfill_guards_live_values_and_resumes_without_republishing() {
        block_on(async {
            let store = MemoryKv::with_clock(std::sync::Arc::new(crate::rt::ManualClock::new(0)));
            let repo = RepoName::new("legacy").unwrap();
            let partition = Partition::Namespace(NamespaceKey::deployment_default());
            let initial = State::Initializing {
                phase: 6,
                after: None,
            }
            .encode();
            store
                .apply(
                    &partition,
                    Batch::new().put(key(&repo), initial.clone()).put(
                        super::super::keys::ref_key(&repo, "refs/heads/main"),
                        Value::new(vec![7; 32]),
                    ),
                )
                .await
                .unwrap();
            let (page, done) = page(&store, &partition, &repo, &initial, 0).await.unwrap();
            assert!(!done);
            assert!(page.preconditions.len() + page.writes.len() <= 100);
            store
                .apply(
                    &partition,
                    Batch::new().put(
                        super::super::keys::ref_key(&repo, "refs/heads/main"),
                        Value::new(vec![8; 32]),
                    ),
                )
                .await
                .unwrap();
            assert!(matches!(
                store.apply(&partition, page).await.unwrap(),
                BatchOutcome::PreconditionFailed { .. }
            ));
            assert!(
                store
                    .get(
                        &partition,
                        &super::super::keys::published_ref(&repo, "refs/heads/main")
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
            for _ in 0..3 {
                let raw = store.get(&partition, &key(&repo)).await.unwrap().unwrap();
                let (page, _) = super::page(&store, &partition, &repo, &raw, 0)
                    .await
                    .unwrap();
                assert_eq!(
                    store.apply(&partition, page).await.unwrap(),
                    BatchOutcome::Committed
                );
            }
            assert_eq!(
                observe(&store, &partition, &repo).await.unwrap(),
                State::Managed
            );
            assert_eq!(
                store
                    .get(
                        &partition,
                        &super::super::keys::published_ref(&repo, "refs/heads/main")
                    )
                    .await
                    .unwrap(),
                Some(Value::new(vec![8; 32]))
            );
        });
    }
    struct SequentialTransition {
        store: MemoryKv,
        repository: RepoName,
        install: std::sync::atomic::AtomicBool,
    }
    impl NamespaceStore for SequentialTransition {
        fn capabilities(&self) -> super::super::StoreCapabilities {
            self.store.capabilities()
        }
        async fn get(
            &self,
            partition: &Partition,
            requested: &Key,
        ) -> Result<Option<Value>, StoreError> {
            let captured = self.store.get(partition, requested).await?;
            if *requested == key(&self.repository)
                && self
                    .install
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                self.store
                    .apply(
                        partition,
                        Batch::new()
                            .put(key(&self.repository), State::Managed.encode())
                            .put(seal_key(&self.repository), Value::new(vec![VERSION])),
                    )
                    .await?;
            }
            Ok(captured)
        }
        async fn scan(
            &self,
            partition: &Partition,
            start: &Key,
            end: &Key,
            after: Option<&Cursor>,
            limit: u32,
        ) -> Result<super::super::ScanPage, StoreError> {
            self.store.scan(partition, start, end, after, limit).await
        }
        async fn apply(
            &self,
            partition: &Partition,
            batch: Batch,
        ) -> Result<BatchOutcome, StoreError> {
            self.store.apply(partition, batch).await
        }
        async fn stats(
            &self,
            partition: &Partition,
        ) -> Result<super::super::PartitionStats, StoreError> {
            self.store.stats(partition).await
        }
        async fn probe(&self) -> Result<(), StoreError> {
            self.store.probe().await
        }
    }
    #[test]
    fn sequential_default_observation_rejects_transition_between_marker_reads() {
        block_on(async {
            let partition = Partition::Namespace(NamespaceKey::deployment_default());
            let store = SequentialTransition {
                store: MemoryKv::default(),
                repository: RepoName::new("legacy").unwrap(),
                install: std::sync::atomic::AtomicBool::new(true),
            };
            assert!(
                observe(&store, &partition, &store.repository)
                    .await
                    .is_err()
            );
            assert_eq!(
                observe(&store, &partition, &store.repository)
                    .await
                    .unwrap(),
                State::Managed
            );
        });
    }
}
