// Fixture setup must fail immediately; node ids are small test indexes.
#![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
use super::*;
use crate::store::{Cursor, Partition, PartitionStats, ReadCredits, ReadReservation, ScanPage};
use crate::{ManualClock, MemoryKv};
use mkit_core::object::Blob;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
enum Reply {
    Good,
    Transport,
    Short,
    MissingHead,
    BadHead,
    MissingEntry,
    BadEntry,
    BadMarker,
    BadReferences,
    BadHeadAndReferences,
}

#[derive(Default)]
struct Calls {
    reservations: Vec<u32>,
    partitions: Vec<Partition>,
    active: usize,
    peak: usize,
    completed: Vec<usize>,
}

struct Scripted {
    kv: MemoryKv,
    replies: Vec<Reply>,
    credits: ReadCredits,
    calls: Mutex<Calls>,
    budget: u32,
    known_allowance: bool,
}

impl NamespaceStore for Scripted {
    fn capabilities(&self) -> crate::store::StoreCapabilities {
        self.kv.capabilities()
    }

    fn read_call_allowance(&self) -> Option<u32> {
        self.known_allowance.then(|| {
            self.budget
                .saturating_sub(self.calls.lock().unwrap().reservations.iter().sum::<u32>())
        })
    }

    fn reader_admission(&self) -> bool {
        true
    }

    fn reserve_read_calls(&self, count: u32) -> Result<Option<ReadReservation>, StoreError> {
        let mut calls = self.calls.lock().unwrap();
        if calls.reservations.iter().sum::<u32>() + count > self.budget {
            return Err(StoreError::unavailable("reservation exhausted"));
        }
        calls.reservations.push(count);
        Ok(Some(self.credits.prepay(count)))
    }

    async fn get(&self, p: &Partition, key: &Key) -> Result<Option<Value>, StoreError> {
        self.kv.get(p, key).await
    }

    async fn get_many(
        &self,
        p: &Partition,
        keys: &[Key],
    ) -> Result<Vec<Option<Value>>, StoreError> {
        assert!(self.credits.paid(), "dispatch must consume prepaid credit");
        let index = {
            let mut calls = self.calls.lock().unwrap();
            let index = calls.partitions.len();
            calls.partitions.push(p.clone());
            calls.active += 1;
            calls.peak = calls.peak.max(calls.active);
            index
        };
        // The first chunk completes later than later chunks in its wave.
        for _ in 0..(6 - index % 6) {
            tokio::task::yield_now().await;
        }
        let mut values = self.kv.get_many(p, keys).await?;
        {
            let mut calls = self.calls.lock().unwrap();
            calls.active -= 1;
            calls.completed.push(index);
        }
        match self.replies[index] {
            Reply::Good => {}
            Reply::Transport => return Err(StoreError::unavailable("later transport")),
            Reply::Short => {
                values.pop();
            }
            Reply::MissingHead => values[0] = None,
            Reply::BadHead => {
                let mut head: Head = decode(values[0].as_ref().unwrap())?;
                head.version = 0;
                values[0] = Some(encode(&head)?);
            }
            Reply::MissingEntry => values[1] = None,
            Reply::BadEntry => {
                let raw = Value::new(b"invalid entry".to_vec());
                let id: Hash = keys[1].as_bytes()[keys[1].as_bytes().len() - 32..]
                    .try_into()
                    .unwrap();
                values[2] = Some(Value::new(entry_digest(&id, &raw).to_vec()));
                values[1] = Some(raw);
            }
            Reply::BadMarker => values[2] = Some(Value::new(vec![0; 32])),
            Reply::BadReferences | Reply::BadHeadAndReferences => {
                let mut row: Entry = decode(values[1].as_ref().unwrap())?;
                row.references.action.reason.clear();
                let raw = encode(&row)?;
                let id: Hash = keys[1].as_bytes()[keys[1].as_bytes().len() - 32..]
                    .try_into()
                    .unwrap();
                values[2] = Some(Value::new(entry_digest(&id, &raw).to_vec()));
                values[1] = Some(raw);
                if matches!(self.replies[index], Reply::BadHeadAndReferences) {
                    values[0] = None;
                }
            }
        }
        Ok(values)
    }

    async fn scan(
        &self,
        p: &Partition,
        start: &Key,
        end: &Key,
        after: Option<&Cursor>,
        limit: u32,
    ) -> Result<ScanPage, StoreError> {
        self.kv.scan(p, start, end, after, limit).await
    }

    async fn apply(&self, p: &Partition, batch: Batch) -> Result<BatchOutcome, StoreError> {
        self.kv.apply(p, batch).await
    }

    async fn stats(&self, p: &Partition) -> Result<PartitionStats, StoreError> {
        self.kv.stats(p).await
    }

    async fn probe(&self) -> Result<(), StoreError> {
        self.kv.probe().await
    }
}

async fn fixture(replies: Vec<Reply>) -> (Scripted, Vec<(Hash, index::LocatedObject)>) {
    let kv = MemoryKv::with_clock(Arc::new(ManualClock::new(0)));
    let pack = [42; 32];
    let object = Object::Blob(Blob { data: vec![9] });
    let id = object.id().unwrap();
    stage(&kv, &pack, 100, &id, &object, None, 0).await.unwrap();
    complete(&kv, &pack, 100, 0).await.unwrap();
    let row = entry(&kv, &pack, &id).await.unwrap().unwrap();
    let location = index::LocatedObject {
        pack,
        value: index::IndexValue {
            frame_offset: 0,
            frame_length: 10,
            wire_type: 0,
            decoded_size: row.canonical_len,
            chain_depth: 0,
            delta_base: None,
        },
    };
    let located = vec![(id, location); replies.len() * 16];
    (
        Scripted {
            kv,
            replies,
            credits: ReadCredits::default(),
            calls: Mutex::new(Calls::default()),
            budget: u32::MAX,
            known_allowance: true,
        },
        located,
    )
}

#[tokio::test]
async fn bounded_waves_reserve_exact_chunk_calls_and_preserve_duplicate_facts() {
    let (store, located) = fixture(vec![Reply::Good; 14]).await;
    let facts = located_entries(&store, &located).await.unwrap();
    assert_eq!(facts.len(), 1);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls.reservations, [6, 6, 2]);
    assert_eq!(calls.partitions.len(), 14);
    assert_eq!(calls.peak, 6);
    assert_ne!(calls.completed[0], 0);
    assert!(!store.credits.paid(), "credits cannot escape their wave");
}

#[tokio::test]
async fn chunk_validation_precedes_later_transport_even_when_reply_finishes_last() {
    for invalid in [
        Reply::Short,
        Reply::MissingHead,
        Reply::BadHead,
        Reply::MissingEntry,
        Reply::BadEntry,
        Reply::BadMarker,
    ] {
        let (store, located) = fixture(vec![Reply::Good, invalid, Reply::Transport]).await;
        let error = located_entries(&store, &located).await.unwrap_err();
        assert!(matches!(error, StoreError::Corrupt(_)), "{error}");
        let (store, located) = fixture(vec![Reply::Transport, invalid, Reply::Good]).await;
        let error = located_entries(&store, &located).await.unwrap_err();
        assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
    }
}

#[tokio::test]
async fn partition_order_precedes_input_order_for_mixed_absence_and_transport() {
    let (store, mut located) = fixture(vec![Reply::MissingHead, Reply::Transport]).await;
    // Give the first input a later partition; its backend failure cannot mask
    // the earlier partition's uniformly corrupt missing inventory.
    located.truncate(2);
    located[0].1.pack = [90; 32];
    located[1].1.pack = [10; 32];
    let error = located_entries(&store, &located).await.unwrap_err();
    assert!(matches!(error, StoreError::Corrupt(_)), "{error}");
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls.reservations, [2]);
    assert!(calls.partitions[0] < calls.partitions[1]);
}

#[tokio::test]
async fn failed_wave_reservation_dispatches_no_reads() {
    let (mut store, located) = fixture(vec![Reply::Good; 7]).await;
    store.budget = 0;
    let error = located_entries(&store, &located).await.unwrap_err();
    assert!(error.to_string().contains("reservation exhausted"));
    let calls = store.calls.lock().unwrap();
    assert!(calls.reservations.is_empty());
    assert!(calls.partitions.is_empty());
}

#[tokio::test]
async fn head_validation_precedes_entry_validation_and_earlier_entry_precedes_later_head() {
    let (store, located) = fixture(vec![Reply::BadHeadAndReferences]).await;
    let error = located_entries(&store, &located).await.unwrap_err();
    assert!(
        matches!(error, StoreError::Corrupt(message) if message == "invalid verified pack inventory")
    );
    let (store, located) = fixture(vec![Reply::BadReferences, Reply::BadHead]).await;
    let error = located_entries(&store, &located).await.unwrap_err();
    assert!(matches!(error, StoreError::Corrupt(message) if message == "bad denial actions"));
}

#[tokio::test]
async fn tight_budget_consumes_earlier_corruption_without_refusing_later_calls() {
    use crate::indexed::budget::{Budgeted, SliceBudget};
    for invalid in [Reply::MissingHead, Reply::BadEntry] {
        let (store, located) = fixture(vec![invalid, Reply::Good]).await;
        let ledger = SliceBudget::new(1);
        let view = Budgeted::new(&store, &ledger);
        let error = located_entries(&view, &located).await.unwrap_err();
        assert!(matches!(error, StoreError::Corrupt(_)), "{error}");
        assert_eq!(ledger.used(), 1);
        assert!(!ledger.refused());
        let calls = store.calls.lock().unwrap();
        assert_eq!(calls.reservations, [1]);
        assert_eq!(calls.partitions.len(), 1);
    }
}

#[tokio::test]
async fn unknown_allowance_validates_each_chunk_before_next_reservation() {
    let (mut store, located) = fixture(vec![Reply::Good; 3]).await;
    store.known_allowance = false;
    located_entries(&store, &located).await.unwrap();
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls.reservations, [1, 1, 1]);
    assert_eq!(calls.peak, 1);
}
