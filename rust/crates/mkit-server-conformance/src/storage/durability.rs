//! Durability cases (R-22): cancellation (rule 4), crash/restart atomicity
//! (rule 5) and the portable export/import round trip. All are generic over
//! any [`NamespaceStore`]; each checks the store against a model.

use core::future::Future as _;
use core::task::{Context, Poll, Waker};

use futures::StreamExt as _;
use mkit_server::store::{
    EXPORT_END, ExportHeader, ExportReader, ExportRecord, ImportMode, codec, encode_export_header,
    encode_export_record, export_partition, import_stream, keys,
};
use mkit_server::{
    Batch, BatchOutcome, Key, KeyClasses, NamespaceStore, Partition, Precondition, StoreError,
    Value,
};

use super::CaseResult::{Pass, Skip};
use super::{
    KvHarness, Model, Outcome, Rng, TempDir, commit, k, model_apply, model_rows, outcome, part,
    put_all, rows, scan_all, v, yield_now,
};

/// Keys the random batches touch.
const KEYS: u8 = 8;

/// Whether `pre` holds on `model` (`NotAfter` is not generated here).
fn holds(model: &Model, pre: &Precondition) -> bool {
    match pre {
        Precondition::Absent(key) => !model.contains_key(key),
        Precondition::Present(key) => model.contains_key(key),
        Precondition::Equals(key, val) => model.get(key) == Some(val),
        Precondition::NotAfter(_) => true,
    }
}

/// Whether `batch` commits on `model`, and the model after it.
fn after(model: &Model, batch: &Batch) -> (bool, Model) {
    let commits = batch.preconditions.iter().all(|pre| holds(model, pre));
    let mut next = model.clone();
    if commits {
        model_apply(&mut next, batch);
    }
    (commits, next)
}

/// The key range of `prefix`: the keys [`random_batch`] writes under it.
fn keys_of(prefix: &[u8]) -> (Key, Key) {
    (k(prefix), k(&[prefix, &[KEYS]].concat()))
}

/// A random batch over [`KEYS`] keys under `prefix`: up to four writes and
/// two preconditions on an atomic store, one write and at most one
/// precondition on its key otherwise. About a quarter of the preconditions
/// are wrong, so some batches fail.
fn random_batch(rng: &mut Rng, model: &Model, atomic: bool, prefix: &[u8]) -> Batch {
    let key = |rng: &mut Rng| k(&[prefix, &[rng.byte(KEYS)]].concat());
    let mut batch = Batch::new();
    let target = key(rng);
    let writes = if atomic { 1 + rng.below(4) } else { 1 };
    for i in 0..writes {
        let key = if i == 0 { target.clone() } else { key(rng) };
        batch = match rng.below(3) {
            0 => batch.delete(key),
            n => batch.put(key, Value::new(vec![rng.byte(255); usize::from(n > 1)])),
        };
    }
    for _ in 0..rng.below(if atomic { 3 } else { 2 }) {
        let key = if atomic { key(rng) } else { target.clone() };
        batch = batch.require(match (model.get(&key), rng.below(4) == 0) {
            (Some(val), false) => Precondition::Equals(key, val.clone()),
            (None, false) | (Some(_), true) => Precondition::Absent(key),
            (None, true) => Precondition::Present(key),
        });
    }
    batch
}

/// One round of [`dur_cancelled_apply_is_all_or_nothing`]: its keys, the
/// states before and after its batch, and whether the after state has been
/// seen.
struct Round {
    range: (Key, Key),
    pre: Vec<(Key, Value)>,
    post: Vec<(Key, Value)>,
    seen_post: bool,
}

impl Round {
    /// Read the round's keys: `Ok(true)` once they hold the after state.
    /// Anything but the before or after state, or the before state after
    /// the after state was seen, fails.
    async fn observe<S: NamespaceStore>(&mut self, s: &S, p: &Partition) -> Result<bool, String> {
        let now = scan_all(s, p, (&self.range.0, &self.range.1), 8).await?;
        if now == self.post {
            self.seen_post = true;
        } else {
            ensure!(now == self.pre, "torn state {now:?}");
            ensure!(!self.seen_post, "the before state reappeared: {now:?}");
        }
        Ok(self.seen_post)
    }
}

/// Rule 4, 200 rounds, each on its own keys: seed them, then drop an
/// `apply` after 0 to 3 polls. A batch that completed reports the outcome
/// the model predicts. A dropped batch may still commit later (a blocking
/// task keeps running), so its keys are watched with a bounded wait, re-read
/// every round until the after state shows, and re-read at the end: always
/// exactly the state before or after it, never torn, and never back to
/// before once after was seen. The store keeps working throughout.
pub async fn dur_cancelled_apply_is_all_or_nothing<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("dur_cancelled_apply_is_all_or_nothing"));
    let atomic = s.capabilities().atomic_multi_key;
    let mut rng = Rng::new(22);
    let mut rounds: Vec<Round> = Vec::new();
    for round in 0_u16..200 {
        let [hi, lo] = round.to_be_bytes();
        let prefix = [b'c', hi, lo];
        let seed: Vec<_> = (0..KEYS)
            .filter(|_| rng.below(2) == 0)
            .map(|i| (k(&[&prefix[..], &[i]].concat()), v(&[i])))
            .collect();
        put_all(&s, &p, &seed).await?;
        let model: Model = seed.iter().cloned().collect();
        let batch = random_batch(&mut rng, &model, atomic, &prefix);
        let (commits, post) = after(&model, &batch);
        let mut apply = Box::pin(s.apply(&p, batch));
        let mut done = None;
        for _ in 0..rng.below(4) {
            let polled = apply.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            if let Poll::Ready(result) = polled {
                done = Some(result);
                break;
            }
        }
        drop(apply);
        let mut this = Round {
            range: keys_of(&prefix),
            pre: model_rows(&model),
            post: model_rows(&post),
            seen_post: false,
        };
        match done {
            Some(Ok(o)) => {
                ensure_eq!(o == BatchOutcome::Committed, commits);
                // Settled: the outcome decides the one state it may hold.
                if !commits {
                    this.post.clone_from(&this.pre);
                }
                this.pre.clone_from(&this.post);
            }
            Some(Err(e)) => return Err(format!("round {round}: apply failed: {e}")),
            None => {}
        }
        for _ in 0..16 {
            if this.observe(&s, &p).await? {
                break;
            }
            yield_now().await;
        }
        rounds.push(this);
        for (i, watched) in rounds.iter_mut().enumerate() {
            if !watched.seen_post {
                watched
                    .observe(&s, &p)
                    .await
                    .map_err(|e| format!("round {i}: {e}"))?;
            }
        }
    }
    commit(&s, &p, Batch::new().put(k(b"after"), v(b"1"))).await?;
    for (i, round) in rounds.iter_mut().enumerate() {
        round
            .observe(&s, &p)
            .await
            .map_err(|e| format!("round {i}: {e}"))?;
    }
    Ok(Pass)
}

/// Crash and restart: after 50 random batches and one more in flight, the
/// store is dropped without shutdown and reopened from its directory. It
/// holds exactly the committed batches (the in-flight one fully or not at
/// all) and keeps working, durably, across a second restart.
pub async fn dur_crash_restart_atomic_at_last_commit<H: KvHarness>(h: H) -> Outcome {
    let dir = TempDir::new()?;
    let Some(s) = h.open_at(dir.path()) else {
        return Ok(Skip("harness has no persistent reopen (`open_at`)"));
    };
    let p = part("dur_crash_restart_atomic_at_last_commit");
    let atomic = s.capabilities().atomic_multi_key;
    let (mut rng, mut model) = (Rng::new(5), Model::new());
    for _ in 0..50 {
        let batch = random_batch(&mut rng, &model, atomic, b"d");
        let (commits, post) = after(&model, &batch);
        let committed = outcome(&s, &p, batch).await? == BatchOutcome::Committed;
        ensure_eq!(committed, commits);
        model = post;
    }
    let batch = random_batch(&mut rng, &model, atomic, b"d");
    let (_, post) = after(&model, &batch);
    let mut in_flight = Box::pin(s.apply(&p, batch));
    let polled = in_flight
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    if let Poll::Ready(result) = polled {
        ensure!(result.is_ok(), "in-flight apply failed: {result:?}");
        model = post.clone();
    }
    drop(in_flight);
    drop(s);
    let s = h.open_at(dir.path()).ok_or("reopen returned no store")?;
    let got = rows(&s, &p).await?;
    ensure!(
        got == model_rows(&model) || got == model_rows(&post),
        "after restart: {got:?}, committed: {model:?}"
    );
    commit(&s, &p, Batch::new().put(k(b"after"), v(b"1"))).await?;
    drop(s);
    let s = h.open_at(dir.path()).ok_or("reopen returned no store")?;
    ensure_eq!(ok!(s.get(&p, &k(b"after")).await), Some(v(b"1")));
    Ok(Pass)
}

/// Every row an export of `p` covers.
async fn export_rows<S: NamespaceStore>(s: &S, p: &Partition) -> Result<Vec<(Key, Value)>, String> {
    let (start, end) = if s.capabilities().key_classes == KeyClasses::RefsOnly {
        keys::class_range(keys::TAG_REF)
    } else {
        (Key::default(), Key::new(vec![0xff]))
    };
    scan_all(s, p, (&start, &end), 64).await
}

/// Export a populated partition through the byte format, import it into
/// an empty partition and compare full scans; `Fresh` then refuses the
/// non-empty partition, and a `Merge` rerun is idempotent and keeps other
/// rows.
pub async fn dur_export_import_roundtrip<H: KvHarness>(h: H) -> Outcome {
    let (src, p) = (h.store(), part("dur_export_import_roundtrip"));
    let dst_p = part("dur_export_import_roundtrip/restored");
    let caps = src.capabilities();
    let mut data: Vec<_> = (0_u8..150).map(|i| (k(&[b'x', i]), v(&[i; 3]))).collect();
    data.push((k(b"empty"), Value::default()));
    if caps.key_classes == KeyClasses::All && caps.implicit_layout_version.is_none() {
        data.push((
            keys::layout_version(),
            codec::encode_u32(keys::LAYOUT_VERSION),
        ));
        data.push((keys::grant_epoch(), codec::encode_u64(3)));
    }
    put_all(&src, &p, &data).await?;
    let (header, stream) = ok!(export_partition(&src, &p, 42).await);
    let records: Vec<ExportRecord> = ok!(stream
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>());
    ensure_eq!(records.len(), data.len());
    let mut bytes = encode_export_header(&header).to_vec();
    for record in &records {
        bytes.extend_from_slice(&ok!(encode_export_record(record)));
    }
    bytes.extend_from_slice(&EXPORT_END);
    let (read_header, reader) = ok!(ExportReader::new(&bytes));
    ensure_eq!(read_header, header);
    let read: Vec<ExportRecord> = ok!(reader.collect::<Result<Vec<_>, _>>());
    ensure_eq!(read, records);
    // Restored into another partition of the same store, so the case
    // never depends on `store()` returning an empty database.
    let (dst, p) = (&src, dst_p);
    let restored: Vec<_> = read
        .iter()
        .map(|r| ExportRecord::new(p.clone(), r.key.clone(), r.value.clone()))
        .collect();
    let stream = || futures::stream::iter(restored.clone().into_iter().map(Ok));
    let imported = ok!(import_stream(dst, &header, ImportMode::Fresh, stream()).await);
    ensure_eq!(imported, records.len() as u64);
    let want = export_rows(&src, &part("dur_export_import_roundtrip")).await?;
    ensure_eq!(export_rows(dst, &p).await?, want);
    let again = import_stream(dst, &header, ImportMode::Fresh, stream()).await;
    ensure_err!(again, StoreError::Invalid(_));
    commit(dst, &p, Batch::new().put(k(b"extra"), v(b"1"))).await?;
    ok!(import_stream(dst, &header, ImportMode::Merge, stream()).await);
    let mut want = want;
    want.push((k(b"extra"), v(b"1")));
    want.sort();
    ensure_eq!(export_rows(dst, &p).await?, want);
    Ok(Pass)
}

/// An export under a newer layout version than this binary's, or with a
/// newer `v` row, is `Unsupported` and imports nothing; so is one whose
/// version differs from a `RefsOnly` store's implicit version.
pub async fn dur_import_newer_layout_rejected<H: KvHarness>(h: H) -> Outcome {
    let (s, p) = (h.store(), part("dur_import_newer_layout_rejected"));
    let caps = s.capabilities();
    let row = ExportRecord::new(p.clone(), k(b"a"), v(b"1"));
    let current = ExportHeader::new(keys::LAYOUT_VERSION, 0);
    let mut cases = vec![(
        ExportHeader::new(keys::LAYOUT_VERSION + 1, 0),
        vec![row.clone()],
    )];
    if caps.key_classes == KeyClasses::All {
        let newer_v = codec::encode_u32(keys::LAYOUT_VERSION + 1);
        let v_row = ExportRecord::new(p.clone(), keys::layout_version(), newer_v);
        cases.push((current, vec![v_row, row.clone()]));
    }
    if let Some(implicit) = caps.implicit_layout_version {
        cases.push((ExportHeader::new(implicit.wrapping_sub(1), 0), vec![row]));
    }
    for (header, records) in cases {
        let stream = futures::stream::iter(records.into_iter().map(Ok));
        let result = import_stream(&s, &header, ImportMode::Fresh, stream).await;
        ensure_err!(result, StoreError::Unsupported(_));
        ensure_eq!(export_rows(&s, &p).await?, vec![]);
    }
    Ok(Pass)
}
