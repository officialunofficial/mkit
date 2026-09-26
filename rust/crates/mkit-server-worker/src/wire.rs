//! The internal JSON RPC between the Worker ([`crate::ns_client`]) and a
//! partition's Durable Object ([`crate::ns_object`]): one [`NsRequest`] per
//! POST, one [`NsReply`] per response.
//!
//! Keys, values and cursors travel as base64 strings; integers (a
//! `NotAfter` deadline, a scan limit) as JSON integers, which `serde_json`
//! reads back exactly. The request carries the encoded partition, so a
//! Durable Object's rows hold the same `part` value as the native backend's
//! and two partitions routed to one instance by mistake still never mix.
//! This wire never leaves the deployment: it is not a public protocol and
//! has no version negotiation (both ends ship in one Worker).

use std::borrow::Cow;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use mkit_server::store::ExportRecord;
use mkit_server::{
    Batch, BatchOutcome, Cursor, Key, Partition, PartitionStats, Precondition, ScanPage,
    StoreError, Value, Write,
};

/// Bytes as a base64 string.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Blob(pub Vec<u8>);

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({} bytes)", self.0.len())
    }
}

impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = Cow::<'de, str>::deserialize(d)?;
        STANDARD
            .decode(text.as_bytes())
            .map(Blob)
            .map_err(D::Error::custom)
    }
}

impl From<&[u8]> for Blob {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

fn key(b: Blob) -> Key {
    Key::new(b.0)
}

fn value(b: Blob) -> Value {
    Value::new(b.0)
}

/// One call on a partition's Durable Object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NsRequest {
    /// [`Partition::encode`] of the partition the call is for.
    pub part: Blob,
    /// The operation.
    pub call: NsCall,
}

impl NsRequest {
    /// A call on `p`.
    ///
    /// # Errors
    /// As [`Partition::encode`].
    pub fn new(p: &Partition, call: NsCall) -> Result<Self, StoreError> {
        Ok(Self {
            part: Blob(p.encode()?.to_vec()),
            call,
        })
    }
}

/// The operations: the `NamespaceStore` methods, plus the portable export
/// page (store-agnostic, M0-02b) for app-level dumps (WP-1.29).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum NsCall {
    /// `get`.
    Get { key: Blob },
    /// `get_many`.
    GetMany { keys: Vec<Blob> },
    /// `scan`.
    Scan {
        start: Blob,
        end: Blob,
        after: Option<Blob>,
        limit: u32,
    },
    /// `apply`.
    Apply { batch: WireBatch },
    /// `stats`.
    Stats,
    /// `probe`.
    Probe,
    /// One `store::export_page`.
    Export { after: Option<Blob>, limit: u32 },
}

/// A [`Batch`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WireBatch {
    /// In order.
    pub preconditions: Vec<WirePrecondition>,
    /// In order.
    pub writes: Vec<WireWrite>,
}

/// A [`Precondition`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WirePrecondition {
    /// `Absent`.
    Absent { key: Blob },
    /// `Present`.
    Present { key: Blob },
    /// `Equals`.
    Equals { key: Blob, value: Blob },
    /// `NotAfter`: checked by the Durable Object against its own clock.
    NotAfter { deadline_ms: u64 },
}

/// A [`Write`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireWrite {
    /// `Put`.
    Put { key: Blob, value: Blob },
    /// `Delete`.
    Delete { key: Blob },
}

impl From<Batch> for WireBatch {
    fn from(batch: Batch) -> Self {
        let b = |k: &Key| Blob::from(k.as_bytes());
        Self {
            preconditions: batch
                .preconditions
                .iter()
                .map(|p| match p {
                    Precondition::Absent(k) => WirePrecondition::Absent { key: b(k) },
                    Precondition::Present(k) => WirePrecondition::Present { key: b(k) },
                    Precondition::Equals(k, v) => WirePrecondition::Equals {
                        key: b(k),
                        value: Blob::from(v.as_bytes()),
                    },
                    Precondition::NotAfter(deadline_ms) => WirePrecondition::NotAfter {
                        deadline_ms: *deadline_ms,
                    },
                })
                .collect(),
            writes: batch
                .writes
                .iter()
                .map(|w| match w {
                    Write::Put(k, v) => WireWrite::Put {
                        key: b(k),
                        value: Blob::from(v.as_bytes()),
                    },
                    Write::Delete(k) => WireWrite::Delete { key: b(k) },
                })
                .collect(),
        }
    }
}

impl From<WireBatch> for Batch {
    fn from(wire: WireBatch) -> Self {
        Self {
            preconditions: wire
                .preconditions
                .into_iter()
                .map(|p| match p {
                    WirePrecondition::Absent { key: k } => Precondition::Absent(key(k)),
                    WirePrecondition::Present { key: k } => Precondition::Present(key(k)),
                    WirePrecondition::Equals { key: k, value: v } => {
                        Precondition::Equals(key(k), value(v))
                    }
                    WirePrecondition::NotAfter { deadline_ms } => {
                        Precondition::NotAfter(deadline_ms)
                    }
                })
                .collect(),
            writes: wire
                .writes
                .into_iter()
                .map(|w| match w {
                    WireWrite::Put { key: k, value: v } => Write::Put(key(k), value(v)),
                    WireWrite::Delete { key: k } => Write::Delete(key(k)),
                })
                .collect(),
        }
    }
}

/// A [`BatchOutcome`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WireOutcome {
    /// `Committed`.
    Committed,
    /// `PreconditionFailed`.
    PreconditionFailed {
        index: usize,
        observed: Option<Blob>,
    },
    /// `DeadlinePassed`.
    DeadlinePassed { backend_now: u64 },
}

impl From<BatchOutcome> for WireOutcome {
    fn from(o: BatchOutcome) -> Self {
        match o {
            BatchOutcome::Committed => Self::Committed,
            BatchOutcome::PreconditionFailed { index, observed } => Self::PreconditionFailed {
                index,
                observed: observed.map(|v| Blob::from(v.as_bytes())),
            },
            BatchOutcome::DeadlinePassed { backend_now } => Self::DeadlinePassed { backend_now },
        }
    }
}

impl From<WireOutcome> for BatchOutcome {
    fn from(o: WireOutcome) -> Self {
        match o {
            WireOutcome::Committed => Self::Committed,
            WireOutcome::PreconditionFailed { index, observed } => Self::PreconditionFailed {
                index,
                observed: observed.map(value),
            },
            WireOutcome::DeadlinePassed { backend_now } => Self::DeadlinePassed { backend_now },
        }
    }
}

/// A Durable Object's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum NsReply {
    /// To `Get`.
    Value { value: Option<Blob> },
    /// To `GetMany`, in request order.
    Values { values: Vec<Option<Blob>> },
    /// To `Scan` and `Export`.
    Page {
        entries: Vec<(Blob, Blob)>,
        next: Option<Blob>,
    },
    /// To `Apply`.
    Outcome { outcome: WireOutcome },
    /// To `Stats`.
    Stats { bytes: u64, keys: Option<u64> },
    /// To `Probe`.
    Ok,
    /// A typed failure; `message` never holds backend detail.
    Err { kind: NsErrKind, message: String },
}

/// The [`StoreError`] kinds a Durable Object reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NsErrKind {
    /// `Invalid`.
    Invalid,
    /// `Unsupported`.
    Unsupported,
    /// `Corrupt`.
    Corrupt,
    /// `Full`: the Durable Object is at its soft cap.
    Full,
    /// `Unavailable`: the Durable Object failed; its log has the detail.
    Unavailable,
}

/// The fixed message of an `Unavailable` reply.
pub const UNAVAILABLE_MESSAGE: &str = "ref store request failed";

impl NsReply {
    /// A scan or export page.
    #[must_use]
    pub fn page(page: ScanPage) -> Self {
        Self::Page {
            entries: page
                .entries
                .into_iter()
                .map(|(k, v)| (Blob::from(k.as_bytes()), Blob::from(v.as_bytes())))
                .collect(),
            next: page.next.map(|c| Blob::from(c.as_bytes())),
        }
    }

    /// The reply for `e`. An `Unavailable` error's detail stays out of it:
    /// the Durable Object logs it.
    #[must_use]
    pub fn error(e: &StoreError) -> Self {
        let (kind, message) = match e {
            StoreError::Invalid(m) => (NsErrKind::Invalid, m.to_string()),
            StoreError::RangeNotSatisfiable { .. } => (NsErrKind::Invalid, e.to_string()),
            StoreError::Unsupported(m) => (NsErrKind::Unsupported, m.to_string()),
            StoreError::Corrupt(m) => (NsErrKind::Corrupt, m.to_string()),
            StoreError::Full => (NsErrKind::Full, String::new()),
            _ => (NsErrKind::Unavailable, UNAVAILABLE_MESSAGE.to_owned()),
        };
        Self::Err { kind, message }
    }
}

impl NsErrKind {
    /// The [`StoreError`] this kind stands for.
    #[must_use]
    pub fn into_error(self, message: String) -> StoreError {
        match self {
            Self::Invalid => StoreError::Invalid(message.into()),
            Self::Unsupported => StoreError::Unsupported(message.into()),
            Self::Corrupt => StoreError::Corrupt(message.into()),
            Self::Full => StoreError::Full,
            Self::Unavailable => StoreError::unavailable(UNAVAILABLE_MESSAGE),
        }
    }
}

/// A page's entries as contract types.
pub(crate) fn scan_page(entries: Vec<(Blob, Blob)>, next: Option<Blob>) -> ScanPage {
    ScanPage {
        entries: entries
            .into_iter()
            .map(|(k, v)| (key(k), value(v)))
            .collect(),
        next: next.map(|c| Cursor::new(c.0)),
    }
}

/// A page's entries as export records of `p`.
pub(crate) fn export_records(p: &Partition, entries: Vec<(Blob, Blob)>) -> Vec<ExportRecord> {
    entries
        .into_iter()
        .map(|(k, v)| ExportRecord::new(p.clone(), key(k), value(v)))
        .collect()
}

/// Stats from their wire fields.
pub(crate) fn stats(bytes: u64, keys: Option<u64>) -> PartitionStats {
    PartitionStats { bytes, keys }
}

pub(crate) fn into_value(b: Option<Blob>) -> Option<Value> {
    b.map(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> Key {
        Key::new(s.as_bytes().to_vec())
    }

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + fmt::Debug>(t: &T) {
        let json = serde_json::to_string(t).unwrap();
        assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), t, "{json}");
    }

    #[test]
    fn ns_call_roundtrips_every_variant() {
        let batch = Batch::new()
            .require(Precondition::Absent(k("a")))
            .require(Precondition::Present(k("b")))
            .require(Precondition::Equals(k("c"), Value::new(vec![0, 255, 7])))
            .require(Precondition::NotAfter(u64::MAX - 1))
            .put(k("d"), Value::new(Vec::new()))
            .delete(k("e"));
        let wire = WireBatch::from(batch.clone());
        assert_eq!(Batch::from(wire.clone()), batch);
        let blob = |s: &str| Blob::from(s.as_bytes());
        let calls = [
            NsCall::Get { key: blob("k") },
            NsCall::GetMany {
                keys: vec![blob("x"), blob("")],
            },
            NsCall::Scan {
                start: blob(""),
                end: blob("\u{7f}"),
                after: Some(blob("m")),
                limit: u32::MAX,
            },
            NsCall::Apply { batch: wire },
            NsCall::Stats,
            NsCall::Probe,
            NsCall::Export {
                after: None,
                limit: 1,
            },
        ];
        let p = Partition::decode(b"nroot\0").unwrap();
        for call in calls {
            roundtrip(&NsRequest::new(&p, call).unwrap());
        }
        // The deadline is a plain JSON integer, exact at u64 range.
        let json = serde_json::to_string(&WirePrecondition::NotAfter {
            deadline_ms: u64::MAX - 1,
        })
        .unwrap();
        assert_eq!(
            json,
            r#"{"kind":"not_after","deadline_ms":18446744073709551614}"#
        );
        // Bytes are base64, and a malformed string is rejected.
        assert_eq!(serde_json::to_string(&blob("hi")).unwrap(), r#""aGk=""#);
        assert!(serde_json::from_str::<Blob>(r#""not base64!""#).is_err());
        for outcome in [
            BatchOutcome::Committed,
            BatchOutcome::PreconditionFailed {
                index: 3,
                observed: Some(Value::new(vec![1])),
            },
            BatchOutcome::PreconditionFailed {
                index: 0,
                observed: None,
            },
            BatchOutcome::DeadlinePassed { backend_now: 42 },
        ] {
            let wire = WireOutcome::from(outcome.clone());
            roundtrip(&NsReply::Outcome {
                outcome: wire.clone(),
            });
            assert_eq!(BatchOutcome::from(wire), outcome);
        }
    }

    #[test]
    fn ns_reply_err_kinds_map_to_store_errors() {
        let cases: [(StoreError, NsErrKind); 6] = [
            (StoreError::Invalid("bad key".into()), NsErrKind::Invalid),
            (StoreError::Unsupported("no".into()), NsErrKind::Unsupported),
            (StoreError::Corrupt("row".into()), NsErrKind::Corrupt),
            (StoreError::Full, NsErrKind::Full),
            (
                StoreError::RangeNotSatisfiable { len: 3 },
                NsErrKind::Invalid,
            ),
            (
                StoreError::unavailable("sqlite at /secret/path"),
                NsErrKind::Unavailable,
            ),
        ];
        for (error, want) in cases {
            let reply = NsReply::error(&error);
            roundtrip(&reply);
            let NsReply::Err { kind, message } = reply else {
                panic!("not an error reply");
            };
            assert_eq!(kind, want);
            assert!(!message.contains("secret"), "{message}");
            let back = kind.into_error(message);
            let same = matches!(
                (&error, &back),
                (
                    StoreError::Invalid(_) | StoreError::RangeNotSatisfiable { .. },
                    StoreError::Invalid(_)
                ) | (StoreError::Unsupported(_), StoreError::Unsupported(_))
                    | (StoreError::Corrupt(_), StoreError::Corrupt(_))
                    | (StoreError::Full, StoreError::Full)
                    | (StoreError::Unavailable(_), StoreError::Unavailable(_))
            );
            assert!(same, "{error:?} came back as {back:?}");
            assert!(!format!("{back:?}").contains("secret"));
        }
        roundtrip(&NsReply::Ok);
        roundtrip(&NsReply::Stats {
            bytes: 1,
            keys: None,
        });
        roundtrip(&NsReply::page(ScanPage {
            entries: vec![(k("a"), Value::new(vec![1]))],
            next: Some(Cursor::new(b"a".to_vec())),
        }));
    }
}
