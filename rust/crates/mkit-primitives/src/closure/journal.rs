//! Fixed-resident authenticated visited state. The host retains immutable pages.
//!
//! Every acknowledged write prepends one record to one of 256 bucket chains.
//! Lookup reads at most one page per supply; the caller charges every request,
//! page byte, and step to its cumulative execution budgets.

use crate::{
    error::{BoundedDetail, Failure, FailureCode, Location},
    evidence::{
        MemberFact, PackSource, PageCommitment, PageKind, RepositoryId, Revision, SourceBinding,
    },
};
use mkit_core::{
    hash::{Hash, domain_digest},
    object::ObjectType,
};

const MAX_PAGE_BYTES: usize = 1024;
const DOMAIN: &[u8] = b"mkit-closure-state:v1";

// Fixed resident facts avoid an allocation per visited-state transition.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum State {
    Gray,
    Black,
    Absent,
    Member(MemberFact),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Record {
    pub kind: ObjectType,
    pub canonical_len: u64,
    pub state: State,
    pub blob_payload_len: Option<u64>,
}

/// Opaque committed roots. Pending writes are deliberately excluded.
#[derive(Debug, Clone)]
pub(super) struct Roots([Option<PageCommitment>; 256]);

// Keep bounded lookup output inline rather than allocating per lookup.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Lookup {
    NeedPage(PageCommitment),
    Found(Option<Record>),
}

// The one fixed outstanding slot includes a bounded member witness.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
enum Pending {
    Lookup {
        id: Hash,
        cursor: Option<PageCommitment>,
        found: Option<Record>,
    },
    Put {
        bucket: usize,
        page: PageCommitment,
    },
}

#[derive(Debug, Clone)]
pub(super) struct Journal {
    roots: Roots,
    pending: Option<Pending>,
}

impl Journal {
    pub fn new() -> Self {
        Self::from_roots(Roots([None; 256]))
    }

    pub fn from_roots(roots: Roots) -> Self {
        Self {
            roots,
            pending: None,
        }
    }

    #[cfg(test)]
    pub fn roots(&self) -> Roots {
        self.roots.clone()
    }

    /// Starts or advances the same lookup. Found releases the outstanding slot.
    pub fn lookup(&mut self, id: &Hash) -> Result<Lookup, Failure> {
        if self.pending.is_none() {
            self.pending = Some(Pending::Lookup {
                id: *id,
                cursor: self.roots.0[usize::from(id[0])],
                found: None,
            });
        }
        match &self.pending {
            Some(Pending::Lookup {
                id: requested,
                cursor,
                found,
            }) if requested == id => {
                if let Some(page) = cursor {
                    Ok(Lookup::NeedPage(*page))
                } else {
                    let result = Lookup::Found(found.clone());
                    self.pending = None;
                    Ok(result)
                }
            }
            _ => Err(failure(FailureCode::InvalidResponse)),
        }
    }

    /// Authenticates precisely the currently requested page before parsing it.
    pub fn supply(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        let (id, expected) = match &self.pending {
            Some(Pending::Lookup {
                id,
                cursor: Some(page),
                ..
            }) => (*id, *page),
            _ => return Err(failure(FailureCode::InvalidResponse)),
        };
        valid_commitment(expected)?;
        if bytes.len() > MAX_PAGE_BYTES
            || bytes.len() as u64 != expected.len
            || domain_digest(DOMAIN, bytes) != expected.digest
        {
            return Err(failure(FailureCode::InvalidResponse));
        }
        let (previous, key, record) = decode(bytes)?;
        if key[0] != id[0] {
            return Err(failure(FailureCode::InvalidResponse));
        }
        self.pending = Some(if key == id {
            Pending::Lookup {
                id,
                cursor: None,
                found: Some(record),
            }
        } else {
            Pending::Lookup {
                id,
                cursor: previous,
                found: None,
            }
        });
        Ok(())
    }

    /// A lost page is acquisition failure; it never advances toward absence.
    #[cfg(test)]
    pub fn unavailable(&self) -> Result<(), Failure> {
        match self.pending {
            Some(Pending::Lookup {
                cursor: Some(_), ..
            }) => Err(failure(FailureCode::UnavailableInput)),
            _ => Err(failure(FailureCode::InvalidResponse)),
        }
    }

    /// Produces one immutable page. Only acknowledgement publishes its root.
    pub fn put(&mut self, id: Hash, record: Record) -> Result<(PageCommitment, Vec<u8>), Failure> {
        if self.pending.is_some() {
            return Err(failure(FailureCode::InvalidResponse));
        }
        validate_record(&id, &record)?;
        let bucket = usize::from(id[0]);
        let bytes = encode(self.roots.0[bucket], id, &record)?;
        let page = PageCommitment {
            digest: domain_digest(DOMAIN, &bytes),
            kind: PageKind::Closure,
            len: bytes.len() as u64,
            items: 1,
        };
        self.pending = Some(Pending::Put { bucket, page });
        Ok((page, bytes))
    }

    pub fn acknowledge(&mut self, commitment: PageCommitment) -> Result<(), Failure> {
        match &self.pending {
            Some(Pending::Put { bucket, page }) if *page == commitment => {
                self.roots.0[*bucket] = Some(*page);
                self.pending = None;
                Ok(())
            }
            _ => Err(failure(FailureCode::InvalidResponse)),
        }
    }
}

fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

fn valid_commitment(page: PageCommitment) -> Result<(), Failure> {
    if page.kind != PageKind::Closure
        || page.items != 1
        || page.len == 0
        || page.len > MAX_PAGE_BYTES as u64
    {
        return Err(failure(FailureCode::InvalidResponse));
    }
    Ok(())
}

fn validate_record(id: &Hash, record: &Record) -> Result<(), Failure> {
    if let Some(len) = record.blob_payload_len
        && (record.kind != ObjectType::Blob || record.canonical_len.checked_sub(10) != Some(len))
    {
        return Err(failure(FailureCode::InvalidResponse));
    }

    if let State::Member(fact) = &record.state
        && (fact.object != *id
            || fact.kind != record.kind
            || fact.canonical_len != record.canonical_len)
    {
        return Err(failure(FailureCode::InvalidResponse));
    }
    Ok(())
}

// Private grammar: version:u8=1; previous:(0 | 1,digest:32,len:le64);
// key:32; kind:u8; canonical_len:le64; payload_len:(0 | 1,le64);
// state:(0=gray | 1=black | 2=absent | 3=member,member_fields).
// Member fields preserve every host fact, in declaration order; booleans are 0/1.
// Previous pages always have role Closure and exactly one item.
fn encode(previous: Option<PageCommitment>, id: Hash, record: &Record) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    out.try_reserve_exact(MAX_PAGE_BYTES)
        .map_err(|_| failure(FailureCode::ResourceLimit))?;
    out.push(1);
    if let Some(page) = previous {
        valid_commitment(page)?;
        out.push(1);
        out.extend_from_slice(&page.digest);
        out.extend_from_slice(&page.len.to_le_bytes());
    } else {
        out.push(0);
    }
    out.extend_from_slice(&id);
    out.push(record.kind as u8);
    out.extend_from_slice(&record.canonical_len.to_le_bytes());
    if let Some(len) = record.blob_payload_len {
        out.push(1);
        out.extend_from_slice(&len.to_le_bytes());
    } else {
        out.push(0);
    }
    match &record.state {
        State::Gray => out.push(0),
        State::Black => out.push(1),
        State::Absent => out.push(2),
        State::Member(fact) => {
            out.push(3);
            out.extend_from_slice(&fact.repository.0);
            out.extend_from_slice(&fact.incarnation.0);
            out.extend_from_slice(&fact.object);
            out.push(fact.kind as u8);
            out.extend_from_slice(&fact.canonical_len.to_le_bytes());
            out.extend_from_slice(&fact.supplier.id);
            out.extend_from_slice(&fact.supplier.len.to_le_bytes());
            out.extend_from_slice(&fact.supplier.binding.0);
            out.extend_from_slice(&fact.canonical_binding.0);
            out.extend_from_slice(&fact.revision.0);
            out.extend_from_slice(&fact.delta_depth.to_le_bytes());
            out.push(u8::from(fact.published));
            out.push(u8::from(fact.held));
        }
    }
    if out.len() > MAX_PAGE_BYTES {
        return Err(failure(FailureCode::ResourceLimit));
    }
    Ok(out)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Failure> {
        let end = self
            .position
            .checked_add(N)
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| failure(FailureCode::InvalidResponse))?;
        let mut value = [0; N];
        value.copy_from_slice(slice);
        self.position = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, Failure> {
        Ok(self.take::<1>()?[0])
    }
    fn number(&mut self) -> Result<u64, Failure> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn boolean(&mut self) -> Result<bool, Failure> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(failure(FailureCode::InvalidResponse)),
        }
    }
    fn kind(&mut self) -> Result<ObjectType, Failure> {
        match self.byte()? {
            1 => Ok(ObjectType::Blob),
            2 => Ok(ObjectType::Tree),
            3 => Ok(ObjectType::Commit),
            4 => Ok(ObjectType::Remix),
            5 => Ok(ObjectType::ChunkedBlob),
            6 => Ok(ObjectType::Delta),
            7 => Ok(ObjectType::Tag),
            _ => Err(failure(FailureCode::InvalidResponse)),
        }
    }
}

fn decode(bytes: &[u8]) -> Result<(Option<PageCommitment>, Hash, Record), Failure> {
    if bytes.len() > MAX_PAGE_BYTES {
        return Err(failure(FailureCode::InvalidResponse));
    }
    let mut input = Cursor { bytes, position: 0 };
    if input.byte()? != 1 {
        return Err(failure(FailureCode::InvalidResponse));
    }
    let previous = if input.boolean()? {
        let page = PageCommitment {
            digest: input.take()?,
            kind: PageKind::Closure,
            len: input.number()?,
            items: 1,
        };
        valid_commitment(page)?;
        Some(page)
    } else {
        None
    };
    let id = input.take()?;
    let kind = input.kind()?;
    let canonical_len = input.number()?;
    let blob_payload_len = if input.boolean()? {
        Some(input.number()?)
    } else {
        None
    };
    let state = match input.byte()? {
        0 => State::Gray,
        1 => State::Black,
        2 => State::Absent,
        3 => State::Member(MemberFact {
            repository: RepositoryId(input.take()?),
            incarnation: Revision(input.take()?),
            object: input.take()?,
            kind: input.kind()?,
            canonical_len: input.number()?,
            supplier: PackSource {
                id: input.take()?,
                len: input.number()?,
                binding: SourceBinding(input.take()?),
            },
            canonical_binding: SourceBinding(input.take()?),
            revision: Revision(input.take()?),
            delta_depth: u32::from_le_bytes(input.take()?),
            published: input.boolean()?,
            held: input.boolean()?,
        }),
        _ => return Err(failure(FailureCode::InvalidResponse)),
    };
    if input.position != bytes.len() {
        return Err(failure(FailureCode::InvalidResponse));
    }
    let record = Record {
        kind,
        canonical_len,
        state,
        blob_payload_len,
    };
    validate_record(&id, &record)?;
    Ok((previous, id, record))
}

pub(super) fn validate_bytes(bytes: &[u8]) -> Result<(), Failure> {
    decode(bytes).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(state: State) -> Record {
        Record {
            kind: ObjectType::Blob,
            canonical_len: 19,
            state,
            blob_payload_len: Some(9),
        }
    }
    fn store(journal: &mut Journal, id: Hash, record: Record) -> (PageCommitment, Vec<u8>) {
        let (page, bytes) = journal.put(id, record).unwrap();
        journal.acknowledge(page).unwrap();
        (page, bytes)
    }
    fn need(journal: &mut Journal, id: &Hash, expected: PageCommitment) {
        assert_eq!(journal.lookup(id).unwrap(), Lookup::NeedPage(expected));
    }

    #[test]
    fn append_lookup_update_and_collision_chain() {
        let mut journal = Journal::new();
        let first = [3; 32];
        let mut second = first;
        second[1] = 4;
        assert_eq!(journal.lookup(&first).unwrap(), Lookup::Found(None));
        let (old, old_bytes) = store(&mut journal, first, record(State::Gray));
        let (other, other_bytes) = store(&mut journal, second, record(State::Black));
        need(&mut journal, &first, other);
        journal.supply(&other_bytes).unwrap();
        need(&mut journal, &first, old);
        journal.supply(&old_bytes).unwrap();
        assert_eq!(
            journal.lookup(&first).unwrap(),
            Lookup::Found(Some(record(State::Gray)))
        );
        let (updated, updated_bytes) = store(&mut journal, first, record(State::Black));
        need(&mut journal, &first, updated);
        journal.supply(&updated_bytes).unwrap();
        assert_eq!(
            journal.lookup(&first).unwrap(),
            Lookup::Found(Some(record(State::Black)))
        );
    }

    #[test]
    fn roots_exclude_unacknowledged_put_and_clone_preserves_pending_write() {
        let mut journal = Journal::new();
        let id = [7; 32];
        let (page, bytes) = journal.put(id, record(State::Gray)).unwrap();
        let mut restarted = Journal::from_roots(journal.roots());
        assert_eq!(restarted.lookup(&id).unwrap(), Lookup::Found(None));
        let mut resumed = journal.clone();
        resumed.acknowledge(page).unwrap();
        let mut restarted = Journal::from_roots(resumed.roots());
        need(&mut restarted, &id, page);
        restarted.supply(&bytes).unwrap();
        assert_eq!(
            restarted.lookup(&id).unwrap(),
            Lookup::Found(Some(record(State::Gray)))
        );
    }

    #[test]
    fn wrong_and_lost_pages_never_prove_absence() {
        let mut journal = Journal::new();
        let id = [8; 32];
        let (page, bytes) = store(&mut journal, id, record(State::Black));
        need(&mut journal, &id, page);
        assert_eq!(
            journal.unavailable().unwrap_err().code,
            FailureCode::UnavailableInput
        );
        assert_eq!(
            journal.supply(&[]).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        need(&mut journal, &id, page);
        let mut restarted = journal.clone();
        restarted.supply(&bytes).unwrap();
        assert_eq!(
            restarted.lookup(&id).unwrap(),
            Lookup::Found(Some(record(State::Black)))
        );
        need(&mut journal, &id, page);
    }

    #[test]
    fn conflicting_operations_refuse_without_advancing() {
        let mut journal = Journal::new();
        let id = [9; 32];
        let other = [10; 32];
        let (page, bytes) = journal.put(id, record(State::Gray)).unwrap();
        assert_eq!(
            journal.lookup(&id).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        assert_eq!(
            journal.put(other, record(State::Gray)).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        let mut wrong = page;
        wrong.len += 1;
        assert_eq!(
            journal.acknowledge(wrong).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        journal.acknowledge(page).unwrap();
        need(&mut journal, &id, page);
        assert_eq!(
            journal.lookup(&other).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        assert_eq!(
            journal.put(other, record(State::Gray)).unwrap_err().code,
            FailureCode::InvalidResponse
        );
        journal.supply(&bytes).unwrap();
        assert_eq!(
            journal.supply(&bytes).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }

    #[test]
    fn member_facts_round_trip_and_bind_to_the_key() {
        let id = [11; 32];
        let fact = MemberFact {
            repository: RepositoryId([1; 32]),
            incarnation: Revision([2; 32]),
            object: id,
            kind: ObjectType::Blob,
            canonical_len: 19,
            supplier: PackSource {
                id: [3; 32],
                len: 100,
                binding: SourceBinding([4; 32]),
            },
            canonical_binding: SourceBinding([5; 32]),
            revision: Revision([6; 32]),
            delta_depth: 7,
            published: true,
            held: false,
        };
        let value = record(State::Member(fact));
        let bytes = encode(None, id, &value).unwrap();
        assert_eq!(decode(&bytes).unwrap(), (None, id, value.clone()));
        let mut journal = Journal::new();
        assert_eq!(
            journal.put([12; 32], value).unwrap_err().code,
            FailureCode::InvalidResponse
        );
    }

    #[test]
    fn strict_grammar_rejects_truncation_suffix_and_reserved_tags() {
        let id = [13; 32];
        let bytes = encode(None, id, &record(State::Absent)).unwrap();
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len]).is_err());
        }
        let mut suffix = bytes.clone();
        suffix.push(0);
        assert!(decode(&suffix).is_err());
        for (offset, value) in [(0, 2), (1, 2), (34, 0), (43, 2), (52, 4)] {
            let mut malformed = bytes.clone();
            malformed[offset] = value;
            assert!(decode(&malformed).is_err(), "offset {offset}");
        }
    }
}
