//! Local pair-coverage checkpoint, version 1. Corruption detection only.
//!
//! Layout (all little-endian), followed by a 32-byte checksum:
//! `BLAKE3(le16(domain_len) || "mkit-pair-checkpoint:v1" || body)`.
//!
//! `version` u8 = 1; repository[32]; view[32]; ruleset u32; profile u8;
//! flags u8 (bit0 head, bit1 packmap, bit2 branch, bit3 `honor_cleared`,
//! bit4 boundary seen; other bits invalid); head[32]?; packmap[32]?;
//! limits u32×7 then work u64; phase u8 (0 chain, 1 walk, 2 base);
//! next packmap (tag 0/1 + [32]); base cursor (tag + origin[32] next[32]
//! depth u32); work used u64; counted ID lists (u32 count + ids):
//! additions, chain, packs, visited, dependencies, suppliers, queue.
//! Set lists are strictly ascending; the queue keeps pop order.

use super::{
    BaseCursor, FLAG_BOUNDARY_SEEN, FLAG_HEAD_CHECKED, PairCheckpointCfg, PairResume,
    PairWalker, ResultingPair,
};
use crate::{
    error::{BoundedDetail, Failure, FailureCode, Location},
    evidence::{ProfileId, RepositoryId, Revision, RulesetBinding, RulesetId},
};
use mkit_core::hash::{Hash, domain_digest};
use std::collections::{BTreeSet, VecDeque};

const DOMAIN: &[u8] = b"mkit-pair-checkpoint:v1";
const VERSION: u8 = 1;
const FLAG_HEAD: u8 = 1;
const FLAG_PACKMAP: u8 = 2;
const FLAG_BRANCH: u8 = 4;
const FLAG_CLEARED: u8 = 8;
const FLAG_BOUNDARY: u8 = 16;
const KNOWN_FLAGS: u8 = FLAG_HEAD | FLAG_PACKMAP | FLAG_BRANCH | FLAG_CLEARED | FLAG_BOUNDARY;
const PHASE_CHAIN: u8 = 0;
const PHASE_WALK: u8 = 1;
const PHASE_BASE: u8 = 2;

fn invalid() -> Failure {
    failure(FailureCode::InvalidCheckpoint)
}
fn failure(code: FailureCode) -> Failure {
    Failure {
        code,
        location: Location::default(),
        detail: BoundedDetail::None,
    }
}

fn put_ids(out: &mut Vec<u8>, ids: &[Hash]) {
    out.extend_from_slice(&u32::try_from(ids.len()).unwrap_or(u32::MAX).to_le_bytes());
    for id in ids {
        out.extend_from_slice(id);
    }
}

pub(super) fn encode(walker: &PairWalker) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    out.try_reserve(256).map_err(|_| failure(FailureCode::ResourceLimit))?;
    out.push(VERSION);
    out.extend_from_slice(&walker.repository.0);
    out.extend_from_slice(&walker.view.0);
    out.extend_from_slice(&walker.ruleset.ruleset.0.to_le_bytes());
    out.push(match walker.ruleset.profile {
        ProfileId::Indexed => 1,
    });
    let mut flags = 0u8;
    flags |= u8::from(walker.pair.head.is_some()) * FLAG_HEAD;
    flags |= u8::from(walker.pair.packmap.is_some()) * FLAG_PACKMAP;
    flags |= u8::from(walker.pair.branch) * FLAG_BRANCH;
    flags |= u8::from(walker.honor_cleared) * FLAG_CLEARED;
    flags |= u8::from(walker.boundary_seen()) * FLAG_BOUNDARY;
    out.push(flags);
    if let Some(head) = walker.pair.head {
        out.extend_from_slice(&head);
    }
    if let Some(packmap) = walker.pair.packmap {
        out.extend_from_slice(&packmap);
    }
    for limit in [
        walker.limits.chain,
        walker.limits.packs,
        walker.limits.discovered,
        walker.limits.dependencies,
        walker.limits.suppliers,
        walker.limits.cleared,
        walker.limits.max_delta_depth,
    ] {
        out.extend_from_slice(&limit.to_le_bytes());
    }
    out.extend_from_slice(&walker.limits.work.to_le_bytes());
    let phase = if walker.next.is_some() {
        PHASE_CHAIN
    } else if walker.cursor.is_some() {
        PHASE_BASE
    } else {
        PHASE_WALK
    };
    out.push(phase);
    if let Some(next) = walker.next {
        out.push(1);
        out.extend_from_slice(&next);
    } else {
        out.push(0);
    }
    if let Some(cursor) = walker.cursor {
        out.push(1);
        out.extend_from_slice(&cursor.origin);
        out.extend_from_slice(&cursor.next);
        out.extend_from_slice(&cursor.depth.to_le_bytes());
    } else {
        out.push(0);
    }
    out.extend_from_slice(&walker.work.to_le_bytes());
    put_ids(&mut out, &walker.additions);
    put_ids(&mut out, &walker.chain);
    put_ids(&mut out, &walker.packs);
    let visited: Vec<Hash> = walker.visited.iter().copied().collect();
    put_ids(&mut out, &visited);
    put_ids(&mut out, &walker.dependencies);
    put_ids(&mut out, &walker.suppliers);
    let queue: Vec<Hash> = walker.queue.iter().copied().collect();
    put_ids(&mut out, &queue);
    let checksum = domain_digest(DOMAIN, &out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Failure> {
        let end = self
            .position
            .checked_add(n)
            .ok_or_else(invalid)?;
        let slice = self.bytes.get(self.position..end).ok_or_else(invalid)?;
        self.position = end;
        Ok(slice)
    }
    fn byte(&mut self) -> Result<u8, Failure> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, Failure> {
        self.take(4)?
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| invalid())
    }
    fn u64(&mut self) -> Result<u64, Failure> {
        self.take(8)?
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| invalid())
    }
    fn id(&mut self) -> Result<Hash, Failure> {
        self.take(32)?.try_into().map_err(|_| invalid())
    }
    fn optional(&mut self) -> Result<bool, Failure> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid()),
        }
    }
    /// One counted ID list; `sorted` enforces strict ascending order.
    fn ids(&mut self, max: u64, sorted: bool) -> Result<Vec<Hash>, Failure> {
        let count = u64::from(self.u32()?);
        if count > max
            || count
                .checked_mul(32)
                .is_none_or(|bytes| bytes > (self.bytes.len() - self.position) as u64)
        {
            return Err(invalid());
        }
        let count = usize::try_from(count).map_err(|_| invalid())?;
        let mut ids = Vec::new();
        ids.try_reserve_exact(count)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        for _ in 0..count {
            let id = self.id()?;
            if sorted && ids.last().is_some_and(|last| *last >= id) {
                return Err(invalid());
            }
            ids.push(id);
        }
        Ok(ids)
    }
}

/// Strict structural decode; expected-parameter binding happens in `decode`.
fn parse(bytes: &[u8], cfg: PairCheckpointCfg) -> Result<Parsed, Failure> {
    if bytes.len() > cfg.max_bytes as usize || bytes.len() < 32 + 1 {
        return Err(invalid());
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    let checksum: Hash = checksum.try_into().map_err(|_| invalid())?;
    if domain_digest(DOMAIN, body) != checksum {
        return Err(invalid());
    }
    let mut input = Cursor {
        bytes: body,
        position: 0,
    };
    if input.byte()? != VERSION {
        return Err(invalid());
    }
    let repository = RepositoryId(input.id()?);
    let view = Revision(input.id()?);
    let ruleset = RulesetId(input.u32()?);
    let profile = match input.byte()? {
        1 => ProfileId::Indexed,
        _ => return Err(invalid()),
    };
    let flags = input.byte()?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(invalid());
    }
    let head = if flags & FLAG_HEAD != 0 {
        Some(input.id()?)
    } else {
        None
    };
    let packmap = if flags & FLAG_PACKMAP != 0 {
        Some(input.id()?)
    } else {
        None
    };
    let limits = super::PairLimits {
        chain: input.u32()?,
        packs: input.u32()?,
        discovered: input.u32()?,
        dependencies: input.u32()?,
        suppliers: input.u32()?,
        cleared: input.u32()?,
        max_delta_depth: input.u32()?,
        work: input.u64()?,
    };
    let body_state = body_of(&mut input, limits, body.len())?;
    let parsed = Parsed {
        repository,
        view,
        ruleset: RulesetBinding { ruleset, profile },
        pair: ResultingPair {
            head,
            packmap,
            branch: flags & FLAG_BRANCH != 0,
        },
        honor_cleared: flags & FLAG_CLEARED != 0,
        boundary_seen: flags & FLAG_BOUNDARY != 0,
        limits,
        phase: body_state.phase,
        next: body_state.next,
        cursor: body_state.cursor,
        work: body_state.work,
        additions: body_state.additions,
        chain: body_state.chain,
        packs: body_state.packs,
        visited: body_state.visited,
        dependencies: body_state.dependencies,
        suppliers: body_state.suppliers,
        queue: body_state.queue,
    };
    parsed.consistent()?;
    Ok(parsed)
}

/// Phase, cursors, and counted lists after the fixed-width header.
fn body_of(
    input: &mut Cursor<'_>,
    limits: super::PairLimits,
    len: usize,
) -> Result<Body, Failure> {
    let phase = input.byte()?;
    if phase > PHASE_BASE {
        return Err(invalid());
    }
    let next = if input.optional()? {
        Some(input.id()?)
    } else {
        None
    };
    let cursor = if input.optional()? {
        Some(BaseCursor {
            origin: input.id()?,
            next: input.id()?,
            depth: input.u32()?,
        })
    } else {
        None
    };
    let work = input.u64()?;
    let additions = input.ids(u64::from(u32::MAX), true)?;
    let chain = input.ids(u64::from(limits.chain), true)?;
    let packs = input.ids(u64::from(limits.packs), true)?;
    let visited = input.ids(u64::from(limits.discovered), true)?;
    let dependencies = input.ids(u64::from(limits.dependencies), true)?;
    let suppliers = input.ids(u64::from(limits.suppliers), true)?;
    let queue = input.ids(u64::from(limits.discovered), false)?;
    if input.position != len {
        return Err(invalid());
    }
    Ok(Body {
        phase,
        next,
        cursor,
        work,
        additions,
        chain,
        packs,
        visited,
        dependencies,
        suppliers,
        queue,
    })
}
struct Body {
    phase: u8,
    next: Option<Hash>,
    cursor: Option<BaseCursor>,
    work: u64,
    additions: Vec<Hash>,
    chain: Vec<Hash>,
    packs: Vec<Hash>,
    visited: Vec<Hash>,
    dependencies: Vec<Hash>,
    suppliers: Vec<Hash>,
    queue: Vec<Hash>,
}

struct Parsed {
    repository: RepositoryId,
    view: Revision,
    ruleset: RulesetBinding,
    pair: ResultingPair,
    honor_cleared: bool,
    boundary_seen: bool,
    limits: super::PairLimits,
    phase: u8,
    next: Option<Hash>,
    cursor: Option<BaseCursor>,
    work: u64,
    additions: Vec<Hash>,
    chain: Vec<Hash>,
    packs: Vec<Hash>,
    visited: Vec<Hash>,
    dependencies: Vec<Hash>,
    suppliers: Vec<Hash>,
    queue: Vec<Hash>,
}
impl Parsed {
    fn consistent(&self) -> Result<(), Failure> {
        // Phase tags, optional fields, and set relations stay mutually consistent.
        if (self.phase == PHASE_CHAIN) != self.next.is_some()
            || (self.phase == PHASE_BASE) != self.cursor.is_some()
            || (self.phase == PHASE_CHAIN && !self.visited.is_empty())
        {
            return Err(invalid());
        }
        let visited: BTreeSet<Hash> = self.visited.iter().copied().collect();
        let mut queued = BTreeSet::new();
        for id in &self.queue {
            if !queued.insert(*id) || visited.contains(id) {
                return Err(invalid());
            }
        }
        let dependencies: BTreeSet<Hash> = self.dependencies.iter().copied().collect();
        if !self.chain.iter().all(|id| dependencies.contains(id))
            || !self.packs.iter().all(|id| dependencies.contains(id))
            || self.work > self.limits.work
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn walker(self, generation: u64) -> Result<PairWalker, Failure> {
        let mut walker = PairWalker::new(
            self.pair,
            &self.additions,
            self.repository,
            self.view,
            self.ruleset,
            self.limits,
            self.honor_cleared,
            generation,
        )?;
        walker.next = self.next;
        walker.chain = self.chain;
        walker.packs = self.packs;
        if self.boundary_seen {
            walker.flags |= FLAG_BOUNDARY_SEEN;
        }
        walker.visited = self.visited.iter().copied().collect();
        walker.queued = self.queue.iter().copied().collect();
        walker.queue = VecDeque::from_iter(self.queue);
        walker.cursor = self.cursor;
        walker.dependencies = self.dependencies;
        walker.suppliers = self.suppliers;
        walker.work = self.work;
        walker.flags |= FLAG_HEAD_CHECKED;
        Ok(walker)
    }
}

/// Decode and bind a checkpoint to its expected parameters.
pub(super) fn decode(
    bytes: &[u8],
    cfg: PairCheckpointCfg,
    expected: &PairResume<'_>,
    generation: u64,
) -> Result<PairWalker, Failure> {
    let parsed = parse(bytes, cfg)?;
    let mut additions = expected.additions.to_vec();
    additions.sort_unstable();
    additions.dedup();
    if parsed.pair != expected.pair
        || parsed.additions != additions
        || parsed.repository != expected.repository
        || parsed.view != expected.view
        || parsed.ruleset != expected.ruleset
        || parsed.limits != expected.limits
        || parsed.honor_cleared != expected.honor_cleared
    {
        return Err(invalid());
    }
    parsed.walker(generation)
}

/// Structural validation for stored rows, without run bindings.
pub(super) fn validate(bytes: &[u8], cfg: PairCheckpointCfg) -> Result<(), Failure> {
    parse(bytes, cfg).map(|_| ())
}
