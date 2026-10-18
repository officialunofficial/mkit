//! Authenticated paged indexes over retained evidence pages.
//!
//! Two index roles share one copy-on-write B-tree over the canonical page
//! format: a keyed map (object-ID index) and append-only ordinal sequences
//! (occurrences, dependencies, head facts). Pages are immutable; every update
//! emits new pages that the host must retain and acknowledge before dependent
//! progress. Lookups and nonmembership are authenticated by the committed
//! root and routed paths; a lost page is acquisition failure, never absence.
use crate::{
    codec::{Budget, Cursor, failure},
    error::{Failure, FailureCode},
    evidence::{
        PageCommitment, PageKind,
        pages::{
            BranchChild, EncodedPage, EvidenceBinding, HEADER_BYTES, LeafRecord, MAX_PAGE_BYTES,
            PAGE_FANOUT, PageView, encode_internal, encode_leaf, read_commitment,
        },
    },
    limits::EvidenceLimits,
};
use mkit_core::hash::Hash;
use std::collections::VecDeque;

const FANOUT: usize = PAGE_FANOUT as usize;
const MAX_DEPTH: usize = 33;

fn invalid() -> Failure {
    failure(FailureCode::InvalidResponse)
}

/// Sorted insertion position and membership result for one descended key.
#[derive(Debug)]
pub(super) struct Descent {
    /// Authenticated leaf reached by the route.
    pub leaf: PageCommitment,
    /// Internal ancestors from root to leaf parent, in descent order.
    pub path: Vec<PathNode>,
    /// The leaf's records, owned and bounded by the page limits.
    pub records: Vec<(Hash, Vec<u8>)>,
    /// First index whose key is not below the descended key.
    pub position: usize,
    /// Whether `records[position]` equals the descended key.
    pub found: bool,
}

impl Descent {
    /// Authenticated value bytes when the descended key is present.
    #[must_use]
    pub(super) fn value(&self) -> Option<&[u8]> {
        self.found.then(|| self.records[self.position].1.as_slice())
    }
}

/// A decoded internal node on a descent path. `choice` is the child slot the
/// route selected below this node.
#[derive(Debug)]
pub(super) struct PathNode {
    commitment: PageCommitment,
    height: u8,
    first: PageCommitment,
    rest: Vec<BranchChild>,
    /// Child slot taken toward the leaf (and later rewrite target).
    choice: usize,
}

/// Restored append position: the open leaf, its contents, and its ancestors.
#[derive(Debug)]
pub(super) struct Spine {
    /// Authenticated open-leaf commitment.
    pub leaf: PageCommitment,
    /// The leaf's committed records.
    pub records: Vec<(Hash, Vec<u8>)>,
    /// Internal ancestors root-first; the last node's `choice` is the leaf slot.
    pub path: Vec<PathNode>,
}

/// How a finished child level grafts into its parent's child table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Graft {
    /// `produced[0]` replaces the child at `choice`.
    Replace,
    /// `produced[0]` replaces at `choice`; `produced[1]` inserts at `choice + 1`.
    ReplaceInsert,
    /// `produced[0]` inserts at `choice + 1` without replacing.
    Insert,
    /// `produced[0]` and `produced[1]` insert at `choice + 1` and `choice + 2`.
    InsertInsert,
}

/// A suspended index operation driven one bounded transition at a time.
// One operation is live at a time and a rewrite is the common case, so boxing
// the smaller variants would add an allocation to every lookup for nothing.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(super) enum Op {
    /// Descend a key (or the rightmost edge) and produce a [`Descent`].
    Descend {
        key: Hash,
        rightmost: bool,
        lower: Option<Hash>,
        upper: Option<Hash>,
        /// Height every page reached next must have; unset until the root.
        expected: Option<u8>,
        path: Vec<PathNode>,
        state: DescendState,
    },
    /// Leaf rewrite plus upward cascade.
    Rewrite {
        /// Graft currently applying to `produced`.
        graft: Graft,
        /// Records to encode at the leaf level.
        records: Vec<(Hash, Vec<u8>)>,
        /// Commitment replaced or extended at the top level.
        prior: PageCommitment,
        /// Internal ancestors, root first.
        path: Vec<PathNode>,
        /// Records added to the committed count.
        added: u64,
        /// Pages queued for emission, in order.
        queue: VecDeque<EncodedPage>,
        /// (insert-separator, commitment) results of the finished level.
        produced: Vec<(Hash, PageCommitment)>,
        /// Emitted page awaiting acknowledgement.
        outstanding: Option<PageCommitment>,
        /// Height of the last encoded level.
        height: u8,
        /// Committed root to publish at `Fin`; set once the top level is known.
        pending_root: Option<PageCommitment>,
        /// Cascading state.
        stage: RewriteStage,
        /// Rebuilt right-edge spine when the caller asked for one.
        track: Option<Track>,
        /// Committed pages this rewrite replaced; none is reachable from the
        /// new root. Reported only once the new root is committed.
        replaced: Vec<PageCommitment>,
    },
    /// Depth-first authentication of every page committed under the root.
    Audit {
        /// Pending nodes with their inherited key intervals and heights.
        stack: Vec<Visit>,
        /// Served node awaiting its page bytes.
        want: Option<Visit>,
        seen: u64,
    },
}

/// A tree node awaiting authentication, with everything its parent implies.
#[derive(Debug, Clone, Copy)]
pub(super) struct Visit {
    page: PageCommitment,
    lower: Option<Hash>,
    upper: Option<Hash>,
    /// Exact height required of the page; unset for the root.
    height: Option<u8>,
}

#[derive(Debug)]
pub(super) enum DescendState {
    Need(PageCommitment),
    Leaf {
        commitment: PageCommitment,
        records: Vec<(Hash, Vec<u8>)>,
    },
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RewriteStage {
    Leaf,
    Up,
    RootEmit,
    Fin,
}

/// Spine rebuild state carried through a rewrite.
#[derive(Debug)]
pub(super) struct Track {
    /// Whether the tracked leaf is the right-side produced page.
    right: bool,
    /// Rebuilt ancestor chain, deepest node first.
    path: Vec<PathNode>,
    /// Tracked leaf's new commitment once emitted.
    leaf: Option<PageCommitment>,
    /// Tracked leaf's committed records.
    records: Vec<(Hash, Vec<u8>)>,
}

/// What an operation needs next, or its terminal result.
#[derive(Debug)]
pub(super) enum Event {
    /// Fetch the page with this exact commitment.
    Page(PageCommitment),
    /// Retain this page, then acknowledge its commitment.
    Emit(EncodedPage),
    /// Descend finished; the authenticated path and leaf are available.
    Descended(Box<Descent>),
    /// Operation complete; `spine` is restored when tracked. `replaced` lists
    /// the committed pages the new root no longer reaches.
    Done {
        spine: Option<Box<Spine>>,
        replaced: Vec<PageCommitment>,
    },
}

/// Shared index state: the committed root, its role, and its bindings.
#[derive(Debug)]
pub(super) struct Index {
    kind: PageKind,
    binding: EvidenceBinding,
    limits: EvidenceLimits,
    root: PageCommitment,
    count: u64,
}

impl Index {
    /// A fresh index whose root is the canonical empty leaf. The returned
    /// page is deterministic; emit and retain it before the first lookup.
    pub(super) fn new(
        kind: PageKind,
        binding: EvidenceBinding,
        limits: EvidenceLimits,
    ) -> Result<(Self, EncodedPage), Failure> {
        let page = encode_leaf(binding, kind, &[], limits)?;
        Ok((
            Self {
                kind,
                binding,
                limits,
                root: page.commitment(),
                count: 0,
            },
            page,
        ))
    }

    /// Restores an index from a checkpointed root and record count.
    pub(super) fn resume(
        kind: PageKind,
        binding: EvidenceBinding,
        limits: EvidenceLimits,
        root: PageCommitment,
        count: u64,
    ) -> Result<Self, Failure> {
        if root.kind != kind
            || root.len < HEADER_BYTES
            || root.len > limits.page_bytes.min(MAX_PAGE_BYTES)
            || root.items > u64::from(PAGE_FANOUT)
            || (root.items == 0 && root.len != HEADER_BYTES)
        {
            return Err(failure(FailureCode::InvalidCheckpoint));
        }
        Ok(Self {
            kind,
            binding,
            limits,
            root,
            count,
        })
    }

    /// The committed root; unchanged while an emission is unacknowledged.
    #[must_use]
    pub(super) fn commitment(&self) -> PageCommitment {
        self.root
    }
    /// Committed record count, excluding buffered appends.
    #[must_use]
    pub(super) fn count(&self) -> u64 {
        self.count
    }

    /// Authenticates supplied page bytes against the exact expected commitment.
    ///
    /// `resident` pages come from the driver's cache, which only holds bytes
    /// the driver encoded itself or already authenticated against this exact
    /// commitment. Those skip the digest, not the structural and budget checks.
    fn view<'a>(
        &self,
        bytes: &'a [u8],
        want: PageCommitment,
        budget: &mut Budget,
        resident: bool,
    ) -> Result<PageView<'a>, Failure> {
        if bytes.len() as u64 != want.len {
            return Err(invalid());
        }
        let view = PageView::decode(bytes, self.binding, self.limits, budget)?;
        if resident {
            view.authenticate_resident(want, budget)?;
        } else {
            view.authenticate(want, budget)?;
        }
        Ok(view)
    }

    /// Encodes one leaf page from bounded records.
    fn leaf_page(&self, records: &[(Hash, Vec<u8>)]) -> Result<EncodedPage, Failure> {
        let mut values = Vec::new();
        values
            .try_reserve_exact(records.len())
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        for (key, value) in records {
            values.push(LeafRecord { key: *key, value });
        }
        encode_leaf(self.binding, self.kind, &values, self.limits)
    }

    fn leaf_records(view: &PageView<'_>) -> Result<Vec<(Hash, Vec<u8>)>, Failure> {
        let mut records = Vec::new();
        records
            .try_reserve_exact(usize::from(view.items()))
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        for record in view.records()? {
            records.push((record.key, record.value.to_vec()));
        }
        Ok(records)
    }

    fn children(view: &PageView<'_>) -> Result<(PageCommitment, Vec<BranchChild>), Failure> {
        let mut budget = Budget::new(u64::from(view.items()) * 128 + 256, 0);
        let payload = view
            .encoded()
            .get(usize::try_from(HEADER_BYTES).map_err(|_| invalid())?..)
            .ok_or_else(invalid)?;
        let mut cursor = Cursor::new(payload, &mut budget);
        let first = read_commitment(&mut cursor)?;
        if first.kind != view.kind() {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        let mut rest = Vec::new();
        rest.try_reserve_exact(usize::from(view.items()) - 1)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        for _ in 1..view.items() {
            let separator = cursor.array()?;
            let child = read_commitment(&mut cursor)?;
            if child.kind != view.kind() {
                return Err(failure(FailureCode::InvalidEvidence));
            }
            rest.push(BranchChild { separator, child });
        }
        cursor.finish()?;
        Ok((first, rest))
    }

    /// Starts a keyed descend at the root.
    pub(super) fn descend(&self, key: Hash) -> Op {
        Op::Descend {
            key,
            rightmost: false,
            lower: None,
            upper: None,
            expected: None,
            path: Vec::new(),
            state: DescendState::Need(self.root),
        }
    }

    /// Starts a descend to the rightmost leaf, restoring an append spine.
    pub(super) fn rightmost(&self) -> Op {
        Op::Descend {
            key: [0; 32],
            rightmost: true,
            lower: None,
            upper: None,
            expected: None,
            path: Vec::new(),
            state: DescendState::Need(self.root),
        }
    }

    /// Starts a full-tree authentication walk for restart recovery.
    pub(super) fn audit(&self) -> Op {
        Op::Audit {
            stack: vec![Visit {
                page: self.root,
                lower: None,
                upper: None,
                height: None,
            }],
            want: None,
            seen: 0,
        }
    }

    /// Begins a rewrite of the leaf reached by `descent` holding `records`,
    /// propagating commitment changes to the root. `insert` appends a fresh
    /// leaf at the right edge instead of replacing `descent.leaf`. `track`
    /// rebuilds the append spine of the written leaf.
    pub(super) fn rewrite(
        descent: Descent,
        records: Vec<(Hash, Vec<u8>)>,
        insert: bool,
        added: u64,
        track: bool,
    ) -> Op {
        Op::Rewrite {
            graft: if insert {
                Graft::Insert
            } else {
                Graft::Replace
            },
            records,
            prior: descent.leaf,
            path: descent.path,
            added,
            queue: VecDeque::new(),
            produced: Vec::new(),
            outstanding: None,
            height: 0,
            pending_root: None,
            stage: RewriteStage::Leaf,
            track: track.then(|| Track {
                right: false,
                path: Vec::new(),
                leaf: None,
                // Replaced by the committed leaf records when the leaf level encodes.
                records: Vec::new(),
            }),
            replaced: Vec::new(),
        }
    }

    /// Drives the operation one bounded transition.
    ///
    /// # Errors
    /// Refuses unacknowledged emissions, inconsistent internal state, encoding
    /// overflow, and exhausted limits.
    pub(super) fn poll(&mut self, op: &mut Op) -> Result<Event, Failure> {
        match op {
            Op::Descend {
                state,
                path,
                key,
                rightmost,
                ..
            } => match state {
                DescendState::Need(want) => Ok(Event::Page(*want)),
                DescendState::Leaf { .. } => {
                    let DescendState::Leaf {
                        commitment,
                        records,
                    } = std::mem::replace(state, DescendState::Done)
                    else {
                        return Err(invalid());
                    };
                    let position = if *rightmost {
                        records.len()
                    } else {
                        records.partition_point(|(k, _)| k < key)
                    };
                    let found =
                        !*rightmost && position < records.len() && records[position].0 == *key;
                    Ok(Event::Descended(Box::new(Descent {
                        leaf: commitment,
                        path: std::mem::take(path),
                        records,
                        position,
                        found,
                    })))
                }
                DescendState::Done => Ok(Event::Done {
                    spine: None,
                    replaced: Vec::new(),
                }),
            },
            Op::Rewrite {
                stage, outstanding, ..
            } => {
                if outstanding.is_some() {
                    return Err(invalid());
                }
                match *stage {
                    RewriteStage::Leaf => self.rewrite_leaf(op),
                    RewriteStage::Up | RewriteStage::RootEmit => self.rewrite_up(op),
                    RewriteStage::Fin => self.rewrite_fin(op),
                }
            }
            Op::Audit { stack, want, seen } => {
                if let Some(visit) = want {
                    return Ok(Event::Page(visit.page));
                }
                if let Some(node) = stack.pop() {
                    *want = Some(node);
                    Ok(Event::Page(node.page))
                } else {
                    if *seen != self.count {
                        return Err(failure(FailureCode::EvidenceMismatch));
                    }
                    Ok(Event::Done {
                        spine: None,
                        replaced: Vec::new(),
                    })
                }
            }
        }
    }

    /// Encodes the leaf level of a rewrite: one page, or two on overflow.
    fn rewrite_leaf(&self, op: &mut Op) -> Result<Event, Failure> {
        let Op::Rewrite {
            records,
            queue,
            produced,
            graft,
            track,
            stage,
            outstanding,
            replaced,
            prior,
            ..
        } = op
        else {
            return Err(invalid());
        };
        // Encode first, mutate second: a refused encode must leave the op
        // exactly as it was so the failure can retry or unwind cleanly.
        if records.len() > FANOUT {
            let mid = records.len() / 2;
            let (left_page, right_page) = (
                self.leaf_page(&records[..mid])?,
                self.leaf_page(&records[mid..])?,
            );
            let right = records.split_off(mid);
            produced.push((
                records.first().ok_or_else(invalid)?.0,
                left_page.commitment(),
            ));
            produced.push((
                right.first().ok_or_else(invalid)?.0,
                right_page.commitment(),
            ));
            if let Some(track) = track.as_mut() {
                track.leaf = Some(right_page.commitment());
                track.records = right;
                track.right = true;
            }
            queue.push_back(left_page);
            queue.push_back(right_page);
            if *graft == Graft::Replace {
                replaced.push(*prior);
            }
            *graft = match *graft {
                Graft::Replace => Graft::ReplaceInsert,
                Graft::Insert => Graft::InsertInsert,
                _ => return Err(invalid()),
            };
        } else {
            let page = self.leaf_page(records)?;
            produced.push((records.first().ok_or_else(invalid)?.0, page.commitment()));
            if let Some(track) = track.as_mut() {
                track.leaf = Some(page.commitment());
                track.records = std::mem::take(records);
            }
            queue.push_back(page);
            if *graft == Graft::Replace {
                replaced.push(*prior);
            }
        }
        *stage = RewriteStage::Up;
        let page = queue.pop_front().ok_or_else(invalid)?;
        *outstanding = Some(page.commitment());
        Ok(Event::Emit(page))
    }

    /// Emits queued pages, then propagates the finished level upward.
    fn rewrite_up(&mut self, op: &mut Op) -> Result<Event, Failure> {
        let Op::Rewrite {
            queue,
            stage,
            outstanding,
            ..
        } = op
        else {
            return Err(invalid());
        };
        if let Some(page) = queue.pop_front() {
            *outstanding = Some(page.commitment());
            return Ok(Event::Emit(page));
        }
        if *stage == RewriteStage::RootEmit {
            *stage = RewriteStage::Fin;
            return self.poll(op);
        }
        self.cascade(op)
    }

    /// Publishes the rewrite: count delta, spine, and committed root.
    fn rewrite_fin(&mut self, op: &mut Op) -> Result<Event, Failure> {
        let Op::Rewrite {
            track,
            added,
            pending_root,
            replaced,
            ..
        } = op
        else {
            return Err(invalid());
        };
        if let Some(root) = pending_root.take() {
            self.root = root;
        }
        self.count = self
            .count
            .checked_add(*added)
            .ok_or_else(|| failure(FailureCode::InvalidEvidence))?;
        *added = 0;
        let root = self.root;
        let spine = track.take().map(|mut track| {
            track.path.reverse();
            Box::new(Spine {
                leaf: track.leaf.unwrap_or(root),
                records: track.records,
                path: track.path,
            })
        });
        Ok(Event::Done {
            spine,
            replaced: std::mem::take(replaced),
        })
    }

    /// Propagates the finished child level into its parent, or finishes.
    #[allow(clippy::too_many_lines)]
    fn cascade(&mut self, op: &mut Op) -> Result<Event, Failure> {
        let Op::Rewrite {
            path,
            produced,
            queue,
            graft,
            height,
            track,
            prior,
            stage,
            outstanding,
            pending_root,
            replaced,
            ..
        } = op
        else {
            return Err(invalid());
        };
        let Some(mut parent) = path.pop() else {
            // The produced level is the top of the tree.
            if produced.len() == 1 && *graft == Graft::Replace {
                *pending_root = Some(produced.first().ok_or_else(invalid)?.1);
                *stage = RewriteStage::Fin;
                return self.poll(op);
            }
            let tracked_right = usize::from(track.as_ref().is_some_and(|t| t.right));
            let (first, rest, choice) = match *graft {
                Graft::Insert | Graft::InsertInsert => (
                    *prior,
                    produced
                        .iter()
                        .map(|(separator, child)| BranchChild {
                            separator: *separator,
                            child: *child,
                        })
                        .collect(),
                    1 + tracked_right,
                ),
                _ => (
                    produced.first().ok_or_else(invalid)?.1,
                    vec![BranchChild {
                        separator: produced.get(1).ok_or_else(invalid)?.0,
                        child: produced.get(1).ok_or_else(invalid)?.1,
                    }],
                    tracked_right,
                ),
            };
            let height = height
                .checked_add(1)
                .filter(|next| *next <= 32)
                .ok_or_else(|| failure(FailureCode::InvalidEvidence))?;
            let page = encode_internal(self.binding, self.kind, height, first, &rest, self.limits)?;
            *pending_root = Some(page.commitment());
            if let Some(track) = track.as_mut() {
                track.path.push(PathNode {
                    commitment: page.commitment(),
                    height,
                    first,
                    rest,
                    choice,
                });
            }
            queue.push_back(page);
            *stage = RewriteStage::RootEmit;
            let page = queue.pop_front().ok_or_else(invalid)?;
            *outstanding = Some(page.commitment());
            return Ok(Event::Emit(page));
        };
        let slot = parent.choice;
        let tracked = slot
            + match *graft {
                Graft::Replace => 0,
                Graft::Insert => 1,
                Graft::ReplaceInsert => usize::from(track.as_ref().is_some_and(|t| t.right)),
                Graft::InsertInsert => 1 + usize::from(track.as_ref().is_some_and(|t| t.right)),
            };
        let first_produced = produced.first().copied().ok_or_else(invalid)?;
        // Encode first, mutate second: the graft applies to copies of the
        // parent's children so a refused encode leaves the op unchanged.
        let mut first = parent.first;
        let mut rest = parent.rest.clone();
        match graft {
            Graft::Replace => {
                if slot == 0 {
                    first = first_produced.1;
                } else {
                    rest[slot - 1].child = first_produced.1;
                }
            }
            Graft::ReplaceInsert => {
                let second = produced.get(1).copied().ok_or_else(invalid)?;
                if slot == 0 {
                    first = first_produced.1;
                } else {
                    rest[slot - 1].child = first_produced.1;
                }
                rest.insert(
                    slot,
                    BranchChild {
                        separator: second.0,
                        child: second.1,
                    },
                );
            }
            Graft::Insert => {
                rest.insert(
                    slot,
                    BranchChild {
                        separator: first_produced.0,
                        child: first_produced.1,
                    },
                );
            }
            Graft::InsertInsert => {
                let second = produced.get(1).copied().ok_or_else(invalid)?;
                rest.insert(
                    slot,
                    BranchChild {
                        separator: first_produced.0,
                        child: first_produced.1,
                    },
                );
                rest.insert(
                    slot + 1,
                    BranchChild {
                        separator: second.0,
                        child: second.1,
                    },
                );
            }
        }
        // The parent is re-encoded in every graft, so its committed page is
        // replaced once the encode below succeeds.
        let old = parent.commitment;
        if rest.len() < FANOUT {
            let node_height = parent.height;
            let page = match encode_internal(
                self.binding,
                self.kind,
                node_height,
                first,
                &rest,
                self.limits,
            ) {
                Ok(page) => page,
                Err(error) => {
                    path.push(parent);
                    return Err(error);
                }
            };
            replaced.push(old);
            parent.first = first;
            parent.rest = rest;
            parent.commitment = page.commitment();
            produced.clear();
            produced.push(([0; 32], page.commitment()));
            queue.push_back(page);
            *graft = Graft::Replace;
            if let Some(track) = track.as_mut() {
                parent.choice = tracked;
                track.path.push(parent);
            }
            *height = node_height;
        } else {
            let mid = rest.len().div_ceil(2);
            let separator = rest[mid - 1].separator;
            let node_height = parent.height;
            let mut left = PathNode {
                commitment: parent.commitment,
                height: node_height,
                first,
                rest: rest[..mid - 1].to_vec(),
                choice: 0,
            };
            let mut right = PathNode {
                commitment: parent.commitment,
                height: node_height,
                first: rest[mid - 1].child,
                rest: rest[mid..].to_vec(),
                choice: 0,
            };
            let encoded = (|| {
                let left_page = encode_internal(
                    self.binding,
                    self.kind,
                    node_height,
                    left.first,
                    &left.rest,
                    self.limits,
                )?;
                let right_page = encode_internal(
                    self.binding,
                    self.kind,
                    node_height,
                    right.first,
                    &right.rest,
                    self.limits,
                )?;
                Ok::<_, Failure>((left_page, right_page))
            })();
            let (left_page, right_page) = match encoded {
                Ok(pages) => pages,
                Err(error) => {
                    path.push(parent);
                    return Err(error);
                }
            };
            replaced.push(old);
            left.commitment = left_page.commitment();
            right.commitment = right_page.commitment();
            produced.clear();
            produced.push(([0; 32], left.commitment));
            produced.push((separator, right.commitment));
            queue.push_back(left_page);
            queue.push_back(right_page);
            *graft = Graft::ReplaceInsert;
            if let Some(track) = track.as_mut() {
                let in_right = tracked >= mid;
                track.right = in_right;
                if in_right {
                    right.choice = tracked - mid;
                    track.path.push(right);
                } else {
                    left.choice = tracked;
                    track.path.push(left);
                }
            }
            *height = node_height;
        }
        let page = queue.pop_front().ok_or_else(invalid)?;
        *outstanding = Some(page.commitment());
        Ok(Event::Emit(page))
    }

    /// Acknowledges the emitted page; the exact commitment must match.
    ///
    /// # Errors
    /// `InvalidResponse` on missing, stale, or mismatched acknowledgement.
    pub(super) fn acknowledge(op: &mut Op, commitment: PageCommitment) -> Result<(), Failure> {
        let Op::Rewrite { outstanding, .. } = op else {
            return Err(invalid());
        };
        if *outstanding != Some(commitment) {
            return Err(invalid());
        }
        *outstanding = None;
        Ok(())
    }

    /// Supplies the bytes of the currently requested page.
    ///
    /// # Errors
    /// Wrong lengths, commitments, bindings, or roles are host-protocol or
    /// evidence failures; a lost page is `UnavailableInput`, never absence.
    pub(super) fn feed(
        &mut self,
        op: &mut Op,
        bytes: &[u8],
        budget: &mut Budget,
    ) -> Result<(), Failure> {
        self.feed_page(op, bytes, budget, false)
    }

    /// Supplies a page the driver's cache held. Its digest was established
    /// when it entered the cache, so it is not hashed again; every other
    /// check and charge is identical to [`Self::feed`].
    pub(super) fn feed_resident(
        &mut self,
        op: &mut Op,
        bytes: &[u8],
        budget: &mut Budget,
    ) -> Result<(), Failure> {
        self.feed_page(op, bytes, budget, true)
    }

    fn feed_page(
        &mut self,
        op: &mut Op,
        bytes: &[u8],
        budget: &mut Budget,
        resident: bool,
    ) -> Result<(), Failure> {
        match op {
            Op::Descend {
                state,
                path,
                key,
                rightmost,
                lower,
                upper,
                expected,
            } => {
                let DescendState::Need(want) = *state else {
                    return Err(invalid());
                };
                let view = self.view(bytes, want, budget, resident)?;
                // A committed child sits exactly one level below its parent
                // and inside the interval its parent routes to it.
                if expected.is_some_and(|height| view.height() != height) {
                    return Err(failure(FailureCode::InvalidEvidence));
                }
                if view.height() == 0 {
                    let records = Self::leaf_records(&view)?;
                    if records.iter().any(|(record, _)| {
                        lower.is_some_and(|low| *record < low)
                            || upper.is_some_and(|high| *record >= high)
                    }) {
                        return Err(failure(FailureCode::InvalidEvidence));
                    }
                    *state = DescendState::Leaf {
                        commitment: want,
                        records,
                    };
                    return Ok(());
                }
                if path.len() >= MAX_DEPTH {
                    return Err(failure(FailureCode::InvalidEvidence));
                }
                let (first, rest) = Self::children(&view)?;
                let route = Route::choose(&rest, *key, *rightmost, *lower, *upper)?;
                let next = if route.choice == 0 {
                    first
                } else {
                    rest[route.choice - 1].child
                };
                path.push(PathNode {
                    commitment: want,
                    height: view.height(),
                    first,
                    rest,
                    choice: route.choice,
                });
                *lower = route.lower;
                *upper = route.upper;
                *expected = view.height().checked_sub(1);
                *state = DescendState::Need(next);
                Ok(())
            }
            Op::Audit { stack, want, seen } => {
                let visit = want.take().ok_or_else(invalid)?;
                // Any refused page leaves `want` installed so a retry
                // re-requests the same node instead of skipping its subtree.
                let result = self.audit_page(visit, bytes, budget, stack, seen, resident);
                if result.is_err() {
                    *want = Some(visit);
                }
                result
            }
            Op::Rewrite { .. } => Err(invalid()),
        }
    }

    /// Authenticates one page of a full-tree walk and queues its children.
    fn audit_page(
        &self,
        visit: Visit,
        bytes: &[u8],
        budget: &mut Budget,
        stack: &mut Vec<Visit>,
        seen: &mut u64,
        resident: bool,
    ) -> Result<(), Failure> {
        let Visit {
            page,
            lower,
            upper,
            height,
        } = visit;
        let view = self.view(bytes, page, budget, resident)?;
        if height.is_some_and(|expected| view.height() != expected) {
            return Err(failure(FailureCode::InvalidEvidence));
        }
        if view.height() == 0 {
            for record in view.records()? {
                if lower.is_some_and(|low| record.key < low)
                    || upper.is_some_and(|high| record.key >= high)
                {
                    return Err(failure(FailureCode::InvalidEvidence));
                }
            }
            *seen = seen
                .checked_add(u64::from(view.items()))
                .ok_or_else(|| failure(FailureCode::InvalidEvidence))?;
            return Ok(());
        }
        let (first, rest) = Self::children(&view)?;
        for child in &rest {
            if lower.is_some_and(|low| child.separator < low)
                || upper.is_some_and(|high| child.separator >= high)
            {
                return Err(failure(FailureCode::InvalidEvidence));
            }
        }
        let below = view.height().checked_sub(1);
        stack
            .try_reserve(rest.len() + 1)
            .map_err(|_| failure(FailureCode::ResourceLimit))?;
        stack.push(Visit {
            page: first,
            lower,
            upper: rest.first().map(|c| c.separator),
            height: below,
        });
        for (index, child) in rest.iter().enumerate() {
            let next = rest.get(index + 1).map(|c| c.separator).or(upper);
            stack.push(Visit {
                page: child.child,
                lower: Some(child.separator),
                upper: next,
                height: below,
            });
        }
        Ok(())
    }
}

/// Where an internal page routes a key, and the interval below that route.
struct Route {
    choice: usize,
    lower: Option<Hash>,
    upper: Option<Hash>,
}

impl Route {
    /// Checks every separator against the inherited interval, then picks the
    /// last child whose separator is at or below `key` (the first otherwise).
    fn choose(
        rest: &[BranchChild],
        key: Hash,
        rightmost: bool,
        lower: Option<Hash>,
        upper: Option<Hash>,
    ) -> Result<Self, Failure> {
        let mut choice = rest.len();
        for (index, child) in rest.iter().enumerate() {
            if lower.is_some_and(|low| child.separator < low)
                || upper.is_some_and(|high| child.separator >= high)
            {
                return Err(failure(FailureCode::InvalidEvidence));
            }
            if choice == rest.len() && !rightmost && key < child.separator {
                choice = index;
            }
        }
        Ok(Self {
            choice,
            lower: if choice == 0 {
                lower
            } else {
                Some(rest[choice - 1].separator)
            },
            upper: if choice < rest.len() {
                Some(rest[choice].separator)
            } else {
                upper
            },
        })
    }
}

/// Ordered stream keyed by big-endian ordinal under one index.
#[derive(Debug)]
pub(super) struct Sequence {
    index: Index,
    open: Vec<(Hash, Vec<u8>)>,
    spine: Option<Spine>,
    drained_bytes: u64,
}

/// Ordinal evidence key: 24 zero bytes then the ordinal big-endian.
#[must_use]
pub(super) fn ordinal_key(ordinal: u64) -> Hash {
    let mut key = [0; 32];
    key[24..].copy_from_slice(&ordinal.to_be_bytes());
    key
}

impl Sequence {
    /// A fresh empty sequence; emits its canonical empty leaf root once.
    pub(super) fn new(
        kind: PageKind,
        binding: EvidenceBinding,
        limits: EvidenceLimits,
    ) -> Result<(Self, EncodedPage), Failure> {
        let (index, page) = Index::new(kind, binding, limits)?;
        Ok((
            Self {
                index,
                open: Vec::new(),
                spine: None,
                drained_bytes: 0,
            },
            page,
        ))
    }

    /// Restores a sequence from a checkpointed root and record count.
    pub(super) fn resume(
        kind: PageKind,
        binding: EvidenceBinding,
        limits: EvidenceLimits,
        root: PageCommitment,
        count: u64,
    ) -> Result<Self, Failure> {
        Ok(Self {
            index: Index::resume(kind, binding, limits, root, count)?,
            open: Vec::new(),
            spine: None,
            drained_bytes: 0,
        })
    }

    /// Mutable access for driving operations.
    #[must_use]
    pub(super) fn index(&mut self) -> &mut Index {
        &mut self.index
    }
    /// Committed root of the sequence.
    #[must_use]
    pub(super) fn commitment(&self) -> PageCommitment {
        self.index.commitment()
    }
    /// Committed record count, excluding buffered appends.
    #[must_use]
    pub(super) fn committed(&self) -> u64 {
        self.index.count()
    }
    /// Buffered record count awaiting a flush.
    #[must_use]
    pub(super) fn pending(&self) -> usize {
        self.open.len()
    }

    /// Buffers one record at the next ordinal.
    pub(super) fn append(&mut self, value: Vec<u8>) {
        let base = self.committed() + self.open.len() as u64;
        self.open.push((ordinal_key(base), value));
    }

    /// Whether buffered records would fill the open leaf. Until then they stay
    /// buffered; a flush is also mandatory at a checkpoint and before sealing.
    #[must_use]
    pub(super) fn needs_flush(&self) -> bool {
        let committed = self
            .spine
            .as_ref()
            .map_or(0, |spine| spine.records.len() % FANOUT);
        !self.open.is_empty() && self.open.len() + committed >= FANOUT
    }

    /// Starts a flush: a rightmost descend when the spine is unknown, else a
    /// leaf rewrite or right-edge insert.
    ///
    /// # Errors
    /// `InvalidResponse` when there is nothing buffered to commit.
    pub(super) fn flush(&mut self) -> Result<Op, Failure> {
        if self.open.is_empty() {
            return Err(invalid());
        }
        match self.spine.take() {
            None => Ok(self.index.rightmost()),
            Some(spine) => Ok(self.rewrite_op(spine)),
        }
    }

    /// Continues a flush after a rightmost descend restored the append spine.
    pub(super) fn graft(&mut self, descent: Descent) -> Op {
        self.rewrite_op(Spine {
            leaf: descent.leaf,
            records: descent.records,
            path: descent.path,
        })
    }

    /// Publishes the spine reported by a finished tracked rewrite.
    pub(super) fn set_spine(&mut self, spine: Option<Box<Spine>>) {
        self.spine = spine.map(|spine| *spine);
    }

    /// Record bytes the last flush op consumed; released by the caller once
    /// the op completes and the pages stand committed.
    pub(super) const fn drained(&self) -> u64 {
        self.drained_bytes
    }

    fn rewrite_op(&mut self, spine: Spine) -> Op {
        let fresh = spine.records.len() >= FANOUT;
        let kept = if fresh { 0 } else { spine.records.len() };
        // One rewrite completes the open leaf or starts exactly one new leaf,
        // and the caller's flush loop re-enters until `open` drains. Growing
        // the tree one leaf at a time makes every internal split land where
        // appending the records singly would put it, so a sequence root
        // depends only on its record stream, never on how flushes batched it.
        let capacity = if fresh { FANOUT } else { FANOUT - kept };
        let moved = self.open.len().min(capacity);
        // `open` bytes are charged at append and the spine at each commit;
        // the op consumes both, so the drained total covers the spine plus
        // the records moving out of `open` regardless of the merge shape.
        let mut drained = spine
            .records
            .iter()
            .map(|(_, value)| u64::try_from(value.len()).unwrap_or(u64::MAX))
            .fold(0, u64::saturating_add);
        let mut records = if fresh {
            Vec::new()
        } else {
            spine.records.clone()
        };
        records.extend(self.open.drain(..moved));
        for (_, value) in &records[kept..] {
            drained = drained.saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
        }
        self.drained_bytes = drained;
        Index::rewrite(
            Descent {
                leaf: spine.leaf,
                path: spine.path,
                records: spine.records,
                position: 0,
                found: false,
            },
            records,
            fresh,
            moved as u64,
            true,
        )
    }
}
