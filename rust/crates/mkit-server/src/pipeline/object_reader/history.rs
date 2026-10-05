//! Selected-ref discovery using canonical local edges, without snapshot fallback.
use super::{
    AtomicBool, BTreeSet, Budget, Budgeted, Caps, Code, Env, Hash, HookSet, MultipartBlobStore,
    NamespaceStore, OBJECT_READER_CALLS, ObjectReader, ObjectType, ReaderSession, ReaderView,
    ServerError, SliceBudget, TakedownVerdict, ViewStore, denied, exhausted, failure, inventory,
    ms, object_denials, resolution_failure, resolve, settle,
};
use mkit_core::object::{EntryMode, Object, TreeEntry};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

const MAX_NODES: usize = 50_000;
const MAX_TAGS: usize = 16;
const MAX_PATH_DEPTH: usize = 1_024;

/// Explicit parent traversal at merges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryMode {
    /// Follow only the first local parent.
    FirstParent,
    /// Breadth-first traversal in canonical parent order, deduplicated by ID.
    AllParents,
}
/// Bounds include skipped ancestors and queued merge branches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HistoryOptions {
    /// Merge traversal; never silently narrowed on a cap.
    pub mode: HistoryMode,
    /// Maximum distinct commits visited, including the requested target.
    pub max_nodes: usize,
    /// Maximum queued distinct commits, including the selected tip.
    pub max_frontier: usize,
    /// Tags peeled at the selected tip, independently bounded from commits.
    pub max_tags: usize,
}
impl Default for HistoryOptions {
    fn default() -> Self {
        Self {
            mode: HistoryMode::AllParents,
            max_nodes: 128,
            max_frontier: 128,
            max_tags: MAX_TAGS,
        }
    }
}
/// A verified canonical commit or remix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryCommit {
    /// Canonical ID.
    pub id: Hash,
    /// Complete serialization, suitable for local signature verification.
    pub canonical: Vec<u8>,
}
/// A bounded page, without cross-request continuation authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryPage {
    /// Starts at the inclusive requested start, or the selected tip.
    pub commits: Vec<HistoryCommit>,
    /// All accessible branches were consumed; stops may hide older history.
    pub complete: bool,
}
/// Bounds for commit discovery and exact path traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathOptions {
    /// How the commit is located from the selected ref.
    pub history: HistoryOptions,
    /// Maximum path components; the empty path names the root tree.
    pub max_depth: usize,
    /// Return canonical commit/path-tree bytes for local inclusion proofs.
    /// They are acquisition data, never reusable authorization evidence.
    pub include_witness: bool,
}
impl Default for PathOptions {
    fn default() -> Self {
        Self {
            history: HistoryOptions::default(),
            max_depth: 128,
            include_witness: false,
        }
    }
}
/// A decoded path ancestor, ordered from the root toward the leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTree {
    /// Verified tree ID.
    pub id: Hash,
    /// Complete canonical tree bytes for local proof construction.
    pub canonical: Vec<u8>,
}
/// Canonical acquisition data; not a permission or continuation handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathWitness {
    /// Canonical selected commit or remix, including its tree binding.
    pub commit: HistoryCommit,
    /// Path trees excluding a tree leaf, whose bytes are in `CommitPathRead`.
    pub trees: Vec<PathTree>,
}
/// Canonical object at an exact decoded path in a proved commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPathRead {
    /// Located commit or remix.
    pub commit: Hash,
    /// Verified leaf ID.
    pub id: Hash,
    /// Exact entry mode; the root has `Tree` mode. Symlinks return their blob
    /// bytes, never their referent. Chunked files retain their manifest.
    pub mode: EntryMode,
    /// Optional canonical commit and ancestor trees. These bytes are charged
    /// as output and remain subject to fresh source checks at the boundary.
    pub witness: Option<PathWitness>,
    /// Complete canonical bytes, not concatenated logical chunk bodies.
    pub canonical: Vec<u8>,
}
// Both the operation and request ledger settle decoded work on failure/cancel.
struct OperationDecode<'a> {
    charge: crate::pipeline::read_limits::DecodeCharge<'a>,
    operation: &'a mut Budget,
    initial: u64,
}
impl Drop for OperationDecode<'_> {
    fn drop(&mut self) {
        self.operation.0 = self
            .operation
            .0
            .saturating_sub(self.initial.saturating_sub(self.charge.budget.0));
    }
}

struct Node {
    id: Hash,
    bytes: Arc<[u8]>,
    object: Object,
    location: crate::store::index::LocatedObject,
}
impl Node {
    fn parents(&self) -> Option<&[Hash]> {
        match &self.object {
            Object::Commit(c) => Some(&c.parents),
            Object::Remix(r) => Some(&r.parents),
            _ => None,
        }
    }
    fn tree(&self) -> Option<Hash> {
        match &self.object {
            Object::Commit(c) => Some(c.tree_hash),
            Object::Remix(r) => Some(r.tree_hash),
            _ => None,
        }
    }
}
#[derive(Clone, Copy)]
enum Role {
    Tip,
    Commit,
    Exact(ObjectType),
    Entry(EntryMode),
}
impl Role {
    fn accepts(self, kind: ObjectType) -> bool {
        match self {
            Self::Tip => matches!(
                kind,
                ObjectType::Commit | ObjectType::Remix | ObjectType::Tag
            ),
            Self::Commit => matches!(kind, ObjectType::Commit | ObjectType::Remix),
            Self::Exact(expected) => expected == kind,
            Self::Entry(EntryMode::Tree) => kind == ObjectType::Tree,
            Self::Entry(EntryMode::Symlink) => kind == ObjectType::Blob,
            Self::Entry(EntryMode::Blob | EntryMode::Executable) => {
                matches!(kind, ObjectType::Blob | ObjectType::ChunkedBlob)
            }
        }
    }
}
impl<B: MultipartBlobStore, N: NamespaceStore + Clone + 'static, H: HookSet>
    ObjectReader<'_, B, N, H>
{
    /// List history through parents only, from one strong selected-ref read in
    /// this reader's view. `start` is inclusive; skipped commits count against
    /// `max_nodes`. All-parent order is BFS in canonical parent order. Every
    /// call captures the selected ref anew and replaces structural session
    /// evidence, retaining spent allowances and the original deadline.
    /// Public missing/orphan/capped starts are uniformly absent. Tags are
    /// peeled only at the tip; snapshots, foreign sources and reconstruction
    /// bases are never traversed as history edges.
    /// # Errors
    /// Invalid ref/options, live authority refusal, owner exhaustion or store
    /// faults. The complete operation shares the existing per-call decode
    /// allowance, including skipped ancestors/bases. Canonical output
    /// exhaustion is typed for either view.
    pub async fn walk_history_in(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        start: Option<Hash>,
        limit: usize,
        options: HistoryOptions,
    ) -> Result<Option<HistoryPage>, ServerError> {
        validate_history(reference, options)?;
        if limit == 0 || limit > options.max_nodes {
            return Err(ServerError::invalid_argument("invalid history page size"));
        }
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        let admission = crate::store::read_io::ReadIo::new();
        let mut decode = Budget(self.cfg.http_decode_budget);
        let result = self
            .history_nodes(
                session,
                reference,
                start,
                limit,
                options,
                &calls,
                &admission,
                &mut decode,
            )
            .await;
        let Some((nodes, complete)) = self.discovery_result(result)? else {
            return Ok(None);
        };
        let total = nodes
            .iter()
            .try_fold(0u64, |n, node| n.checked_add(node.bytes.len() as u64))
            .ok_or_else(exhausted)?;
        reserve_output(session, total)?;
        let commits = nodes
            .into_iter()
            .map(|node| HistoryCommit {
                id: node.id,
                canonical: node.bytes.to_vec(),
            })
            .collect();
        Ok(Some(HistoryPage { commits, complete }))
    }
    /// Locate one commit using bounded parent-only selected-ref discovery.
    /// # Errors
    /// As [`Self::walk_history_in`]. Public missing/orphan/capped targets are absent.
    pub async fn locate_commit_in(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        target: Hash,
        options: HistoryOptions,
    ) -> Result<Option<HistoryCommit>, ServerError> {
        Ok(self
            .walk_history_in(session, reference, Some(target), 1, options)
            .await?
            .and_then(|page| page.commits.into_iter().next()))
    }
    /// Locate the commit through parents, then follow only exact decoded path
    /// components, without normalization or symlink following. An expected-ID
    /// mismatch is absent before loading the different leaf. Non-tree
    /// intermediates and mode/kind mismatches are absent. Only the leaf counts
    /// as output by default; optional witness bytes are also charged. Ancestors
    /// always consume decode/I/O allowances. No URL is issued.
    /// # Errors
    /// As [`Self::walk_history_in`], plus invalid path/depth options.
    #[allow(clippy::too_many_arguments)] // Explicit target binding and independent bounds.
    pub async fn read_commit_path_in(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        commit: Hash,
        path: &[Vec<u8>],
        expected: Option<Hash>,
        options: PathOptions,
    ) -> Result<Option<CommitPathRead>, ServerError> {
        validate_history(reference, options.history)?;
        if options.max_depth > MAX_PATH_DEPTH
            || path.iter().any(|name| !TreeEntry::validate_name(name))
        {
            return Err(ServerError::invalid_argument("invalid commit path"));
        }
        let calls = SliceBudget::new(OBJECT_READER_CALLS);
        let admission = crate::store::read_io::ReadIo::new();
        let mut decode = Budget(self.cfg.http_decode_budget);
        let result = self
            .path_node(
                session,
                reference,
                commit,
                path,
                expected,
                options,
                &calls,
                &admission,
                &mut decode,
            )
            .await;
        let Some((node, mode, ancestors)) = self.discovery_result(result)? else {
            return Ok(None);
        };
        let total = ancestors
            .iter()
            .try_fold(node.bytes.len() as u64, |n, ancestor| {
                n.checked_add(ancestor.bytes.len() as u64)
            })
            .ok_or_else(exhausted)?;
        reserve_output(session, total)?;
        let witness = if options.include_witness {
            let mut ancestors = ancestors.into_iter();
            let commit_node = ancestors.next().ok_or_else(|| failure(()))?;
            Some(PathWitness {
                commit: HistoryCommit {
                    id: commit_node.id,
                    canonical: commit_node.bytes.to_vec(),
                },
                trees: ancestors
                    .map(|tree| PathTree {
                        id: tree.id,
                        canonical: tree.bytes.to_vec(),
                    })
                    .collect(),
            })
        } else {
            None
        };
        Ok(Some(CommitPathRead {
            commit,
            id: node.id,
            mode,
            witness,
            canonical: node.bytes.to_vec(),
        }))
    }
    fn discovery_result<T>(
        &self,
        result: Result<Option<T>, ServerError>,
    ) -> Result<Option<T>, ServerError> {
        match result {
            Err(error) if error.code() == Code::NotFound => Ok(None),
            Err(error)
                if matches!(self.view, ReaderView::Public)
                    && error.code() == Code::ResourceExhausted =>
            {
                Ok(None)
            }
            other => other,
        }
    }
    async fn capture_ref(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
    ) -> Result<Option<Hash>, ServerError> {
        let started = ms(self.pipe.clock.now_ms());
        session.io.calls.charge_many(2).map_err(|_| exhausted())?;
        let authority = self.authorize(calls).await?;
        let writer = authority.is_some();
        session
            .proofs
            .bind(&self.identity, authority, started, self.cfg)?;
        if !session.proofs.current(ms(self.pipe.clock.now_ms())) {
            return Err(exhausted());
        }
        let capped = AtomicBool::new(false);
        let meta = Budgeted::new(&self.pipe.meta, calls)
            .with_session(&session.io.calls)
            .flagging(&capped)
            .with_io(admission);
        let view = ViewStore {
            store: &meta,
            repo: &self.repo,
            writer,
            policy: self.pipe.publication_policy.as_deref(),
        };
        let shard = self.pipe.shards.ref_shard(&self.repo, reference);
        let result = crate::store::read::read_ref(&view, &shard, &self.repo.name, reference)
            .await
            .map_err(failure);
        let tip = settle(result, &capped)?;
        session.proofs.capture_selected(tip);
        Ok(tip)
    }
    /// Only proved IDs are loaded; no membership probe of an unproved target
    /// and no snapshot fallback. Final live checks precede decoded edge use.
    #[allow(clippy::too_many_lines)] // One precedence-ordered same-view operation.
    async fn proved_node(
        &self,
        session: &mut ReaderSession,
        id: Hash,
        role: Role,
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
        operation: &mut Budget,
    ) -> Result<Option<Node>, ServerError> {
        session.io.calls.charge_many(2).map_err(|_| exhausted())?;
        let authority = self.authorize(calls).await?;
        let writer = authority.is_some();
        session.proofs.bind(
            &self.identity,
            authority,
            ms(self.pipe.clock.now_ms()),
            self.cfg,
        )?;
        let capped = AtomicBool::new(false);
        let result = async {
            let (io, charge, _, proofs) = session.split_with_proofs(operation.0);
            let initial = charge.budget.0;
            let mut decode = OperationDecode {
                charge,
                operation,
                initial,
            };
            let meta = Budgeted::new(&self.pipe.meta, calls)
                .with_session(&io.calls)
                .flagging(&capped)
                .with_io(admission);
            let blobs = Budgeted::new(&self.pipe.blobs, calls)
                .with_session(&io.calls)
                .with_encoded(&io.encoded)
                .flagging(&capped)
                .with_io(admission);
            let targets = BTreeSet::from([id]);
            proofs
                .revalidate(&meta, &self.repo, self.seams.takedown.as_ref(), &targets)
                .await?;
            if !proofs.current(ms(self.pipe.clock.now_ms())) {
                return Err(exhausted());
            }
            if !proofs.contains(&id) {
                return Ok(None);
            }
            let checks = super::super::reader_checks::Checks::new(&meta);
            let view = ViewStore {
                store: &checks,
                repo: &self.repo,
                writer,
                policy: self.pipe.publication_policy.as_deref(),
            };
            let env = Env {
                no_reads: &BTreeSet::new(),
                blobs: &blobs,
                meta: &view,
                shards: self.pipe.shards.as_ref(),
                repo: &self.repo,
                indexed: self.indexed,
                cfg: self.cfg,
                metrics: self.pipe.metrics.as_ref(),
                caps: Caps::Reader,
            };
            let (located, _) = resolve::locate_ids(&env, &[id], resolve::OnCap::Fail)
                .await
                .map_err(resolution_failure)?;
            let Some((_, location)) = located.into_iter().next() else {
                return Ok(None);
            };
            let locations = [(id, location)];
            checks
                .prefetch_locations(&locations)
                .await
                .map_err(failure)?;
            if denied(&checks, &id).await? || denied(&checks, &location.pack).await? {
                return Ok(None);
            }
            let bytes = match resolve::load(&env, id, location, &mut decode.charge.budget).await {
                Ok(bytes) => bytes,
                Err(resolve::Miss::NotFound) => return Ok(None),
                Err(miss) => return Err(resolution_failure(miss)),
            };
            if !resolve::type_of(&bytes).is_some_and(|kind| role.accepts(kind)) {
                return Ok(None);
            }
            meta.charge().map_err(|_| exhausted())?;
            if !matches!(
                self.seams.takedown.check(&self.repo, &id).await?,
                TakedownVerdict::Clear
            ) {
                return Ok(None);
            }
            // Descriptor proofs retain live dependency reads after their
            // strong directory walk, rather than borrowing phase guard replies.
            let live_view = ViewStore {
                store: &meta,
                repo: &self.repo,
                writer,
                policy: self.pipe.publication_policy.as_deref(),
            };
            let facts = if self.pipe.cfg.takedown_denial {
                inventory::located_entries(&live_view, &locations)
                    .await
                    .map_err(failure)?
            } else {
                BTreeMap::new()
            };
            if self.pipe.cfg.takedown_denial
                && !object_denials(
                    &live_view,
                    self.pipe.shards.as_ref(),
                    &self.repo,
                    &locations,
                    &facts,
                    self.indexed,
                )
                .await?
                .is_empty()
            {
                return Ok(None);
            }
            io.calls.charge_many(2).map_err(|_| exhausted())?;
            let current = self.authorize(calls).await?;
            proofs.bind(
                &self.identity,
                current,
                ms(self.pipe.clock.now_ms()),
                self.cfg,
            )?;
            proofs
                .revalidate(&meta, &self.repo, self.seams.takedown.as_ref(), &targets)
                .await?;
            if !proofs.contains(&id) {
                return Ok(None);
            }
            // Loading, authorization, seam callbacks and descriptor I/O may revoke a source.
            // The final target/pack guards are one fresh bounded phase.
            checks.reset();
            checks
                .prefetch_locations(&locations)
                .await
                .map_err(failure)?;
            if !view
                .has(
                    &self
                        .pipe
                        .shards
                        .membership(&self.repo, &crate::store::BlobKey::pack(location.pack)),
                    &crate::store::keys::membership(&self.repo.name, &location.pack),
                )
                .await
                .map_err(failure)?
            {
                return Ok(None);
            }
            if !crate::indexed::resolve::member_dependencies_clear(
                &view,
                self.pipe.shards.as_ref(),
                &self.repo,
                id,
                location,
                self.indexed.max_delta_chain_depth,
                self.pipe.metrics.as_ref(),
                Caps::Reader,
            )
            .await?
            {
                return Ok(None);
            }
            if !proofs.current(ms(self.pipe.clock.now_ms())) {
                return Err(exhausted());
            }
            let object = mkit_core::serialize::deserialize(&bytes).map_err(failure)?;
            // Preserve the existing canonical manifest/chunk contract for a
            // subsequent deep-file read, without promoting unrelated siblings.
            if matches!(object, Object::ChunkedBlob(_))
                && proofs.can_decode(&id, &bytes)
                && !self.seams.takedown.stops_descent(&self.repo, &id)
            {
                proofs.expand(id, location.pack, &object);
            }
            Ok(Some(Node {
                id,
                bytes,
                object,
                location,
            }))
        }
        .await;
        settle(result, &capped)
    }
    fn link_node(
        &self,
        session: &mut ReaderSession,
        node: &Node,
        child: Hash,
    ) -> Result<bool, ServerError> {
        if self.seams.takedown.stops_descent(&self.repo, &node.id) {
            return Ok(false);
        }
        if !session.proofs.link(node.id, &node.object, child) {
            return Err(exhausted());
        }
        Ok(true)
    }
    #[allow(clippy::too_many_arguments)] // Page selector plus explicit bounded operation context.
    async fn history_nodes(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        start: Option<Hash>,
        limit: usize,
        options: HistoryOptions,
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
        decode: &mut Budget,
    ) -> Result<Option<(Vec<Node>, bool)>, ServerError> {
        let Some(mut tip) = self
            .capture_ref(session, reference, calls, admission)
            .await?
        else {
            return Ok(None);
        };
        let mut tags = BTreeSet::new();
        let mut role = Role::Tip;
        let first = loop {
            let Some(node) = self
                .proved_node(session, tip, role, calls, admission, decode)
                .await?
            else {
                return Ok(None);
            };
            if let Object::Tag(tag) = &node.object {
                if tags.len() >= options.max_tags || !tags.insert(tip) {
                    return Err(exhausted());
                }
                if !matches!(
                    tag.target_type,
                    ObjectType::Tag | ObjectType::Commit | ObjectType::Remix
                ) || !self.link_node(session, &node, tag.target)?
                {
                    return Ok(None);
                }
                tip = tag.target;
                role = Role::Exact(tag.target_type);
            } else {
                break node;
            }
        };
        let mut frontier = VecDeque::from([tip]);
        let mut seen = BTreeSet::from([tip]);
        let mut first = Some(first);
        let mut visited = 0;
        let mut emitting = start.is_none();
        let mut output = Vec::new();
        while let Some(id) = frontier.pop_front() {
            if visited >= options.max_nodes {
                return Err(exhausted());
            }
            visited += 1;
            let node = if let Some(first) = first.take() {
                first
            } else {
                let Some(node) = self
                    .proved_node(session, id, Role::Commit, calls, admission, decode)
                    .await?
                else {
                    continue;
                };
                node
            };
            emitting |= start == Some(id);
            let parents = node.parents().ok_or_else(|| failure(()))?;
            let count = if self.seams.takedown.stops_descent(&self.repo, &id) {
                0
            } else if options.mode == HistoryMode::FirstParent {
                parents.len().min(1)
            } else {
                parents.len()
            };
            // A final result needs no successor evidence. Do not reject a target
            // at exactly the node cap merely because it has older parents.
            if emitting && output.len() + 1 == limit {
                let complete = frontier.is_empty()
                    && parents[..count].iter().all(|parent| seen.contains(parent));
                output.push(node);
                // A singleton here is the node just validated, with no await
                // afterward. Retained pages must refresh their earlier nodes.
                if output.len() > 1 {
                    self.final_nodes(session, &output, calls, admission).await?;
                }
                return Ok(Some((output, complete)));
            }
            let additional = parents[..count]
                .iter()
                .filter(|id| !seen.contains(*id))
                .collect::<BTreeSet<_>>()
                .len();
            if frontier.len().saturating_add(additional) > options.max_frontier {
                return Err(exhausted());
            }
            for parent in &parents[..count] {
                if !seen.contains(parent) && self.link_node(session, &node, *parent)? {
                    seen.insert(*parent);
                    frontier.push_back(*parent);
                }
            }
            if emitting {
                output.push(node);
            }
        }
        if !emitting {
            return Ok(None);
        }
        self.final_nodes(session, &output, calls, admission).await?;
        Ok(Some((output, true)))
    }
    #[allow(clippy::too_many_arguments)] // Exact path target and operation context.
    async fn path_node(
        &self,
        session: &mut ReaderSession,
        reference: &str,
        commit: Hash,
        path: &[Vec<u8>],
        expected: Option<Hash>,
        options: PathOptions,
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
        decode: &mut Budget,
    ) -> Result<Option<(Node, EntryMode, Vec<Node>)>, ServerError> {
        if path.len() > options.max_depth {
            return Err(exhausted());
        }
        let Some((mut commits, _)) = self
            .history_nodes(
                session,
                reference,
                Some(commit),
                1,
                options.history,
                calls,
                admission,
                decode,
            )
            .await?
        else {
            return Ok(None);
        };
        let Some(node) = commits.pop() else {
            return Ok(None);
        };
        let mut id = node.tree().ok_or_else(|| failure(()))?;
        if !self.link_node(session, &node, id)? {
            return Ok(None);
        }
        let mut ancestors = Vec::new();
        if options.include_witness {
            ancestors.push(node);
        }
        let mut mode = EntryMode::Tree;
        for name in path {
            if mode != EntryMode::Tree {
                return Ok(None);
            }
            let Some(node) = self
                .proved_node(session, id, Role::Entry(mode), calls, admission, decode)
                .await?
            else {
                return Ok(None);
            };
            let Object::Tree(tree) = &node.object else {
                return Ok(None);
            };
            let Some(entry) = tree.entries.iter().find(|entry| entry.name == *name) else {
                return Ok(None);
            };
            if !self.link_node(session, &node, entry.object_hash)? {
                return Ok(None);
            }
            id = entry.object_hash;
            mode = entry.mode;
            if options.include_witness {
                ancestors.push(node);
            }
        }
        if expected.is_some_and(|expected| expected != id) {
            return Ok(None);
        }
        let Some(node) = self
            .proved_node(session, id, Role::Entry(mode), calls, admission, decode)
            .await?
        else {
            return Ok(None);
        };
        if options.include_witness {
            ancestors.push(node);
            self.final_nodes(session, &ancestors, calls, admission)
                .await?;
            let leaf = ancestors.pop().ok_or_else(|| failure(()))?;
            Ok(Some((leaf, mode, ancestors)))
        } else {
            Ok(Some((node, mode, ancestors)))
        }
    }
    // Earlier outputs may be revoked while later commits load. Refresh their
    // same-view membership, dependencies, strong denial and live gate together.
    #[allow(clippy::too_many_lines)] // A final page boundary with fresh same-view checks.
    async fn final_nodes(
        &self,
        session: &mut ReaderSession,
        nodes: &[Node],
        calls: &SliceBudget,
        admission: &crate::store::read_io::ReadIo,
    ) -> Result<(), ServerError> {
        if nodes.is_empty() {
            return Ok(());
        }
        session.io.calls.charge_many(2).map_err(|_| exhausted())?;
        let authority = self.authorize(calls).await?;
        let writer = authority.is_some();
        session.proofs.bind(
            &self.identity,
            authority,
            ms(self.pipe.clock.now_ms()),
            self.cfg,
        )?;
        let capped = AtomicBool::new(false);
        let result = async {
            let meta = Budgeted::new(&self.pipe.meta, calls)
                .with_session(&session.io.calls)
                .flagging(&capped)
                .with_io(admission);
            let checks = super::super::reader_checks::Checks::new(&meta);
            let view = ViewStore {
                store: &checks,
                repo: &self.repo,
                writer,
                policy: self.pipe.publication_policy.as_deref(),
            };
            let ids: BTreeSet<_> = nodes.iter().map(|node| node.id).collect();
            session
                .proofs
                .revalidate(&meta, &self.repo, self.seams.takedown.as_ref(), &ids)
                .await?;
            if !session.proofs.current(ms(self.pipe.clock.now_ms())) {
                return Err(exhausted());
            }
            if ids.iter().any(|id| !session.proofs.contains(id)) {
                return Err(ServerError::not_found("object reader unavailable"));
            }
            let locations: Vec<_> = nodes.iter().map(|node| (node.id, node.location)).collect();
            for node in nodes {
                meta.charge().map_err(|_| exhausted())?;
                if !matches!(
                    self.seams.takedown.check(&self.repo, &node.id).await?,
                    TakedownVerdict::Clear
                ) {
                    return Err(ServerError::not_found("object reader unavailable"));
                }
            }
            // Descriptor proofs retain live dependency reads after their
            // strong directory walk, rather than borrowing phase guard replies.
            let live_view = ViewStore {
                store: &meta,
                repo: &self.repo,
                writer,
                policy: self.pipe.publication_policy.as_deref(),
            };
            let facts = if self.pipe.cfg.takedown_denial {
                inventory::located_entries(&live_view, &locations)
                    .await
                    .map_err(failure)?
            } else {
                BTreeMap::new()
            };
            if self.pipe.cfg.takedown_denial
                && !object_denials(
                    &live_view,
                    self.pipe.shards.as_ref(),
                    &self.repo,
                    &locations,
                    &facts,
                    self.indexed,
                )
                .await?
                .is_empty()
            {
                return Err(ServerError::not_found("object reader unavailable"));
            }
            session.io.calls.charge_many(2).map_err(|_| exhausted())?;
            let authority = self.authorize(calls).await?;
            session.proofs.bind(
                &self.identity,
                authority,
                ms(self.pipe.clock.now_ms()),
                self.cfg,
            )?;
            session
                .proofs
                .revalidate(&meta, &self.repo, self.seams.takedown.as_ref(), &ids)
                .await?;
            if ids.iter().any(|id| !session.proofs.contains(id)) {
                return Err(ServerError::not_found("object reader unavailable"));
            }
            checks.reset();
            checks
                .prefetch_locations(&locations)
                .await
                .map_err(failure)?;
            for node in nodes {
                // Retain the actual body source, not a different newly selected
                // pack that could conceal denial of the source just read.
                if !view
                    .has(
                        &self.pipe.shards.membership(
                            &self.repo,
                            &crate::store::BlobKey::pack(node.location.pack),
                        ),
                        &crate::store::keys::membership(&self.repo.name, &node.location.pack),
                    )
                    .await
                    .map_err(failure)?
                    || !crate::indexed::resolve::member_dependencies_clear(
                        &view,
                        self.pipe.shards.as_ref(),
                        &self.repo,
                        node.id,
                        node.location,
                        self.indexed.max_delta_chain_depth,
                        self.pipe.metrics.as_ref(),
                        Caps::Reader,
                    )
                    .await?
                {
                    return Err(ServerError::not_found("object reader unavailable"));
                }
            }
            if !session.proofs.current(ms(self.pipe.clock.now_ms())) {
                return Err(exhausted());
            }
            Ok(())
        }
        .await;
        settle(result, &capped)
    }
}
fn validate_history(reference: &str, options: HistoryOptions) -> Result<(), ServerError> {
    if !crate::refs::is_served_ref_name(reference)
        || reference.starts_with("refs/mkit/packmap/")
        || options.max_nodes == 0
        || options.max_nodes > MAX_NODES
        || options.max_frontier == 0
        || options.max_frontier > MAX_NODES
        || options.max_tags > MAX_TAGS
    {
        return Err(ServerError::invalid_argument(
            "invalid history options or ref",
        ));
    }
    Ok(())
}
fn reserve_output(session: &mut ReaderSession, bytes: u64) -> Result<(), ServerError> {
    let (_, _, output, _) = session.split_with_proofs(0);
    if bytes > output.remaining() {
        return Err(exhausted());
    }
    output.used = output.used.saturating_add(bytes);
    Ok(())
}
