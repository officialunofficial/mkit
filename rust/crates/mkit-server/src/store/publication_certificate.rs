//! Immutable publication evidence. Authority comes from a guarded row anchor,
//! never from the presence of a content-addressed page alone.
use super::{
    Batch, BatchOutcome, NamespaceStore, Precondition, StoreError, Value, content_shard, keys,
};
use crate::RepoId;
use mkit_core::hash::{Hash, hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// An exact map lookup reads at most 32 branches and one leaf.
pub const LOOKUP_CALLS: u32 = 33;
/// One insertion reads 33 pages and creates at most 34 pages. Each creation
/// may need a second call to validate an already-present immutable value.
pub const INSERT_CALLS: u32 = LOOKUP_CALLS + 2 * 34;
/// Largest radix page, including version and all 256 children.
pub const MAX_PAGE_BYTES: usize = 8_485;
/// Largest immutable certificate header.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Most tasks in a frontier page.
pub const FRONTIER_TASKS: usize = 128;
/// Verified reachable object. Intermediate candidate marks require owed work.
pub const REACHABLE: u8 = 1;
/// Current denial proof target, including surplus inventory objects.
pub const DENIAL: u8 = 2;
/// Packmap node, listed pack, or non-branch closure support pack.
pub const SUPPORT: u8 = 4;
/// External delta source pack, independently published before the advance.
pub const EXTERNAL: u8 = 8;
const FLAGS: u8 = REACHABLE | DENIAL | SUPPORT | EXTERNAL;

fn corrupt() -> StoreError {
    StoreError::Corrupt("invalid publication certificate".into())
}

/// A completed immutable proof, only authoritative through its row anchor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Header {
    namespace: String,
    repository: String,
    generation: u64,
    pair: super::publication::Pair,
    depth_limit: u32,
    root: Option<Hash>,
}
impl Header {
    /// Construct the proof binding. The caller must first finish all work.
    #[must_use]
    pub fn new(
        repo: &RepoId,
        generation: u64,
        pair: super::publication::Pair,
        depth_limit: u32,
        root: Option<Hash>,
    ) -> Self {
        Self {
            namespace: repo.namespace.as_str().into(),
            repository: repo.name.as_str().into(),
            generation,
            pair,
            depth_limit,
            root,
        }
    }
    /// Root used by exact membership and denial queries.
    #[must_use]
    pub fn root(&self) -> Option<Hash> {
        self.root
    }
    /// Whether the exact authoritative binding and verification limit match.
    #[must_use]
    pub fn matches(
        &self,
        repo: &RepoId,
        generation: u64,
        pair: &super::publication::Pair,
        depth_limit: u32,
    ) -> bool {
        self.namespace == repo.namespace.as_str()
            && self.repository == repo.name.as_str()
            && self.generation == generation
            && self.pair == *pair
            && self.depth_limit <= depth_limit
    }
    /// Create a write-once header, returning its content address.
    /// # Errors
    /// Invalid size, storage failure, or an inconsistent existing value.
    pub async fn write<S: NamespaceStore>(&self, store: &S, now: u64) -> Result<Hash, StoreError> {
        let mut bytes = vec![1];
        serde_json::to_writer(&mut bytes, self).map_err(|_| corrupt())?;
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(corrupt());
        }
        immutable(store, bytes, true, now).await
    }
    /// Read and authenticate a header and its root page; absence is corruption.
    /// # Errors
    /// Missing, malformed or unauthenticated proof, or a storage failure.
    pub async fn read<S: NamespaceStore>(store: &S, digest: &Hash) -> Result<Self, StoreError> {
        let bytes = authenticated(store, digest, true, MAX_HEADER_BYTES).await?;
        if bytes.first() != Some(&1) {
            return Err(corrupt());
        }
        let header: Self = serde_json::from_slice(&bytes[1..]).map_err(|_| corrupt())?;
        if let Some(root) = header.root {
            load(store, &root).await?;
        }
        Ok(header)
    }
}

#[derive(Clone, Debug)]
enum Node {
    Leaf {
        id: Hash,
        flags: u8,
    },
    Branch {
        depth: u8,
        prefix: Hash,
        children: BTreeMap<u8, Hash>,
    },
}
impl Node {
    fn prefix(&self) -> &[u8] {
        match self {
            Self::Leaf { id, .. } => id,
            Self::Branch { prefix, depth, .. } => &prefix[..usize::from(*depth)],
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![1];
        match self {
            Self::Leaf { id, flags } => {
                bytes.push(0);
                bytes.extend(id);
                bytes.push(*flags);
            }
            Self::Branch {
                depth,
                prefix,
                children,
            } => {
                bytes.extend([1, *depth]);
                bytes.extend(prefix);
                bytes.extend(u16::try_from(children.len()).unwrap_or(0).to_be_bytes());
                for (label, child) in children {
                    bytes.push(*label);
                    bytes.extend(child);
                }
            }
        }
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.first() != Some(&1) {
            return Err(corrupt());
        }
        match bytes.get(1) {
            Some(0) if bytes.len() == 35 => {
                let id = bytes[2..34].try_into().map_err(|_| corrupt())?;
                let flags = bytes[34];
                if flags == 0 || flags & !FLAGS != 0 {
                    return Err(corrupt());
                }
                Ok(Self::Leaf { id, flags })
            }
            Some(1) if bytes.len() >= 37 => {
                let depth = bytes[2];
                let prefix: Hash = bytes[3..35].try_into().map_err(|_| corrupt())?;
                let count = usize::from(u16::from_be_bytes([bytes[35], bytes[36]]));
                if depth > 31
                    || prefix[usize::from(depth)..].iter().any(|b| *b != 0)
                    || !(2..=256).contains(&count)
                    || bytes.len() != 37 + count * 33
                {
                    return Err(corrupt());
                }
                let mut children = BTreeMap::new();
                let mut last = None;
                for child in bytes[37..].chunks_exact(33) {
                    let label = child[0];
                    if last.is_some_and(|last| label <= last) {
                        return Err(corrupt());
                    }
                    children.insert(label, child[1..].try_into().map_err(|_| corrupt())?);
                    last = Some(label);
                }
                Ok(Self::Branch {
                    depth,
                    prefix,
                    children,
                })
            }
            _ => Err(corrupt()),
        }
    }
    fn below(&self, parent: &Self, label: u8) -> Result<(), StoreError> {
        let Self::Branch { depth, prefix, .. } = parent else {
            return Err(corrupt());
        };
        let n = usize::from(*depth);
        if self.prefix().len() <= n
            || self.prefix()[..n] != prefix[..n]
            || self.prefix()[n] != label
        {
            return Err(corrupt());
        }
        Ok(())
    }
}

async fn authenticated<S: NamespaceStore>(
    store: &S,
    digest: &Hash,
    header: bool,
    max: usize,
) -> Result<Vec<u8>, StoreError> {
    let key = if header {
        keys::publication_certificate(digest)
    } else {
        keys::publication_page(digest)
    };
    let raw = store
        .get(&content_shard(digest), &key)
        .await?
        .ok_or_else(corrupt)?;
    if raw.as_bytes().len() > max || hash(raw.as_bytes()) != *digest {
        return Err(corrupt());
    }
    Ok(raw.as_bytes().to_vec())
}
async fn load<S: NamespaceStore>(store: &S, digest: &Hash) -> Result<Node, StoreError> {
    Node::decode(&authenticated(store, digest, false, MAX_PAGE_BYTES).await?)
}
async fn immutable<S: NamespaceStore>(
    store: &S,
    bytes: Vec<u8>,
    header: bool,
    now: u64,
) -> Result<Hash, StoreError> {
    let digest = hash(&bytes);
    let key = if header {
        keys::publication_certificate(&digest)
    } else {
        keys::publication_page(&digest)
    };
    let p = content_shard(&digest);
    let value = Value::new(bytes);
    let batch = Batch::new()
        .require(Precondition::NotAfter(now.saturating_add(10_000)))
        .require(Precondition::Absent(key.clone()))
        .put(key.clone(), value.clone());
    match store.apply(&p, batch).await? {
        BatchOutcome::Committed => Ok(digest),
        BatchOutcome::PreconditionFailed { .. } => {
            if store.get(&p, &key).await?.as_ref() == Some(&value) {
                Ok(digest)
            } else {
                Err(corrupt())
            }
        }
        BatchOutcome::DeadlinePassed { .. } => {
            Err(StoreError::unavailable("publication page deadline passed"))
        }
    }
}

/// Exact flag query. Empty roots prove absence; missing pages never do.
/// # Errors
/// Invalid authenticated path or storage/call-budget failure.
pub async fn get<S: NamespaceStore>(
    store: &S,
    root: Option<Hash>,
    id: &Hash,
) -> Result<u8, StoreError> {
    let Some(mut next) = root else {
        return Ok(0);
    };
    let mut parent: Option<(Node, u8)> = None;
    for _ in 0..LOOKUP_CALLS {
        let node = load(store, &next).await?;
        if let Some((parent, label)) = &parent {
            node.below(parent, *label)?;
        }
        if !id.starts_with(node.prefix()) {
            return Ok(0);
        }
        match &node {
            Node::Leaf { id: key, flags } => return Ok(if key == id { *flags } else { 0 }),
            Node::Branch {
                depth, children, ..
            } => {
                let label = id[usize::from(*depth)];
                let Some(child) = children.get(&label) else {
                    return Ok(0);
                };
                next = *child;
                parent = Some((node, label));
            }
        }
    }
    Err(corrupt())
}

/// Insert flags using path copying. Untouched subtrees and old roots survive.
/// Partial page writes on error are unanchored and confer no authority. A
/// caller reserves [`INSERT_CALLS`] and checkpoints the returned root with its
/// corresponding owed work before consuming another item.
/// # Errors
/// Invalid flags/path, storage failure or exhausted caller budget.
pub async fn insert<S: NamespaceStore>(
    store: &S,
    root: Option<Hash>,
    id: Hash,
    flags: u8,
    now: u64,
) -> Result<Hash, StoreError> {
    if flags == 0 || flags & !FLAGS != 0 {
        return Err(corrupt());
    }
    let mut path: Vec<(Node, u8)> = Vec::new();
    let mut next = root;
    let mut replacement = None;
    while let Some(digest) = next {
        if path.len() >= LOOKUP_CALLS as usize {
            return Err(corrupt());
        }
        let node = load(store, &digest).await?;
        if let Some((parent, label)) = path.last() {
            node.below(parent, *label)?;
        }
        let common = id
            .iter()
            .zip(node.prefix())
            .take_while(|(a, b)| a == b)
            .count();
        if common < node.prefix().len() {
            let leaf = immutable(store, Node::Leaf { id, flags }.encode(), false, now).await?;
            let mut prefix = [0; 32];
            prefix[..common].copy_from_slice(&id[..common]);
            replacement = Some(Node::Branch {
                depth: u8::try_from(common).map_err(|_| corrupt())?,
                prefix,
                children: BTreeMap::from([(id[common], leaf), (node.prefix()[common], digest)]),
            });
            break;
        }
        match node {
            Node::Leaf { flags: old, .. } => {
                if old | flags == old {
                    return root.ok_or_else(corrupt);
                }
                replacement = Some(Node::Leaf {
                    id,
                    flags: old | flags,
                });
                break;
            }
            Node::Branch {
                depth,
                prefix,
                children,
            } => {
                let label = id[usize::from(depth)];
                next = children.get(&label).copied();
                path.push((
                    Node::Branch {
                        depth,
                        prefix,
                        children,
                    },
                    label,
                ));
            }
        }
    }
    let mut digest = immutable(
        store,
        replacement.unwrap_or(Node::Leaf { id, flags }).encode(),
        false,
        now,
    )
    .await?;
    while let Some((mut node, label)) = path.pop() {
        let Node::Branch { children, .. } = &mut node else {
            return Err(corrupt());
        };
        children.insert(label, digest);
        digest = immutable(store, node.encode(), false, now).await?;
    }
    Ok(digest)
}

/// One immutable frontier task; it is pending work, never evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Task {
    kind: u8,
    id: Hash,
}
impl Task {
    /// Construct one of the four normative task kinds.
    /// # Errors
    /// A kind outside 0..=3.
    pub fn new(kind: u8, id: Hash) -> Result<Self, StoreError> {
        if kind > 3 {
            return Err(corrupt());
        }
        Ok(Self { kind, id })
    }
    /// Task kind.
    #[must_use]
    pub fn kind(&self) -> u8 {
        self.kind
    }
    /// Task identifier.
    #[must_use]
    pub fn id(&self) -> Hash {
        self.id
    }
}
/// A bounded immutable frontier page.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Frontier {
    pub tasks: Vec<Task>,
    pub next: Option<Hash>,
}
impl Frontier {
    /// Stage a page. The returned digest becomes durable only with its cursor.
    /// # Errors
    /// Empty/oversized work, invalid kind or storage/call-budget failure.
    pub async fn write<S: NamespaceStore>(&self, store: &S, now: u64) -> Result<Hash, StoreError> {
        if self.tasks.is_empty()
            || self.tasks.len() > FRONTIER_TASKS
            || self.tasks.iter().any(|t| t.kind > 3)
        {
            return Err(corrupt());
        }
        let mut bytes = vec![1, 2, u8::from(self.next.is_some())];
        bytes.extend(
            u16::try_from(self.tasks.len())
                .map_err(|_| corrupt())?
                .to_be_bytes(),
        );
        bytes.extend(self.next.unwrap_or([0; 32]));
        for task in &self.tasks {
            bytes.push(task.kind);
            bytes.extend(task.id);
        }
        immutable(store, bytes, false, now).await
    }
    /// Authenticate a page without treating any task as a verified object.
    /// # Errors
    /// Missing, malformed or wrong-role page, or storage failure.
    pub async fn read<S: NamespaceStore>(store: &S, digest: &Hash) -> Result<Self, StoreError> {
        let bytes = authenticated(store, digest, false, 4_261).await?;
        Self::decode(&bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < 37 || bytes[..2] != [1, 2] || bytes[2] > 1 {
            return Err(corrupt());
        }
        let count = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        if !(1..=FRONTIER_TASKS).contains(&count) || bytes.len() != 37 + count * 33 {
            return Err(corrupt());
        }
        let next: Hash = bytes[5..37].try_into().map_err(|_| corrupt())?;
        if bytes[2] == 0 && next != [0; 32] {
            return Err(corrupt());
        }
        let tasks = bytes[37..]
            .chunks_exact(33)
            .map(|t| Task::new(t[0], t[1..].try_into().map_err(|_| corrupt())?))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            tasks,
            next: (bytes[2] == 1).then_some(next),
        })
    }
}

pub(crate) fn validate_record(
    partition: &super::Partition,
    key: &super::Key,
    raw: &Value,
) -> Result<(), StoreError> {
    let (digest, header) = match keys::parse(key) {
        Some(keys::ParsedKey::PublicationCertificate(digest)) => (digest, true),
        Some(keys::ParsedKey::PublicationPage(digest)) => (digest, false),
        _ => return Ok(()),
    };
    let bytes = raw.as_bytes();
    if *partition != content_shard(&digest) || hash(bytes) != digest {
        return Err(corrupt());
    }
    if header {
        if bytes.first() != Some(&1) || bytes.len() > MAX_HEADER_BYTES {
            return Err(corrupt());
        }
        serde_json::from_slice::<Header>(&bytes[1..]).map_err(|_| corrupt())?;
    } else if bytes.get(1) == Some(&2) {
        Frontier::decode(bytes)?;
    } else {
        Node::decode(bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
