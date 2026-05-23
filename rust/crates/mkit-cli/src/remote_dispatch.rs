//! URL-scheme → `Transport` dispatch for `mkit push` / `mkit pull`.
//!
//! The Rust binary wires all five shipping schemes here: `mkit+file://`,
//! `mkit+https://` (and `mkit+http://` for local dev), `mkit+s3://`, and
//! `mkit+ssh://`. The memory transport is in-process only, so it is
//! reached via [`push_all`] / [`pull_all`] with an `Arc<MemoryTransport>`
//! constructed in-process rather than URL-based construction. Integration
//! tests in the `mkit-cli` crate exercise the memory path directly.
//!
//! Credentials / environment sources:
//! - HTTP(S): optional `MKIT_API_TOKEN` bearer.
//! - S3/R2: `MKIT_R2_ACCESS_KEY_ID` + `MKIT_R2_SECRET_ACCESS_KEY` (plus
//!   optional `MKIT_R2_REGION`, default `auto`). Missing creds do NOT
//!   fail at connect time; the first signed request returns
//!   `TransportError::AccessDenied`.
//! - SSH: spawns `ssh(1)` subprocess — inherits the user's agent / keys /
//!   `~/.ssh/config`. Per-repo `.mkit/config` SSH options (host-key
//!   checking, known-hosts path, identity file) are wired through via
//!   `SshTransport::connect_with_options` when config is loaded.

use std::path::Path;
use std::sync::Arc;

use mkit_core::hash::Hash;
use mkit_core::ops::reachable_objects;
use mkit_core::pack::{PackError, PackReader};
use mkit_core::protocol::{PackKey, Transport, TransportError};
use mkit_core::refs::{self, Head};
use mkit_core::store::{ObjectStore, StoreError};
use mkit_transport_file::FileTransport;
use mkit_transport_http::HttpTransport;
use mkit_transport_s3::S3Transport;
use mkit_transport_ssh::{SshInitError, SshTransport};

/// Errors returned by the push / pull helpers. Mapped to exit codes by
/// the commands themselves.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    #[error("malformed URL: {0}")]
    MalformedUrl(String),
    #[error("no HEAD branch to push")]
    NoHead,
    /// A poll-loop checkpoint observed `signal::is_shutdown() == true`
    /// and aborted partway through. Callers should map this to
    /// `exit::TEMPFAIL` (75) so retries are safe — the transfer is
    /// half-finished but the remote is unmodified for any ref we
    /// hadn't reached yet.
    #[error("interrupted")]
    Interrupted,
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("refs: {0}")]
    Refs(#[from] refs::RefError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("pack: {0}")]
    Pack(#[from] PackError),
    #[error("ssh init: {0}")]
    SshInit(#[from] SshInitError),
}

/// Open a transport for the given URL. Returns a type-erased `Arc`
/// so callers can treat all schemes uniformly.
pub fn open(url: &str) -> Result<Arc<dyn Transport>, DispatchError> {
    if let Some(rest) = url.strip_prefix("mkit+file://") {
        // mkit+file:///abs/path -> /abs/path
        let path = Path::new(rest);
        return Ok(Arc::new(FileTransport::new(path)));
    }
    if url.starts_with("mkit+memory://") {
        // Memory transport is in-process; the URL-based path is not
        // useful on its own but we accept it so `mkit remote add`
        // round-trips cleanly.
        return Err(DispatchError::UnsupportedScheme(
            "mkit+memory:// must be driven via in-process harness (see tests)".to_string(),
        ));
    }
    if url.starts_with("mkit+https://") || url.starts_with("mkit+http://") {
        // HttpTransport::connect strips the `mkit+` prefix itself and
        // reads MKIT_API_TOKEN from the environment.
        let tx = HttpTransport::connect(url)?;
        return Ok(Arc::new(tx));
    }
    if url.starts_with("mkit+s3://") {
        // S3Transport::connect reads MKIT_R2_ACCESS_KEY_ID /
        // MKIT_R2_SECRET_ACCESS_KEY from the environment. Missing
        // credentials surface as AccessDenied on the first signed call,
        // not at connect time.
        let tx = S3Transport::connect(url)?;
        return Ok(Arc::new(tx));
    }
    if url.starts_with("mkit+ssh://") {
        // SshTransport::connect parses the URL, spawns `ssh(1)`, and
        // performs the `Hello` / `HelloResponse` handshake. Any failure
        // here tears the child down before returning, so callers never
        // see a half-initialised transport.
        let tx = SshTransport::connect(url)?;
        return Ok(Arc::new(tx));
    }
    #[cfg(feature = "enc-transport")]
    if url.starts_with("mkit+enc://") {
        return open_enc(url);
    }
    Err(DispatchError::MalformedUrl(url.to_string()))
}

/// `mkit+enc://` dispatch (Phase 2 of issue #156).
///
/// Parses the URL, derives an ephemeral dialer keypair (keystore
/// integration is SPEC-TRANSPORT-ENC §6 item 5, still deferred), and
/// runs the encrypted-stream handshake against the URL-advertised
/// server public key.
///
/// Ephemeral dialer keys are acceptable for v0.x because the
/// encrypted transport does not (yet) consult a per-peer authorization
/// list on the server side — `serve_tcp`'s bouncer is permissive. When
/// the server-side keyring lands, this function will switch to loading
/// a stable identity from `mkit-keystore` so the operator's per-peer
/// allowlist works.
#[cfg(feature = "enc-transport")]
fn open_enc(url: &str) -> Result<Arc<dyn Transport>, DispatchError> {
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::ed25519::PrivateKey;
    use mkit_transport_enc::url::parse_enc_url;
    use zeroize::Zeroizing;

    let target = parse_enc_url(url).map_err(DispatchError::Transport)?;
    // Ephemeral dialer key — fresh per process. The server's bouncer
    // is permissive in v0.x, so the key is effectively pseudonymous;
    // bumping to a stable keystore-backed key is SPEC-TRANSPORT-ENC §6
    // item 5.
    //
    // The previous shape passed only 64 bits of entropy (a `u64`
    // seed via `PrivateKey::from_seed`) — commonware's own
    // documentation calls `from_seed` "insecure" and reserves it
    // for examples / testing. Draw 32 bytes (≥256 bits) from
    // `getrandom` and hand them to the Ed25519 SigningKey via
    // commonware-codec's `DecodeExt::decode`, mirroring
    // `PrivateKey`'s own `Read` impl. The intermediate bytes are
    // wrapped in `Zeroizing` so the stack copy is scrubbed on drop;
    // the resulting `PrivateKey` carries its own `Secret`-based
    // zeroization for the lifetime of the value.
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut())
        .map_err(|e| DispatchError::Transport(TransportError::RemoteError(e.to_string())))?;
    let sk = PrivateKey::decode(secret.as_ref())
        .map_err(|e| DispatchError::Transport(TransportError::RemoteError(e.to_string())))?;
    let tx = mkit_transport_enc::connect_tcp(&target.host, target.port, &target.server_pubkey, sk)
        .map_err(|e| DispatchError::Transport(TransportError::RemoteError(e.to_string())))?;
    Ok(Arc::new(tx))
}

/// Push every ref under `refs/heads/` to the remote, assembling a pack
/// of every object reachable from the branch tip that the remote does
/// not already hold. Returns the count of refs pushed.
///
/// Per-ref flow:
/// 1. Resolve the local branch tip.
/// 2. Walk reachable objects (`ops::reachable_objects`).
/// 3. Filter out any object the remote already has via
///    [`Transport::pack_exists`] (single-object packs, so the digest ==
///    pack key).
/// 4. Build a pack with [`PackWriter`]; the whole-pack digest is the
///    `PackKey` used by [`Transport::upload_pack`].
/// 5. Publish the ref with [`Transport::write_ref`].
pub fn push_all(cwd: &Path, tx: &dyn Transport) -> Result<usize, DispatchError> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = ObjectStore::open(cwd)?;
    let refs_list = refs::list_refs(&mkit_dir)?;
    let mut n = 0;
    for r in refs_list {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let Some(h) = r.hash else { continue };
        let full_name = format!("refs/heads/{}", r.name);

        // Walk the reachable set and figure out what the remote lacks.
        // The current contract with the memory / file transports is one
        // object per pack, keyed by the object's own digest. This keeps
        // fetch simple (ask the remote for each hash as it walks the
        // object graph) and means `pack_exists` is a per-object HEAD
        // check against the same key we'd upload under.
        let reachable = reachable_objects(&store, &h)?;
        for obj in &reachable {
            if crate::signal::is_shutdown() {
                return Err(DispatchError::Interrupted);
            }
            let key = PackKey::from_hash(*obj);
            if tx.pack_exists(&key)? {
                continue;
            }
            let bytes = store.read(obj)?;
            tx.upload_pack(&bytes, &key)?;
        }
        // Multi-object pack-level transfer (one pack per ref) is more
        // efficient but requires the transport contract to advertise
        // pack keys alongside refs — deferred. Per-object addressing
        // keeps fetch simple and matches what file.rs / memory.rs
        // already implement.

        tx.write_ref(&full_name, &h)?;
        n += 1;
    }
    Ok(n)
}

/// Mirror the remote's ref set + all reachable objects into the local
/// repo. Count returned = number of refs updated locally. Unlike
/// [`fetch_all`], this also moves HEAD to the first branch if HEAD was
/// unset — matching the "clone-ish" behaviour the pre-pack port already
/// had.
pub fn pull_all(cwd: &Path, tx: &dyn Transport) -> Result<usize, DispatchError> {
    let n = fetch_all(cwd, tx)?;
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    // If HEAD is unset (freshly initialised), point it at the first
    // branch we saw. Intuitive UX for the `pull` ≈ `clone` path.
    if (refs::read_head(&mkit_dir).is_err()
        || matches!(refs::read_head(&mkit_dir), Ok(Head::Branch(ref b)) if refs::read_ref(&mkit_dir, b).is_ok_and(|x| x.is_none())))
        && let Ok(mut all) = refs::list_refs(&mkit_dir)
    {
        all.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(first) = all.first() {
            let _ = refs::write_head_branch(&mkit_dir, &first.name);
        }
    }
    Ok(n)
}

/// `fetch` — `pull_all` without the HEAD update. Downloads every object
/// reachable from each remote ref (via [`Transport::download_pack`] on
/// the object's own digest) and writes the ref into `refs/heads/`.
pub fn fetch_all(cwd: &Path, tx: &dyn Transport) -> Result<usize, DispatchError> {
    let mkit_dir = cwd.join(mkit_core::MKIT_DIR);
    let store = ObjectStore::open(cwd)?;
    let remote_refs = tx.list_refs("refs/heads/")?;
    let mut n = 0;
    for r in remote_refs {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        let Some(h) = r.hash else { continue };
        // Download the pack the remote uploaded for this ref. The
        // per-object fallback below handles the case where the pack
        // was never assembled (a push whose reachable set was empty
        // because the remote already had everything).
        //
        // The push path uploads one pack keyed by its own digest; the
        // memory / file transports `list_refs` only returns the ref,
        // not the pack digest. So we walk commit→tree→blobs on the
        // *local* side after downloading, re-using `download_pack` on
        // each object's hash as a fallback. That matches the
        // per-object transport semantics in file.rs / memory.rs.
        fetch_object_closure(&store, tx, &h)?;
        refs::write_ref(&mkit_dir, &r.name, &h)?;
        n += 1;
    }
    Ok(n)
}

/// Recursively download every object reachable from `root` into
/// `store`, fetching one digest at a time. Used by [`fetch_all`] /
/// [`pull_all`] when the remote's ref-advertise doesn't carry a
/// pack key (which is the current contract for the memory + file
/// transports).
fn fetch_object_closure(
    store: &ObjectStore,
    tx: &dyn Transport,
    root: &Hash,
) -> Result<(), DispatchError> {
    use std::collections::VecDeque;

    let mut queue: VecDeque<Hash> = VecDeque::new();
    queue.push_back(*root);
    let mut seen = std::collections::HashSet::new();

    while let Some(h) = queue.pop_front() {
        if crate::signal::is_shutdown() {
            return Err(DispatchError::Interrupted);
        }
        if !seen.insert(h) {
            continue;
        }
        if store.contains(&h) {
            // Already local — still walk to be sure children are
            // present. Read through the store to enqueue them.
        } else {
            // Download. Transports that keyed on the object digest
            // (memory, file) return raw object bytes here.
            let key = PackKey::from_hash(h);
            let bytes = match tx.download_pack(&key) {
                Ok(b) => b,
                Err(TransportError::PackNotFound) => {
                    // Accept as a no-op: the remote may have assembled
                    // a multi-object pack and thus does not key on the
                    // object digest. The per-object path can't see the
                    // pack in that case; the caller is expected to
                    // either download the pack explicitly (future: a
                    // proper ref-advertise carrying pack keys) or
                    // accept missing objects. For the memory/file
                    // transports the per-object mapping is always
                    // populated by the push side, so this branch is
                    // defensive.
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // If the remote returned a real packfile, unpack it. Else,
            // treat the bytes as a single raw object.
            if bytes.starts_with(mkit_core::pack::MAGIC) {
                let _ = PackReader::read(&bytes, store)?;
            } else {
                let stored = store.write(&bytes)?;
                // Sanity check: the digest MUST match the key we asked
                // for — otherwise the remote is serving mismatched
                // content.
                if stored != h {
                    return Err(DispatchError::Transport(TransportError::InvalidResponse));
                }
            }
        }
        // Enqueue children so we walk the whole closure.
        if let Ok(obj) = store.read_object(&h) {
            use mkit_core::object::Object;
            match obj {
                Object::Commit(c) => {
                    queue.push_back(c.tree_hash);
                    for p in c.parents {
                        queue.push_back(p);
                    }
                }
                Object::Remix(r) => {
                    queue.push_back(r.tree_hash);
                    for p in r.parents {
                        queue.push_back(p);
                    }
                }
                Object::Tree(t) => {
                    for e in t.entries {
                        queue.push_back(e.object_hash);
                    }
                }
                Object::ChunkedBlob(cb) => {
                    for c in cb.chunks {
                        queue.push_back(c);
                    }
                }
                Object::Blob(_) | Object::Delta(_) => {}
            }
        }
    }
    Ok(())
}
