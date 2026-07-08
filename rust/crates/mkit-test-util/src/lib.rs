//! Dev-only helpers shared by test suites across the workspace.
//!
//! Not published — add this crate to `[dev-dependencies]` only.

use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use mkit_core::hash::Hash;
use mkit_core::protocol::{PackKey, RefWriteCondition, Transport, TransportResult};
use mkit_core::refs::Ref;

/// True if `name` can be spawned as a subprocess (i.e. it resolves on
/// `PATH`). We only care whether the OS could exec it, not its exit code —
/// some tools (e.g. `ssh`) reject `--version`-style flags but are still
/// present.
#[must_use]
pub fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Returns `true` if `name` is available. If it is not: panic when
/// `MKIT_TEST_STRICT` is set (a CI job that is supposed to have this tool
/// silently not running the test is a bug), otherwise print a loud `SKIP:`
/// line to stderr and return `false` so the caller can skip.
///
/// # Panics
///
/// Panics if `name` is unavailable and `MKIT_TEST_STRICT` is set.
#[must_use]
pub fn require_tool(name: &str) -> bool {
    if tool_available(name) {
        return true;
    }
    assert!(
        std::env::var_os("MKIT_TEST_STRICT").is_none(),
        "{name} required (MKIT_TEST_STRICT set) but not found"
    );
    eprintln!("SKIP: {name} not available");
    false
}

/// A [`Transport`] wrapper that counts bytes handed to `upload_pack` and
/// bytes returned by `download_pack`, so a test can assert exactly how much
/// a push or fetch moved over the wire.
///
/// Everything else delegates to the wrapped transport `T`. `upload_blob` /
/// `download_blob` are intentionally NOT overridden here: the
/// [`Transport`] trait's default impl for both routes through
/// `upload_pack`/`download_pack` (see `mkit_core::protocol::Transport`), so
/// leaving them un-overridden means auxiliary-blob traffic (e.g. a packmap
/// chain node) is counted too — the byte totals this wrapper reports are the
/// FULL wire cost of an operation, not just its packfile bytes. A caller
/// that wants to exclude auxiliary-blob traffic (e.g. to count only
/// packfile *downloads* for an applied-pack-skip assertion) should wrap
/// with its own transport instead.
#[derive(Debug)]
pub struct CountingTransport<T> {
    inner: T,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
}

impl<T: Transport> CountingTransport<T> {
    /// Wrap `inner`, starting both counters at zero.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            uploaded: AtomicU64::new(0),
            downloaded: AtomicU64::new(0),
        }
    }

    /// Read-and-reset the cumulative bytes passed to `upload_pack` (directly
    /// or via the default `upload_blob` delegation) since the last call.
    pub fn take_uploaded(&self) -> u64 {
        self.uploaded.swap(0, Ordering::SeqCst)
    }

    /// Read-and-reset the cumulative bytes returned by `download_pack`
    /// (directly or via the default `download_blob` delegation) since the
    /// last call.
    pub fn take_downloaded(&self) -> u64 {
        self.downloaded.swap(0, Ordering::SeqCst)
    }

    /// Borrow the wrapped transport.
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T: Transport> Transport for CountingTransport<T> {
    fn upload_pack(&self, bytes: &[u8], key: &PackKey) -> TransportResult<()> {
        self.uploaded
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        self.inner.upload_pack(bytes, key)
    }

    fn download_pack(&self, key: &PackKey) -> TransportResult<Vec<u8>> {
        let bytes = self.inner.download_pack(key)?;
        self.downloaded
            .fetch_add(bytes.len() as u64, Ordering::SeqCst);
        Ok(bytes)
    }

    fn pack_exists(&self, key: &PackKey) -> TransportResult<bool> {
        self.inner.pack_exists(key)
    }

    fn update_ref(
        &self,
        name: &str,
        condition: RefWriteCondition,
        hash: &Hash,
    ) -> TransportResult<()> {
        self.inner.update_ref(name, condition, hash)
    }

    fn read_ref(&self, name: &str) -> TransportResult<Option<Hash>> {
        self.inner.read_ref(name)
    }

    fn list_refs(&self, prefix: &str) -> TransportResult<Vec<Ref>> {
        self.inner.list_refs(prefix)
    }
}
