//! Optional activation hints: bounded, volatile and never authorization evidence.
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use mkit_server::indexed::budget::SliceBudget;
use mkit_server::{NamespaceStore, Partition, RepoId};

use crate::ns_client::{DoNamespaceStore, NsTransport};

const CALLS: u32 =
    (mkit_server::store::REPO_INDEX_FANOUT + mkit_server::store::REF_INDEX_FANOUT) as u32;
const MAX_REPOSITORIES: usize = 4096;
const ANONYMOUS_WAVES: usize = 8;
const ANONYMOUS_WINDOW_MS: u64 = 60_000;
type Anonymous = Arc<Mutex<VecDeque<u64>>>;
type Recent = Arc<Mutex<BTreeMap<RepoId, u64>>>;

#[derive(Debug, Clone)]
pub(crate) struct Prewake {
    ttl_ms: u64,
    recent: Recent,
    allowance: SliceBudget,
    anonymous: Anonymous,
}

fn now_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        worker::Date::now().as_millis()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    }
}

impl Prewake {
    pub(crate) fn new(ttl_ms: u64) -> Self {
        static ANONYMOUS: OnceLock<Anonymous> = OnceLock::new();
        static RECENT: OnceLock<Recent> = OnceLock::new();
        Self {
            ttl_ms,
            anonymous: ANONYMOUS.get_or_init(Anonymous::default).clone(),
            recent: RECENT.get_or_init(Recent::default).clone(),
            allowance: SliceBudget::new(CALLS),
        }
    }

    #[cfg(test)]
    fn claim(&self, repo: &RepoId, now: u64, request: Option<&SliceBudget>) -> bool {
        self.claim_read(repo, now, request, false)
    }

    fn claim_read(
        &self,
        repo: &RepoId,
        now: u64,
        request: Option<&SliceBudget>,
        anonymous: bool,
    ) -> bool {
        let mut recent = self.recent.lock().unwrap_or_else(PoisonError::into_inner);
        if recent.get(repo).is_some_and(|until| now < *until) {
            return false;
        }
        recent.retain(|_, until| now < *until);
        // Do not evict a live entry: that would permit another wave inside its TTL.
        if recent.len() >= MAX_REPOSITORIES || self.allowance.remaining() < CALLS {
            return false;
        }
        let mut window = self
            .anonymous
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Retain future timestamps if the wall clock moves backwards.
        while window
            .front()
            .is_some_and(|start| now.saturating_sub(*start) >= ANONYMOUS_WINDOW_MS)
        {
            window.pop_front();
        }
        if anonymous && window.len() >= ANONYMOUS_WAVES {
            return false;
        }
        if request.is_some_and(|budget| budget.charge_many(CALLS).is_err())
            || self.allowance.charge_many(CALLS).is_err()
        {
            return false;
        }
        if anonymous {
            window.push_back(now);
        }
        // Claim before awaiting, including failed/cancelled waves, to bound retries.
        recent.insert(repo.clone(), now.saturating_add(self.ttl_ms));
        true
    }

    pub(crate) async fn run<T: NsTransport>(&self, store: &DoNamespaceStore<T>, repo: &RepoId) {
        self.run_read(store, repo, false).await;
    }

    pub(crate) async fn run_anonymous<T: NsTransport>(
        &self,
        store: &DoNamespaceStore<T>,
        repo: &RepoId,
    ) {
        self.run_read(store, repo, true).await;
    }

    async fn run_read<T: NsTransport>(
        &self,
        store: &DoNamespaceStore<T>,
        repo: &RepoId,
        anonymous: bool,
    ) {
        if store.read_call_allowance().is_none_or(|left| left < CALLS)
            || !self.claim_read(repo, now_ms(), store.request_budget(), anonymous)
        {
            return;
        }
        let wave = async {
            // Keep the measured width of sixteen. Ref scans are on the read
            // prologue; object-index lookups follow them. One claim covers both
            // families so a ref-only read cannot suppress later object warming.
            futures::future::join_all((0..mkit_server::store::REF_INDEX_FANOUT).map(
                |bucket| async move {
                    let partition = Partition::RefIndex {
                        ns: repo.namespace.clone(),
                        repo: repo.name.clone(),
                        bucket,
                    };
                    if let Err(error) = store.ping(&partition).await {
                        tracing::warn!(error = %error, "ref index warm-up failed");
                    }
                },
            ))
            .await;
            futures::future::join_all((0..mkit_server::store::REPO_INDEX_FANOUT).map(
                |prefix| async move {
                    let partition = Partition::RepoIndex {
                        ns: repo.namespace.clone(),
                        repo: repo.name.clone(),
                        prefix,
                    };
                    if let Err(error) = store.ping(&partition).await {
                        tracing::warn!(error = %error, "repository index warm-up failed");
                    }
                },
            ))
            .await;
        };
        #[cfg(target_arch = "wasm32")]
        finish_wave(&crate::sleep::WorkerSleep, wave).await;
        #[cfg(not(target_arch = "wasm32"))]
        wave.await;
    }
}

// A slow optional activation must not hold the read until its request deadline.
#[cfg(any(target_arch = "wasm32", test))]
async fn finish_wave(sleep: &impl mkit_server::Sleep, wave: impl std::future::Future<Output = ()>) {
    if mkit_server::with_timeout(sleep, std::time::Duration::from_secs(1), wave)
        .await
        .is_err()
    {
        tracing::warn!("repository index warm-up timed out");
    }
}

pub(crate) fn parse(
    var: &impl Fn(&str) -> Option<String>,
) -> Result<Option<u64>, crate::adapter::ConfigError> {
    let enabled = match var("REPO_INDEX_PREWAKE").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        _ => {
            return Err(crate::adapter::ConfigError(
                "REPO_INDEX_PREWAKE must be true or false".into(),
            ));
        }
    };
    let ttl = var("REPO_INDEX_PREWAKE_TTL_SECONDS")
        .map_or(Ok(90), |s| s.parse::<u64>())
        .map_err(|_| {
            crate::adapter::ConfigError("invalid REPO_INDEX_PREWAKE_TTL_SECONDS".into())
        })?;
    if !(1..=120).contains(&ttl) {
        return Err(crate::adapter::ConfigError(
            "REPO_INDEX_PREWAKE_TTL_SECONDS must be 1..120".into(),
        ));
    }
    Ok(enabled.then_some(ttl * 1000))
}

#[cfg(test)]
mod tests;

pub(crate) fn parse_anonymous(
    var: &impl Fn(&str) -> Option<String>,
) -> Result<bool, crate::adapter::ConfigError> {
    match var("REPO_INDEX_PREWAKE_ANONYMOUS").as_deref() {
        None | Some("true") => Ok(true),
        Some("false") => Ok(false),
        _ => Err(crate::adapter::ConfigError(
            "REPO_INDEX_PREWAKE_ANONYMOUS must be true or false".into(),
        )),
    }
}
