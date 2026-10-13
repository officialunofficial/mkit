// SPDX-License-Identifier: MIT OR Apache-2.0
//
// wasm32-only Worker glue. The fetch handler hands every request to
// `mkit_server_worker::adapter::fetch` (CORS, the body cap, the streaming
// Connect bridge, the pipeline over R2 + Durable Objects). RefStore keeps
// the single-sharding namespace store; migration v2 adds the D34 classes.
// Each class delegates its key-value protocol and alarm to NsObject.

use mkit_server_worker::adapter;
use worker::{Context, Env, Request, Response, Result, event};

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    #[cfg(feature = "__test-faults")]
    if req.path() == "/__mkit_test/worker-sleep" {
        return mkit_server_worker::sleep::runtime_probe().await;
    }
    #[cfg(feature = "__test-faults")]
    if req.path() == "/__mkit_test/hook-fetch" {
        let mode = req
            .url()?
            .query_pairs()
            .find(|(key, _)| key == "mode")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        return mkit_server_worker::hooks::fetch_probe::run(&mode).await;
    }
    #[cfg(feature = "__test-faults")]
    if env
        .var("TEST_IMMUTABLE_CACHE")
        .ok()
        .is_some_and(|value| value.to_string() == "true")
    {
        return serve_cached(req, env, ctx).await;
    }
    #[cfg(feature = "http-objects")]
    return adapter::fetch_with_context(req, env, ctx).await;
    #[cfg(not(feature = "http-objects"))]
    {
        let _ = ctx;
        adapter::fetch(req, env).await
    }
}

mkit_server_worker::durable_objects!();

/// Explicit runtime conformance opt-in; ordinary fetch retains the default stores.
#[cfg(feature = "__test-faults")]
async fn serve_cached(req: Request, env: Env, ctx: Context) -> Result<Response> {
    use mkit_server::store::{CacheConfig, MemoryImmutableCache};
    use mkit_server_worker::{clock::WorkerClock, sleep::WorkerSleep};
    use std::{sync::Arc, time::Duration};

    thread_local! {
        static CACHE: MemoryImmutableCache = MemoryImmutableCache::new(
            8 * 1024 * 1024,
            Duration::from_secs(60),
            Arc::new(WorkerClock),
        );
    }
    #[allow(unused_mut)]
    let mut cfg = adapter::WorkerConfig::from_env(&env)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    #[cfg(feature = "http-objects")]
    {
        cfg.http_mount = cfg.http_mount.take().map(|mount| mount.with_context(ctx));
    }
    #[cfg(not(feature = "http-objects"))]
    let _ = ctx;
    let cache_config = CacheConfig::new(
        &cfg.audience,
        Arc::new(WorkerSleep),
        Duration::from_millis(10),
    )
    .map_err(|error| worker::Error::RustError(error.to_string()))?;
    let cache = CACHE.with(Clone::clone);
    adapter::serve_with_cache(
        req,
        env,
        &cfg,
        mkit_server_worker::hooks::build::hooks_from_env,
        |_| cache.clone(),
        cache_config,
    )
    .await
}
