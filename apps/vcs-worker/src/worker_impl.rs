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
    #[cfg(feature = "http-objects")]
    return adapter::fetch_with_context(req, env, ctx).await;
    #[cfg(not(feature = "http-objects"))]
    {
        let _ = ctx;
        adapter::fetch(req, env).await
    }
}

mkit_server_worker::durable_objects!();
