// SPDX-License-Identifier: MIT OR Apache-2.0
//
// wasm32-only Worker glue. The fetch handler hands every request to
// `mkit_server_worker::adapter::fetch` (CORS, the body cap, the streaming
// Connect bridge, the pipeline over R2 + Durable Objects). The `RefStore`
// Durable Object — class `RefStore`, binding `REFSTORE`, instance "root",
// all unchanged, so no wrangler migration — is one partition's key-value
// store (`mkit_server_worker::ns_object::NsObject`).

use mkit_server_worker::adapter;
use mkit_server_worker::ns_object::NsObject;
use worker::{
    Context, DurableObject, Env, Request, Response, Result, State, durable_object, event,
    wasm_bindgen,
};

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    adapter::fetch(req, env).await
}

/// The deployment-default namespace's partition: one SQLite key-value
/// store, capped for the `WORKERS_PLAN` var.
#[durable_object]
pub struct RefStore {
    object: NsObject,
}

impl DurableObject for RefStore {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object(state, &env),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }
}
