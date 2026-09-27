// SPDX-License-Identifier: MIT OR Apache-2.0
//
// wasm32-only Worker glue. The fetch handler hands every request to
// `mkit_server_worker::adapter::fetch` (CORS, the body cap, the streaming
// Connect bridge, the pipeline over R2 + Durable Objects). RefStore keeps
// the single-sharding namespace store; migration v2 adds the D34 classes.
// Each class delegates its key-value protocol and alarm to NsObject.

use mkit_server_worker::adapter;
use mkit_server_worker::classes::ShardClass;
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
            object: adapter::ns_object(state, &env, ShardClass::RefStore),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

/// The `NsCoordinator` partition store, with the deployment capacity and timer registry.
#[durable_object]
pub struct NsCoordinator {
    object: NsObject,
}

impl DurableObject for NsCoordinator {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object(state, &env, ShardClass::NsCoordinator),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

/// The `RefShard` partition store, with the deployment capacity and timer registry.
#[durable_object]
pub struct RefShard {
    object: NsObject,
}

impl DurableObject for RefShard {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object(state, &env, ShardClass::RefShard),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

/// The `RepoIndexShard` partition store, with the deployment capacity and timer registry.
#[durable_object]
pub struct RepoIndexShard {
    object: NsObject,
}

impl DurableObject for RepoIndexShard {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object(state, &env, ShardClass::RepoIndexShard),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}

/// The `ContentIndexShard` partition store, with the deployment capacity and timer registry.
#[durable_object]
pub struct ContentIndexShard {
    object: NsObject,
}

impl DurableObject for ContentIndexShard {
    fn new(state: State, env: Env) -> Self {
        Self {
            object: adapter::ns_object(state, &env, ShardClass::ContentIndexShard),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        self.object.handle(req).await
    }

    async fn alarm(&self) -> Result<Response> {
        self.object.alarm().await
    }
}
