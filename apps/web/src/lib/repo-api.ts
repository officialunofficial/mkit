// Repo client — transport-agnostic interface over the `mkit.repo.v1.RepoService`
// ConnectRPC service, backed by an in-memory mock (design note §3–§5).
//
// This file is a BARREL: the implementation was split into focused modules under
// `./repo/*`, and everything is re-exported here so every existing
// `from '../lib/repo-api'` import keeps working unchanged.
//
//   repo/envelope.ts — the Connect-flavored signed envelope + sign callback.
//   repo/backend.ts  — service shapes, fork-ref scheme, the RepoBackend
//                      interface, decodeLogObject, typed errors, MockRepoBackend
//                      (incl. seedDemo) and WasmRepoBackend.
//   repo/store.tsx   — the RepoBackend context (provider + useRepoBackend hook).
//   repo/hooks.ts    — query keys, query hooks, the push mutation, useRepoEvents.
//
// Service contract (unary unless noted):
//   PutObject(room, object_id, bytes)            getObject(room, object_id)
//   GetRef(room, name)                           ListRefs(room, prefix)
//   UpdateRef(room, name, new_id, expectation,   WatchRefs(room, prefix)  [server-streaming]
//             expected_id?)
//
// CAS lives INSIDE the message via `RefExpectation` (ANY | MISSING | MATCH),
// mirroring mkit-rpc/proto/mkit/rpc/v1/ssh/ssh.proto — NOT in transport headers.

export * from './repo/envelope'
export * from './repo/backend'
export * from './repo/store'
export * from './repo/hooks'
export * from './repo/use-resolved-backend'
