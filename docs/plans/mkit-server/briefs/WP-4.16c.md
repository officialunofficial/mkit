## Purpose

Embedders such as Uno Kit need canonical object bytes in-process, to build file layouts, disclosure proofs
(`build_disclosure_from`) and diffs. Those bytes include `ChunkedBlob` manifests, which HTTP serving never returns
(it serves concatenated content). Everything must follow the same reachability, visibility and takedown rules as HTTP
id-route serving. It is in-process only: **no wire, HTTP or spec change.**

## A. Fixed

- `mkit_core::store::ObjectSource` is **synchronous**, and Worker storage is async. So the design is an **async
  prefetch API** plus a **sync in-memory source**. There must be no blocking inside async code and no
  `block_on`-style hacks.
- The authorization, visibility, published-view and global-denial rules match the HTTP id route exactly: blocked or
  unreachable ids give the same "absent" answer, with no oracle.
- Budgets: a bounded batch size and a bounded call count per batch, charged within the request's existing
  allowances.

## B. Decided

1. **In `mkit-server`, a shared-core async reader** (native and Worker both use it), created from the pipeline for one
   repository and one **reader view**:
   - `ReaderView::Public` is anonymous: published refs, public repositories only.
   - `ReaderView::Owner` is the writer view, for the embedding host that holds the owner key. It is constructed only
     from a verified auth-v2 envelope for that repository's owner or grant, reusing the existing auth stage. It is
     never trusted by flag alone.
2. **Methods:**
   - `async fn read_canonical(&self, ids: &[Hash]) -> Result<Vec<Option<Vec<u8>>>>`: canonical serialized object
     bytes. For a `ChunkedBlob` this is the manifest; for Blob, Tree, Commit, Remix and Tag it is their canonical
     encoding. Pack-only Delta objects are never returned. There's a bounded batch size (document it, for example 64).
     Each id must be reachable under the view, using the same `reach` rules as the HTTP id route.
   - `async fn object_sizes(&self, ids: &[Hash]) -> Result<Vec<Option<u64>>>`: uncompressed content sizes from the
     indexed metadata, **without reading object bytes**, with the same authorization and bounds. This lets callers
     get chunk sizes without one read per chunk.
3. **In `mkit-core`, a small public sync in-memory source:** `store::MemorySource` (or a similar name), holding
   `id -> bytes` and implementing `store::ObjectSource`. It verifies integrity on read, as the trait requires. It is
   wasm-clean. The documented pattern is: prefetch with the async reader, insert into `MemorySource`, then call
   `build_disclosure_from`, `diff_trees` and friends synchronously.
4. **In `mkit-server-worker`,** a thin embedding constructor, for example
   `adapter::object_reader(&env, &cfg, repo, view) -> ObjectReader`, and a native equivalent. Document it in the
   embedding section of the Worker README. 4.18 is writing that section in parallel, so add a short subsection and
   keep it merge-friendly.
5. **Docs:**
   - R-202 row in `00-plan.md` ("WP-4.16c: in-process canonical object reader for embedders, for UNO-420");
   - a registry row;
   - CHANGELOG.

## C. Your decisions

Type and module names, the batch size, and error types. Record them in the PR body.

## D. Escalate

- The id-route reachability check can't be reused without a per-id cost beyond the budget.
- The owner view can't be built from the existing auth stage without new wire.
- You'd pass 600 lines.

## Tests

- **Parity with HTTP id-route answers** for the same ids and views: public vs private repo, published vs pending,
  unreachable ids, blocked ids (global denial).
- **The manifest bytes** for a `ChunkedBlob`, and `object_sizes` for its chunks, with no byte reads (count the calls).
- **An end-to-end prefetch** into `MemorySource`, then `build_disclosure_from`, then `verify_disclosure`, matching
  the native `?proof=1` bundle bytes for the same commit and path.
- **The owner view refuses** a non-owner or invalid envelope.
- **Batch bounds** are enforced.
- **Worker wasm** builds and a wrangler smoke test passes.

## Gates

- the common gates;
- `just ci-server`;
- wasm32 clippy (`mkit-core` and `mkit-server-worker`);
- the vcs-worker default conformance on a free port.

Do the self-review, then open the PR.

## Execution ruling (user, 2026-09-30)

Bounded canonical ancestor reads are allowed for object_sizes authorization,
exactly as for the HTTP id route. Requested-object sizes must come only from
indexed metadata, with no requested-object byte reads. One manifest serves all
its chunks. Share one reachability walk and one set-based global-denial pass per
batch, reusing eligible positive reachability proofs. The denial API refactor
uses the same data and descriptor scan, adds no state, and is allowed under
R-198. Bound and assert batch calls within the existing 9,000-call Worker
physical allowance and 8,500-call core share; stop and report numbers if even
one shared pass plus walk cannot fit. read_canonical shares the same proofs.
