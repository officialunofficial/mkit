# D31 response and retained ownership ledger

This is a source ownership ledger, not a 128MB isolate certificate. Source checkpoint: parent77db85e2 plus the D31 commit containing this file. The final integrated artifact still needs its own pin. Budgets unchanged:4096 authoritative first scans/attempt, shared9000 call purse across retries; ordinary first batch4, scanner<=6. One scan asks limit1. Value512KiB,key<=1024 bytes,cursor<=key. There is no additional4096-prefix Vec. join_all retains at most width result pages; every dispatched scan consumes transport body before ordered descriptor checking begins. Error stops before next batch; unprocessed successful pages drop on error.

## Representations and stage overlap

Let V=524288 raw bytes; B64(V)=699052 ASCII bytes, and J<=B64(V)+2*B64(1024)+256=702044 bytes for one scan page (fixed JSON envelope conservatively256; current descriptor key itself70bytes). Keep allocation capacity/slack separate from length. Native/Wasm Vec growth may reserve beyond lengths. UTF16 JS string has at most2J bytes, regardless of V8's optional one-byte string representation. No decoder zstd scratch occurs in this first-page transport stage.

- Source SQL row/ScanPage retains raw key/value/cursor. NsReply::page moves value Vec into Blob. Blob::serialize allocates one base64 temporary at a time; serde_json output String grows while underlying raw reply remains owned. Producer Rust raw + serialized JSON + temporary base64 + capacities overlap. Source SQL/DO cached state is an additional owner, not attributed to these transient lengths.
- Response creation crosses Rust String -> JS string -> response byte buffer; transient JS UTF16/string/body buffers and Rust serialization may overlap. Source DO response lifetime ends only at reader EOF/cancel/error. HTTP body transport may retain runtime buffers. Both DO and caller may share one isolate: do not exclude either side from whole-isolate accounting.
- StubTransport retains small Rust request body, JS Request and AbortController until full response text await; JS response.text() buffers response bytes and resolves a JS string. wasm-bindgen UTF8 conversion allocates the Rust reply String; JS byte/string/Rust reply overlap may exist until callbacks/GC release them. Error statuses are also consumed. Guard abort on early error/drop requests cancellation; actual local fixture verifies caller error/body cancel, not termination of producer work.
- DoNamespaceStore serde_json borrows base64 text through Cow when unescaped; decoding allocates Blob raw Vec. Rust JSON reply is retained until decode returns. NsReply::Page -> wire::scan_page moves raw key/value bytes into Key/Value; no new full-page raw clone in this conversion. join_all retains those raw pages; ordinary max2MiB/scanner3MiB raw, plus keys/cursors/Vec/result/future bookkeeping. These are raw-only components, not whole memory maxima.
- After all first-page responses settle, prove_shard moves one current page out of result iterator. Other width-1 pages remain retained while current descriptor/nested validation runs. decode_actions allocates one current descriptor's typed action/page/reason vectors from raw JSON and holds them across serial nested reads. No second first-page batch overlaps. Continuation fetch may replace current page while remaining prefetched pages stay owned.
- Nested inventory::visit SCAN_ROWS8 allows8*512KiB raw metadata values (4MiB) and MAX_PAGE_BYTES8MiB generic dispatcher ceiling; each returned row's current Entry/StoredAction is decoded sequentially. Its transport JSON/base64/producer/consumer strings and runtime body buffers overlap with the remaining first pages and outer target/decoded action. Nested recursion/visits are serial but can retain outer decoded rows; serial does not mean no retained parent. Existing source bounds/valid-input graphs and allocator evidence must cover that nesting.
- Chunk page raw<=512KiB, canonical Vec<Hash><=512KiB; both coexist during page verification. Verified page chunks256 (8192 raw bytes) feed serial target intersection. Target holds caller's id BTreeSet, prepared publication data and pack Vec; existing ProofContext typed manifests capped4MiB plus target packs/header inventory. Caller pipeline/indexed working sets are additional retained owners and cannot be subtracted from isolate memory.
- Cancellation/error of a whole Rust proof drops Rust pages/futures; supported transport signal guard requests actual JS cancellation. Completion counters in host test are only host-body analogues. Local transport fixture separately records starts/active/peak/EOF/error/cancel across real DO requests. GC/restarts and baseline Wasm page capacity require runtime measurement; file count and process RSS cannot establish isolate memory.

A deliberately loose first-page representation sum can exceed10MiB for width4 once source and caller JS strings, byte buffers and Rust copies coexist. Adding nested8-row transport and caller working sets can materially change the peak. No assertion4*512KiB<128MB is used. Full profile numeric memory sampling/identity/coverage and bounded native/Wasm allocator evidence are still required before final resource closure.


## Local component evidence

The executor retained25/25 focused denial/planner tests, including the unchanged
signed D36 publication/takedown intersection and million-chunk paging. The new
early-error test fails on the original buffered helper (completed1 versus4), then
passes with joined batches. A real local release Rust StubTransport fixture
(`apps/vcs-worker/tests/transport-probe`) passes8 caller lifetime scenarios with
worker0.8.6: success/503 EOF, body error, pending header/body drop, ordinary4
success/error and scanner6 success followed by serial nested I/O. Measured
first-batch peaks4/6, outgoing0 at Rust return and after400ms; a nested dispatch
starts with0 prior outgoing calls. That fixture is separate from a full4096
workerd proof and contains no inspector/memory claim. Raw logs, artifact/source
hashes and full results are retained in the executor's
`$TMPDIR/night2/d31-resume/transport-runtime/evidence.json`.
