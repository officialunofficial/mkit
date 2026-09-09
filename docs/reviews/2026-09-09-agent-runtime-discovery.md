# Agent runtime discovery for mkit.sh

Initial research, 2026-09-09, followed by the goal-definition interview below.
Implementation has not been requested.

## Existing integration surfaces

The web application already runs mkit WASM in the browser and exposes WebMCP
tools in the multiplayer demo for reading state and signing/pushing commits.
Those tools require an unlocked browser identity for writes. The push tool
accepts a message and ref; it is not a general source-file editing interface.
Sources: [web README](../../apps/web/README.md) and
[tool implementations](../../apps/web/src/components/multiplayer/webmcp-tools.tsx).

The hosted MCP server supplies documentation and source reference. The local
`mkit mcp` command operates a repository. These are distinct integration paths.
Source: [MCP README](../../apps/mcp/README.md).

## External candidates

- [fx](https://fx.sh/) demonstrates its CLI compiled to browser WASM, backed
  by a browser workspace. The demonstration requires JSPI. Its embeddable
  library allows host-controlled storage, tools, and networking. This alone
  does not establish compatibility with Cloudflare Workers.
- [Nanocodex bindings](https://github.com/gakonst/nanocodex/blob/master/js/bindings/README.md)
  document a `nanocodex/cloudflare` Durable Object adapter with SQLite history
  and event replay. Direct tool mode is the default on Cloudflare. Application
  routing, authorization, and workspace policy remain host responsibilities.
- [Cloudflare Sandbox](https://developers.cloudflare.com/sandbox/concepts/architecture/)
  combines Workers, Durable Objects, and isolated Linux containers. It is an
  execution option for shell commands and builds, separate from agent selection.

These are documented capabilities, not integrations tested in this repository.
The research browser could not retrieve mkit.sh; local application sources were
used for its existing behavior, without asserting deployed parity.

## Decisions to resolve in conversation

1. Desired experience: embedded browser assistant, hosted background agent, or
   interoperability with local agents?
2. First complete task: demonstrate signed history, edit real files, or execute
   and test a code change?
3. Must execution continue after the browser closes?
4. Model access: user credentials or service-funded calls; OpenAI-only or multiple
   providers?
5. Who signs results: the user after review or a distinct agent identity?

After the first decision, define a single end-to-end acceptance scenario before
choosing a runtime and writing a concrete implementation plan.

## Interview decisions

- Users create general code projects with files and a terminal; keep the interface simple.
- Entry point: remix/fork the current mkit.sh demo repository, rather than an empty project.
- Remixes are public.
- Creating and operating a workspace requires stable passkey-backed Ed25519 identity.
  The existing temporary identity fallback is insufficient for this flow.
- Automatically save a version after each completed agent task.
- Agents continue after the browser closes. The user accepted a separate agent
  signing identity authorized by their identity; the delegation protocol remains to be designed.
- Nanocodex is mandatory (user reaffirmed this after discussing funding).
- The user asks to use Cloudflare's free tier for model usage; feasibility is unresolved.

## Cost and model compatibility findings

[Workers AI pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/)
provides 10,000 neurons per day free, including on Workers Paid. This is a service
allocation, not an allowance automatically granted to each mkit user.

[Nanocodex's current README](https://github.com/gakonst/nanocodex)
limits its model interface to an OpenAI model family; configuring a gateway does
not make it an arbitrary-provider runtime. Running its agent on Cloudflare does
not make its model calls eligible for Workers AI's free allocation.

[Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/#containers)
lists Containers as unavailable on Workers Free. The $5/month Workers Paid plan
includes limited container usage, with additional usage billed separately. A
Sandbox-backed general terminal therefore cannot be promised as entirely free.

The runtime must remain nanocodex. Budget for the terminal's container execution
and enforce application usage limits independently of inference funding.

## Groq follow-up

The user proposed Groq's free tier while requiring nanocodex.
[Groq's free limits](https://console.groq.com/docs/rate-limits) currently list
`openai/gpt-oss-120b` at 30 requests/minute, 1,000 requests/day, 8,000 tokens/minute,
and 200,000 tokens/day. Limits apply to the organization, not each end user;
the account's limits page is authoritative for exceptions.

Groq offers a [Responses API](https://console.groq.com/docs/responses-api), but
its [reference](https://console.groq.com/docs/api-reference) marks
`previous_response_id` unsupported. Nanocodex documents a persistent Responses
WebSocket and a closed OpenAI model set, so Groq is not a documented drop-in
backend. An OpenAI-branded open-weight model is not the supported model family.

Potential investigation, not demonstrated compatibility: retain nanocodex and
evaluate a transport/model adaptation for Groq. Verify streamed tool calls,
complete-history replay, cancellation, recovery, and multi-turn coding quality.
This may require a maintained nanocodex fork or a protocol bridge; do not promise
a small adapter or imply that changing the base URL is sufficient.

## Executed compatibility investigation

**Result: the basic coding flow works with unchanged nanocodex and an external
Groq adapter. No fork was needed for the tested scenario.**

Inspected upstream commit `449e8866136e4f4b6bbb96d265c1a776ffbd808b` and tested
the separate published npm artifact `nanocodex@0.5.0`. Their package surfaces
differ: npm 0.5.0 exposes node/browser entrypoints but lacks the newer
`nanocodex/host` and `nanocodex/cloudflare` exports present in the checkout.
Select and pin a tested build before implementing the hosted service.

First, a deterministic localhost peer proved the released WASM agent can call
an application tool and complete a follow-up through a configurable WebSocket.
Then a live Groq test used `openai/gpt-oss-120b`: the agent created `sum.mjs`,
executed two assertions, reported success, and recalled the filename in a new
turn. Four inference requests used 1,895 reported total tokens. The supplied
credential was used in memory, not stored in repository files.

The external adapter owns model mapping, conversion of input `additional_tools`
to ordinary function declarations, local warmup, full-history reconstruction,
and HTTP-to-WebSocket completion delivery. This proves buffered text and direct
tool calls, not streamed events or durable recovery.

Reproducible code, setup, and exact limits:
[compatibility probes](probes/nanocodex-groq/README.md).

### Next implementation milestones

1. Pin a nanocodex build with the chosen Cloudflare integration; repeat the
   coding probe against that artifact.
2. Make the broker production-ready: streaming, cancellation, bounded history,
   actual Groq usage/model reporting, rate-limit handling, and recovery tests.
3. Add a durable workspace session with isolated Sandbox tools; prove a task
   finishes and can be reopened after browser disconnect and process restart.
4. Implement demo remix ownership, passkey-authenticated authorization, and an
   explicit scoped agent signing grant. Verify revocation and prevent the agent
   from authorizing itself or writing outside its granted remix.
5. Connect files, terminal, chat, and automatic version publication. Exercise
   create-remix → edit → test → signed version → reopen → public remix.

No product implementation or deployment was performed in this investigation.


## Hosted implementation follow-through

The follow-through shipped `/create` on mkit.sh and the same-origin workspace
API on Cloudflare. The published `nanocodex@0.5.0` WASM remains unmodified. Its
external streaming adapter runs inside a Durable Object; a separate Sandbox
container supplies files and a real PTY. An owner-signed grant delegates to a
server signing key, while the passkey-derived owner seed stays in the browser.

Validation includes 132 backend tests, real workerd/R2/SQLite tests, native Chrome
PRF create/assert/recovery, production signed remix and file saves, and a real
production terminal command. A production agent task completed 81.845 seconds
after submission with its owner tab closed, created `browser-smoke.txt`, and
automatically published signed version
`023c65477c849ba8b15b131af6671e375b494ecf8ddc60be98b7e9756a1243c7`
in workspace `ff5660c38a5977596157c836ededb894`.

Live testing caught and fixed binary WebSocket framing, cross-DO serialization
of manifests and command options, exact replay cancellation, terminal teardown,
and quota admission at minute boundaries. Admission now uses the ordinary o200k
tokenizer and a continuously replenished shared budget, with bounded retries.

Browser disconnection is supported. A worker process restart during a task is
reported as interrupted; the saved draft survives and uncertain shell commands
are not replayed. Completed conversations resume from their saved snapshot.
See `apps/workspace-worker/README.md` for limits and reproducible verification.

### Cross-page identity navigation correction

The initial workspace UI used plain anchors for public projects and source links. These replaced the browser document and discarded the memory-only signing seed, so a user who had just unlocked appeared locked again. Main navigation already used Waku links. Workspace and demo internal links now use the router, and the workspace reacts to router query changes when selecting projects. The identity persistence policy remains unchanged: a reload or a separate tab requires passkey unlock.

A native Chrome WebAuthn PRF browser probe reproduced the old public-project link replacing the document, then passed against the corrected build while preserving the same signing public key through project and Multiplayer navigation. The component regression covers changing the workspace query without a popstate event while retaining the unlocked identity. Identity and workspace tests: 25 passed; TypeScript and production build passed.

### Terminal recovery correction

The production tail captured `Connection closed: this Durable Object instance is no longer active` during terminal cleanup. `SandboxWorkspace` retained an RPC stub indefinitely, so later calls could keep using a retired connection. It now retains the namespace and workspace id and obtains a fresh SDK connection for each call. It does not replay user commands. A regression makes the old connection fail and verifies that a later operation uses the new connection.

The terminal previously disabled all retries. It now retries consecutive disconnects after one, two, and four seconds, retaining manual Reconnect after that limit. Unmounting cancels retries, including when an identity is locked or an agent task takes over. Tests verify automatic recovery, the retry limit, and cancellation.

The live browser probe also exposed an ownership-loading race: unknown workspace metadata was treated as a negative ownership check, causing a DELETE of the newly issued owner session. Unknown ownership now waits for metadata instead of revoking the cookie. A regression verifies no logout occurs while metadata is pending.

Verification: 133 backend tests, 16 workspace UI tests, TypeScript, and the production build passed. Deployed backend `53279550-08a0-4090-9096-4a51ea0feacd` and web `042d62cb-a962-4110-ac41-d7e68ed3f210`. A native PRF browser test injected one terminal connection failure, verified automatic recovery and actual PTY command output, ran an agent task, and verified another PTY command after task completion without pressing Reconnect. Workspace `e76f6901d56e0ad39f0bfee933382274`, automatic version `c48fd705cbcc9e3e930a57461ce0d4368a0af3b74fe444ee5c8bdcdeb2581ed5`; all observed workspace HTTP responses were 200 and no browser errors were reported.

### Documentation response failure correction

A user reported a failed `add documentation` task in workspace `52a47466a8718153266e749e8a082fe1`. Its private response frames were not available from the public workspace API. A separate live documentation probe reproduced the same generic bridge failure: the provider emitted `error` / `response.failed` with `tool_use_failed` because file-write arguments were not valid JSON. At 1,024 output tokens this repeated, including with low reasoning. A 4,096-token request at default reasoning also failed once; 4,096 with explicit low reasoning completed and consumed 3,305 output tokens. The provider Responses output limit includes reasoning tokens as well as visible output ([API reference](https://console.groq.com/docs/api-reference)).

The bridge now explicitly uses low reasoning, matching the nanocodex runtime setting, and allows up to 4,096 output tokens. It reduces that allowance as input history grows so input, output, and the shared 512-token reserve remain within the 7,500-token request budget. Existing request and daily admission limits remain enforced. Known malformed tool requests and output-limit events now receive distinct safe messages, without exposing provider bodies or generated arguments. Partial tool calls remain rejected.

136 backend tests and TypeScript passed. Backend deployment: `8e9c17c7-7180-41ce-b4a0-3e14ca6e30a3`. Native PRF browser verification remixed the user's public source and submitted the exact prompt `add documentation`: task completed and saved `README.md` (331 bytes) in signed version `8af3e9eb29d99d989d66f245c0823bc241c38adfa702c86e1c464866a519d6b2`, test workspace `fdeba3c4271d800f22ebb946cfabcbd7`. All observed HTTP requests succeeded and no browser errors occurred. This verifies response completion and signed file persistence; it is not a review of generated documentation quality. The user's original failed task was not replayed.
