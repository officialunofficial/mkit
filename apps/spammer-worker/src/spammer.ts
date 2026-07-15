// The `Spammer` Durable Object (PLAN.md build step 8; extended by issue #854
// — "DO wiring" — to poll the room's read side and drive response traffic).
//
// One singleton instance owns the whole synthetic-activity loop: a
// self-rescheduling `alarm()` that, once every ~1000 ms, asks `scheduler.ts`
// for this tick's batch, emits it concurrently via `events.ts`, and records
// the resulting per-identity floors — plus the `/control` surface
// (enable/disable/status) that is the ONLY way to turn any of this on.
//
// As of #854, the SAME alarm loop optionally (see "responderEnabled" below)
// also polls the room's unauthenticated reads every `POLL_EVERY_N_TICKS`
// ticks, diffs them via `observer.ts`'s pure `observe`, and enqueues response
// bundles via `scheduler.ts`'s `enqueueResponseBundle` — ALL the decidable
// logic for "what to fetch" / "what changed" / "what to say" lives in the
// pure `responder.ts`/`observer.ts`/`scheduler.ts` modules; this file is only
// I/O glue (wasm calls, `Date.now()`, DO storage) and orchestration, per this
// codebase's standing "the DO stays thin" principle.
//
// DORMANT BY DEFAULT: a freshly-created instance has never had `enabled` set,
// so `(await storage.get("enabled")) ?? false` is `false` and `alarm()`
// no-ops without rescheduling itself even if one somehow fired. The DO never
// arms its own first alarm — only an authenticated `POST /control` (action
// "enable") does that (see `ensureAlarmScheduled`). The responder has its
// OWN independent `"responderEnabled"` flag (default `false`, same posture)
// that gates ONLY the polling/response half of the tick — it never touches
// the alarm itself, which the ambient loop alone owns (see the `/control`
// section's "responder-enable"/"responder-disable" cases).
//
// Storage layout (DO SQLite, `new_sqlite_classes` migration in
// wrangler.jsonc):
//   - `identity_floors` SQL table — per-identity `last_chat_ms`/`last_push_ms`/
//     `last_reaction_ms` (PLAN.md's floor bookkeeping the scheduler needs).
//   - `ctx.storage` KV keys:
//     - `"enabled"` (boolean) — the ambient loop's kill switch (unchanged).
//     - `"schedulerMeta"` (the scheduler's round-robin cursors + tick
//       counter, PLUS — as of #850/#851/#854 — the optional
//       `responseQueue`/`lastBundleMsByAuthor`/`reactionIdentitiesByBundle`
//       fields `SchedulerState` gained; see `SchedulerMeta` below, which
//       mirrors `SchedulerState` exactly minus the floor arrays that live in
//       `identity_floors` instead).
//     - `"responderEnabled"` (boolean, default `false`) — the responder's
//       OWN independent kill switch (#854/#848: "independently killable from
//       ambient traffic").
//     - `"observerWatermark"` (`ObserverWatermark`, `observer.ts`) — the
//       per-ref head map / known-fork-ref inventory / responded-event LRU
//       `observe` round-trips every poll. Absent means "never polled yet";
//       `loadObserverWatermark` defaults it to `initialObserverWatermark()`,
//       NOT an empty-history replay risk — see that function's doc comment
//       and #848's "restart/redeploy safety" story.
//     - `"replyBudgetLedger"` (`LedgerState`, `reply-budget.ts`) — the
//       per-UTC-day AI-personalization neuron spend + last-call timestamp.
//       Absent means "no personalization call has ever been attempted";
//       `loadReplyLedger` defaults it to `initialLedgerState(now)`.
//   - This KV API is backed by the SAME SQLite storage the
//     `new_sqlite_classes` migration provisions, so all of the above is
//     still "SQLite-backed" underneath, and — unlike a plain in-memory field
//     — survives an isolate eviction between ticks.

import { DurableObject } from "cloudflare:workers";
import {
  generatePersonalizedReply,
  refreshContentPools,
  REPLY_SHORT_HEX_LEN,
  type ContentPools,
  type PersonalizedReplyEvent,
} from "./ai-content";
import { isAuthorized, jsonResponse, resolveAction } from "./control-auth";
import { emitChat, emitChatText, emitCommit, emitReaction, emitRemix, MAIN_REF, type EmitContext } from "./events";
import { getIdentityPool, POOL_SIZE, type Identity } from "./identities";
import { initialObserverWatermark, observe, type CommitMeta, type ObserverWatermark, type RefEntry } from "./observer";
import { canPersonalize, initialLedgerState, recordCall, utcDayKey, type LedgerState } from "./reply-budget";
import { buildSnapshot, chooseReplyText, forkUpstreamsFromWatermark, mergedSyntheticPubkeys, refsNeedingFetch } from "./responder";
import { enqueueResponseBundle, planTick, type PlannedEvent, type ResponseIntent, type SchedulerState } from "./scheduler";
import { getWasm, type WasmApi } from "./wasm";

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS identity_floors (
    identity_index INTEGER PRIMARY KEY,
    last_chat_ms INTEGER,
    last_push_ms INTEGER,
    last_reaction_ms INTEGER
  )
`;

/**
 * The scheduler's round-robin cursors + tick counter — everything
 * `SchedulerState` needs beyond the per-identity floor arrays (those live in
 * `identity_floors` instead — see this file's top storage-layout comment).
 * As of #850/#851, `SchedulerState` also carries the OPTIONAL
 * `responseQueue`/`lastBundleMsByAuthor`/`reactionIdentitiesByBundle` fields;
 * they round-trip through this same DO-storage key so a response bundle
 * queued on one tick survives an isolate eviction before it fully drains,
 * exactly like the cursors/tick counter already did.
 */
type SchedulerMeta = {
  chatCursor: number;
  pushCursor: number;
  reactionCursor: number;
  tick: number;
  responseQueue?: readonly ResponseIntent[];
  lastBundleMsByAuthor?: Readonly<Record<string, number>>;
  reactionIdentitiesByBundle?: Readonly<Record<string, readonly number[]>>;
};

const DEFAULT_SCHEDULER_META: SchedulerMeta = { chatCursor: 0, pushCursor: 0, reactionCursor: 0, tick: 0 };

/** How long an alarm tick waits before rescheduling itself — PLAN.md's "Alarm interval: 1000 ms". */
const ALARM_INTERVAL_MS = 1000;

/**
 * How often (in ticks) the responder polls `list_refs`/`list_commits` — every
 * 5 ticks ≈ 5s at the real 1000ms alarm cadence, matching #848's "~5s
 * cadence, tunable" (`Implementation Decisions → Read side`). Consulted ONLY
 * when `"responderEnabled"` is true; the ambient loop's own per-tick cadence
 * is completely unaffected by this constant either way.
 */
export const POLL_EVERY_N_TICKS = 5;

/**
 * `list_commits` page size per polled ref, per poll. Kept intentionally
 * SMALL — one shallow page, not a deep walk — now that EVERY ref is polled
 * each cycle (not just `main`), which multiplies the metadata volume fetched
 * per poll relative to a `main`-only design. See #848's "Known transport
 * risk": a stripped `Content-Encoding` header can leave a still-gzipped
 * response body silently unparseable at volume; the vendored
 * `mkit-repo-client` transport already sniffs the gzip magic number
 * regardless of that header (fixed independent of page size — see
 * `rust/crates/mkit-repo-client/src/transport.rs`), but a small page size
 * keeps per-ref payloads modest on top of that fix, not instead of it.
 */
export const COMMIT_PAGE_SIZE = 20;

/** Raw `list_refs` row shape crossing the wasm boundary — `RepoWasmApi.list_refs` is typed `Promise<any>` (wasm-bindgen can't express the JS object shape), so this is asserted, not inferred. Mirrors `mkit-repo-client::list_refs`'s doc comment (`{ name, objectIdHex }`). */
type RawRefEntry = { name: string; objectIdHex: string };

/** Raw `list_commits` response shape — see `RawRefEntry`'s doc comment for why this is asserted. Mirrors `mkit-repo-client::list_commits`'s doc comment (`{ commits: [...], nextCursorHex }`); `nextCursorHex` is unused here — one shallow page (`COMMIT_PAGE_SIZE`) per ref per poll is deliberate (see that const's doc comment), so this DO never walks a second page. */
type RawCommitsPage = { commits: CommitMeta[]; nextCursorHex: string };

/**
 * How often (in ticks) to kick off a background Workers-AI content refresh —
 * every 1200 ticks ≈ 20 minutes at the real 1000ms alarm cadence. Deliberately
 * tick-based (not wall-clock-based) for consistency with the rest of this
 * DO's tick-driven design. See `ai-content.ts`'s doc comment for the
 * free-tier budget math behind this cadence.
 */
const CONTENT_REFRESH_EVERY_N_TICKS = 1200;

/** DO storage key for the last successfully AI-refreshed pool — absent until the first refresh ever succeeds. */
const CONTENT_POOLS_STORAGE_KEY = "contentPools";

type FloorRow = {
  identity_index: number;
  last_chat_ms: number | null;
  last_push_ms: number | null;
  last_reaction_ms: number | null;
};

/**
 * `/control?action=status` payload — extended by #854 with a `responder`
 * sub-object (#848: "the status endpoint to report responder state
 * (enabled, watermark summary, queue depth, budget remaining)") on top of
 * the pre-existing ambient-loop fields, which are UNCHANGED.
 */
export type ControlStatus = {
  enabled: boolean;
  room: string;
  poolSize: number;
  responder: {
    /** The independent responder kill-switch flag (`"responderEnabled"` storage key) — NOT the same as `enabled` (the ambient loop's flag). */
    enabled: boolean;
    /** `Object.keys(watermark.refHeads).length` — how many refs the watermark currently tracks. */
    refsTracked: number;
    /** `watermark.knownForkRefs.length` — the fork-of-fork upstream candidate pool size. */
    knownForkRefs: number;
    /** Undrained response-queue intent count (`SchedulerState.responseQueue`). */
    queueDepth: number;
    /** `false` until the first successful poll (or explicitly-fresh watermark) has recorded at least one ref — mirrors `refsTracked > 0`, exposed as its own boolean since "has this instance EVER observed the room" is the operationally interesting question, not the exact count. */
    watermarkInitialized: boolean;
    budget: {
      /** UTC day key (`YYYY-MM-DD`) the ledger's spend below is accounted against. */
      dayKey: string;
      /** Neurons spent on `dayKey` so far — `0` if `dayKey` isn't today (an unrolled-over ledger reads as "nothing spent today yet", mirrors `reply-budget.ts`'s own lazy-rollover semantics). */
      usedNeurons: number;
    };
  };
};

export class Spammer extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // `sql.exec` is fully synchronous — no async gap exists between this and
    // the constructor returning, so (per the Durable Objects storage model)
    // no request/alarm can be dispatched against a not-yet-migrated instance;
    // `blockConcurrencyWhile` would add nothing here.
    this.ctx.storage.sql.exec(SCHEMA);
  }

  // -------------------------------------------------------------------------
  // /control surface
  // -------------------------------------------------------------------------

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/control")) {
      return jsonResponse({ error: "not found" }, 404);
    }

    // Per wrangler.jsonc's own comment: CONTROL_TOKEN gates EVERY /control
    // call, including a plain status read — there is no unauthenticated
    // "peek" endpoint.
    if (!isAuthorized(request, this.env.CONTROL_TOKEN)) {
      return jsonResponse({ error: "unauthorized" }, 401);
    }

    const action = await resolveAction(request, url);
    switch (action) {
      case "enable": {
        await this.setEnabled(true);
        await this.ensureAlarmScheduled();
        return jsonResponse(await this.statusPayload(), 200);
      }
      case "disable": {
        // Delete first, then clear the flag: if a request races an in-flight
        // alarm's own reschedule, the flag is what the alarm's `finally`
        // re-checks before calling `setAlarm` again (see `alarm()` below), so
        // clearing it is what actually matters for "stops within ~1 tick".
        await this.ctx.storage.deleteAlarm();
        await this.setEnabled(false);
        return jsonResponse(await this.statusPayload(), 200);
      }
      case "status": {
        return jsonResponse(await this.statusPayload(), 200);
      }
      case "reset-content": {
        // Immediate, synchronous revert to content.ts's curated static pool —
        // no network/wasm call, just a storage delete, so it takes effect on
        // the very next tick. The escape hatch for "the stored AI-refreshed
        // pool drifted off-brand" without waiting for CONTENT_REFRESH_EVERY_N_TICKS
        // or a redeploy.
        await this.ctx.storage.delete(CONTENT_POOLS_STORAGE_KEY);
        return jsonResponse({ ...(await this.statusPayload()), contentPoolReset: true }, 200);
      }
      case "refresh-content": {
        // Manual, on-demand AI content refresh — the only way to get a fresh
        // AI-generated pool now that the automatic per-tick trigger is
        // opt-in (env.AI_CONTENT_AUTO_REFRESH). Awaited (not fire-and-forget)
        // since this is an explicit, infrequent admin action, not hot-path.
        const refreshed = await refreshContentPools(this.env.AI);
        if (refreshed) await this.ctx.storage.put(CONTENT_POOLS_STORAGE_KEY, refreshed);
        return jsonResponse({ ...(await this.statusPayload()), contentRefreshed: refreshed !== null }, 200);
      }
      case "responder-enable": {
        // Same storage-flag pattern as "enable" above, but deliberately does
        // NOT call `ensureAlarmScheduled` — the ambient loop (gated by
        // `"enabled"`) is the ONLY thing that arms/owns the alarm; the
        // responder piggybacks on whatever cadence is already running (or
        // stays inert, still flagged on, if the ambient loop itself is off —
        // #848: "independently killable from ambient traffic" cuts both
        // ways, so it's also independently enable-able without implicitly
        // starting the ambient loop).
        await this.setResponderEnabled(true);
        return jsonResponse(await this.statusPayload(), 200);
      }
      case "responder-disable": {
        await this.setResponderEnabled(false);
        return jsonResponse(await this.statusPayload(), 200);
      }
      default:
        return jsonResponse({ error: `unknown action: ${action}` }, 400);
    }
  }

  private async setEnabled(value: boolean): Promise<void> {
    await this.ctx.storage.put("enabled", value);
  }

  private async isEnabled(): Promise<boolean> {
    return (await this.ctx.storage.get<boolean>("enabled")) ?? false;
  }

  private async setResponderEnabled(value: boolean): Promise<void> {
    await this.ctx.storage.put("responderEnabled", value);
  }

  private async isResponderEnabled(): Promise<boolean> {
    return (await this.ctx.storage.get<boolean>("responderEnabled")) ?? false;
  }

  /** Arms the first alarm only if none is already pending — never stomps an in-flight schedule. */
  private async ensureAlarmScheduled(): Promise<void> {
    const existing = await this.ctx.storage.getAlarm();
    if (existing === null) {
      await this.ctx.storage.setAlarm(Date.now());
    }
  }

  private async statusPayload(): Promise<ControlStatus> {
    // Read fresh (not cached) so a status call right after enable/disable
    // always reflects the value that call just wrote.
    const now = Date.now();
    const watermark = await this.loadObserverWatermark();
    const meta = (await this.ctx.storage.get<SchedulerMeta>("schedulerMeta")) ?? DEFAULT_SCHEDULER_META;
    const ledger = await this.loadReplyLedger(now);
    const refsTracked = Object.keys(watermark.refHeads).length;

    return {
      enabled: await this.isEnabled(),
      room: this.env.ROOM,
      poolSize: POOL_SIZE,
      responder: {
        enabled: await this.isResponderEnabled(),
        refsTracked,
        knownForkRefs: watermark.knownForkRefs.length,
        queueDepth: meta.responseQueue?.length ?? 0,
        watermarkInitialized: refsTracked > 0,
        budget: { dayKey: ledger.dayKey, usedNeurons: ledger.dayKey === utcDayKey(now) ? ledger.neuronsSpentToday : 0 },
      },
    };
  }

  // -------------------------------------------------------------------------
  // Alarm loop
  // -------------------------------------------------------------------------

  async alarm(): Promise<void> {
    if (!(await this.isEnabled())) {
      // Disabled — a stray/late-firing alarm from before a disable no-ops
      // and, critically, does NOT reschedule itself. This is what makes
      // disable's "stops within ~1 tick" true even if disable raced an
      // alarm that had already started running.
      return;
    }

    try {
      const wasm = await getWasm();
      const pool = getIdentityPool(wasm.mkit);
      let state = await this.loadSchedulerState();
      const now = Date.now();

      // Responder polling (#854): piggybacks on this SAME alarm tick at a
      // coarser cadence (`POLL_EVERY_N_TICKS`), and ONLY when
      // `responderEnabled` — the ambient picks below run completely
      // unconditionally regardless of this flag. `watermark` is loaded
      // EVERY tick (cheap, a single storage.get) regardless of whether this
      // tick polls, because `forkUpstreamsFromWatermark` below needs the
      // freshest persisted watermark either way — see that function's doc
      // comment for the deliberate #851/#854 coupling this creates.
      let watermark = await this.loadObserverWatermark();
      if (state.tick % POLL_EVERY_N_TICKS === 0 && (await this.isResponderEnabled())) {
        try {
          const polled = await this.pollAndEnqueueResponses(wasm, pool, watermark, state, now);
          watermark = polled.watermark;
          state = polled.state;
          await this.ctx.storage.put("observerWatermark", watermark);
        } catch (err) {
          // A poll failure (network, malformed wasm response, transport
          // hiccup, …) must never break the ambient tick it's piggybacking
          // on — log and skip; the next poll (POLL_EVERY_N_TICKS ticks from
          // now) simply tries again against the still-valid `watermark`
          // this tick never advanced.
          console.error("[spammer] responder poll failed — skipping this poll:", err);
        }
      }

      const forkUpstreams = forkUpstreamsFromWatermark(watermark);
      const { events, nextState } = planTick(state, now, forkUpstreams);

      // Persist floors + cursors/tick BEFORE emitting: if an emit throws (or
      // this whole alarm invocation throws and Cloudflare auto-retries it),
      // the identities already picked this tick must never be re-picked
      // inside their floor window — see PLAN.md's floor-safety design.
      // `scheduler.ts`'s contract is "picked ⇒ spent", independent of whether
      // the network write actually lands.
      this.persistFloors(events, now);
      await this.persistSchedulerMeta(nextState);

      // Fire-and-forget: a background Workers AI content refresh, at most
      // once every CONTENT_REFRESH_EVERY_N_TICKS ticks. `ctx.waitUntil` lets
      // this keep running after `alarm()` returns without delaying this
      // tick's own reschedule or emit — see ai-content.ts's doc comment for
      // why this must never sit on the hot per-tick path.
      //
      // OPT-IN, default off: env.AI_CONTENT_AUTO_REFRESH must be exactly
      // "true" (not just "AI binding present") for this to fire at all. A
      // live run against lobby-v2 showed the model can drift away from the
      // curated pool's honest, mkit-aware voice into inventing a fictional
      // dev-team narrative for EMPTY-TREE commits (no real file changes) —
      // e.g. "Add prop 'size' to Button component." with no diff behind it,
      // which reads as misleading chat roleplay rather than a real
      // demonstration of mkit's signing/content-addressing. The tightened
      // prompt in ai-content.ts should prevent a repeat, but auto-refresh
      // stays opt-in until that's proven, rather than firing unprompted on
      // every worker's very first tick (tick 0 % N === 0).
      if (this.env.AI_CONTENT_AUTO_REFRESH === "true" && nextState.tick % CONTENT_REFRESH_EVERY_N_TICKS === 0) {
        this.ctx.waitUntil(this.refreshContentPoolsInBackground());
      }

      if (events.length > 0) {
        const contentPools = await this.ctx.storage.get<ContentPools>(CONTENT_POOLS_STORAGE_KEY);
        const ctx: EmitContext = { wasm, baseUrl: this.env.REPO_BASE_URL, contentPools };
        await this.emitBatch(ctx, pool, events, nextState.tick, now);
      }
    } catch (err) {
      console.error("[spammer] alarm tick failed:", err);
    } finally {
      // Re-check (not the value captured above) — a `/control` disable can
      // race and land while this tick was mid-flight doing real network I/O.
      if (await this.isEnabled()) {
        await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
      }
    }
  }

  /**
   * Runs entirely outside the hot per-tick path (invoked only via
   * `ctx.waitUntil`, at most once every `CONTENT_REFRESH_EVERY_N_TICKS`
   * ticks). On success, overwrites the stored pool for future ticks to read;
   * on ANY failure (`refreshContentPools` never throws — see its own doc
   * comment) leaves the existing stored pool untouched, so a bad refresh
   * degrades to "keep using the last known-good pool", never to an error.
   */
  private async refreshContentPoolsInBackground(): Promise<void> {
    const refreshed = await refreshContentPools(this.env.AI);
    if (refreshed) {
      await this.ctx.storage.put(CONTENT_POOLS_STORAGE_KEY, refreshed);
    }
  }

  private async emitBatch(
    ctx: EmitContext,
    pool: Identity[],
    events: PlannedEvent[],
    tick: number,
    now: number,
  ): Promise<void> {
    const room = this.env.ROOM;

    // "remix" and "reaction" both need something real to point at; fetch the
    // current `main` head at most once per tick, shared by both kinds — but
    // ONLY for picks that actually fall back to it: a response pick already
    // carries its own real target (`event.response.targetIdHex`, #850) and
    // an ambient fork-of-fork remix pick already carries its own upstream
    // (`event.remixUpstream.headHex`, #851), so neither needs `main`'s head
    // at all.
    const needsMainHead = events.some(
      (e) => (e.kind === "remix" && !e.response && !e.remixUpstream) || (e.kind === "reaction" && !e.response),
    );
    const mainHead = needsMainHead ? ((await ctx.wasm.repo.get_ref(ctx.baseUrl, room, MAIN_REF)) ?? null) : null;

    // Response-chat text must be resolved BEFORE the concurrent emit step
    // below — see `resolveChatTexts`'s own doc comment for why (shared,
    // persisted AI-personalization budget ledger).
    const chatTexts = await this.resolveChatTexts(ctx, events, tick, now);

    const results = await Promise.allSettled(
      events.map((event, slot) => this.emitOne(ctx, room, pool, event, tick, slot, mainHead, chatTexts)),
    );
    for (const [i, result] of results.entries()) {
      if (result.status === "rejected") {
        const event = events[i]!;
        console.error(
          `[spammer] tick ${tick} slot ${i} (${event.kind}, identity #${event.identityIndex}) failed:`,
          result.reason,
        );
      }
    }
  }

  private async emitOne(
    ctx: EmitContext,
    room: string,
    pool: Identity[],
    event: PlannedEvent,
    tick: number,
    slot: number,
    mainHead: string | null,
    chatTexts: ReadonlyMap<number, string>,
  ): Promise<unknown> {
    const identity = pool[event.identityIndex];
    if (!identity) throw new Error(`[spammer] no identity at pool index ${event.identityIndex}`);
    // Deterministic per-(tick, slot) counter — enough variety that the two
    // chat picks (or any two same-kind picks) in one tick never select the
    // identical content-pool phrase; see content.ts's `pick`.
    const counter = tick * 97 + slot;

    switch (event.kind) {
      case "chat": {
        // A response chat (#850) already has its text resolved (personalized
        // AI reply, or `chooseReplyText`'s template fallback) — post it
        // verbatim via `emitChatText`. An ambient chat pick has no entry in
        // `chatTexts` at all and keeps using `emitChat`'s own pool pick,
        // completely unchanged from before #854.
        const text = chatTexts.get(slot);
        return text !== undefined ? emitChatText(ctx, room, identity, text) : emitChat(ctx, room, identity, counter);
      }
      case "commit":
        return emitCommit(ctx, room, identity, counter);
      case "remix": {
        // Real-event target (#850) wins over a fork-of-fork upstream (#851),
        // which wins over `main`'s tip (pre-#851 default) — the three are
        // mutually exclusive on any one `PlannedEvent` per `scheduler.ts`'s
        // own contract (`response` and `remixUpstream` are never both set).
        const target = event.response?.targetIdHex ?? event.remixUpstream?.headHex ?? mainHead;
        if (!target) {
          console.warn(`[spammer] tick ${tick}: no remix target available — skipping remix (identity #${identity.index})`);
          return null;
        }
        return emitRemix(ctx, room, identity, target, counter);
      }
      case "reaction": {
        const target = event.response?.targetIdHex ?? mainHead;
        if (!target) {
          console.warn(`[spammer] tick ${tick}: no reaction target available — skipping reaction (identity #${identity.index})`);
          return null;
        }
        return emitReaction(ctx, room, identity, target, counter);
      }
    }
  }

  /**
   * Resolve the post TEXT for every response-chat event (`event.kind ===
   * "chat" && event.response`, issue #850) in `events`, BEFORE `emitBatch`'s
   * concurrent `Promise.allSettled` emit step. Deliberately sequential (not
   * folded into `emitOne`'s per-event concurrency): personalization spends a
   * SHARED, DO-storage-persisted budget ledger (`reply-budget.ts`), and two
   * response chats resolving concurrently against the same in-memory
   * `LedgerState` value could both pass `canPersonalize` and double-spend
   * before either one's `recordCall` gets persisted. Resolving in order, one
   * `ledger` variable threaded through the loop, makes "checked ⇒ spent"
   * hold for the ledger the same way `scheduler.ts`'s floor arrays already
   * make it hold for identities (see `alarm()`'s "persist BEFORE emitting"
   * comment for the parallel).
   *
   * Personalization requires BOTH `env.AI_REPLY_PERSONALIZATION === "true"`
   * (opt-in, default unset — mirrors `AI_CONTENT_AUTO_REFRESH`'s posture,
   * and #855's rollout: zero budget granted until the template pipeline is
   * proven) AND `canPersonalize(ledger, now)` (the hard daily budget/spacing
   * gate). `recordCall` is applied ONLY when `generatePersonalizedReply`
   * returns non-null — it never throws (see its own doc comment) but DOES
   * legitimately return `null` on a quota/network/validation failure, which
   * must fall back to `chooseReplyText` WITHOUT spending budget on a call
   * that produced nothing usable. The ledger is read from (and, if touched,
   * written back to) storage at most once per tick, and only if
   * personalization was actually attempted — an unset flag or an
   * already-exhausted budget never touches storage for this at all.
   */
  private async resolveChatTexts(
    ctx: EmitContext,
    events: PlannedEvent[],
    tick: number,
    now: number,
  ): Promise<Map<number, string>> {
    const texts = new Map<number, string>();
    let ledger: LedgerState | null = null;

    for (let slot = 0; slot < events.length; slot++) {
      const event = events[slot]!;
      if (event.kind !== "chat" || !event.response) continue;

      const counter = tick * 97 + slot;
      let personalized: string | null = null;

      if (this.env.AI_REPLY_PERSONALIZATION === "true") {
        ledger ??= await this.loadReplyLedger(now);
        if (canPersonalize(ledger, now)) {
          const request: PersonalizedReplyEvent = {
            shortHash: event.response.targetIdHex.slice(0, REPLY_SHORT_HEX_LEN),
            shortAuthor: event.response.realAuthorPubkeyHex.slice(0, REPLY_SHORT_HEX_LEN),
            branch: event.response.ref === MAIN_REF ? undefined : event.response.ref,
          };
          personalized = await generatePersonalizedReply(this.env.AI, request);
          if (personalized !== null) ledger = recordCall(ledger, now);
        }
      }

      texts.set(slot, personalized ?? chooseReplyText(ctx.contentPools, event.response, counter));
    }

    if (ledger !== null) await this.ctx.storage.put("replyBudgetLedger", ledger);
    return texts;
  }

  /**
   * The poll-and-diff half of the responder (#854): list every ref, page
   * `list_commits` only for the ones {@link refsNeedingFetch} says moved
   * (or are new), hand the result to `observer.ts`'s pure `observe`, and
   * enqueue a response bundle (`scheduler.ts`'s `enqueueResponseBundle`) for
   * each real event it detected. ALL the decidable logic here — which refs
   * to fetch, how to trim/cap each page, which authors are synthetic, the
   * diff itself, bundle composition — lives in `responder.ts`/`observer.ts`/
   * `scheduler.ts`; this method is pure I/O sequencing.
   */
  private async pollAndEnqueueResponses(
    wasm: WasmApi,
    pool: Identity[],
    watermark: ObserverWatermark,
    state: SchedulerState,
    now: number,
  ): Promise<{ watermark: ObserverWatermark; state: SchedulerState }> {
    const room = this.env.ROOM;

    const rawRefs = (await wasm.repo.list_refs(this.env.REPO_BASE_URL, room, "")) as RawRefEntry[];
    const refs: RefEntry[] = rawRefs.map((r) => ({ name: r.name, headHex: r.objectIdHex }));

    const fetchedCommitPagesByRef: Record<string, CommitMeta[]> = {};
    for (const ref of refsNeedingFetch(watermark, refs)) {
      const page = (await wasm.repo.list_commits(
        this.env.REPO_BASE_URL,
        room,
        ref.name,
        "",
        COMMIT_PAGE_SIZE,
      )) as RawCommitsPage;
      fetchedCommitPagesByRef[ref.name] = page.commits;
    }

    const snapshot = buildSnapshot(refs, fetchedCommitPagesByRef, watermark);
    const syntheticPubkeys = mergedSyntheticPubkeys(pool, this.env.RESPONDER_NONHUMAN_ALLOWLIST);
    const { realEvents, nextWatermark } = observe(watermark, snapshot, syntheticPubkeys);

    // `RealEvent` (observer.ts) and `RealEventRef` (scheduler.ts) are the
    // SAME shape by design — #849 and #850 were built as independent,
    // parallel-buildable modules (see scheduler.ts's `RealEventRef` doc
    // comment) that #854 is what reconciles; passing one where the other is
    // typed needs no adapter.
    let nextState = state;
    for (const event of realEvents) {
      nextState = enqueueResponseBundle(nextState, event, now);
    }

    return { watermark: nextWatermark, state: nextState };
  }

  private async loadObserverWatermark(): Promise<ObserverWatermark> {
    return (await this.ctx.storage.get<ObserverWatermark>("observerWatermark")) ?? initialObserverWatermark();
  }

  private async loadReplyLedger(now: number): Promise<LedgerState> {
    return (await this.ctx.storage.get<LedgerState>("replyBudgetLedger")) ?? initialLedgerState(now);
  }

  // -------------------------------------------------------------------------
  // SQLite-backed floor bookkeeping
  // -------------------------------------------------------------------------

  private async loadSchedulerState(): Promise<SchedulerState> {
    const rows = this.ctx.storage.sql
      .exec<FloorRow>("SELECT identity_index, last_chat_ms, last_push_ms, last_reaction_ms FROM identity_floors")
      .toArray();

    const lastChatMs = new Array<number | undefined>(POOL_SIZE).fill(undefined);
    const lastPushMs = new Array<number | undefined>(POOL_SIZE).fill(undefined);
    const lastReactionMs = new Array<number | undefined>(POOL_SIZE).fill(undefined);
    for (const row of rows) {
      if (row.identity_index < 0 || row.identity_index >= POOL_SIZE) continue; // stale row from a shrunk pool — ignore
      lastChatMs[row.identity_index] = row.last_chat_ms ?? undefined;
      lastPushMs[row.identity_index] = row.last_push_ms ?? undefined;
      lastReactionMs[row.identity_index] = row.last_reaction_ms ?? undefined;
    }

    const meta = (await this.ctx.storage.get<SchedulerMeta>("schedulerMeta")) ?? DEFAULT_SCHEDULER_META;
    return { lastChatMs, lastPushMs, lastReactionMs, ...meta };
  }

  /** Targeted per-event upsert: touches ONLY the column for that event's category, never clobbering the other two floors on the same row. */
  private persistFloors(events: PlannedEvent[], now: number): void {
    for (const event of events) {
      const column =
        event.kind === "chat" ? "last_chat_ms" : event.kind === "reaction" ? "last_reaction_ms" : "last_push_ms";
      // `column` is one of exactly three hardcoded literals chosen above by
      // our own switch — never externally supplied — so string-building the
      // column name here carries no injection risk.
      this.ctx.storage.sql.exec(
        `INSERT INTO identity_floors (identity_index, ${column}) VALUES (?, ?)
         ON CONFLICT(identity_index) DO UPDATE SET ${column} = excluded.${column}`,
        event.identityIndex,
        now,
      );
    }
  }

  private async persistSchedulerMeta(state: SchedulerState): Promise<void> {
    const meta: SchedulerMeta = {
      chatCursor: state.chatCursor,
      pushCursor: state.pushCursor,
      reactionCursor: state.reactionCursor,
      tick: state.tick,
      // Round-trip #850/#851's optional response-scheduling fields the SAME
      // way the cursors/tick counter already round-trip — see this class's
      // top storage-layout comment and `SchedulerMeta`'s own doc comment.
      responseQueue: state.responseQueue,
      lastBundleMsByAuthor: state.lastBundleMsByAuthor,
      reactionIdentitiesByBundle: state.reactionIdentitiesByBundle,
    };
    await this.ctx.storage.put("schedulerMeta", meta);
  }
}
