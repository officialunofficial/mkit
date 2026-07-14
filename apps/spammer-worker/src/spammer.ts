// The `Spammer` Durable Object (PLAN.md build step 8).
//
// One singleton instance owns the whole synthetic-activity loop: a
// self-rescheduling `alarm()` that, once every ~1000 ms, asks `scheduler.ts`
// for this tick's batch, emits it concurrently via `events.ts`, and records
// the resulting per-identity floors — plus the `/control` surface
// (enable/disable/status) that is the ONLY way to turn any of this on.
//
// DORMANT BY DEFAULT: a freshly-created instance has never had `enabled` set,
// so `(await storage.get("enabled")) ?? false` is `false` and `alarm()`
// no-ops without rescheduling itself even if one somehow fired. The DO never
// arms its own first alarm — only an authenticated `POST /control` (action
// "enable") does that (see `ensureAlarmScheduled`).
//
// Storage layout (DO SQLite, `new_sqlite_classes` migration in
// wrangler.jsonc):
//   - `identity_floors` SQL table — per-identity `last_chat_ms`/`last_push_ms`/
//     `last_reaction_ms` (PLAN.md's floor bookkeeping the scheduler needs).
//   - `ctx.storage` KV keys `"enabled"` (boolean) and `"schedulerMeta"` (the
//     scheduler's round-robin cursors + tick counter) — small, non-relational
//     bookkeeping that doesn't warrant its own table; the KV API is backed by
//     the SAME SQLite storage the `new_sqlite_classes` migration provisions,
//     so this is still "SQLite-backed" underneath, and — unlike a plain
//     in-memory field — survives an isolate eviction between ticks.

import { DurableObject } from "cloudflare:workers";
import { refreshContentPools, type ContentPools } from "./ai-content";
import { isAuthorized, jsonResponse, resolveAction } from "./control-auth";
import { emitChat, emitCommit, emitReaction, emitRemix, MAIN_REF, type EmitContext } from "./events";
import { getIdentityPool, POOL_SIZE, type Identity } from "./identities";
import { planTick, type PlannedEvent, type SchedulerState } from "./scheduler";
import { getWasm } from "./wasm";

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS identity_floors (
    identity_index INTEGER PRIMARY KEY,
    last_chat_ms INTEGER,
    last_push_ms INTEGER,
    last_reaction_ms INTEGER
  )
`;

/** The scheduler's round-robin cursors + tick counter — everything `SchedulerState` needs beyond the per-identity floor arrays. */
type SchedulerMeta = {
  chatCursor: number;
  pushCursor: number;
  reactionCursor: number;
  tick: number;
};

const DEFAULT_SCHEDULER_META: SchedulerMeta = { chatCursor: 0, pushCursor: 0, reactionCursor: 0, tick: 0 };

/** How long an alarm tick waits before rescheduling itself — PLAN.md's "Alarm interval: 1000 ms". */
const ALARM_INTERVAL_MS = 1000;

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

export type ControlStatus = { enabled: boolean; room: string; poolSize: number };

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
    return { enabled: await this.isEnabled(), room: this.env.ROOM, poolSize: POOL_SIZE };
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
      const state = await this.loadSchedulerState();
      const now = Date.now();
      const { events, nextState } = planTick(state, now);

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
      if (nextState.tick % CONTENT_REFRESH_EVERY_N_TICKS === 0) {
        this.ctx.waitUntil(this.refreshContentPoolsInBackground());
      }

      if (events.length > 0) {
        const contentPools = await this.ctx.storage.get<ContentPools>(CONTENT_POOLS_STORAGE_KEY);
        const ctx: EmitContext = { wasm, baseUrl: this.env.REPO_BASE_URL, contentPools };
        await this.emitBatch(ctx, pool, events, nextState.tick);
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

  private async emitBatch(ctx: EmitContext, pool: Identity[], events: PlannedEvent[], tick: number): Promise<void> {
    const room = this.env.ROOM;

    // "remix" and "reaction" both need something real to point at; fetch the
    // current `main` head at most once per tick, shared by both kinds.
    const needsMainHead = events.some((e) => e.kind === "remix" || e.kind === "reaction");
    const mainHead = needsMainHead ? ((await ctx.wasm.repo.get_ref(ctx.baseUrl, room, MAIN_REF)) ?? null) : null;

    const results = await Promise.allSettled(
      events.map((event, slot) => this.emitOne(ctx, room, pool, event, tick, slot, mainHead)),
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
  ): Promise<unknown> {
    const identity = pool[event.identityIndex];
    if (!identity) throw new Error(`[spammer] no identity at pool index ${event.identityIndex}`);
    // Deterministic per-(tick, slot) counter — enough variety that the two
    // chat picks (or any two same-kind picks) in one tick never select the
    // identical content-pool phrase; see content.ts's `pick`.
    const counter = tick * 97 + slot;

    switch (event.kind) {
      case "chat":
        return emitChat(ctx, room, identity, counter);
      case "commit":
        return emitCommit(ctx, room, identity, counter);
      case "remix":
        if (!mainHead) {
          console.warn(`[spammer] tick ${tick}: no main head yet — skipping remix (identity #${identity.index})`);
          return null;
        }
        return emitRemix(ctx, room, identity, mainHead, counter);
      case "reaction":
        if (!mainHead) {
          console.warn(`[spammer] tick ${tick}: no main head yet — skipping reaction (identity #${identity.index})`);
          return null;
        }
        return emitReaction(ctx, room, identity, mainHead, counter);
    }
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
    };
    await this.ctx.storage.put("schedulerMeta", meta);
  }
}
