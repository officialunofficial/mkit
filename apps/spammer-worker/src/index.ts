// Worker entry for `mkit-spammer`.
//
// Routes `/control` (any method/action — see `spammer.ts`'s own auth +
// action dispatch) to the singleton `Spammer` Durable Object by forwarding
// the request as-is (`stub.fetch(request)`); everything else, including
// `/health`, is answered directly by this Worker without touching the DO —
// `/health` needs no `CONTROL_TOKEN` and reveals nothing about spammer
// state, it just proves the Worker deployed and is routable.
//
// The DO name is a fixed literal ("singleton") rather than derived from the
// request: PLAN.md's design is exactly one `Spammer` instance for the whole
// Worker (one room, one alarm loop, one identity pool) — `getByName` with a
// constant name is what makes every request land on that same instance.
//
// This Worker NEVER arms anything on its own: the only way any alarm gets
// scheduled is an authenticated `POST /control` (action "enable") reaching
// `spammer.ts`'s `fetch` handler through the forward below.

export { Spammer } from "./spammer";

const SPAMMER_INSTANCE_NAME = "singleton";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return new Response("ok", { status: 200 });
    }

    if (url.pathname.startsWith("/control")) {
      const stub = env.SPAMMER.getByName(SPAMMER_INSTANCE_NAME);
      return stub.fetch(request);
    }

    return new Response("not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
