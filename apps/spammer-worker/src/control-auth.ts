// Pure `/control` auth + action-resolution helpers, split out of spammer.ts.
//
// spammer.ts imports `cloudflare:workers` (the `DurableObject` base class),
// which only resolves inside the real Workers runtime — that pulls any
// plain-Node unit test importing anything from spammer.ts into needing the
// full `@cloudflare/vitest-pool-workers` "integration" project, even for
// logic as simple as a string comparison. These four functions touch no DO
// state and no `cloudflare:workers` import, so they live here instead and are
// unit-testable (and v8-coverage-measurable) in plain Node — same reasoning
// as scheduler.ts's separation from spammer.ts.

export function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Constant-time string comparison — avoids leaking `CONTROL_TOKEN` via a
 * length/prefix timing oracle on the `/control` auth check. A length mismatch
 * still short-circuits (unavoidable without padding to a fixed size, and not
 * worth it here: length alone reveals nothing usable about the token).
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  if (aBytes.length !== bBytes.length) return false;
  let diff = 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i]! ^ bBytes[i]!;
  return diff === 0;
}

/**
 * `true` only for a well-formed `Authorization: Bearer <token>` header whose
 * token matches `expected`. `expected` being `undefined` (the `CONTROL_TOKEN`
 * secret was never set) always returns `false` — an unset secret fails every
 * `/control` call closed, never open (see wrangler.jsonc's own comment).
 */
export function isAuthorized(request: Request, expected: string | undefined): boolean {
  if (!expected) return false;
  const header = request.headers.get("Authorization") ?? "";
  const match = /^Bearer (.+)$/.exec(header);
  if (!match) return false;
  return timingSafeEqual(match[1]!, expected);
}

/**
 * The requested `/control` action: the `?action=` query param wins if
 * present; otherwise a POST body of `{"action": "..."}` is tried; anything
 * else (a bare GET, an unparsable body) defaults to `"status"` — a plain-GET
 * status check needs no body at all.
 */
export async function resolveAction(request: Request, url: URL): Promise<string> {
  const fromQuery = url.searchParams.get("action");
  if (fromQuery) return fromQuery;
  if (request.method === "POST") {
    try {
      const body: unknown = await request.clone().json();
      if (body && typeof body === "object" && typeof (body as Record<string, unknown>).action === "string") {
        return (body as Record<string, unknown>).action as string;
      }
    } catch {
      // No/invalid JSON body — fall through to the "status" default below.
    }
  }
  return "status";
}
