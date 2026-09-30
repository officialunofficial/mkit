// Runtime test wrapper only. Route one synthetic HTTPS origin to a local
// HTTP fixture so no public endpoint, credential or TLS trust override is used.
import app from '../../build/worker/shim.mjs';
export * from '../../build/worker/shim.mjs';
const originalFetch = globalThis.fetch.bind(globalThis);
const originalSet = globalThis.setTimeout.bind(globalThis);
const originalClear = globalThis.clearTimeout.bind(globalThis);
const active = new Set();
let mode, fixture, calls, aborted;
globalThis.setTimeout = (callback, delay, ...args) => {
  const handle = originalSet(() => { active.delete(handle); callback(...args); }, delay);
  active.add(handle);
  return handle;
};
globalThis.clearTimeout = (handle) => { active.delete(handle); originalClear(handle); };
globalThis.fetch = (request, init) => {
  if (new URL(request.url).hostname !== 'hook-probe.invalid') return originalFetch(request, init);
  calls++;
  if (request.redirect !== 'manual') throw new Error('hook redirects must be manual');
  init.signal.addEventListener('abort', () => { aborted++; }, {once: true});
  return originalFetch(new Request(`${fixture}/${mode}`, request), init);
};
export default {
  async fetch(request, env, ctx) {
    mode = new URL(request.url).searchParams.get('mode') || 'stall';
    fixture = env.HOOK_PROBE_ORIGIN;
    calls = aborted = 0;
    const response = await new app(ctx, env).fetch(request);
    const result = await response.json();
    return Response.json({...result, calls, aborted, activeTimers: active.size});
  }
};
