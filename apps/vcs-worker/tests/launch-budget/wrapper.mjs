// Fixture only: observe the unchanged release module's host calls and bodies.
import memorySnapshot from './memory.mjs';
import {WorkerEntrypoint} from 'cloudflare:workers';
import {AsyncLocalStorage} from 'node:async_hooks';
import Release, * as classes from '__RELEASE_SHIM__';

const als = new AsyncLocalStorage();
let serial = 0;
const originalFetch = globalThis.fetch.bind(globalThis);
// Optional fixture-only signed HTTPS receiver mapping. Ordinary budget runs
// leave this literal unchanged and do not configure a signed receiver.
const receiver = '__RECEIVER_ORIGIN__';
const PREFIX = 'MKIT_LAUNCH_BUDGET ';
const isolate = {id: null, outgoing: 0, outgoingPeak: 0,
  active: 0, activePeak: 0, cacheCalls: 0, unattributedCache: 0, cacheObserved: false};
Object.defineProperty(globalThis, '__mkitLaunchBudget', {value: () => ({
  at: Date.now(), ...isolate, wasmMemory: memorySnapshot()})});
const counters = () => ({doFetch: 0, r2: 0, hookFetch: 0, bindingFetch: 0, cache: 0,
  sqlStatements: 0, sqlPending: 0, sqlRowsRead: 0, sqlRowsWritten: 0,
  timerWindows: 0, timerWindowRows: 0, timerWindowRowsMax: 0,
  outgoing: 0, outgoingPeak: 0, cancelled: 0, streamBytes: 0, errors: 0});
const owner = () => ({active: 0, group: null});

function begin(holder, kind, name, path = '') {
  isolate.id ||= crypto.randomUUID();
  if (!holder.active) holder.group = {id: ++serial, counters: counters(), alarms: 0,
    invocations: 0, requests: 0, overlap: false, failed: false};
  const group = holder.group;
  group.overlap ||= holder.active > 0;
  holder.active++;
  isolate.active++;
  isolate.activePeak = Math.max(isolate.activePeak, isolate.active);
  group.invocations++;
  group.alarms += Number(kind === 'alarm');
  group.requests += Number(kind === 'request' || kind === 'fetch');
  return {id: ++serial, holder, group, kind, name, path: path.slice(0, 180),
    method: '', status: null, returned: false, waits: 0, body: 0,
    emitted: false, error: false};
}

function finish(scope) {
  if (scope.emitted || !scope.returned || scope.waits || scope.body) return;
  scope.emitted = true;
  scope.holder.active--;
  isolate.active--;
  const final = scope.holder.active === 0;
  const c = scope.group.counters;
  scope.group.failed ||= scope.error;
  console.log(PREFIX + JSON.stringify({scope: scope.id, group: scope.group.id,
    kind: scope.kind, class: scope.name, path: scope.path,
    method: scope.method, status: scope.status,
    groupFinal: final, groupInvocations: scope.group.invocations,
    groupAlarms: scope.group.alarms, groupRequests: scope.group.requests,
    overlap: scope.group.overlap,
    // Rust's shared task queue has no demonstrated per-task ALS propagation.
    // Persistent DOs deliberately report conservative overlapping group totals.
    attribution: scope.kind === 'request' ? 'request-env' : 'conservative-do-group',
    exactRustOverlapAttribution: false,
    complete: final && c.outgoing === 0 && c.sqlPending === 0,
    isolate: {...isolate}, wasmMemory: memorySnapshot(),
    handlerError: scope.group.failed, ...c}));
}

function waitContext(context, scope) {
  return hostProxy(context, (target, key) => {
    if (key !== 'waitUntil') return undefined;
    return promise => {
      scope.waits++;
      const observed = Promise.resolve(promise).then(
        value => { scope.waits--; finish(scope); return value; },
        error => { scope.waits--; scope.error = true; finish(scope); throw error; });
      return target.waitUntil(observed);
    };
  });
}

function hostProxy(target, special) {
  return new Proxy(target, {get(target, key) {
    const wrapped = special(target, key);
    if (wrapped !== undefined) return wrapped;
    const value = Reflect.get(target, key, target);
    // EnvBinding checks constructor.name; never bind or replace constructor.
    return typeof value === 'function' && key !== 'constructor' ? value.bind(target) : value;
  }});
}

function current(holder, fixed) {
  // Fresh incoming-request Env proxies retain their request scope directly.
  // DO bindings are shared, so all overlapping events share one conservative
  // group until their response bodies and waitUntil promises have completed.
  return fixed ? fixed.group : holder.group;
}

function token(group, category) {
  if (!group) throw new Error('budget call outside an observed invocation');
  const c = group.counters;
  c[category]++;
  c.outgoing++;
  isolate.outgoing++;
  isolate.outgoingPeak = Math.max(isolate.outgoingPeak, isolate.outgoing);
  c.outgoingPeak = Math.max(c.outgoingPeak, c.outgoing);
  let ended = false;
  return {group, close(error = false, cancelled = false) {
    if (ended) return;
    ended = true;
    c.outgoing--;
    isolate.outgoing--;
    c.errors += Number(error);
    c.cancelled += Number(cancelled);
  }};
}

function trackedStream(body, done, group) {
  const reader = body.getReader();
  let ended = false, cancelling = false;
  const close = (error, cancelled) => {
    if (!ended) { ended = true; done(error, cancelled); reader.releaseLock(); }
  };
  return new ReadableStream({
    async pull(controller) {
      try {
        const piece = await reader.read();
        // Cancellation may resolve a concurrent read. Its cancel callback owns
        // completion, and a cancelled controller must not be closed again.
        if (ended || cancelling) return;
        if (piece.done) { close(false, false); controller.close(); }
        else { group.counters.streamBytes += piece.value.byteLength; controller.enqueue(piece.value); }
      } catch (error) {
        if (!ended && !cancelling) { close(true, false); controller.error(error); }
      }
    },
    async cancel(reason) {
      cancelling = true;
      try { await reader.cancel(reason); close(false, true); }
      catch (error) { close(true, true); throw error; }
    },
  }, {highWaterMark: 0});
}

function response(result, held) {
  if (!result.body) { held.close(); return result; }
  return new Response(trackedStream(result.body, (e, c) => held.close(e, c), held.group), result);
}

async function outgoing(group, category, call, type = 'response') {
  const held = token(group, category);
  try {
    const result = await call();
    if (type === 'response') {
      if (!result) {held.close(); return result;}
      return response(result, held);
    }
    if (type !== 'r2-get' || !result || !result.body) { held.close(); return result; }
    let stream;
    return hostProxy(result, (target, key) => {
      if (key === 'body') {
        stream ||= trackedStream(target.body, (e, c) => held.close(e, c), group);
        return stream;
      }
      if (['arrayBuffer', 'text', 'json'].includes(key)) return async (...args) => {
        try { const data = await target[key](...args); held.close(); return data; }
        catch (error) { held.close(true); throw error; }
      };
      return undefined;
    });
  } catch (error) { held.close(true); throw error; }
}

function instrumentEnv(env, holder, fixed) {
  const cache = new Map(); // One entry for each of the finite deployment bindings.
  return hostProxy(env, (target, name) => {
    const value = Reflect.get(target, name, target);
    const kind = value?.constructor?.name;
    if (!['DurableObjectNamespace', 'R2Bucket', 'Fetcher'].includes(kind)) return undefined;
    if (cache.has(name)) return cache.get(name);
    const wrapped = hostProxy(value, (binding, key) => {
      const group = () => current(holder, fixed);
      if (kind === 'DurableObjectNamespace' && key === 'get') return (...args) =>
        hostProxy(binding.get(...args), (stub, method) => method === 'fetch' ? (...args) =>
          outgoing(group(), 'doFetch', () => stub.fetch(...args)) : undefined);
      if (kind === 'Fetcher' && key === 'fetch') return (...args) =>
        outgoing(group(), 'bindingFetch', () => binding.fetch(...args));
      if (kind === 'R2Bucket') {
        if (['head', 'get', 'put', 'delete', 'list', 'createMultipartUpload'].includes(key))
          return async (...args) => {
            const result = await outgoing(group(), 'r2', () => binding[key](...args),
              key === 'get' ? 'r2-get' : 'value');
            return key === 'createMultipartUpload' ? upload(result, group) : result;
          };
        // resumeMultipartUpload is a synchronous handle construction, not I/O.
        if (key === 'resumeMultipartUpload') return (...args) => upload(binding[key](...args), group);
      }
      return undefined;
    });
    cache.set(name, wrapped);
    return wrapped;
  });
}

function upload(value, group) {
  return hostProxy(value, (target, key) => ['uploadPart', 'complete', 'abort'].includes(key) ?
    (...args) => outgoing(group(), 'r2', () => target[key](...args), 'value') : undefined);
}

function sqlStorage(sql, holder) {
  return hostProxy(sql, (target, key) => key === 'exec' ? (statement, ...args) => {
    const group = holder.group;
    if (!group) throw new Error('SQL outside observed invocation');
    group.counters.sqlStatements++;
    let cursor;
    try { cursor = target.exec(statement, ...args); }
    catch (error) { group.counters.errors++; throw error; }
    group.counters.sqlPending++;
    const timer = statement.includes('INDEXED BY kv_timers');
    if (timer) group.counters.timerWindows++;
    let rows = 0, finished = false;
    const row = () => {
      rows++;
      if (timer) { group.counters.timerWindowRows++;
        group.counters.timerWindowRowsMax = Math.max(group.counters.timerWindowRowsMax, rows); }
    };
    const done = () => {
      if (finished) return;
      finished = true;
      const c = group.counters;
      c.sqlPending--;
      c.sqlRowsRead += cursor.rowsRead;
      c.sqlRowsWritten += cursor.rowsWritten;
    };
    return hostProxy(cursor, (cursor, method) => {
      if (method === 'raw') return () => {
        const iterator = cursor.raw();
        let observed;
        observed = hostProxy(iterator, (iterator, key) => {
          // js-sys try_iter calls Symbol.iterator before next. Returning the
          // native target there would silently bypass the observing next.
          if (key === Symbol.iterator) return () => observed;
          if (key === 'next') return (...args) => {
            const result = iterator.next(...args);
            if (result.done) done(); else row();
            return result;
          };
          return undefined;
        });
        return observed;
      };
      if (method === 'next') return (...args) => {
        const result = cursor.next(...args);
        if (result.done) done(); else row();
        return result;
      };
      if (method === 'toArray') return () => { const result = cursor.toArray();
        for (let i = 0; i < result.length; i++) row();
        done(); return result; };
      return undefined;
    });
  } : undefined);
}

function instrumentState(state, holder) {
  let storage, sql;
  return hostProxy(state, (target, key) => {
    if (key === 'storage') {
      storage ||= hostProxy(target.storage, (target, key) => {
        if (key === 'sql') { sql ||= sqlStorage(target.sql, holder); return sql; }
        return undefined;
      });
      return storage;
    }
    if (key === 'waitUntil') return promise => {
      const scope = als.getStore();
      if (!scope || scope.holder !== holder) throw new Error('unattributed DO waitUntil');
      return waitContext(target, scope).waitUntil(promise);
    };
    return undefined;
  });
}

async function invoke(scope, call) {
  return als.run(scope, async () => {
    try {
      const result = await call();
      if (result instanceof Response) scope.status = result.status;
      if (result instanceof Response && result.body) {
        scope.body++;
        return new Response(trackedStream(result.body, (error) => {
          scope.error ||= error; scope.body--; finish(scope);
        }, scope.group), result);
      }
      return result;
    } catch (error) { scope.error = true; throw error; }
    finally { scope.returned = true; finish(scope); }
  });
}

function durable(Base, name) {
  return class extends Base {
    constructor(state, env) {
      const holder = owner();
      // Constructor-time SQL work belongs to a separate conservative scope.
      const scope = begin(holder, 'constructor', name);
      super(instrumentState(state, holder), instrumentEnv(env, holder));
      this.budgetOwner = holder;
      scope.returned = true;
      finish(scope);
    }
    fetch(request) {
      return invoke(begin(this.budgetOwner, 'fetch', name, new URL(request.url).pathname),
        () => super.fetch(request));
    }
    alarm(...args) {
      return invoke(begin(this.budgetOwner, 'alarm', name), () => super.alarm(...args));
    }
  };
}

export const RefStore = durable(classes.RefStore, 'RefStore');
export const NsCoordinator = durable(classes.NsCoordinator, 'NsCoordinator');
export const RefShard = durable(classes.RefShard, 'RefShard');
export const RepoIndexShard = durable(classes.RepoIndexShard, 'RepoIndexShard');
export const ContentIndexShard = durable(classes.ContentIndexShard, 'ContentIndexShard');

// Cache bodies and promises join the same isolate-wide outgoing lifetime.
// Task ALS attribution remains explicitly approximate; missed scopes are counted.
if (globalThis.caches) {
  const nativeCaches = globalThis.caches;
  const observed = new WeakMap();
  const cache = value => {
    if (!observed.has(value)) observed.set(value, hostProxy(value, (target, key) => {
      if (!['match', 'put', 'delete'].includes(key)) return undefined;
      return (...args) => {
        isolate.cacheCalls++;
        const scope = als.getStore();
        if (scope) return outgoing(scope.group, 'cache', () => target[key](...args),
          key === 'match' ? 'response' : 'value');
        isolate.unattributedCache++;
        isolate.outgoing++;
        isolate.outgoingPeak = Math.max(isolate.outgoingPeak, isolate.outgoing);
        let ended = false;
        const close = () => {if (!ended) {ended = true; isolate.outgoing--;}};
        return Promise.resolve().then(() => target[key](...args)).then(result => {
          if (key === 'match' && result?.body) return new Response(
            trackedStream(result.body, close, {counters: counters()}), result);
          close(); return result;
        }, error => {close(); throw error;});
      };
    }));
    return observed.get(value);
  };
  const wrapped = hostProxy(nativeCaches, (target, key) => {
    if (key === 'default') return cache(target.default);
    if (key === 'open') return async (...args) => cache(await target.open(...args));
    return undefined;
  });
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'caches');
  if (!descriptor || descriptor.configurable || descriptor.writable) {
    Object.defineProperty(globalThis, 'caches', descriptor?.configurable === false
      ? {value: wrapped} : {value: wrapped, configurable: true});
    isolate.cacheObserved = true;
  }
}

globalThis.fetch = (...args) => {
  const scope = als.getStore();
  if (!scope) throw new Error('Fetch outside observed invocation');
  return outgoing(scope.group, 'hookFetch', () => {
    if (receiver.startsWith('__')) return originalFetch(...args);
    const [input, init] = args;
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    if (url.origin !== 'https://inspection.launch.invalid') return originalFetch(...args);
    if (request.redirect !== 'manual') throw new Error('signed hook must refuse redirects');
    return originalFetch(new Request(receiver + url.pathname, request), init);
  });
};

export default class extends WorkerEntrypoint {
  fetch(request) {
    const scope = begin(owner(), 'request', 'Entrypoint', new URL(request.url).pathname);
    scope.method = request.method;
    return invoke(scope, () => new Release(waitContext(this.ctx, scope),
      instrumentEnv(this.env, scope.holder, scope)).fetch(request));
  }
}
