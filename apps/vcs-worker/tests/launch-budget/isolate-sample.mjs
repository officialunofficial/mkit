// Local inspector only. Sampled retention evidence; never a complete peak claim.
// node isolate-sample.mjs <inspector port> <output.json> <stop-file>
import {writeFile, access} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
const [port, output, stop] = process.argv.slice(2);
if (!/^\d+$/.test(port || '') || !output || !stop) throw Error('three arguments required');
const {default: WebSocket} = await import(process.env.MKIT_PROBE_WS_MODULE ?? 'ws');
const deadline = Date.now() + 30 * 60 * 1000;
const clients = new Map(), samples = [], gaps = [], contextEvents = [];
async function client(target) {
  const socket = new WebSocket(target.webSocketDebuggerUrl,
    {headers: {Origin: 'https://devtools.devprod.cloudflare.dev'}});
  let serial = 0;
  let generation = 0, coverageUnknown = false;
  const pending = new Map(), contexts = new Map();
  const contextEvent = (kind, context = {}) => {
    if (contextEvents.length < 100000) contextEvents.push({at: Date.now(),
      target: target.id, kind, generation, ...context});
  };
  const rejectPending = error => {
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timer);waiter.reject(error);
    }
    pending.clear();
  };
  socket.on('close', () => rejectPending(Error('inspector socket closed')));
  socket.on('error', error => rejectPending(error));
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(Error('inspector connection timeout')), 3000);
      socket.once('open', () => {clearTimeout(timer);resolve();});
      socket.once('error', error => {clearTimeout(timer);reject(error);});
      socket.once('close', () => {clearTimeout(timer);reject(Error('inspector socket closed'));});
    });
    socket.on('message', raw => {
      const message = JSON.parse(raw.toString());
      if (message.method === 'Runtime.executionContextCreated') {
        const context = message.params.context;
        generation++;
        if (!contexts.has(context.id) && contexts.size >= 16) {
          coverageUnknown = true;
          gaps.push({at: Date.now(), target: target.id, error: 'live context bound exceeded'});
        } else {
          if (contexts.has(context.id)) contextEvent('replaced', {
            id: context.id, created: contexts.get(context.id).created});
          const observed = {id: context.id, generation, created: Date.now(),
            name: String(context.name ?? '').slice(0, 180),
            origin: String(context.origin ?? '').slice(0, 180),
            default: context.auxData?.isDefault ?? null};
          contexts.set(context.id, observed);
          contextEvent('created', observed);
        }
      } else if (message.method === 'Runtime.executionContextDestroyed') {
        const id = message.params.executionContextId;
        const observed = contexts.get(id);
        contexts.delete(id);generation++;
        contextEvent('destroyed', {id, created: observed?.created ?? null});
      } else if (message.method === 'Runtime.executionContextsCleared') {
        contexts.clear();coverageUnknown = false;generation++;contextEvent('cleared');
      }
      const waiter = pending.get(message.id);
      if (waiter) {pending.delete(message.id);clearTimeout(waiter.timer);
        message.error ? waiter.reject(Error(JSON.stringify(message.error))) : waiter.resolve(message.result);}
    });
    const rpc = (method, params = {}) => new Promise((resolve, reject) => {
      const id = ++serial;
      const timer = setTimeout(() => {pending.delete(id);reject(Error('inspector RPC timeout'));}, 3000);
      pending.set(id, {resolve, reject, timer});socket.send(JSON.stringify({id, method, params}));
    });
    await rpc('Runtime.enable');
    const close = () => {generation++;contextEvent('retired');contexts.clear();
      rejectPending(Error('inspector client retired'));socket.terminate();};
    return {socket, rpc, close, contexts, generation: () => generation,
      coverageUnknown: () => coverageUnknown, url: target.webSocketDebuggerUrl, target: target.id};
  } catch (error) {
    rejectPending(error);socket.terminate();throw error;
  }
}
try {
  while (Date.now() < deadline) {
    try {await access(stop);break;} catch {}
    try {
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`,
        {signal: AbortSignal.timeout(3000)})).json();
      const enabled = targets.filter(t => t.webSocketDebuggerUrl);
      if (enabled.length > 16) gaps.push({at: Date.now(), error: "target bound exceeded", targets: enabled.length});
      const selected = enabled.slice(0, 16);
      const wanted = new Map(selected.map(target => [target.id, target.webSocketDebuggerUrl]));
      for (const [id, active] of clients) {
        if (wanted.get(id) !== active.url) {active.close();clients.delete(id);}
      }
      for (const target of selected) {
        let active = clients.get(target.id);
        if (!active) {active = await client(target);clients.set(target.id, active);}
        const started = Date.now();
        const generation = active.generation();
        try {
          const identityErrors = [];
          const identify = async () => {try {return (await active.rpc('Runtime.getIsolateId')).id ?? null;}
            catch (error) {identityErrors.push(String(error));return null;}};
          const isolateBefore = await identify();
          const heap = await active.rpc('Runtime.getHeapUsage');
          const observed = [...active.contexts.values()];
          const memories = [], memoryErrors = [], skippedContexts = [];
          for (const context of observed) {
            if (active.contexts.get(context.id) !== context) {
              skippedContexts.push(context.id);continue;
            }
            try {
              const memory = await active.rpc('Runtime.evaluate', {contextId: context.id, expression:
                '({wasm:globalThis.__mkitLaunchMemory ? globalThis.__mkitLaunchMemory() : null,budget:globalThis.__mkitLaunchBudget ? globalThis.__mkitLaunchBudget() : null})',
                returnByValue: true, timeout: 1000});
              if (memory.exceptionDetails) throw Error('numeric getter evaluation exception');
              if (active.contexts.get(context.id) !== context) throw Error('context retired during evaluation');
              memories.push({context, wasm: memory.result?.value?.wasm ?? null,
                budget: memory.result?.value?.budget ?? null});
            } catch (error) {
              memoryErrors.push({context: context.id, generation: context.generation, error: String(error)});
            }
          }
          // Retain heap even when identity or context lifetime prevents joining
          // it to the fixture's numeric getters.
          const modules = memories.filter(memory => memory.budget?.id);
          const isolateAfter = await identify();
          const isolate = isolateBefore && isolateBefore === isolateAfter ? isolateBefore : null;
          const unknownReasons = [];
          if (!isolate) unknownReasons.push('isolate identity changed or unavailable');
          if (active.coverageUnknown()) unknownReasons.push('untracked live context coverage');
          if (generation !== active.generation()) unknownReasons.push('context lifetime changed during sample');
          if (memoryErrors.length) unknownReasons.push('getter error');
          if (skippedContexts.length || memories.length !== observed.length)
            unknownReasons.push('incomplete observed context coverage');
          if (modules.length !== 1) unknownReasons.push('no unique observed module');
          const module = unknownReasons.length === 0 ? modules[0] : null;
          samples.push({started, finished: Date.now(), isolate, isolateBefore, isolateAfter, identityErrors,
            target: active.target, heap, contexts: observed, generationStarted: generation,
            generation: active.generation(), memories, memoryErrors, skippedContexts,
            memoryUnknown: !module, unknownReasons,
            wasm: module?.wasm ?? null, budget: module?.budget ?? null});
        } catch (error) {
          gaps.push({at: Date.now(), target: active.target, error: String(error)});
          active.close();clients.delete(target.id);
        }
      }
    } catch (error) {gaps.push({at: Date.now(), error: String(error)});}
    if (samples.length + gaps.length + contextEvents.length > 100000) throw Error('observation bound exceeded');
    await delay(250);
  }
} finally {
  for (const active of clients.values()) active.close();
  await writeFile(output, JSON.stringify({scope: 'sampled local CDP isolate retention',
    completePeakCertificate: false, deadlineExceeded: Date.now() >= deadline,
    samples, gaps, contextEvents}, null, 2));
}
