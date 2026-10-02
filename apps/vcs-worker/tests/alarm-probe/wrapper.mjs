// SPDX-License-Identifier: MIT OR Apache-2.0
// Exercise bounded continuations on the real Rust driver and workerd clock.
import {RefStore} from '../../build/worker/shim.mjs';
export * from '../../build/worker/shim.mjs';

const encode = value => btoa(String.fromCharCode(...value));
const utf8 = value => new TextEncoder().encode(value);
const part = encode(utf8('nroot\0'));
const TIMER_COUNT = 65;

export class AlarmProbe extends RefStore {
  constructor(state, env) {
    const fault = {active: false, injected: 0, rejected: 0};
    const storage = new Proxy(state.storage, {
      get(target, key) {
        if (key === `${env.FAIL_SCHEDULE}Alarm`) {
          return (...args) => {
            if (fault.active && fault.injected === 0) {
              fault.injected++;
              return Promise.reject(new Error('injected alarm scheduling failure'));
            }
            return target[key](...args);
          };
        }
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      }
    });
    const wrapped = new Proxy(state, {
      get(target, key) {
        if (key === 'storage') return storage;
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      }
    });
    super(wrapped, env);
    this.fault = fault;
    this.storage = state.storage;
    this.ticks = [];
  }

  async call(call) {
    const response = await super.fetch(new Request('https://alarm-probe.invalid/kv', {
      method: 'POST', body: JSON.stringify({part, call})
    }));
    const result = await response.json();
    if (result.reply === 'err') throw new Error(JSON.stringify(result));
    return result;
  }

  async alarm() {
    const tick = {now: Date.now()};
    this.ticks.push(tick);
    this.fault.active = true;
    try {
      await super.alarm();
    } catch (error) {
      tick.failed = true;
      this.fault.rejected++;
      throw error;
    } finally {
      this.fault.active = false;
    }
    tick.next = await this.storage.getAlarm();
    const state = await this.probeState();
    if (state.remaining === 0 && state.ticks.length >= 3) {
      this.complete(state);
    }
  }

  async fetch(request) {
    if (request.method === 'POST') {
      if (this.completion) throw new Error('fixture already started');
      // Install completion before the committing Apply can arm the first tick.
      this.completion = new Promise(resolve => { this.complete = resolve; });
      const due = Date.now() + 100;
      const writes = [];
      for (let i = 0; i < TIMER_COUNT; i++) {
        const reference = utf8(`default\0refs/heads/alarm-probe/${i}`);
        const key = new Uint8Array(11 + reference.length);
        key.set([119, 0]); // Existing w\0 <due:be64> <kind:u8> <reference>.
        new DataView(key.buffer).setBigUint64(2, BigInt(due));
        key[10] = 255; // Existing ref-deleting test timer, test-faults only.
        key.set(reference, 11);
        writes.push({kind: 'put', key: encode(key), value: ''});
      }
      const result = await this.call({op: 'apply', batch: {preconditions: [], writes}});
      if (result.reply !== 'outcome' || result.outcome.outcome !== 'committed') {
        throw new Error(`fixture did not commit: ${JSON.stringify(result)}`);
      }
      return Response.json({seeded: TIMER_COUNT, due});
    }
    if (new URL(request.url).pathname.endsWith('/state')) {
      return Response.json(await this.probeState());
    }
    if (!this.completion) throw new Error('fixture has not started');
    // Await a single completion notification without repeated requests/scans
    // competing with the object's input and storage gates during each tick.
    return Response.json(await this.completion);
  }

  async probeState() {
    const result = await this.call({op: 'scan', start: encode(utf8('w\0')),
      end: encode(utf8('w\x01')), after: null, limit: 128});
    if (result.reply !== 'page' || result.next !== null) {
      throw new Error(`unexpected timer scan: ${JSON.stringify(result)}`);
    }
    const remaining = result.entries.filter(([key]) => atob(key).charCodeAt(10) === 255).length;
    return {fault: this.fault, remaining, ticks: this.ticks, alarm: await this.storage.getAlarm()};
  }
}

export default {
  fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (!/^\/fixture-[0-9]+(?:\/state)?$/.test(path)) return new Response('ready');
    const id = path.split('/')[1];
    return env.ALARM_PROBE.get(env.ALARM_PROBE.idFromName(id)).fetch(request);
  }
};
