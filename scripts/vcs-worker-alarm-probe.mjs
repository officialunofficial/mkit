#!/usr/bin/env node
// SPDX-License-Identifier: MIT OR Apache-2.0
// Stress bounded alarm continuations on an already-built test-faults Worker.
// This uses workerd's real clock; frozen-clock edge cases live in Rust tests.
// Build: (cd apps/vcs-worker && worker-build --release --features __test-faults)
// Run: node scripts/vcs-worker-alarm-probe.mjs
import assert from 'node:assert/strict';
import {mkdtemp, writeFile, open} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawn} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
import net from 'node:net';

const root = resolve(import.meta.dirname, '..');
// Same watchdog as timers.fire_on_schedule; completion has no client polling.
const WATCHDOG_MS = 20_000;
const keepGoing = process.argv.slice(2).includes('--keep-going');
const failSchedule = process.argv.slice(2).find(arg => arg.startsWith('--fail-schedule='))?.split('=')[1];
const failPhase = process.argv.slice(2).find(arg => arg.startsWith('--fail-phase='))?.split('=')[1];
assert.ok(!failPhase || (failPhase === 'install' && failSchedule === 'set'), '--fail-phase=install needs --fail-schedule=set');
assert.ok(!failSchedule || ['set', 'delete'].includes(failSchedule));
assert.ok(process.argv.slice(2).every(arg => arg === '--keep-going' || arg === `--fail-schedule=${failSchedule}` || arg === `--fail-phase=${failPhase}`),
  'usage: vcs-worker-alarm-probe.mjs [--keep-going] [--fail-schedule=set|delete] [--fail-phase=install]');
const fixtures = failSchedule ? 1 : 20;
const scratch = await mkdtemp(join(process.env.TMPDIR || tmpdir(), 'alarm-runtime-'));
const listener = net.createServer();
await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
const port = listener.address().port;
await new Promise(resolve => listener.close(resolve));
const origin = `http://127.0.0.1:${port}`;
const config = join(scratch, 'wrangler.json');
await writeFile(config, JSON.stringify({name: 'mkit-alarm-runtime-probe',
  main: join(root, 'apps/vcs-worker/tests/alarm-probe/wrapper.mjs'),
  compatibility_date: '2026-09-09', build: {command: 'true'},
  vars: {FAIL_SCHEDULE: failSchedule || '', FAIL_PHASE: failPhase || '', WORKERS_PLAN: 'free', AUTH_AUDIENCE: origin, AUTH_REPOSITORY: 'default',
    SHARDING: 'single', TICKET_KEYS: 'fake-dev 1111111111111111111111111111111111111111111111111111111111111111'},
  durable_objects: {bindings: [{name: 'ALARM_PROBE', class_name: 'AlarmProbe'}]},
  migrations: [{tag: 'v1', new_sqlite_classes: ['AlarmProbe']}]}));
const log = await open(join(scratch, 'wrangler.log'), 'w');
const child = spawn('npx', ['--yes', 'wrangler@4.134.0', 'dev', '--config', config,
  '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', '0', '--persist-to', join(scratch, 'state'),
  '--show-interactive-dev-session=false'], {cwd: root, detached: true,
  stdio: ['ignore', log.fd, log.fd], env: {...process.env, WRANGLER_SEND_METRICS: 'false'}});
try {
  // TCP readiness leaves every fixture cold and does not retry a failed RPC.
  const readyUntil = Date.now() + 120_000;
  while (true) {
    const ready = await new Promise(resolve => {
      const socket = net.connect({host: '127.0.0.1', port});
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('error', () => { socket.destroy(); resolve(false); });
    });
    if (ready) break;
    assert.ok(Date.now() < readyUntil, `wrangler did not start; see ${scratch}/wrangler.log`);
    await delay(100);
  }
  let passed = 0, failed = 0;
  for (let i = 1; i <= fixtures; i++) {
    const url = `${origin}/fixture-${i}`;
    const seed = await fetch(url, {method: 'POST', signal: AbortSignal.timeout(WATCHDOG_MS)});
    assert.equal(seed.status, 200);
    assert.equal((await seed.json()).seeded, 65);
    let state, timedOut = false;
    const completionSignal = AbortSignal.timeout(WATCHDOG_MS);
    try {
      const response = await fetch(url, {signal: completionSignal});
      assert.equal(response.status, 200);
      state = await response.json();
    } catch (error) {
      if (!completionSignal.aborted) throw error;
      timedOut = true;
      // One diagnostic read follows the failed completion request. It cannot
      // turn that failure into a pass, and the fixture is never retried.
      try {
        const response = await fetch(`${url}/state`, {signal: AbortSignal.timeout(WATCHDOG_MS)});
        assert.equal(response.status, 200);
        state = {...await response.json(), timedOut};
      } catch (diagnosticError) {
        state = {timedOut, diagnosticError: String(diagnosticError)};
      }
    }
    await writeFile(join(scratch, `fixture-${i}.json`), JSON.stringify(state, null, 2));
    if (timedOut || state.remaining !== 0 || state.ticks.length < 3) {
      failed++;
      console.log(`FAIL alarm continuation ${i}/${fixtures}: ${JSON.stringify(state)}`);
      assert.ok(keepGoing, `fixture ${i} stalled; see ${scratch}/fixture-${i}.json`);
      continue;
    }
    assert.ok(state.ticks.length >= 3, `fixture ${i} must span the existing 32-fire kind cap`);
    if (failSchedule) {
      assert.equal(state.fault.injected, 1, 'scheduling fault must be exercised');
      assert.equal(state.fault.rejected, failPhase === 'install' ? 0 : 1, 'failed scheduling must reject the alarm for runtime retry');
    }
    if (failPhase === 'install') assert.equal(state.fault.idleSets, 0, 'an armed object must not call setAlarm again');
    passed++;
    console.log(`PASS alarm continuation ${i}/${fixtures}: 65 timers drained in ${state.ticks.length} ticks`);
  }
  console.log(`Alarm continuation rate: ${passed}/${fixtures} pass; ${failed}/${fixtures} fail`);
  process.exitCode = failed === 0 ? 0 : 1;
} finally {
  try { process.kill(-child.pid, 'SIGTERM'); } catch {}
  await log.close();
  console.log(`Runtime evidence: ${scratch}`);
}
