// SPDX-License-Identifier: MIT OR Apache-2.0
//
// TEST-ONLY hook Worker for scripts/vcs-worker-hooks.sh. Like the 3.14
// reference Worker it answers only Admit and Outcome (everything else is 501)
// in Connect JSON, requires `Content-Type: application/json`, and expects no
// signature: a service binding is the isolated channel of SPEC-SERVER §7.3.
//
// It records what it is sent, in module state (one local workerd isolate lives
// for the whole run), and serves it at GET /__recorded for the script's
// assertions. Modes, set with POST /__mode?admit=allow|challenge and
// &outcome=ok|fail, make the next answers a payment challenge (the server
// answers 402) or an unavailable hook (the server retries the delivery).

const SERVICE = '/mkit.server.hooks.v1.HooksService/';
const state = (globalThis.__mkitHook ??= {
  admit: 'allow',
  outcome: 'ok',
  admits: [],
  outcomes: [],
  violations: [],
});

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

function control(url) {
  if (url.pathname === '/__recorded') return json(state);
  if (url.pathname === '/__mode') {
    state.admit = url.searchParams.get('admit') ?? state.admit;
    state.outcome = url.searchParams.get('outcome') ?? state.outcome;
    return json({ admit: state.admit, outcome: state.outcome });
  }
  if (url.pathname === '/__reset') {
    Object.assign(state, {
      admit: 'allow',
      outcome: 'ok',
          admits: [],
      outcomes: [],
      violations: [],
    });
    return json({});
  }
  return new Response('not found', { status: 404 });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/__')) return control(url);
    if (request.method !== 'POST' || !url.pathname.startsWith(SERVICE)) {
      return new Response('not implemented', { status: 501 });
    }
    // The binding is unsigned: a signature header would mean the adapter
    // chose the wrong channel.
    for (const [name] of request.headers) {
      if (name.startsWith('x-mkit-hook-')) state.violations.push(`signed: ${name}`);
    }
    if (request.headers.get('content-type') !== 'application/json') {
      state.violations.push('content-type');
      return json({ code: 'invalid_argument' }, 400);
    }
    if (request.headers.get('connect-protocol-version') !== '1') {
      state.violations.push('connect-protocol-version');
    }
    const body = await request.json();
    switch (url.pathname.slice(SERVICE.length)) {
      case 'Admit': {
        state.admits.push({
          audience: body.operation?.audience,
          procedure: body.operation?.procedure,
          mode: state.admit,
        });
        if (state.admit === 'challenge') {
          return json({
            challenge: {
              challenges: [{ scheme: 'payment', value: 'id="stub"' }],
              description: 'stub challenge',
            },
          });
        }
        // Unique across restarts of this stub: the server refuses a reservation id it
        // has seen (SPEC-SERVER §6.3).
        const reservationId = `stub-${crypto.randomUUID()}`;
        state.admits[state.admits.length - 1].reservationId = reservationId;
        return json({ allow: { reservationId } });
      }
      case 'Outcome': {
        const outcome = body.outcome ?? {};
        state.outcomes.push({
          reservationId: outcome.reservationId,
          audience: outcome.audience,
          kind: ['committed', 'aborted', 'expired', 'readServed'].find((k) => k in outcome),
          answered: state.outcome === 'fail' ? 503 : 200,
        });
        return state.outcome === 'fail' ? new Response('down', { status: 503 }) : json({});
      }
      default:
        return new Response('not implemented', { status: 501 });
    }
  },
};
