// SPDX-License-Identifier: MIT OR Apache-2.0
// Local-only fixture for the example's isolated HooksService binding.
const admissions = new Map();
const outcomes = new Map();
export default {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === '/calls' && request.method === 'GET') {
      return Response.json({admissions: [...admissions.values()], outcomes: [...outcomes.values()]});
    }
    if (request.method !== 'POST' || request.headers.get('content-type') !== 'application/json') {
      return new Response(null, {status: 400});
    }
    const body = await request.json();
    if (path === '/mkit.server.hooks.v1.HooksService/Admit') {
      const op = body.operation;
      if (!op?.audience || !op.idempotencyKey) return new Response(null, {status: 400});
      const id = `embedded:${op.idempotencyKey}`;
      admissions.set(id, op);
      return Response.json({allow: {reservationId: id}});
    }
    if (path === '/mkit.server.hooks.v1.HooksService/Outcome') {
      const outcome = body.outcome;
      if (!outcome?.reservationId || !outcome.audience) return new Response(null, {status: 400});
      outcomes.set(outcome.reservationId, outcome);
      return Response.json({});
    }
    return new Response(null, {status: 404});
  },
};
