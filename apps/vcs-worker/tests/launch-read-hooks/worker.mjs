// Local-only isolated service-binding receiver transport. Its host receiver
// survives Worker restarts so lost replies can be checked without test routes.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || !url.pathname.startsWith('/mkit.server.hooks.v1.HooksService/')) {
      return new Response(null, {status: 404});
    }
    for (const [name] of request.headers) {
      if (name.startsWith('x-mkit-hook-')) return new Response(null, {status: 401});
    }
    if (request.headers.get('content-type') !== 'application/json' ||
        request.headers.get('connect-protocol-version') !== '1') {
      return new Response(null, {status: 400});
    }
    const origin = new URL(env.RECEIVER_ORIGIN);
    if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' ||
        origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) {
      return new Response(null, {status: 503});
    }
    try {
      return await fetch(new URL(url.pathname, origin), {
        method: 'POST', headers: request.headers, body: request.body,
        redirect: 'manual', signal: AbortSignal.timeout(5000),
      });
    } catch {
      return new Response(null, {status: 503});
    }
  },
};
