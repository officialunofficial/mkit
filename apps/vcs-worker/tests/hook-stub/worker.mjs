// TEST-ONLY isolated binding forwarder. MPP semantics live in the Rust stub.
// Never referenced by release/staging configurations.
export default {
  async fetch(request, env) {
    let upstream;
    try {
      upstream = new URL(env.STUB_UPSTREAM);
      if (upstream.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(upstream.hostname) ||
          upstream.username || upstream.password || upstream.pathname !== '/' || upstream.search || upstream.hash) {
        return new Response(null, { status: 503 });
      }
    } catch {
      return new Response(null, { status: 503 });
    }
    const path = new URL(request.url).pathname;
    if (!path.startsWith('/mkit.server.hooks.v1.HooksService/') || request.method !== 'POST') {
      return new Response(null, { status: 404 });
    }
    for (const [name] of request.headers) {
      if (name.startsWith('x-mkit-hook-')) return new Response(null, { status: 401 });
    }
    if (request.headers.get('content-type') !== 'application/json' ||
        request.headers.get('connect-protocol-version') !== '1') return new Response(null, { status: 400 });
    try {
      return await fetch(new URL(path, upstream), {
        method: 'POST', headers: request.headers, body: request.body,
        redirect: 'manual', signal: AbortSignal.timeout(30000),
      });
    } catch {
      return new Response(null, { status: 503 });
    }
  },
};
