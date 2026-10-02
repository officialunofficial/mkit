// Local-only controlled cancellation at the ordinary release response bridge.
// No production configuration, fault feature, or internal store route is used.
import launch from '__RELEASE_MODULE__';
export * from '__RELEASE_MODULE__';
export default {
  async fetch(request, env, context) {
    // worker-build exports a WorkerEntrypoint class whose fetch is an instance
    // method. Forward the real invocation context and bindings to that instance.
    const entrypoint = new launch(context, env);
    const mode = request.headers.get('x-launch-read-cancel');
    if (!mode) return entrypoint.fetch(request);
    if (!['before', 'after'].includes(mode)) return new Response(null, {status: 400});
    const headers = new Headers(request.headers);
    headers.delete('x-launch-read-cancel');
    const response = await entrypoint.fetch(new Request(request, {headers}));
    if (response.status !== 200 || !response.body) return response;
    const reader = response.body.getReader();
    let generated = 0;
    if (mode === 'after') {
      const first = await reader.read();
      if (!first.done) generated = first.value.byteLength;
    }
    await reader.cancel('local conformance cancellation');
    return Response.json({mode, generated, objectBytes: Number(response.headers.get('content-length'))});
  },
};
