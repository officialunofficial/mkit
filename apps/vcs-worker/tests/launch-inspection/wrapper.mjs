// Fixture-only HTTPS transport mapping around the ordinary release entrypoint.
// The driver replaces both literals before Wrangler bundles this file.
import app from '__RELEASE_SHIM__';
export * from '__RELEASE_SHIM__';
const receiver = '__RECEIVER_ORIGIN__';
const originalFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = (input, init) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const url = new URL(request.url);
  if (url.origin !== 'https://inspection.launch.invalid') return originalFetch(input, init);
  if (request.redirect !== 'manual') throw new Error('signed hook must refuse redirects');
  // Preserve exact method/body/header bytes, redirect mode and the production
  // cancellation signal. No release route or verdict is added by this wrapper.
  return originalFetch(new Request(receiver + url.pathname, request), init);
};
export default {
  fetch(request, env, ctx) {
    return new app(ctx, env).fetch(request);
  },
};
