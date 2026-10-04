// Local fault harness only: the reference binary has no fault flags or test routes.
import Host, {HostEvents as Receiver} from '__REFERENCE_SHIM__';
export {RefStore, NsCoordinator, RefShard, RepoIndexShard, ContentIndexShard} from '__REFERENCE_SHIM__';
export class HostEvents extends Receiver {
  constructor(ctx, env) { super(ctx, env); this.env = env; }
  async fetch(req) {
    if (this.env.RECEIVER_OUTAGE === 'true' && req.method === 'POST') {
      const event = await req.clone().json();
      if (event.kind === 'committed') return new Response('local receiver outage', {status:503});
    }
    return super.fetch(req);
  }
}
export default {
  async fetch(req, env, ctx) {
    if (new URL(req.url).pathname === '/__reference_test/events') {
      const repo = req.headers.get('X-Repository');
      const id = env.HOST_EVENTS.idFromName(`${env.AUTH_AUDIENCE}:${repo}`);
      return env.HOST_EVENTS.get(id).fetch(req);
    }
    const url = new URL(req.url);
    if (url.pathname.startsWith('/mkit.transport.v1.TransportService/')) {
      url.pathname = '/_embedding/mkit' + url.pathname;
      req = new Request(url, req);
    }
    return new Host(ctx, env).fetch(req);
  }
};
