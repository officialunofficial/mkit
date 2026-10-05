// Test-only observer around real R2 reads; preserve receiver and constructor.
import Host from '__RELEASE_SHIM__';
export * from '__RELEASE_SHIM__';
export default {
  fetch(request, env, ctx) {
    const storage = new Proxy(env.STORAGE, {get(target, key) {
      if (key === 'get') return (...args) => {
        const range = args[1]?.range;
        console.log('MKIT_CONFORMANCE_R2_GET', JSON.stringify({key: args[0], range}));
        if (range?.length === 0 || range?.suffix === 0) {
          console.log('MKIT_CONFORMANCE_ZERO_RANGE');
          throw new Error('zero-length backend range');
        }
        return target.get(...args);
      };
      const value = Reflect.get(target, key, target);
      return typeof value === 'function' && key !== 'constructor' ? value.bind(target) : value;
    }});
    return new Host(ctx, {...env, STORAGE: storage}).fetch(request);
  },
};
