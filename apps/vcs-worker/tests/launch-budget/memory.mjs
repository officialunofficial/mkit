// Fixture-only observer installed before the unchanged release Wasm module.
// Linear-memory capacity is a retained allocation, not a Rust live-heap count.
let memories = [];
let instances = 0;
const NativeInstance = WebAssembly.Instance;
WebAssembly.Instance = new Proxy(NativeInstance, {
  construct(target, args) {
    const instance = Reflect.construct(target, args, target);
    const exported = [...new Set(Object.values(instance.exports).filter(
      value => value instanceof WebAssembly.Memory))];
    if (exported.length) {
      instances++;
      // Reinitialization is an observation gap, not authority to root old buffers.
      memories = exported;
    }
    return instance;
  },
});
const snapshot = () => ({instances,
  linearBytes: memories.reduce((total, memory) => total + memory.buffer.byteLength, 0)});
// Numeric state only. This adds no HTTP route and exposes no memory bytes.
Object.defineProperty(globalThis, '__mkitLaunchMemory', {value: snapshot});
export default snapshot;
