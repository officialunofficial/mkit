// Fixture-only observer installed before the unchanged release Wasm module.
// Linear-memory capacity is a retained allocation, not a Rust live-heap count.
const memories = new Set();
const NativeInstance = WebAssembly.Instance;
WebAssembly.Instance = new Proxy(NativeInstance, {
  construct(target, args) {
    const instance = Reflect.construct(target, args, target);
    for (const value of Object.values(instance.exports)) {
      if (value instanceof WebAssembly.Memory) memories.add(value);
    }
    return instance;
  },
});
const snapshot = () => ({instances: memories.size,
  linearBytes: [...memories].reduce((total, memory) => total + memory.buffer.byteLength, 0)});
// Numeric state only. This adds no HTTP route and exposes no memory bytes.
Object.defineProperty(globalThis, '__mkitLaunchMemory', {value: snapshot});
export default snapshot;
