import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [{
    name: 'compiled-wasm-in-node',
    enforce: 'pre',
    load(id) {
      if (!id.endsWith('.wasm')) return null
      return `import { readFileSync } from 'node:fs'; export default new WebAssembly.Module(readFileSync(${JSON.stringify(id)}));`
    },
  }],
  test: { server: { deps: { inline: ['tiktoken'] } }, include: ['src/**/*.test.ts'], testTimeout: 15000 },
})
