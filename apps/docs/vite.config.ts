import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import { vocs } from "vocs/vite";

export default defineConfig({
  plugins: [
    nodePolyfills({
      include: ["buffer", "crypto", "events", "stream", "util"],
      globals: { Buffer: true, global: true, process: true },
      protocolImports: true,
    }),
    vocs(),
    react(),
  ],
});
