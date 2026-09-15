import { initSync } from "../vendor/mkit-wasm/mkit_wasm.js";
import * as api from "../vendor/mkit-wasm/mkit_wasm.js";
import wasmModule from "../vendor/mkit-wasm/mkit_wasm_bg.wasm";

initSync({ module: wasmModule });
export const mkit = api;
export const encoder = new TextEncoder();
export const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function fromHex(value: string): Uint8Array {
    if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error("Invalid hexadecimal bytes");
    return Uint8Array.from(value.match(/../g)!, (pair) => Number.parseInt(pair, 16));
}
