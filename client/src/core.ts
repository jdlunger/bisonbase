// The record core (core/src/lib.rs), compiled to wasm (wasm/src/lib.rs, built by `npm run wasm`). Call
// `init` once before anything else in this library.

import initWasm, { initSync } from "../../wasm/pkg/fedcrdt_wasm.js";

export * from "../../wasm/pkg/fedcrdt_wasm.js";

/** Loads the wasm core: in a browser, by fetching it; elsewhere (e.g. Node), from its bytes. */
export async function init(wasm?: BufferSource) {
  if (wasm) initSync({ module: wasm });
  else await initWasm();
}
