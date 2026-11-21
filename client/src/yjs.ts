// The Yjs adapter for `openDoc` (docs.ts): docs whose format is "yjs".

import * as Y from "yjs";
import type { Adapter } from "./docs.ts";

/** What `apply` tags transactions with, so `observe` can tell them from local changes. */
export const REMOTE = Symbol("bisonbase remote");

export const yjs: Adapter<Y.Doc> = {
  format: "yjs",
  create: () => new Y.Doc(),
  apply: (doc, update) => Y.applyUpdate(doc, update, REMOTE),
  encodeState: (doc) => Y.encodeStateAsUpdate(doc),
  merge: (updates) => Y.mergeUpdates(updates),
  observe(doc, cb) {
    const f = (u: Uint8Array, origin: unknown) => cb(u, origin !== REMOTE);
    doc.on("update", f);
    return () => doc.off("update", f);
  },
  destroy: (doc) => doc.destroy(),
};
