// Shared docs (see "shared documents" in core/src/lib.rs): their records, and keeping a doc's content in
// sync with a node, for any CRDT library (an `Adapter`) and any schema.
//
// `openDoc` streams the doc's records, applies the updates and snapshots of those who may edit it (its
// author, its editors, the node's owners: checked here for every one, as peers pass records along without
// checking), and writes our own edits as updates, batched so typing doesn't sign a record per key. With
// a `Store`, it keeps the doc's last known content and our unsent edits on this device. Once enough
// updates pile up, editors write a snapshot, so that readers can start from it. Encrypted docs are
// decrypted and encrypted here: the node only ever sees ciphertext.

import { type Rec, type SealedKey, type Who, b58, enckeyPath, liveSignedBytes, pathWithin, unb58 } from "./core.ts";
import { type EncKeys, decrypt, encrypt, newDocKey, seal, unseal } from "./crypto.ts";
import { type NodeClient, streamedRecord } from "./node.ts";
import { type Signer, principal } from "./signer.ts";

/** A CRDT library, as `openDoc` needs it. `D` is its document type. */
export interface Adapter<D> {
  /** What docs in it say their `format` is, e.g. "yjs". */
  format: string;
  create(): D;
  /** Applies an update or a whole state (as `encodeState` makes), from elsewhere. */
  apply(doc: D, update: Uint8Array): void;
  /** The whole content, as one update. */
  encodeState(doc: D): Uint8Array;
  /** Several updates as one. */
  merge(updates: Uint8Array[]): Uint8Array;
  /** Calls `cb` for each change to `doc`: `local` unless it came from `apply`. Returns how to stop. */
  observe(doc: D, cb: (update: Uint8Array, local: boolean) => void): () => void;
  destroy(doc: D): void;
}

/** Where a device keeps things between visits, e.g. IndexedDB. Failures should resolve, not throw. */
export interface Store {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<unknown>;
  del(key: string): Promise<unknown>;
}

/** A version newer than both the clock and `prev`, so quick successive edits still go through. */
export const nextVersion = (prev = 0) => Math.max(Date.now(), prev + 1);

const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

// ---- doc records ----

/** Starts a doc at `path`. With `encryption` (our X25519 keys), it's encrypted: its content key is
 * sealed to us. Returns its hash (base58): its chain's, for good. */
export async function createDoc(
  node: NodeClient,
  signer: Signer,
  o: { path: string; title?: string; format: string; schema: string; encryption?: EncKeys | null },
) {
  const keys: SealedKey[] | undefined = o.encryption ? [{ user: principal(signer), sealed: await seal(o.encryption.publicKey, newDocKey()) }] : undefined;
  const data = { title: (o.title ?? "").trim(), editors: [], format: o.format, schema: o.schema, ...(keys && { keys }) };
  return node.write(signer, { path: o.path, version: nextVersion(), type: "doc", data });
}

/** Writes a new version of the doc record `doc` with these changes. Its author or an owner only. */
export function saveDoc(node: NodeClient, signer: Signer, doc: Rec, changes: { title?: string; editors?: Who[]; keys?: SealedKey[] }) {
  const d = doc.doc!;
  const data = { ...d, ...changes, title: (changes.title ?? d.title).trim() };
  return node.write(signer, { path: doc.path, version: nextVersion(doc.version), type: "doc", edits: doc.hash, data });
}

/** A user's X25519 public key, from their newest enckey record on `node`; null if they have none. */
export async function encKeyOf(node: NodeClient, user: Uint8Array): Promise<Uint8Array | null> {
  const recs = (await node.list({ prefix: enckeyPath(user), type: "enckey" })).map((e) => e.rec);
  const mine = recs.filter((r) => r.verified && r.enckey && bytesEqual(r.author, user));
  return mine.sort((a, b) => b.version - a.version)[0]?.enckey!.key ?? null;
}

/** Publishes our X25519 public key, unless `node` already has it. Needs a grant covering our space. */
export async function publishEncKey(node: NodeClient, signer: Signer, keys: EncKeys) {
  if (signer.as) throw new Error("Only the user themselves can publish their encryption key.");
  const current = await encKeyOf(node, signer.key);
  if (current && bytesEqual(current, keys.publicKey)) return;
  await node.write(signer, { path: enckeyPath(signer.key), version: nextVersion(), type: "enckey", data: { key: keys.publicKey } });
}

/** `keys` plus `docKey` sealed to each of `users` who has published an encryption key and has none
 * yet. Those who haven't published one are left out (see `missing`). */
export async function sealTo(node: NodeClient, keys: SealedKey[], docKey: Uint8Array, users: Uint8Array[]) {
  const out = [...keys];
  const missing: Uint8Array[] = [];
  for (const u of users) {
    if (out.some((k) => bytesEqual(k.user, u))) continue;
    const pub = await encKeyOf(node, u);
    if (pub) out.push({ user: u, sealed: await seal(pub, docKey) });
    else missing.push(u);
  }
  return { keys: out, missing };
}

// ---- keeping a doc in sync ----

/** A doc record as `openDoc` follows it: its current version, its chain's hash, and whose its first
 * version is (base58; null if the node doesn't have it). */
export type DocInfo = { rec: Rec; root: string; by: string | null };

export type DocStatus = {
  /** The doc record's current version, once loaded (null if it isn't a doc, or was deleted). */
  doc: DocInfo | null;
  deleted: boolean;
  /** Whether the content is caught up with the node, or shown from what this device kept. */
  ready: boolean;
  /** Whether we may edit it: our signer's principal is its author, an editor, or an owner. */
  editable: boolean;
  /** Encrypted, and we don't have its key: nothing can be shown or written. */
  locked: boolean;
  /** Our edits: some not sent yet; being sent; or failing to send (why). */
  unsent: boolean;
  sending: boolean;
  saveError: string;
  /** Why we can't sync, if we can't. */
  syncError: string;
  /** Updates we got but aren't applying: their authors may not edit the doc (as far as we know). */
  ignored: number;
};

export type OpenDocOptions<D> = {
  node: NodeClient;
  /** The doc's hash (base58). */
  hash: string;
  adapter: Adapter<D>;
  /** Who writes our edits; none to only read. */
  signer?: Signer | null;
  /** Our X25519 keys, to open an encrypted doc's key sealed to us. */
  encryption?: EncKeys | null;
  store?: Store | null;
  /** Write a snapshot once this many updates aren't in the newest one. 0: never. */
  snapshotEvery?: number;
  onStatus?: (s: DocStatus) => void;
};

/** Send our edits once typing pauses this long, */
const FLUSH_IDLE_MS = 250;
/** or at the latest this long after the first unsent one. */
const FLUSH_MAX_MS = 1500;
const RETRY_MS = 3000;
const SAVE_STATE_MS = 500;
/** Wait this long after the last update before writing a snapshot, so we don't write one mid-burst. */
const SNAPSHOT_IDLE_MS = 5000;

export type DocSync<D> = {
  /** The doc's content: show it, and change it, through its library. */
  content: D;
  status: () => DocStatus;
  /** Loads the doc record again, e.g. after changing it ourselves. */
  reload: () => Promise<void>;
  /** The doc's content key, if it's encrypted and we have it. */
  docKey: () => Uint8Array | null;
  /** Remembers a content key from elsewhere (e.g. an invite link) on this device, and unlocks with it. */
  addDocKey: (key: Uint8Array) => Promise<void>;
  /** Stops syncing. Unsent edits are sent now if they can be, and kept on this device until they are. */
  close: () => void;
};

/** Keeps a doc's content in sync with `node`. See the top of this file. */
export function openDoc<D>(o: OpenDocOptions<D>): DocSync<D> {
  const { node, hash, adapter, store } = o;
  const signer = o.signer ?? null;
  const me = signer && b58(principal(signer));
  const docBytes = unb58(hash)!;
  const content = adapter.create();
  const stateKey = `doc:${hash}`;
  const keyKey = `dockey:${hash}`;
  /** Unsent edits are ours alone: they're sent signed by us. */
  const outboxKey = me && `outbox:${hash}:${me}`;
  const snapshotEvery = o.snapshotEvery ?? 200;

  let status: DocStatus = {
    doc: null,
    deleted: false,
    ready: false,
    editable: false,
    locked: false,
    unsent: false,
    sending: false,
    saveError: "",
    syncError: "",
    ignored: 0,
  };
  const set = (s: Partial<DocStatus>) => {
    status = { ...status, ...s };
    o.onStatus?.(status);
  };

  let stopped = false;
  let owners = new Set<string>();
  let claims = new Map<string, string | null>();
  let docKey: Uint8Array | null = null;
  /** Updates and snapshots from the node not applied yet: we don't know their authors as editors (yet),
   * or can't decrypt them (yet). */
  let pending: Rec[] = [];
  /** Hashes (base58) of the updates in the content, and of those in the newest snapshot applied. */
  const known = new Set<string>();
  let covered = new Set<string>();
  let docDirty = true;
  let fresh = false;
  let caughtUp = false;
  /** Whether to stream every update rather than start from a snapshot: we didn't trust the node's. */
  let full = false;
  /** Our edits not sent yet, and when the first of them was made; and the ones being sent. */
  const outbox: Uint8Array[] = [];
  let firstUnsent = 0;
  let inflight: Uint8Array | null = null;
  let flushTimer: ReturnType<typeof setTimeout> | undefined;
  let stateTimer: ReturnType<typeof setTimeout> | undefined;
  let snapshotTimer: ReturnType<typeof setTimeout> | undefined;
  let snapshotting = false;
  /** Each delegation's current version (by hash), or null if it's gone: for checking `as`. */
  const delegations = new Map<string, Promise<Rec | null>>();

  const keepOutbox = () => {
    if (!outboxKey || !store) return;
    const all = inflight ? [inflight, ...outbox] : outbox;
    if (all.length) store.set(outboxKey, adapter.merge(all));
    else store.del(outboxKey);
  };
  const keepState = () => store?.set(stateKey, adapter.encodeState(content));

  /** Who's named by a doc's editors: their IDs (base58), as far as we know who claimed what. */
  const editorsOf = (d: DocInfo) =>
    (d.rec.doc?.editors ?? []).map((w) => ("user" in w ? b58(w.user) : (claims.get(b58(w.claim)) ?? null))).filter((u): u is string => !!u);
  const mayEdit = (d: DocInfo, user: string) => user === d.by || owners.has(user) || editorsOf(d).includes(user);
  const hasOpenClaims = (d: DocInfo) => !!d.rec.doc?.editors.some((w) => "claim" in w && !claims.get(b58(w.claim)));

  /** Whether `r`'s `as`, if any, holds: its delegation is live, by that user, for its author's key, and
   * covers it. A revoked delegation covers nothing: its key may have leaked. */
  async function delegationHolds(r: Rec) {
    if (!r.as) return true;
    const h = b58(r.as.delegation);
    if (!delegations.has(h)) {
      delegations.set(
        h,
        node.chain(h).then(
          (c) => (c.deleted ? null : c.current),
          () => null,
        ),
      );
    }
    const head = await delegations.get(h);
    const d = head?.verified ? head.delegate : undefined;
    return (
      !!d &&
      bytesEqual(head!.author, r.as.user) &&
      bytesEqual(d.key, r.author) &&
      (d.expires === undefined || r.version <= d.expires) &&
      (!d.types || d.types.includes(r.type)) &&
      (!d.paths || d.paths.some((p) => pathWithin(r.path, p)))
    );
  }

  async function trusted(r: Rec) {
    const d = status.doc;
    return !!d && r.verified && mayEdit(d, b58(r.principal)) && (await delegationHolds(r));
  }

  /** The content key of the encrypted doc `d`: sealed to us in it, or kept on this device. */
  async function findDocKey(d: DocInfo) {
    const keys = d.rec.doc?.keys;
    if (!keys) return null;
    if (me && o.encryption) {
      const mine = keys.find((k) => b58(k.user) === me);
      if (mine) {
        try {
          return await unseal(o.encryption, mine.sealed);
        } catch (e) {
          console.warn("Couldn't open this doc's key, sealed to us:", e);
        }
      }
    }
    return (await store?.get<Uint8Array>(keyKey)) ?? null;
  }

  async function loadDoc() {
    const chain = await node.chain(hash);
    if (stopped) return;
    const cur = chain.current?.type === "doc" && chain.current.verified ? chain.current : null;
    const doc = cur && !chain.deleted ? { rec: cur, root: chain.root, by: chain.by } : null;
    if (doc?.rec.doc?.format !== undefined && doc.rec.doc.format !== adapter.format) {
      throw new Error(`This doc's format is ${doc.rec.doc.format}, not ${adapter.format}.`);
    }
    if (doc?.rec.doc?.keys) docKey ??= await findDocKey(doc);
    set({
      doc,
      deleted: !!chain.deleted,
      editable: !!doc && !!me && mayEdit(doc, me) && (!doc.rec.doc?.keys || !!docKey),
      locked: !!doc?.rec.doc?.keys && !docKey,
    });
  }

  /** The bytes to apply for `r`, decrypted if the doc is encrypted; null if we can't (yet). */
  async function plain(r: Rec, data: Uint8Array) {
    if (!status.doc?.rec.doc?.keys) return data;
    if (!docKey) return null;
    try {
      return await decrypt(docKey, docBytes, data);
    } catch {
      return null;
    }
  }

  /** Applies the pending updates and snapshots whose authors may edit the doc; keeps the rest for if
   * that changes. */
  async function apply() {
    if (!status.doc) return;
    const keep: Rec[] = [];
    for (const r of pending) {
      const ref = r.docUpdate?.doc ?? r.docSnapshot?.doc;
      if (!r.verified || !ref || b58(ref) !== hash) continue;
      const data = r.docUpdate?.update ?? r.docSnapshot!.state;
      const bytes = (await trusted(r)) ? await plain(r, data) : null;
      if (stopped) return;
      if (!bytes) {
        keep.push(r);
        continue;
      }
      adapter.apply(content, bytes);
      if (r.docUpdate) known.add(b58(r.hash));
      else {
        const covers = r.docSnapshot!.covers.map(b58);
        covers.forEach((c) => known.add(c));
        if (covers.length >= covered.size) covered = new Set(covers);
      }
    }
    pending = keep;
    set({ ignored: pending.length });
    if (status.ready) scheduleSnapshot();
  }

  /** Catches up with what the stream brought: the doc record if it changed, then the updates. One at a time. */
  let queue = Promise.resolve();
  const process = () =>
    (queue = queue.then(async () => {
      try {
        if (docDirty) {
          docDirty = false;
          await loadDoc();
        }
        // Someone we don't know of may have claimed an invite since we loaded who claimed what.
        const d = status.doc;
        if (fresh && d && hasOpenClaims(d) && pending.some((r) => !mayEdit(d, b58(r.principal)))) {
          claims = await node.claims();
          await loadDoc();
        }
        fresh = false;
        await apply();
        if (outbox.length) schedule();
      } catch (e) {
        docDirty = true;
        set({ syncError: (e as Error).message });
      }
    }));

  // ---- the stream ----

  let es: EventSource | null = null;
  function connect() {
    es?.close();
    caughtUp = false;
    // Starting over: whatever we couldn't apply comes again.
    pending = [];
    es = node.stream({ doc: hash, snapshot: !full });
    es.addEventListener("record", (e) => {
      const r = streamedRecord((e as MessageEvent<string>).data);
      if (r.type === "doc_update" || r.type === "doc_snapshot") {
        pending.push(r);
        fresh = true;
        // The node started us from a snapshot we may not trust: then we'd miss the updates it covers.
        if (!full && !caughtUp && r.type === "doc_snapshot") {
          process().then(async () => {
            if (!stopped && !full && pending.includes(r) && status.doc && !(await trusted(r))) {
              full = true;
              connect();
            }
          });
          return;
        }
      } else docDirty = true; // a new version of the doc, or its deletion
      if (caughtUp) process();
    });
    es.addEventListener("ready", () => {
      caughtUp = true;
      process().then(() => {
        if (stopped) return;
        set({ ready: true });
        scheduleSnapshot();
      });
    });
    es.onopen = () => set({ syncError: "" });
    es.onerror = () => set({ syncError: "can't reach the node; reconnecting…" });
  }

  // ---- our edits ----

  const schedule = (ms?: number) => {
    clearTimeout(flushTimer);
    flushTimer = setTimeout(flush, ms ?? Math.max(0, Math.min(FLUSH_IDLE_MS, firstUnsent + FLUSH_MAX_MS - Date.now())));
  };

  /** Writes an update to the doc: encrypted, if it is. Returns its hash. */
  async function writeUpdate(update: Uint8Array) {
    const d = status.doc!;
    const data = d.rec.doc?.keys ? await encrypt(docKey!, docBytes, update) : update;
    const h = await node.write(signer!, { path: d.rec.path, version: nextVersion(), type: "doc_update", data: { doc: docBytes, update: data } });
    known.add(h);
    return h;
  }

  /** Sends our unsent edits as one update record. */
  async function flush() {
    if (inflight || !outbox.length || !status.doc || !status.editable) return;
    inflight = adapter.merge(outbox.splice(0));
    firstUnsent = 0;
    set({ sending: true });
    let saveError = "";
    try {
      await writeUpdate(inflight);
    } catch (e) {
      saveError = (e as Error).message;
      outbox.unshift(inflight);
    }
    inflight = null;
    keepOutbox();
    set({ unsent: outbox.length > 0, sending: false, saveError });
    if (outbox.length && !stopped) schedule(saveError ? RETRY_MS : undefined);
  }

  // ---- snapshots ----

  function scheduleSnapshot() {
    if (!snapshotEvery || !status.editable || snapshotting) return;
    const uncovered = [...known].filter((h) => !covered.has(h)).length;
    if (uncovered < snapshotEvery) return;
    clearTimeout(snapshotTimer);
    snapshotTimer = setTimeout(writeSnapshot, SNAPSHOT_IDLE_MS);
  }

  async function writeSnapshot() {
    const d = status.doc;
    if (stopped || !d || !status.editable || snapshotting) return;
    snapshotting = true;
    try {
      const covers = [...known];
      const state = adapter.encodeState(content);
      const data = d.rec.doc?.keys ? await encrypt(docKey!, docBytes, state) : state;
      await node.write(signer!, {
        path: d.rec.path,
        version: nextVersion(),
        type: "doc_snapshot",
        data: { doc: docBytes, state: data, covers: covers.map((h) => unb58(h)!) },
      });
      covered = new Set(covers);
    } catch (e) {
      console.warn("Couldn't write a snapshot:", e);
    } finally {
      snapshotting = false;
    }
  }

  // ---- start ----

  const stopObserving = adapter.observe(content, (u, local) => {
    clearTimeout(stateTimer);
    stateTimer = setTimeout(keepState, SAVE_STATE_MS);
    if (!local) return;
    outbox.push(u);
    keepOutbox();
    if (!firstUnsent) firstUnsent = Date.now();
    set({ unsent: true });
    schedule();
  });

  /** Loads what this device kept. Whether it had the doc's content. */
  async function restore() {
    if (!store) return false;
    const [state, unsent] = await Promise.all([store.get<Uint8Array>(stateKey), outboxKey ? store.get<Uint8Array>(outboxKey) : undefined]);
    if (stopped) return false;
    if (state) adapter.apply(content, state);
    if (unsent) {
      // Ours, but not sent yet: applied as if from elsewhere, then queued to send.
      adapter.apply(content, unsent);
      outbox.push(unsent);
      firstUnsent ||= Date.now();
      set({ unsent: true });
      schedule();
    }
    return !!state;
  }

  const setup = Promise.all([node.info(), node.claims()]).then(
    ([info, c]) => {
      owners = new Set(info.owners);
      claims = c;
    },
    (e) => set({ syncError: (e as Error).message }),
  );
  // What this device kept is enough to show, until the stream catches up (or if it can't).
  Promise.all([restore(), setup.then(process)]).then(([had]) => had && !stopped && status.doc && set({ ready: true }));
  setup.then(() => !stopped && connect());

  return {
    content,
    status: () => status,
    reload: () => {
      docDirty = true;
      return process();
    },
    docKey: () => docKey,
    addDocKey: async (key) => {
      await store?.set(keyKey, key);
      docKey = key;
      docDirty = true;
      await process();
    },
    close: () => {
      stopped = true;
      es?.close();
      clearTimeout(flushTimer);
      clearTimeout(snapshotTimer);
      if (stateTimer) {
        clearTimeout(stateTimer);
        keepState();
      }
      stopObserving();
      // Leaving: send what's left now, rather than next time. It's kept here until it's gone.
      const left = outbox.splice(0);
      if (left.length && status.doc && status.editable) {
        const merged = adapter.merge(left);
        writeUpdate(merged).then(keepOutbox, () => {
          outbox.unshift(merged);
          keepOutbox();
        });
      }
      adapter.destroy(content);
    },
  };
}

/** Joins `doc`'s live room on `node` (see `live` in src/main.rs): a WebSocket, and the signed hello that
 * has to be its first message. Only the doc's editors may join. */
export async function joinLive(node: NodeClient, signer: Signer, doc: string, nodeKey: Uint8Array) {
  const expires = Date.now() + 10 * 60 * 1000;
  const signature = await signer.sign(liveSignedBytes(nodeKey, unb58(doc)!, BigInt(expires)));
  const ws = new WebSocket(node.liveUrl(doc));
  ws.binaryType = "arraybuffer";
  const hello: Record<string, unknown> = { user: b58(signer.key), expires, signature: b58(signature) };
  if (signer.as) Object.assign(hello, { as: b58(signer.as.user), delegation: b58(signer.as.delegation) });
  return { ws, hello: JSON.stringify(hello) };
}
