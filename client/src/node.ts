// Talking to a node: reading, writing and streaming records, over its HTTP API (see src/main.rs). Every
// record that comes back is decoded and checked here, by the wasm core: nothing depends on trusting the node.

import { type Draft, type Entry, type Rec, b58, decodeEntries, decodeRecord, decodeRecords, encodeRecord, signedBytes, unb58 } from "./core.ts";
import type { Signer } from "./signer.ts";

/** Who a node is, and who owns it. IDs are base58. */
export type NodeInfo = { pubkey: string; phrase: string; owners: string[] };

/** What to list: chains first written by `author` (base58 ID), of one `type`, at or under `prefix`. */
export type ListQuery = { author?: string; type?: string; prefix?: string };

/** A chain, as a node has it: every version, oldest first; the current one; and the tombstone, if it was
 * deleted. `root` is its first record's hash (base58), `by` (base58) whose that record is, if known. */
export type Chain = { versions: Rec[]; current: Rec | null; deleted: Rec | null; root: string; by: string | null };

/** A record to write: a `Draft` without what the signer fills in. Public unless it says otherwise. */
export type NewRecord = Omit<Draft, "author" | "private" | "as"> & { private?: boolean };

const query = (q: Record<string, string | boolean | undefined>) =>
  new URLSearchParams(Object.entries(q).filter((e): e is [string, string] => !!e[1]).map(([k, v]) => [k, String(v)]));

const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Compares bytes like the node does (memcmp, then length). */
export const bytesCmp = (a: Uint8Array, b: Uint8Array) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

export class NodeClient {
  readonly url: string;
  private readonly headers: () => Promise<Record<string, string>>;

  /** `url`: the node's base URL, "" for the page's own origin. `headers`: extra headers for reads, e.g.
   * an owner's read token. */
  constructor(url = "", headers: () => Promise<Record<string, string>> = async () => ({})) {
    this.url = url.replace(/\/+$/, "");
    this.headers = headers;
  }

  private async fetch(path: string, init?: RequestInit) {
    const res = await fetch(`${this.url}${path}`, init);
    if (!res.ok) throw new Error((await res.text()) || res.statusText);
    return res;
  }

  private async get(path: string) {
    return new Uint8Array(await (await this.fetch(path, { headers: await this.headers() })).arrayBuffer());
  }

  info = async (): Promise<NodeInfo> => (await this.fetch("/api/node")).json();

  /** The current version of each live chain matching `q`, newest first. */
  list = async (q: ListQuery = {}): Promise<Entry[]> => decodeEntries(await this.get(`/api/records?${query(q)}`));

  /** The chain that the record with this hash (base58) is in. */
  async chain(hash: string): Promise<Chain> {
    const recs = decodeRecords(await this.get(`/api/records/${hash}`));
    // The first record: the one whose `edits` isn't here.
    const root = recs.find((r) => !r.edits || !recs.some((o) => bytesEqual(o.hash, r.edits!))) ?? recs[0];
    const newest = (a: Rec, b: Rec) => a.version - b.version || bytesCmp(a.hash, b.hash);
    const live = recs.filter((r) => r.type !== "tombstone").sort(newest);
    return {
      versions: recs,
      current: live.at(-1) ?? null,
      deleted: recs.find((r) => r.type === "tombstone") ?? null,
      root: b58(root.hash),
      by: root.edits ? null : b58(root.principal),
    };
  }

  /** Stores a signed record (its CBOR). Returns its hash (base58). */
  async put(bytes: Uint8Array): Promise<string> {
    const res = await this.fetch("/api/records", {
      method: "POST",
      headers: { "content-type": "application/cbor" },
      body: bytes as Uint8Array<ArrayBuffer>,
    });
    return ((await res.json()) as { hash: string }).hash;
  }

  /** Signs `r` with `signer` and stores it. Returns its hash (base58). */
  async write(signer: Signer, r: NewRecord): Promise<string> {
    const draft: Draft = { ...r, author: signer.key, private: r.private ?? false, ...(signer.as && { as: signer.as }) };
    return this.put(encodeRecord(draft, await signer.sign(signedBytes(draft))));
  }

  /** Records as the node stores them: a doc's (`doc`, its hash, base58), or those at or under `prefix`.
   * "record" events carry a record (see `streamedRecord`); after what's already there comes a "ready"
   * event. With `snapshot`, a doc's stream starts from its newest snapshot (see `compact` in src/main.rs).
   * EventSource reconnects by itself, picking up where it left off. */
  stream = (q: { doc?: string; prefix?: string; snapshot?: boolean }) => new EventSource(`${this.url}/api/stream?${query(q)}`);

  /** Who claimed each claim on this node (by its hash, base58): their ID, or null while unclaimed. */
  async claims(): Promise<Map<string, string | null>> {
    const m = new Map<string, string | null>();
    for (const e of await this.list({ type: "claim" })) {
      if (e.rec.verified && e.rec.claim) m.set(b58(e.root), e.rec.claim.user ? b58(e.rec.claim.user) : null);
    }
    return m;
  }

  /** The WebSocket URL of a doc's live room. */
  liveUrl(doc: string) {
    const base = this.url ? new URL(this.url) : location;
    return `${base.protocol === "https:" ? "wss" : "ws"}://${base.host}/api/docs/${doc}/live`;
  }
}

/** A "record" event's record, decoded and checked. */
export const streamedRecord = (data: string) => decodeRecord(Uint8Array.from(atob(data), (c) => c.charCodeAt(0)));

/** Whether `s` is a record hash: 32 bytes of base58. */
export const isHash = (s: string) => unb58(s)?.length === 32;
