// Runs the client library against a real node: `npm run test:client` starts one on a fresh database
// and runs this with its URL in NODE_URL and its first-owner claim token in CLAIM_TOKEN.

import { readFileSync } from "node:fs";
import * as Y from "yjs";
import {
  type DocStatus,
  type DocSync,
  type Signer,
  type Store,
  NodeClient,
  b58,
  claimSignedBytes,
  createDoc,
  decodeId,
  delegatePath,
  encKeyOf,
  encKeysFromSeed,
  init,
  joinLive,
  keySigner,
  newKeyPair,
  openDoc,
  publishEncKey,
  saveDoc,
  sealTo,
  unb58,
  userPath,
} from "../src/index.ts";
import { yjs } from "../src/yjs.ts";

const url = process.env.NODE_URL!;
const token = process.env.CLAIM_TOKEN!;
await init(readFileSync(new URL("../../wasm/pkg/fedcrdt_wasm_bg.wasm", import.meta.url)));
const node = new NodeClient(url);

let failures = 0;
function check(ok: unknown, what: string) {
  console.log(`${ok ? "ok  " : "FAIL"} ${what}`);
  if (!ok) failures++;
}
async function rejects(p: Promise<unknown>, has: string, what: string) {
  try {
    await p;
    check(false, `${what} (it went through)`);
  } catch (e) {
    check((e as Error).message.includes(has), `${what}: ${(e as Error).message}`);
  }
}
async function until(f: () => boolean | Promise<boolean>, what: string, ms = 10_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await f()) return check(true, what);
    await new Promise((r) => setTimeout(r, 100));
  }
  check(false, `${what} (timed out)`);
}
const memoryStore = (): Store => {
  const m = new Map<string, unknown>();
  return { get: async <T>(k: string) => m.get(k) as T | undefined, set: async (k, v) => m.set(k, v), del: async (k) => m.delete(k) };
};
async function user() {
  const k = await newKeyPair();
  return keySigner(k.privateKey, k.publicKey);
}
const v = () => Date.now();

// ---- an owner, and grants ----

const alice = await user();
const info = await node.info();
const nodeKey = decodeId(info.pubkey)!;
const t = unb58(token)!;
const res = await fetch(`${url}/api/claim`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ token, user: b58(alice.key), signature: b58(await alice.sign(claimSignedBytes(nodeKey, t))) }),
});
check(res.ok, "alice claims the node");
for (const path of ["/u", "/doc", "/todo"]) {
  await node.write(alice, { path: "/node/grant", version: v(), type: "grant", data: { path, grantees: "anyone" } });
}

const cors = await fetch(`${url}/api/records`, { headers: { origin: "https://some-app.example" } });
check(cors.headers.get("access-control-allow-origin") === "*", "any origin may use the API");

// ---- app types ----

const bob = await user();
const item = { title: "milk", n: 3, big: 2n ** 60n, bytes: new Uint8Array([1, 2]), tags: ["a"], nested: { done: false, none: null } };
await node.write(bob, { path: "/todo/1", version: v(), type: "todo.item", data: item });
const [got] = await node.list({ type: "todo.item" });
check(got?.rec.verified, "an app type is stored and checks out");
/** JSON with sorted keys (CBOR maps sort theirs), BigInts and bytes spelled out. */
const canon = (x: unknown): string =>
  typeof x === "bigint" ? `${x}n` : x instanceof Uint8Array ? `bytes:${[...x]}` : Array.isArray(x) ? `[${x.map(canon)}]`
  : x && typeof x === "object" ? `{${Object.keys(x).sort().map((k) => `${k}:${canon((x as Record<string, unknown>)[k])}`)}}` : JSON.stringify(x);
check(canon(got?.rec.data) === canon(item), `its data round-trips: ${canon(got?.rec.data)}`);
await rejects(node.write(bob, { path: "/todo/2", version: v(), type: "todo", data: null }), "unknown record type", "types without a namespace are refused");

// ---- delegation ----

const appKey = await newKeyPair();
const delegation = await node.write(bob, {
  path: delegatePath(bob.key),
  version: v(),
  type: "delegate",
  data: { key: appKey.publicKey, name: "Test app", paths: ["/todo", "/doc"], types: ["todo.item", "doc_update", "doc_snapshot"] },
});
const app: Signer = keySigner(appKey.privateKey, appKey.publicKey, { user: bob.key, delegation: unb58(delegation)! });
await node.write(app, { path: "/todo/3", version: v(), type: "todo.item", data: { title: "eggs" } });
const bobs = await node.list({ author: b58(bob.key), type: "todo.item" });
check(bobs.length === 2 && bobs.some((e) => e.rec.as && b58(e.rec.principal) === b58(bob.key)), "the app writes as bob");
await rejects(node.write(app, { path: "/todo/4", version: v(), type: "post", data: "hi" }), "doesn't cover", "only what bob let it");
await rejects(node.write(app, { path: `${userPath(bob.key)}/x`, version: v(), type: "todo.item", data: 1 }), "doesn't cover", "nor elsewhere");

// ---- docs: syncing, snapshots ----

const carol = await user();
const doc = await createDoc(node, bob, { path: "/doc", title: "Plans", format: "yjs", schema: "test.notes" });
const docRec = (await node.chain(doc)).current!;
await saveDoc(node, bob, docRec, { editors: [{ user: carol.key }] });

const sessions: DocSync<Y.Doc>[] = [];
const open = (signer: Signer | null, opts: { encryption?: Awaited<ReturnType<typeof encKeysFromSeed>>; store?: Store } = {}) => {
  let status: DocStatus | null = null;
  const s = openDoc({ node, hash: doc, adapter: yjs, signer, snapshotEvery: 3, store: opts.store ?? memoryStore(), ...opts, onStatus: (x) => (status = x) });
  sessions.push(s);
  return { s, text: () => s.content.getText("t").toString(), status: () => status };
};
const b = open(bob);
const c = open(carol);
await until(() => !!b.status()?.ready && !!c.status()?.ready, "both editors catch up");
check(b.status()?.editable && c.status()?.editable, "both may edit");
for (const w of ["one ", "two ", "three ", "four "]) {
  b.s.content.getText("t").insert(b.text().length, w);
  await new Promise((r) => setTimeout(r, 400));
}
c.s.content.getText("t").insert(0, "carol: ");
await until(() => b.text() === c.text() && b.text() === "carol: one two three four ", "edits meet");
// Through the app, as bob: a third session.
const a = open(app);
await until(() => !!a.status()?.ready && a.text() === b.text(), "the app sees the doc");
a.s.content.getText("t").insert(0, "[app] ");
await until(() => b.text().startsWith("[app] "), "and edits it as bob");
await until(async () => (await node.list({ type: "doc_snapshot" })).length > 0, "an editor writes a snapshot", 15_000);
const reader = open(null);
await until(() => !!reader.status()?.ready && reader.text() === b.text(), "a reader starts from it, and catches up");
check(!reader.status()?.editable, "readers can't edit");

// A non-editor's update is ignored.
const dave = await user();
await rejects(
  node.write(dave, { path: "/doc", version: v(), type: "doc_update", data: { doc: unb58(doc)!, update: Y.encodeStateAsUpdate(new Y.Doc()) } }),
  "author and editors",
  "the node refuses a non-editor's update",
);

// The live room, through the app.
const live = await joinLive(node, app, doc, nodeKey);
const closed = await new Promise<string>((done) => {
  live.ws.onopen = () => live.ws.send(live.hello);
  live.ws.onclose = (e) => done(`closed: ${e.reason}`);
  setTimeout(() => done("open"), 1000);
});
check(closed === "open", `the app joins the live room as bob (${closed})`);
live.ws.close();

// ---- encrypted docs ----

const bobEnc = await encKeysFromSeed(crypto.getRandomValues(new Uint8Array(32)));
const carolEnc = await encKeysFromSeed(crypto.getRandomValues(new Uint8Array(32)));
await publishEncKey(node, bob, bobEnc);
await publishEncKey(node, carol, carolEnc);
check(b58((await encKeyOf(node, carol.key))!) === b58(carolEnc.publicKey), "carol's encryption key is published");
await rejects(publishEncKey(node, app, bobEnc), "Only the user", "an app can't publish bob's key");

const secret = await createDoc(node, bob, { path: "/doc", title: "Secret", format: "yjs", schema: "test.notes", encryption: bobEnc });
const openSecret = (signer: Signer | null, encryption: typeof bobEnc | null) => {
  let status: DocStatus | null = null;
  const s = openDoc({ node, hash: secret, adapter: yjs, signer, encryption, onStatus: (x) => (status = x) });
  sessions.push(s);
  return { s, text: () => s.content.getText("t").toString(), status: () => status };
};
const bs = openSecret(bob, bobEnc);
await until(() => !!bs.status()?.ready && !!bs.status()?.editable, "bob opens his encrypted doc");
bs.s.content.getText("t").insert(0, "attack at dawn");
await until(async () => (await node.list({ type: "doc_update", prefix: "/doc" })).length > 0 && !bs.status()?.unsent, "bob's edit is sent");
const raw = (await (await fetch(`${url}/api/records?type=doc_update`)).arrayBuffer());
check(!Buffer.from(raw).includes("attack at dawn"), "the node only has ciphertext");
const outsider = openSecret(dave, null);
await until(() => !!outsider.status()?.locked, "others can't read it");

const secretRec = (await node.chain(secret)).current!;
const sealed = await sealTo(node, secretRec.doc!.keys!, bs.s.docKey()!, [carol.key, dave.key]);
check(sealed.missing.length === 1 && b58(sealed.missing[0]) === b58(dave.key), "dave has no encryption key to seal to");
await saveDoc(node, bob, secretRec, { editors: [{ user: carol.key }], keys: sealed.keys });
bs.s.reload();
const cs = openSecret(carol, carolEnc);
await until(() => cs.text() === "attack at dawn", "carol, now an editor, reads it");
cs.s.content.getText("t").insert(0, "carol: ");
await until(() => bs.text() === "carol: attack at dawn", "and writes to it");

for (const s of sessions) s.close();
console.log(failures ? `\n${failures} failed` : "\nall passed");
process.exit(failures ? 1 : 0);
