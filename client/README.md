# bisonbase client

What any app needs to keep its data on bisonbase nodes: records, CRDT docs, keys, and encryption. The node
checks signatures and permissions, stores and federates; it never looks inside your data. Everything that
comes back from a node is checked here, by the same Rust core the node uses (compiled to wasm), so nothing
depends on trusting the node.

```ts
import { NodeClient, init, keySigner, newKeyPair, openDoc } from "./client/src/index.ts";
import { yjs } from "./client/src/yjs.ts";

await init(); // loads the wasm core (in Node: `init(bytesOfTheWasmFile)`)
const node = new NodeClient("https://node.example");
```

## Records of your own types

An app's types have a "." in their name (`todo.item`, `com.example.board`); their data is any plain JS
value: maps with text keys, arrays, text, numbers, BigInts, booleans, null, and Uint8Array for bytes. A
record is at most 1 MiB. Writing needs a grant covering its path, from the node's owners.

```ts
const hash = await node.write(signer, { path: "/todo/1", version: Date.now(), type: "todo.item", data: { title: "milk", done: false } });
const items = await node.list({ type: "todo.item", prefix: "/todo" }); // each: { rec, root, by, versions }
await node.write(signer, { path: "/todo/1", version: Date.now(), type: "todo.item", edits: items[0].rec.hash, data: { title: "milk", done: true } });
```

Each record and its edits form a chain; its current version is the newest (last writer wins), and only its
author (or the node's owners) may edit or delete it. `node.stream({ prefix })` streams records as they arrive.

## CRDT docs

A doc is a "doc" record (title, editors, `format`, `schema`) plus "doc_update" records holding the
format's updates, which merge in any order. `openDoc` keeps a doc's content in sync, for any CRDT library
you write an `Adapter` for (`yjs.ts` is one): it checks every update's author against the doc's editors,
batches your edits, keeps content and unsent edits in a `Store` if you give it one, and writes snapshots now
and then so readers can start from one.

```ts
import { createDoc } from "./client/src/index.ts";
const doc = await createDoc(node, signer, { path: "/board", format: "yjs", schema: "myapp.board" });
const sync = openDoc({ node, hash: doc, adapter: yjs, signer, onStatus: (s) => render(s) });
sync.content.getMap("cards").set("a", "hello"); // sent as an update
```

## Signing for a user: the connect flow

An app makes its own key and asks the user, on their bisonbase page, to let it sign for them:

```ts
const key = await newKeyPair(); // keep it, e.g. in IndexedDB: its private half can't be extracted
location.href = connectUrl("https://bisonbase.example", { key: key.publicKey, name: "My app", types: ["todo.item"], paths: ["/todo"], returnTo: location.href });
// …and once they're back:
const r = connectResult(location.hash); // { user, delegation, node }
const signer = keySigner(key.privateKey, key.publicKey, { user: r.user, delegation: r.delegation });
```

Records it signs carry `as: { user, delegation }` and count as the user's. The user can revoke it at
`/connect`; readers then stop trusting everything that key signed.

## Encrypted docs

Pass `encryption` (the user's X25519 keys) to `createDoc` and `openDoc`: the doc's content key is sealed to
each editor's published encryption key (`publishEncKey`, `sealTo`), and updates and snapshots are encrypted
with it. The title isn't encrypted. Removing an editor doesn't take back what they could already read.
Apps signing for a user don't have the user's encryption keys.

## Tests

`npm run test:client` starts a node on a fresh database and runs `test/integration.ts` against it.
