// Records, IDs and paths come from core/src/lib.rs, compiled to wasm (see wasm/src/lib.rs); main.tsx
// loads it before anything here runs.
import {
  type Draft,
  type Rec,
  b58,
  checkPath,
  checkPrefix,
  claimSignedBytes,
  decodeEntries,
  decodeId,
  decodeRecord,
  decodeRecords,
  encodeRecord,
  pathWithin,
  phrase,
  signedBytes,
  twoWords,
  unb58,
} from "../../wasm/pkg/fedcrdt_wasm.js";

export { type Rec, b58, pathWithin };

/** `node`: the key is a node's (its phrase is "node_word"). */
export type User = { pubkey: string; phrase: string; node: boolean };

async function api<T>(path: string, body?: unknown, method = body === undefined ? "GET" : "POST"): Promise<T> {
  const res = await fetch(
    path,
    body === undefined
      ? { method }
      : { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
  );
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return (res.status === 204 ? null : await res.json()) as T;
}

export const getUsers = () => api<User[]>("/api/users");
export const getUser = (pubkey: string) => api<User>(`/api/users/${pubkey}`);

// ---- user IDs ----
//
// A user's ID is their raw 32-byte Ed25519 public key. In the API, URLs and the UI it's written in
// base58 (`b58`, `decodeId`). Store bytes; base58 and phrases are only for input and output.

/** Whether `s` is an ID: 32 bytes of base58. */
export const isPubkey = (s: string) => decodeId(s) !== undefined;

/** Whether `s` is a record hash: 32 bytes of base58. */
export const isHash = (s: string) => unb58(s)?.length === 32;

/** IDs of keys known to be nodes': this one, and the peers it federates with. */
const nodes = new Set<string>();
export const isNode = (pubkey: string) => nodes.has(pubkey);

/** The node this page talks to, and who owns it. */
export type NodeInfo = { pubkey: string; phrase: string; owners: string[] };
let thisNode: NodeInfo | null = null;
export const getNode = (url = "") => api<NodeInfo>(`${url}/api/node`);

/** Loads this node's info and the nodes it knows of. */
export async function loadNode() {
  const [n, list] = await Promise.all([getNode(), api<string[]>("/api/nodes")]);
  thisNode = n;
  for (const s of list) nodes.add(s);
  return n;
}

/** Whether we own this node (as of the last `loadNode`). */
export const amOwner = () => !!keys && !!thisNode?.owners.includes(keys.pubkey);

/** An ID's "🦬two_words" nickname, or "node_word" for a known node's. */
export function userPhrase(pubkey: string) {
  const pk = decodeId(pubkey);
  if (!pk) throw new Error("not an ID");
  return phrase(pk, nodes.has(pubkey));
}

// ---- bytes ----

const enc = new TextEncoder();
const b64 = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s: string) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

// ---- keys ----
//
// Everything hangs off one secret: the passkey's PRF output for a fixed salt. Only that passkey
// can produce it. From it we derive (HKDF) an Ed25519 keypair, whose public key is the user's ID.
// There is no sign-in: having the keys loaded is all; the
// node has no sessions and never sees the secret or the private keys.

const PRF_SALT = enc.encode("bisonbase keys v1");
const REMEMBER_KEY = "bisonbase-keys";
const RECENT_PASSKEYS_KEY = "bisonbase-recent-passkeys";

/** A passkey that keys were derived from on this device. */
export type Passkey = {
  /** base64url credential ID. */
  credId: string;
  /** Its two_word name (see passkeyName), recomputed from its user handle; null if unknown. */
  name: string | null;
  /** The ID (public key) of the keys it derives. */
  pubkey: string;
  lastUsed: number;
};

type PasskeyIds = Pick<Passkey, "credId" | "name">;

/** user.id length for passkeys whose name is derived from it. */
const NAMED_USER_ID_LEN = 32;

/**
 * A passkey's two_word name, derived from its random user.id. The name in the passkey picker includes it,
 * and since the user.id comes back on every use (as the user handle), we can show the same name here.
 * Null for passkeys whose name we can't reconstruct.
 */
function passkeyName(userId: Uint8Array): string | null {
  if (userId.length === NAMED_USER_ID_LEN) return twoWords(userId);
  // Passkeys from the old server-side version: user.id was a v4 UUID, named "user-" + its first 8 hex digits.
  if (userId.length === 16 && userId[6] >> 4 === 4 && userId[8] >> 6 === 2) {
    return `user-${[...userId.slice(0, 4)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }
  return null;
}

type Keys = {
  secret: Uint8Array<ArrayBuffer>;
  pubkey: string;
  pk: Uint8Array;
  signKey: CryptoKey;
  passkey: Passkey | null;
};
let keys: Keys | null = null;

/** The loaded keys' ID, i.e. the derived public signing key, if keys are loaded. */
export const myPubkey = () => keys?.pubkey ?? null;

/** The passkey the loaded keys came from, if known. */
export const myPasskey = () => keys?.passkey ?? null;

/** PKCS#8 wrapper for a raw 32-byte Ed25519 seed, which is how WebCrypto wants it. */
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** `passkey` is the passkey the secret came from, if known. */
async function deriveKeys(secret: Uint8Array<ArrayBuffer>, passkey: PasskeyIds | null): Promise<Keys> {
  const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const hkdf = (info: string) => ({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: enc.encode(info) });

  const seed = new Uint8Array(await crypto.subtle.deriveBits(hkdf("bisonbase/identity/ed25519"), ikm, 256));
  const pkcs8 = new Uint8Array([...ED25519_PKCS8_PREFIX, ...seed]);
  // Import once extractable just to read the public key out of the JWK, then keep a non-extractable copy.
  const jwk = await crypto.subtle.exportKey(
    "jwk",
    await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]),
  );
  const signKey = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
  seed.fill(0);
  pkcs8.fill(0);

  const pk = unb64(jwk.x!);
  const pubkey = b58(pk);
  return { secret, pubkey, pk, signKey, passkey: passkey && { ...passkey, pubkey, lastUsed: Date.now() } };
}

const sign = async (data: Uint8Array) =>
  new Uint8Array(await crypto.subtle.sign("Ed25519", keys!.signKey, data as Uint8Array<ArrayBuffer>));

/** Sets freshly derived keys, records the passkey's use, and updates the remembered copy if remembering. */
function loadKeys(k: Keys) {
  keys = k;
  if (k.passkey) k.passkey = rememberPasskeyUse(k.passkey);
  if (isRemembering()) setRemember(true);
}

// ---- remembering keys across reloads (opt-in; stored unencrypted in localStorage) ----

export function isRemembering() {
  try {
    return localStorage.getItem(REMEMBER_KEY) !== null;
  } catch {
    return false;
  }
}

export function setRemember(on: boolean) {
  try {
    if (on && keys) localStorage.setItem(REMEMBER_KEY, JSON.stringify({ secret: b64(keys.secret), passkey: keys.passkey }));
    else localStorage.removeItem(REMEMBER_KEY);
  } catch {}
}

/** Loads remembered keys, if any. No prompt. */
export async function restoreKeys() {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(REMEMBER_KEY);
  } catch {}
  if (!stored) return;
  // Older versions stored just the base64url secret.
  const { secret, passkey } = stored.startsWith("{")
    ? (JSON.parse(stored) as { secret: string; passkey: Passkey | null })
    : { secret: stored, passkey: null };
  keys = await deriveKeys(unb64(secret), null);
  if (passkey) keys.passkey = passkey; // keep its last-used time; restoring isn't a passkey use
}

// ---- recently used passkeys on this device (localStorage; just IDs, nothing secret) ----

export function recentPasskeys(): Passkey[] {
  try {
    const list = JSON.parse(localStorage.getItem(RECENT_PASSKEYS_KEY) ?? "[]");
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function saveRecentPasskeys(list: Passkey[]) {
  try {
    localStorage.setItem(RECENT_PASSKEYS_KEY, JSON.stringify(list.slice(0, 20)));
  } catch {}
}

/** Moves the passkey to the top of the recent list; returns its entry. */
function rememberPasskeyUse(p: Passkey): Passkey {
  const list = recentPasskeys();
  // A sign-in may not report the user handle; keep a name learned earlier (e.g. at creation).
  const entry = { ...p, name: p.name ?? list.find((r) => r.credId === p.credId)?.name ?? null };
  saveRecentPasskeys([entry, ...list.filter((r) => r.credId !== p.credId)]);
  return entry;
}

export function forgetRecentPasskey(credId: string) {
  saveRecentPasskeys(recentPasskeys().filter((r) => r.credId !== credId));
}

// ---- passkey ceremonies (entirely client-side) ----

const prfExtension = () => ({ prf: { eval: { first: PRF_SALT } } }) as AuthenticationExtensionsClientInputs;
const prfOutput = (cred: PublicKeyCredential) =>
  (cred.getClientExtensionResults() as any).prf?.results?.first as ArrayBuffer | undefined;

const NO_PRF =
  "This passkey (or browser) doesn't support the PRF extension, so it can't derive your keys. Try another browser, or a passkey stored in a different place.";

/** Asks a passkey for its PRF secret (one prompt). `credId` restricts it to that passkey. */
async function prfFromPasskey(credId?: BufferSource) {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: random(32), // nobody verifies this assertion; we only want the PRF output
      rpId: location.hostname,
      userVerification: "preferred",
      allowCredentials: credId ? [{ type: "public-key", id: credId }] : [],
      extensions: prfExtension(),
    },
  })) as PublicKeyCredential;
  const out = prfOutput(cred);
  if (!out) throw new Error(NO_PRF);
  const userHandle = (cred.response as AuthenticatorAssertionResponse).userHandle;
  const ids: PasskeyIds = {
    credId: b64(cred.rawId),
    name: userHandle ? passkeyName(new Uint8Array(userHandle)) : null,
  };
  return { secret: new Uint8Array(out), ids };
}

/** Derives keys from an existing passkey (one prompt). `credId` (base64url) asks for that specific passkey. */
export async function deriveFromExistingPasskey(credId?: string) {
  try {
    const { secret, ids } = await prfFromPasskey(credId ? unb64(credId) : undefined);
    loadKeys(await deriveKeys(secret, ids));
  } catch (e) {
    throw new Error(
      `Couldn't get your keys from a passkey (${(e as Error).message}). If you don't have one for this site yet, derive keys with a new passkey instead.`,
    );
  }
}

/** Creates a passkey, then derives keys from it: one or two prompts. */
export async function deriveFromNewPasskey() {
  // The two_word part of the name is derived from the random user.id, so we can recompute it on every use.
  const userId = random(NAMED_USER_ID_LEN);
  const words = passkeyName(userId)!;
  const name = `bisonbase ${new Date().toISOString().slice(0, 10)} ${words}`;
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: random(32), // nobody verifies the attestation either
      rp: { id: location.hostname, name: "bisonbase" },
      user: { id: userId, name, displayName: name },
      pubKeyCredParams: [-8, -7, -257].map((alg) => ({ type: "public-key" as const, alg })),
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "preferred" },
      // Some authenticators return the PRF output right away, saving the second prompt.
      extensions: prfExtension(),
    },
  })) as PublicKeyCredential;
  const secret = prfOutput(cred);
  if (!secret && (cred.getClientExtensionResults() as any).prf?.enabled === false) {
    throw new Error(`The passkey was created, but it can't be used: ${NO_PRF}`);
  }
  const secretBytes = secret ? new Uint8Array(secret) : (await prfFromPasskey(cred.rawId)).secret;
  loadKeys(await deriveKeys(secretBytes, { credId: b64(cred.rawId), name: words }));
}

export function forgetKeys() {
  keys = null;
  setRemember(false);
}

// ---- records ----
//
// Everything users write is a record: a dCBOR map signed by its author, identified by its hash. Paths
// are only categories: any number of records share one. An edit or delete is a new record naming the
// version it replaces (`edits`); a record and its edits form a chain, linked to by its first record's
// hash. The node stores and returns records exactly as signed; the wasm core decodes and checks them
// here in the browser, so nothing depends on trusting the node.

/** A record as shown: its decoded IDs, its chain, and whether it checks out. */
export type Post = {
  rec: Rec;
  /** This version's hash (base58). */
  hash: string;
  /** Its chain's first record's hash (base58): the link that stays the same across edits. */
  root: string;
  author: User;
  /** Who wrote the chain's first version, if known: who may edit it, besides the node's owners. */
  by: User | null;
  /** How many versions its chain has. */
  versions: number;
  /** Whether its signature verified, in this browser. */
  verified: boolean;
  /** The text, if it's a plain post. */
  text: string | null;
  /** For grant records: who may write, and where. */
  grant?: { path: string; grantees: User[] | "anyone" };
  /** For federate records: which node gets pushed what. `types` and `paths` are null for all. */
  federate?: { peer: User; url: string; types: string[] | null; paths: string[] | null };
  /** For a node record: its URL. */
  nodeUrl?: string;
  /** For an owner record: who. */
  ownerUser?: User;
};

const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Compares bytes like the node does (memcmp, then length). */
const bytesCmp = (a: Uint8Array, b: Uint8Array) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};

/** Trims and NFC-normalizes a path someone typed, then checks it (see check_path in core/src/lib.rs).
 * Throws if it's bad. `prefix`: "/" is fine too. */
export function normalizePath(input: string, prefix = false) {
  const path = input.trim().normalize("NFC");
  if (prefix) checkPrefix(path);
  else checkPath(path);
  return path;
}

const toUser = (pk: Uint8Array): User => {
  const pubkey = b58(pk);
  return { pubkey, phrase: userPhrase(pubkey), node: nodes.has(pubkey) };
};

export function viewPost(rec: Rec, chain?: { root: Uint8Array; by?: Uint8Array; versions: number }): Post {
  const f = rec.federate;
  const g = rec.grant;
  return {
    grant: g && { path: g.path, grantees: g.grantees === "anyone" ? "anyone" : g.grantees.map(toUser) },
    federate: f && { peer: toUser(f.peer), url: f.url, types: f.types ?? null, paths: f.paths ?? null },
    nodeUrl: rec.nodeUrl,
    ownerUser: rec.ownerUser && toUser(rec.ownerUser),
    rec,
    hash: b58(rec.hash),
    root: b58(chain?.root ?? rec.hash),
    author: toUser(rec.author),
    by: chain ? (chain.by ? toUser(chain.by) : null) : toUser(rec.author),
    versions: chain?.versions ?? 1,
    verified: rec.verified,
    text: rec.text ?? null,
  };
}

/** The current version of each live record, newest first; optionally only those first written by
 * `author`, of one `type`, or at or under `prefix`. */
export async function getPosts(q: { author?: string; type?: string; prefix?: string } = {}) {
  const params = new URLSearchParams(Object.entries(q).filter((e): e is [string, string] => !!e[1]));
  const res = await fetch(`/api/records?${params}`);
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return decodeEntries(new Uint8Array(await res.arrayBuffer())).map((e) => viewPost(e.rec, e));
}

/** A record's whole chain: every version, oldest first; the current one; and the tombstone, if it was deleted. */
export type Chain = { versions: Post[]; current: Post | null; deleted: Post | null };

/** The chain that the record with this hash (base58) is in. */
export async function getChain(hash: string): Promise<Chain> {
  const res = await fetch(`/api/records/${hash}`);
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  const recs = decodeRecords(new Uint8Array(await res.arrayBuffer()));
  // The first record: the one whose `edits` isn't here.
  const root = recs.find((r) => !r.edits || !recs.some((o) => bytesEqual(o.hash, r.edits!))) ?? recs[0];
  const chain = { root: root.hash, by: root.edits ? undefined : root.author, versions: recs.length };
  const versions = recs.map((r) => viewPost(r, chain));
  const newest = (a: Post, b: Post) => a.rec.version - b.rec.version || bytesCmp(a.rec.hash, b.rec.hash);
  const live = versions.filter((p) => p.rec.type !== "tombstone").sort(newest);
  return { versions, current: live.at(-1) ?? null, deleted: versions.find((p) => p.rec.type === "tombstone") ?? null };
}

/** Signs `d` (as us) and stores it. Returns its hash (base58). */
async function putRec(d: Draft) {
  const signature = await sign(signedBytes(d));
  const res = await fetch("/api/records", {
    method: "POST",
    headers: { "content-type": "application/cbor" },
    body: encodeRecord(d, signature) as Uint8Array<ArrayBuffer>,
  });
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return ((await res.json()) as { hash: string }).hash;
}

/** A version newer than both the clock and `prev`, so quick successive edits still go through. */
const nextVersion = (prev = 0) => Math.max(Date.now(), prev + 1);

// ---- grants: who may write where ----
//
// Owners may write anywhere. They let others write at or under a path with grant records, at /node/grants.

/** Where we may write, from the grants that name us (or anyone). */
export async function myGrants(): Promise<string[]> {
  if (!keys) return [];
  const me = keys.pubkey;
  return (await getPosts({ type: "grant", prefix: "/node/grants" }))
    .filter((p) => p.verified && p.grant && (p.grant.grantees === "anyone" || p.grant.grantees.some((u) => u.pubkey === me)))
    .map((p) => p.grant!.path);
}

/** Parses IDs (base58) separated by spaces, commas or new lines, or "anyone". */
function parseGrantees(s: string): Uint8Array[] | "anyone" {
  if (s.trim().toLowerCase() === "anyone") return "anyone";
  const ids = s.split(/[\s,]+/).filter(Boolean);
  if (!ids.length) throw new Error("Say who: IDs, or \"anyone\".");
  return ids.map((id) => {
    const pk = decodeId(id);
    if (!pk) throw new Error(`${id} isn't an ID (32 bytes of base58).`);
    return pk;
  });
}

/** Lets `grantees` (IDs, or "anyone") write at or under `path` ("/" for everywhere). Owners only. Returns the grant's hash. */
export async function makeGrant(grantees: string, path: string) {
  if (!keys) throw new Error("Sign in first.");
  const data = { path: normalizePath(path, true), grantees: parseGrantees(grantees) };
  return putRec({ author: keys.pk, path: "/node/grants", version: nextVersion(), type: "grant", data });
}

/** Makes `user` (an ID) an owner of this node. Owners only. */
export async function addOwner(user: string) {
  if (!keys) throw new Error("Sign in first.");
  const u = decodeId(user.trim());
  if (!u) throw new Error("That isn't an ID (32 bytes of base58).");
  return putRec({ author: keys.pk, path: "/node/owner", version: nextVersion(), type: "owner", data: { user: u } });
}

// ---- writing posts ----

/** Whether we may edit or delete this record: we wrote it, or we own this node. */
export const canEdit = (p: Post) =>
  !!keys && p.rec.type !== "node" && (amOwner() || (p.by?.pubkey === keys.pubkey && !pathWithin(p.rec.path, "/node")));

/** Creates a post at `path`, or edits `existing` (possibly moving it to `path`). Returns its hash. */
export async function putPost(text: string, path: string, existing?: Post) {
  if (!keys) throw new Error("Sign in first.");
  return putRec({
    author: keys.pk,
    path: normalizePath(path),
    version: nextVersion(existing?.rec.version),
    type: "post",
    edits: existing?.rec.hash,
    data: text.trim(),
  });
}

/** Deletes a record, with a signed tombstone naming its current version. */
export async function deletePost(p: Post) {
  if (!keys) throw new Error("Sign in first.");
  await putRec({ author: keys.pk, path: p.rec.path, version: nextVersion(p.rec.version), type: "tombstone", edits: p.rec.hash, data: null });
}

/** A post with a made-up signature, to show what a bad one looks like. */
export function forgedPost(): Post {
  const pk = decodeId("4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS")!;
  const draft: Draft = {
    author: pk,
    path: "/demo/forged",
    version: Date.now(),
    type: "post",
    data: "This post was added client-side with a made-up signature, so it should show as a bad signature.",
  };
  return viewPost(decodeRecord(encodeRecord(draft, new Uint8Array(64))));
}

// ---- this node, and federation ----
//
// Each node has its own key. Its owner claims it once with a one-time link (printed by the node); owners
// may then add other owners, grants, and "federate" records naming peer nodes to push records to. All
// of those live under /node and are never federated. See core/src/lib.rs.

/** Claims this node as its first owner (us), with the token from its claim link. Returns the node's ID. */
export async function claimNode(token: string) {
  if (!keys) throw new Error("Sign in first.");
  const node = await getNode();
  const t = unb58(token);
  if (!t) throw new Error("This claim link is broken: its token isn't base58.");
  const signature = await sign(claimSignedBytes(decodeId(node.pubkey)!, t));
  await api("/api/claim", { token, user: keys.pubkey, signature: b58(signature) });
  await loadNode();
  return node.pubkey;
}

/** Has this node push records to the node at `url`: those of the given types (comma- or space-separated;
 * none for all) at or under the given paths (one per line; none for all). Owners only. Returns the record's hash. */
export async function putFederate(url: string, types: string, paths: string) {
  if (!keys) throw new Error("Sign in first.");
  url = url.trim().replace(/\/+$/, "");
  if (!/^https?:\/\/\S+$/.test(url)) throw new Error("Enter the other node's http:// or https:// URL.");
  const peer = await getNode(url).then(
    (s) => s.pubkey,
    (e) => {
      throw new Error(`Couldn't reach a node at ${url}: ${e.message}`);
    },
  );
  if (peer === thisNode?.pubkey) throw new Error("That's this node.");
  const t = types.split(/[\s,]+/).filter(Boolean);
  const p = paths.split("\n").map((s) => s.trim()).filter(Boolean).map((s) => normalizePath(s, true));
  nodes.add(peer);
  return putRec({
    author: keys.pk,
    path: "/node/federate",
    version: nextVersion(),
    type: "federate",
    data: { peer: decodeId(peer)!, url, ...(t.length && { types: t }), ...(p.length && { paths: p }) },
  });
}
