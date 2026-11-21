// This app's side of things: passkeys and keys, and what its pages show and write. Records, nodes, docs and
// encryption come from the client library (client/src), which any app can use; main.tsx loads its wasm
// core before anything here runs.
import {
  type ConnectRequest,
  type Draft,
  type EncKeys,
  type NewRecord,
  type Rec,
  type Signer,
  type Who,
  NodeClient,
  b58,
  checkPath,
  checkPrefix,
  claimSignedBytes,
  createDoc as createDocRecord,
  decodeId,
  decodeRecord,
  delegatePath,
  encKeysFromSeed,
  encodeRecord,
  joinLive,
  keySigner,
  nextVersion,
  pathWithin,
  phrase,
  publishEncKey,
  readSignedBytes,
  saveDoc as saveDocRecord,
  sealTo,
  twoWords,
  unb58,
} from "../../client/src/index.ts";
import {
  type PasskeyIds,
  b64,
  createPasskey,
  deriveBits,
  identityKey,
  prfFromPasskey,
  random,
  signIn,
  signOut,
  takeHandoff,
  unb64,
} from "./passkey.ts";

export { type Rec, b58, pathWithin };

/** The node this page talks to: its own origin. Owners' reads carry their read token (see `readHeaders`). */
export const node = new NodeClient("", () => readHeaders());

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

/** The public key for a base58 ID; throws if it isn't one. */
export function decodeIdOrThrow(id: string) {
  const pk = decodeId(id);
  if (!pk) throw new Error("That isn't an ID (32 bytes of base58).");
  return pk;
}

/** Whether `s` is an ID: 32 bytes of base58. */
export const isPubkey = (s: string) => decodeId(s) !== undefined;

/** Whether `s` is a record hash: 32 bytes of base58. */
export const isHash = (s: string) => unb58(s)?.length === 32;

/** IDs of keys known to be nodes': this one, and the peers it federates with. */
const nodes = new Set<string>();
export const isNode = (pubkey: string) => nodes.has(pubkey);

/** The node this page talks to, and who owns it. */
export type NodeInfo = { pubkey: string; phrase: string; owners: string[]; private: boolean };
let thisNode: NodeInfo | null = null;
export const getNode = (url = "") => api<NodeInfo>(`${url}/api/node`);

/** Loads this node's info and the nodes it knows of. */
export async function loadNode() {
  const [n, list] = await Promise.all([getNode(), api<string[]>("/api/nodes")]);
  thisNode = n;
  for (const s of list) nodes.add(s);
  await loadClaims();
  return n;
}

/** Who claimed each claim on this node (by its hash, base58): their ID, or null while unclaimed. */
const claims = new Map<string, string | null>();

/** Loads who claimed which claim, for showing owner, grant and doc records that name claims. */
export async function loadClaims() {
  const list = await getPosts({ type: "claim" });
  claims.clear();
  for (const c of list) if (c.verified && c.claim) claims.set(c.root, c.claim.claimedBy?.pubkey ?? null);
}

/** Whether we own this node (as of the last `loadNode`). */
export const amOwner = () => !!keys && !!thisNode?.owners.includes(keys.pubkey);

/** An ID's "🦬two_words" nickname, or "node_word" for a known node's. */
export function userPhrase(pubkey: string) {
  const pk = decodeId(pubkey);
  if (!pk) throw new Error("not an ID");
  return phrase(pk, nodes.has(pubkey));
}


// ---- keys ----
//
// Everything hangs off one secret: the passkey's PRF output for a fixed salt. Only that passkey
// can produce it. From it we derive (HKDF) an Ed25519 keypair, whose public key is the user's ID (see
// passkey.ts). There is no sign-in: having the keys loaded is all; the node has no sessions and never sees
// the secret or the private keys. (A private node does want an access token: see `renewAccess`.)

/** The credential ID of the passkey whose saved keys to load on startup. */
const CURRENT_KEY = "bisonbase-keys";
const RECENT_PASSKEYS_KEY = "bisonbase-recent-passkeys";

/** A passkey that keys were derived from on this device. */
export type Passkey = {
  /** base64url credential ID. */
  credId: string;
  /** Its two_word name (see passkeyName in passkey.ts), recomputed from its user handle; null if unknown. */
  name: string | null;
  /** The ID (public key) of the keys it derives. */
  pubkey: string;
  lastUsed: number;
};


type Keys = {
  secret: Uint8Array<ArrayBuffer>;
  pubkey: string;
  pk: Uint8Array;
  signer: Signer;
  /** For encrypted docs: their keys get sealed to `enc.publicKey`, published as our enckey. */
  enc: EncKeys;
  passkey: Passkey | null;
};
let keys: Keys | null = null;

/** The loaded keys' ID, i.e. the derived public signing key, if keys are loaded. */
export const myPubkey = () => keys?.pubkey ?? null;

/** What signs our records, if keys are loaded. */
export const mySigner = () => keys?.signer ?? null;

/** Our X25519 keys, for encrypted docs, if keys are loaded. */
export const myEncKeys = () => keys?.enc ?? null;

/** The passkey the loaded keys came from, if known. */
export const myPasskey = () => keys?.passkey ?? null;


/** `passkey` is the passkey the secret came from, if known. */
async function deriveKeys(secret: Uint8Array<ArrayBuffer>, passkey: PasskeyIds | null): Promise<Keys> {
  const { signKey, pk } = await identityKey(secret);
  const encSeed = await deriveBits(secret, "bisonbase/encryption/x25519");
  const encKeys = await encKeysFromSeed(encSeed);
  encSeed.fill(0);

  const pubkey = b58(pk);
  return { secret, pubkey, pk, signer: keySigner(signKey, pk), enc: encKeys, passkey: passkey && { ...passkey, pubkey, lastUsed: Date.now() } };
}

const sign = (data: Uint8Array) => keys!.signer.sign(data);

/**
 * Sets freshly derived keys and records the passkey's use. Their secret is saved if it already was,
 * or if the keys they replace were saved: staying signed in carries over to the next passkey.
 */
function loadKeys(k: Keys) {
  const save = isRemembering() || (!!k.passkey && !!findStored(k.passkey.credId)?.secret);
  keys = k;
  if (k.passkey) k.passkey = rememberPasskeyUse(k.passkey);
  setRemember(save);
}

// ---- recently used passkeys on this device, and optionally their keys (localStorage) ----
//
// Each passkey whose keys we derived gets an entry: just IDs, plus, if "stay signed in" was on for it,
// its secret, stored unencrypted. CURRENT_KEY names the one to load on startup (only ever a saved one).

/** A recent passkey as stored. */
type StoredPasskey = Passkey & { secret?: string };

/** A recent passkey, and whether its keys are saved (so using it needs no prompt). */
export type RecentPasskey = Passkey & { saved: boolean };

const isStoredPasskey = (p: any): p is StoredPasskey =>
  typeof p === "object" && p !== null &&
  typeof p.credId === "string" &&
  (p.name === null || typeof p.name === "string") &&
  typeof p.pubkey === "string" && isPubkey(p.pubkey) &&
  typeof p.lastUsed === "number" &&
  (p.secret === undefined || typeof p.secret === "string");

/** The stored list. Entries an older version wrote are dropped (and the list saved without them). */
function storedPasskeys(): StoredPasskey[] {
  try {
    const s = localStorage.getItem(RECENT_PASSKEYS_KEY);
    if (s === null) return [];
    let list: unknown;
    try {
      list = JSON.parse(s);
    } catch {}
    if (!Array.isArray(list)) {
      console.warn(`Dropping outdated localStorage item ${RECENT_PASSKEYS_KEY}`);
      localStorage.removeItem(RECENT_PASSKEYS_KEY);
      return [];
    }
    const ok = list.filter(isStoredPasskey);
    if (ok.length < list.length) {
      console.warn(`Dropping ${list.length - ok.length} outdated entries of localStorage item ${RECENT_PASSKEYS_KEY}`);
      saveStoredPasskeys(ok);
    }
    return ok;
  } catch {
    return [];
  }
}

function saveStoredPasskeys(list: StoredPasskey[]) {
  try {
    localStorage.setItem(RECENT_PASSKEYS_KEY, JSON.stringify(list.slice(0, 20)));
  } catch {}
}

const findStored = (credId: string) => storedPasskeys().find((p) => p.credId === credId);

/** Without the secret. */
const ids = ({ secret, ...p }: StoredPasskey): Passkey => p;

export function recentPasskeys(): RecentPasskey[] {
  return storedPasskeys().map((p) => ({ ...ids(p), saved: p.secret !== undefined }));
}

/** Moves the passkey to the top of the recent list, keeping any saved secret; returns its entry. */
function rememberPasskeyUse(p: Passkey): Passkey {
  const list = storedPasskeys();
  const old = list.find((r) => r.credId === p.credId);
  // A sign-in may not report the user handle; keep a name learned earlier (e.g. at creation).
  const entry = { ...p, name: p.name ?? old?.name ?? null };
  saveStoredPasskeys([{ ...entry, secret: old?.secret }, ...list.filter((r) => r.credId !== p.credId)]);
  return entry;
}

/** Removes the passkey from the recent list, along with its saved keys. */
export function forgetRecentPasskey(credId: string) {
  saveStoredPasskeys(storedPasskeys().filter((r) => r.credId !== credId));
}

function setCurrent(credId: string | null) {
  try {
    if (credId) localStorage.setItem(CURRENT_KEY, credId);
    else localStorage.removeItem(CURRENT_KEY);
  } catch {}
}

/** Whether the loaded keys are saved on this device. */
export function isRemembering() {
  const credId = keys?.passkey?.credId;
  return !!credId && !!findStored(credId)?.secret;
}

/** Saves the loaded keys on this device (and loads them on startup), or deletes the saved copy. */
export function setRemember(on: boolean) {
  const p = keys?.passkey;
  if (!p) return;
  const secret = on ? b64(keys!.secret) : undefined;
  saveStoredPasskeys(storedPasskeys().map((r) => (r.credId === p.credId ? { ...r, secret } : r)));
  setCurrent(on ? p.credId : null);
}

/** Loads a recent passkey's saved keys, if they're saved and still derive its ID. No prompt. */
async function loadSaved(credId: string): Promise<boolean> {
  const p = findStored(credId);
  if (!p?.secret) return false;
  const k = await deriveKeys(unb64(p.secret), null);
  if (k.pubkey !== p.pubkey) {
    console.warn(`Dropping saved keys for passkey ${credId}: they don't derive its ID`);
    forgetRecentPasskey(credId);
    return false;
  }
  k.passkey = ids(p); // keep its last-used time; loading saved keys isn't a passkey use
  keys = k;
  setCurrent(credId);
  return true;
}

/** Loads the keys the private node's sign-in page just derived (see `handOff`), else those saved to load
 * on startup, if any. No prompt. */
export async function restoreKeys() {
  const handoff = takeHandoff();
  if (handoff) return loadKeys(await deriveKeys(handoff.secret, handoff.ids));
  let credId: string | null = null;
  try {
    credId = localStorage.getItem(CURRENT_KEY);
  } catch {}
  if (credId && !(await loadSaved(credId))) setCurrent(null);
}

/** Loads a recent passkey's keys: its saved ones if any (no prompt), else from the passkey (one prompt). */
export async function loadPasskey(credId: string) {
  if (!(await loadSaved(credId))) await deriveFromExistingPasskey(credId);
}

// ---- passkey ceremonies (entirely client-side) ----

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
  const { secret, ids } = await createPasskey();
  loadKeys(await deriveKeys(secret, ids));
}

/** Unloads the keys, deleting their saved copy. Other passkeys' saved keys stay. On a private node, also
 * signs out of it, back to its sign-in page. */
export async function forgetKeys() {
  setRemember(false);
  keys = null;
  // What the service worker kept (public/sw.js) may include private records we read as an owner.
  await caches?.delete(OFFLINE_CACHE).catch(() => {});
  if (thisNode?.private) {
    await signOut();
    location.reload();
  }
}

/** Who we last signed in to this private node as, this page load. */
let accessFor: string | null = null;

/** On a private node, signs in again with the loaded keys, once per page load and keys, so that the
 * access cookie (30 days) keeps up while the app is used. Quietly does nothing if they have no access. */
export async function renewAccess() {
  if (!keys || !thisNode?.private || accessFor === keys.pubkey) return;
  accessFor = keys.pubkey;
  await signIn(sign, keys.pubkey).catch((e) => console.warn("Couldn't renew access:", e));
}

/** The service worker's cache: the app and the API's latest answers, for when the node can't be reached. */
const OFFLINE_CACHE = "bisonbase-offline";

// ---- records ----
//
// Everything users write is a record: a dCBOR map signed by its author, identified by its hash. Paths
// are only categories: any number of records share one. An edit or delete is a new record naming the
// version it replaces (`edits`); a record and its edits form a chain, linked to by its first record's
// hash. The node stores and returns records exactly as signed; the wasm core decodes and checks them
// here in the browser, so nothing depends on trusting the node.

/** A user as an owner or grant record names them: `user` directly, or via `claim` (a claim's hash,
 * base58), in which case `user` is whoever claimed it, or null while it's unclaimed. */
export type Party = { user: User | null; claim?: string };

/** A record as shown: its decoded IDs, its chain, and whether it checks out. */
export type Post = {
  rec: Rec;
  /** This version's hash (base58). */
  hash: string;
  /** Its chain's first record's hash (base58): the link that stays the same across edits. */
  root: string;
  /** Whose it is: its principal (see `as` in core/src/lib.rs). */
  author: User;
  /** Who signed it, if not its author: a key signing for them, under their delegation. */
  signedBy: User | null;
  /** Whose the chain's first version is, if known: who may edit it, besides the node's owners. */
  by: User | null;
  /** How many versions its chain has. */
  versions: number;
  /** Whether its signature verified, in this browser. */
  verified: boolean;
  /** The text, if it's a plain post. */
  text: string | null;
  /** For grant records: who may write, and where. */
  grant?: { path: string; grantees: Party[] | "anyone" };
  /** For peer records: which node gets pushed what. `types` and `paths` are null for all. */
  peer?: { node: User; url: string; types: string[] | null; paths: string[] | null };
  /** For claim records: who claimed it, if anyone has yet. */
  claim?: { claimedBy: User | null };
  /** For a node record: its URL. */
  nodeUrl?: string;
  /** For an owner record: who. */
  owner?: Party;
  /** For an access record: who may get into this node, if it's private. */
  access?: Party;
  /** For a doc: its title, who may edit it besides its author (`by`), what it holds, and whether it's encrypted. */
  doc?: { title: string; editors: Party[]; format: string; schema: string; encrypted: boolean };
  /** For a delegation: the key it lets sign for its author, what it's called, and what it covers. */
  delegate?: { key: string; name: string; paths: string[] | null; types: string[] | null; expires: number | null };
};

const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);


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

const toParty = (w: Who): Party => {
  if ("user" in w) return { user: toUser(w.user) };
  const claim = b58(w.claim);
  const user = claims.get(claim);
  return { user: user ? toUser(decodeId(user)!) : null, claim };
};

export function viewPost(rec: Rec, chain?: { root: Uint8Array; by?: Uint8Array; versions: number }): Post {
  const p = rec.peer;
  const g = rec.grant;
  return {
    grant: g && { path: g.path, grantees: g.grantees === "anyone" ? "anyone" : g.grantees.map(toParty) },
    peer: p && { node: toUser(p.node), url: p.url, types: p.types ?? null, paths: p.paths ?? null },
    claim: rec.claim && { claimedBy: rec.claim.user ? toUser(rec.claim.user) : null },
    nodeUrl: rec.nodeUrl,
    owner: rec.owner && toParty(rec.owner),
    access: rec.access && toParty(rec.access),
    doc: rec.doc && {
      title: rec.doc.title,
      editors: rec.doc.editors.map(toParty),
      format: rec.doc.format,
      schema: rec.doc.schema,
      encrypted: !!rec.doc.keys,
    },
    delegate: rec.delegate && {
      key: b58(rec.delegate.key),
      name: rec.delegate.name,
      paths: rec.delegate.paths ?? null,
      types: rec.delegate.types ?? null,
      expires: rec.delegate.expires ?? null,
    },
    rec,
    hash: b58(rec.hash),
    root: b58(chain?.root ?? rec.hash),
    author: toUser(rec.principal),
    signedBy: rec.as ? toUser(rec.author) : null,
    by: chain ? (chain.by ? toUser(chain.by) : null) : toUser(rec.principal),
    versions: chain?.versions ?? 1,
    verified: rec.verified,
    text: rec.text ?? null,
  };
}

/** The current version of each live record, newest first; optionally only those first written by
 * `author`, of one `type`, or at or under `prefix`. */
export async function getPosts(q: { author?: string; type?: string; prefix?: string } = {}) {
  return (await node.list(q)).map((e) => viewPost(e.rec, e));
}

/** A record's whole chain: every version, oldest first; the current one; and the tombstone, if it was deleted. */
export type Chain = { versions: Post[]; current: Post | null; deleted: Post | null };

/** The chain that the record with this hash (base58) is in. */
export async function getChain(hash: string): Promise<Chain> {
  const c = await node.chain(hash);
  const chain = { root: unb58(c.root)!, by: c.by ? decodeId(c.by) : undefined, versions: c.versions.length };
  const view = (r: Rec) => viewPost(r, chain);
  return { versions: c.versions.map(view), current: c.current && view(c.current), deleted: c.deleted && view(c.deleted) };
}

// ---- reading private records ----
//
// Only this node's owners may read private records. The node has no sessions, so owners send a read
// token with each read: their ID, an expiry, and their signature over both (see read_signed_bytes in
// core/src/lib.rs), good on this node only. We sign one now and then, and only while we're an owner.

const READ_TOKEN_MS = 10 * 60 * 1000;
let readToken: { header: string; pubkey: string; node: string; expires: number } | null = null;

/** Headers for reading records: our read token, if we own this node. */
async function readHeaders(): Promise<Record<string, string>> {
  if (!keys || !thisNode || !amOwner()) return {};
  const t = readToken;
  if (t && t.pubkey === keys.pubkey && t.node === thisNode.pubkey && t.expires - Date.now() > 60_000) {
    return { authorization: t.header };
  }
  const expires = Date.now() + READ_TOKEN_MS;
  const signature = await sign(readSignedBytes(decodeId(thisNode.pubkey)!, BigInt(expires)));
  const header = `Bisonbase ${keys.pubkey}.${expires}.${b58(signature)}`;
  readToken = { header, pubkey: keys.pubkey, node: thisNode.pubkey, expires };
  return { authorization: header };
}

/** Signs `d` (as us) and stores it; public unless it says otherwise. Returns its hash (base58). */
async function putRec(draft: NewRecord) {
  if (!keys) throw new Error("Sign in first.");
  return node.write(keys.signer, draft);
}

// ---- grants, owners and claims ----
//
// Owners may write anywhere. They let others write at or under a path with grant records. Owner and grant
// records name users by ID, or name a claim: a one-time link for someone not known yet. All of these
// live under /node.

export const OWNER_PATH = "/node/owner";
export const GRANT_PATH = "/node/grant";
export const ACCESS_PATH = "/node/access";
export const PEER_PATH = "/node/peer";
export const CLAIM_PATH = "/node/claim";

/** Whether a grant's grantees include `pubkey` (or anyone, if `anyone`). */
export const grantNames = (p: Post, pubkey: string, anyone = true) =>
  p.verified && !!p.grant && (p.grant.grantees === "anyone" ? anyone : p.grant.grantees.some((g) => g.user?.pubkey === pubkey));

/** Where we may write, from the grants that name us (or anyone). */
export async function myGrants(): Promise<string[]> {
  if (!keys) return [];
  const me = keys.pubkey;
  return (await getPosts({ type: "grant", prefix: GRANT_PATH })).filter((p) => grantNames(p, me)).map((p) => p.grant!.path);
}

/** Who a form names: a user (ID), a new claim link, or (for grants) anyone. */
export type Choice = { kind: "user"; id: string } | { kind: "claim" } | { kind: "anyone" };

/** A new claim, made by us, to name in an owner, grant or doc record. It goes at `path`: owners' under
 * /node, others' wherever they may write. */
async function newClaim(path = CLAIM_PATH) {
  const token = random(32);
  const tokenHash = new Uint8Array(await crypto.subtle.digest("SHA-256", token));
  const hash = await putRec({ path, version: nextVersion(), type: "claim", data: { tokenHash } });
  return { who: { claim: unb58(hash)! } as Who, link: `${location.origin}/claim#${b58(token)}` };
}

/** The record data naming `c`, and the claim link, if it made one. */
async function choose(c: Choice): Promise<{ who: Who; link?: string }> {
  if (c.kind === "claim") return newClaim();
  if (c.kind === "anyone") throw new Error("Only a grant can name anyone.");
  const pk = decodeId(c.id.trim());
  if (!pk) throw new Error("That isn't an ID (32 bytes of base58).");
  return { who: { user: pk } };
}

/** A record we wrote (its hash), and the claim link it names, if it made one. */
export type Written = { hash: string; link?: string };

/** Lets `c` write at or under `path` ("/" for everywhere). Owners only. */
export async function makeGrant(c: Choice, path: string): Promise<Written> {
  if (!keys) throw new Error("Sign in first.");
  path = normalizePath(path, true);
  const { who, link } = c.kind === "anyone" ? { who: null } : await choose(c);
  const data = { path, grantees: who ? [who] : ("anyone" as const) };
  return { hash: await putRec({ path: GRANT_PATH, version: nextVersion(), type: "grant", data }), link };
}

/** Makes `c` an owner of this node. Owners only. */
export async function addOwner(c: Choice): Promise<Written> {
  if (!keys) throw new Error("Sign in first.");
  const { who, link } = await choose(c);
  return { hash: await putRec({ path: OWNER_PATH, version: nextVersion(), type: "owner", data: who }), link };
}

/** Lets `c` into this node, if it's private. Owners only. */
export async function addAccess(c: Choice): Promise<Written> {
  if (!keys) throw new Error("Sign in first.");
  const { who, link } = await choose(c);
  return { hash: await putRec({ path: ACCESS_PATH, version: nextVersion(), type: "access", data: who }), link };
}

/** What a claim link's token is for: its claim (null if this node has none with that token), and the
 * owner, access, grant and doc records that name it. */
export async function findClaim(token: string) {
  const t = unb58(token);
  if (!t) throw new Error("This claim link is broken: its token isn't base58.");
  const tokenHash = new Uint8Array(await crypto.subtle.digest("SHA-256", t as Uint8Array<ArrayBuffer>));
  const [claims, records, docs] = await Promise.all([getPosts({ type: "claim" }), getPosts({ prefix: "/node" }), getPosts({ type: "doc" })]);
  const claim = claims.find((p) => p.verified && p.rec.claim && bytesEqual(p.rec.claim.tokenHash, tokenHash)) ?? null;
  const names = (w?: Party) => !!claim && w?.claim === claim.root;
  return {
    claim,
    owner: records.some((p) => p.verified && names(p.owner)),
    access: records.some((p) => p.verified && names(p.access)),
    grants: records.filter((p) => p.verified && p.grant?.grantees !== "anyone" && p.grant?.grantees.some(names)).map((p) => p.grant!.path),
    docs: docs.filter((p) => p.verified && p.doc?.editors.some(names)),
  };
}

/** Claims the claim with this token (from its link) as us. */
export async function redeemClaim(token: string) {
  if (!keys) throw new Error("Sign in first.");
  const node = await getNode();
  const t = unb58(token);
  if (!t) throw new Error("This claim link is broken: its token isn't base58.");
  const signature = await sign(claimSignedBytes(decodeId(node.pubkey)!, t));
  await api("/api/claim", { token, user: keys.pubkey, signature: b58(signature) });
  await loadNode();
  // The claim may have let us write in our space: try publishing our encryption key again.
  tried.delete(keys.pubkey);
  await ensureEncKey();
}

// ---- writing posts ----

/** Whether we may edit or delete this record: we wrote it, or we own this node. (Doc updates and snapshots never change.) */
export const canEdit = (p: Post) =>
  !!keys &&
  !["node", "doc_update", "doc_snapshot"].includes(p.rec.type) &&
  (amOwner() || (p.by?.pubkey === keys.pubkey && !pathWithin(p.rec.path, "/node")));

/** Creates a post at `path`, or edits `existing` (possibly moving it to `path`). `isPrivate`: only this
 * node's owners may read it, and it's never federated. Returns its hash. */
export async function putPost(text: string, path: string, isPrivate: boolean, existing?: Post) {
  if (!keys) throw new Error("Sign in first.");
  return putRec({
    path: normalizePath(path),
    version: nextVersion(existing?.rec.version),
    type: "post",
    edits: existing?.rec.hash,
    private: isPrivate,
    data: text.trim(),
  });
}

/** Deletes a record, with a signed tombstone naming its current version. The tombstone is as private as
 * the record, so deleting a private record doesn't tell peers about it. */
export async function deletePost(p: Post) {
  if (!keys) throw new Error("Sign in first.");
  await putRec({
    path: p.rec.path,
    version: nextVersion(p.rec.version),
    type: "tombstone",
    edits: p.rec.hash,
    private: p.rec.private,
    data: null,
  });
}

/** A post with a made-up signature, to show what a bad one looks like. */
export function forgedPost(): Post {
  const pk = decodeId("4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS")!;
  const draft: Draft = {
    author: pk,
    path: "/demo/forged",
    version: Date.now(),
    type: "post",
    private: false,
    data: "This post was added client-side with a made-up signature, so it should show as a bad signature.",
  };
  return viewPost(decodeRecord(encodeRecord(draft, new Uint8Array(64))));
}

// ---- federation ----
//
// Owners may add "peer" records naming other nodes for this one to push records to. Like everything
// under /node, they're never federated themselves. See core/src/lib.rs.

/** Has this node push records to the node at `url`: those of the given types (comma- or space-separated;
 * none for all) at or under the given paths (one per line; none for all). Owners only. Returns the record's hash. */
export async function putPeer(url: string, types: string, paths: string) {
  if (!keys) throw new Error("Sign in first.");
  url = url.trim().replace(/\/+$/, "");
  if (!/^https?:\/\/\S+$/.test(url)) throw new Error("Enter the other node's http:// or https:// URL.");
  const node = await getNode(url).then(
    (s) => s.pubkey,
    (e) => {
      throw new Error(`Couldn't reach a node at ${url}: ${e.message}`);
    },
  );
  if (node === thisNode?.pubkey) throw new Error("That's this node.");
  const t = types.split(/[\s,]+/).filter(Boolean);
  const p = paths.split("\n").map((s) => s.trim()).filter(Boolean).map((s) => normalizePath(s, true));
  nodes.add(node);
  return putRec({
    path: PEER_PATH,
    version: nextVersion(),
    type: "peer",
    data: { node: decodeId(node)!, url, ...(t.length && { types: t }), ...(p.length && { paths: p }) },
  });
}

// ---- encryption keys ----
//
// Encrypted docs' keys are sealed to each reader's X25519 public key, which they publish as an "enckey"
// record in their space (/u/<ID>/key). We publish ours once we're signed in, if this node lets us write
// there (see "user spaces" in core/src/lib.rs).

/** Whose keys we've tried to publish this session: once is enough, unless something changes (`retry`). */
const tried = new Set<string>();

/** Publishes our encryption key on this node, unless it has it. Quietly does nothing if it can't, or
 * already tried, unless `required`. */
export async function ensureEncKey(required = false) {
  if (!keys || (tried.has(keys.pubkey) && !required)) return;
  tried.add(keys.pubkey);
  try {
    await publishEncKey(node, keys.signer, keys.enc);
  } catch (e) {
    if (required) throw new Error(`Couldn't publish your encryption key: ${(e as Error).message}`);
  }
}

// ---- apps acting for us ----
//
// Other apps make their own keys, and ask us to let them sign records for us, at /connect (see
// client/src/signer.ts). Agreeing writes a "delegate" record; deleting it revokes it.

/** Lets the app's key sign records for us, as it asked. Returns the delegation's hash. */
export async function connectApp(r: ConnectRequest) {
  if (!keys) throw new Error("Sign in first.");
  const data = {
    key: r.key,
    name: r.name,
    ...(r.paths?.length && { paths: r.paths.map((p) => normalizePath(p, true)) }),
    ...(r.types?.length && { types: r.types }),
    ...(r.expires && { expires: r.expires }),
  };
  return putRec({ path: delegatePath(keys.pk), version: nextVersion(), type: "delegate", data });
}

/** The apps we've let sign for us, on this node. */
export async function myDelegations() {
  if (!keys) return [];
  const me = keys.pubkey;
  return (await getPosts({ prefix: delegatePath(keys.pk), type: "delegate" })).filter((p) => p.verified && p.author.pubkey === me && !p.signedBy);
}

// ---- shared documents ----
//
// A doc is a "doc" chain: its title, who may edit it besides its author, and what it holds: its format
// (always Yjs, here) and schema (markdown or a list, here). Its content is built from "doc_update" records,
// kept in sync by `openDoc` (client/src/docs.ts). Encrypted docs have their key sealed to each editor.

export const DOC_PATH = "/doc";

/** The schemas this app shows: markdown (a Y.Text "md"), and lists (see List.tsx). */
export const SCHEMAS = { markdown: "bisonbase.markdown", list: "bisonbase.list" } as const;

/** How a doc with this schema is shown in lists: an icon, and what to call it. */
export const docLabel = (schema: string) =>
  schema === SCHEMAS.list ? { icon: "🛒", noun: "list" } : schema === SCHEMAS.markdown ? { icon: "📄", noun: "doc" } : { icon: "🧩", noun: `${schema} doc` };

/** Starts a doc with this schema at `path`; `encrypted`: only its editors can read it. Returns its hash
 * (base58): its chain's, for good. */
export async function createDoc(schema: string, path = DOC_PATH, encrypted = false) {
  if (!keys) throw new Error("Sign in first.");
  if (encrypted) await ensureEncKey(true);
  return createDocRecord(node, keys.signer, { path: normalizePath(path), format: "yjs", schema, encryption: encrypted ? keys.enc : null });
}

/** Writes a new version of `doc` with these changes. Its author or an owner only. */
function saveDoc(doc: Post, changes: { title?: string; editors?: Who[]; keys?: { user: Uint8Array; sealed: Uint8Array }[] }) {
  if (!keys) throw new Error("Sign in first.");
  return saveDocRecord(node, keys.signer, doc.rec, changes);
}

const editorsOf = (doc: Post) => doc.rec.doc?.editors ?? [];

export const renameDoc = (doc: Post, title: string) => saveDoc(doc, { title });

/** Lets the user with this ID edit `doc`. For an encrypted doc, seals its key (`docKey`) to them. */
export async function addDocEditor(doc: Post, id: string, docKey: Uint8Array | null) {
  const pk = decodeId(id.trim());
  if (!pk) throw new Error("That isn't an ID (32 bytes of base58).");
  if (doc.doc?.editors.some((e) => e.user?.pubkey === b58(pk)) || doc.by?.pubkey === b58(pk)) throw new Error("They can already edit it.");
  const editors = [...editorsOf(doc), { user: pk }];
  if (!doc.doc?.encrypted) return saveDoc(doc, { editors });
  if (!docKey) throw new Error("You don't have this doc's key, so you can't share it.");
  const sealed = await sealTo(node, doc.rec.doc!.keys!, docKey, [pk]);
  if (sealed.missing.length) throw new Error("They haven't published an encryption key on this node yet: they need to sign in here once.");
  return saveDoc(doc, { editors, keys: sealed.keys });
}

/** Stops `doc`'s `i`th editor from editing it. What they wrote stays, and so does what they could read. */
export function removeDocEditor(doc: Post, i: number) {
  const removed = editorsOf(doc)[i];
  const editors = editorsOf(doc).filter((_, j) => j !== i);
  const gone = removed && ("user" in removed ? b58(removed.user) : claims.get(b58(removed.claim)));
  const keys = doc.rec.doc?.keys?.filter((k) => b58(k.user) !== gone);
  return saveDoc(doc, { editors, ...(keys && { keys }) });
}

/** Makes a claim link, next to `doc`, for whoever opens it to become an editor. Returns the link. For an
 * encrypted doc, the link carries its key (`docKey`): whoever has the link can read the doc. */
export async function inviteToDoc(doc: Post, docKey: Uint8Array | null) {
  if (doc.doc?.encrypted && !docKey) throw new Error("You don't have this doc's key, so you can't share it.");
  const { who, link } = await newClaim(doc.rec.path);
  await saveDoc(doc, { editors: [...editorsOf(doc), who] });
  return doc.doc?.encrypted ? `${link}.${b58(docKey!)}` : link;
}

/** For an encrypted doc we may change: seals its key to any editor who has none yet, if they've published
 * an encryption key (e.g. since claiming an invite). Whether it wrote a new version. */
export async function sealForEditors(doc: Post, docKey: Uint8Array) {
  const sealed = doc.rec.doc?.keys;
  if (!sealed) return false;
  await loadClaims();
  const users = [doc.by?.pubkey, ...editorsOf(doc).map((w) => ("user" in w ? b58(w.user) : claims.get(b58(w.claim))))]
    .filter((u): u is string => !!u)
    .map((u) => decodeId(u)!);
  const next = await sealTo(node, sealed, docKey, users);
  if (next.keys.length === sealed.length) return false;
  await saveDoc(doc, { keys: next.keys });
  return true;
}

/** Whether `pubkey` may write updates to `doc`: they started it, it names them as an editor, or they own
 * this node. Checked for every update, as peers pass records along without checking. */
export const mayEditDoc = (doc: Post, pubkey: string) =>
  doc.by?.pubkey === pubkey || !!doc.doc?.editors.some((e) => e.user?.pubkey === pubkey) || !!thisNode?.owners.includes(pubkey);

/** Whether some editor of `doc` is named by a claim we don't know to be claimed (as of `loadClaims`). */
export const docHasOpenClaims = (doc: Post) => !!doc.doc?.editors.some((e) => e.claim && !e.user);

/** A WebSocket to `doc`'s live room on this node, and the hello to send first: we may only join as one of
 * its editors. */
export async function joinDocLive(doc: string) {
  if (!keys || !thisNode) throw new Error("Sign in first.");
  return joinLive(node, keys.signer, doc, decodeId(thisNode.pubkey)!);
}
