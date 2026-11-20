// Records, IDs and paths come from core/src/lib.rs, compiled to wasm (see wasm/src/lib.rs); main.tsx
// loads it before anything here runs.
import {
  type Authorization,
  type Draft,
  type Rec,
  b58,
  checkPath,
  claimSignedBytes,
  decodeId,
  decodeRecord,
  decodeRecords,
  encodeRecord,
  grantSignedBytes,
  pathWithin,
  phrase,
  signedBytes,
  twoWords,
} from "../../wasm/pkg/fedcrdt_wasm.js";

export { type Authorization, type Rec, b58, pathWithin };

/** `server`: the key is a server's (its phrase is "server_word"). */
export type User = { pubkey: string; phrase: string; server: boolean };

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

/** IDs of keys known to be servers', from their /server records and federate records naming them. */
const servers = new Set<string>();
export const isServer = (pubkey: string) => servers.has(pubkey);
export async function loadServers() {
  for (const s of await api<string[]>("/api/servers")) servers.add(s);
}

/** An ID's "🦬two_words" nickname, or "server_word" for a known server's. */
export function userPhrase(pubkey: string) {
  const pk = decodeId(pubkey);
  if (!pk) throw new Error("not an ID");
  return phrase(pk, servers.has(pubkey));
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
// server has no sessions and never sees the secret or the private keys.

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
// Everything users write is a record: a dCBOR map signed by its author, identified by (owner, path),
// where the newest version wins. The server stores and returns records exactly as signed; the wasm
// core decodes and checks them here in the browser, so nothing depends on trusting the server.

/** A record as shown: its decoded IDs, its bb:// address, and whether it checks out. */
export type Post = {
  rec: Rec;
  author: User;
  owner: User;
  /** bb://<owner><path> */
  uri: string;
  /** Whether its signature (and authorization, if any) verified, in this browser. */
  verified: boolean;
  /** The text, if it's a plain post. */
  text: string | null;
  /** For grant records: who may write, and where. */
  grant?: { grantee: User; path: string };
  /** For federate records: which server gets pushed what. `types` and `paths` are null for all. */
  federate?: { peer: User; url: string; types: string[] | null; paths: string[] | null };
  /** For a server record: its URL. */
  serverUrl?: string;
  /** For a server's owner record: who claimed it. */
  claimedBy?: User;
};

const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Trims and NFC-normalizes a path someone typed, then checks it (see check_path in core/src/lib.rs). Throws if it's bad. */
export function normalizePath(input: string) {
  const path = input.trim().normalize("NFC");
  checkPath(path);
  return path;
}

const toUser = (pk: Uint8Array): User => {
  const pubkey = b58(pk);
  return { pubkey, phrase: userPhrase(pubkey), server: servers.has(pubkey) };
};

export function viewPost(rec: Rec): Post {
  const f = rec.federate;
  return {
    grant: rec.grant && { grantee: toUser(rec.grant.grantee), path: rec.grant.path },
    federate: f && { peer: toUser(f.peer), url: f.url, types: f.types ?? null, paths: f.paths ?? null },
    serverUrl: rec.serverUrl,
    claimedBy: rec.claimedBy && toUser(rec.claimedBy),
    rec,
    author: toUser(rec.author),
    owner: toUser(rec.owner),
    uri: `bb://${b58(rec.owner)}${rec.path}`,
    verified: rec.verified,
    text: rec.text ?? null,
  };
}

/** Live records, newest first; optionally only `owner`'s space, `author`'s, those `user` owns or
 * wrote, of one `type`, or at or under `prefix`. */
export async function getPosts(q: { owner?: string; author?: string; user?: string; type?: string; prefix?: string } = {}) {
  const params = new URLSearchParams(Object.entries(q).filter((e): e is [string, string] => !!e[1]));
  const res = await fetch(`/api/records?${params}`);
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  const list = decodeRecords(new Uint8Array(await res.arrayBuffer()));
  // Learn which keys are servers' first, so they get server phrases.
  for (const r of list) {
    if (r.serverUrl !== undefined && r.path === "/server") servers.add(b58(r.owner));
    if (r.federate) servers.add(b58(r.federate.peer));
  }
  return list.map(viewPost);
}

/** Signs `d` (as us) and stores it. */
async function putRec(d: Draft) {
  const signature = await sign(signedBytes(d));
  const res = await fetch("/api/records", {
    method: "POST",
    headers: { "content-type": "application/cbor" },
    body: encodeRecord(d, signature) as Uint8Array<ArrayBuffer>,
  });
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
}

/** A version newer than both the clock and `prev`, so quick successive edits still go through. */
const nextVersion = (prev = 0) => Math.max(Date.now(), prev + 1);

// ---- grants: letting someone else write in your space ----
//
// The owner signs {author: grantee, owner, path} and keeps it in their space as a "grant" record
// (by default under /grants). The grantee finds it there and copies its signature into their
// records' `authorization`.

/** A grant given to us: where we may write. */
export type Grant = { owner: User; ownerPk: Uint8Array; path: string; signature: Uint8Array; uri: string };

/** Lets `grantee` (base58 ID) write at or under `path` in our space, saving the grant as a record. Returns its address. */
export async function makeGrant(grantee: string, path: string) {
  if (!keys) throw new Error("Derive keys first.");
  const g = decodeId(grantee.trim());
  if (!g) throw new Error("That isn't an ID (32 bytes of base58).");
  path = normalizePath(path);
  const signature = await sign(grantSignedBytes(g, keys.pk, path));
  const at = `/grants/${b58(random(8))}`;
  await putRec({ author: keys.pk, owner: keys.pk, path: at, version: nextVersion(), type: "grant", data: { grantee: g, path, signature } });
  return `bb://${keys.pubkey}${at}`;
}

/** Grants others have given us, from their grant records (verified here). */
export async function myGrants(): Promise<Grant[]> {
  if (!keys) return [];
  const pk = keys.pk;
  return (await getPosts({ type: "grant" }))
    .filter((p) => p.verified && p.grant?.grantee.pubkey === keys?.pubkey && !bytesEqual(p.rec.owner, pk))
    .map((p) => ({ owner: p.owner, ownerPk: p.rec.owner, path: p.rec.grant!.path, signature: p.rec.grant!.signature, uri: p.uri }));
}

// ---- writing posts ----

/** Who owns the space a write goes to, and the authorization needed if it isn't us. */
function placement(existing?: Post, grant?: Grant): Pick<Draft, "owner" | "authorization"> {
  const owner = existing?.rec.owner ?? grant?.ownerPk ?? keys!.pk;
  if (bytesEqual(owner, keys!.pk)) return { owner };
  // Writing to an existing record of ours in someone's space reuses the authorization it carries.
  const authorization: Authorization | undefined =
    grant && bytesEqual(grant.ownerPk, owner)
      ? { path: grant.path, signature: grant.signature }
      : existing && bytesEqual(existing.rec.author, keys!.pk)
        ? existing.rec.authorization
        : undefined;
  if (!authorization) throw new Error("Writing in someone else's space needs a grant from them.");
  return { owner, authorization };
}

/** Whether we can delete this record (and edit it, if it's a post): it's in our space, or we wrote it under a grant. */
export const canEdit = (p: Post) =>
  !!keys && (bytesEqual(p.rec.owner, keys.pk) || (bytesEqual(p.rec.author, keys.pk) && !!p.rec.authorization));

/** Creates a post at `path` (in our space, or the grant's owner's), or replaces `existing`. Always signed. */
export async function putPost(text: string, opts: { path?: string; grant?: Grant }, existing?: Post) {
  if (!keys) throw new Error("Derive keys first.");
  const path = existing?.rec.path ?? normalizePath(opts.path ?? "");
  const where = placement(existing, opts.grant);
  if (where.authorization && !pathWithin(path, where.authorization.path)) {
    throw new Error(`The grant only covers ${where.authorization.path}.`);
  }
  await putRec({ author: keys.pk, ...where, path, version: nextVersion(existing?.rec.version), type: "post", data: text.trim() });
}

/** Deletes a post, leaving a signed tombstone at its path. */
export async function deletePost(p: Post) {
  if (!keys) throw new Error("Derive keys first.");
  await putRec({ author: keys.pk, ...placement(p), path: p.rec.path, version: nextVersion(p.rec.version), type: "tombstone", data: null });
}

/** A random path for a new post. */
export const newPostPath = () => `/posts/${b58(random(8))}`;

/** A post with a made-up signature, to show what a bad one looks like. */
export function forgedPost(): Post {
  const pk = decodeId("4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS")!;
  const draft: Draft = {
    author: pk,
    owner: pk,
    path: "/demo/forged",
    version: Date.now(),
    type: "post",
    data: "This post was added client-side with a made-up signature, so it should show as a bad signature.",
  };
  return viewPost(decodeRecord(encodeRecord(draft, new Uint8Array(64))));
}

// ---- this server, and federation ----
//
// Each server has its own key and space. Its owner claims it once with a one-time link (printed by the
// server), and is then granted /federate in its space, where each "federate" record names a peer
// server to push records to. See core/src/lib.rs.

export type ServerInfo = { pubkey: string; phrase: string; owner: string | null };
export const getServer = (url = "") => api<ServerInfo>(`${url}/api/server`);

/** Claims this server as its owner (us), with the token from its claim link. Returns the server's ID. */
export async function claimServer(token: string) {
  if (!keys) throw new Error("Sign in first.");
  const server = await getServer();
  const t = decodeId(token);
  if (!t) throw new Error("This claim link is broken: its token isn't 32 bytes of base58.");
  const signature = await sign(claimSignedBytes(decodeId(server.pubkey)!, t));
  await api("/api/claim", { token, user: keys.pubkey, signature: b58(signature) });
  servers.add(server.pubkey);
  return server.pubkey;
}

/** Has `server` (our own server's ID) push records to the server at `url`: those of the given types
 * (comma- or space-separated; none for all) at the given paths (bb://<ID or *>/<path>, one per line;
 * none for all). We need its /federate grant, i.e. to be its owner. Returns the record's address. */
export async function putFederate(server: string, url: string, types: string, paths: string) {
  if (!keys) throw new Error("Sign in first.");
  url = url.trim().replace(/\/+$/, "");
  if (!/^https?:\/\/\S+$/.test(url)) throw new Error("Enter the other server's http:// or https:// URL.");
  const peer = await getServer(url).then(
    (s) => s.pubkey,
    (e) => {
      throw new Error(`Couldn't reach a server at ${url}: ${e.message}`);
    },
  );
  if (peer === server) throw new Error("That's this server.");
  const grant = (await myGrants()).find((g) => g.owner.pubkey === server && pathWithin("/federate", g.path));
  if (!grant) throw new Error("Only this server's owner can federate it.");
  const t = types.split(/[\s,]+/).filter(Boolean);
  const p = paths.split("\n").map((s) => s.trim()).filter(Boolean);
  const path = `/federate/${peer}`;
  servers.add(peer);
  await putRec({
    author: keys.pk,
    owner: grant.ownerPk,
    authorization: { path: grant.path, signature: grant.signature },
    path,
    version: nextVersion(),
    type: "federate",
    data: { url, ...(t.length && { types: t }), ...(p.length && { paths: p }) },
  });
  return `bb://${server}${path}`;
}
