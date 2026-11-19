import WORDS_TXT from "../../google-10000-english-usa-no-swears.txt?raw";

import { type Cbor, decode, encode } from "./cbor.ts";

export type User = { pubkey: string; phrase: string };

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
// base58 (Bitcoin alphabet: letters and digits only, so a double-click selects it all, and no 0/O/I/l).
// Store bytes; base58 and phrases are only for input and output. Keep in sync with src/lib.rs.

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function b58(bytes: Uint8Array) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  for (; n > 0n; n /= 58n) s = B58[Number(n % 58n)] + s;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) s = "1" + s; // leading zero bytes
  return s;
}

function unb58(s: string) {
  let n = 0n;
  for (const c of s) {
    const d = B58.indexOf(c);
    if (d < 0) throw new Error("not base58");
    n = n * 58n + BigInt(d);
  }
  const out: number[] = [];
  for (; n > 0n; n >>= 8n) out.unshift(Number(n & 0xffn));
  for (let i = 0; i < s.length && s[i] === "1"; i++) out.unshift(0); // leading zero bytes
  return Uint8Array.from(out);
}

/** The raw public key for a base58 ID; null unless it's exactly 32 bytes. */
function decodeId(id: string) {
  try {
    const pk = unb58(id);
    return pk.length === 32 ? pk : null;
  } catch {
    return null;
  }
}

/** Whether `s` is an ID: 32 bytes of base58. */
export const isPubkey = (s: string) => decodeId(s) !== null;

/** An ID's four_word nickname, from SHA-256 of its raw bytes; same as `phrase` in src/lib.rs. */
export async function userPhrase(pubkey: string) {
  const pk = decodeId(pubkey);
  if (!pk) throw new Error("not an ID");
  const h = new DataView(await crypto.subtle.digest("SHA-256", pk));
  return [0, 4, 8, 12].map((i) => WORDS[h.getUint32(i) % WORDS.length]).join("_");
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
// can produce it. From it we derive (HKDF) an Ed25519 keypair, whose public key is the user's ID,
// and an AES-GCM key for encrypting notes. There is no sign-in: having the keys loaded is all; the
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

const WORDS = WORDS_TXT.split("\n")
  .map((w) => w.trim())
  .filter(Boolean);

/** user.id length for passkeys whose name is derived from it. */
const NAMED_USER_ID_LEN = 32;

/**
 * A passkey's two_word name, derived from its random user.id. The name in the passkey picker includes it,
 * and since the user.id comes back on every use (as the user handle), we can show the same name here.
 * Null for passkeys whose name we can't reconstruct.
 */
async function passkeyName(userId: Uint8Array<ArrayBuffer>): Promise<string | null> {
  if (userId.length === NAMED_USER_ID_LEN) {
    const h = new DataView(await crypto.subtle.digest("SHA-256", userId));
    return [0, 4].map((i) => WORDS[h.getUint32(i) % WORDS.length]).join("_");
  }
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
  noteKey: CryptoKey;
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
  const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey", "deriveBits"]);
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

  const noteKey = await crypto.subtle.deriveKey(
    hkdf("bisonbase/notes/aes-gcm"),
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const pk = unb64(jwk.x!);
  const pubkey = b58(pk);
  return { secret, pubkey, pk, signKey, noteKey, passkey: passkey && { ...passkey, pubkey, lastUsed: Date.now() } };
}

const sign = async (data: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.sign("Ed25519", keys!.signKey, data));

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
    name: userHandle ? await passkeyName(new Uint8Array(userHandle)) : null,
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
  const twoWords = (await passkeyName(userId))!;
  const name = `bisonbase ${new Date().toISOString().slice(0, 10)} ${twoWords}`;
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
  loadKeys(await deriveKeys(secretBytes, { credId: b64(cred.rawId), name: twoWords }));
}

export function forgetKeys() {
  keys = null;
  setRemember(false);
}

// ---- records ----
//
// Everything users write is a record: a deterministic-CBOR map signed by its author, identified by
// (owner, path), where the newest version wins. Field by field, see src/lib.rs. The server stores
// and returns records exactly as signed, so everything here is checked in the browser.
//
// Encrypted records have a `wrapped_key`: `data` is then iv || AES-GCM(CBOR of the real data) under
// a random key, itself encrypted ("wrapped") under the author's note key. Signatures cover the
// ciphertext, so anyone can verify an encrypted record without reading it.

const RECORD_CONTEXT = enc.encode("bisonbase-record-v1\n");
const GRANT_CONTEXT = enc.encode("bisonbase-grant-v1\n");

export type Authorization = { path: string; signature: Uint8Array };
export type Rec = {
  author: Uint8Array;
  owner: Uint8Array;
  path: string;
  version: number;
  type: string;
  data: Cbor;
  wrapped_key?: Uint8Array;
  authorization?: Authorization;
  signature: Uint8Array;
};

/** A record as shown: its decoded IDs, its bb:// address, and whether it checks out. */
export type Post = {
  rec: Rec;
  author: User;
  owner: User;
  /** bb://<owner><path> */
  uri: string;
  /** Whether its signature (and authorization, if any) verified, in this browser. */
  verified: boolean;
  encrypted: boolean;
  /** The text, if it's a plain post. */
  text: string | null;
  /** For grant records: who may write, and where. */
  grant?: { grantee: User; path: string };
};

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  parts.reduce((at, p) => (out.set(p, at), at + p.length), 0);
  return out;
};
const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

const unsigned = ({ signature: _, ...rest }: Rec) => rest as Cbor;
const signedBytes = (r: Rec) => concat(RECORD_CONTEXT, encode(unsigned(r)));
const grantBytes = (author: Uint8Array, owner: Uint8Array, path: string) =>
  concat(GRANT_CONTEXT, encode({ author, owner, path }));

/** Paths: "/" then "/"-separated segments: non-empty, not "." or "..", no control characters,
 * Unicode NFC, ≤ 1024 bytes. Returns the NFC form, or throws. Same rules as check_path in src/lib.rs. */
export function normalizePath(input: string) {
  const path = input.trim().normalize("NFC");
  if (!path.startsWith("/")) throw new Error("A path must start with /");
  if (enc.encode(path).length > 1024) throw new Error("That path is too long");
  for (const seg of path.slice(1).split("/")) {
    if (!seg) throw new Error("A path can't have empty segments (// or a trailing /)");
    if (seg === "." || seg === "..") throw new Error("Path segments can't be . or ..");
    if (/\p{Cc}/u.test(seg)) throw new Error("A path can't contain control characters");
  }
  return path;
}

/** Whether `path` is `prefix` or below it, by whole segments. */
export const pathWithin = (path: string, prefix: string) =>
  path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : prefix + "/");

const isBytes = (v: unknown, n?: number): v is Uint8Array => v instanceof Uint8Array && (n === undefined || v.length === n);

function recFromCbor(v: Cbor): Rec {
  const r = v as Rec;
  const a = r?.authorization;
  if (
    !isBytes(r?.author, 32) ||
    !isBytes(r.owner, 32) ||
    typeof r.path !== "string" ||
    typeof r.version !== "number" ||
    typeof r.type !== "string" ||
    !("data" in r) ||
    (r.wrapped_key !== undefined && !isBytes(r.wrapped_key)) ||
    (a !== undefined && (typeof a.path !== "string" || !isBytes(a.signature, 64))) ||
    !isBytes(r.signature, 64)
  ) {
    throw new Error("malformed record");
  }
  return r;
}

async function verifySig(pk: Uint8Array<ArrayBuffer>, msg: Uint8Array<ArrayBuffer>, sig: Uint8Array<ArrayBuffer>) {
  try {
    const key = await crypto.subtle.importKey("raw", pk, "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, sig, msg);
  } catch {
    return false;
  }
}

/** Checks a record's signature and authorization against its author's and owner's IDs, without trusting the server. */
export async function verifyRec(r: Rec) {
  const own = bytesEqual(r.author, r.owner);
  if (r.type === "grant") {
    const g = grantData(r);
    if (!own || !g || !(await verifySig(r.owner as any, grantBytes(g.grantee, r.owner, g.path), g.signature as any))) return false;
  }
  const a = r.authorization;
  if (own ? a : !a) return false;
  if (a && (!pathWithin(r.path, a.path) || !(await verifySig(r.owner as any, grantBytes(r.author, r.owner, a.path), a.signature as any)))) {
    return false;
  }
  return verifySig(r.author as any, signedBytes(r), r.signature as any);
}

/** A grant record's data, if well-formed: {grantee, path, signature}. */
type GrantData = { grantee: Uint8Array; path: string; signature: Uint8Array };
function grantData(r: Rec): GrantData | null {
  const g = r.data as GrantData;
  return r.type === "grant" && isBytes(g?.grantee, 32) && typeof g.path === "string" && isBytes(g.signature, 64) ? g : null;
}

const toUser = async (pk: Uint8Array): Promise<User> => ({ pubkey: b58(pk), phrase: await userPhrase(b58(pk)) });

export async function viewPost(rec: Rec): Promise<Post> {
  const [author, owner] = await Promise.all([toUser(rec.author), toUser(rec.owner)]);
  const g = grantData(rec);
  return {
    grant: g ? { grantee: await toUser(g.grantee), path: g.path } : undefined,
    rec,
    author,
    owner,
    uri: `bb://${owner.pubkey}${rec.path}`,
    verified: await verifyRec(rec),
    encrypted: !!rec.wrapped_key,
    text: !rec.wrapped_key && typeof rec.data === "string" ? rec.data : null,
  };
}

/** Live records, newest first; optionally only `owner`'s space, `author`'s, those `user` owns or
 * wrote, of one `type`, or at or under `prefix`. */
export async function getPosts(q: { owner?: string; author?: string; user?: string; type?: string; prefix?: string } = {}) {
  const params = new URLSearchParams(Object.entries(q).filter((e): e is [string, string] => !!e[1]));
  const res = await fetch(`/api/records?${params}`);
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  const list = decode(new Uint8Array(await res.arrayBuffer()));
  if (!Array.isArray(list)) throw new Error("malformed record list");
  return Promise.all(list.map((v) => viewPost(recFromCbor(v))));
}

/** Signs `r` (as us) and stores it. */
async function putRec(r: Omit<Rec, "signature">) {
  const rec = { ...r, signature: new Uint8Array() };
  rec.signature = await sign(signedBytes(rec));
  const res = await fetch("/api/records", {
    method: "POST",
    headers: { "content-type": "application/cbor" },
    body: encode(rec as unknown as Cbor),
  });
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
}

/** A version newer than both the clock and `prev`, so quick successive edits still go through. */
const nextVersion = (prev = 0) => Math.max(Date.now(), prev + 1);

/** AES-GCM: iv || ciphertext. */
async function seal(key: CryptoKey, data: Uint8Array<ArrayBuffer>) {
  const iv = random(12);
  return concat(iv, new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data)));
}

async function open(key: CryptoKey, sealed: Uint8Array) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: sealed.slice(0, 12) }, key, sealed.slice(12)));
}

const aesKey = (raw: Uint8Array<ArrayBuffer>) =>
  crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

/** Decrypts one of our own encrypted posts. */
export async function decryptPost(p: Post) {
  if (!keys || !p.rec.wrapped_key || !isBytes(p.rec.data)) throw new Error("locked");
  const key = await aesKey(await open(keys.noteKey, p.rec.wrapped_key));
  const data = decode(await open(key, p.rec.data));
  if (typeof data !== "string") throw new Error("not text");
  return data;
}

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
  const signature = await sign(grantBytes(g, keys.pk, path));
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
    .map((p) => {
      const g = grantData(p.rec)!;
      return { owner: p.owner, ownerPk: p.rec.owner, path: g.path, signature: g.signature, uri: p.uri };
    });
}

// ---- writing posts ----

/** Who owns the space a write goes to, and the authorization needed if it isn't us. */
function placement(existing?: Post, grant?: Grant): Pick<Rec, "owner" | "authorization"> {
  const owner = existing?.rec.owner ?? grant?.ownerPk ?? keys!.pk;
  if (bytesEqual(owner, keys!.pk)) return { owner };
  // Writing to an existing record of ours in someone's space reuses the authorization it carries.
  const authorization =
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

/** Creates a post at `path` (in our space, or the grant's owner's), or replaces `existing`. Signed always; encrypted if asked. */
export async function putPost(text: string, opts: { encrypt: boolean; path?: string; grant?: Grant }, existing?: Post) {
  if (!keys) throw new Error("Derive keys first.");
  const path = existing?.rec.path ?? normalizePath(opts.path ?? "");
  const where = placement(existing, opts.grant);
  if (where.authorization && !pathWithin(path, where.authorization.path)) {
    throw new Error(`The grant only covers ${where.authorization.path}.`);
  }
  let data: Cbor = text.trim();
  let wrapped_key: Uint8Array | undefined;
  if (opts.encrypt) {
    const raw = random(32);
    data = await seal(await aesKey(raw), encode(data));
    wrapped_key = await seal(keys.noteKey, raw);
  }
  await putRec({ author: keys.pk, ...where, path, version: nextVersion(existing?.rec.version), type: "post", data, wrapped_key });
}

/** Deletes a post, leaving a signed tombstone at its path. */
export async function deletePost(p: Post) {
  if (!keys) throw new Error("Derive keys first.");
  await putRec({ author: keys.pk, ...placement(p), path: p.rec.path, version: nextVersion(p.rec.version), type: "tombstone", data: null });
}

/** A random path for a new post. */
export const newPostPath = () => `/posts/${b58(random(8))}`;

/** A post with a made-up signature, to show what a bad one looks like. */
export function forgedPost(): Promise<Post> {
  const pk = unb58("4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS");
  return viewPost({
    author: pk,
    owner: pk,
    path: "/demo/forged",
    version: Date.now(),
    type: "post",
    data: "This post was added client-side with a made-up signature, so it should show as a bad signature.",
    signature: new Uint8Array(64),
  });
}
