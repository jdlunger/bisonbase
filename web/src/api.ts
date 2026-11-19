import WORDS_TXT from "../../google-10000-english-usa-no-swears.txt?raw";

export type User = { pubkey: string; phrase: string };
export type Note = {
  /** Chosen by the author's client (random). */
  id: string;
  author: User;
  /** Milliseconds since the epoch, by the author's clock; the newest signed write wins. */
  version: number;
  /** Plain text, or base64url(iv || AES-GCM ciphertext) under a per-note key when `encrypted`. */
  body: string;
  encrypted: boolean;
  /** base64url(iv || the per-note key, AES-GCM-encrypted under the author's note key). */
  wrapped_key: string | null;
  /** base64url Ed25519 signature by the author over writePayload(..). */
  sig: string;
  created_at: number;
  updated_at: number;
};

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
/** All notes, or just `author`'s. */
export const getNotes = (author?: string) =>
  api<Note[]>(author ? `/api/notes?author=${encodeURIComponent(author)}` : "/api/notes");

// ---- user IDs ----
//
// A user's ID is their raw 32-byte Ed25519 public key. In the API, URLs and the UI it's written in
// base58 (Bitcoin alphabet: letters and digits only, so a double-click selects it all, and no 0/O/I/l).
// Store bytes; base58 and phrases are only for input and output. Keep in sync with src/lib.rs.

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function b58(bytes: Uint8Array) {
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
  const pubkey = b58(unb64(jwk.x!));
  return { secret, pubkey, signKey, noteKey, passkey: passkey && { ...passkey, pubkey, lastUsed: Date.now() } };
}

const sign = async (data: Uint8Array<ArrayBuffer>) => b64(await crypto.subtle.sign("Ed25519", keys!.signKey, data));

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

// ---- notes ----
//
// Every write (create, edit, delete) is signed by the author and carries a version; the server
// keeps the newest. Each note is encrypted under its own random key, which is itself encrypted
// ("wrapped") under the author's note key. Signatures cover exactly what's stored, so anyone can
// verify an encrypted note without reading it.

/** The exact bytes a write's signature covers. Keep in sync with write_payload in src/main.rs. */
function writePayload(id: string, version: number, put?: Pick<Note, "body" | "encrypted" | "wrapped_key">) {
  const head = `bisonbase-note-v2\n${id}\n${version}`;
  return enc.encode(
    put
      ? `${head}\nput\n${put.encrypted ? "encrypted" : "plain"}\n${put.wrapped_key ?? ""}\n${put.body}`
      : `${head}\ndelete`,
  );
}

/** A version newer than both the clock and `prev`, so quick successive edits still go through. */
const nextVersion = (prev = 0) => Math.max(Date.now(), prev + 1);

/** AES-GCM: base64url(iv || ciphertext). */
async function seal(key: CryptoKey, data: Uint8Array<ArrayBuffer>) {
  const iv = random(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return b64(new Uint8Array([...iv, ...new Uint8Array(ct)]));
}

async function open(key: CryptoKey, sealed: string) {
  const bytes = unb64(sealed);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12)));
}

const aesKey = (raw: Uint8Array<ArrayBuffer>) =>
  crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

export async function decryptNote(note: Note) {
  if (!keys || !note.wrapped_key) throw new Error("locked");
  const key = await aesKey(await open(keys.noteKey, note.wrapped_key));
  return new TextDecoder().decode(await open(key, note.body));
}

/** Creates a note, or replaces `existing`. Signed always; encrypted if asked. */
export async function putNote(text: string, opts: { encrypt: boolean }, existing?: Note) {
  if (!keys) throw new Error("Derive keys first.");
  const id = existing?.id ?? b64(random(16));
  const version = nextVersion(existing?.version);
  let body = text.trim();
  let wrapped_key: string | null = null;
  if (opts.encrypt) {
    const raw = random(32);
    body = await seal(await aesKey(raw), enc.encode(body));
    wrapped_key = await seal(keys.noteKey, raw);
  }
  const put = { body, encrypted: opts.encrypt, wrapped_key };
  const sig = await sign(writePayload(id, version, put));
  await api(`/api/notes/${id}`, { ...put, author: keys.pubkey, version, sig }, "PUT");
}

export async function deleteNote(note: Note) {
  if (!keys) throw new Error("Derive keys first.");
  const version = nextVersion(note.version);
  const sig = await sign(writePayload(note.id, version));
  await api(`/api/notes/${note.id}`, { author: keys.pubkey, version, sig }, "DELETE");
}

/** Checks a note's signature against its author's ID (their Ed25519 public key), without trusting the server. */
export async function verifyNote(note: Note): Promise<boolean> {
  try {
    const pk = decodeId(note.author.pubkey);
    if (!pk) return false;
    const key = await crypto.subtle.importKey("raw", pk, "Ed25519", false, ["verify"]);
    const msg = writePayload(note.id, note.version, note);
    const sig = unb64(note.sig);
    if (!isSshsig(sig)) return await crypto.subtle.verify("Ed25519", key, sig, msg);
    const s = await parseSshsig(sig, pk, NOTE_NAMESPACE);
    return !!s && (await crypto.subtle.verify("Ed25519", key, s.raw, await sshsigSignedData(NOTE_NAMESPACE, s.reserved, msg)));
  } catch {
    return false;
  }
}

// ---- SSH signatures ----
//
// Writes by the `note` CLI (src/bin/note.rs) are signed with an ssh-ed25519 key from the author's
// SSH agent, in OpenSSH's SSHSIG format (what `ssh-keygen -Y sign` makes), under NOTE_NAMESPACE.
// The author's ID is then their SSH public key itself. Keep in sync with src/lib.rs.

const NOTE_NAMESPACE = "bisonbase-note";
const SSHSIG = enc.encode("SSHSIG");

const isSshsig = (sig: Uint8Array) => SSHSIG.every((b, i) => sig[i] === b);

/** SSH wire-format string: u32 big-endian length, then the bytes. */
const sshString = (b: Uint8Array) => {
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length);
  out.set(b, 4);
  return out;
};

const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Picks an SSHSIG blob apart; null unless it's an ssh-ed25519, sha512 signature by `pk` under `namespace`. */
async function parseSshsig(sig: Uint8Array, pk: Uint8Array, namespace: string) {
  let at = SSHSIG.length;
  const dv = new DataView(sig.buffer, sig.byteOffset, sig.byteLength);
  const u32 = () => {
    const v = dv.getUint32(at); // throws past the end
    at += 4;
    return v;
  };
  const str = () => {
    const n = u32();
    if (at + n > sig.length) throw new Error("truncated");
    return sig.slice(at, (at += n));
  };
  if (u32() !== 1) return null;
  const keyBlob = str();
  const ns = str();
  const reserved = str();
  const hash = str();
  const sigBlob = str();
  if (at !== sig.length) return null;
  const want = new Uint8Array([...sshString(enc.encode("ssh-ed25519")), ...sshString(pk)]);
  if (!bytesEqual(keyBlob, want) || !bytesEqual(ns, enc.encode(namespace))) return null;
  if (!bytesEqual(hash, enc.encode("sha512"))) return null;
  const algo = sshString(enc.encode("ssh-ed25519"));
  if (sigBlob.length !== algo.length + 4 + 64 || !bytesEqual(sigBlob.slice(0, algo.length), algo)) return null;
  if (new DataView(sigBlob.buffer).getUint32(algo.length) !== 64) return null;
  return { reserved, raw: sigBlob.slice(algo.length + 4) };
}

/** The bytes an SSHSIG signature actually covers. */
async function sshsigSignedData(namespace: string, reserved: Uint8Array, msg: Uint8Array<ArrayBuffer>) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-512", msg));
  return new Uint8Array([
    ...SSHSIG,
    ...sshString(enc.encode(namespace)),
    ...sshString(reserved),
    ...sshString(enc.encode("sha512")),
    ...sshString(hash),
  ]);
}
