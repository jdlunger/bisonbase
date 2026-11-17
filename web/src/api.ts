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
export const getNotes = () => api<Note[]>("/api/notes");

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

type Keys = { secret: Uint8Array<ArrayBuffer>; pubkey: string; signKey: CryptoKey; noteKey: CryptoKey };
let keys: Keys | null = null;

/** The loaded keys' ID, i.e. the derived public signing key, if keys are loaded. */
export const myPubkey = () => keys?.pubkey ?? null;

/** PKCS#8 wrapper for a raw 32-byte Ed25519 seed, which is how WebCrypto wants it. */
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

async function deriveKeys(secret: Uint8Array<ArrayBuffer>): Promise<Keys> {
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
  return { secret, pubkey: jwk.x!, signKey, noteKey };
}

const sign = async (data: Uint8Array<ArrayBuffer>) => b64(await crypto.subtle.sign("Ed25519", keys!.signKey, data));

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
    if (on && keys) localStorage.setItem(REMEMBER_KEY, b64(keys.secret));
    else localStorage.removeItem(REMEMBER_KEY);
  } catch {}
}

/** Loads remembered keys, if any. No prompt. */
export async function restoreKeys() {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(REMEMBER_KEY);
  } catch {}
  if (stored) keys = await deriveKeys(unb64(stored));
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
  return new Uint8Array(out);
}

/** Derives keys from an existing passkey (one prompt). */
export async function deriveFromExistingPasskey() {
  try {
    keys = await deriveKeys(await prfFromPasskey());
  } catch (e) {
    throw new Error(
      `Couldn't get your keys from a passkey (${(e as Error).message}). If you don't have one for this site yet, derive keys with a new passkey instead.`,
    );
  }
  if (isRemembering()) setRemember(true);
}

/** Creates a passkey, then derives keys from it: one or two prompts. */
export async function deriveFromNewPasskey() {
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: random(32), // nobody verifies the attestation either
      rp: { id: location.hostname, name: "bisonbase" },
      user: {
        id: random(16),
        name: `bisonbase ${new Date().toISOString().slice(0, 10)}`,
        displayName: `bisonbase ${new Date().toISOString().slice(0, 10)}`,
      },
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
  keys = await deriveKeys(secret ? new Uint8Array(secret) : await prfFromPasskey(cred.rawId));
  if (isRemembering()) setRemember(true);
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
    const key = await crypto.subtle.importKey("raw", unb64(note.author.pubkey), "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, unb64(note.sig), writePayload(note.id, note.version, note));
  } catch {
    return false;
  }
}
