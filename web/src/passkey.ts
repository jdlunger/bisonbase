// Passkeys, the keys they derive, and signing in to a private node: what both the app (api.ts) and the
// private node's sign-in page (gate.ts) need. Needs the wasm core loaded.
import { accessSignedBytes, b58, twoWords } from "../../client/src/core.ts";

// ---- bytes ----

export const enc = new TextEncoder();
export const b64 = (b: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const unb64 = (s: string) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
export const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

// ---- keys ----
//
// Everything hangs off one secret: the passkey's PRF output for a fixed salt. Only that passkey
// can produce it. From it we derive (HKDF) an Ed25519 keypair, whose public key is the user's ID.

const PRF_SALT = enc.encode("bisonbase keys v1");

/** Which passkey: its base64url credential ID, and its two_word name (see passkeyName), or null if unknown. */
export type PasskeyIds = { credId: string; name: string | null };

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

/** 32 bytes derived from the secret, for `info`. */
export async function deriveBits(secret: Uint8Array<ArrayBuffer>, info: string) {
  const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const params = { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: enc.encode(info) };
  return new Uint8Array(await crypto.subtle.deriveBits(params, ikm, 256));
}

/** PKCS#8 wrapper for a raw 32-byte Ed25519 seed, which is how WebCrypto wants it. */
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** The Ed25519 signing key the secret derives (non-extractable), and its public key: the user's ID. */
export async function identityKey(secret: Uint8Array<ArrayBuffer>) {
  const seed = await deriveBits(secret, "bisonbase/identity/ed25519");
  const pkcs8 = new Uint8Array([...ED25519_PKCS8_PREFIX, ...seed]);
  // Import once extractable just to read the public key out of the JWK, then keep a non-extractable copy.
  const jwk = await crypto.subtle.exportKey(
    "jwk",
    await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]),
  );
  const signKey = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
  seed.fill(0);
  pkcs8.fill(0);
  return { signKey, pk: unb64(jwk.x!) };
}

// ---- passkey ceremonies (entirely client-side) ----

const prfExtension = () => ({ prf: { eval: { first: PRF_SALT } } }) as AuthenticationExtensionsClientInputs;
const prfOutput = (cred: PublicKeyCredential) =>
  (cred.getClientExtensionResults() as any).prf?.results?.first as ArrayBuffer | undefined;

const NO_PRF =
  "This passkey (or browser) doesn't support the PRF extension, so it can't derive your keys. Try another browser, or a passkey stored in a different place.";

/** Asks a passkey for its PRF secret (one prompt). `credId` restricts it to that passkey. */
export async function prfFromPasskey(credId?: BufferSource) {
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

/** Creates a passkey, and gets its PRF secret: one or two prompts. */
export async function createPasskey() {
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
  const ids: PasskeyIds = { credId: b64(cred.rawId), name: words };
  return { secret: secretBytes, ids };
}

// ---- signing in to a private node ----
//
// A private node (`--private`) shows only a sign-in page to those it doesn't let in. To get in, we sign an
// access token (see access_signed_bytes in core/src/lib.rs) for this origin, and the node keeps it as a
// cookie, if we have access. It's good for 30 days; the app signs a new one whenever it loads our keys.

const ACCESS_TOKEN_MS = 30 * 24 * 60 * 60 * 1000 - 60_000;

/** Signs in to this private node as `pubkey` (base58), signing with `sign`; with a claim link's `claim`
 * token, claims it first, if it lets us in. Resolves whether we got in. */
export async function signIn(sign: (data: Uint8Array) => Promise<Uint8Array>, pubkey: string, claim?: string) {
  const expires = Date.now() + ACCESS_TOKEN_MS;
  const signature = await sign(accessSignedBytes(location.origin, BigInt(expires)));
  const res = await fetch("/api/auth", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ user: pubkey, expires, signature: b58(signature), claim }),
  });
  if (res.ok) return true;
  if (res.status === 403) return false;
  throw new Error((await res.text()) || res.statusText);
}

/** Signs out of this private node: it forgets our access cookie. */
export async function signOut() {
  await fetch("/api/auth", { method: "DELETE" });
}

// ---- handing keys from the sign-in page to the app ----
//
// So that getting in takes one passkey prompt, not two: the sign-in page leaves the secret for the app,
// in this tab only, and the app takes it on load.

const HANDOFF_KEY = "bisonbase-handoff";

export function handOff(secret: Uint8Array, ids: PasskeyIds) {
  try {
    sessionStorage.setItem(HANDOFF_KEY, JSON.stringify({ secret: b64(secret), ...ids }));
  } catch {}
}

/** The secret the sign-in page left, if any; it's then gone. */
export function takeHandoff(): { secret: Uint8Array<ArrayBuffer>; ids: PasskeyIds } | null {
  try {
    const s = sessionStorage.getItem(HANDOFF_KEY);
    sessionStorage.removeItem(HANDOFF_KEY);
    if (!s) return null;
    const { secret, credId, name } = JSON.parse(s);
    if (typeof secret !== "string" || typeof credId !== "string" || (name !== null && typeof name !== "string")) return null;
    return { secret: unb64(secret), ids: { credId, name } };
  } catch {
    return null;
  }
}
