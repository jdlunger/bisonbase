// Who signs records: a user's own key, or another key (e.g. an app's) signing for a user, under a
// "delegate" record the user wrote (see "user spaces" in core/src/lib.rs). Also the connect flow, by which
// an app asks a user for such a delegation.

import { type Acting, b58, decodeId, unb58 } from "./core.ts";

export type Signer = {
  /** The public key that signs: the record's `author`. */
  key: Uint8Array;
  sign(bytes: Uint8Array): Promise<Uint8Array>;
  /** Signing for this user, under their delegation: the record's `as`. */
  as?: Acting;
};

/** Whose records a signer writes: the user it signs for, or else its own key's. */
export const principal = (s: Signer) => s.as?.user ?? s.key;

/** PKCS#8 wrapper for a raw 32-byte Ed25519 seed, which is how WebCrypto wants it. */
const ED25519_PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

const b64urlDecode = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

/** An Ed25519 key pair from a 32-byte seed; the private key isn't extractable. */
export async function keyPairFromSeed(seed: Uint8Array): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const pkcs8 = new Uint8Array([...ED25519_PKCS8_PREFIX, ...seed]);
  // Import once extractable just to read the public key out of the JWK, then keep a non-extractable copy.
  const jwk = await crypto.subtle.exportKey("jwk", await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]));
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, ["sign"]);
  pkcs8.fill(0);
  return { privateKey, publicKey: b64urlDecode(jwk.x!) };
}

/** A fresh Ed25519 key pair, e.g. an app's; the private key isn't extractable, but can be kept in IndexedDB. */
export async function newKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const k = (await crypto.subtle.generateKey("Ed25519", false, ["sign"])) as CryptoKeyPair;
  return { privateKey: k.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", k.publicKey)) };
}

/** A signer for an Ed25519 private key; with `as`, signing for that user under their delegation. */
export const keySigner = (privateKey: CryptoKey, publicKey: Uint8Array, as?: Acting): Signer => ({
  key: publicKey,
  sign: async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, bytes as Uint8Array<ArrayBuffer>)),
  as,
});

// ---- the connect flow ----
//
// An app makes its own key, then sends the user to their bisonbase page's /connect (see `connectUrl`),
// saying what it wants to write. If they agree, that page writes a delegation for the app's key and
// sends them back to `returnTo`, with the user and the delegation in its fragment (see `connectResult`).

/** What an app asks to write for a user: `paths` and `types` (none: anywhere, anything), until `expires`
 * (ms since the epoch). `name` is how it's shown. */
export type ConnectRequest = { key: Uint8Array; name: string; paths?: string[]; types?: string[]; expires?: number; returnTo: string };

/** Where to send a user to connect an app: `origin` is their bisonbase page's. */
export function connectUrl(origin: string, r: ConnectRequest) {
  const p = new URLSearchParams({ key: b58(r.key), name: r.name, return: r.returnTo });
  if (r.paths?.length) p.set("paths", r.paths.join(","));
  if (r.types?.length) p.set("types", r.types.join(","));
  if (r.expires) p.set("expires", String(r.expires));
  return `${origin.replace(/\/+$/, "")}/connect#${p}`;
}

/** Parses /connect's fragment (as `connectUrl` builds it). Throws if it's malformed. */
export function parseConnectRequest(fragment: string): ConnectRequest {
  const p = new URLSearchParams(fragment.replace(/^#/, ""));
  const key = decodeId(p.get("key") ?? "");
  const returnTo = p.get("return") ?? "";
  if (!key) throw new Error("The app's key isn't an ID (32 bytes of base58).");
  if (!/^https?:\/\//.test(returnTo)) throw new Error("The app's return address isn't an http(s) URL.");
  const list = (k: string) => p.get(k)?.split(",").map((s) => s.trim()).filter(Boolean);
  const expires = Number(p.get("expires")) || undefined;
  return { key, name: (p.get("name") ?? "").trim(), paths: list("paths"), types: list("types"), expires, returnTo };
}

/** What /connect sends back: the user, their delegation's hash, and their node's URL (base58 but the URL). */
export type ConnectResult = { user: Uint8Array; delegation: Uint8Array; node: string };

/** Where /connect sends the user back to, once they've agreed. */
export function connectReturnUrl(returnTo: string, r: ConnectResult) {
  const url = new URL(returnTo);
  url.hash = new URLSearchParams({ bisonbase_user: b58(r.user), bisonbase_delegation: b58(r.delegation), bisonbase_node: r.node }).toString();
  return url.toString();
}

/** The result in `fragment` (location.hash, back from /connect), or null if there's none. */
export function connectResult(fragment: string): ConnectResult | null {
  const p = new URLSearchParams(fragment.replace(/^#/, ""));
  const user = decodeId(p.get("bisonbase_user") ?? "");
  const delegation = unb58(p.get("bisonbase_delegation") ?? "");
  const node = p.get("bisonbase_node");
  return user && delegation?.length === 32 && node ? { user, delegation, node } : null;
}
