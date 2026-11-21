// Encryption for encrypted docs (see "shared documents" in core/src/lib.rs). Each user publishes an
// X25519 public key ("enckey" record). An encrypted doc has a random 32-byte content key, sealed to each
// of its readers; its updates and snapshots are that key's AES-256-GCM ciphertext.
//
//   sealed      ephemeral X25519 public key (32) || nonce (12) || AES-256-GCM ciphertext, under
//               HKDF-SHA256(X25519(ephemeral, recipient), salt: ephemeral || recipient, info: SEAL_INFO)
//   encrypted   nonce (12) || AES-256-GCM ciphertext under the content key, the doc's hash as
//               additional data, so ciphertext can't be moved to another doc
//
// Removing an editor doesn't take back the key they had: what they could read, they still can.

const subtle = crypto.subtle;
const enc = new TextEncoder();
const SEAL_INFO = enc.encode("bisonbase-seal-v1");
const X25519_PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

const buf = (b: Uint8Array) => b as Uint8Array<ArrayBuffer>;
const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));

/** A user's X25519 key pair, for opening what's sealed to them. */
export type EncKeys = { privateKey: CryptoKey; publicKey: Uint8Array };

/** An X25519 key pair from a 32-byte seed; the private key isn't extractable. */
export async function encKeysFromSeed(seed: Uint8Array): Promise<EncKeys> {
  const pkcs8 = new Uint8Array([...X25519_PKCS8_PREFIX, ...seed]);
  const jwk = await subtle.exportKey("jwk", await subtle.importKey("pkcs8", pkcs8, "X25519", true, ["deriveBits"]));
  const privateKey = await subtle.importKey("pkcs8", pkcs8, "X25519", false, ["deriveBits"]);
  pkcs8.fill(0);
  return { privateKey, publicKey: Uint8Array.from(atob(jwk.x!.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)) };
}

async function sealKey(privateKey: CryptoKey, publicKey: Uint8Array, salt: Uint8Array) {
  const peer = await subtle.importKey("raw", buf(publicKey), "X25519", false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: peer }, privateKey, 256);
  const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: buf(salt), info: SEAL_INFO }, ikm, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** `plaintext`, sealed to whoever has the private half of `recipient` (an X25519 public key). */
export async function seal(recipient: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const eph = (await subtle.generateKey("X25519", false, ["deriveBits"])) as CryptoKeyPair;
  const ephPub = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const key = await sealKey(eph.privateKey, recipient, new Uint8Array([...ephPub, ...recipient]));
  const nonce = random(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, buf(plaintext)));
  return new Uint8Array([...ephPub, ...nonce, ...ct]);
}

/** Opens what `seal` sealed to `keys`. Throws if it wasn't sealed to them, or was changed. */
export async function unseal(keys: EncKeys, sealed: Uint8Array): Promise<Uint8Array> {
  const ephPub = sealed.subarray(0, 32);
  const key = await sealKey(keys.privateKey, ephPub, new Uint8Array([...ephPub, ...keys.publicKey]));
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: buf(sealed.subarray(32, 44)) }, key, buf(sealed.subarray(44))));
}

/** A fresh content key for an encrypted doc. */
export const newDocKey = () => random(32);

const aes = (docKey: Uint8Array) => subtle.importKey("raw", buf(docKey), "AES-GCM", false, ["encrypt", "decrypt"]);

/** Encrypts an update or snapshot of the doc `doc` (its hash). */
export async function encrypt(docKey: Uint8Array, doc: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  const nonce = random(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: buf(doc) }, await aes(docKey), buf(plaintext));
  return new Uint8Array([...nonce, ...new Uint8Array(ct)]);
}

/** Decrypts what `encrypt` made for the doc `doc`. Throws if it's for another key or doc, or was changed. */
export async function decrypt(docKey: Uint8Array, doc: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await subtle.decrypt({ name: "AES-GCM", iv: buf(data.subarray(0, 12)), additionalData: buf(doc) }, await aes(docKey), buf(data.subarray(12))),
  );
}
