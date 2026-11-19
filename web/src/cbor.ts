// Deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding), the subset records use: integers
// (safe JS integers only), byte strings (Uint8Array), text, arrays, maps with text keys (plain
// objects; undefined values are left out), booleans and null. No floats, tags or indefinite lengths.
// The decoder rejects anything not deterministically encoded. Keep in sync with src/lib.rs.

export type Cbor = number | Uint8Array | string | Cbor[] | { [k: string]: Cbor | undefined } | boolean | null;

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder("utf-8", { fatal: true });

function head(major: number, n: number): number[] {
  const m = major << 5;
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) return [m | 26, n >>> 24, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  const b = BigInt(n);
  return [m | 27, ...[56, 48, 40, 32, 24, 16, 8, 0].map((s) => Number((b >> BigInt(s)) & 0xffn))];
}

/** Deterministic map key order: by encoded bytes, which for text keys is by length, then bytewise. */
function keyOrder(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

export function encode(v: Cbor): Uint8Array<ArrayBuffer> {
  const parts: (number[] | Uint8Array)[] = [];
  const go = (v: Cbor) => {
    if (v === null) parts.push([0xf6]);
    else if (v === true) parts.push([0xf5]);
    else if (v === false) parts.push([0xf4]);
    else if (typeof v === "number") {
      if (!Number.isSafeInteger(v)) throw new Error(`CBOR: ${v} isn't a safe integer`);
      parts.push(v >= 0 ? head(0, v) : head(1, -1 - v));
    } else if (typeof v === "string") {
      const b = utf8.encode(v);
      parts.push(head(3, b.length), b);
    } else if (v instanceof Uint8Array) parts.push(head(2, v.length), v);
    else if (Array.isArray(v)) {
      parts.push(head(4, v.length));
      v.forEach(go);
    } else {
      const entries = Object.entries(v)
        .filter((e): e is [string, Cbor] => e[1] !== undefined)
        .map(([k, val]) => [utf8.encode(k), k, val] as const)
        .sort((a, b) => keyOrder(a[0], b[0]));
      parts.push(head(5, entries.length));
      for (const [kb, , val] of entries) {
        parts.push(head(3, kb.length), kb);
        go(val);
      }
    }
  };
  go(v);
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Decodes exactly one value, which must be deterministically encoded and fill all of `bytes`. */
export function decode(bytes: Uint8Array): Cbor {
  let at = 0;
  const take = (n: number) => {
    if (at + n > bytes.length) throw new Error("CBOR: truncated");
    return bytes.subarray(at, (at += n));
  };
  const arg = (info: number) => {
    if (info < 24) return info;
    const size = { 24: 1, 25: 2, 26: 4, 27: 8 }[info];
    if (!size) throw new Error("CBOR: indefinite lengths aren't allowed");
    let n = 0n;
    for (const b of take(size)) n = (n << 8n) | BigInt(b);
    if (n < (size === 1 ? 24n : 1n << BigInt(4 * size))) throw new Error("CBOR: not in shortest form");
    if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("CBOR: integer too large");
    return Number(n);
  };
  const value = (depth: number): Cbor => {
    if (depth > 32) throw new Error("CBOR: nested too deeply");
    const ib = take(1)[0];
    const [major, info] = [ib >> 5, ib & 0x1f];
    if (major === 7) {
      const simple = { 20: false, 21: true, 22: null }[info];
      if (simple === undefined) throw new Error("CBOR: only true, false and null simple values are allowed");
      return simple;
    }
    const n = arg(info);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
        return take(n).slice();
      case 3:
        return fromUtf8.decode(take(n));
      case 4:
        return Array.from({ length: n }, () => value(depth + 1));
      case 5: {
        const m: { [k: string]: Cbor } = {};
        let prev: Uint8Array | null = null;
        for (let i = 0; i < n; i++) {
          const kStart = at;
          const k = value(depth + 1);
          if (typeof k !== "string") throw new Error("CBOR: map keys must be text");
          const kb = bytes.subarray(kStart, at);
          if (prev && keyOrder(prev, kb) >= 0) throw new Error("CBOR: map keys out of order, or duplicated");
          if (k === "__proto__") throw new Error("CBOR: bad map key");
          prev = kb;
          m[k] = value(depth + 1);
        }
        return m;
      }
      default:
        throw new Error("CBOR: tags aren't allowed");
    }
  };
  const v = value(0);
  if (at !== bytes.length) throw new Error("CBOR: trailing bytes");
  return v;
}
