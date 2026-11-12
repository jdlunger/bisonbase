// Converting values between their TypeScript form and what the API sends over the wire:
// booleans are stored as 0/1, blobs travel as {"$base64": ...}, json is stored as text.

import type { ColumnType, Wire } from './types.ts'

export function toBase64(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return btoa(s)
}

export function fromBase64(b64: string): Uint8Array {
  const s = atob(b64)
  const bytes = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i)
  return bytes
}

/** Describe a value for an error message. */
function describe(value: unknown): string {
  if (value === null) return 'null'
  if (value instanceof Uint8Array) return 'Uint8Array'
  if (Array.isArray(value)) return 'array'
  return typeof value
}

const EXPECTED: Record<ColumnType, string> = {
  text: 'a string',
  integer: 'an integer',
  real: 'a finite number',
  boolean: 'a boolean',
  blob: 'a Uint8Array',
  json: 'a JSON value',
}

/** Convert a column value to its wire form, checking its type. `column` names it in errors. */
export function encode(type: ColumnType, nullable: boolean, value: unknown, column: string): Wire {
  const bad = () =>
    new TypeError(`Column "${column}" expects ${EXPECTED[type]}${nullable ? ' or null' : ''}, got ${describe(value)}`)
  if (value === undefined) throw bad()
  if (value === null) {
    if (nullable) return null
    if (type === 'json') return 'null'
    throw bad()
  }
  switch (type) {
    case 'text':
      if (typeof value !== 'string') throw bad()
      return value
    case 'integer':
      if (typeof value !== 'number' || !Number.isSafeInteger(value)) throw bad()
      return value
    case 'real':
      if (typeof value !== 'number' || !Number.isFinite(value)) throw bad()
      return value
    case 'boolean':
      if (typeof value !== 'boolean') throw bad()
      return value ? 1 : 0
    case 'blob':
      if (!(value instanceof Uint8Array)) throw bad()
      return { $base64: toBase64(value) }
    case 'json': {
      const text = JSON.stringify(value)
      if (text === undefined) throw bad()
      return text
    }
  }
}

/** Convert a wire value read from a column back to its TypeScript form. */
export function decode(type: ColumnType, value: Wire): unknown {
  if (value === null) return null
  switch (type) {
    case 'boolean':
      return value !== 0 && value !== '0' && value !== ''
    case 'blob':
      return typeof value === 'object' ? fromBase64(value.$base64) : new TextEncoder().encode(String(value))
    case 'json':
      // SQLite may have stored numeric JSON as a number (the column has numeric affinity).
      return typeof value === 'string' ? JSON.parse(value) : value
    default:
      return value
  }
}

/** Convert a value used in raw SQL (`db.sql`) to its wire form. */
export function encodeParam(value: unknown): Wire {
  if (value === null || typeof value === 'string') return value
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`SQL parameter must be finite, got ${value}`)
    return value
  }
  if (typeof value === 'boolean') return value ? 1 : 0
  if (value instanceof Uint8Array) return { $base64: toBase64(value) }
  if (value === undefined) throw new TypeError('SQL parameter is undefined')
  return JSON.stringify(value)
}
