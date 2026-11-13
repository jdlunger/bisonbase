// Builds requests for the server's relational API (select / insert / update / delete) from the
// typed options tables take. Names and value types are checked here, so mistakes throw where
// they're written; the server checks names again against the database itself.

import { encode } from './values.ts'
import { OWNER, type ColumnDef, type TableDef } from './table.ts'
import type { Wire } from './types.ts'

/** A where clause as sent: values in wire form, operators as is. */
export type WireWhere = Record<string, Wire | Record<string, Wire | Wire[]>>

export interface SelectRequest {
  table: string
  where?: WireWhere
  order_by?: string[]
  limit?: number
  offset?: number
}

export interface InsertRequest {
  table: string
  rows: Record<string, Wire>[]
}

export interface UpdateRequest {
  table: string
  where: WireWhere
  set: Record<string, Wire>
}

export interface DeleteRequest {
  table: string
  where: WireWhere
}

const ID: ColumnDef = { name: 'id', type: 'integer', nullable: false }
const OWNER_COL: ColumnDef = { name: OWNER, type: 'text', nullable: false }

function column(table: TableDef, name: string): ColumnDef {
  if (name === 'id') return ID
  if (name === OWNER && table.owned) return OWNER_COL
  const col = table.byName.get(name)
  if (!col) throw new Error(`Table "${table.name}" has no column "${name}"`)
  return col
}

const OPS = new Set(['$ne', '$lt', '$lte', '$gt', '$gte', '$in'])

function isOps(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || value instanceof Uint8Array || Array.isArray(value)) return false
  const keys = Object.keys(value)
  return keys.length > 0 && keys.every((k) => k.startsWith('$'))
}

export function whereWire(table: TableDef, where: object | number): WireWhere {
  if (typeof where === 'number') where = { id: where }
  const out: WireWhere = {}
  for (const [name, cond] of Object.entries(where)) {
    const col = column(table, name)
    if (cond === undefined) throw new Error(`where.${name} is undefined; leave it out or use null`)
    const enc = (v: unknown) => encode(col.type, col.nullable, v, name)
    if (!isOps(cond)) {
      // null means IS NULL, even for a column that can't hold it.
      out[name] = cond === null ? null : enc(cond)
      continue
    }
    const ops: Record<string, Wire | Wire[]> = {}
    for (const [op, value] of Object.entries(cond)) {
      if (value === undefined) continue
      if (!OPS.has(op)) throw new Error(`Unknown operator where.${name}.${op}`)
      if (op === '$in') {
        if (!Array.isArray(value)) throw new Error(`where.${name}.$in must be an array`)
        ops[op] = value.map(enc)
      } else {
        ops[op] = op === '$ne' && value === null ? null : enc(value)
      }
    }
    // Every operator was undefined: no condition on this column.
    if (Object.keys(ops).length) out[name] = ops
  }
  return out
}

function orderBy(table: TableDef, order: string | readonly string[] | undefined): string[] | undefined {
  if (order === undefined) return undefined
  const items = typeof order === 'string' ? [order] : order
  return items.map((item) => {
    const [name, dir = 'asc', ...rest] = item.trim().split(/\s+/)
    const d = dir.toLowerCase()
    if (rest.length || (d !== 'asc' && d !== 'desc')) throw new Error(`Bad orderBy "${item}"; use "column" or "column desc"`)
    column(table, name)
    return `${name} ${d}`
  })
}

function count(name: string, n: number | undefined): n is number {
  if (n === undefined) return false
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${name} must be a non-negative integer`)
  return true
}

export interface SelectSpec {
  where?: object | number
  orderBy?: string | readonly string[]
  limit?: number
  offset?: number
}

export function selectRequest(table: TableDef, opts: SelectSpec = {}): SelectRequest {
  const req: SelectRequest = { table: table.name }
  if (opts.where !== undefined) req.where = whereWire(table, opts.where)
  const order = orderBy(table, opts.orderBy)
  if (order?.length) req.order_by = order
  if (count('limit', opts.limit)) req.limit = opts.limit
  if (count('offset', opts.offset)) req.offset = opts.offset
  return req
}

/** One row to insert, with defaults filled in here so the code's defaults win over the database's. */
export function insertRow(table: TableDef, row: Record<string, unknown>): Record<string, Wire> {
  for (const name of Object.keys(row)) {
    if (name === OWNER && table.owned) throw new Error(`${OWNER} is set by the server to the signed-in user`)
    column(table, name)
  }
  const out: Record<string, Wire> = {}
  if (row.id !== undefined) out.id = encode('integer', false, row.id, 'id')
  for (const col of table.columns) {
    let value = row[col.name]
    if (value === undefined) {
      if (col.default) value = col.default.value
      else if (col.nullable) value = null
      else throw new Error(`Missing value for column "${col.name}" of table "${table.name}"`)
    }
    out[col.name] = encode(col.type, col.nullable, value, col.name)
  }
  return out
}

export function insertRequest(table: TableDef, rows: readonly Record<string, unknown>[]): InsertRequest {
  return { table: table.name, rows: rows.map((r) => insertRow(table, r)) }
}

/** An update of matching rows, or null when there's nothing to set. */
export function updateRequest(table: TableDef, where: object | number, changes: Record<string, unknown>): UpdateRequest | null {
  const set: Record<string, Wire> = {}
  for (const [name, value] of Object.entries(changes)) {
    if (value === undefined) continue
    if (name === 'id') throw new Error("A row's id can't be changed")
    if (name === OWNER && table.owned) throw new Error(`A row's ${OWNER} can't be changed`)
    const col = column(table, name)
    set[name] = encode(col.type, col.nullable, value, name)
  }
  if (Object.keys(set).length === 0) return null
  return { table: table.name, where: whereWire(table, where), set }
}

export function deleteRequest(table: TableDef, where: object | number): DeleteRequest {
  return { table: table.name, where: whereWire(table, where) }
}
