// Compiles structured operations (select / insert / update / delete) to SQL with quoted
// identifiers and bound parameters. Nothing outside this file and schema.ts writes SQL, so
// these operations can later move to a server-side relational API without changing callers.

import { encode } from './values.ts'
import type { ColumnDef, TableDef } from './table.ts'
import type { ColumnType, Wire } from './types.ts'

export interface Statement {
  sql: string
  params: Wire[]
}

export const quote = (name: string) => `"${name.replaceAll('"', '""')}"`

export const SQL_TYPES: Record<ColumnType, string> = {
  text: 'TEXT',
  integer: 'INTEGER',
  real: 'REAL',
  boolean: 'BOOLEAN',
  blob: 'BLOB',
  json: 'JSON',
}

const ID: ColumnDef = { name: 'id', type: 'integer', nullable: false }

function column(table: TableDef, name: string): ColumnDef {
  if (name === 'id') return ID
  const col = table.byName.get(name)
  if (!col) throw new Error(`Table "${table.name}" has no column "${name}"`)
  return col
}

/** A default value as an SQL literal (DEFAULT clauses can't take parameters). */
export function literal(col: ColumnDef, value: unknown): string {
  const wire = encode(col.type, col.nullable, value, col.name)
  if (wire === null) return 'NULL'
  if (typeof wire === 'number') return String(wire)
  if (typeof wire === 'string') return `'${wire.replaceAll("'", "''")}'`
  const hex = Array.from(atob(wire.$base64), (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
  return `X'${hex}'`
}

/** A column definition for CREATE TABLE or ALTER TABLE ADD COLUMN. */
export function columnSql(col: ColumnDef): string {
  let sql = `${quote(col.name)} ${SQL_TYPES[col.type]}`
  if (!col.nullable) sql += ' NOT NULL'
  if (col.default) sql += ` DEFAULT ${literal(col, col.default.value)}`
  return sql
}

export function createTableSql(table: TableDef): string {
  const cols = [`"id" INTEGER PRIMARY KEY`, ...table.columns.map(columnSql)]
  return `CREATE TABLE IF NOT EXISTS ${quote(table.name)} (${cols.join(', ')})`
}

export function addColumnSql(table: TableDef, col: ColumnDef): string {
  return `ALTER TABLE ${quote(table.name)} ADD COLUMN ${columnSql(col)}`
}

const allColumns = (table: TableDef) => ['id', ...table.columns.map((c) => c.name)].map(quote).join(', ')

const OPS: Record<string, string> = { $ne: '<>', $lt: '<', $lte: '<=', $gt: '>', $gte: '>=' }

function isOps(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || value instanceof Uint8Array || Array.isArray(value)) return false
  const keys = Object.keys(value)
  return keys.length > 0 && keys.every((k) => k.startsWith('$'))
}

/** A WHERE clause (including the keyword, or empty) and its parameters. */
export function whereSql(table: TableDef, where: object | number | undefined, params: Wire[]): string {
  if (where === undefined) return ''
  if (typeof where === 'number') where = { id: where }
  const terms: string[] = []
  for (const [name, cond] of Object.entries(where)) {
    const col = column(table, name)
    const q = quote(name)
    if (cond === undefined) throw new Error(`where.${name} is undefined; leave it out or use null`)
    if (!isOps(cond)) {
      if (cond === null) terms.push(`${q} IS NULL`)
      else {
        terms.push(`${q} = ?`)
        params.push(encode(col.type, col.nullable, cond, name))
      }
      continue
    }
    for (const [op, value] of Object.entries(cond)) {
      if (value === undefined) continue
      if (op === '$in') {
        if (!Array.isArray(value)) throw new Error(`where.${name}.$in must be an array`)
        if (value.length === 0) {
          terms.push('0')
          continue
        }
        terms.push(`${q} IN (${value.map(() => '?').join(', ')})`)
        for (const v of value) params.push(encode(col.type, col.nullable, v, name))
      } else if (op === '$ne' && value === null) {
        terms.push(`${q} IS NOT NULL`)
      } else if (op === '$ne') {
        // Like JavaScript's !==, NULL counts as different from any value.
        terms.push(`${q} IS NOT ?`)
        params.push(encode(col.type, col.nullable, value, name))
      } else if (OPS[op]) {
        terms.push(`${q} ${OPS[op]} ?`)
        params.push(encode(col.type, col.nullable, value, name))
      } else {
        throw new Error(`Unknown operator where.${name}.${op}`)
      }
    }
  }
  return terms.length ? ` WHERE ${terms.join(' AND ')}` : ''
}

function orderSql(table: TableDef, orderBy: string | readonly string[] | undefined): string {
  if (orderBy === undefined) return ''
  const items = typeof orderBy === 'string' ? [orderBy] : orderBy
  if (items.length === 0) return ''
  const parts = items.map((item) => {
    const [name, dir = 'asc', ...rest] = item.trim().split(/\s+/)
    const d = dir.toLowerCase()
    if (rest.length || (d !== 'asc' && d !== 'desc')) throw new Error(`Bad orderBy "${item}"; use "column" or "column desc"`)
    column(table, name)
    return `${quote(name)} ${d.toUpperCase()}`
  })
  return ` ORDER BY ${parts.join(', ')}`
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

export function selectSql(table: TableDef, opts: SelectSpec = {}): Statement {
  const params: Wire[] = []
  let sql = `SELECT ${allColumns(table)} FROM ${quote(table.name)}`
  sql += whereSql(table, opts.where, params)
  sql += orderSql(table, opts.orderBy)
  const hasLimit = count('limit', opts.limit)
  const hasOffset = count('offset', opts.offset)
  if (hasLimit || hasOffset) {
    sql += ' LIMIT ?'
    params.push(hasLimit ? opts.limit! : -1)
  }
  if (hasOffset) {
    sql += ' OFFSET ?'
    params.push(opts.offset!)
  }
  return { sql, params }
}

/** INSERT one row, filling in defaults here so the code's defaults win over the database's. */
export function insertSql(table: TableDef, row: Record<string, unknown>): Statement {
  for (const name of Object.keys(row)) column(table, name)
  const names: string[] = []
  const params: Wire[] = []
  if (row.id !== undefined) {
    names.push('id')
    params.push(encode('integer', false, row.id, 'id'))
  }
  for (const col of table.columns) {
    let value = row[col.name]
    if (value === undefined) {
      if (col.default) value = col.default.value
      else if (col.nullable) value = null
      else throw new Error(`Missing value for column "${col.name}" of table "${table.name}"`)
    }
    names.push(col.name)
    params.push(encode(col.type, col.nullable, value, col.name))
  }
  const sql = names.length
    ? `INSERT INTO ${quote(table.name)} (${names.map(quote).join(', ')}) VALUES (${names.map(() => '?').join(', ')})`
    : `INSERT INTO ${quote(table.name)} DEFAULT VALUES`
  return { sql: `${sql} RETURNING ${allColumns(table)}`, params }
}

/** UPDATE matching rows, or null when there's nothing to set. */
export function updateSql(table: TableDef, where: object | number, changes: Record<string, unknown>): Statement | null {
  const params: Wire[] = []
  const sets: string[] = []
  for (const [name, value] of Object.entries(changes)) {
    if (value === undefined) continue
    if (name === 'id') throw new Error("A row's id can't be changed")
    const col = column(table, name)
    sets.push(`${quote(name)} = ?`)
    params.push(encode(col.type, col.nullable, value, name))
  }
  if (sets.length === 0) return null
  const sql = `UPDATE ${quote(table.name)} SET ${sets.join(', ')}${whereSql(table, where, params)}`
  return { sql, params }
}

export function deleteSql(table: TableDef, where: object | number): Statement {
  const params: Wire[] = []
  return { sql: `DELETE FROM ${quote(table.name)}${whereSql(table, where, params)}`, params }
}
