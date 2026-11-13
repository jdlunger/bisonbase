// A table's columns, normalized from the spec passed to createTable.

import type { ColumnSpec, ColumnType, Columns } from './types.ts'

export interface ColumnDef {
  name: string
  type: ColumnType
  nullable: boolean
  /** Present when the column has a default. */
  default?: { value: unknown }
}

/** Who may read a table's rows in an app database (only a row's owner may change it). */
export type Sharing = 'private' | 'shared'

export interface TableDef {
  name: string
  /** Every column except `id` (and `_owner`), in declaration order. */
  columns: ColumnDef[]
  byName: Map<string, ColumnDef>
  /** In an app database: rows have an `_owner`, set by the server. */
  owned?: { sharing: Sharing }
}

/** The column holding a row's owner (a user id) in app databases. */
export const OWNER = '_owner'

const TYPES: readonly ColumnType[] = ['text', 'integer', 'real', 'boolean', 'blob', 'json']
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/

/** Check that a table or column name is a plain identifier. */
export function checkName(kind: string, name: string): void {
  if (!IDENT.test(name)) {
    throw new Error(`${kind} name "${name}" must be letters, digits and underscores, not starting with a digit`)
  }
  if (name.toLowerCase().startsWith('sqlite_')) throw new Error(`${kind} name "${name}" is reserved by SQLite`)
  if (name.toLowerCase().startsWith('_bisonbase')) throw new Error(`${kind} name "${name}" is reserved by bisonbase`)
}

function parseColumn(name: string, spec: ColumnSpec): ColumnDef {
  checkName('Column', name)
  if (name.toLowerCase() === 'id') throw new Error('Every table gets an "id" column automatically; don\'t declare one')
  const [base, hasDefault, value] = Array.isArray(spec) ? [spec[0], true, spec[1]] : [spec as string, false, undefined]
  const nullable = base.endsWith('?')
  const type = (nullable ? base.slice(0, -1) : base) as ColumnType
  if (!TYPES.includes(type)) {
    throw new Error(`Column "${name}" has unknown type "${base}"; use one of ${TYPES.join(', ')}`)
  }
  return { name, type, nullable, ...(hasDefault ? { default: { value } } : {}) }
}

export function parseTable(name: string, columns: Columns, owned?: { sharing: Sharing }): TableDef {
  checkName('Table', name)
  if (owned && Object.keys(columns).some((c) => c.toLowerCase() === OWNER)) {
    throw new Error(`Every table in an app database gets an "${OWNER}" column automatically; don't declare one`)
  }
  if (owned && owned.sharing !== 'private' && owned.sharing !== 'shared') {
    throw new Error(`Table "${name}": sharing must be "private" or "shared"`)
  }
  const defs = Object.entries(columns).map(([col, spec]) => parseColumn(col, spec))
  const byName = new Map(defs.map((c) => [c.name, c]))
  return { name, columns: defs, byName, ...(owned ? { owned } : {}) }
}
