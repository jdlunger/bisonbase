// A table's columns, normalized from the spec passed to createTable.

import type { ColumnSpec, ColumnType, Columns } from './types.ts'

export interface ColumnDef {
  name: string
  type: ColumnType
  nullable: boolean
  /** Present when the column has a default. */
  default?: { value: unknown }
}

export interface TableDef {
  name: string
  /** Every column except `id`, in declaration order. */
  columns: ColumnDef[]
  byName: Map<string, ColumnDef>
}

const TYPES: readonly ColumnType[] = ['text', 'integer', 'real', 'boolean', 'blob', 'json']
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/

/** Check that a table or column name is a plain identifier. */
export function checkName(kind: string, name: string): void {
  if (!IDENT.test(name)) {
    throw new Error(`${kind} name "${name}" must be letters, digits and underscores, not starting with a digit`)
  }
  if (name.toLowerCase().startsWith('sqlite_')) throw new Error(`${kind} name "${name}" is reserved by SQLite`)
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

export function parseTable(name: string, columns: Columns): TableDef {
  checkName('Table', name)
  const defs = Object.entries(columns).map(([col, spec]) => parseColumn(col, spec))
  const byName = new Map(defs.map((c) => [c.name, c]))
  return { name, columns: defs, byName }
}
