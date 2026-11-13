// Declared tables as the server's `migrate` op takes them. The server creates missing tables,
// adds new columns, and refuses anything that would change or drop existing data.

import { encode } from './values.ts'
import type { TableDef } from './table.ts'
import type { ColumnType, Wire } from './types.ts'

export interface MigrateRequest {
  tables: {
    name: string
    columns: { name: string; type: ColumnType; nullable: boolean; default?: Wire }[]
    /** App databases only. */
    sharing?: 'private' | 'shared'
  }[]
}

/** The database's tables don't match the app's and can't be changed to match safely. */
export class SchemaError extends Error {
  override name = 'SchemaError'
}

export function migrateRequest(tables: Iterable<TableDef>): MigrateRequest {
  return {
    tables: [...tables].map((t) => ({
      name: t.name,
      columns: t.columns.map((c) => ({
        name: c.name,
        type: c.type,
        nullable: c.nullable,
        ...(c.default ? { default: encode(c.type, c.nullable, c.default.value, c.name) } : {}),
      })),
      ...(t.owned ? { sharing: t.owned.sharing } : {}),
    })),
  }
}
