// Bringing a per-user database in line with the tables the app declares: create missing
// tables, add new columns, and refuse anything that would change or drop existing data.

import { addColumnSql, createTableSql, SQL_TYPES } from './sql.ts'
import type { TableDef } from './table.ts'

/** What `GET ?op=schema` returns. */
export interface ServerSchema {
  tables: {
    name: string
    type: string
    columns: { name: string; type: string; not_null: boolean; default: unknown; pk: boolean }[]
  }[]
}

/** The database's tables don't match the app's and can't be changed to match safely. */
export class SchemaError extends Error {
  override name = 'SchemaError'
}

/** The statements that bring `server` in line with `tables`. Throws SchemaError if that's unsafe. */
export function migrationSql(tables: Iterable<TableDef>, server: ServerSchema, db: string): string[] {
  const existing = new Map(server.tables.map((t) => [t.name.toLowerCase(), t]))
  const statements: string[] = []
  const fail = (table: string, msg: string) => {
    throw new SchemaError(`Table "${table}" in ${db}: ${msg}`)
  }
  for (const table of tables) {
    const found = existing.get(table.name.toLowerCase())
    if (!found) {
      statements.push(createTableSql(table))
      continue
    }
    if (found.type !== 'table') fail(table.name, `the database has a ${found.type} with this name`)
    const cols = new Map(found.columns.map((c) => [c.name.toLowerCase(), c]))
    const id = cols.get('id')
    if (!id || !id.pk || id.type.toUpperCase() !== 'INTEGER') {
      fail(table.name, 'it exists but has no "id INTEGER PRIMARY KEY" column, so it wasn\'t created by this library')
    }
    if (found.columns.filter((c) => c.pk).length > 1) fail(table.name, 'it has a composite primary key')
    for (const col of table.columns) {
      const have = cols.get(col.name.toLowerCase())
      const want = SQL_TYPES[col.type]
      if (!have) {
        if (!col.nullable && !col.default) {
          fail(table.name, `new column "${col.name}" needs a default (or make it nullable) so existing rows get a value`)
        }
        statements.push(addColumnSql(table, col))
        continue
      }
      if (have.type.toUpperCase() !== want) {
        fail(table.name, `column "${col.name}" is ${have.type || 'untyped'} in the database but declared as ${col.type}; changing a column's type isn't supported`)
      }
      if (have.not_null === col.nullable) {
        const [was, now] = have.not_null ? ['NOT NULL', 'nullable'] : ['nullable', 'not nullable']
        fail(table.name, `column "${col.name}" is ${was} in the database but declared ${now}; changing that isn't supported`)
      }
    }
    for (const have of found.columns) {
      const name = have.name.toLowerCase()
      if (name !== 'id' && !table.columns.some((c) => c.name.toLowerCase() === name)) {
        fail(table.name, `column "${have.name}" is in the database but not declared; removing columns isn't supported because it would lose data. Declare it again`)
      }
    }
  }
  return statements
}
