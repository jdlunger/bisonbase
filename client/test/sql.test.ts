import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseTable } from '../src/table.ts'
import { createTableSql, deleteSql, insertSql, selectSql, updateSql } from '../src/sql.ts'
import { migrationSql, SchemaError, type ServerSchema } from '../src/schema.ts'
import { decode, encode, encodeParam, fromBase64, toBase64 } from '../src/values.ts'

const todos = parseTable('todos', {
  content: 'text',
  done: ['boolean', false],
  note: 'text?',
  meta: ['json', { tags: [] }],
  pic: 'blob?',
})

test('create table', () => {
  assert.equal(
    createTableSql(todos),
    `CREATE TABLE IF NOT EXISTS "todos" ("id" INTEGER PRIMARY KEY, "content" TEXT NOT NULL, ` +
      `"done" BOOLEAN NOT NULL DEFAULT 0, "note" TEXT, "meta" JSON NOT NULL DEFAULT '{"tags":[]}', "pic" BLOB)`,
  )
  const t = parseTable('t', { s: ['text', "it's"], b: ['blob?', new Uint8Array([0, 255])], r: ['real', -1.5] })
  assert.match(createTableSql(t), /"s" TEXT NOT NULL DEFAULT 'it''s', "b" BLOB DEFAULT X'00ff', "r" REAL NOT NULL DEFAULT -1.5/)
})

test('bad declarations', () => {
  assert.throws(() => parseTable('t', { id: 'integer' }), /automatically/)
  assert.throws(() => parseTable('t', { a: 'string' as any }), /unknown type/)
  assert.throws(() => parseTable('t t', { a: 'text' }), /Table name/)
  assert.throws(() => parseTable('t', { 'a"b': 'text' }), /Column name/)
  assert.throws(() => parseTable('sqlite_x', {}), /reserved/)
})

test('select', () => {
  assert.deepEqual(selectSql(todos), {
    sql: `SELECT "id", "content", "done", "note", "meta", "pic" FROM "todos"`,
    params: [],
  })
  const s = selectSql(todos, {
    where: { done: false, note: null, id: { $gte: 2, $lt: 10 }, content: { $in: ['a', 'b'], $ne: null } },
    orderBy: ['done', 'id desc'],
    limit: 5,
    offset: 10,
  })
  assert.equal(
    s.sql.replace(/^SELECT .* FROM/, 'FROM'),
    `FROM "todos" WHERE "done" = ? AND "note" IS NULL AND "id" >= ? AND "id" < ? AND "content" IN (?, ?) ` +
      `AND "content" IS NOT NULL ORDER BY "done" ASC, "id" DESC LIMIT ? OFFSET ?`,
  )
  assert.deepEqual(s.params, [0, 2, 10, 'a', 'b', 5, 10])
  assert.deepEqual(selectSql(todos, { offset: 3 }).params, [-1, 3])
  assert.deepEqual(selectSql(todos, { limit: 0 }).params, [0])
  assert.match(selectSql(todos, { where: { id: { $in: [] } } }).sql, /WHERE 0$/)
  assert.match(selectSql(todos, { where: { note: { $ne: 'x' } } }).sql, /"note" IS NOT \?$/)
})

test('select rejects mistakes', () => {
  assert.throws(() => selectSql(todos, { where: { nope: 1 } }), /no column "nope"/)
  assert.throws(() => selectSql(todos, { where: { content: undefined } }), /undefined/)
  assert.throws(() => selectSql(todos, { where: { done: 'yes' } }), /expects a boolean/)
  assert.throws(() => selectSql(todos, { where: { id: { $like: 1 } } }), /Unknown operator/)
  assert.throws(() => selectSql(todos, { orderBy: 'id sideways' }), /Bad orderBy/)
  assert.throws(() => selectSql(todos, { orderBy: 'nope' }), /no column/)
  assert.throws(() => selectSql(todos, { limit: -1 }), /non-negative/)
})

test('insert fills defaults and nulls', () => {
  const s = insertSql(todos, { content: 'hi' })
  assert.equal(
    s.sql,
    `INSERT INTO "todos" ("content", "done", "note", "meta", "pic") VALUES (?, ?, ?, ?, ?) ` +
      `RETURNING "id", "content", "done", "note", "meta", "pic"`,
  )
  assert.deepEqual(s.params, ['hi', 0, null, '{"tags":[]}', null])
  const s2 = insertSql(todos, { id: 7, content: 'x', done: true, pic: new Uint8Array([1, 2, 3]) })
  assert.deepEqual(s2.params, [7, 'x', 1, null, '{"tags":[]}', { $base64: 'AQID' }])
  assert.throws(() => insertSql(todos, {}), /Missing value for column "content"/)
  assert.throws(() => insertSql(todos, { content: 'x', extra: 1 }), /no column "extra"/)
  assert.throws(() => insertSql(todos, { content: null }), /expects a string/)
  assert.match(insertSql(parseTable('e', {}), {}).sql, /DEFAULT VALUES RETURNING "id"$/)
})

test('update and delete', () => {
  assert.deepEqual(updateSql(todos, 3, { done: true, note: undefined }), {
    sql: `UPDATE "todos" SET "done" = ? WHERE "id" = ?`,
    params: [1, 3],
  })
  assert.equal(updateSql(todos, 3, {}), null)
  assert.throws(() => updateSql(todos, 3, { id: 4 }), /can't be changed/)
  assert.deepEqual(updateSql(todos, {}, { note: null }), { sql: `UPDATE "todos" SET "note" = ?`, params: [null] })
  assert.deepEqual(deleteSql(todos, { done: true }), { sql: `DELETE FROM "todos" WHERE "done" = ?`, params: [1] })
  assert.deepEqual(deleteSql(todos, {}), { sql: `DELETE FROM "todos"`, params: [] })
})

test('values', () => {
  const bytes = new Uint8Array(70000).map((_, i) => i % 256)
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes)
  assert.equal(decode('boolean', 1), true)
  assert.equal(decode('boolean', 0), false)
  assert.equal(decode('boolean', null), null)
  assert.deepEqual(decode('json', '{"a":[1]}'), { a: [1] })
  assert.equal(decode('json', 5), 5) // stored as a number by SQLite's numeric affinity
  assert.deepEqual(decode('blob', { $base64: 'AQID' }), new Uint8Array([1, 2, 3]))
  assert.equal(encode('json', false, null, 'j'), 'null')
  assert.equal(encode('json', true, null, 'j'), null)
  assert.throws(() => encode('integer', false, 1.5, 'n'), /expects an integer/)
  assert.throws(() => encode('real', false, NaN, 'n'), /finite/)
  assert.throws(() => encode('json', false, () => 1, 'j'), /JSON value/)
  assert.deepEqual([true, false, null, 'a', 2, new Uint8Array([1])].map(encodeParam), [1, 0, null, 'a', 2, { $base64: 'AQ==' }])
})

const server = (columns: [string, string, boolean, boolean?][]): ServerSchema => ({
  tables: [
    {
      name: 'todos',
      type: 'table',
      columns: columns.map(([name, type, not_null, pk = false]) => ({ name, type, not_null, default: null, pk })),
    },
  ],
})
const ID: [string, string, boolean, boolean] = ['id', 'INTEGER', false, true]

test('migration: create, add columns, nothing to do', () => {
  assert.deepEqual(migrationSql([todos], { tables: [] }, 'db'), [createTableSql(todos)])
  const all = server([ID, ['content', 'TEXT', true], ['done', 'BOOLEAN', true], ['note', 'TEXT', false], ['meta', 'JSON', true], ['pic', 'BLOB', false]])
  assert.deepEqual(migrationSql([todos], all, 'db'), [])
  const some = server([ID, ['content', 'TEXT', true]])
  assert.deepEqual(migrationSql([todos], some, 'db'), [
    `ALTER TABLE "todos" ADD COLUMN "done" BOOLEAN NOT NULL DEFAULT 0`,
    `ALTER TABLE "todos" ADD COLUMN "note" TEXT`,
    `ALTER TABLE "todos" ADD COLUMN "meta" JSON NOT NULL DEFAULT '{"tags":[]}'`,
    `ALTER TABLE "todos" ADD COLUMN "pic" BLOB`,
  ])
})

test('migration refuses unsafe changes', () => {
  const t = parseTable('todos', { content: 'text', n: 'integer' })
  const err = (s: ServerSchema, re: RegExp) => assert.throws(() => migrationSql([t], s, 'db'), (e) => e instanceof SchemaError && re.test(e.message))
  err(server([ID, ['content', 'TEXT', true]]), /new column "n" needs a default/)
  err(server([ID, ['content', 'INTEGER', true], ['n', 'INTEGER', true]]), /column "content" is INTEGER.*declared as text/)
  err(server([ID, ['content', 'TEXT', false], ['n', 'INTEGER', true]]), /"content" is nullable in the database/)
  err(server([ID, ['content', 'TEXT', true], ['n', 'INTEGER', true], ['old', 'TEXT', false]]), /"old" is in the database but not declared/)
  err(server([['content', 'TEXT', true], ['n', 'INTEGER', true]]), /no "id INTEGER PRIMARY KEY"/)
  err({ tables: [{ name: 'todos', type: 'view', columns: [] }] }, /has a view/)
})
