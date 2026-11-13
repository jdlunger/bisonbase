// End to end against a real bisonbase server started in-process from ../node. Skipped when the
// native module hasn't been built (cd node && npm run build).

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdtempSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import { ApiError, BisonBase, SchemaError, type QueryState } from '../src/index.ts'

const nodeDir = new URL('../../node/', import.meta.url)
const built = existsSync(nodeDir) && readdirSync(nodeDir).some((f) => f.endsWith('.node'))
const require = createRequire(import.meta.url)
// CI sets this so that a missing build fails the run instead of skipping these tests.
if (!built && process.env.BISONBASE_REQUIRE_ALL_TESTS) throw new Error('End-to-end tests need ../node built')

let server: { url: string; close(): Promise<void> }
let dataDir: string
const APP = randomUUID()

/**
 * Make a user and an app token for APP, the way an OAuth sign-in would. Runs in a child
 * process: two copies of SQLite in one process break each other's file locks.
 */
function appToken(appId = APP): string {
  const script = `
    const { DatabaseSync } = require('node:sqlite')
    const { createHash, randomBytes, randomUUID } = require('node:crypto')
    const [file, appId] = process.argv.slice(1)
    const db = new DatabaseSync(file)
    const user = randomUUID()
    const now = Math.floor(Date.now() / 1000)
    db.prepare('INSERT INTO users(id, username, is_admin, created_at) VALUES (?, ?, 0, ?)').run(user, 'u' + user.slice(0, 8), now)
    const token = 'wfs_' + randomBytes(32).toString('hex')
    db.prepare("INSERT INTO api_tokens(user_id, name, token_hash, scopes, created_at, client_id, app_id) " +
      "VALUES (?, 'test', ?, 'db:write', ?, 'http://localhost:3000', ?)")
      .run(user, createHash('sha256').update(token).digest('hex'), now, appId)
    db.close()
    process.stdout.write(token)`
  return execFileSync(process.execPath, ['-e', script, join(dataDir, 'system.db'), appId], { encoding: 'utf8' })
}

before(async () => {
  if (!built) return
  const { start } = require('../../node/index.js')
  dataDir = mkdtempSync(join(tmpdir(), 'bisonbase-'))
  server = await start({ port: 0, dataDir, log: 'off' })
})
after(() => server?.close())

const opts = { skip: built ? false : 'build ../node first' }
const columns = { content: 'text', done: ['boolean', false], tags: ['json', []], pic: 'blob?' } as const

/** Wait until the live query's state satisfies `ok`. */
function until<R>(q: { subscribe(l: () => void): () => void; getSnapshot(): QueryState<R> }, ok: (s: QueryState<R>) => boolean) {
  return new Promise<QueryState<R>>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timed out; last state ${JSON.stringify(q.getSnapshot())}`)), 5000)
    const check = () => {
      const s = q.getSnapshot()
      if (ok(s)) {
        clearTimeout(timer)
        unsubscribe()
        resolve(s)
      }
    }
    const unsubscribe = q.subscribe(check)
    check()
  })
}

test('create, insert, select, update, delete', opts, async () => {
  const bb = new BisonBase(APP, 'Test', { url: server.url, token: appToken() })
  const todos = bb.createUserDb('todos').createTable('todos', columns)

  const a = await todos.insert({ content: 'a' })
  assert.deepEqual(a, { id: 1, content: 'a', done: false, tags: [], pic: null })
  const more = await todos.insert([
    { content: 'b', done: true, tags: ['x', { y: 1 }] },
    { content: 'c', pic: new Uint8Array([0, 1, 255]) },
  ])
  assert.deepEqual(more.map((t) => t.id), [2, 3])
  assert.deepEqual(more[1].pic, new Uint8Array([0, 1, 255]))

  assert.deepEqual((await todos.select({ where: { done: true } })).map((t) => t.content), ['b'])
  assert.deepEqual((await todos.select({ orderBy: 'id desc', limit: 2 })).map((t) => t.id), [3, 2])
  assert.deepEqual((await todos.select({ where: { id: { $in: [1, 3] } } })).map((t) => t.id), [1, 3])
  assert.deepEqual((await todos.select({ where: { id: 2 } }))[0].tags, ['x', { y: 1 }])

  assert.equal(await todos.update(1, { done: true }), 1)
  assert.equal(await todos.update({ done: true }, { content: 'done' }), 2)
  assert.equal(await todos.delete({ content: 'done' }), 2)
  assert.deepEqual((await todos.select()).map((t) => t.content), ['c'])

  await assert.rejects(todos.insert({ content: 'x', id: 3 }), (e) => e instanceof ApiError && e.status === 400)
})

test('the schema grows with the code, and refuses unsafe changes', opts, async () => {
  const token = appToken()
  const one = new BisonBase(APP, 'Test', { url: server.url, token })
  await one.createUserDb('notes').createTable('notes', { title: 'text' }).insert({ title: 'old' })

  const two = new BisonBase(APP, 'Test', { url: server.url, token })
  const notes = two.createUserDb('notes').createTable('notes', { title: 'text', pinned: ['boolean', false], body: 'text?' })
  assert.deepEqual(await notes.select(), [{ id: 1, title: 'old', pinned: false, body: null }])

  const three = new BisonBase(APP, 'Test', { url: server.url, token })
  const bad = three.createUserDb('notes').createTable('notes', { title: 'integer', pinned: ['boolean', false], body: 'text?' })
  await assert.rejects(bad.select(), (e) => e instanceof SchemaError && /column "title" is TEXT/.test(e.message))
  const four = new BisonBase(APP, 'Test', { url: server.url, token })
  const dropped = four.createUserDb('notes').createTable('notes', { title: 'text', pinned: ['boolean', false] })
  await assert.rejects(dropped.select(), (e) => e instanceof SchemaError && /"body" is in the database but not declared/.test(e.message))
})

test('users have separate databases', opts, async () => {
  const mine = new BisonBase(APP, 'Test', { url: server.url, token: appToken() }).createUserDb('todos').createTable('todos', columns)
  const theirs = new BisonBase(APP, 'Test', { url: server.url, token: appToken() }).createUserDb('todos').createTable('todos', columns)
  await mine.insert({ content: 'mine' })
  assert.deepEqual(await theirs.select(), [])
})

test('live queries load, reload after writes, and empty on sign-out', opts, async () => {
  const bb = new BisonBase(APP, 'Test', { url: server.url, token: appToken() })
  const todos = bb.createUserDb('todos').createTable('todos', columns)
  const open = todos.liveQuery({ where: { done: false }, orderBy: 'id' })
  assert.equal(todos.liveQuery({ orderBy: 'id', where: { done: false } }), open, 'same options share a query')
  assert.equal(open.getSnapshot().loading, true)

  // Keep it subscribed for the whole test, as a mounted component would.
  const stop = open.subscribe(() => {})
  assert.deepEqual((await until(open, (s) => !s.loading)).rows, [])
  await todos.insert({ content: 'x' })
  assert.deepEqual((await until(open, (s) => s.rows.length === 1)).rows.map((t) => t.content), ['x'])
  await todos.update({}, { done: true })
  await until(open, (s) => s.rows.length === 0)

  const states: string[] = []
  bb.onAuthChange(() => states.push(bb.auth.status))
  await bb.signOut()
  assert.deepEqual(states, ['signed-out'])
  assert.deepEqual(open.getSnapshot(), { rows: [], loading: false, error: null })
  stop()
})

test('live queries follow changes made elsewhere', opts, async () => {
  // Two clients for the same user, as in two tabs or on two devices.
  const token = appToken()
  const here = new BisonBase(APP, 'Test', { url: server.url, token }).createUserDb('live')
  const there = new BisonBase(APP, 'Test', { url: server.url, token }).createUserDb('live')
  const todos = here.createTable('todos', columns)
  const notes = here.createTable('notes', { text: 'text' })
  const theirTodos = there.createTable('todos', columns)
  const theirNotes = there.createTable('notes', { text: 'text' })

  const open = todos.liveQuery({ orderBy: 'id' })
  let updates = 0
  const stop = open.subscribe(() => updates++)
  await until(open, (s) => !s.loading)
  for (let i = 0; i < 250 && !here._live; i++) await new Promise((r) => setTimeout(r, 20))
  assert.ok(here._live, 'change stream connected')

  await theirTodos.insert({ content: 'from there' })
  assert.deepEqual((await until(open, (s) => s.rows.length === 1)).rows.map((t) => t.content), ['from there'])
  await theirTodos.update({}, { done: true })
  await until(open, (s) => s.rows[0]?.done === true)

  // A change to another table doesn't reload this one.
  const openNotes = notes.liveQuery()
  const stopNotes = openNotes.subscribe(() => {})
  await until(openNotes, (s) => !s.loading)
  const seen = updates
  await theirNotes.insert({ text: 'n' })
  await until(openNotes, (s) => s.rows.length === 1)
  await new Promise((r) => setTimeout(r, 100))
  assert.equal(updates, seen)
  stopNotes()

  stop()
  assert.equal(here._live, false, 'stream closes when nothing is subscribed')
})

test('a revoked token signs the user out', opts, async () => {
  const token = appToken()
  const bb = new BisonBase(APP, 'Test', { url: server.url, token })
  const todos = bb.createUserDb('todos').createTable('todos', columns)
  await todos.select()
  await fetch(`${server.url}/oauth/revoke`, { method: 'POST', body: new URLSearchParams({ token }) })
  await assert.rejects(todos.select(), (e) => e instanceof ApiError && e.status === 401)
  assert.equal(bb.auth.status, 'signed-out')
  assert.match((bb.auth as { error?: string }).error ?? '', /expired or was revoked/)
})
