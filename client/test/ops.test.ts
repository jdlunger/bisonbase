import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseTable } from '../src/table.ts'
import { deleteRequest, insertRequest, selectRequest, updateRequest } from '../src/ops.ts'
import { migrateRequest } from '../src/schema.ts'
import { decode, encode, fromBase64, toBase64 } from '../src/values.ts'
import { events } from '../src/watch.ts'

const todos = parseTable('todos', {
  content: 'text',
  done: ['boolean', false],
  note: 'text?',
  meta: ['json', { tags: [] }],
  pic: 'blob?',
})

test('migrate request', () => {
  assert.deepEqual(migrateRequest([todos]), {
    tables: [
      {
        name: 'todos',
        columns: [
          { name: 'content', type: 'text', nullable: false },
          { name: 'done', type: 'boolean', nullable: false, default: 0 },
          { name: 'note', type: 'text', nullable: true },
          { name: 'meta', type: 'json', nullable: false, default: '{"tags":[]}' },
          { name: 'pic', type: 'blob', nullable: true },
        ],
      },
    ],
  })
  const t = parseTable('t', { b: ['blob?', new Uint8Array([0, 255])], n: ['text?', null] })
  assert.deepEqual(migrateRequest([t]).tables[0].columns.map((c) => c.default), [{ $base64: 'AP8=' }, null])
})

test('bad declarations', () => {
  assert.throws(() => parseTable('t', { id: 'integer' }), /automatically/)
  assert.throws(() => parseTable('t', { a: 'string' as any }), /unknown type/)
  assert.throws(() => parseTable('t t', { a: 'text' }), /Table name/)
  assert.throws(() => parseTable('t', { 'a"b': 'text' }), /Column name/)
  assert.throws(() => parseTable('sqlite_x', {}), /reserved/)
})

test('select', () => {
  assert.deepEqual(selectRequest(todos), { table: 'todos' })
  assert.deepEqual(
    selectRequest(todos, {
      where: { done: false, note: null, id: { $gte: 2, $lt: 10 }, content: { $in: ['a', 'b'], $ne: null }, pic: { $ne: undefined } },
      orderBy: ['done', 'id DESC'],
      limit: 5,
      offset: 10,
    }),
    {
      table: 'todos',
      where: { done: 0, note: null, id: { $gte: 2, $lt: 10 }, content: { $in: ['a', 'b'], $ne: null } },
      order_by: ['done asc', 'id desc'],
      limit: 5,
      offset: 10,
    },
  )
  assert.deepEqual(selectRequest(todos, { where: 3 }), { table: 'todos', where: { id: 3 } })
  assert.deepEqual(selectRequest(todos, { where: { pic: new Uint8Array([1]) } }).where, { pic: { $base64: 'AQ==' } })
  assert.deepEqual(selectRequest(todos, { limit: 0 }), { table: 'todos', limit: 0 })
})

test('select rejects mistakes', () => {
  assert.throws(() => selectRequest(todos, { where: { nope: 1 } }), /no column "nope"/)
  assert.throws(() => selectRequest(todos, { where: { content: undefined } }), /undefined/)
  assert.throws(() => selectRequest(todos, { where: { done: 'yes' } }), /expects a boolean/)
  assert.throws(() => selectRequest(todos, { where: { id: { $like: 1 } } }), /Unknown operator/)
  assert.throws(() => selectRequest(todos, { where: { id: { $in: 1 } } }), /must be an array/)
  assert.throws(() => selectRequest(todos, { orderBy: 'id sideways' }), /Bad orderBy/)
  assert.throws(() => selectRequest(todos, { orderBy: 'nope' }), /no column/)
  assert.throws(() => selectRequest(todos, { limit: -1 }), /non-negative/)
})

test('insert fills defaults and nulls', () => {
  assert.deepEqual(insertRequest(todos, [{ content: 'hi' }]), {
    table: 'todos',
    rows: [{ content: 'hi', done: 0, note: null, meta: '{"tags":[]}', pic: null }],
  })
  assert.deepEqual(insertRequest(todos, [{ id: 7, content: 'x', done: true, pic: new Uint8Array([1, 2, 3]) }]).rows[0], {
    id: 7,
    content: 'x',
    done: 1,
    note: null,
    meta: '{"tags":[]}',
    pic: { $base64: 'AQID' },
  })
  assert.throws(() => insertRequest(todos, [{}]), /Missing value for column "content"/)
  assert.throws(() => insertRequest(todos, [{ content: 'x', extra: 1 }]), /no column "extra"/)
  assert.throws(() => insertRequest(todos, [{ content: null }]), /expects a string/)
  assert.deepEqual(insertRequest(parseTable('e', {}), [{}]), { table: 'e', rows: [{}] })
})

test('update and delete', () => {
  assert.deepEqual(updateRequest(todos, 3, { done: true, note: undefined }), { table: 'todos', where: { id: 3 }, set: { done: 1 } })
  assert.equal(updateRequest(todos, 3, {}), null)
  assert.throws(() => updateRequest(todos, 3, { id: 4 }), /can't be changed/)
  assert.deepEqual(updateRequest(todos, {}, { note: null }), { table: 'todos', where: {}, set: { note: null } })
  assert.deepEqual(deleteRequest(todos, { done: true }), { table: 'todos', where: { done: 1 } })
  assert.deepEqual(deleteRequest(todos, {}), { table: 'todos', where: {} })
})

test('app tables: sharing and _owner', () => {
  const posts = parseTable('posts', { body: 'text' }, { sharing: 'shared' })
  assert.equal(migrateRequest([posts]).tables[0].sharing, 'shared')
  assert.equal(migrateRequest([todos]).tables[0].sharing, undefined)
  assert.deepEqual(selectRequest(posts, { where: { _owner: 'u1' }, orderBy: '_owner' }), {
    table: 'posts',
    where: { _owner: 'u1' },
    order_by: ['_owner asc'],
  })
  assert.throws(() => insertRequest(posts, [{ body: 'x', _owner: 'u1' }]), /set by the server/)
  assert.throws(() => updateRequest(posts, {}, { _owner: 'u1' }), /can't be changed/)
  // Only app tables have an owner.
  assert.throws(() => selectRequest(todos, { where: { _owner: 'u1' } }), /no column "_owner"/)
  assert.throws(() => parseTable('t', { _owner: 'text' }, { sharing: 'private' }), /automatically/)
  assert.throws(() => parseTable('_bisonbase_x', { a: 'text' }), /reserved/)
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
})

test('event stream parsing', async () => {
  // Split mid-event and mid-character, with CRLFs and keep-alive comments.
  const text = 'event: ready\r\ndata: {}\r\n\r\n:\n\nevent:change\ndata: {"tables":\ndata: ["é"]}\n\n'
  const bytes = new TextEncoder().encode(text)
  const cuts = [5, 30, bytes.indexOf(0xc3) + 1, bytes.length]
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      let at = 0
      for (const cut of cuts) {
        c.enqueue(bytes.slice(at, cut))
        at = cut
      }
      c.close()
    },
  })
  const got = []
  for await (const e of events(body)) got.push(e)
  assert.deepEqual(got, [
    ['ready', {}],
    ['change', { tables: ['é'] }],
  ])
})

test('watch retries failures until stopped, and stops on fatal errors', async () => {
  const { watch } = await import('../src/watch.ts')
  const stream = (text: string) => new Response(new TextEncoder().encode(text), { headers: { 'content-type': 'text/event-stream' } })
  let attempts = 0
  const got: string[] = []
  await new Promise<void>((resolve) => {
    const stop = watch({
      async open() {
        attempts++
        if (attempts === 1) throw new TypeError('fetch failed') // network error
        if (attempts === 2) return new Response('busy', { status: 503 })
        return stream('event: ready\ndata: {}\n\n')
      },
      onEvent(event) {
        got.push(event)
        if (attempts === 3) {
          stop()
          resolve()
        }
      },
    })
  })
  assert.deepEqual([attempts, got], [3, ['ready']])

  let tries = 0
  const fatal = new Error('signed out')
  watch({
    async open() {
      tries++
      throw fatal
    },
    fatal: (e) => e === fatal,
    onEvent() {},
  })
  await new Promise((r) => setTimeout(r, 1500))
  assert.equal(tries, 1)
})
