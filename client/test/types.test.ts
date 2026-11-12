// Type tests: checked by `npm run typecheck` (tsc); running them only builds the table.

import { test } from 'node:test'
import { BisonBase, type InsertOf, type Json, type RowOf } from '../src/index.ts'

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false
const assertType = <T extends true>() => {}

test('row types', () => {
  const bb = new BisonBase('00000000-0000-4000-8000-000000000000', 'Types', { url: 'http://x', token: 't' })
  const todos = bb.createUserDb('types').createTable('todos', {
    content: 'text',
    done: ['boolean', false],
    note: 'text?',
    count: ['integer?', null],
    meta: 'json',
    pic: 'blob',
  })
  type Todo = RowOf<typeof todos>
  assertType<
    Equal<Todo, { id: number; content: string; done: boolean; note: string | null; count: number | null; meta: Json; pic: Uint8Array }>
  >()
  type New = InsertOf<typeof todos>
  assertType<Equal<keyof New, 'id' | 'content' | 'done' | 'note' | 'count' | 'meta' | 'pic'>>()
  assertType<Equal<{ [K in keyof New]-?: undefined extends New[K] ? K : never }[keyof New], 'id' | 'done' | 'note' | 'count'>>()

  const check = () => {
    void todos.insert({ content: 'a', meta: null, pic: new Uint8Array() })
    void todos.insert([{ content: 'a', meta: [1, { a: 'b' }], pic: new Uint8Array(), done: true }])
    // @ts-expect-error content is required
    void todos.insert({ meta: null, pic: new Uint8Array() })
    // @ts-expect-error wrong type
    void todos.insert({ content: 1, meta: null, pic: new Uint8Array() })
    // @ts-expect-error unknown column
    void todos.insert({ content: 'a', meta: null, pic: new Uint8Array(), nope: 1 })
    void todos.update(1, { done: true })
    // @ts-expect-error done is not nullable
    void todos.update(1, { done: null })
    void todos.select({ where: { done: false, note: null, id: { $gt: 3 } }, orderBy: ['done', 'id desc'] })
    // @ts-expect-error unknown column in orderBy
    void todos.select({ orderBy: 'nope' })
    // @ts-expect-error wrong type in where
    void todos.delete({ done: 'yes' })
    void bb.createUserDb('types2').createTable('t', {
      // @ts-expect-error default doesn't match the type
      a: ['boolean', 'no'],
      // @ts-expect-error unknown type
      b: 'string',
      c: ['text?', null],
    })
  }
  void check
})
