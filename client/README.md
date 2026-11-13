# bisonbase

TypeScript and React client for [bisonbase](../README.md). Users sign in with their bisonbase
account; the app declares typed tables and reads and writes them without writing SQL.

> **Status: early.** Two kinds of databases: `createAppDb`, one SQLite file in the app's own
> storage, shared by all its users, where each row belongs to the user who created it; and
> `createUserDb`, a separate SQLite file for each user in `apps/<appId>/` in their own account.

```tsx
import { BisonBase, type RowOf } from 'bisonbase'
import { AuthElement } from 'bisonbase/react'

// A UUID that identifies the app; make one with crypto.randomUUID() and keep it.
const bb = new BisonBase('f1487da1-14ff-4998-a2c4-90b6353fe8c3', 'My Todo App', {
  url: 'https://bisonbase.example.com', // default: /bb on the page's origin
})

const todos = bb.createUserDb('todos').createTable('todos', {
  content: 'text',
  done: ['boolean', false], // [type, default]
})
type Todo = RowOf<typeof todos> // { id: number; content: string; done: boolean }

function App() {
  const myTodos = todos.useSelect({ orderBy: 'id' }) // [] until signed in and loaded
  return <>
    <AuthElement />
    {myTodos.map((t) => <p key={t.id}>{t.content}</p>)}
    <button onClick={() => todos.insert({ content: 'New' })}>Add</button>
  </>
}
```

[examples/ts/react-todo](../examples/ts/react-todo) is a complete app.

## Tables

`createTable(name, columns)` declares a table. Every table also gets `id`, an integer primary key.

| Column spec | TypeScript type | Stored as |
|---|---|---|
| `"text"` | `string` | `TEXT` |
| `"integer"` | `number` (safe integer) | `INTEGER` |
| `"real"` | `number` | `REAL` |
| `"boolean"` | `boolean` | `BOOLEAN` (0/1) |
| `"blob"` | `Uint8Array` | `BLOB` |
| `"json"` | `Json` | `JSON` (text) |
| `"text?"` etc. | `string \| null` | nullable |
| `["text", "x"]` | `string` | with a default |

Nullable columns and columns with a default may be left out of `insert`.

When a signed-in user first touches a database, the library creates it and its tables, and
adds columns that are new in the code (a new non-nullable column needs a default). It never
changes a column's type, drops a column or deletes data: if the database doesn't match the
code in one of those ways, operations fail with a `SchemaError` that says what's different.

## App databases

`bb.createAppDb(name)` is a database in the app's own storage on the server, shared by everyone
who uses the app. Its tables take a third argument:

```ts
const db = bb.createAppDb('board')
const notes = db.createTable('notes', { text: 'text' })                        // private
const posts = db.createTable('posts', { body: 'text' }, { sharing: 'shared' }) // everyone reads
type Post = RowOf<typeof posts> // { id: number; body: string; _owner: string }
```

Every row has an `_owner`, the id of the user who inserted it, set by the server. Users read
only their own rows of `private` tables (the default) and every row of `shared` ones, and only
ever change or delete their own: an update or delete simply doesn't match other users' rows.
`(await bb.appInfo()).user.id` is the signed-in user's id, e.g. to filter `{ _owner: id }`.

The app needs registering by a bisonbase admin first. When an admin signs in to the app, it
registers itself (with the page's origin, which from then on is the only one allowed to use the
app's id); admins can also register apps under Apps in bisonbase. Only the app's owners (and
admins) can create the database or change its tables, so the first sign-in after a schema change
should be an owner's; for anyone else the tables must already match, or operations fail with a
403 `ApiError`.

## Reading and writing

```ts
await todos.select({ where: { done: false }, orderBy: ['done', 'id desc'], limit: 20 })
await todos.select({ where: { id: { $gte: 10, $lt: 20 }, content: { $in: ['a', 'b'] } } })
await todos.insert({ content: 'a' })               // returns the row, with id and defaults
await todos.insert([{ content: 'b' }, { content: 'c' }]) // one transaction
await todos.update(3, { done: true })               // by id; returns the number changed
await todos.update({ done: true }, { content: 'x' }) // by where; {} means every row
await todos.delete({ done: true })
```

`where` matches when every listed column matches; `null` matches NULL. Operators are `$ne`,
`$lt`, `$lte`, `$gt`, `$gte` and `$in`.

The server checks every table and column name against the database and binds every value; it
accepts no SQL.

## React

Import `bisonbase/react` once (importing `AuthElement` or `useAuth` does it).

- `table.useSelect(options?)`: the matching rows, kept up to date. Empty while signed out or
  loading. Components using the same options share one query.
- `table.useSelectState(options?)`: `{ rows, loading, error }`.
- `useAuth()`: `{ status: 'signed-out' | 'pending' | 'signed-in', error? }`.
- `<AuthElement />`: a sign-in button, or a sign-out button once signed in. Unstyled; target
  `.bb-auth`, `.bb-auth-error`.

While a live query is in use, the client keeps a change stream open to its database (one per
database, over server-sent events). The server says which tables changed after every write,
whether it came from this page, another tab or device, or the bisonbase web UI, and the queries
on those tables load again. Writes through the library also reload their table's queries
straight away. If the stream drops, it reconnects and reloads everything.

Outside React, `table.liveQuery(options)` returns the same shared query, with `subscribe` and
`getSnapshot`.

## Signing in

`bb.signIn()` sends the browser to bisonbase ("Sign in with bisonbase", OAuth 2.1 with PKCE). When
it comes back, the constructor takes the code out of the address bar and trades it for a token,
which is kept in `localStorage`. `bb.signOut()` forgets and revokes it. `bb.auth` and
`bb.onAuthChange(fn)` give the state outside React.

In scripts and tests, pass a token instead: `new BisonBase(id, name, { url, token })`.

## Develop

```sh
npm install
npm run typecheck   # includes the type tests in test/types.test.ts
npm test            # unit tests, plus end-to-end tests if ../node has been built
npm run build       # dist/
```
