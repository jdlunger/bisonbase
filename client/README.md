# bisonbase

TypeScript and React client for [bisonbase](../README.md). Users sign in with their bisonbase
account; the app reads and writes files, and SQLite databases among them, through typed tables
and without writing SQL.

> **Status: early.** An app has two folders: `bb.files`, `apps/<appId>/` in each user's own
> account, which only that user can reach; and `bb.appFiles`, the app's own storage on the
> server, shared by all its users. A database is a file in one of them: `bb.files.db("todos.db")`.

```tsx
import { BisonBase, type RowOf } from 'bisonbase'
import { AuthElement } from 'bisonbase/react'

// A UUID that identifies the app; make one with crypto.randomUUID() and keep it.
const bb = new BisonBase('f1487da1-14ff-4998-a2c4-90b6353fe8c3', 'My Todo App', {
  url: 'https://bisonbase.example.com', // default: /bb on the page's origin
})

const todos = bb.files.db('todos.db').createTable('todos', {
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

[examples/ts/react-todo](../examples/ts/react-todo) is a complete app, and
[examples/ts/react-workspace](../examples/ts/react-workspace) a bigger one that uses all of the
library: tasks, a calendar and notes, each private or shared with other users.

## Files

`bb.files` is the app's folder in the signed-in user's account; `bb.appFiles` is the app's own
storage (see [App storage](#app-storage)). Paths are relative to the folder, and can't leave it.

```ts
await bb.files.write('notes/today.md', '# Today')          // string, Blob, ArrayBuffer or bytes
const text = await bb.files.readText('notes/today.md')
const blob = await bb.files.read('photos/cat.jpg')         // a Blob
await bb.files.list('notes')        // [{ name, path, type: 'file' | 'dir', size, modified }]
await bb.files.move('notes/today.md', 'archive/today.md')  // { overwrite: true } to replace a file
await bb.files.mkdir('drafts')
await bb.files.delete('archive', { recursive: true })

const notes = bb.files.folder('notes') // a folder inside; paths are relative to it
```

Writing creates the folders a file is in. Listing a folder that doesn't exist gives `[]`.

To change a file only if nobody else has since you read it, pass its version back:

```ts
const { blob, etag } = await bb.files.readFile('doc.json')
await bb.files.write('doc.json', updated, { ifMatch: etag }) // else a 412 ApiError
await bb.files.write('new.json', '{}', { create: true })    // only if it doesn't exist, else 409
```

In React, `folder.useList(path?)` is a folder's listing, kept up to date: it reloads after writes
from this page, and the server tells it about changes made anywhere else.

```tsx
function Notes() {
  const entries = bb.files.useList('notes') // [] until signed in and loaded
  return <ul>{entries.map((e) => <li key={e.path}>{e.name}</li>)}</ul>
}
```

## Databases

`folder.db(path)` is the SQLite database at `path` in that folder; it's created when it's first
used. It's still a file, so it shows up in listings, and can be moved or deleted like one.

```ts
const todos = bb.files.db('todos.db')         // each user's own copy (a UserDb)
const board = bb.appFiles.db('data/board.db') // shared by everyone (an AppDb; see below)
```

`bb.createUserDb('todos')` and `bb.createAppDb('board')` are shorthand for
`bb.files.db('todos.db')` and `bb.appFiles.db('board.db')`.

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

## App storage

`bb.appFiles` is the app's own storage on the server, shared by everyone who uses the app.
Everyone signed in can list and read its files; only the app's owners (and bisonbase admins) can
write, move or delete them, e.g. to publish content or templates to every user.

Its databases are shared too. Their tables take a third argument:

```ts
const db = bb.appFiles.db('board.db')
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

### Transactions

`db.transact` runs writes to tables of one database together: all of them take effect, or none
do. The results come back in order, typed: the stored row (or rows) for an insert, the number
changed for an update or delete.

```ts
const db = bb.appFiles.db('workspace.db')
const mine = db.createTable('tasks', { title: 'text' })
const shared = db.createTable('shared_tasks', { title: 'text' }, { sharing: 'shared' })

// Share a task: move it from the private table to the shared one.
const [moved, deleted] = await db.transact((tx) => [
  tx.insert(shared, { title: task.title }), // RowOf<typeof shared>
  tx.delete(mine, task.id),                 // number
])
```

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
