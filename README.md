# bisonbase

I love the idea of an open-source backend-as-a-service with auth + relational DB + file storage, à la [PocketBase](https://pocketbase.io/), but I have a few additional ideas:

 - Write it in Rust (like [TrailBase](https://trailbase.io/))
 - Run it as a library, so you only have to run one server (written in TypeScript, or Rust!)
 - Support multi-tenancy, so you can run multiple apps on top
 - Give end-users access to their own data
 - Support different app data models:
   - per-user-instanced, all data separate
   - app-instanced, data shared

## Library usage: End Goal

This is in progress. My end goal is that writing a quick web app is as easy as:

```ts
// Assumes server reachable on current domain at /bb. Registers app if super admin
const bb = new BisonBase("todo_app", "My Todo App");

// Creates (or updates) database & table if signed in with admin account
// Rows owned by individual users by default
// For a separate DB in every user's own files (if not sharing), bb.files.db("todos.db")
const todos = bb.appFiles.db("todos.db").createTable("todos", {
  content: "text",
  done: ["boolean", false],
});

function App() {
  // Fetches once signed in, re-renders on updates
  const myTodos = todos.useSelect();

  return <>
    {/* Sign-in button linking to OAuth OIDC flow at /bb/sign_in, then displays username */}
    <AuthElement />

    {myTodos.map(t => <p key={t.id} className={t.done ? "line-through": ""}>{t.content}</p>)}

    <form onSubmit={e => {
      e.preventDefault();
      todos.insert({
        content: new FormData(e.currentTarget).get("newTodo") as string,
      });
      e.currentTarget.reset();
    }}>
      <input type="text" name="newTodo" />
    </form>
  </>;
}
```

This works now. Files are the main API: `bb.files` is the app's folder in each user's own account,
and `bb.appFiles` the app's own storage, shared by its users. A database is a file in either:
`bb.appFiles.db("todos.db")` (shared storage, rows owned by users) or `bb.files.db("todos.db")`
(a database in each user's own account). See [client/](client) (the `bisonbase` package),
[examples/ts/react-todo](examples/ts/react-todo), and
[examples/ts/react-workspace](examples/ts/react-workspace), a multi-user workspace (tasks, a
calendar and notes, each private or shared) that uses the client's databases.

### App-owned storage

An admin registers an app (under Apps in the UI, or just by signing in to it: the client
registers it then), which gives it storage of its own, outside every user's files, shared by
everyone who uses it. Only the app's registered origin can sign in with its id. Admins can make
other users owners of the app.

- Each table of an app database has an `_owner` column, which the server fills in with the id of
  the user who inserted the row. Users only reach their own rows: a table's `sharing` is
  `private` (the default; reads see only your rows) or `shared` (reads see every row). Either
  way, only a row's owner can update or delete it, and `_owner` can't be set or changed.
- Only owners (and admins) can create databases and tables, add columns or change sharing, and
  add, change or delete plain files there; anyone else can check that the tables match, list and
  read plain files, and use the databases through the API above.
- In the UI, users see their own rows of each app's databases (read-only) under Apps; owners see
  and can change everything. Deleting a user deletes their rows from every app.

App storage is served at `/api/v1/apps/<app id>/files/<path>`, with the same ops as above.
`GET /api/v1/apps/<app id>` describes the app and whether the user owns it, and an admin can
`POST /api/v1/apps/<app id>?op=register` with `{"name", "origin"}` (an app's own token needs
neither origin nor name).

### Database API

Apps never send SQL. A database is a file in the signed-in user's own tree, addressed as
`/api/v1/files/<path>?op=<op>`; a token can't name anything outside that tree (and an app's
token, nothing outside `apps/<app id>/`). Table and column names are checked against the
database's schema, and values are always bound parameters.

| op | method | scope | body |
| --- | --- | --- | --- |
| `mkdb` | POST | db:write | none: creates an empty database |
| `migrate` | POST | db:read, or db:write if anything changes | `{"tables": [{"name", "columns": [{"name", "type", "nullable", "default"}]}]}` |
| `select` | POST | db:read | `{"table", "where", "order_by": ["col desc"], "limit", "offset"}` |
| `insert` | POST | db:write | `{"table", "rows": [{...}]}`, returns the stored rows |
| `update` | POST | db:write | `{"table", "where", "set": {...}}`, returns `{"changes"}` |
| `delete` | POST | db:write | `{"table", "where"}`, returns `{"changes"}` |
| `transact` | POST | db:write | `{"ops": [{"op": "insert", ...}, ...]}`, all or nothing |
| `schema` | GET | db:read | none: tables and columns |
| `watch` | GET | db:read | none: server-sent events, `ready` then `change` with `{"tables": [...]}` (`null` for anything) |

`watch` also works on any other path, with files:read: a folder (even one that doesn't exist
yet) or a plain file. Its `change` events are `{"path": ...}` when a file or folder at, inside or
above it is written, created, moved or deleted (`null` if the stream fell behind); rows changing
inside a database aren't reported there.

`where` is `{"col": value}`, `{"col": null}` for NULL, or operators: `{"col": {"$gte": 1, "$in":
[...], "$ne": ...}}`. Blobs travel as `{"$base64": "..."}`. Unknown keys are refused, and
`update` and `delete` need a `where` (`{}` for every row).

## TODO

 - Per-file ownership for files in app storage (for now only an app's owners can write files there)
 - Admin features - first user is super admin, then can set other users as app admins (done: app owners)
 - TS & React library, with auth, file, and db APIs (started in [client/](client): auth, files, per-user and app dbs)
 - Schema creations & migrations

## LLM Usage

This repo is currently mostly vibe-coded, as a prototype, and should be used with caution. If it proves useful to myself others, I will spend more (human) time on it.

## Run Example

Prerequisites: Rust & Node installed

Compile bisonbase as a Node add-on, install example's dependencies, and run full stack server:

```sh
(cd node && npm install && npm run build:debug)
(cd examples/ts && npm install)
node examples/ts/react-todo/server.ts      # http://localhost:3000
node examples/ts/react-workspace/server.ts # or the bigger example, on http://localhost:3001
```

To try the workspace with more than one person, invite another user under Admin in bisonbase
and sign in as them in a private window.

## Publish

Both packages are published from GitHub Actions with npm trusted publishing when a version tag is
pushed. Run these from the repo root, with `patch` swapped for `minor`, `major` or an exact version
as needed. To check a build without publishing, use Actions → client (or node) → Run workflow.

### Client

Publishes [`bisonbase`](https://www.npmjs.com/package/bisonbase) via [.github/workflows/client.yml](../.github/workflows/client.yml).

```sh
v=$(cd client && npm version patch --no-git-tag-version) && v=${v#v}
git commit -am "bisonbase v$v"
git tag "client-v$v"
git push origin main "client-v$v"
```

### Server

Publishes [`@bisonbase/server`](https://www.npmjs.com/package/@bisonbase/server) and the `@bisonbase/binding-*` packages via
[.github/workflows/node.yml](../.github/workflows/node.yml). The version bump also updates
`node/npm/*/package.json`.

```sh
v=$(cd node && npm version patch --no-git-tag-version) && v=${v#v}
git commit -am "@bisonbase/server v$v"
git tag "server-v$v"
git push origin main "server-v$v"
```
