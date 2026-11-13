# bisonbase for Node.js

A complete backend for prototyping client-side web apps, started from Node. You get:

- a private file tree per user,
- SQLite databases (any file in the tree) read and written through a relational JSON API over
  HTTP, with a stream of changes,
- a web UI with passkey login, a file browser and database editor, API tokens and an admin page.

It's the [bisonbase](https://github.com/jdlunger/bisonbase/blob/main/README.md) Rust server compiled as a native addon. It runs on its own threads inside your Node process and listens on its own port. Prebuilt binaries are published for Linux (x64, arm64, glibc), macOS (x64, arm64) and Windows (x64), so no Rust toolchain is needed.

## Use it from code

```js
import { start } from '@bisonbase/server'

const server = await start({ port: 8080, dataDir: './data' })
console.log(`bisonbase at ${server.url}`)
if (server.setupUrl) console.log(`create the admin account: ${server.setupUrl}`)

// later
await server.close()
```

On first start the data directory has no users, so `setupUrl` is a one-time link for creating the admin account. Browser apps then get an API token with "Sign in with bisonbase" (OAuth with PKCE) and call the HTTP API; see the [API section](https://github.com/jdlunger/bisonbase/blob/main/README.md#api) and the [examples](https://github.com/jdlunger/bisonbase/tree/main/examples).

`start()` resolves once the server is listening. The server keeps the process alive until you call `close()`. Call `server.unref()` if it shouldn't, and `await using server = await start()` closes it automatically on Node versions that support it. You can run several servers in one process, as long as each has its own `dataDir`.

### Options

All optional.

| Option | Default | |
|---|---|---|
| `port` | `8080` | `0` picks a free port; read it back from `server.port`. Listens on 127.0.0.1 |
| `dataDir` | `"./data"` | `system.db` and user files |
| `log` | `"bisonbase=info"` | `RUST_LOG`-style filter, or `"off"`. The first `start()` in a process sets up logging |

The server is served at `http://localhost:<port>`, which browsers treat as a secure context, so passkeys work.

## Use it from the command line

```sh
npx @bisonbase/server --port 8080 --data-dir ./data
```

## Build from source

Needs Rust and Node 18+.

```sh
cd node
npm install
npm run build   # writes bisonbase.<platform>.node
npm test
```

Releases are built by [`.github/workflows/node.yml`](https://github.com/jdlunger/bisonbase/blob/main/.github/workflows/node.yml). Pushing a `server-v*` tag builds every platform and publishes `@bisonbase/server` along with the `@bisonbase/binding-*` packages.
