// Shared setup: a bisonbase server in a temp directory, and Chrome. Tests skip when either is
// missing (build the native module with `cd node && npm run build:debug`; install Chromium).

import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Chrome, findChrome } from './cdp.ts'

export const root = new URL('../../', import.meta.url)
const nodeDir = new URL('node/', root)
const chrome = findChrome()
const built = existsSync(nodeDir) && readdirSync(nodeDir).some((f) => f.endsWith('.node'))

const missing = !built ? 'build ../../node first (npm run build:debug)' : !chrome ? 'no Chrome or Chromium found (set CHROME_PATH)' : false
// CI sets this so that missing prerequisites fail the run instead of skipping every test.
if (missing && process.env.BISONBASE_REQUIRE_ALL_TESTS) throw new Error(`Browser tests can't run: ${missing}`)

/** `skip` for node:test, with the reason, when the browser tests can't run here. */
export const skip = missing

export interface Server {
  url: string
  setupUrl: string | null
  close(): Promise<void>
}

export async function startServer(): Promise<Server> {
  const { start } = createRequire(import.meta.url)(new URL('node/index.js', root).pathname)
  const dataDir = mkdtempSync(join(tmpdir(), 'bisonbase-browser-'))
  const server = await start({ port: 0, dataDir, log: 'off' })
  return {
    url: server.url,
    setupUrl: server.setupUrl,
    async close() {
      await server.close()
      rmSync(dataDir, { recursive: true, force: true })
    },
  }
}

export const launchChrome = () => Chrome.launch(chrome!)
