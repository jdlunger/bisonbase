// The React todo example (examples/ts/react-todo) on the bisonbase client library: "Sign in
// with bisonbase" with a passkey, live queries, and what happens when access is revoked.
// Needs `npm ci` in examples/ts (esbuild, React).

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { createRequire } from 'node:module'
import type { Chrome, Page } from './cdp.ts'
import { launchChrome, root, skip as baseSkip, startServer, type Server } from './env.ts'

const path = (p: string) => new URL(p, root).pathname
const examples = path('examples/ts/')
const skip = baseSkip || (!existsSync(`${examples}node_modules/esbuild`) && 'run npm ci in examples/ts first')
if (skip && process.env.BISONBASE_REQUIRE_ALL_TESTS) throw new Error(`React example tests can't run: ${skip}`)

let server: Server
let chrome: Chrome
let esbuild: { dispose(): Promise<void> }
let app: string // the example's URL
let page: Page
let key: string

before(async () => {
  if (skip) return
  server = await startServer()
  chrome = await launchChrome()
  // The same build as examples/ts/react-todo/server.ts, on a free port.
  const { context } = createRequire(examples)('esbuild')
  const { tailwind } = await import(`${examples}tailwind.ts`)
  const ctx = await context({
    entryPoints: [path('examples/ts/react-todo/app.tsx')],
    outdir: path('examples/ts/react-todo/'),
    write: false,
    bundle: true,
    format: 'esm',
    logLevel: 'warning',
    plugins: [tailwind],
    define: { BISONBASE_URL: JSON.stringify(server.url) },
    alias: {
      bisonbase: path('client/src/index.ts'),
      'bisonbase/react': path('client/src/react.tsx'),
      react: `${examples}node_modules/react`,
    },
  })
  esbuild = ctx
  const { port } = await ctx.serve({ servedir: path('examples/ts/react-todo/'), host: '127.0.0.1', port: 0 })
  app = `http://127.0.0.1:${port}/`

  // A bisonbase account with a passkey.
  page = await chrome.newPage()
  key = await page.addAuthenticator()
  await page.goto(server.setupUrl!)
  await page.fill('#signup-form input[name=username]', 'alice')
  await page.click('Create passkey & sign up')
  await page.waitForPath('/files')
})
after(async () => {
  try {
    await esbuild?.dispose()
    await chrome?.close()
  } finally {
    await server?.close()
  }
})

const items = (p: Page) => p.eval<string[]>(`[...document.querySelectorAll('#items li:not(.empty) span')].map(s => s.textContent)`)
const signedIn = (p: Page) => p.waitForText('Sign out')

async function add(p: Page, content: string) {
  const before = (await items(p)).length
  await p.fill('#add input', content)
  await p.click('Add')
  await p.waitFor(`document.querySelectorAll('#items li:not(.empty)').length === ${before + 1}`)
}

/** On the consent page: allow, and wait to be back in the app, signed in. */
async function allow(p: Page) {
  await p.waitForText('Allow access?')
  await p.click('Allow')
  await p.waitFor(`location.origin === ${JSON.stringify(new URL(app).origin)}`)
  await signedIn(p)
}

test('sign in with bisonbase, then add, complete and clear todos', { skip }, async () => {
  await page.goto(app)
  await page.waitForText('Sign in')
  await page.click('Sign in')
  await allow(page)
  assert.equal(new URL(await page.url()).search, '', 'the code is gone from the address bar')
  await page.waitForText('Nothing to do.')

  await add(page, 'buy milk')
  await add(page, 'walk dog')
  assert.deepEqual(await items(page), ['buy milk', 'walk dog'])
  await page.waitForText('2 items left')

  await page.eval(`document.querySelector('#items li input[type=checkbox]').click()`)
  await page.waitForText('1 item left')
  assert.deepEqual(await items(page), ['walk dog', 'buy milk'], 'done items sort last')
  await page.click('Clear completed')
  await page.waitFor(`document.querySelectorAll('#items li:not(.empty)').length === 1`)

  // The token survives a reload.
  await page.reload()
  await signedIn(page)
  await page.waitFor(`document.querySelectorAll('#items li:not(.empty)').length === 1`)
  assert.deepEqual(await items(page), ['walk dog'])
  assert.deepEqual(page.errors, [])
})

test('on another device, sign in with a synced passkey and see the same todos', { skip }, async () => {
  const laptop = await chrome.newPage()
  await laptop.addCredentials(await laptop.addAuthenticator(), await page.credentials(key))
  await laptop.goto(app)
  await laptop.click('Sign in')
  // No bisonbase session on this device yet: log in first.
  await laptop.waitForPath('/login')
  await laptop.fill('#login-form input[name=username]', 'alice')
  await laptop.click('Log in with passkey')
  await allow(laptop)
  await laptop.waitFor(`document.querySelectorAll('#items li:not(.empty)').length === 1`)

  // A change made here shows up on the first device when its window regains focus.
  await add(laptop, 'from laptop')
  await page.eval(`window.dispatchEvent(new Event('focus'))`)
  await page.waitForText('from laptop')
})

test('disconnecting the app in bisonbase signs the app out', { skip }, async () => {
  await page.goto(`${server.url}/settings`)
  await page.waitForText('React Todo')
  await page.click('Disconnect')
  await page.waitForText('No apps.')

  await page.goto(app)
  await page.waitForText('Your sign-in expired or was revoked')
  assert.equal(await page.eval('!!document.querySelector("#items")'), false)
})

test('signing out revokes the token', { skip }, async () => {
  await page.click('Sign in')
  await allow(page)
  const token = await page.eval<string>(`Object.keys(localStorage).filter(k => k.startsWith('bisonbase:token:')).map(k => localStorage.getItem(k))[0]`)
  assert.ok(token)
  await page.click('Sign out')
  await page.waitForText('Sign in')
  assert.equal(await page.eval(`Object.keys(localStorage).some(k => k.startsWith('bisonbase:token:'))`), false)
  await page.waitFor('true') // let the revoke request finish
  const res = await fetch(`${server.url}/api/v1/files/`, { headers: { authorization: `Bearer ${token}` } })
  assert.equal(res.status, 401)
})

test('cancelling on the consent page leaves the app signed out with a message', { skip }, async () => {
  // `page` is signed out of the app but still logged in to bisonbase, so it goes straight to consent.
  // (A fresh copy of the passkey wouldn't do: its signature counter is behind the server's,
  // which bisonbase rejects as a possible clone.)
  await page.click('Sign in')
  await page.waitForText('Allow access?')
  await page.click('Cancel')
  await page.waitForText('Sign-in was cancelled.')
  assert.equal(await page.eval('!!document.querySelector("#items")'), false)
})

test("the app's todos are in its own storage, which the admin who signed in registered", { skip }, async () => {
  await page.goto(`${server.url}/apps`)
  await page.waitForText('React Todo')
  await page.click('Browse storage')
  await page.waitForText('todos.db')
  await page.click('todos.db')
  await page.click('todos')
  await page.waitForText('from laptop')
  assert.deepEqual(page.errors, [])
})
