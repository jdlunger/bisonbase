// The workspace example (examples/ts/react-workspace): tasks, a calendar and notes, each private
// or shared, used by two people at once. Needs `npm ci` in examples/ts (esbuild, React).

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
let app: string
let alice: Page
let bob: Page

before(async () => {
  if (skip) return
  server = await startServer()
  chrome = await launchChrome()
  // The same build as examples/ts/react-workspace/server.ts, on a free port.
  const { context } = createRequire(examples)('esbuild')
  const { tailwind } = await import(`${examples}tailwind.ts`)
  const ctx = await context({
    entryPoints: [path('examples/ts/react-workspace/app.tsx')],
    outdir: path('examples/ts/react-workspace/'),
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
  const { port } = await ctx.serve({ servedir: path('examples/ts/react-workspace/'), host: '127.0.0.1', port: 0 })
  app = `http://127.0.0.1:${port}/`

  // alice is the first account, so an admin; bob joins with an invite.
  alice = await chrome.newPage()
  await alice.addAuthenticator()
  await alice.goto(server.setupUrl!)
  await alice.fill('#signup-form input[name=username]', 'alice')
  await alice.click('Create passkey & sign up')
  await alice.waitForPath('/files')
  await alice.goto(`${server.url}/admin`)
  await alice.fill('input[name=note]', 'for bob')
  await alice.click('Create invite link')
  const invite = await alice.waitFor<string>('document.querySelector("pre.token")?.textContent.trim()')
  bob = await chrome.newPage()
  await bob.addAuthenticator()
  await bob.goto(invite)
  await bob.fill('#signup-form input[name=username]', 'bob')
  await bob.click('Create passkey & sign up')
  await bob.waitForPath('/files')
})
after(async () => {
  try {
    await esbuild?.dispose()
    await chrome?.close()
  } finally {
    await server?.close()
  }
})

async function signIn(p: Page) {
  await p.goto(app)
  await p.click('Sign in')
  await p.waitForText('Allow access?')
  await p.click('Allow')
  await p.waitFor(`location.origin === ${JSON.stringify(new URL(app).origin)}`)
  await p.waitForText('Sign out')
}

/** The rows of a list, as `title [badges…]` text. */
const rows = (p: Page, sel: string) =>
  p.eval<string[]>(`[...document.querySelectorAll(${JSON.stringify(`${sel} > li:not(.empty)`)})].map(li => li.innerText.replace(/\\s+/g, ' ').trim())`)
/** The data-uid of the item in `list` whose title is `title`. */
const uid = (p: Page, list: string, title: string) =>
  p.waitFor<string>(`[...document.querySelectorAll(${JSON.stringify(`${list} [data-uid]`)})].find(e => e.querySelector('.title')?.textContent.includes(${JSON.stringify(title)}))?.dataset.uid`)
const item = (u: string) => `[data-uid="${u}"]`

/** On the calendar, select tomorrow (which may be in next month's first week: the grid shows it too). */
async function pickTomorrow(p: Page) {
  await p.waitFor(`!!document.querySelector('#grid')`)
  await p.eval(`(() => { const d = new Date(); d.setDate(d.getDate() + 1)
    document.querySelector('#grid [data-date="' + d.toLocaleDateString('sv') + '"]').click() })()`)
}

/** Open an item's details, unless they're open. */
async function expand(p: Page, u: string) {
  await p.waitFor(`!!document.querySelector('${item(u)} .title')`)
  await p.eval(`document.querySelector('${item(u)} .details, ${item(u)} .when') || document.querySelector('${item(u)} .title').click()`)
}

async function addTask(p: Page, title: string, shared: boolean) {
  await p.fill('#new-task input[placeholder="New task"]', title)
  await p.click(shared ? 'Shared' : 'Private', '#new-task')
  await p.click('Add', '#new-task')
  await uid(p, '#tasks', title)
}

test('alice signs in, which registers the app, and adds private and shared tasks', { skip }, async () => {
  await signIn(alice)
  await alice.waitForText('alice (owner)')
  await alice.waitForText('Nothing to do.')
  await alice.waitForText('In this workspace: alice (you)')

  await addTask(alice, 'secret plan', false)
  await addTask(alice, 'team lunch', true)
  assert.deepEqual((await rows(alice, '#tasks')).sort(), ['secret plan Private', 'team lunch Shared'])

  // Open a task, give it details, then share it: it moves to the shared table in one transaction.
  const plan = await uid(alice, '#tasks', 'secret plan')
  await expand(alice, plan)
  await alice.fill(`${item(plan)} input[placeholder="Hours"]`, '1.5')
  await alice.eval(`document.querySelector('${item(plan)} input[placeholder="Hours"]').dispatchEvent(new FocusEvent('focusout', { bubbles: true }))`)
  await alice.waitForText('about 1.5 h')
  await addTask(alice, 'only mine', false)
  await alice.click('Shared', `${item(plan)} .share-switch`)
  await alice.waitFor(`document.querySelector('${item(plan)}')?.innerText.includes('Shared')`)
  await alice.waitForText('about 1.5 h') // the estimate moved with it
  assert.deepEqual(alice.errors, [])
})

test('alice adds a shared event and a note; the open tab follows her to a reload', { skip }, async () => {
  await alice.click('Calendar', '#tabs')
  // Tomorrow, so it's still upcoming whenever the test runs.
  await pickTomorrow(alice)
  await alice.waitForText('Nothing planned.')
  await alice.fill('#new-event input[placeholder="New event"]', 'standup')
  await alice.click('Shared', '#new-event')
  await alice.click('Add event')
  await uid(alice, '#events', 'standup')
  await alice.waitFor(`document.querySelector('#grid').innerText.includes('standup')`)
  await alice.waitFor(`document.querySelector('#upcoming').innerText.includes('standup')`)

  await alice.click('Notes', '#tabs')
  await alice.click('New')
  await alice.fill('.editor input[aria-label=Title]', 'Ideas')
  await alice.fill('.editor textarea', 'a shared workspace')
  await alice.waitFor(`document.querySelector('.editor .status')?.textContent === 'Saved' && document.querySelector('#notes').innerText.includes('Ideas')`)
  await alice.click('Shared', '.editor .share-switch')
  await alice.waitFor(`document.querySelector('#notes').innerText.includes('Shared')`)

  // The tab is a preference in alice's own database.
  await alice.reload()
  await alice.waitFor(`document.querySelector('#tabs [aria-current=page]')?.textContent === 'Notes'`)
  await alice.waitForText('Ideas')
  assert.deepEqual(alice.errors, [])
})

test("bob sees what's shared, not what's private, and can comment and answer but not edit", { skip }, async () => {
  await signIn(bob)
  await bob.waitForText('In this workspace: alice, bob (you)')
  // A new user starts on Tasks: preferences are per user.
  await bob.waitFor(`document.querySelector('#tabs [aria-current=page]')?.textContent === 'Tasks'`)
  await uid(bob, '#tasks', 'team lunch')
  assert.deepEqual(
    (await rows(bob, '#tasks')).sort(),
    ['secret plan Shared by alice', 'team lunch Shared by alice'],
  )
  const lunch = await uid(bob, '#tasks', 'team lunch')
  assert.equal(await bob.eval(`document.querySelector('${item(lunch)} input[type=checkbox]').disabled`), true)

  // Comment on alice's task; she sees it live.
  await expand(bob, lunch)
  await bob.fill(`${item(lunch)} .comments input`, 'pizza?')
  await bob.click('Post', `${item(lunch)} .comments`)
  await bob.waitFor(`document.querySelector('${item(lunch)} .comments').innerText.includes('pizza?')`)
  assert.equal(await bob.eval(`!!document.querySelector('${item(lunch)} .share-switch')`), false, 'no sharing controls on others\' items')

  await alice.click('Tasks', '#tabs')
  await expand(alice, lunch)
  await alice.waitFor(`document.querySelector('${item(lunch)} .comments').innerText.includes('pizza?')`)

  // Answer alice's event; she sees the answer.
  await bob.click('Calendar', '#tabs')
  await pickTomorrow(bob)
  const standup = await uid(bob, '#events', 'standup')
  await expand(bob, standup)
  await bob.click('Going', item(standup))
  await bob.waitFor(`document.querySelector('${item(standup)} .rsvp').innerText.includes('Going: bob')`)
  await bob.click('Maybe', item(standup))
  await bob.waitFor(`document.querySelector('${item(standup)} .rsvp').innerText.includes('Maybe: bob')`)

  await alice.click('Calendar', '#tabs')
  await pickTomorrow(alice)
  await expand(alice, standup)
  await alice.waitFor(`document.querySelector('${item(standup)} .rsvp')?.innerText.includes('Maybe: bob')`)

  // Shared notes are read-only for others.
  await bob.click('Notes', '#tabs')
  await expand(bob, await uid(bob, '#notes', 'Ideas'))
  await bob.waitFor(`document.querySelector('.editor textarea')?.value === 'a shared workspace'`)
  assert.equal(await bob.eval(`document.querySelector('.editor textarea').readOnly`), true)
  assert.deepEqual(bob.errors, [])
})

test('making a shared item private hides it from others again', { skip }, async () => {
  await alice.click('Tasks', '#tabs')
  const lunch = await uid(alice, '#tasks', 'team lunch')
  await expand(alice, lunch)
  await alice.click('Private', `${item(lunch)} .share-switch`)
  await alice.waitFor(`document.querySelector('${item(lunch)}')?.innerText.includes('Private')`)

  await bob.click('Tasks', '#tabs')
  await bob.waitFor(`!document.querySelector('#tasks').innerText.includes('team lunch')`)
  assert.deepEqual(await rows(bob, '#tasks'), ['secret plan Shared by alice'])
  assert.deepEqual(alice.errors, [])
  assert.deepEqual(bob.errors, [])
})
