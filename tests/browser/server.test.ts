// The server's own pages: passkey signup, login, adding passkeys, invites and recovery links.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import type { Chrome, Page } from './cdp.ts'
import { launchChrome, skip, startServer, type Server } from './env.ts'

let server: Server
let chrome: Chrome
/** The admin's tab and authenticator, shared by the tests below (which run in order). */
let admin: Page
let adminKey: string

before(async () => {
  if (skip) return
  server = await startServer()
  chrome = await launchChrome()
})
after(async () => {
  try {
    await chrome?.close()
  } finally {
    await server?.close()
  }
})

/** Log in on the login page with the passkey in the page's authenticator. */
async function logIn(page: Page, username: string) {
  await page.fill('#login-form input[name=username]', username)
  await page.click('Log in with passkey')
}

test('the setup link creates the admin with a passkey', { skip }, async () => {
  admin = await chrome.newPage()
  adminKey = await admin.addAuthenticator()
  await admin.goto(server.setupUrl!)
  await admin.fill('#signup-form input[name=username]', 'alice')
  await admin.click('Create passkey & sign up')
  await admin.waitForPath('/files')
  await admin.waitForText('Log out')
  const nav = await admin.eval<string>('document.querySelector("header, nav, body").innerText')
  assert.match(nav, /alice/)
  assert.match(nav, /Admin/)
  assert.equal((await admin.credentials(adminKey)).length, 1)

  // The link only works once.
  const other = await chrome.newPage()
  await other.goto(server.setupUrl!)
  await other.waitForText('invalid, already used, or expired')
  assert.equal(await other.eval('!!document.querySelector("#signup-form")'), false)
})

test('log out, then log back in with the passkey', { skip }, async () => {
  await admin.click('Log out')
  await admin.waitForPath('/login')
  assert.equal((await fetch(`${server.url}/files`, { redirect: 'manual' })).status, 303)
  await logIn(admin, 'alice')
  await admin.waitForPath('/files')
  assert.deepEqual(admin.errors, [])
})

test('the same passkey works on another device, but a stale clone of it is refused', { skip }, async () => {
  const snapshot = await admin.credentials(adminKey)
  const laptop = await chrome.newPage()
  await laptop.addCredentials(await laptop.addAuthenticator(), snapshot)
  await laptop.goto(`${server.url}/login`)
  await logIn(laptop, 'alice')
  await laptop.waitForPath('/files')

  // Another copy of the same snapshot: its signature counter is now behind the server's.
  const clone = await chrome.newPage()
  await clone.addCredentials(await clone.addAuthenticator(), snapshot)
  await clone.goto(`${server.url}/login`)
  await logIn(clone, 'alice')
  const error = await clone.waitFor<string>('document.querySelector("#status.err")?.textContent')
  assert.match(error, /compromised/)
  assert.equal(new URL(await clone.url()).pathname, '/login')
})

test('an unknown username is refused', { skip }, async () => {
  const page = await chrome.newPage()
  await page.addAuthenticator()
  await page.goto(`${server.url}/login`)
  await logIn(page, 'nobody')
  await page.waitFor('document.querySelector("#status.err")?.textContent')
  assert.equal(new URL(await page.url()).pathname, '/login')
})

test('a second passkey can be added in Settings, from another authenticator', { skip }, async () => {
  await admin.goto(`${server.url}/settings`)
  // The authenticator that already holds alice's passkey is refused (excludeCredentials).
  await admin.fill('#add-passkey-form input[name=name]', 'Same key')
  await admin.click('Add a passkey')
  await admin.waitFor('document.querySelector("#status.err")?.textContent')

  // Plug in a new security key instead.
  await admin.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: adminKey })
  adminKey = await admin.addAuthenticator()
  await admin.fill('#add-passkey-form input[name=name]', 'Backup key')
  await admin.click('Add a passkey')
  await admin.waitForText('Passkey added')
  assert.match(await admin.text(), /Backup key/)
  assert.doesNotMatch(await admin.text(), /Same key/)
  assert.equal((await admin.credentials(adminKey)).length, 1)

  // And it logs in.
  await admin.click('Log out')
  await logIn(admin, 'alice')
  await admin.waitForPath('/files')
})

/** The one-time link the admin page shows after creating an invite or recovery link. */
const shownLink = (page: Page) => page.waitFor<string>('document.querySelector("pre.token")?.textContent.trim()')

let bob: Page
test('an invite link signs up a user who is not an admin', { skip }, async () => {
  await admin.goto(`${server.url}/admin`)
  await admin.fill('input[name=note]', 'for bob')
  await admin.click('Create invite link')
  const invite = await shownLink(admin)
  assert.match(invite, /\/signup\?invite=/)

  bob = await chrome.newPage()
  await bob.addAuthenticator()
  await bob.goto(invite)
  await bob.fill('#signup-form input[name=username]', 'bob')
  await bob.click('Create passkey & sign up')
  await bob.waitForPath('/files')
  await bob.waitForText('Log out')
  const text = await bob.text()
  assert.match(text, /bob/)
  assert.doesNotMatch(text, /Admin/)
  const token = new URL(invite).searchParams.get('invite')!
  const info = await fetch(`${server.url}/ui/signup?invite=${encodeURIComponent(token)}`).then((r) => r.json())
  assert.equal(info.allowed, false, 'invite is used up')
})

test('a recovery link replaces lost passkeys and signs out other sessions', { skip }, async () => {
  await admin.goto(`${server.url}/admin`)
  // bob's row in the users table
  await admin.waitForText('bob')
  await admin.eval(`[...document.querySelectorAll('tr')].find(r => r.cells[0]?.textContent === 'bob')
    .querySelectorAll('button').values().find(b => b.textContent === 'Recovery link').click()`)
  const link = await shownLink(admin)
  assert.match(link, /recover/)

  // Bob, on a new device without his passkey.
  const phone = await chrome.newPage()
  const key = await phone.addAuthenticator()
  await phone.goto(link)
  await phone.click('Create new passkey')
  await phone.waitFor('location.pathname !== new URL(' + JSON.stringify(link) + ').pathname')
  await phone.waitForText('bob')
  assert.equal((await phone.credentials(key)).length, 1)

  // His old session is gone.
  await bob.goto(`${server.url}/files`)
  await bob.waitForPath('/login')
})
