// The file browser and database editor: folders, text files, and editing a database's rows.

import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import type { Chrome, Page } from './cdp.ts'
import { launchChrome, skip, startServer, type Server } from './env.ts'

let server: Server
let chrome: Chrome
let page: Page

before(async () => {
  if (skip) return
  server = await startServer()
  chrome = await launchChrome()
  page = await chrome.newPage()
  await page.addAuthenticator()
  await page.goto(server.setupUrl!)
  await page.fill('#signup-form input[name=username]', 'alice')
  await page.click('Create passkey & sign up')
  await page.waitForPath('/files')
})
after(async () => {
  try {
    await chrome?.close()
  } finally {
    await server?.close()
  }
})

/** Create something in the folder on screen. */
async function create(name: string, kind: 'folder' | 'text' | 'sqlite') {
  await page.fill('input[name=name]', name)
  await page.fill('select[name=kind]', kind)
  await page.click('Create')
}

test('folders and text files', { skip }, async () => {
  await page.waitForText('This folder is empty.')
  await create('docs', 'folder')
  await page.click('docs')
  await page.waitForPath('/files/docs')
  await page.waitForText('This folder is empty.')

  await create('notes.txt', 'text')
  await page.waitForPath('/files/docs/notes.txt')
  await page.fill('textarea[name=content]', 'hello\nworld')
  await page.press('textarea[name=content]', 's', { ctrlKey: true })
  await page.waitForText('Saved')
  await page.reload()
  assert.equal(await page.waitFor('document.querySelector("textarea[name=content]")?.value'), 'hello\nworld')

  // Back to the top, where the folder expands in place.
  await page.click('Files', 'main nav')
  await page.waitForPath('/files')
  await page.eval(`document.querySelector('button[aria-label="Expand docs"]').click()`)
  await page.waitForText('notes.txt')
  assert.match(await page.text(), /11 B/)
  await page.eval(`[...document.querySelectorAll('tr')].find(r => r.innerText.includes('notes.txt'))
    .querySelectorAll('button').values().find(b => b.textContent === 'Delete').click()`)
  await page.waitForText('Deleted notes.txt')
  await page.waitForText('This folder is empty.')
  assert.deepEqual(page.errors, [])
})

test('a database: console, inline edits, the row form', { skip }, async () => {
  await page.goto(`${server.url}/files`)
  await create('app.db', 'sqlite')
  await page.waitForPath('/files/app.db')
  await page.waitForText('No tables.')

  await page.fill('textarea[name=sql]', "CREATE TABLE items(id INTEGER PRIMARY KEY, title TEXT); INSERT INTO items(title) VALUES ('first')")
  await page.press('textarea[name=sql]', 'Enter', { ctrlKey: true })
  await page.waitForText('Executed 2 statements')
  await page.click('items', 'aside')
  await page.waitFor(`location.search === '?table=items'`)
  await page.waitForText('first')

  // Double-click a cell, type, Enter.
  await page.eval(`[...document.querySelectorAll('td[tabindex]')].find(t => t.textContent === 'first')
    .dispatchEvent(new MouseEvent('dblclick', { bubbles: true }))`)
  await page.fill('td :is(input, textarea)', 'second')
  await page.press('td :is(input, textarea)', 'Enter')
  await page.waitForText('title: Updated 1 column(s)')
  assert.equal(await page.eval(`!!document.querySelector('td :is(input, textarea)')`), false)
  assert.match(await page.text(), /second/)

  await page.click('+ Insert row')
  await page.waitForText('New row')
  await page.fill('#v1', 'third')
  await page.click('Insert')
  await page.waitForText('Row inserted')
  await page.waitForText('third')

  await page.click('Edit')
  await page.waitForText('Edit row')
  assert.equal(await page.waitFor(`document.querySelector('#v1')?.value`), 'second')
  await page.fill('#v1', 'changed')
  await page.click('Save')
  await page.waitForText('Updated 1 column(s)')
  await page.waitForText('changed')

  await page.click('Delete', 'section table')
  await page.waitForText('Row deleted')
  assert.doesNotMatch(await page.text(), /changed/)
  assert.match(await page.text(), /third/)
  assert.deepEqual(page.errors, [])
})

test('admins browse system.db', { skip }, async () => {
  await page.goto(`${server.url}/admin`)
  await page.click('Open system database')
  await page.waitForPath('/admin/db')
  await page.click('users', 'aside')
  await page.waitForText('alice')
  await page.fill('textarea[name=sql]', 'DELETE FROM sessions')
  await page.click('Run (Ctrl+Enter)')
  await page.waitFor('!!document.querySelector("[role=alert]")')
  assert.deepEqual(page.errors, [])
})
