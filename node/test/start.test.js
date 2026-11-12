'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { start } = require('..')

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bisonbase-'))
const opts = (dataDir) => ({ port: 0, dataDir, log: 'off' })

test('starts on a free port and serves the UI and API', async () => {
  const dataDir = tmp()
  const server = await start(opts(dataDir))
  try {
    assert.ok(server.port > 0)
    assert.equal(server.host, '127.0.0.1')
    assert.equal(server.url, `http://localhost:${server.port}`)
    assert.match(server.setupUrl, new RegExp(`^${server.url}/signup\\?invite=`))
    assert.ok(fs.existsSync(path.join(dataDir, 'system.db')))

    const login = await fetch(`${server.url}/login`)
    assert.equal(login.status, 200)
    assert.match(await login.text(), /passkey/i)

    const api = await fetch(`${server.url}/api/v1/files/`)
    assert.equal(api.status, 401)
    assert.equal((await api.json()).error.code, 'unauthorized')
  } finally {
    await server.close()
  }
})

test('close is idempotent and frees the port', async () => {
  const server = await start(opts(tmp()))
  const { url } = server
  await Promise.all([server.close(), server.close()])
  await server.close()
  await assert.rejects(fetch(`${url}/login`))
})

test('several servers can run in one process', async () => {
  const a = await start(opts(tmp()))
  const b = await start(opts(tmp()))
  try {
    assert.notEqual(a.port, b.port)
    assert.equal((await fetch(`${a.url}/login`)).status, 200)
    assert.equal((await fetch(`${b.url}/login`)).status, 200)
  } finally {
    await Promise.all([a.close(), b.close()])
  }
})

test('reports errors as rejections', async () => {
  const server = await start(opts(tmp()))
  try {
    await assert.rejects(start({ ...opts(tmp()), port: server.port }), /binding 127\.0\.0\.1:\d+/)
  } finally {
    await server.close()
  }
})

test('Symbol.asyncDispose (await using) closes the server', async () => {
  const server = await start(opts(tmp()))
  assert.equal((await fetch(`${server.url}/login`)).status, 200)
  await server[Symbol.asyncDispose]()
  await assert.rejects(fetch(`${server.url}/login`))
})

test('the CLI starts and stops on SIGTERM', async () => {
  const { spawn } = require('node:child_process')
  const child = spawn(process.execPath, [path.join(__dirname, '../bin/bisonbase.js'), '-p', '0', '-d', tmp()], {
    env: { ...process.env, RUST_LOG: 'bisonbase=info' },
  })
  let out = ''
  const url = await new Promise((resolve, reject) => {
    const onData = (d) => {
      out += d
      const m = out.match(/public origin (http:\/\/localhost:\d+)/)
      if (m) resolve(m[1])
    }
    child.stdout.on('data', onData)
    child.stderr.on('data', onData)
    child.on('exit', (c) => reject(new Error(`exited ${c}: ${out}`)))
  })
  assert.match(out, /signup\?invite=/)
  assert.equal((await fetch(`${url}/login`)).status, 200)
  child.kill('SIGTERM')
  const [code] = await new Promise((r) => child.on('exit', (...a) => r(a)))
  assert.equal(code, 0)
})
