#!/usr/bin/env node
'use strict'

const { parseArgs } = require('node:util')
const { start } = require('..')

const usage = `usage: bisonbase [options]

  -p, --port <n>         port to listen on, 0 for any (default 8080)
  -d, --data-dir <dir>   where system.db and user files live (default ./data)
  -h, --help`

let args
try {
  args = parseArgs({
    options: {
      port: { type: 'string', short: 'p' },
      'data-dir': { type: 'string', short: 'd' },
      help: { type: 'boolean', short: 'h' },
    },
  }).values
} catch (e) {
  console.error(`${e.message}\n\n${usage}`)
  process.exit(2)
}
if (args.help) {
  console.log(usage)
  process.exit(0)
}

const port = args.port === undefined ? undefined : Number(args.port)
if (port !== undefined && !(Number.isInteger(port) && port >= 0 && port < 65536)) {
  console.error(`invalid --port: ${args.port}`)
  process.exit(2)
}

start({
  port,
  dataDir: args['data-dir'],
  log: process.env.RUST_LOG ?? 'bisonbase=info,tower_http=info',
}).then(
  (server) => {
    const stop = () => server.close().then(() => process.exit(0))
    process.once('SIGINT', stop)
    process.once('SIGTERM', stop)
  },
  (e) => {
    console.error(`bisonbase: ${e.message}`)
    process.exit(1)
  },
)
