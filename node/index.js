'use strict'

const native = require('./native.js')

// Running servers, so they can't be garbage-collected: dropping the native object stops the
// listener, and callers often don't keep a reference (e.g. a script that only starts one).
const running = new Set()

/** A running bisonbase server. Keeps the process alive until closed (or `unref()`ed). */
class Server {
  #native
  #keepAlive
  #closing

  constructor(n) {
    this.#native = n
    // Native listeners don't hold the event loop open, so a timer does.
    this.#keepAlive = setInterval(() => {}, 2 ** 31 - 1)
    running.add(this)
  }

  /** Public origin of the web UI and API, e.g. "http://localhost:8080". */
  get url() {
    return this.#native.url
  }

  /** Address the listener is bound to. */
  get host() {
    return this.#native.host
  }

  /** Port the listener is bound to (useful with `port: 0`). */
  get port() {
    return this.#native.port
  }

  /** One-time admin signup link if the data directory had no users, else null. */
  get setupUrl() {
    return this.#native.setupUrl
  }

  /** Let the process exit even if the server is still running. */
  unref() {
    this.#keepAlive.unref()
    return this
  }

  /** Undo `unref()`. */
  ref() {
    this.#keepAlive.ref()
    return this
  }

  /** Stop accepting connections and wait for in-flight requests. Safe to call twice. */
  close() {
    this.#closing ??= this.#native.close().finally(() => {
      clearInterval(this.#keepAlive)
      running.delete(this)
    })
    return this.#closing
  }

  [Symbol.asyncDispose]() {
    return this.close()
  }
}

/**
 * Start a bisonbase server in this process.
 * @param {import('./index').StartOptions} [options]
 * @returns {Promise<Server>}
 */
async function start(options = {}) {
  return new Server(await native.start(options))
}

module.exports = { start, Server }
