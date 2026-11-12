// A small driver for headless Chrome over the DevTools protocol, for the browser tests. No
// dependencies: Node's built-in WebSocket talks to Chrome. Passkeys use Chrome's virtual
// WebAuthn authenticator, so ceremonies complete without anyone touching a device.

import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** The Chrome or Chromium binary: $CHROME_PATH, or the first one found on PATH. */
export function findChrome(): string | null {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH
  for (const name of ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']) {
    try {
      execFileSync('which', [name], { stdio: 'ignore' })
      return name
    } catch {}
  }
  return null
}

type Handler = (params: any, sessionId?: string) => void

export class Chrome {
  #proc: ChildProcess
  #profile: string
  #ws: WebSocket
  #id = 0
  #pending = new Map<number, { resolve: (v: any) => void; reject: (e: Error) => void }>()
  #handlers = new Map<string, Set<Handler>>()

  private constructor(proc: ChildProcess, profile: string, ws: WebSocket) {
    this.#proc = proc
    this.#profile = profile
    this.#ws = ws
    ws.onclose = () => {
      for (const p of this.#pending.values()) p.reject(new Error('Chrome closed the connection'))
      this.#pending.clear()
    }
    ws.onmessage = (m) => {
      const msg = JSON.parse(String(m.data))
      if (msg.id) {
        const p = this.#pending.get(msg.id)
        this.#pending.delete(msg.id)
        if (msg.error) p?.reject(new Error(`${msg.error.message} ${msg.error.data ?? ''}`))
        else p?.resolve(msg.result)
      } else {
        for (const h of this.#handlers.get(msg.method) ?? []) h(msg.params, msg.sessionId)
      }
    }
  }

  static async launch(binary: string): Promise<Chrome> {
    const profile = mkdtempSync(join(tmpdir(), 'chrome-'))
    const proc = spawn(binary, [
      '--headless=new',
      '--remote-debugging-port=0',
      '--no-sandbox', // CI containers often can't use Chrome's sandbox; only trusted pages are loaded
      '--no-first-run',
      '--disable-gpu',
      `--user-data-dir=${profile}`,
      'about:blank',
    ], { stdio: ['ignore', 'ignore', 'pipe'], detached: true }) // own process group, so close() can end all of Chrome's processes
    const url = await new Promise<string>((resolve, reject) => {
      let err = ''
      const timer = setTimeout(() => reject(new Error(`Chrome didn't start:\n${err}`)), 20_000)
      proc.stderr!.on('data', (d) => {
        err += d
        const m = err.match(/DevTools listening on (ws:\/\/\S+)/)
        if (m) {
          clearTimeout(timer)
          resolve(m[1])
        }
      })
      proc.on('exit', () => reject(new Error(`Chrome exited:\n${err}`)))
    })
    const ws = new WebSocket(url)
    await new Promise((resolve, reject) => {
      ws.onopen = resolve
      ws.onerror = reject
    })
    return new Chrome(proc, profile, ws)
  }

  send(method: string, params: object = {}, sessionId?: string): Promise<any> {
    const id = ++this.#id
    this.#ws.send(JSON.stringify({ id, method, params, sessionId }))
    return new Promise((resolve, reject) => this.#pending.set(id, { resolve, reject }))
  }

  on(method: string, handler: Handler): void {
    if (!this.#handlers.has(method)) this.#handlers.set(method, new Set())
    this.#handlers.get(method)!.add(handler)
  }

  /** A tab in a fresh browser context: its own cookies and storage, like a separate device. */
  async newPage(): Promise<Page> {
    const { browserContextId } = await this.send('Target.createBrowserContext')
    const { targetId } = await this.send('Target.createTarget', { url: 'about:blank', browserContextId })
    const { sessionId } = await this.send('Target.attachToTarget', { targetId, flatten: true })
    const page = new Page(this, sessionId)
    await page.init()
    return page
  }

  async close(): Promise<void> {
    this.#ws.close()
    this.#proc.stderr?.destroy()
    const group = (signal: NodeJS.Signals) => {
      try {
        process.kill(-this.#proc.pid!, signal)
      } catch {} // already gone
    }
    if (this.#proc.exitCode === null && this.#proc.signalCode === null) {
      const exited = new Promise((r) => this.#proc.once('exit', r))
      group('SIGTERM')
      // Don't hang the test run if Chrome ignores SIGTERM.
      await Promise.race([exited, new Promise((r) => setTimeout(r, 5000).unref())])
    }
    group('SIGKILL') // helper processes that outlived the browser
    // Best effort: a helper may still be writing to the profile for a moment.
    rmSync(this.#profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 })
  }
}

export class Page {
  #chrome: Chrome
  #session: string
  /** Waiters for the `load` lifecycle event of a navigation, by loaderId. */
  #loads = new Map<string, () => void>()
  #loaded = new Set<string>()
  /** Uncaught exceptions and console.error messages on the page. */
  errors: string[] = []

  constructor(chrome: Chrome, session: string) {
    this.#chrome = chrome
    this.#session = session
  }

  async init() {
    const mine = (h: Handler): Handler => (p, s) => s === this.#session && h(p)
    this.#chrome.on('Page.lifecycleEvent', mine((p) => {
      if (p.name !== 'load') return
      this.#loaded.add(p.loaderId)
      this.#loads.get(p.loaderId)?.()
    }))
    this.#chrome.on('Runtime.exceptionThrown', mine((p) => this.errors.push(p.exceptionDetails.exception?.description ?? p.exceptionDetails.text)))
    this.#chrome.on('Runtime.consoleAPICalled', mine((p) => {
      if (p.type === 'error') this.errors.push(p.args.map((a: any) => a.value ?? a.description).join(' '))
    }))
    // Accept confirm() prompts, as a user clicking OK would.
    this.#chrome.on('Page.javascriptDialogOpening', mine(() => void this.send('Page.handleJavaScriptDialog', { accept: true })))
    await Promise.all([
      this.send('Page.enable'),
      this.send('Page.setLifecycleEventsEnabled', { enabled: true }),
      this.send('Runtime.enable'),
    ])
  }

  send(method: string, params: object = {}): Promise<any> {
    return this.#chrome.send(method, params, this.#session)
  }

  /** Evaluate an expression in the page and return its (JSON) value. */
  async eval<T = unknown>(expression: string): Promise<T> {
    const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text)
    return r.result.value
  }

  /** Wait for the navigation with this loaderId to finish loading. */
  #waitForLoad(loaderId: string): Promise<void> {
    if (this.#loaded.has(loaderId)) return Promise.resolve()
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Timed out waiting for the page to load')), 15_000)
      this.#loads.set(loaderId, () => {
        clearTimeout(timer)
        this.#loads.delete(loaderId)
        resolve()
      })
    })
  }

  async goto(url: string): Promise<void> {
    const { loaderId, errorText } = await this.send('Page.navigate', { url })
    if (errorText) throw new Error(`Navigating to ${url}: ${errorText}`)
    if (loaderId) await this.#waitForLoad(loaderId)
  }

  async reload(): Promise<void> {
    const { frameTree } = await this.send('Page.getFrameTree')
    const before = frameTree.frame.loaderId
    await this.send('Page.reload')
    await this.waitFor(`document.readyState === 'complete'`)
    // A reload gets a new loaderId; wait for that one.
    for (;;) {
      const { frameTree: t } = await this.send('Page.getFrameTree')
      if (t.frame.loaderId !== before) return this.#waitForLoad(t.frame.loaderId)
      await new Promise((r) => setTimeout(r, 20))
    }
  }

  /** Wait until `expression` is truthy in the page (across navigations), and return its value. */
  async waitFor<T = unknown>(expression: string, timeout = 10_000): Promise<T> {
    const end = Date.now() + timeout
    for (;;) {
      try {
        const v = await this.eval<T>(expression)
        if (v) return v
      } catch {} // e.g. the page is navigating
      if (Date.now() > end) {
        const where = await this.eval<string>('location.href + "\\n" + document.body?.innerText').catch(() => '?')
        throw new Error(`Timed out waiting for ${expression}\nPage: ${where}\nErrors: ${this.errors.join('\n')}`)
      }
      await new Promise((r) => setTimeout(r, 50))
    }
  }

  /** Wait until the page's text contains `text`. */
  waitForText(text: string, timeout?: number): Promise<unknown> {
    return this.waitFor(`document.body?.innerText.includes(${JSON.stringify(text)})`, timeout)
  }

  /** Wait until location.pathname is `path`. */
  waitForPath(path: string, timeout?: number): Promise<unknown> {
    return this.waitFor(`location.pathname === ${JSON.stringify(path)}`, timeout)
  }

  url(): Promise<string> {
    return this.eval('location.href')
  }

  text(): Promise<string> {
    return this.eval('document.body.innerText')
  }

  /** Set an input's, textarea's or select's value the way typing does (React sees it too). */
  async fill(selector: string, value: string): Promise<void> {
    await this.waitFor(`!!document.querySelector(${JSON.stringify(selector)})`)
    await this.eval(`(() => {
      const el = document.querySelector(${JSON.stringify(selector)})
      Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value').set.call(el, ${JSON.stringify(value)})
      el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }))
    })()`)
  }

  /** Dispatch a key press on the element matching `selector`. */
  async press(selector: string, key: string, mods: { ctrlKey?: boolean; shiftKey?: boolean } = {}): Promise<void> {
    await this.waitFor(`!!document.querySelector(${JSON.stringify(selector)})`)
    await this.eval(`document.querySelector(${JSON.stringify(selector)})
      .dispatchEvent(new KeyboardEvent('keydown', { key: ${JSON.stringify(key)}, bubbles: true, ...${JSON.stringify(mods)} }))`)
  }

  /** Click the button or link whose text is `label`, optionally inside the element matching `within`. */
  async click(label: string, within = 'body'): Promise<void> {
    const find = `[...document.querySelectorAll(${JSON.stringify(within)})].flatMap(r => [...r.querySelectorAll('button, a')])
      .find(b => b.textContent.trim() === ${JSON.stringify(label)})`
    await this.waitFor(`!!(${find})`)
    await this.eval(`(${find}).click()`)
  }

  /** Add a virtual passkey authenticator (a platform authenticator with user verification). */
  async addAuthenticator(): Promise<string> {
    await this.send('WebAuthn.enable')
    const { authenticatorId } = await this.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    })
    return authenticatorId
  }

  /** The passkeys an authenticator holds. */
  async credentials(authenticatorId: string): Promise<any[]> {
    return (await this.send('WebAuthn.getCredentials', { authenticatorId })).credentials
  }

  /** Copy passkeys into this page's authenticator, as if synced from another device. */
  async addCredentials(authenticatorId: string, credentials: any[]): Promise<void> {
    for (const credential of credentials) await this.send('WebAuthn.addCredential', { authenticatorId, credential })
  }
}
