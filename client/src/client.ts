// The client: BisonBase (sign-in and the connection to the server), Folder (files, in each
// user's own account or in the app's own storage; see files.ts), UserDb and AppDb (a SQLite file
// in one of those folders) and Table (typed select / insert / update / delete, plus live queries
// that the server keeps up to date).

import { revoke, startSignIn, takeSignInResponse } from './auth.ts'
import { deleteRequest, insertRequest, selectRequest, updateRequest } from './ops.ts'
import { migrateRequest, SchemaError } from './schema.ts'
import { checkName, parseTable, type Sharing, type TableDef } from './table.ts'
import type { Columns, InsertFor, RowFor, SelectOptions, UpdateFor, Where, Wire } from './types.ts'
import { decode } from './values.ts'
import { watch } from './watch.ts'
import { Folder } from './files.ts'

export interface BisonBaseOptions {
  /** The bisonbase server. Default: `/bb` on the current origin. */
  url?: string
  /**
   * Use this token instead of signing in through the browser, e.g. a personal token in a
   * script or test. It isn't stored.
   */
  token?: string
}

export type AuthState =
  /** `error` says why, when signing in failed or the token stopped working. */
  | { status: 'signed-out'; error?: string }
  /** Finishing a sign-in (trading the code from the redirect for a token). */
  | { status: 'pending' }
  | { status: 'signed-in' }

/** An error response from the bisonbase API. */
export class ApiError extends Error {
  override name = 'ApiError'
  readonly status: number
  readonly code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

/** An operation needed the user to be signed in. */
export class NotSignedInError extends Error {
  override name = 'NotSignedInError'
  constructor() {
    super('Not signed in')
  }
}

/** A registered app, and what the signed-in user may do with its storage. */
export interface AppInfo {
  id: string
  name: string
  /** The only origin that may sign in with the app's id. */
  origin: string
  /** The user may create databases and change tables in the app's storage. */
  owner: boolean
  /** The signed-in user. Rows they own have this `_owner`. */
  user: { id: string; username: string }
}

/** Rows as the server sends them: column names, then values in wire form. */
interface Rows {
  columns: string[]
  rows: Wire[][]
  truncated?: boolean
}

/** The state of a live query, as `useSelectState` and `useListState` return it. */
export interface QueryState<R> {
  /** Empty while signed out or before the first load. Kept (stale) while reloading or after an error. */
  rows: readonly R[]
  /** True until the first load finishes (only while signed in or signing in). */
  loading: boolean
  error: Error | null
}

/** Set by `bisonbase/react` when it's imported. */
interface Hooks {
  useQuery<R>(query: LiveQuery<R>): QueryState<R>
}
let hooks: Hooks | null = null

/** @internal Subscribe a component to a live query; needs `bisonbase/react`. */
export function useLiveQuery<R>(query: LiveQuery<R>, what: string): QueryState<R> {
  if (!hooks) throw new Error(`${what} needs React: add \`import "bisonbase/react"\` to your app`)
  return hooks.useQuery(query)
}
/** @internal */
export function setHooks(h: Hooks): void {
  hooks = h
}

const EMPTY: readonly never[] = Object.freeze([])
const SIGNED_OUT: QueryState<never> = Object.freeze({ rows: EMPTY, loading: false, error: null })
const LOADING: QueryState<never> = Object.freeze({ rows: EMPTY, loading: true, error: null })
const EXPIRED = 'Your sign-in expired or was revoked. Please sign in again.'

function storage(): Storage | null {
  try {
    return globalThis.localStorage ?? null
  } catch {
    return null
  }
}

/** @internal JSON with object keys sorted, so equal options give equal cache keys. */
export function stableKey(value: unknown): string {
  return JSON.stringify(value, (_, v) =>
    v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Uint8Array)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v instanceof Uint8Array
        ? { $bytes: Array.from(v) }
        : v,
  )
}

/** The connection to a bisonbase server for one app. Make one per page. */
export class BisonBase {
  /** The instance `<AuthElement />` and other React helpers use. */
  static instance: BisonBase | null = null

  readonly appId: string
  readonly appName: string
  /** The server's origin, e.g. `https://example.com/bb`, without a trailing slash. */
  readonly url: string

  #token: string | null = null
  #persist: boolean
  #auth: AuthState = { status: 'signed-out' }
  /** Resolves when no sign-in is pending. */
  #settled: Promise<void> = Promise.resolve()
  /** Bumped whenever the token changes, so results fetched with an old token are dropped. */
  #epoch = 0
  #authListeners = new Set<() => void>()
  #dbs = new Map<string, Database>()
  #feeds = new Set<ChangeFeed>()
  #queries = new Map<string, LiveQuery<any>>()
  #registering: Promise<void> | null = null

  /**
   * The app's folder in the signed-in user's own account, `apps/<appId>/`: only that user can
   * read or change what's in it.
   */
  readonly files: Folder<UserDb>
  /**
   * The app's own storage on the server, shared by everyone who uses the app. Anyone signed in
   * can list and read its files; only the app's owners (and admins) can add, change or delete
   * them. Databases in it hold rows that belong to each user (see `AppDb`).
   */
  readonly appFiles: Folder<AppDb>

  /**
   * @param appId A UUID that identifies the app and never changes; the app's files live in
   *   `apps/<appId>/` in each user's account. Make one with `crypto.randomUUID()`.
   * @param appName The name shown to users when they sign in and in their file browser.
   */
  constructor(appId: string, appName: string, options: BisonBaseOptions = {}) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(appId)) {
      throw new Error(`App id must be a UUID (make one with crypto.randomUUID()), got "${appId}"`)
    }
    this.appId = appId.toLowerCase()
    this.appName = appName
    const base = options.url ?? (typeof location !== 'undefined' ? `${location.origin}/bb` : undefined)
    if (!base) throw new Error('Pass options.url: there is no current page to default to')
    this.url = base.replace(/\/+$/, '')
    this.#persist = options.token === undefined
    this.files = new Folder(this, 'user', '')
    this.appFiles = new Folder(this, 'app', '')

    if (BisonBase.instance) {
      console.warn('BisonBase: more than one instance was created; React helpers use the latest one')
    }
    BisonBase.instance = this

    if (options.token !== undefined) {
      this.#setToken(options.token)
    } else {
      const response = takeSignInResponse(this.url)
      if (response) {
        this.#setAuth({ status: 'pending' })
        this.#settled = response.then(
          (token) => this.#setToken(token),
          (e: Error) => this.#setToken(null, e.message),
        )
      } else {
        const saved = storage()?.getItem(this.#tokenKey) ?? null
        if (saved) this.#setToken(saved)
      }
    }

    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
      // Changes arrive over each database's change stream; if one isn't connected, at least
      // pick up changes made elsewhere when the user comes back to this page.
      window.addEventListener('focus', () => this.#refreshAll())
      window.addEventListener('storage', (e) => {
        if (e.key === this.#tokenKey && this.#persist && e.newValue !== this.#token) this.#setToken(e.newValue)
      })
    }
  }

  get #tokenKey() {
    return `bisonbase:token:${this.url}:${this.appId}`
  }

  /** Whether the user is signed in. */
  get auth(): AuthState {
    return this.#auth
  }

  /** Call `listener` whenever `auth` changes. Returns a function that stops listening. */
  onAuthChange(listener: () => void): () => void {
    this.#authListeners.add(listener)
    return () => this.#authListeners.delete(listener)
  }

  /** Send the browser to the server to sign in; it comes back to the current page. */
  signIn(): Promise<void> {
    return startSignIn({ server: this.url, appId: this.appId, appName: this.appName, scope: 'files:write db:write' })
  }

  /** Forget the token here and revoke it on the server. */
  async signOut(): Promise<void> {
    const token = this.#token
    this.#setToken(null)
    if (token && this.#persist) await revoke(this.url, token)
  }

  /**
   * Shorthand for `bb.files.db(name + ".db")`: a database that each user gets their own copy of,
   * stored as `apps/<appId>/<name>.db` in their account. Only that user can read or change it.
   */
  createUserDb(name: string): UserDb {
    return this.files.db(`${checkDbName(name)}.db`)
  }

  /**
   * Shorthand for `bb.appFiles.db(name + ".db")`: a database in the app's own storage, shared by
   * everyone who uses the app. Each row belongs to the user who inserted it: users read their own
   * rows (and every row of tables declared `shared`), and only change their own. The app must be
   * registered by a server admin (it is registered automatically when an admin signs in to it),
   * and only the app's owners can create the database and change its tables, which happens when
   * one of them signs in.
   */
  createAppDb(name: string): AppDb {
    return this.appFiles.db(`${checkDbName(name)}.db`)
  }

  /** @internal The database at `key` (its API path), made by `make` the first time. */
  _db<D extends Database>(key: string, make: () => D): D {
    let db = this.#dbs.get(key)
    if (!db) {
      db = make()
      this.#dbs.set(key, db)
    }
    return db as D
  }

  /** @internal Follow `feed` (it resets when the user changes). */
  _addFeed(feed: ChangeFeed) {
    this.#feeds.add(feed)
  }

  /**
   * @internal Run `fn` against the app's storage. If the app isn't registered yet, register it
   * (which works when the signed-in user is an admin) and run `fn` again.
   */
  async _inAppStorage<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn()
    } catch (e) {
      if (!(e instanceof ApiError && e.code === 'app_not_registered')) throw e
    }
    this.#registering ??= this.#register().finally(() => (this.#registering = null))
    await this.#registering
    return fn()
  }

  async #register() {
    try {
      await this._request(`apps/${this.appId}`, 'register', { name: this.appName })
    } catch (r) {
      if (r instanceof ApiError && r.status === 403) {
        throw new ApiError(404, 'app_not_registered', `${this.appName} isn't registered with the server yet; an admin needs to sign in to it once, or register it under Admin`)
      }
      // A conflict means it was registered meanwhile, e.g. by another tab, or by this page's
      // other requests while signing in.
      if (!(r instanceof ApiError && r.status === 409)) throw r
    }
  }

  /** The app's registration, and what the signed-in user may do with its storage. */
  async appInfo(): Promise<AppInfo> {
    return this._request(`apps/${this.appId}`, null, undefined, 'GET')
  }

  #setAuth(state: AuthState) {
    this.#auth = state
    for (const listener of [...this.#authListeners]) listener()
  }

  #setToken(token: string | null, error?: string) {
    const changed = token !== this.#token
    this.#token = token
    if (this.#persist) {
      const s = storage()
      if (token) s?.setItem(this.#tokenKey, token)
      else s?.removeItem(this.#tokenKey)
    }
    this.#setAuth(token ? { status: 'signed-in' } : error ? { status: 'signed-out', error } : { status: 'signed-out' })
    if (!changed) return
    this.#epoch++
    for (const db of this.#dbs.values()) db._reset()
    for (const feed of this.#feeds) feed.reset()
    for (const q of this.#queries.values()) q._authChanged()
  }

  #refreshAll() {
    for (const q of this.#queries.values()) if (!q.feed.live) q._invalidate()
  }

  /**
   * @internal A cached live query, shared by everything that asks for the same rows. `scope`
   * and `table` say which writes make it stale (see `_invalidate`); `feed` is the change stream
   * that keeps it up to date while it's in use.
   */
  _liveQuery<R>(key: string, run: () => Promise<R[]>, feed: ChangeFeed, scope: object, table?: string): LiveQuery<R> {
    let q = this.#queries.get(key)
    if (!q) {
      q = new LiveQuery(this, run, feed, scope, table, () => this.#queries.delete(key))
      this.#queries.set(key, q)
    }
    return q
  }

  /**
   * @internal Mark live queries in `scope` (a database, or a storage area's file listings) on
   * `tables` (by name, or all of them) stale, and reload the ones in use.
   */
  _invalidate(scope: object, tables?: readonly string[]) {
    const names = tables && new Set(tables.map((t) => t.toLowerCase()))
    for (const q of this.#queries.values()) {
      if (q.scope === scope && (!names || !q.table || names.has(q.table.toLowerCase()))) q._invalidate()
    }
  }

  /** @internal */
  get _epoch() {
    return this.#epoch
  }

  /** @internal Whether a query can run now (signed in or signing in). */
  get _active() {
    return this.#auth.status !== 'signed-out'
  }

  /**
   * @internal Call the API (`path` is relative to `/api/v1/`) after any pending sign-in: POST an
   * op by default. Returns the JSON response.
   */
  async _request(path: string, op: string | null, body?: unknown, method = 'POST'): Promise<any> {
    const res = await this._send(path, op, { method, body })
    return res.json().catch(() => ({}))
  }

  /** @internal Like `_fetch`, but an error response throws `ApiError` (or `SchemaError`). */
  async _send(path: string, query: Query, init: FetchInit): Promise<Response> {
    const res = await this._fetch(path, query, init)
    if (res.ok || res.status === 304) return res
    const json = await res.json().catch(() => ({}))
    const code = json.error?.code ?? 'unknown'
    const message = json.error?.message ?? res.statusText
    if (code === 'schema_mismatch') throw new SchemaError(`${path}: ${message}`)
    throw new ApiError(res.status, code, message)
  }

  /**
   * @internal Call the API with the token, signing out if the server rejects it. `query` is an
   * op, or query parameters (undefined ones are left out). `body` is sent as JSON, `raw` as is.
   */
  async _fetch(path: string, query: Query, init: FetchInit): Promise<Response> {
    await this.#settled
    const token = this.#token
    if (!token) throw new NotSignedInError()
    const headers: Record<string, string> = { ...init.headers, authorization: `Bearer ${token}` }
    if (init.body !== undefined) headers['content-type'] = 'application/json'
    const params = new URLSearchParams()
    for (const [k, v] of Object.entries(typeof query === 'string' ? { op: query } : (query ?? {}))) {
      if (v !== undefined) params.set(k, v)
    }
    const qs = params.size ? `?${params}` : ''
    const res = await fetch(`${this.url}/api/v1/${path}${qs}`, {
      method: init.method,
      headers,
      body: init.body !== undefined ? JSON.stringify(init.body) : init.raw,
      signal: init.signal,
    })
    if (res.status === 401 && this.#token === token) this.#setToken(null, EXPIRED)
    return res
  }
}

/** @internal An op, or query parameters. */
type Query = string | null | Record<string, string | undefined>
/** @internal */
interface FetchInit {
  method: string
  body?: unknown
  raw?: BodyInit
  headers?: Record<string, string>
  signal?: AbortSignal
}

function checkDbName(name: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(name)) throw new Error(`Database name "${name}" must be letters, digits, "_" and "-"`)
  return name
}

/**
 * @internal A server change stream (`?op=watch`) on one path. It's open while live queries that
 * use it are, and reconnects when the user changes.
 */
export class ChangeFeed {
  #bb: BisonBase
  #open: (signal: AbortSignal) => Promise<Response>
  #onEvent: (event: string, data: any) => void
  /** How many live queries using this stream are in use. */
  #watchers = 0
  #stop: (() => void) | null = null
  /** Whether the stream is connected. */
  live = false

  constructor(bb: BisonBase, open: (signal: AbortSignal) => Promise<Response>, onEvent: (event: string, data: any) => void) {
    this.#bb = bb
    this.#open = open
    this.#onEvent = onEvent
    bb._addFeed(this)
  }

  /** A live query using this stream is in use. */
  retain() {
    if (this.#watchers++ === 0) this.#start()
  }

  /** A live query using this stream is no longer in use. */
  release() {
    if (--this.#watchers === 0) this.#end()
  }

  /** Reconnect (the user changed). */
  reset() {
    this.#end()
    if (this.#watchers > 0) this.#start()
  }

  #start() {
    if (this.#stop || !this.#bb._active) return
    const stop = watch({
      open: this.#open,
      // Signed out, or the tables can't be set up: retrying won't help.
      fatal: (e) => e instanceof NotSignedInError || e instanceof SchemaError,
      onEvent: this.#onEvent,
      onLive: (live) => {
        // A stream that was already stopped may report late; only the current one counts.
        if (this.#stop === stop) this.live = live
      },
    })
    this.#stop = stop
  }

  #end() {
    this.#stop?.()
    this.#stop = null
    this.live = false
  }
}

/** A query whose rows are kept up to date while something is subscribed to it. */
export class LiveQuery<R> {
  #bb: BisonBase
  #run: () => Promise<R[]>
  #dispose: () => void
  #state: QueryState<R>
  #listeners = new Set<() => void>()
  #stale = true
  #running = false
  #again = false
  #gc: ReturnType<typeof setTimeout> | undefined
  /** @internal The change stream that keeps it up to date. */
  readonly feed: ChangeFeed
  /** @internal What it reads: a database, or a storage area's files. */
  readonly scope: object
  /** @internal The table it reads, if any. */
  readonly table: string | undefined

  /** @internal */
  constructor(bb: BisonBase, run: () => Promise<R[]>, feed: ChangeFeed, scope: object, table: string | undefined, dispose: () => void) {
    this.#bb = bb
    this.#run = run
    this.feed = feed
    this.scope = scope
    this.table = table
    this.#dispose = dispose
    this.#state = bb._active ? LOADING : SIGNED_OUT
  }

  /** For `useSyncExternalStore`. */
  subscribe = (listener: () => void): (() => void) => {
    if (this.#listeners.has(listener)) return () => {}
    // While anything is subscribed, the change stream stays open.
    if (this.#listeners.size === 0) this.feed.retain()
    this.#listeners.add(listener)
    clearTimeout(this.#gc)
    if (this.#stale) void this.#load()
    return () => {
      if (!this.#listeners.delete(listener)) return
      // Keep the rows a little while in case the same query is used again soon.
      if (this.#listeners.size === 0) {
        this.feed.release()
        this.#gc = setTimeout(this.#dispose, 30_000)
        // In Node, don't keep the process alive just for this.
        ;(this.#gc as { unref?: () => void }).unref?.()
      }
    }
  }

  /** For `useSyncExternalStore`. Returns the same object until something changes. */
  getSnapshot = (): QueryState<R> => this.#state

  #set(state: QueryState<R>) {
    this.#state = state
    for (const listener of [...this.#listeners]) listener()
  }

  /** @internal */
  _invalidate() {
    this.#stale = true
    if (this.#listeners.size) void this.#load()
  }

  /** @internal */
  _authChanged() {
    this.#set(this.#bb._active ? LOADING : SIGNED_OUT)
    this._invalidate()
  }

  async #load() {
    if (!this.#bb._active) {
      if (this.#state !== SIGNED_OUT) this.#set(SIGNED_OUT)
      return
    }
    if (this.#running) {
      this.#again = true
      return
    }
    this.#running = true
    try {
      do {
        this.#again = false
        this.#stale = false
        const epoch = this.#bb._epoch
        try {
          const rows = await this.#run()
          if (!this.#again && epoch === this.#bb._epoch) this.#set({ rows, loading: false, error: null })
        } catch (e) {
          if (this.#again || epoch !== this.#bb._epoch) continue
          if (e instanceof NotSignedInError) this.#set(SIGNED_OUT)
          else this.#set({ rows: this.#state.rows, loading: false, error: e as Error })
        }
      } while (this.#again)
    } finally {
      this.#running = false
    }
  }
}

/** What `UserDb` and `AppDb` have in common: tables, set-up, and the change stream. */
export abstract class Database {
  readonly bb: BisonBase
  /** Its path in the folder it was made from, e.g. `todos.db`. */
  readonly name: string
  /** @internal Where the API serves it, relative to `/api/v1/`. */
  readonly _api: string
  #tables = new Map<string, Table<any, any>>()
  #ready: Promise<void> | null = null
  /** @internal The change stream, which reloads live queries on the tables that change. */
  readonly _feed: ChangeFeed

  constructor(bb: BisonBase, name: string, api: string) {
    this.bb = bb
    this.name = name
    this._api = api
    this._feed = new ChangeFeed(
      bb,
      async (signal) => {
        await this._ensure()
        return this.bb._fetch(this._api, 'watch', { method: 'GET', signal })
      },
      (event, data) => {
        // `ready` comes first on every (re)connection: changes may have been missed before it.
        if (event === 'ready') this.bb._invalidate(this)
        else if (event === 'change') this.bb._invalidate(this, data?.tables ?? undefined)
      },
    )
  }

  /** @internal */
  _addTable<C extends Columns, R>(def: TableDef): Table<C, R> {
    checkName('Table', def.name)
    if ([...this.#tables.keys()].some((t) => t.toLowerCase() === def.name.toLowerCase())) {
      throw new Error(`Table "${def.name}" was already created in ${this.name}`)
    }
    const table = new Table<C, R>(this, def)
    this.#tables.set(def.name, table)
    this.#ready = null
    return table
  }

  /** @internal Create the database if need be. */
  protected abstract _create(): Promise<void>

  /** @internal Forget that the schema was set up (the user changed). */
  _reset() {
    this.#ready = null
  }

  /** @internal Create the database and bring its tables up to date, once per sign-in. */
  _ensure(): Promise<void> {
    if (!this.#ready) {
      const ready = this.#setUp()
      this.#ready = ready
      ready.catch(() => {
        if (this.#ready === ready) this.#ready = null // try again next time
      })
    }
    return this.#ready
  }

  async #setUp(): Promise<void> {
    await this._create()
    await this.bb._request(this._api, 'migrate', migrateRequest([...this.#tables.values()].map((t) => t.def)))
  }

  /** @internal Run a relational op once the tables are set up. */
  async _op(op: 'select' | 'insert' | 'update' | 'delete' | 'transact', body: unknown): Promise<any> {
    await this._ensure()
    return this.bb._request(this._api, op, body)
  }

  /**
   * Run several writes to this database's tables in one transaction: all of them take effect,
   * or none do. `build` lists them with `tx`, and the results come back in the same order:
   * the stored row (or rows) for an insert, the number of rows changed for an update or delete.
   *
   * ```ts
   * // Move a task from a private table to a shared one.
   * const [moved] = await db.transact((tx) => [
   *   tx.insert(sharedTasks, { title: task.title }),
   *   tx.delete(myTasks, task.id),
   * ])
   * ```
   */
  async transact<const T extends readonly TxOp<unknown>[]>(build: (tx: Tx) => T): Promise<TxResults<T>> {
    const ops = build(TX) as readonly TxOp<unknown>[]
    const sent: { table: Table<any, any>; body: object }[] = []
    const plan = ops.map((op) => {
      if (!(op instanceof TxOp)) throw new Error('transact: list the writes made with tx.insert, tx.update and tx.delete')
      if (op.table.db !== this) throw new Error(`transact: table "${op.table.name}" isn't in database "${this.name}"`)
      // Nothing to send (no rows to insert, nothing to set): answer it here.
      if (!op.body) return () => op.empty
      const i = sent.push({ table: op.table, body: { op: op.op, ...op.body } }) - 1
      return (results: any[]) => op.decode(results[i])
    })
    const results: any[] = sent.length ? (await this._op('transact', { ops: sent.map((s) => s.body) })).results : []
    if (sent.length) this.bb._invalidate(this, [...new Set(sent.map((s) => s.table.name))])
    return plan.map((get) => get(results)) as TxResults<T>
  }
}

/** One write in a transaction, made with `tx.insert`, `tx.update` or `tx.delete`. */
export class TxOp<V> {
  readonly table: Table<any, any>
  readonly op: 'insert' | 'update' | 'delete'
  /** @internal The request without its `op`, or null when there's nothing to send. */
  readonly body: object | null
  /** @internal Turn the server's result into this op's value. */
  readonly decode: (result: any) => V
  /** @internal The value when nothing was sent. */
  readonly empty: V
  /** Only here so TypeScript tells ops with different results apart. */
  declare readonly _value?: V

  /** @internal Use `tx.insert`, `tx.update` or `tx.delete` in `db.transact`. */
  constructor(table: Table<any, any>, op: TxOp<V>['op'], body: object | null, decode: (result: any) => V, empty: V) {
    this.table = table
    this.op = op
    this.body = body
    this.decode = decode
    this.empty = empty
  }
}

/** Builds the writes of a `transact`. Each method checks its arguments the way the table's own does. */
export interface Tx {
  insert<C extends Columns, R>(table: Table<C, R>, row: InsertFor<C>): TxOp<R>
  insert<C extends Columns, R>(table: Table<C, R>, rows: readonly InsertFor<C>[]): TxOp<R[]>
  update<C extends Columns, R>(table: Table<C, R>, where: Where<R> | number, changes: UpdateFor<C>): TxOp<number>
  delete<C extends Columns, R>(table: Table<C, R>, where: Where<R> | number): TxOp<number>
}

/** What `transact` resolves to: each op's result, in order. */
export type TxResults<T extends readonly TxOp<unknown>[]> = { -readonly [K in keyof T]: T[K] extends TxOp<infer V> ? V : never }

const TX: Tx = {
  insert(table: Table<any, any>, rows: object | readonly object[]): TxOp<any> {
    const many = Array.isArray(rows)
    const req = insertRequest(table.def, (many ? rows : [rows]) as Record<string, unknown>[])
    return new TxOp(table, 'insert', req.rows.length ? req : null, (r: Rows) => {
      const decoded = table._decode(r)
      return many ? decoded : decoded[0]
    }, [])
  },
  update(table: Table<any, any>, where: object | number, changes: object) {
    const req = updateRequest(table.def, where, changes as Record<string, unknown>)
    return new TxOp(table, 'update', req, (r: { changes: number }) => r.changes, 0)
  },
  delete(table: Table<any, any>, where: object | number) {
    if (where === undefined) throw new Error('delete needs a where; pass {} to delete every row')
    return new TxOp(table, 'delete', deleteRequest(table.def, where), (r: { changes: number }) => r.changes, 0)
  },
}

/**
 * A database each signed-in user has their own copy of, in their own account. Make one with
 * `bb.files.db(path)` (or `bb.createUserDb`).
 */
export class UserDb extends Database {
  /** Path within the user's files, e.g. `apps/<appId>/todos.db`. */
  readonly path: string

  /** @internal Use `bb.files.db`. `path` is in the user's files, `name` in the folder. */
  constructor(bb: BisonBase, name: string, path: string, api: string) {
    super(bb, name, api)
    this.path = path
  }

  /**
   * Declare a table. It's created, or new columns are added, the first time it's used after
   * signing in. Every table also has an `id` integer primary key.
   *
   * ```ts
   * const todos = db.createTable("todos", { content: "text", done: ["boolean", false] })
   * ```
   */
  createTable<const C extends Columns>(name: string, columns: C): Table<C> {
    return this._addTable<C, RowFor<C>>(parseTable(name, columns))
  }

  protected async _create() {
    await this.bb._request(this._api, 'mkdb')
  }
}

export interface AppTableOptions {
  /**
   * Who may read the table's rows: `"private"` (the default), only the user who owns each row;
   * `"shared"`, everyone who uses the app. Either way only a row's owner may change or delete it.
   */
  sharing?: Sharing
}

/** A row of an app database's table: its columns, plus `_owner`, the id of the user it belongs to. */
export type OwnedRow<C> = RowFor<C> & { _owner: string }

/**
 * A database in the app's own storage, shared by all its users. Make one with
 * `bb.appFiles.db(path)` (or `bb.createAppDb`).
 */
export class AppDb extends Database {
  /** Path within the app's storage, e.g. `todos.db`. */
  readonly path: string

  /** @internal Use `bb.appFiles.db`. `path` is in the app's storage, `name` in the folder. */
  constructor(bb: BisonBase, name: string, path: string, api: string) {
    super(bb, name, api)
    this.path = path
  }

  /**
   * Declare a table. Like `UserDb.createTable`, but every row also has an `_owner`: the id of
   * the user who inserted it, which the server sets. Only the app's owners can create the table
   * or add columns; for everyone else, the table must already match.
   *
   * ```ts
   * const posts = db.createTable("posts", { body: "text" }, { sharing: "shared" })
   * ```
   */
  createTable<const C extends Columns>(name: string, columns: C, options: AppTableOptions = {}): Table<C, OwnedRow<C>> {
    return this._addTable<C, OwnedRow<C>>(parseTable(name, columns, { sharing: options.sharing ?? 'private' }))
  }

  protected async _create() {
    await this.bb._inAppStorage(() => this.bb._request(this._api, 'mkdb'))
  }
}

/** A table in a database. Make one with `db.createTable`. `R` is the type of its rows. */
export class Table<C extends Columns, R = RowFor<C>> {
  readonly db: Database
  /** @internal */
  readonly def: TableDef

  /** @internal Use `db.createTable`. */
  constructor(db: Database, def: TableDef) {
    this.db = db
    this.def = def
  }

  get name(): string {
    return this.def.name
  }

  /** @internal Rows as the server sends them, decoded. */
  _decode(result: Rows): R[] {
    const types = result.columns.map((c) => (c === 'id' ? null : this.def.byName.get(c)?.type ?? null))
    return result.rows.map(
      (row) => Object.fromEntries(row.map((v, i) => [result.columns[i], types[i] ? decode(types[i], v) : v])) as R,
    )
  }

  /** Fetch rows once. For rows that stay up to date in a component, use `useSelect`. */
  async select(options?: SelectOptions<R>): Promise<R[]> {
    const result: Rows = await this.db._op('select', selectRequest(this.def, options))
    if (result.truncated) console.warn(`BisonBase: results from ${this.name} were truncated by the server's row limit`)
    return this._decode(result)
  }

  /** Insert a row and return it as stored (with its `id` and defaults). */
  insert(row: InsertFor<C>): Promise<R>
  /** Insert several rows in one transaction. */
  insert(rows: readonly InsertFor<C>[]): Promise<R[]>
  async insert(rows: InsertFor<C> | readonly InsertFor<C>[]): Promise<R | R[]> {
    const many = Array.isArray(rows)
    const list = (many ? rows : [rows]) as Record<string, unknown>[]
    const req = insertRequest(this.def, list)
    if (req.rows.length === 0) return []
    const inserted = this._decode(await this.db._op('insert', req))
    this.#changed()
    return many ? inserted : inserted[0]
  }

  /**
   * Change the rows matching `where` (or the row with that id). Returns how many changed.
   * Pass `{}` to change every row.
   */
  async update(where: Where<R> | number, changes: UpdateFor<C>): Promise<number> {
    const req = updateRequest(this.def, where, changes as Record<string, unknown>)
    if (!req) return 0
    const { changes: n } = await this.db._op('update', req)
    this.#changed()
    return n
  }

  /** Delete the rows matching `where` (or the row with that id). Returns how many were deleted. Pass `{}` to delete every row. */
  async delete(where: Where<R> | number): Promise<number> {
    if (where === undefined) throw new Error('delete needs a where; pass {} to delete every row')
    const { changes: n } = await this.db._op('delete', deleteRequest(this.def, where))
    this.#changed()
    return n
  }

  /** Reload live queries on this table now, rather than waiting for the change stream. */
  #changed() {
    this.db.bb._invalidate(this.db, [this.name])
  }

  /** The live query for these options, shared with every other user of the same options. */
  liveQuery(options?: SelectOptions<R>): LiveQuery<R> {
    const key = stableKey(['select', this.db._api, this.name, options ?? {}])
    // Validate now so mistakes throw where the query is written, not later in a fetch.
    selectRequest(this.def, options)
    return this.db.bb._liveQuery(key, () => this.select(options), this.db._feed, this.db, this.name)
  }

  /**
   * React hook: the rows matching `options`, kept up to date. Empty while signed out or
   * loading. Needs `import "bisonbase/react"` somewhere in the app.
   */
  useSelect(options?: SelectOptions<R>): readonly R[] {
    return this.useSelectState(options).rows
  }

  /** React hook: like `useSelect`, plus whether it's loading and the last error. */
  useSelectState(options?: SelectOptions<R>): QueryState<R> {
    return useLiveQuery(this.liveQuery(options), 'useSelect')
  }
}

export { SchemaError }

/** The row type of a table: `type Todo = RowOf<typeof todos>`. */
export type RowOf<T> = T extends Table<any, infer R> ? R : never
/** What a table's `insert` takes. */
export type InsertOf<T> = T extends Table<infer C, any> ? InsertFor<C> : never
