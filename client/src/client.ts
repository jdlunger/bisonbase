// The client: BisonBase (sign-in and the connection to the server), UserDb (one SQLite file
// per user) and Table (typed select / insert / update / delete, plus live queries that the
// server keeps up to date).

import { revoke, startSignIn, takeSignInResponse } from './auth.ts'
import { deleteRequest, insertRequest, selectRequest, updateRequest } from './ops.ts'
import { migrateRequest, SchemaError } from './schema.ts'
import { checkName, parseTable, type TableDef } from './table.ts'
import type { Columns, InsertFor, RowFor, SelectOptions, UpdateFor, Where, Wire } from './types.ts'
import { decode } from './values.ts'
import { watch } from './watch.ts'

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

/** Rows as the server sends them: column names, then values in wire form. */
interface Rows {
  columns: string[]
  rows: Wire[][]
  truncated?: boolean
}

/** The state of a live query, as `useSelectState` returns it. */
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

/** JSON with object keys sorted, so equal options give equal cache keys. */
function stableKey(value: unknown): string {
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
  #dbs = new Map<string, UserDb>()
  #queries = new Map<string, LiveQuery<any>>()

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
    return startSignIn({ server: this.url, appId: this.appId, appName: this.appName, scope: 'db:write' })
  }

  /** Forget the token here and revoke it on the server. */
  async signOut(): Promise<void> {
    const token = this.#token
    this.#setToken(null)
    if (token && this.#persist) await revoke(this.url, token)
  }

  /**
   * A database that each user gets their own copy of, stored as `apps/<appId>/<name>.db`
   * in their account. Only that user can read or change it.
   */
  createUserDb(name: string): UserDb {
    if (!/^[A-Za-z0-9_-]+$/.test(name)) throw new Error(`Database name "${name}" must be letters, digits, "_" and "-"`)
    if (this.#dbs.has(name)) throw new Error(`Database "${name}" was already created`)
    const db = new UserDb(this, name)
    this.#dbs.set(name, db)
    return db
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
    for (const q of this.#queries.values()) q._authChanged()
  }

  #refreshAll() {
    for (const q of this.#queries.values()) if (!q.table.db._live) q._invalidate()
  }

  /** @internal A cached live query, shared by everything that asks for the same rows. */
  _liveQuery<R>(key: string, run: () => Promise<R[]>, table: Table<any>): LiveQuery<R> {
    let q = this.#queries.get(key)
    if (!q) {
      q = new LiveQuery(this, run, table, () => this.#queries.delete(key))
      this.#queries.set(key, q)
    }
    return q
  }

  /**
   * @internal Mark live queries on `tables` of `db` (by name, or every table) stale, and reload
   * the ones in use.
   */
  _invalidate(db: UserDb, tables?: readonly string[]) {
    const names = tables && new Set(tables.map((t) => t.toLowerCase()))
    for (const q of this.#queries.values()) {
      if (q.table.db === db && (!names || names.has(q.table.name.toLowerCase()))) q._invalidate()
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

  /** @internal POST an op to the files API, after any pending sign-in. */
  async _request(path: string, op: string, body?: unknown): Promise<any> {
    const res = await this._fetch(path, op, { method: 'POST', body })
    const json = await res.json().catch(() => ({}))
    if (!res.ok) {
      const code = json.error?.code ?? 'unknown'
      const message = json.error?.message ?? res.statusText
      if (code === 'schema_mismatch') throw new SchemaError(`${path}: ${message}`)
      throw new ApiError(res.status, code, message)
    }
    return json
  }

  /** @internal Call the files API with the token, signing out if the server rejects it. */
  async _fetch(path: string, op: string, init: { method: string; body?: unknown; signal?: AbortSignal }): Promise<Response> {
    await this.#settled
    const token = this.#token
    if (!token) throw new NotSignedInError()
    const headers: Record<string, string> = { authorization: `Bearer ${token}` }
    if (init.body !== undefined) headers['content-type'] = 'application/json'
    const res = await fetch(`${this.url}/api/v1/files/${path}?op=${op}`, {
      method: init.method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: init.signal,
    })
    if (res.status === 401 && this.#token === token) this.#setToken(null, EXPIRED)
    return res
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
  readonly table: Table<any>

  constructor(bb: BisonBase, run: () => Promise<R[]>, table: Table<any>, dispose: () => void) {
    this.#bb = bb
    this.#run = run
    this.table = table
    this.#dispose = dispose
    this.#state = bb._active ? LOADING : SIGNED_OUT
  }

  /** For `useSyncExternalStore`. */
  subscribe = (listener: () => void): (() => void) => {
    if (this.#listeners.has(listener)) return () => {}
    // While anything is subscribed, the database's change stream stays open.
    if (this.#listeners.size === 0) this.table.db._retain()
    this.#listeners.add(listener)
    clearTimeout(this.#gc)
    if (this.#stale) void this.#load()
    return () => {
      if (!this.#listeners.delete(listener)) return
      // Keep the rows a little while in case the same query is used again soon.
      if (this.#listeners.size === 0) {
        this.table.db._release()
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

/** A database each signed-in user has their own copy of. Make one with `bb.createUserDb`. */
export class UserDb {
  readonly bb: BisonBase
  readonly name: string
  /** Path within the user's files, e.g. `apps/<appId>/todos.db`. */
  readonly path: string
  #tables = new Map<string, Table<any>>()
  #ready: Promise<void> | null = null
  /** How many live queries on this database are in use. */
  #watchers = 0
  #stopWatch: (() => void) | null = null
  /** @internal Whether the change stream is connected. */
  _live = false

  /** @internal Use `bb.createUserDb`. */
  constructor(bb: BisonBase, name: string) {
    this.bb = bb
    this.name = name
    this.path = `apps/${bb.appId}/${name}.db`
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
    checkName('Table', name)
    if ([...this.#tables.keys()].some((t) => t.toLowerCase() === name.toLowerCase())) {
      throw new Error(`Table "${name}" was already created in ${this.name}`)
    }
    const table = new Table<C>(this, parseTable(name, columns))
    this.#tables.set(name, table)
    this.#ready = null
    return table
  }

  /** @internal Forget that the schema was set up, and reconnect the change stream (the user changed). */
  _reset() {
    this.#ready = null
    this.#unwatch()
    if (this.#watchers > 0) this.#watch()
  }

  /** @internal A live query on this database is in use. */
  _retain() {
    if (this.#watchers++ === 0) this.#watch()
  }

  /** @internal A live query on this database is no longer in use. */
  _release() {
    if (--this.#watchers === 0) this.#unwatch()
  }

  /** Follow the server's change stream, reloading live queries on the tables that change. */
  #watch() {
    if (this.#stopWatch || !this.bb._active) return
    const stop = watch({
      open: async (signal) => {
        await this._ensure()
        return this.bb._fetch(this.path, 'watch', { method: 'GET', signal })
      },
      // Signed out, or the tables can't be set up: retrying won't help.
      fatal: (e) => e instanceof NotSignedInError || e instanceof SchemaError,
      onEvent: (event, data) => {
        // `ready` comes first on every (re)connection: changes may have been missed before it.
        if (event === 'ready') this.bb._invalidate(this)
        else if (event === 'change') {
          const tables = (data as { tables?: string[] | null }).tables
          this.bb._invalidate(this, tables ?? undefined)
        }
      },
      onLive: (live) => {
        // A stream that was already stopped may report late; only the current one counts.
        if (this.#stopWatch === stop) this._live = live
      },
    })
    this.#stopWatch = stop
  }

  #unwatch() {
    this.#stopWatch?.()
    this.#stopWatch = null
    this._live = false
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
    await this.bb._request(this.path, 'mkdb')
    await this.bb._request(this.path, 'migrate', migrateRequest([...this.#tables.values()].map((t) => t.def)))
  }

  /** @internal Run a relational op once the tables are set up. */
  async _op(op: 'select' | 'insert' | 'update' | 'delete', body: unknown): Promise<any> {
    await this._ensure()
    return this.bb._request(this.path, op, body)
  }
}

/** A table in a database. Make one with `db.createTable`. */
export class Table<C extends Columns> {
  readonly db: UserDb
  /** @internal */
  readonly def: TableDef

  /** @internal Use `db.createTable`. */
  constructor(db: UserDb, def: TableDef) {
    this.db = db
    this.def = def
  }

  get name(): string {
    return this.def.name
  }

  #rows(result: Rows): RowFor<C>[] {
    const types = result.columns.map((c) => (c === 'id' ? null : this.def.byName.get(c)?.type ?? null))
    return result.rows.map(
      (row) => Object.fromEntries(row.map((v, i) => [result.columns[i], types[i] ? decode(types[i], v) : v])) as RowFor<C>,
    )
  }

  /** Fetch rows once. For rows that stay up to date in a component, use `useSelect`. */
  async select(options?: SelectOptions<RowFor<C>>): Promise<RowFor<C>[]> {
    const result: Rows = await this.db._op('select', selectRequest(this.def, options))
    if (result.truncated) console.warn(`BisonBase: results from ${this.name} were truncated by the server's row limit`)
    return this.#rows(result)
  }

  /** Insert a row and return it as stored (with its `id` and defaults). */
  insert(row: InsertFor<C>): Promise<RowFor<C>>
  /** Insert several rows in one transaction. */
  insert(rows: readonly InsertFor<C>[]): Promise<RowFor<C>[]>
  async insert(rows: InsertFor<C> | readonly InsertFor<C>[]): Promise<RowFor<C> | RowFor<C>[]> {
    const many = Array.isArray(rows)
    const list = (many ? rows : [rows]) as Record<string, unknown>[]
    const req = insertRequest(this.def, list)
    if (req.rows.length === 0) return []
    const inserted = this.#rows(await this.db._op('insert', req))
    this.#changed()
    return many ? inserted : inserted[0]
  }

  /**
   * Change the rows matching `where` (or the row with that id). Returns how many changed.
   * Pass `{}` to change every row.
   */
  async update(where: Where<RowFor<C>> | number, changes: UpdateFor<C>): Promise<number> {
    const req = updateRequest(this.def, where, changes as Record<string, unknown>)
    if (!req) return 0
    const { changes: n } = await this.db._op('update', req)
    this.#changed()
    return n
  }

  /** Delete the rows matching `where` (or the row with that id). Returns how many were deleted. Pass `{}` to delete every row. */
  async delete(where: Where<RowFor<C>> | number): Promise<number> {
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
  liveQuery(options?: SelectOptions<RowFor<C>>): LiveQuery<RowFor<C>> {
    const key = stableKey([this.db.name, this.name, options ?? {}])
    // Validate now so mistakes throw where the query is written, not later in a fetch.
    selectRequest(this.def, options)
    return this.db.bb._liveQuery(key, () => this.select(options), this)
  }

  /**
   * React hook: the rows matching `options`, kept up to date. Empty while signed out or
   * loading. Needs `import "bisonbase/react"` somewhere in the app.
   */
  useSelect(options?: SelectOptions<RowFor<C>>): readonly RowFor<C>[] {
    return this.useSelectState(options).rows
  }

  /** React hook: like `useSelect`, plus whether it's loading and the last error. */
  useSelectState(options?: SelectOptions<RowFor<C>>): QueryState<RowFor<C>> {
    if (!hooks) throw new Error('useSelect needs React: add `import "bisonbase/react"` to your app')
    return hooks.useQuery(this.liveQuery(options))
  }
}

export { SchemaError }

/** The row type of a table: `type Todo = RowOf<typeof todos>`. */
export type RowOf<T> = T extends Table<infer C> ? RowFor<C> : never
/** What a table's `insert` takes. */
export type InsertOf<T> = T extends Table<infer C> ? InsertFor<C> : never
