// Files: the app's folder in each user's own account (`bb.files`) and the app's own storage on
// the server (`bb.appFiles`). A database is a file in one of them: `folder.db("todos.db")`.

import { ApiError, AppDb, ChangeFeed, LiveQuery, stableKey, useLiveQuery, UserDb, type BisonBase, type Database, type QueryState } from './client.ts'

/** A file or folder, as `list` returns it. */
export interface FileEntry {
  name: string
  /** Its path in the folder that listed it, to pass to `read`, `write`, `delete` and so on. */
  path: string
  type: 'file' | 'dir'
  /** In bytes; 0 for folders. */
  size: number
  /** When it last changed, in milliseconds since 1970 (like `Date.now()`). */
  modified: number
}

/** A file just written. */
export interface WrittenFile extends FileEntry {
  type: 'file'
  /** Its version: pass it as `ifMatch` to write it only if nobody has changed it since. */
  etag: string
}

/** What `write` takes. Strings are written as UTF-8. */
export type FileData = Blob | ArrayBuffer | ArrayBufferView | string

export interface WriteOptions {
  /** Only write if the file is still at this version (`etag`); otherwise fail with a 412 `ApiError`. */
  ifMatch?: string
  /** Only write if there's no file there yet; otherwise fail with a 409 `ApiError`. */
  create?: boolean
}

/** A file's contents and version, as `readFile` returns them. */
export interface ReadFile {
  blob: Blob
  /** Its version; see `WriteOptions.ifMatch`. */
  etag: string
}

/** Which storage area a folder is in. */
type Kind = 'user' | 'app'

/** Split a path into segments, refusing ones that would leave the folder. */
function segments(path: string): string[] {
  const parts = path.split('/').filter((s) => s !== '')
  for (const s of parts) {
    if (s === '.' || s === '..') throw new Error(`Path "${path}" may not contain "." or ".." segments`)
    if (/[\\\0]/.test(s)) throw new Error(`Path "${path}" contains invalid characters`)
  }
  return parts
}

const join = (...paths: string[]) => paths.flatMap(segments).join('/')

/** One change stream and the listings it keeps up to date, per storage area. */
interface Area {
  feeds: Map<string, ChangeFeed>
}
const areas = new WeakMap<BisonBase, Record<Kind, Area>>()

/**
 * A folder of files: `bb.files` (the app's folder in the signed-in user's account), `bb.appFiles`
 * (the app's own storage), or a folder inside one of them (`folder.folder("photos")`). Paths are
 * relative to the folder, with `/` between segments. A database is a file too: `folder.db(path)`.
 *
 * `D` is the kind of database in it: `UserDb` in a user's files, `AppDb` in the app's storage.
 */
export class Folder<D extends Database = Database> {
  readonly bb: BisonBase
  /** Its path in its storage area; `""` for `bb.files` and `bb.appFiles` themselves. */
  readonly path: string
  readonly #kind: Kind

  /** @internal Use `bb.files`, `bb.appFiles` or `folder.folder`. */
  constructor(bb: BisonBase, kind: Kind, path: string) {
    this.bb = bb
    this.#kind = kind
    this.path = path
  }

  /** Where the API serves `path` (relative to this folder), relative to `/api/v1/`. */
  #api(path = ''): string {
    const full = join(this.path, path)
    const prefix = this.#kind === 'user' ? `files/apps/${this.bb.appId}` : `apps/${this.bb.appId}/files`
    return full ? `${prefix}/${full.split('/').map(encodeURIComponent).join('/')}` : prefix
  }

  /** The storage area's state: one shared object per area, which also scopes its live listings. */
  get #area(): Area {
    let a = areas.get(this.bb)
    if (!a) areas.set(this.bb, (a = { user: { feeds: new Map() }, app: { feeds: new Map() } }))
    return a[this.#kind]
  }

  /** Call the API, registering the app first if need be (for the app's storage). */
  #send(path: string, query: Record<string, string | undefined> | string | null, init: Parameters<BisonBase['_send']>[2]) {
    const send = () => this.bb._send(this.#api(path), query, init)
    return this.#kind === 'app' ? this.bb._inAppStorage(send) : send()
  }

  /** Something in this storage area changed here: reload its live listings. */
  #changed() {
    this.bb._invalidate(this.#area)
  }

  /** The folder at `path` inside this one. It needn't exist yet: writing a file in it creates it. */
  folder(path: string): Folder<D> {
    return new Folder(this.bb, this.#kind, join(this.path, path))
  }

  /**
   * The SQLite database at `path`, e.g. `folder.db("todos.db")`. It's created, along with the
   * tables declared on it, the first time it's used after signing in.
   *
   * In a user's files (`bb.files`), only that user can read or change it. In the app's storage
   * (`bb.appFiles`), it's shared by everyone who uses the app, and each row belongs to the user
   * who inserted it; see `AppDb`.
   */
  db(path: string): D {
    const rel = join(this.path, path)
    if (!rel) throw new Error('A database needs a file name')
    const api = this.#api(path)
    const name = join(path)
    return this.bb._db(api, () =>
      this.#kind === 'user'
        ? new UserDb(this.bb, name, `apps/${this.bb.appId}/${rel}`, api)
        : new AppDb(this.bb, name, rel, api),
    ) as unknown as D
  }

  /**
   * The files and folders in the folder at `path` (default: this one), sorted by name. A folder
   * that doesn't exist yet is empty.
   */
  async list(path = ''): Promise<FileEntry[]> {
    let res: Response
    try {
      res = await this.#send(path, null, { method: 'GET' })
    } catch (e) {
      if (e instanceof ApiError && e.code === 'not_found') return []
      throw e
    }
    // A file's contents, if `path` isn't a folder; a folder's listing has `entries`.
    const json = (res.headers.get('content-type') ?? '').startsWith('application/json') ? await res.json() : null
    if (!Array.isArray(json?.entries)) throw new Error(`"${join(this.path, path)}" is a file, not a folder`)
    return (json.entries as { name: string; type: 'file' | 'dir'; size: number; modified: number }[])
      .map((e): FileEntry => ({ name: e.name, path: join(path, e.name), type: e.type, size: e.size, modified: e.modified * 1000 }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  }

  /** The file at `path`, with its version (`etag`). */
  async readFile(path: string): Promise<ReadFile> {
    if (!join(path)) throw new Error('read needs a file path')
    const res = await this.#send(path, null, { method: 'GET' })
    if ((res.headers.get('content-type') ?? '').startsWith('application/json') && !/\.json$/i.test(path)) {
      // A folder's listing, not a file.
      const json = await res.clone().json().catch(() => null)
      if (json && Array.isArray(json.entries)) throw new Error(`"${join(this.path, path)}" is a folder, not a file`)
    }
    return { blob: await res.blob(), etag: res.headers.get('etag') ?? '' }
  }

  /** The contents of the file at `path`. */
  async read(path: string): Promise<Blob> {
    return (await this.readFile(path)).blob
  }

  /** The contents of the file at `path`, as UTF-8 text. */
  async readText(path: string): Promise<string> {
    return (await this.read(path)).text()
  }

  /**
   * Write the file at `path`, replacing it if it exists, and creating the folders it's in if
   * need be. Returns the file as stored, with its new version (`etag`).
   */
  async write(path: string, data: FileData, options: WriteOptions = {}): Promise<WrittenFile> {
    const p = join(path)
    if (!p) throw new Error('write needs a file path')
    const headers: Record<string, string> = {}
    if (options.ifMatch !== undefined) headers['if-match'] = options.ifMatch
    if (options.create) headers['if-none-match'] = '*'
    const raw: BodyInit = typeof data === 'string' ? new TextEncoder().encode(data) : (data as BodyInit)
    const res = await this.#send(path, null, { method: 'PUT', raw, headers })
    const e = await res.json()
    this.#changed()
    return { name: e.name, path: p, type: 'file', size: e.size, modified: e.modified * 1000, etag: res.headers.get('etag') ?? '' }
  }

  /** Create the folder at `path` (and the folders it's in), if it doesn't exist. */
  async mkdir(path: string): Promise<void> {
    await this.#send(path, 'mkdir', { method: 'POST' })
    this.#changed()
  }

  /**
   * Move or rename the file or folder at `from` to `to` (both in this folder). Fails with a 409
   * `ApiError` if something is at `to`, unless `overwrite` is set and it's a file.
   */
  async move(from: string, to: string, options: { overwrite?: boolean } = {}): Promise<void> {
    const dest = join(this.path, to)
    if (!dest) throw new Error('move needs a destination')
    const prefix = this.#kind === 'user' ? `apps/${this.bb.appId}/` : ''
    await this.#send(from, { op: 'move', to: prefix + dest, overwrite: options.overwrite ? 'true' : undefined }, { method: 'POST' })
    this.#changed()
  }

  /**
   * Delete the file or folder at `path`. A folder must be empty, unless `recursive` is set.
   * Deleting a database deletes all of its tables and rows.
   */
  async delete(path: string, options: { recursive?: boolean } = {}): Promise<void> {
    if (!join(this.path, path)) throw new Error('delete needs a path; the folder itself can only be emptied')
    await this.#send(path, { recursive: options.recursive ? 'true' : undefined }, { method: 'DELETE' })
    this.#changed()
  }

  /**
   * The listing of the folder at `path`, kept up to date: it reloads when anything in it is
   * written, moved or deleted, here or elsewhere.
   */
  liveList(path = ''): LiveQuery<FileEntry> {
    const dir = join(this.path, path)
    const area = this.#area
    let feed = area.feeds.get(dir)
    if (!feed) {
      const api = this.#api(path)
      const invalidate = () => this.bb._invalidate(area)
      feed = new ChangeFeed(
        this.bb,
        (signal) => {
          const open = () => this.bb._send(api, 'watch', { method: 'GET', signal })
          return this.#kind === 'app' ? this.bb._inAppStorage(open) : open()
        },
        // `ready` comes first on every (re)connection: changes may have been missed before it.
        (event) => (event === 'ready' || event === 'change') && invalidate(),
      )
      area.feeds.set(dir, feed)
    }
    const key = stableKey(['list', this.#kind, dir, path])
    return this.bb._liveQuery(key, () => this.list(path), feed, area)
  }

  /**
   * React hook: the files and folders in the folder at `path` (default: this one), kept up to
   * date. Empty while signed out or loading. Needs `import "bisonbase/react"` somewhere in the app.
   */
  useList(path = ''): readonly FileEntry[] {
    return this.useListState(path).rows
  }

  /** React hook: like `useList`, plus whether it's loading and the last error. */
  useListState(path = ''): QueryState<FileEntry> {
    return useLiveQuery(this.liveList(path), 'useList')
  }
}
