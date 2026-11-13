// Calls to the server's JSON endpoints, and the shapes of their answers.

import { useCallback, useEffect, useState } from 'react'

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
  }
}

/** Send a logged-out user to the login page, coming back here afterwards. */
export function toLogin() {
  const next = location.pathname + location.search
  location.assign(`/login?next=${encodeURIComponent(next)}`)
}

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { credentials: 'same-origin', ...init })
  const data = await res.json().catch(() => ({}))
  if (res.status === 401 && url.startsWith('/ui/')) {
    toLogin()
    throw new ApiError('Your session ended; log in again.', 401)
  }
  if (!res.ok) throw new ApiError(data?.error?.message || `HTTP ${res.status}`, res.status)
  return data as T
}

/** A query string from the params that are set. */
export function query(params: Record<string, string | number | null | undefined>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v != null) q.set(k, String(v))
  const s = q.toString()
  return s ? `?${s}` : ''
}

export const get = <T>(url: string) => call<T>(url)

export const post = <T = { ok: true }>(url: string, body: unknown) =>
  call<T>(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

export const postForm = <T>(url: string, body: FormData) => call<T>(url, { method: 'POST', body })

export interface Loaded<T> {
  data: T | undefined
  error: string | undefined
  /** Fetch again, keeping the current data on screen meanwhile. */
  reload: () => void
  /** Replace the data locally, e.g. after an edit the server answered with. */
  setData: (d: T) => void
}

/** GET `url` (none: nothing yet) and re-fetch when it changes. */
export function useApi<T>(url: string | null): Loaded<T> {
  const [state, setState] = useState<{ url: string; data?: T; error?: string }>()
  const [n, setN] = useState(0)
  useEffect(() => {
    if (!url) return
    let live = true
    get<T>(url).then(
      (data) => live && setState({ url, data }),
      (e: Error) => live && setState({ url, error: e.message }),
    )
    return () => {
      live = false
    }
  }, [url, n])
  const current = state?.url === url ? state : undefined
  const reload = useCallback(() => setN((n) => n + 1), [])
  const setData = useCallback((data: T) => url && setState({ url, data }), [url])
  return { data: current?.data, error: current?.error, reload, setData }
}

// ---- response shapes ----

export interface Me {
  id: string
  username: string
  is_admin: boolean
}

export interface Session {
  user: Me | null
  signup_open: boolean
}

export interface AppLabel {
  name: string
  hue: number
}

export interface ListEntry {
  name: string
  kind: 'dir' | 'db' | 'file'
  size: number
  modified: number
}

/** A registered app's own storage, as the viewer sees it. */
export interface AppView {
  id: string
  name: string
  hue: number
  /** The viewer may change the app's storage. */
  manage: boolean
}

interface BrowseBase {
  owner: { id: string; username: string }
  editable: boolean
  path: string
  apps: Record<string, AppLabel>
  /** Set in an app's storage. */
  app: AppView | null
  /** The viewer sees only database rows they own here. */
  rows_only: boolean
}

export interface DirNode {
  kind: 'dir'
  entries: ListEntry[]
  usage: number
  quota: number
}

export interface DbNode {
  kind: 'db'
  size: number
  modified: number
}

export interface FileNode {
  kind: 'file'
  size: number
  modified: number
  mime: string
  is_image: boolean
  text: string | null
  truncated: boolean
  editable: boolean
  etag: string
  crlf: boolean
}

export type Browse = BrowseBase & (DirNode | DbNode | FileNode)

export interface Column {
  name: string
  decl_type: string
  not_null: boolean
  default: string | null
  pk: boolean
  generated: boolean
}

export interface TableSchema {
  name: string
  kind: 'table' | 'view'
  columns: Column[]
}

export interface CellEdit {
  col: number
  name: string
  kind: 'null' | 'integer' | 'real' | 'text'
  affinity: string
  full: string | null
}

export interface Cell {
  text: string
  class: '' | 'null' | 'num'
  edit?: CellEdit
}

export interface GridRow {
  key: string | null
  version: string
  cells: Cell[]
}

export interface TableView {
  name: string
  columns: string[]
  can_insert: boolean
  can_edit: boolean
  can_delete: boolean
  rows: GridRow[]
  page: number
  more: boolean
}

export interface Preview {
  name: string
  columns: string[]
  rows: Cell[][]
  more: boolean
  error: string | null
}

export interface DbView {
  tables: TableSchema[]
  writable: boolean
  table: TableView | null
  error: string | null
  previews: Preview[]
  previews_omitted: number
}

export interface Field {
  name: string
  info: string
  editable: boolean
  kind: string
  affinity: string
  value: string
  multiline: boolean
  too_large: boolean
  options: [string, string][]
}

export interface RowForm {
  key: string | null
  version: string
  fields: Field[]
}

export interface ConsoleResult {
  tables: TableSchema[]
  message: string | null
  error: string | null
  result: { columns: string[]; rows: Cell[][]; truncated: boolean } | null
}

export interface EditResult {
  message: string
  row: GridRow | null
}

export interface Settings {
  passkeys: { id: number; name: string; created: number; last_used: number | null }[]
  tokens: { id: number; name: string; scopes: string; created: number; expires: number | null; last_used: number | null }[]
  apps: {
    app_id: string
    name: string
    hue: number
    folder: string
    client_id: string
    permissions: string[]
    authorized: number
    last_used: number | null
  }[]
  origin: string
}

export interface AdminData {
  signup_mode: 'open' | 'invite' | 'closed'
  invites: {
    id: number
    note: string
    grants_admin: boolean
    created: number
    expires: number
    used_at: number | null
    used_by: string | null
    active: boolean
  }[]
  users: { id: string; username: string; is_admin: boolean; is_self: boolean; created: number }[]
}

export interface RegisteredApp {
  id: string
  name: string
  origin: string
  hue: number
  created: number
  manage: boolean
  /** Only for admins. */
  owners?: { id: string; username: string }[]
  /** Only for those who manage the app. */
  usage?: number
  quota: number
}

export interface Consent {
  username: string
  app_name: string
  app_id: string
  hue: number
  folder: string
  origin: string
  local: boolean
  permissions: string[]
  client_id: string
  redirect_uri: string
  scope: string
  state: string
  code_challenge: string
}
