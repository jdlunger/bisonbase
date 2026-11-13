// Formatting and URL helpers.

export function fmtSize(n: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return i === 0 ? `${n} B` : `${v.toFixed(1)} ${units[i]}`
}

const pad = (n: number) => String(n).padStart(2, '0')

/** A Unix time as `2026-01-31 14:05 UTC`. */
export function fmtTime(t: number | null | undefined, never = 'never'): string {
  if (t == null) return never
  const d = new Date(t * 1000)
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
}

/** A file path (`a/b c`) as URL path segments (`a/b%20c`). */
export const encodePath = (p: string) => p.split('/').filter(Boolean).map(encodeURIComponent).join('/')

/** URL path segments back to a file path. */
export function decodePath(p: string): string {
  try {
    return p.split('/').filter(Boolean).map(decodeURIComponent).join('/')
  } catch {
    return p
  }
}

/**
 * Which file tree a page shows: the viewer's own (both null), another user's (`owner`, for
 * admins), or a registered app's own storage (`app`).
 */
export interface Tree {
  owner: string | null
  app: string | null
}

export const OWN_TREE: Tree = { owner: null, app: null }
export const userTree = (owner: string | null): Tree => ({ owner, app: null })
export const appTree = (app: string): Tree => ({ owner: null, app })

/** Where a file tree's pages live. */
export function treeBase(t: Tree): string {
  if (t.app) return `/apps/${t.app}/files`
  return t.owner ? `/admin/users/${t.owner}/files` : '/files'
}

export function treeHref(t: Tree, path: string): string {
  const base = treeBase(t)
  return path ? `${base}/${encodePath(path)}` : base
}

export function rawHref(t: Tree, path: string): string {
  const base = t.app ? `/apps/${t.app}/raw` : t.owner ? `/admin/users/${t.owner}/raw` : '/raw'
  return `${base}/${encodePath(path)}`
}

/** The API path of a file in a tree (as apps use it). */
export function apiPath(t: Tree, path: string): string {
  return t.app ? `/api/v1/apps/${t.app}/files/${path}` : `/api/v1/files/${path}`
}

/** The id of the app whose folder `path` is (`apps/<uuid>`), if it is one. */
export function appFolderId(path: string): string | null {
  const m = /^apps\/([0-9a-f-]{36})$/.exec(path)
  return m ? m[1] : null
}

export const quoteIdent = (s: string) => `"${s.replace(/"/g, '""')}"`
