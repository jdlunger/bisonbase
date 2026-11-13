// Everything the workspace stores, and the few helpers that write it. Tasks, events and notes
// can each be private or shared: every kind has two tables with the same columns, one private
// (users only see their own rows) and one shared (everyone sees every row, only its owner may
// change it). Making an item shared or private moves it between them in one transaction.

import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { BisonBase, type AppInfo, type Columns, type InsertFor, type OwnedRow, type Table } from 'bisonbase'
import { useAuth } from 'bisonbase/react'

declare const BISONBASE_URL: string // filled in by server.ts

export const bb = new BisonBase('456bec2e-774f-48b3-9383-ef569b648739', 'Workspace', { url: BISONBASE_URL })

// ---- the app's own storage: one database, shared by everyone who uses the app ----

export const db = bb.createAppDb('workspace')

/** A private table and a shared one with the same columns. */
function privateAndShared<const C extends Columns>(name: string, columns: C) {
  return {
    mine: db.createTable(name, columns),
    shared: db.createTable(`shared_${name}`, columns, { sharing: 'shared' }),
  }
}
type Pair<C extends Columns> = { mine: Table<C, OwnedRow<C>>; shared: Table<C, OwnedRow<C>> }

// `uid` stays the same when an item moves between its private and shared tables (its `id`
// doesn't), so comments and RSVPs refer to items by it.
export const tasks = privateAndShared('tasks', {
  uid: 'text',
  title: 'text',
  details: ['text', ''],
  done: ['boolean', false],
  priority: ['integer', 2], // 1 high, 2 normal, 3 low
  due: 'text?', // YYYY-MM-DD, so ranges compare as text
  tags: ['json', []],
  estimate: 'real?', // hours
})

export const events = privateAndShared('events', {
  uid: 'text',
  title: 'text',
  start: 'integer', // ms since the epoch
  end: 'integer',
  all_day: ['boolean', false],
  location: 'text?',
})

export const notes = privateAndShared('notes', {
  uid: 'text',
  title: 'text',
  body: ['text', ''],
  pinned: ['boolean', false],
  updated: 'integer',
  attachment: 'blob?',
  attachment_name: 'text?',
  attachment_type: 'text?',
})

/** Everyone who has used the workspace, so shared items can show who they're from. */
export const members = db.createTable('members', { username: 'text', joined: 'integer' }, { sharing: 'shared' })

/** Comments on shared items. Anyone may comment; only the author can delete a comment. */
export const comments = db.createTable('comments', { item: 'text', body: 'text', at: 'integer' }, { sharing: 'shared' })

/** Each user's answer to a shared event: one row per user and event, which only they can change. */
export const rsvps = db.createTable('rsvps', { event: 'text', answer: 'text' }, { sharing: 'shared' })

// ---- the user's own account: a database only they can read ----

/** Preferences that follow the user from device to device. */
export const prefs = bb.createUserDb('workspace').createTable('prefs', {
  tab: ['text', 'tasks'],
  show_done: ['boolean', true],
  week_starts_monday: ['boolean', false],
})

// ---- types ----

type RowOfPair<P> = P extends Pair<infer C> ? OwnedRow<C> : never
/** A row, and whether it's in the shared table. */
export type Item<P> = RowOfPair<P> & { shared: boolean }
export type Task = Item<typeof tasks>
export type CalEvent = Item<typeof events>
export type Note = Item<typeof notes>
export type Kind = 'task' | 'event' | 'note'

// ---- helpers ----

/** Rows from both of a pair's tables, kept up to date. */
export function useItems<C extends Columns>(pair: Pair<C>, options: Parameters<Table<C, OwnedRow<C>>['useSelect']>[0] = {}) {
  const mine = pair.mine.useSelectState(options)
  const shared = pair.shared.useSelectState(options)
  const rows = useMemo(() => {
    // Right after an item moves, one table may have reloaded before the other: show it once.
    const byUid = new Map<unknown, OwnedRow<C> & { shared: boolean }>()
    for (const r of shared.rows) byUid.set(r.uid, { ...r, shared: true })
    for (const r of mine.rows) if (!byUid.has(r.uid)) byUid.set(r.uid, { ...r, shared: false })
    return [...byUid.values()]
  }, [mine.rows, shared.rows])
  return { rows, loading: mine.loading || shared.loading, error: mine.error ?? shared.error }
}

/** The table an item is in. */
export function tableOf<C extends Columns>(pair: Pair<C>, item: { shared: boolean }) {
  return item.shared ? pair.shared : pair.mine
}

/** Make an item shared or private: delete it from one table and insert it in the other, atomically. */
export async function setShared<C extends Columns>(pair: Pair<C>, item: OwnedRow<C> & { shared: boolean }, shared: boolean) {
  if (item.shared === shared) return
  const [from, to] = shared ? [pair.mine, pair.shared] : [pair.shared, pair.mine]
  const { id, _owner, shared: _, ...columns } = item
  await db.transact((tx) => [tx.delete(from, id), tx.insert(to, columns as unknown as InsertFor<C>)])
}

/** Add a row to a pair's private or shared table. */
export function add<C extends Columns>(pair: Pair<C>, shared: boolean, row: InsertFor<C>) {
  return (shared ? pair.shared : pair.mine).insert(row)
}

export const newUid = () => crypto.randomUUID()

// ---- who's signed in ----

export interface Me extends AppInfo {
  /** Usernames by user id, from `members`. */
  names: Map<string, string>
}

export const MeContext = createContext<Me | null>(null)

/** The signed-in user, or null while signed out or loading. */
export function useMe(): Me | null {
  return useContext(MeContext)
}

/** Load the signed-in user, and add them to `members` (or update their name). */
export function useLoadMe(): Me | null {
  const auth = useAuth()
  const [info, setInfo] = useState<AppInfo | null>(null)
  const memberRows = members.useSelect()
  useEffect(() => {
    if (auth.status !== 'signed-in') {
      setInfo(null)
      return
    }
    let current = true
    void (async () => {
      // Using the database first sets it up, and registers the app if need be (when an admin
      // signs in): appInfo needs the app registered.
      await members.select({ limit: 1 })
      const me = await bb.appInfo()
      if (!current) return
      setInfo(me)
      // An update only ever reaches the user's own rows, even with `{}` for "every row":
      // so this renames the user's member row, if they have one.
      if ((await members.update({}, { username: me.user.username })) === 0) {
        await members.insert({ username: me.user.username, joined: Date.now() })
      }
    })().catch((e) => console.error('Loading the signed-in user failed:', e))
    return () => {
      current = false
    }
  }, [auth.status])
  return useMemo(() => {
    if (!info) return null
    const names = new Map(memberRows.map((m) => [m._owner, m.username]))
    names.set(info.user.id, info.user.username)
    return { ...info, names }
  }, [info, memberRows])
}

/** The user's preferences, and a function that changes them. */
export function usePrefs() {
  const rows = prefs.useSelect({ limit: 1 })
  const current = rows[0] ?? { id: 0, tab: 'tasks', show_done: true, week_starts_monday: false }
  const set = async (changes: Partial<Omit<typeof current, 'id'>>) => {
    if (rows[0]) await prefs.update(rows[0].id, changes)
    else await prefs.insert({ ...changes })
  }
  return [current, set] as const
}

// ---- formatting ----

export const pad = (n: number) => String(n).padStart(2, '0')
/** A local date as YYYY-MM-DD. */
export const isoDate = (d: Date) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
export const today = () => isoDate(new Date())
export const time = (ms: number) => new Date(ms).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
export const shortDate = (d: string | number) =>
  (typeof d === 'number' ? new Date(d) : new Date(`${d}T00:00`)).toLocaleDateString([], { month: 'short', day: 'numeric' })
