// Small pieces the three views share: who an item is from, the private/shared switch, and
// comments on shared items.

import { useState, type ReactNode } from 'react'
import { comments, useMe } from './data.ts'

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <section className={`rounded-xl border border-line bg-card p-4 ${className}`}>{children}</section>
}

export function Badge({ children, tone = 'muted' }: { children: ReactNode; tone?: 'muted' | 'accent' | 'danger' }) {
  const tones = {
    muted: 'bg-line/60 text-muted',
    accent: 'bg-accent/15 text-accent',
    danger: 'bg-danger/15 text-danger',
  }
  return <span className={`inline-block rounded-full px-2 py-px text-xs whitespace-nowrap ${tones[tone]}`}>{children}</span>
}

/** "Private", or "Shared" with who it's from when that's someone else. */
export function Sharing({ item }: { item: { shared: boolean; _owner: string } }) {
  const me = useMe()
  if (!item.shared) return <Badge>Private</Badge>
  const mine = item._owner === me?.user.id
  return <Badge tone="accent">{mine ? 'Shared' : `Shared by ${me?.names.get(item._owner) ?? 'someone'}`}</Badge>
}

/** Whether the signed-in user owns the item (and so may change it). */
export function useOwns(item: { _owner: string } | null | undefined): boolean {
  const me = useMe()
  return !!item && item._owner === me?.user.id
}

/** A switch between private and shared. */
export function ShareSwitch({ shared, onChange, disabled }: { shared: boolean; onChange(shared: boolean): void; disabled?: boolean }) {
  return (
    <span className="share-switch inline-flex overflow-hidden rounded-md border border-line text-sm" role="group" aria-label="Sharing">
      {(['Private', 'Shared'] as const).map((label) => {
        const on = (label === 'Shared') === shared
        return (
          <button
            key={label}
            type="button"
            disabled={disabled}
            aria-pressed={on}
            className={`rounded-none px-2.5 py-1 ${on ? 'bg-accent text-white' : 'bg-transparent text-fg'} disabled:opacity-50`}
            onClick={() => !on && onChange(label === 'Shared')}
          >
            {label}
          </button>
        )
      })}
    </span>
  )
}

/** Comments on a shared item, identified as e.g. `task:<uid>`. */
export function Comments({ item }: { item: string }) {
  const me = useMe()
  const rows = comments.useSelect({ where: { item }, orderBy: 'at' })
  const [body, setBody] = useState('')
  return (
    <div className="comments mt-3 border-t border-line pt-3">
      <h4 className="mb-2 text-xs font-semibold tracking-wide text-muted uppercase">Comments</h4>
      <ul className="mb-2 space-y-1.5 text-sm">
        {rows.map((c) => (
          <li key={c.id} className="group flex gap-2">
            <span className="font-medium">{me?.names.get(c._owner) ?? 'someone'}</span>
            <span className="flex-1 break-words">{c.body}</span>
            {c._owner === me?.user.id && (
              <button className="bg-transparent p-0 text-xs text-danger opacity-0 group-hover:opacity-100 focus:opacity-100" onClick={() => comments.delete(c.id)}>
                Delete
              </button>
            )}
          </li>
        ))}
        {rows.length === 0 && <li className="text-muted">No comments yet.</li>}
      </ul>
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          if (body.trim()) void comments.insert({ item, body: body.trim(), at: Date.now() })
          setBody('')
        }}
      >
        <input className="min-w-0 flex-1 text-sm" placeholder="Add a comment" value={body} onChange={(e) => setBody(e.target.value)} />
        <button className="text-sm">Post</button>
      </form>
    </div>
  )
}
