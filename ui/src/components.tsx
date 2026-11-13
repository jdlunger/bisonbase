// Pieces shared by the pages: the header, flash messages, copyable paths, app labels.

import { useEffect, useRef, useState, useSyncExternalStore, type ButtonHTMLAttributes, type CSSProperties, type MouseEvent, type ReactNode } from 'react'
import type { AppLabel, Me } from './api.ts'
import { Link, useHref } from './router.tsx'

// ---- flash messages ----

interface FlashMsg {
  kind: 'ok' | 'err' | 'note'
  text: string
  /** The page it belongs to; navigating away hides it. */
  href: string
}

let flashed: FlashMsg | null = null
const flashListeners = new Set<() => void>()

/** Show a message on the page at `href` (default: this one). */
export function flash(kind: FlashMsg['kind'], text: string, href = location.pathname + location.search) {
  flashed = { kind, text, href }
  flashListeners.forEach((f) => f())
}

/** Run `fn`, showing any error it throws as a flash message. */
export async function act(fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn()
  } catch (e) {
    flash('err', (e as Error).message)
  }
}

/** The current flash message, and `?msg=` / `?err=` from the URL. */
export function Flash() {
  const href = useHref()
  const f = useSyncExternalStore(
    (cb) => {
      flashListeners.add(cb)
      return () => flashListeners.delete(cb)
    },
    () => flashed,
  )
  const q = new URLSearchParams(location.search)
  const msg = q.get('msg')
  const err = q.get('err')
  return (
    <>
      {msg && <Note kind="ok">{msg}</Note>}
      {err && <Note kind="err">{err}</Note>}
      {f && f.href === href && <Note kind={f.kind}>{f.text}</Note>}
    </>
  )
}

// ---- layout ----

const noteBg = { ok: 'bg-ok', err: 'bg-err', note: 'bg-code' }

/** A message box; `ok`/`err`/`note` pick its color. */
export function Note({ kind, children }: { kind: FlashMsg['kind']; children: ReactNode }) {
  return (
    <div role={kind === 'err' ? 'alert' : undefined} className={`mb-3 rounded-md px-3 py-2 ${noteBg[kind]}`}>
      {children}
    </div>
  )
}

export function Card({ narrow, className = '', children }: { narrow?: boolean; className?: string; children: ReactNode }) {
  const width = narrow ? 'mx-auto my-12 max-w-100' : 'mb-5'
  return <section className={`rounded-xl border border-line bg-card px-5 py-4 ${width} ${className}`}>{children}</section>
}

/** A button that looks like a link. */
export function TextButton({ danger, className = '', ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { danger?: boolean }) {
  return <button type="button" className={`bg-transparent p-0 ${danger ? 'text-danger' : 'text-accent'} ${className}`} {...rest} />
}

/** For links that look like buttons. */
export const buttonLink = 'inline-block rounded-md bg-accent px-2.5 py-1.5 text-white hover:no-underline'

/** A form's row of inputs and buttons. */
export const toolbar = 'mb-3 flex flex-wrap items-center gap-3'

/** A table of things (passkeys, files, …) with actions in the last column. */
export const listTable =
  'w-full border border-line bg-card [&_td]:px-3 [&_td]:py-1.5 [&_th]:px-3 [&_th]:py-1.5 [&_th]:text-left [&_th]:text-[13px] [&_th]:font-semibold [&_th]:text-muted [&_tbody_tr]:border-t [&_tbody_tr]:border-line'

/** The last column of a listTable. */
export const actionsCell = 'text-right whitespace-nowrap [&>*]:ml-3'

/** A form field's label with its input below. */
export const labelBlock = 'block [&>input]:mt-1 [&>input]:w-full'


export type Section = 'files' | 'apps' | 'settings' | 'admin' | ''

export function Header({ user, section }: { user: Me | null; section: Section }) {
  return (
    <header className="flex items-center gap-6 border-b border-line bg-card px-4 py-2.5">
      <Link className="font-bold text-fg" href="/">
        bisonbase
      </Link>
      {user && (
        <>
          <nav className="flex gap-4">
            <Link href="/files" className={navCls(section === 'files')}>
              Files
            </Link>
            <Link href="/apps" className={navCls(section === 'apps')}>
              Apps
            </Link>
            <Link href="/settings" className={navCls(section === 'settings')}>
              Settings
            </Link>
            {user.is_admin && (
              <Link href="/admin" className={navCls(section === 'admin')}>
                Admin
              </Link>
            )}
          </nav>
          <form method="post" action="/logout" className="ml-auto flex items-center gap-2">
            <span className="text-muted">{user.username}</span>
            <TextButton type="submit">Log out</TextButton>
          </form>
        </>
      )}
    </header>
  )
}

const navCls = (active: boolean) => (active ? 'font-semibold text-fg' : 'text-muted')

export function useTitle(title: string | undefined) {
  useEffect(() => {
    document.title = title ? `${title} · bisonbase` : 'bisonbase'
  }, [title])
}

export function Loading({ error }: { error?: string }) {
  return error ? <Note kind="err">{error}</Note> : <p className="text-muted">Loading…</p>
}

export function ErrorPage({ status, message }: { status: number; message: string }) {
  useTitle(`Error ${status}`)
  return (
    <>
      <h1>Error {status}</h1>
      <p>{message}</p>
      <p>
        <a href="#" onClick={(e) => (e.preventDefault(), history.back())}>
          Go back
        </a>{' '}
        · <Link href="/">Home</Link>
      </p>
    </>
  )
}

// ---- small things ----

export function AppTag({ app }: { app: AppLabel }) {
  return (
    <span
      className="inline-block rounded-full border border-[hsl(var(--hue)_55%_78%)] bg-[hsl(var(--hue)_75%_91%)] px-2 align-[1px] text-[13px] leading-5 font-semibold whitespace-nowrap text-[hsl(var(--hue)_65%_28%)] dark:border-[hsl(var(--hue)_35%_34%)] dark:bg-[hsl(var(--hue)_35%_22%)] dark:text-[hsl(var(--hue)_80%_82%)]"
      style={{ '--hue': app.hue } as CSSProperties}
    >
      {app.name}
    </span>
  )
}

async function copyText(text: string) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text)
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.append(ta)
  ta.select()
  const ok = document.execCommand('copy')
  ta.remove()
  if (!ok) throw new Error('copy failed')
}

/** Its children, with a Copy button for `text` shown on hover. */
export function Copyable({ text, children }: { text: string; children: ReactNode }) {
  const [label, setLabel] = useState('Copy')
  const timer = useRef<number>(undefined)
  useEffect(() => () => clearTimeout(timer.current), [])
  const copy = async (e: MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    try {
      await copyText(text)
      setLabel('Copied')
    } catch {
      setLabel("Couldn't copy")
    }
    clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setLabel('Copy'), 1500)
  }
  return (
    <span className="group relative">
      {children}
      <button
        type="button"
        className="invisible absolute top-1/2 left-full z-10 ml-2 -translate-y-1/2 rounded-[5px] border border-line bg-card px-[7px] py-0 text-[11px] leading-[18px] font-medium whitespace-nowrap text-muted group-focus-within:visible group-hover:visible hover:border-accent hover:text-accent [@media(hover:none)]:visible"
        title={`Copy ${text}`} aria-label={`Copy ${text}`} onClick={copy}>
        {label}
      </button>
    </span>
  )
}

/** The status line under a passkey form. */
export function Status({ text, error }: { text: string; error: boolean }) {
  return (
    <p id="status" className={`min-h-[1.5em] ${error ? 'err text-danger' : 'text-muted'}`}>
      {text}
    </p>
  )
}

/** A one-time secret (token or link), shown once right after it is created. */
export function Secret({ label, value }: { label: string; value: string }) {
  return (
    <Note kind="ok">
      {label}
      <pre className="token mt-1.5 break-all whitespace-pre-wrap select-all">{value}</pre>
    </Note>
  )
}
