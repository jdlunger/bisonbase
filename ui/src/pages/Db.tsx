// Database view and editor: tables, paged rows, a row form, editing cells in place, and a SQL
// console. Used for SQLite files in a user's tree and, for admins, system.db. Which table, page
// and row are shown is in the URL (?table=, &page=, &edit=<key> or &insert=1).

import { useEffect, useLayoutEffect, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import {
  post,
  query,
  useApi,
  type Cell,
  type CellEdit,
  type ConsoleResult,
  type DbView,
  type EditResult,
  type GridRow,
  type RowForm,
  type TableView,
} from '../api.ts'
import { act, buttonLink, flash, Loading, Note, TextButton, toolbar, useTitle } from '../components.tsx'
import { fmtSize, quoteIdent, rawHref } from '../format.ts'
import { Link, navigate, useHref } from '../router.tsx'
import { ApiPath } from './Files.tsx'

type Source = { kind: 'file'; owner: string | null; path: string } | { kind: 'system' }

/** A database file in a user's tree. */
export function FileDb({ owner, path, size }: { owner: string | null; path: string; size: number }) {
  return (
    <>
      <div className={toolbar}>
        <a className={buttonLink} href={rawHref(owner, path)}>
          Download
        </a>
        <span className="text-muted">{fmtSize(size)} · SQLite database</span>
      </div>
      <ApiPath path={path} />
      <Browser src={{ kind: 'file', owner, path }} />
    </>
  )
}

export function SystemDb() {
  useTitle('system.db')
  return (
    <>
      <nav className="mt-1 mb-3 text-base">
        <Link href="/admin">Admin</Link> / <Link href="/admin/db">System database</Link>
        <TableCrumb />
      </nav>
      <Note kind="note">
        Only some columns can be edited, and every change is recorded in audit_log. The console is read-only.
      </Note>
      <div className={toolbar}>
        <span className="text-muted">System database</span>
      </div>
      <Browser src={{ kind: 'system' }} />
    </>
  )
}

/** " / <table>" after the crumbs, when a table is open. */
export function TableCrumb() {
  useHref()
  const t = new URLSearchParams(location.search).get('table')
  return t ? <> / {t}</> : null
}

/** Where to fetch and post for a source. */
function endpoints(src: Source) {
  const base = src.kind === 'system' ? '/ui/sysdb' : '/ui/db'
  const where = src.kind === 'system' ? {} : { path: src.path, owner: src.owner }
  return {
    view: (table: string | null, page: number) => `${base}${query({ ...where, table, page: page || null })}`,
    form: (table: string, key: string | null) => `${base}/row${query({ ...where, table, key })}`,
    row: `${base}/row`,
    sql: `${base}/sql`,
    /** Fields every post carries. */
    body: src.kind === 'system' ? {} : { path: src.path, owner: src.owner },
  }
}

function Browser({ src }: { src: Source }) {
  const href = useHref()
  // Everything below starts over on another table, page or row.
  return <BrowserAt key={href} src={src} />
}

function BrowserAt({ src }: { src: Source }) {
  const q = new URLSearchParams(location.search)
  const table = q.get('table')
  const page = Math.max(0, Number(q.get('page')) || 0)
  const edit = q.get('edit')
  const insert = q.has('insert')
  const api = endpoints(src)
  const v = useApi<DbView>(api.view(table, page))
  const [result, setResult] = useState<ConsoleResult | null>(null)

  const base = location.pathname
  const tableHref = (t: string, p = 0) => `${base}?table=${encodeURIComponent(t)}${p > 0 ? `&page=${p}` : ''}`

  if (!v.data) return <Loading error={v.error} />
  const d = v.data
  const t = d.table
  const here = t ? tableHref(t.name, page) : base
  const showForm = t && (edit != null || (insert && t.can_insert))

  return (
    <div className="grid gap-5 md:grid-cols-[240px_1fr]">
      <aside>
        <h3 className="text-sm tracking-wide text-muted uppercase">Tables</h3>
        <ul>
          {d.tables.map((s) => (
            <li key={s.name}>
              <details open={s.name === table}>
                <summary>
                  <Link href={tableHref(s.name)}>{s.name}</Link>
                  {s.kind === 'view' && <span className="text-muted"> (view)</span>}
                </summary>
                <ul className="my-0 pl-[18px] text-[13px]">
                  {s.columns.map((c) => (
                    <li key={c.name}>
                      {c.name}{' '}
                      <span className="text-muted">
                        {c.decl_type}
                        {c.pk && ' PK'}
                        {c.not_null && ' NOT NULL'}
                        {c.generated && ' GENERATED'}
                      </span>
                    </li>
                  ))}
                </ul>
              </details>
            </li>
          ))}
          {d.tables.length === 0 && <li className="text-muted">No tables.</li>}
        </ul>
      </aside>
      <section className="min-w-0">
        {showForm && <RowEditor src={src} table={t.name} rowKey={edit} done={here} />}
        <Console
          src={src}
          initial={table ? `SELECT * FROM ${quoteIdent(table)} LIMIT 100;` : ''}
          writable={d.writable}
          onResult={(r) => {
            setResult(r)
            v.setData({ ...d, tables: r.tables })
          }}
        />
        {result ? (
          <>
            {result.message && <Note kind="ok">{result.message}</Note>}
            {result.error && <Note kind="err">{result.error}</Note>}
            {result.result && (
              <>
                <Grid columns={result.result.columns} rows={result.result.rows} />
                {result.result.truncated && <p className="text-muted">Result truncated.</p>}
              </>
            )}
          </>
        ) : (
          <>
            {d.error && <Note kind="err">{d.error}</Note>}
            {t && (
              <TableRows
                src={src}
                table={t}
                editHref={(key) => `${here}&edit=${encodeURIComponent(key)}`}
                setTable={(table) => v.setData({ ...d, table })}
                reload={v.reload}
              />
            )}
            {t && (page > 0 || t.more) && (
              <p className="flex items-center gap-4">
                {page > 0 && <Link href={tableHref(t.name, page - 1)}>← Prev</Link>}
                <span className="text-muted">Page {page + 1}</span>
                {t.more && <Link href={tableHref(t.name, page + 1)}>Next →</Link>}
              </p>
            )}
            {t?.can_insert && !showForm && (
              <p>
                <Link className={buttonLink} href={`${here}&insert=1`}>
                  + Insert row
                </Link>
              </p>
            )}
            {d.previews.map((p) => (
              <div className="mt-5" key={p.name}>
                <h3>
                  <Link href={tableHref(p.name)}>{p.name}</Link>{' '}
                  <span className="text-[13px] font-normal text-muted">
                    {p.more ? `first ${p.rows.length} rows` : `${p.rows.length} row${p.rows.length === 1 ? '' : 's'}`}
                  </span>
                </h3>
                {p.error ? <Note kind="err">{p.error}</Note> : <Grid columns={p.columns} rows={p.rows} />}
              </div>
            ))}
            {d.previews_omitted > 0 && (
              <p className="text-muted">
                {d.previews_omitted} more table{d.previews_omitted === 1 ? '' : 's'} not shown.
              </p>
            )}
          </>
        )}
      </section>
    </div>
  )
}

// ---- console ----

function Console({
  src,
  initial,
  writable,
  onResult,
}: {
  src: Source
  initial: string
  writable: boolean
  onResult: (r: ConsoleResult) => void
}) {
  const [sql, setSql] = useState(initial)
  const [busy, setBusy] = useState(false)
  const form = useRef<HTMLFormElement>(null)
  const api = endpoints(src)
  const run = (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    act(async () => onResult(await post<ConsoleResult>(api.sql, { ...api.body, sql }))).finally(() => setBusy(false))
  }
  const keys = (e: KeyboardEvent) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      form.current?.requestSubmit()
    }
  }
  return (
    <form className="mb-3" ref={form} onSubmit={run}>
      <textarea
        className="w-full resize-y"
        name="sql"
        rows={6}
        spellCheck={false}
        placeholder="SELECT * FROM ..."
        value={sql}
        onChange={(e) => setSql(e.target.value)}
        onKeyDown={keys}
      />
      <div className="mt-2">
        <button type="submit" disabled={busy}>
          Run (Ctrl+Enter)
        </button>
        {!writable && <span className="text-muted"> Read-only console</span>}
      </div>
    </form>
  )
}

const gridWrap = 'mb-3 max-h-[70vh] overflow-auto rounded-lg border border-line bg-card'
const grid =
  'my-0! w-full text-[13px] [&_td,&_th]:max-w-100 [&_td,&_th]:overflow-hidden [&_td,&_th]:border-r [&_td,&_th]:border-b [&_td,&_th]:border-line [&_td,&_th]:px-2.5 [&_td,&_th]:py-1 [&_td,&_th]:text-ellipsis [&_td,&_th]:whitespace-nowrap [&_th]:sticky [&_th]:top-0 [&_th]:bg-code [&_th]:text-left'

/** The server's cell classes. */
const cellCls = (c: Cell) => ({ null: 'text-muted italic', num: 'text-right' })[c.class as string] ?? ''

/** A read-only grid of cells. */
function Grid({ columns, rows }: { columns: string[]; rows: Cell[][] }) {
  return (
    <div className={gridWrap}>
      <table className={grid}>
        <thead>
          <tr>
            {columns.map((c, i) => (
              <th key={i}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {row.map((c, j) => (
                <td key={j} className={cellCls(c)}>
                  {c.text}
                </td>
              ))}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length || 1} className="text-muted">
                No rows.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

// ---- a table's rows ----

/** The type to send for a value typed into a cell whose current type is `kind`. */
function inlineType(kind: CellEdit['kind'], affinity: string, value: string): string {
  const base = kind === 'null' ? affinity : kind
  const v = value.trim()
  if (base === 'integer' || base === 'real') {
    if (/^[-+]?\d+$/.test(v)) return base
    if (v !== '' && Number.isFinite(Number(v))) return 'real'
  }
  return 'text'
}

function TableRows({
  src,
  table: t,
  editHref,
  setTable,
  reload,
}: {
  src: Source
  table: TableView
  editHref: (key: string) => string
  setTable: (t: TableView) => void
  reload: () => void
}) {
  const api = endpoints(src)
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null)
  const actions = t.can_edit || t.can_delete

  const saveCell = async (i: number, c: CellEdit, value: string): Promise<boolean> => {
    const row = t.rows[i]
    try {
      const r = await post<EditResult>(api.row, {
        ...api.body,
        table: t.name,
        action: 'update',
        key: row.key,
        version: row.version,
        values: [{ name: c.name, type: inlineType(c.kind, c.affinity, value), value }],
      })
      if (r.row) setTable({ ...t, rows: t.rows.map((x, j) => (j === i ? r.row! : x)) })
      setStatus({ ok: true, text: `${c.name}: ${r.message}` })
      return true
    } catch (e) {
      setStatus({ ok: false, text: `${c.name}: ${(e as Error).message}` })
      return false
    }
  }

  const remove = (row: GridRow) =>
    confirm('Delete this row?') &&
    act(async () => {
      const r = await post<EditResult>(api.row, {
        ...api.body,
        table: t.name,
        action: 'delete',
        key: row.key,
        version: row.version,
      })
      flash('ok', r.message)
      reload()
    })

  return (
    <>
      {status && <Note kind={status.ok ? 'ok' : 'err'}>{status.text}</Note>}
      <div className={gridWrap}>
        <table className={grid}>
          <thead>
            <tr>
              {actions && <th></th>}
              {t.columns.map((c, i) => (
                <th key={i}>{c}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {t.rows.map((row, i) => (
              <tr key={i}>
                {actions && (
                  <td className="[&>*]:mr-2">
                    {row.key != null && t.can_edit && (
                      <Link href={editHref(row.key)}>
                        Edit
                      </Link>
                    )}
                    {row.key != null && t.can_delete && (
                      <TextButton danger onClick={() => remove(row)}>
                        Delete
                      </TextButton>
                    )}
                  </td>
                )}
                {row.cells.map((c, j) =>
                  c.edit && row.key != null ? (
                    <EditableCell key={j} cell={c} edit={c.edit} save={(value) => saveCell(i, c.edit!, value)} />
                  ) : (
                    <td key={j} className={cellCls(c)}>
                      {c.text}
                    </td>
                  ),
                )}
              </tr>
            ))}
            {t.rows.length === 0 && (
              <tr>
                <td colSpan={t.columns.length + 1} className="text-muted">
                  No rows.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}

/**
 * A cell edited in place: double-click (or Enter/F2 when focused) to edit. Enter or leaving the
 * field saves, Escape cancels, Shift+Enter inserts a newline (turning the input into a
 * multi-line box). A failed save keeps the editor open so the value isn't lost.
 */
function EditableCell({ cell, edit, save }: { cell: Cell; edit: CellEdit; save: (value: string) => Promise<boolean> }) {
  const original = edit.full ?? (edit.kind === 'null' ? '' : cell.text)
  const [editing, setEditing] = useState(false)
  const [value, setValue] = useState(original)
  const [multi, setMulti] = useState(false)
  const [state, setState] = useState<'editing' | 'saving' | 'failed'>('editing')
  const td = useRef<HTMLTableCellElement>(null)
  const editor = useRef<HTMLInputElement & HTMLTextAreaElement>(null)
  const width = useRef(0)
  /** Set while the input is swapped for a textarea, whose blur must not save. */
  const swapping = useRef<number | null>(null)
  const wasEditing = useRef(false)

  const start = () => {
    width.current = td.current?.offsetWidth ?? 0
    setValue(original)
    setMulti(original.includes('\n'))
    setState('editing')
    setEditing(true)
  }
  const close = () => setEditing(false)

  // Focus the editor when it appears (or is swapped), and the cell again when it closes.
  useLayoutEffect(() => {
    if (editing) {
      const el = editor.current
      if (!el) return
      el.focus()
      const at = swapping.current ?? el.value.length
      el.selectionStart = el.selectionEnd = at
      swapping.current = null
    } else if (wasEditing.current) {
      td.current?.focus()
    }
    wasEditing.current = editing
  }, [editing, multi])

  const commit = async () => {
    if (state === 'saving') return
    if (value === original) return close()
    setState('saving')
    if (await save(value)) close()
    else {
      setState('failed')
      editor.current?.focus()
    }
  }

  const keys = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      close()
    } else if (e.key === 'Enter' && e.shiftKey) {
      if (!multi) {
        e.preventDefault()
        const el = editor.current!
        const a = el.selectionStart ?? value.length
        const b = el.selectionEnd ?? a
        swapping.current = a + 1
        setValue(value.slice(0, a) + '\n' + value.slice(b))
        setMulti(true)
      } // in a textarea, Shift+Enter is just a newline
    } else if (e.key === 'Enter' && !e.nativeEvent.isComposing) {
      e.preventDefault()
      commit()
    }
  }

  if (!editing) {
    return (
      <td
        ref={td}
        className={`${cellCls(cell)} cursor-text hover:bg-code focus:outline-2 focus:-outline-offset-2 focus:outline-accent`}
        title="Double-click to edit"
        tabIndex={0}
        onDoubleClick={start}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === 'F2') {
            e.preventDefault()
            start()
          }
        }}
      >
        {cell.text}
      </td>
    )
  }
  const props = {
    ref: editor,
    className: `block w-full resize-y px-1.5 py-0.5 font-mono text-[13px] ${state === 'failed' ? 'border-danger' : ''}`,
    value,
    spellCheck: false,
    readOnly: state === 'saving',
    style: { minWidth: Math.max(width.current, multi ? 280 : 120) },
    onChange: (e: { target: { value: string } }) => setValue(e.target.value),
    onKeyDown: keys,
    onBlur: () => {
      if (swapping.current == null && state === 'editing') commit()
    },
  }
  return (
    <td ref={td} className="max-w-none! overflow-visible! p-0.5! whitespace-normal!">
      {multi ? <textarea {...props} rows={Math.min(12, Math.max(3, value.split('\n').length + 1))} /> : <input {...props} />}
    </td>
  )
}

// ---- row form ----

function RowEditor({ src, table, rowKey, done }: { src: Source; table: string; rowKey: string | null; done: string }) {
  const api = endpoints(src)
  const f = useApi<RowForm>(api.form(table, rowKey))
  const [values, setValues] = useState<{ kind: string; value: string }[] | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (f.data) setValues(f.data.fields.map((x) => ({ kind: x.kind, value: x.value })))
  }, [f.data])

  if (!f.data || !values) return <Loading error={f.error} />
  const form = f.data
  const insert = form.key == null

  const set = (i: number, v: Partial<{ kind: string; value: string }>) =>
    setValues(values.map((x, j) => (j === i ? { ...x, ...v } : x)))

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    act(async () => {
      const r = await post<EditResult>(api.row, {
        ...api.body,
        table,
        action: insert ? 'insert' : 'update',
        key: form.key,
        version: form.version,
        values: form.fields.flatMap((x, i) => (x.editable ? [{ name: x.name, type: values[i].kind, value: values[i].value }] : [])),
      })
      flash('ok', r.message, done)
      navigate(done)
    }).finally(() => setBusy(false))
  }

  return (
    <form className="mb-5 rounded-xl border border-line bg-card px-5 py-4" onSubmit={submit}>
      <h3 className="text-base">
        {insert ? 'New row' : 'Edit row'} <span className="text-muted">in {table}</span>
      </h3>
      <table className="w-full [&_td]:py-1.5 [&_td]:pr-2 [&_td]:align-top">
        <tbody>
          {form.fields.map((x, i) => {
            const { kind, value } = values[i]
            const unused = kind === 'null' || kind === 'default'
            // Typing into a field set to default or NULL switches it to the column's type.
            const type = (v: string) => set(i, { value: v, ...(unused ? { kind: x.affinity } : {}) })
            return (
              <tr key={x.name}>
                <th className="w-[22%] py-1.5 pr-3 text-left align-top font-semibold">
                  <label htmlFor={`v${i}`}>{x.name}</label>
                  <div className="text-xs font-normal text-muted">{x.info}</div>
                </th>
                {x.editable ? (
                  <>
                    <td className="w-36">
                      <select name={`t${i}`} value={kind} onChange={(e) => set(i, { kind: e.target.value })}>
                        {x.options.map(([v, label]) => (
                          <option key={v} value={v}>
                            {label}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      {x.too_large ? (
                        <span className="text-muted">{value}</span>
                      ) : x.multiline ? (
                        <textarea
                          id={`v${i}`}
                          name={`v${i}`}
                          rows={4}
                          spellCheck={false}
                          className={`w-full resize-y ${unused ? 'opacity-45' : ''}`}
                          value={value}
                          onChange={(e) => type(e.target.value)}
                        />
                      ) : (
                        <input
                          id={`v${i}`}
                          name={`v${i}`}
                          spellCheck={false}
                          autoComplete="off"
                          className={`w-full resize-y ${unused ? 'opacity-45' : ''}`}
                          value={value}
                          onChange={(e) => type(e.target.value)}
                        />
                      )}
                    </td>
                  </>
                ) : (
                  <>
                    <td className="w-36 text-muted">read-only</td>
                    <td>
                      <span className={kind === 'null' ? 'text-muted italic' : undefined}>{kind === 'null' ? 'NULL' : value}</span>
                    </td>
                  </>
                )}
              </tr>
            )
          })}
        </tbody>
      </table>
      <div className={toolbar}>
        <button type="submit" disabled={busy}>
          {insert ? 'Insert' : 'Save'}
        </button>
        <Link href={done}>Cancel</Link>
      </div>
    </form>
  )
}
