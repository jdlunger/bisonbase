// Notes: a list and an editor that saves as you type. A note can carry a small attachment,
// stored in the row itself as a blob.

import { useEffect, useMemo, useRef, useState } from 'react'
import { add, newUid, notes, setShared, shortDate, tableOf, time, useItems, type Note } from './data.ts'
import { Card, Comments, ShareSwitch, Sharing, useOwns } from './ui.tsx'

const MAX_ATTACHMENT = 256 * 1024

export function Notes() {
  const { rows, loading } = useItems(notes, { orderBy: 'updated desc' })
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const q = search.trim().toLowerCase()
  const list = rows
    .filter((n) => !q || n.title.toLowerCase().includes(q) || n.body.toLowerCase().includes(q))
    .sort((a, b) => +b.pinned - +a.pinned || b.updated - a.updated)
  const note = rows.find((n) => n.uid === selected) ?? null

  const create = async () => {
    const uid = newUid()
    await add(notes, false, { uid, title: 'Untitled', updated: Date.now() })
    setSelected(uid)
  }

  return (
    <div className="grid gap-4 md:grid-cols-[16rem_1fr]">
      <Card className="p-2">
        <div className="mb-2 flex gap-2 p-1">
          <input className="min-w-0 flex-1 text-sm" placeholder="Search notes" value={search} onChange={(e) => setSearch(e.target.value)} />
          <button onClick={() => void create()}>New</button>
        </div>
        <ul id="notes" className="space-y-0.5">
          {list.map((n) => (
            <li key={n.uid}>
              <button data-uid={n.uid}
                className={`w-full rounded-md px-2 py-1.5 text-left text-fg ${n.uid === selected ? 'bg-accent/10' : 'bg-transparent hover:bg-line/40'}`}
                onClick={() => setSelected(n.uid)}>
                <span className="title block truncate font-medium">{n.pinned && '📌 '}{n.title || 'Untitled'}</span>
                <span className="flex items-center gap-1.5 text-xs text-muted">
                  {shortDate(n.updated)} <Sharing item={n} />
                </span>
              </button>
            </li>
          ))}
          {!loading && list.length === 0 && <li className="empty p-2 text-sm text-muted">{q ? 'No matching notes.' : 'No notes yet.'}</li>}
        </ul>
      </Card>
      <Card>
        {note ? <Editor key={note.uid} note={note} onDeleted={() => setSelected(null)} /> : <p className="text-muted">Pick a note, or make a new one.</p>}
      </Card>
    </div>
  )
}

function Editor({ note, onDeleted }: { note: Note; onDeleted(): void }) {
  const owns = useOwns(note)
  const [title, setTitle] = useState(note.title)
  const [body, setBody] = useState(note.body)
  const [status, setStatus] = useState<'saved' | 'editing' | 'saving'>('saved')
  // The row can move (made shared or private) or change while the editor is open.
  const latest = useRef(note)
  latest.current = note

  // Show changes made elsewhere, unless the user is in the middle of editing.
  useEffect(() => {
    if (status !== 'saved') return
    setTitle(note.title)
    setBody(note.body)
  }, [note.title, note.body])

  // Save a moment after typing stops.
  useEffect(() => {
    if (status !== 'editing') return
    const t = setTimeout(async () => {
      setStatus('saving')
      const n = latest.current
      await tableOf(notes, n).update(n.id, { title, body, updated: Date.now() })
      setStatus('saved')
    }, 500)
    return () => clearTimeout(t)
  }, [title, body, status])

  const edit = <T,>(set: (v: T) => void) => (v: T) => {
    set(v)
    setStatus('editing')
  }

  return (
    <div className="editor space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <input className="min-w-0 flex-1 text-lg font-semibold" aria-label="Title" readOnly={!owns} value={title}
          onChange={(e) => edit(setTitle)(e.target.value)} />
        {owns && (
          <button className={note.pinned ? '' : 'bg-line/60 text-fg'} onClick={() => void tableOf(notes, note).update(note.id, { pinned: !note.pinned })}>
            {note.pinned ? 'Pinned' : 'Pin'}
          </button>
        )}
      </div>
      <p className="flex flex-wrap items-center gap-2 text-xs text-muted">
        <Sharing item={note} />
        <span>Edited {shortDate(note.updated)}, {time(note.updated)}</span>
        {owns && <span className="status">{status === 'saved' ? 'Saved' : 'Saving…'}</span>}
      </p>
      <textarea className="min-h-60 w-full rounded-md border border-line bg-card px-2.5 py-1.5 leading-relaxed" aria-label="Body"
        readOnly={!owns} placeholder={owns ? 'Write something…' : ''} value={body} onChange={(e) => edit(setBody)(e.target.value)} />
      <Attachment note={note} owns={owns} />
      {owns && (
        <div className="flex items-center gap-2">
          <ShareSwitch shared={note.shared} onChange={(s) => void setShared(notes, note, s)} />
          <button className="ml-auto bg-transparent px-1.5 text-danger" onClick={async () => {
            if (!confirm(`Delete "${note.title}"?`)) return
            await tableOf(notes, note).delete(note.id)
            onDeleted()
          }}>Delete note</button>
        </div>
      )}
      {note.shared && <Comments item={`note:${note.uid}`} />}
    </div>
  )
}

function Attachment({ note, owns }: { note: Note; owns: boolean }) {
  const [error, setError] = useState('')
  const url = useMemo(
    () => (note.attachment ? URL.createObjectURL(new Blob([note.attachment as Uint8Array<ArrayBuffer>], { type: note.attachment_type ?? '' })) : null),
    [note.attachment, note.attachment_type],
  )
  useEffect(() => () => void (url && URL.revokeObjectURL(url)), [url])
  const table = tableOf(notes, note)

  return (
    <div className="attachment text-sm">
      {url && (
        <div className="mb-2 flex flex-wrap items-center gap-2">
          {note.attachment_type?.startsWith('image/') && <img src={url} alt="" className="max-h-40 rounded-md border border-line" />}
          <a href={url} download={note.attachment_name ?? 'attachment'}>{note.attachment_name}</a>
          <span className="text-muted">{Math.ceil((note.attachment?.length ?? 0) / 1024)} KB</span>
          {owns && (
            <button className="bg-transparent px-1.5 text-danger" onClick={() => void table.update(note.id, { attachment: null, attachment_name: null, attachment_type: null })}>
              Remove
            </button>
          )}
        </div>
      )}
      {owns && !url && (
        <label className="cursor-pointer text-accent">
          Attach a file…
          <input type="file" className="hidden" onChange={async (e) => {
            const file = e.target.files?.[0]
            e.target.value = ''
            if (!file) return
            if (file.size > MAX_ATTACHMENT) return setError(`Attachments can be up to ${MAX_ATTACHMENT / 1024} KB.`)
            setError('')
            await table.update(note.id, {
              attachment: new Uint8Array(await file.arrayBuffer()),
              attachment_name: file.name,
              attachment_type: file.type || null,
              updated: Date.now(),
            })
          }} />
        </label>
      )}
      {error && <p className="text-danger">{error}</p>}
    </div>
  )
}
