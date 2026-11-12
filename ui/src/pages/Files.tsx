// A user's file tree: folders, text and image files, and (through Db.tsx) databases. Users
// change their own tree; admins can look at anyone's, read-only.

import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent, type ReactNode } from 'react'
import { post, postForm, query, useApi, type Browse, type DirNode, type FileNode, type ListEntry } from '../api.ts'
import { act, actionsCell, AppTag, buttonLink, Copyable, flash, listTable, Loading, Note, TextButton, toolbar, useTitle } from '../components.tsx'
import { appFolderId, fmtSize, fmtTime, rawHref, treeBase, treeHref } from '../format.ts'
import { Link, navigate } from '../router.tsx'
import { FileDb, TableCrumb } from './Db.tsx'

/** Whose tree: null for the viewer's own. */
type Owner = string | null

const browseUrl = (owner: Owner, path: string) => `/ui/files${query({ path, owner })}`

export function Files({ owner, path }: { owner: Owner; path: string }) {
  const b = useApi<Browse>(browseUrl(owner, path))
  useTitle(path.split('/').pop() || 'Files')
  if (!b.data) return <Loading error={b.error} />
  const d = b.data
  return (
    <>
      <Crumbs browse={d} owner={owner} after={d.kind === 'db' && <TableCrumb />} />
      {owner && <Note kind="note">Viewing {d.owner.username}'s files as an admin (read-only).</Note>}
      {d.kind === 'dir' && <Dir browse={d} owner={owner} reload={b.reload} />}
      {d.kind === 'file' && <File browse={d} owner={owner} />}
      {d.kind === 'db' && <FileDb owner={owner} path={d.path} size={d.size} />}
    </>
  )
}

/** The path to a page, each part a link; app folders show the app's name. */
export function Crumbs({ browse, owner, after }: { browse: Browse; owner: Owner; after?: ReactNode }) {
  const parts = browse.path ? browse.path.split('/') : []
  const crumbs: { name: ReactNode; href: string; title?: string }[] = [
    { name: owner ? `${browse.owner.username}'s files` : 'Files', href: treeBase(owner), title: '/' },
  ]
  parts.forEach((name, i) => {
    const p = parts.slice(0, i + 1).join('/')
    const app = appFolderId(p)
    const label = app && browse.apps[app]
    crumbs.push({ name: label ? <AppTag app={label} /> : name, href: treeHref(owner, p), title: `/${p}` })
  })
  const links = crumbs.map((c, i) => (
    <span key={c.href}>
      {i > 0 && ' / '}
      <Link href={c.href} title={c.title}>
        {c.name}
      </Link>
    </span>
  ))
  return (
    <nav className="mt-1 mb-3 text-base">
      {owner && (
        <>
          <Link href="/admin">Admin</Link> /{' '}
        </>
      )}
      {parts.length ? <Copyable text={`/${browse.path}`}>{links}</Copyable> : <span>{links}</span>}
      {after}
    </nav>
  )
}

/** Shown under the crumbs of files and databases. */
export function ApiPath({ path }: { path: string }) {
  const p = `/api/v1/files/${path}`
  return (
    <p className="text-muted">
      API path:{' '}
      <Copyable text={p}>
        <code>{p}</code>
      </Copyable>
    </p>
  )
}

// ---- folders ----

function Dir({ browse, owner, reload }: { browse: Browse & DirNode; owner: Owner; reload: () => void }) {
  const dir = browse.path
  const [dragging, setDragging] = useState(false)
  const [name, setName] = useState('')
  const [kind, setKind] = useState('folder')
  const fileInput = useRef<HTMLInputElement>(null)
  // Bumped after every change, so expanded folders re-fetch too.
  const [version, setVersion] = useState(0)
  const changed = () => {
    reload()
    setVersion((v) => v + 1)
  }

  const upload = (files: FileList | null) => {
    if (!files?.length) return
    act(async () => {
      const body = new FormData()
      body.append('dir', dir)
      for (const f of files) body.append('file', f)
      try {
        const r = await postForm<{ count: number }>('/ui/upload', body)
        flash('ok', `Uploaded ${r.count} file(s)`)
      } finally {
        if (fileInput.current) fileInput.current.value = ''
        changed()
      }
    })
  }

  // Drag-and-drop anywhere on the page uploads into this folder.
  useEffect(() => {
    if (!browse.editable) return
    const over = (e: DragEvent) => {
      e.preventDefault()
      setDragging(true)
    }
    const leave = (e: DragEvent) => !e.relatedTarget && setDragging(false)
    const drop = (e: DragEvent) => {
      e.preventDefault()
      setDragging(false)
      upload(e.dataTransfer?.files ?? null)
    }
    window.addEventListener('dragover', over)
    window.addEventListener('dragleave', leave)
    window.addEventListener('drop', drop)
    return () => {
      window.removeEventListener('dragover', over)
      window.removeEventListener('dragleave', leave)
      window.removeEventListener('drop', drop)
    }
  })

  const create = (e: FormEvent) => {
    e.preventDefault()
    act(async () => {
      const r = await post<{ path: string }>('/ui/new', { dir, name, kind })
      setName('')
      if (kind === 'folder') changed()
      else navigate(treeHref(owner, r.path))
    })
  }

  const usage = (
    <span className="ml-auto text-muted">
      {fmtSize(browse.usage)} of {fmtSize(browse.quota)} used
    </span>
  )
  return (
    <>
      {browse.editable ? (
        <>
          <div className={toolbar}>
            <form
              className="flex gap-2"
              id="upload-form"
              onSubmit={(e) => {
                e.preventDefault()
                upload(fileInput.current?.files ?? null)
              }}
            >
              <input type="file" name="file" multiple required ref={fileInput} />
              <button type="submit">Upload</button>
            </form>
            <form className="flex gap-2" onSubmit={create}>
              <input name="name" placeholder="Name" required value={name} onChange={(e) => setName(e.target.value)} />
              <select name="kind" value={kind} onChange={(e) => setKind(e.target.value)}>
                <option value="folder">Folder</option>
                <option value="text">Text file</option>
                <option value="sqlite">SQLite database</option>
              </select>
              <button type="submit">Create</button>
            </form>
            {usage}
          </div>
          {dragging && <div className="mb-3 rounded-xl border-2 border-dashed border-accent p-8 text-center text-accent">Drop files here to upload</div>}
        </>
      ) : (
        <div className={toolbar}>{usage}</div>
      )}
      <table className={listTable}>
        <thead>
          <tr>
            <th>Name</th>
            <th className="text-right!">Size</th>
            <th>Modified</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <Rows listing={browse} owner={owner} depth={0} version={version} changed={changed} />
        </tbody>
      </table>
    </>
  )
}

interface RowsProps {
  listing: Browse & DirNode
  owner: Owner
  depth: number
  /** Changes when the tree changed. */
  version: number
  changed: () => void
}

function Rows(props: RowsProps) {
  const { listing } = props
  if (listing.entries.length === 0) {
    return (
      <tr>
        <td colSpan={4} className="text-muted" style={indent(props.depth)}>
          This folder is empty.
        </td>
      </tr>
    )
  }
  return (
    <>
      {listing.entries.map((e) => (
        <Row key={e.name} entry={e} {...props} />
      ))}
    </>
  )
}

/** Nested rows' left padding. */
const indent = (depth: number) => ({ paddingLeft: 12 + depth * 20 })

const expand = 'inline-block w-[18px] text-muted!'

const icons = { dir: '📁', db: '🗄️', file: '📄' }

/** A folder's row can expand to show its entries right below it. */
function Row({ entry: e, listing, owner, depth, version, changed }: RowsProps & { entry: ListEntry }) {
  const path = listing.path ? `${listing.path}/${e.name}` : e.name
  const app = appFolderId(path)
  const label = app ? listing.apps[app] : undefined
  const [expanded, setExpanded] = useState(false)
  const [children, setChildren] = useState<(Browse & DirNode) | { error: string } | null>(null)

  useEffect(() => {
    if (!expanded) return
    let live = true
    fetch(browseUrl(owner, path), { credentials: 'same-origin' })
      .then(async (r) => {
        if (r.status === 401) return location.reload()
        const data = await r.json()
        if (!r.ok) throw new Error(data?.error?.message || `HTTP ${r.status}`)
        if (live) setChildren(data)
      })
      .catch((err: Error) => live && setChildren({ error: `Couldn't open this folder (${err.message}).` }))
    return () => {
      live = false
    }
  }, [expanded, version, owner, path])

  const rename = () => {
    const name = prompt('New name', e.name)
    if (!name || name === e.name) return
    act(async () => {
      await post('/ui/rename', { path, new_name: name })
      changed()
    })
  }
  const remove = () => {
    const what = label ? `${label.name}’s folder` : e.name
    if (!confirm(`Delete ${what}${e.kind === 'dir' ? ' and everything in it' : ''}?`)) return
    act(async () => {
      await post('/ui/delete', { path })
      flash('ok', `Deleted ${e.name}`)
      changed()
    })
  }
  const toggle = expanded ? 'Collapse' : 'Expand'
  return (
    <>
      <tr>
        <td style={indent(depth)}>
          {e.kind === 'dir' ? (
            <TextButton
              className={expand}
              aria-expanded={expanded}
              aria-label={`${toggle} ${e.name}`}
              title={toggle}
              onClick={() => {
                setExpanded(!expanded)
                if (expanded) setChildren(null)
              }}
            >
              {expanded ? '▾' : '▸'}
            </TextButton>
          ) : (
            <span className={expand} />
          )}
          <Copyable text={`/${path}`}>
            {icons[e.kind]}{' '}
            <Link href={treeHref(owner, path)} title={`/${path}`}>
              {label ? <AppTag app={label} /> : e.name}
            </Link>
          </Copyable>
        </td>
        <td className="text-right tabular-nums">{e.kind === 'dir' ? '' : fmtSize(e.size)}</td>
        <td>{fmtTime(e.modified)}</td>
        <td className={actionsCell}>
          {listing.editable && (
            <>
              {!label && (
                <TextButton onClick={rename}>
                  Rename
                </TextButton>
              )}
              <TextButton danger onClick={remove}>
                Delete
              </TextButton>
            </>
          )}
        </td>
      </tr>
      {expanded &&
        children &&
        ('error' in children ? (
          <tr>
            <td colSpan={4} className="text-danger" style={indent(depth + 1)}>
              {children.error}
            </td>
          </tr>
        ) : (
          <Rows listing={children} owner={owner} depth={depth + 1} version={version} changed={changed} />
        ))}
    </>
  )
}

// ---- files ----

const preview = 'max-w-full overflow-auto rounded-lg border border-line bg-card p-3'

function File({ browse, owner }: { browse: Browse & FileNode; owner: Owner }) {
  const raw = rawHref(owner, browse.path)
  const [info, setInfo] = useState({ etag: browse.etag, size: browse.size, modified: browse.modified })
  // Textareas use \n line endings whatever the file had; `crlf` puts them back on save.
  const [text, setText] = useState(browse.text ?? '')
  const [saving, setSaving] = useState(false)
  const form = useRef<HTMLFormElement>(null)

  const save = (e: FormEvent) => {
    e.preventDefault()
    setSaving(true)
    act(async () => {
      const content = browse.crlf ? text.replace(/\r?\n/g, '\r\n') : text
      const r = await post<typeof info>('/ui/save', { path: browse.path, content, etag: info.etag })
      setInfo(r)
      flash('ok', 'Saved')
    }).finally(() => setSaving(false))
  }
  const keys = (e: KeyboardEvent) => {
    if (e.key === 's' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      form.current?.requestSubmit()
    }
  }

  return (
    <>
      <div className={toolbar}>
        <a className={buttonLink} href={raw}>
          Download
        </a>
        <span className="text-muted">
          {fmtSize(info.size)} · {browse.mime} · modified {fmtTime(info.modified)}
        </span>
      </div>
      <ApiPath path={browse.path} />
      {browse.is_image && <img className={preview} src={`${raw}?inline=1`} alt={browse.path.split('/').pop()} />}
      {browse.text != null ? (
        browse.editable ? (
          <form ref={form} onSubmit={save}>
            <textarea className="w-full resize-y" name="content" rows={24} spellCheck={false} value={text} onChange={(e) => setText(e.target.value)} onKeyDown={keys} />
            <div className="mt-2">
              <button type="submit" disabled={saving}>
                Save (Ctrl+S)
              </button>
            </div>
          </form>
        ) : (
          <pre className={`${preview} whitespace-pre-wrap`}>
            {browse.text}
            {browse.truncated && '\n… (truncated)'}
          </pre>
        )
      ) : (
        !browse.is_image && <p className="text-muted">No preview for this file type.</p>
      )}
    </>
  )
}
