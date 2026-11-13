// The user's passkeys, connected apps and API tokens.

import { useState, type FormEvent } from 'react'
import { post, useApi, type Settings as Data } from '../api.ts'
import { act, actionsCell, AppTag, Card, Copyable, flash, labelBlock, listTable, Loading, Secret, Status, TextButton, toolbar, useTitle } from '../components.tsx'
import { fmtTime, treeHref } from '../format.ts'
import { addPasskey, ceremonyError } from '../passkeys.ts'
import { Link } from '../router.tsx'

const SCOPES = ['files:read', 'files:write', 'db:read', 'db:write']

export function Settings() {
  useTitle('Settings')
  const s = useApi<Data>('/ui/settings')
  if (!s.data) return <Loading error={s.error} />
  return (
    <>
      <h1>Settings</h1>
      <Passkeys data={s.data} reload={s.reload} />
      <Apps data={s.data} reload={s.reload} />
      <Tokens data={s.data} reload={s.reload} />
    </>
  )
}

interface Props {
  data: Data
  reload: () => void
}

function Passkeys({ data, reload }: Props) {
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState({ text: '', error: false })
  const add = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setStatus({ text: 'Waiting for your authenticator…', error: false })
    try {
      await addPasskey(name)
      setStatus({ text: '', error: false })
      setName('')
      flash('ok', 'Passkey added')
      reload()
    } catch (err) {
      setStatus({ text: ceremonyError(err as Error), error: true })
    } finally {
      setBusy(false)
    }
  }
  const remove = (id: number, name: string) =>
    confirm(`Remove passkey ${name}?`) &&
    act(async () => {
      await post('/ui/passkeys/delete', { id })
      flash('ok', 'Passkey removed')
      reload()
    })
  return (
    <Card>
      <h2>Passkeys</h2>
      <table className={listTable}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Added</th>
            <th>Last used</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {data.passkeys.map((p) => (
            <tr key={p.id}>
              <td>{p.name}</td>
              <td>{fmtTime(p.created)}</td>
              <td>{fmtTime(p.last_used)}</td>
              <td className={actionsCell}>
                {data.passkeys.length > 1 && (
                  <TextButton danger onClick={() => remove(p.id, p.name)}>
                    Remove
                  </TextButton>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <form id="add-passkey-form" className={toolbar} onSubmit={add}>
        <input name="name" placeholder="Passkey name (e.g. Phone)" value={name} onChange={(e) => setName(e.target.value)} />
        <button type="submit" disabled={busy}>
          Add a passkey
        </button>
      </form>
      <Status {...status} />
    </Card>
  )
}

function Apps({ data, reload }: Props) {
  const disconnect = (id: string, name: string) =>
    confirm(`Disconnect ${name}? Its folder and files stay.`) &&
    act(async () => {
      await post('/ui/apps/disconnect', { app_id: id })
      flash('ok', 'App disconnected')
      reload()
    })
  return (
    <Card>
      <h2>Connected apps</h2>
      <p className="text-muted">Apps you allowed to use your account with “Sign in with bisonbase”.</p>
      <table className={listTable}>
        <thead>
          <tr>
            <th>App</th>
            <th>Folder</th>
            <th>Can</th>
            <th>Allowed</th>
            <th>Last used</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {data.apps.map((a) => (
            <tr key={a.app_id}>
              <td>
                <AppTag app={a} />
                <br />
                <a href={a.client_id} target="_blank" rel="noopener" className="text-muted">
                  {a.client_id}
                </a>
              </td>
              <td>
                <Copyable text={a.folder}>
                  <Link href={treeHref(null, a.folder.slice(1))} title={a.folder}>
                    <code className="whitespace-nowrap">/apps/{a.app_id.slice(0, 8)}…</code>
                  </Link>
                </Copyable>
              </td>
              <td>
                {a.permissions.map((p, i) => (
                  <span key={p}>
                    {i > 0 && <br />}
                    {p}
                  </span>
                ))}
              </td>
              <td>{fmtTime(a.authorized)}</td>
              <td>{fmtTime(a.last_used)}</td>
              <td className={actionsCell}>
                <TextButton danger onClick={() => disconnect(a.app_id, a.name)}>
                  Disconnect
                </TextButton>
              </td>
            </tr>
          ))}
          {data.apps.length === 0 && (
            <tr>
              <td colSpan={6} className="text-muted">
                No apps.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Card>
  )
}

function Tokens({ data, reload }: Props) {
  const [created, setCreated] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [scopes, setScopes] = useState(new Set(['files:read', 'db:read']))
  const [days, setDays] = useState('')
  const create = (e: FormEvent) => {
    e.preventDefault()
    act(async () => {
      const r = await post<{ token: string }>('/ui/tokens/create', {
        name,
        scopes: [...scopes],
        expires_days: days.trim() ? Number(days) : null,
      })
      setCreated(r.token)
      setName('')
      reload()
    })
  }
  const revoke = (id: number, name: string) =>
    confirm(`Revoke token ${name}?`) &&
    act(async () => {
      await post('/ui/tokens/delete', { id })
      flash('ok', 'Token revoked')
      reload()
    })
  const toggle = (s: string, on: boolean) => {
    const next = new Set(scopes)
    if (on) next.add(s)
    else next.delete(s)
    setScopes(next)
  }
  const o = data.origin
  return (
    <Card>
      <h2>API tokens</h2>
      {created && <Secret label="New token (copy it now; it won't be shown again):" value={created} />}
      <table className={listTable}>
        <thead>
          <tr>
            <th>Name</th>
            <th>Scopes</th>
            <th>Created</th>
            <th>Expires</th>
            <th>Last used</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {data.tokens.map((t) => (
            <tr key={t.id}>
              <td>{t.name}</td>
              <td>
                <code>{t.scopes}</code>
              </td>
              <td>{fmtTime(t.created)}</td>
              <td>{fmtTime(t.expires)}</td>
              <td>{fmtTime(t.last_used)}</td>
              <td className={actionsCell}>
                <TextButton danger onClick={() => revoke(t.id, t.name)}>
                  Revoke
                </TextButton>
              </td>
            </tr>
          ))}
          {data.tokens.length === 0 && (
            <tr>
              <td colSpan={6} className="text-muted">
                No tokens.
              </td>
            </tr>
          )}
        </tbody>
      </table>
      <form className="mt-4 grid max-w-120 gap-2.5" onSubmit={create}>
        <label className={labelBlock}>
          Name <input name="name" required placeholder="my-app" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <fieldset>
          <legend>Scopes</legend>
          <div className="flex flex-wrap gap-3">
          {SCOPES.map((s) => (
            <label className="inline-flex items-center gap-1.5" key={s}>
              <input type="checkbox" checked={scopes.has(s)} onChange={(e) => toggle(s, e.target.checked)} /> {s}
            </label>
          ))}
          </div>
        </fieldset>
        <label className={labelBlock}>
          Expires in days (blank = never){' '}
          <input name="expires_days" type="number" min="1" max="36499" value={days} onChange={(e) => setDays(e.target.value)} />
        </label>
        <div>
          <button type="submit">Create token</button>
        </div>
      </form>
      <details className="mt-4">
        <summary>Using the API</summary>
        <pre className="mt-2 overflow-auto rounded-md bg-code p-3">{`curl -H "Authorization: Bearer $TOKEN" ${o}/api/v1/files/
curl -X PUT -H "Authorization: Bearer $TOKEN" --data-binary @notes.txt ${o}/api/v1/files/docs/notes.txt
curl -X POST -H "Authorization: Bearer $TOKEN" "${o}/api/v1/files/app.db?op=mkdb"
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"tables": [{"name": "notes", "columns": [{"name": "text", "type": "text"}]}]}' "${o}/api/v1/files/app.db?op=migrate"
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"table": "notes", "rows": [{"text": "hello"}]}' "${o}/api/v1/files/app.db?op=insert"
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"table": "notes", "where": {"id": {"$gte": 1}}, "order_by": ["id desc"]}' "${o}/api/v1/files/app.db?op=select"
curl -N -H "Authorization: Bearer $TOKEN" "${o}/api/v1/files/app.db?op=watch"`}</pre>
      </details>
    </Card>
  )
}
