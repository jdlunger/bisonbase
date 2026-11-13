// Registered apps: those with storage of their own, shared by all their users. Everyone sees the
// apps they use or own and can open their data there; admins register apps and choose owners.

import { useState, type FormEvent } from 'react'
import { post, useApi, type Me, type RegisteredApp } from '../api.ts'
import { act, actionsCell, AppTag, Card, Copyable, flash, listTable, Loading, TextButton, toolbar, useTitle } from '../components.tsx'
import { appTree, fmtSize, fmtTime, treeBase } from '../format.ts'
import { Link, navigate } from '../router.tsx'

export function Apps({ me }: { me: Me }) {
  useTitle('Apps')
  const a = useApi<{ apps: RegisteredApp[] }>('/ui/apps')
  if (!a.data) return <Loading error={a.error} />
  const apps = a.data.apps
  return (
    <>
      <h1>Apps</h1>
      <p className="text-muted">
        Apps an admin registered keep data in storage of their own, shared by everyone who uses them. Each row of their
        databases belongs to the user who created it, and you can see yours here.
        {!me.is_admin && ' Apps you have signed in to that store data only in your own files are under Settings.'}
      </p>
      {me.is_admin && <Register />}
      <Card>
        <table className={listTable}>
          <thead>
            <tr>
              <th>App</th>
              <th>Origin</th>
              {me.is_admin && <th>Owners</th>}
              <th className="text-right!">Storage</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {apps.map((app) => (
              <AppRow key={app.id} app={app} admin={me.is_admin} reload={a.reload} />
            ))}
            {apps.length === 0 && (
              <tr>
                <td colSpan={5} className="text-muted">
                  {me.is_admin ? 'No apps registered yet.' : 'No apps with their own storage yet.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>
    </>
  )
}

function Register() {
  const [name, setName] = useState('')
  const [origin, setOrigin] = useState('')
  const [id, setId] = useState('')
  const create = (e: FormEvent) => {
    e.preventDefault()
    act(async () => {
      const r = await post<{ id: string }>('/ui/admin/apps/create', { name, origin, id: id || null })
      flash('ok', `Registered ${name}. Its app id is ${r.id}.`, treeBase(appTree(r.id)))
      navigate(treeBase(appTree(r.id)))
    })
  }
  return (
    <Card>
      <h2>Register an app</h2>
      <p className="text-muted">
        Only the origin given can sign in with the app's id. Leave the id empty to make a new one, or give the one the
        app already uses (an admin signing in to an app can also register it from there).
      </p>
      <form className={toolbar} onSubmit={create}>
        <input name="name" placeholder="Name" required value={name} onChange={(e) => setName(e.target.value)} />
        <input
          name="origin"
          placeholder="https://app.example.com"
          required
          className="w-64"
          value={origin}
          onChange={(e) => setOrigin(e.target.value)}
        />
        <input name="id" placeholder="App id (optional)" className="w-80" value={id} onChange={(e) => setId(e.target.value)} />
        <button type="submit">Register</button>
      </form>
    </Card>
  )
}

function AppRow({ app, admin, reload }: { app: RegisteredApp; admin: boolean; reload: () => void }) {
  const setOwner = (username: string, owner: boolean) =>
    act(async () => {
      await post('/ui/admin/apps/owner', { id: app.id, username, owner })
      flash('ok', owner ? `${username} now owns ${app.name}` : `${username} no longer owns ${app.name}`)
      reload()
    })
  const addOwner = () => {
    const username = prompt(`Who should also manage ${app.name}'s storage? Username:`)
    if (username?.trim()) setOwner(username.trim(), true)
  }
  const remove = () => {
    const typed = prompt(
      `This permanently deletes ${app.name}'s storage, with every user's data in it, and unregisters the app.\n\nType the app's name to confirm:`,
    )
    if (typed === null || typed.trim() !== app.name) return
    act(async () => {
      await post('/ui/admin/apps/delete', { id: app.id, confirm: typed.trim() })
      flash('ok', `Deleted ${app.name}`)
      reload()
    })
  }
  return (
    <tr>
      <td>
        <AppTag app={app} />{' '}
        <Copyable text={app.id}>
          <code className="text-[12px] text-muted">{app.id.slice(0, 8)}…</code>
        </Copyable>
        <div className="text-[13px] text-muted">registered {fmtTime(app.created)}</div>
      </td>
      <td>
        <code>{app.origin}</code>
      </td>
      {admin && (
        <td>
          {app.owners?.map((o) => (
            <span key={o.id} className="mr-2 whitespace-nowrap">
              {o.username}{' '}
              <TextButton danger title={`Remove ${o.username}`} aria-label={`Remove ${o.username}`} onClick={() => setOwner(o.username, false)}>
                ✕
              </TextButton>
            </span>
          ))}
          <TextButton onClick={addOwner}>Add owner</TextButton>
        </td>
      )}
      <td className="text-right tabular-nums">{app.usage != null && `${fmtSize(app.usage)} of ${fmtSize(app.quota)}`}</td>
      <td className={actionsCell}>
        <Link href={treeBase(appTree(app.id))}>{app.manage ? 'Browse storage' : 'Your data'}</Link>
        {admin && (
          <TextButton danger onClick={remove}>
            Delete
          </TextButton>
        )}
      </td>
    </tr>
  )
}
