// Admin: signup mode, invites, users, and a way into system.db.

import { useState, type FormEvent } from 'react'
import { post, useApi, type AdminData, type Me } from '../api.ts'
import { act, actionsCell, buttonLink, Card, flash, listTable, Loading, Secret, TextButton, toolbar, useTitle } from '../components.tsx'
import { fmtTime, treeBase } from '../format.ts'
import { Link } from '../router.tsx'

/** A one-time link, shown once right after it is created. */
interface NewLink {
  label: string
  url: string
}

export function Admin({ me }: { me: Me }) {
  useTitle('Admin')
  const a = useApi<AdminData>('/ui/admin')
  const [link, setLink] = useState<NewLink | null>(null)
  if (!a.data) return <Loading error={a.error} />
  return (
    <>
      <h1>Admin</h1>
      {link && <Secret label={link.label} value={link.url} />}

      <Card>
        <h2>System database</h2>
        <p className="text-muted">
          Browse every table of <code>system.db</code>. Names, notes, expiry times, admin flags and the signup mode can
          be edited there; sessions, tokens, invites and passkeys can be deleted. Every change is recorded in{' '}
          <code>audit_log</code>.
        </p>
        <p>
          <Link className={buttonLink} href="/admin/db">
            Open system database
          </Link>{' '}
          <Link href="/admin/db?table=audit_log">Audit log</Link>
        </p>
      </Card>

      <SignupMode mode={a.data.signup_mode} reload={a.reload} />
      <Invites data={a.data} reload={a.reload} onLink={setLink} />
      <Users data={a.data} me={me} reload={a.reload} onLink={setLink} />
    </>
  )
}

function SignupMode({ mode, reload }: { mode: AdminData['signup_mode']; reload: () => void }) {
  const [value, setValue] = useState(mode)
  const save = (e: FormEvent) => {
    e.preventDefault()
    act(async () => {
      await post('/ui/admin/signup', { mode: value })
      flash('ok', `Signup mode set to ${value}`)
      reload()
    })
  }
  const options = [
    ['open', 'Open — anyone can sign up'],
    ['invite', 'Invite only'],
    ['closed', 'Closed'],
  ] as const
  return (
    <Card>
      <h2>Signups</h2>
      <form className={toolbar} onSubmit={save}>
        {options.map(([v, label]) => (
          <label className="inline-flex items-center gap-1.5" key={v}>
            <input type="radio" name="mode" value={v} checked={value === v} onChange={() => setValue(v)} /> {label}
          </label>
        ))}
        <button type="submit">Save</button>
      </form>
    </Card>
  )
}

interface ListProps {
  data: AdminData
  reload: () => void
  onLink: (l: NewLink) => void
}

function inviteStatus(i: AdminData['invites'][number]): string {
  if (i.used_at != null) return i.used_by ? `used by ${i.used_by} at ${fmtTime(i.used_at)}` : `used at ${fmtTime(i.used_at)}`
  return i.active ? 'active' : 'expired'
}

function Invites({ data, reload, onLink }: ListProps) {
  const [note, setNote] = useState('')
  const [days, setDays] = useState('7')
  const [grantsAdmin, setGrantsAdmin] = useState(false)
  const create = (e: FormEvent) => {
    e.preventDefault()
    act(async () => {
      const r = await post<{ url: string }>('/ui/admin/invites/create', {
        note,
        days: Number(days),
        grants_admin: grantsAdmin,
      })
      onLink({ label: "One-time invite link (copy it now; it won't be shown again):", url: r.url })
      setNote('')
      setGrantsAdmin(false)
      reload()
    })
  }
  const revoke = (id: number) =>
    act(async () => {
      await post('/ui/admin/invites/delete', { id })
      flash('ok', 'Invite revoked')
      reload()
    })
  return (
    <Card>
      <h2>Invites</h2>
      <form className={toolbar} onSubmit={create}>
        <input name="note" placeholder="Note (who is this for?)" value={note} onChange={(e) => setNote(e.target.value)} />
        <label>
          Expires in{' '}
          <input name="days" type="number" min="1" max="365" className="w-20" value={days} onChange={(e) => setDays(e.target.value)} />{' '}
          days
        </label>
        <label className="inline-flex items-center gap-1.5">
          <input type="checkbox" name="grants_admin" checked={grantsAdmin} onChange={(e) => setGrantsAdmin(e.target.checked)} /> Admin
        </label>
        <button type="submit">Create invite link</button>
      </form>
      <table className={listTable}>
        <thead>
          <tr>
            <th>Note</th>
            <th>Admin</th>
            <th>Created</th>
            <th>Expires</th>
            <th>Status</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {data.invites.map((i) => (
            <tr key={i.id}>
              <td>{i.note}</td>
              <td>{i.grants_admin && 'yes'}</td>
              <td>{fmtTime(i.created)}</td>
              <td>{fmtTime(i.expires)}</td>
              <td>{inviteStatus(i)}</td>
              <td className={actionsCell}>
                {i.active && (
                  <TextButton danger onClick={() => revoke(i.id)}>
                    Revoke
                  </TextButton>
                )}
              </td>
            </tr>
          ))}
          {data.invites.length === 0 && (
            <tr>
              <td colSpan={6} className="text-muted">
                No invites.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Card>
  )
}

function Users({ data, me, reload, onLink }: ListProps & { me: Me }) {
  type User = AdminData['users'][number]
  const setAdmin = (u: User) =>
    act(async () => {
      await post('/ui/admin/users/admin', { id: u.id, admin: !u.is_admin })
      flash('ok', 'User updated')
      reload()
    })
  const recovery = (u: User) =>
    confirm(`Create a one-time recovery link for ${u.username}? Anyone with the link can add a passkey to this account.`) &&
    act(async () => {
      const r = await post<{ url: string; username: string }>('/ui/admin/users/recover', { id: u.id })
      onLink({
        label: `Recovery link for ${r.username} (valid 7 days, works once; copy it now and send it to them privately). It adds a new passkey and signs them out everywhere else:`,
        url: r.url,
      })
    })
  const remove = (u: User) => {
    const typed = prompt(`This permanently deletes ${u.username} and all their files and databases.\n\nType the username to confirm:`)
    if (typed === null || typed.trim().toLowerCase() !== u.username.toLowerCase()) return
    act(async () => {
      await post('/ui/admin/users/delete', { id: u.id, confirm: typed.trim() })
      flash('ok', `Deleted ${u.username} and all their files`)
      reload()
    })
  }
  return (
    <Card>
      <h2>Users</h2>
      <table className={listTable}>
        <thead>
          <tr>
            <th>Username</th>
            <th>Role</th>
            <th>Created</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {data.users.map((u) => (
            <tr key={u.id}>
              <td>{u.username}</td>
              <td>{u.is_admin ? 'admin' : 'user'}</td>
              <td>{fmtTime(u.created)}</td>
              <td className={actionsCell}>
                <Link href={treeBase(u.id === me.id ? null : u.id)}>Browse files</Link>
                {!u.is_self && (
                  <TextButton onClick={() => setAdmin(u)}>
                    {u.is_admin ? 'Remove admin' : 'Make admin'}
                  </TextButton>
                )}
                <TextButton onClick={() => recovery(u)}>
                  Recovery link
                </TextButton>
                {!u.is_self && (
                  <TextButton danger onClick={() => remove(u)}>
                    Delete
                  </TextButton>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}
