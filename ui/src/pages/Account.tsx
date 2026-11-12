// Logging in, signing up, and recovering an account with a recovery link.

import { useState, type FormEvent } from 'react'
import { query, useApi } from '../api.ts'
import { Card, labelBlock, Loading, Status, useTitle } from '../components.tsx'
import { ceremonyError, login, recover, signup } from '../passkeys.ts'
import { Link } from '../router.tsx'

/** A passkey ceremony behind a form: busy state and the status line. */
function useCeremony() {
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState({ text: '', error: false })
  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setStatus({ text: 'Waiting for your authenticator…', error: false })
    try {
      await fn()
    } catch (e) {
      setStatus({ text: ceremonyError(e as Error), error: true })
    } finally {
      setBusy(false)
    }
  }
  return { busy, status, run }
}

/** Only local redirect targets. */
function safeNext(next: string | null): string {
  return next && next.startsWith('/') && !next.startsWith('//') && !next.includes('\\') ? next : '/files'
}

export function Login({ signupOpen }: { signupOpen: boolean }) {
  useTitle('Log in')
  const [username, setUsername] = useState('')
  const { busy, status, run } = useCeremony()
  const submit = (e: FormEvent) => {
    e.preventDefault()
    run(async () => {
      await login(username.trim())
      // A full load, so the whole app sees the new session.
      location.assign(safeNext(new URLSearchParams(location.search).get('next')))
    })
  }
  return (
    <Card narrow>
      <h1>Log in</h1>
      <form id="login-form" className="grid gap-3" onSubmit={submit}>
        <label className={labelBlock}>
          Username{' '}
          <input
            name="username"
            autoComplete="username webauthn"
            required
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <button type="submit" disabled={busy}>
          Log in with passkey
        </button>
      </form>
      <Status {...status} />
      {signupOpen && (
        <p className="text-muted">
          No account? <Link href="/signup">Sign up</Link>
        </p>
      )}
    </Card>
  )
}

export function Signup({ invite }: { invite: string | null }) {
  useTitle('Sign up')
  const info = useApi<{ allowed: boolean; notice: string }>(`/ui/signup${query({ invite })}`)
  const [username, setUsername] = useState('')
  const { busy, status, run } = useCeremony()
  const submit = (e: FormEvent) => {
    e.preventDefault()
    run(async () => {
      const done = await signup(username.trim(), invite || null)
      location.assign(done.redirect || '/files')
    })
  }
  return (
    <Card narrow>
      <h1>Create account</h1>
      {!info.data ? (
        <Loading error={info.error} />
      ) : (
        <>
          {info.data.notice && <p className="rounded-md bg-code px-3 py-2">{info.data.notice}</p>}
          {info.data.allowed && (
            <>
              <form id="signup-form" className="grid gap-3" onSubmit={submit}>
                <label className={labelBlock}>
                  Username{' '}
                  <input
                    name="username"
                    autoComplete="username"
                    required
                    autoFocus
                    pattern="[A-Za-z0-9_.\-]{3,32}"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </label>
                <button type="submit" disabled={busy}>
                  Create passkey &amp; sign up
                </button>
              </form>
              <Status {...status} />
            </>
          )}
        </>
      )}
      <p className="text-muted">
        Already have an account? <Link href="/login">Log in</Link>
      </p>
    </Card>
  )
}

export function Recover({ token }: { token: string }) {
  useTitle('Recover account')
  const info = useApi<{ username: string | null }>(`/ui/recover${query({ token })}`)
  const { busy, status, run } = useCeremony()
  const submit = (e: FormEvent) => {
    e.preventDefault()
    run(async () => {
      const done = await recover(token)
      location.assign(done.redirect || '/settings')
    })
  }
  return (
    <Card narrow>
      <h1>Recover account</h1>
      {!info.data ? (
        <Loading error={info.error} />
      ) : info.data.username ? (
        <>
          <p>
            Create a new passkey for <strong>{info.data.username}</strong>. This signs the account out on every other
            device; afterwards, remove any passkeys you lost under <em>Settings</em>.
          </p>
          <form id="recover-form" onSubmit={submit}>
            <button type="submit" disabled={busy}>
              Create new passkey
            </button>
          </form>
          <Status {...status} />
        </>
      ) : (
        <p className="rounded-md bg-code px-3 py-2">This recovery link is invalid, already used, or expired. Ask an administrator for a new one.</p>
      )}
      <p className="text-muted">
        <Link href="/login">Log in</Link>
      </p>
    </Card>
  )
}
