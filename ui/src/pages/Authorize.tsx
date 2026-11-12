// "Sign in with bisonbase": asks the user whether to let an app use their account. The answer
// is an ordinary form post, which the server answers by redirecting back to the app.

import { useEffect } from 'react'
import { useApi, type Consent } from '../api.ts'
import { AppTag, Card, Copyable, Loading, TextButton, useTitle } from '../components.tsx'

export function Authorize() {
  useTitle('Allow access?')
  const c = useApi<Consent | { redirect: string }>(`/ui/oauth/authorize${location.search}`)
  const redirect = c.data && 'redirect' in c.data ? c.data.redirect : null
  useEffect(() => {
    if (redirect) location.replace(redirect)
  }, [redirect])
  if (!c.data || redirect) return <Loading error={c.error} />
  const a = c.data as Consent
  const hidden: [string, string][] = [
    ['client_id', a.client_id],
    ['redirect_uri', a.redirect_uri],
    ['scope', a.scope],
    ['state', a.state],
    ['code_challenge', a.code_challenge],
    ['app_id', a.app_id],
    ['app_name', a.app_name],
  ]
  return (
    <Card narrow>
      <h1 className="mt-0">Allow access?</h1>
      <p>
        <AppTag app={{ name: a.app_name, hue: a.hue }} /> at <strong className="break-all">{a.origin}</strong> wants to use your
        bisonbase account <strong>{a.username}</strong>.
      </p>
      <p>It gets its own folder and can't see anything else in your account:</p>
      <p>
        <Copyable text={a.folder}>
          <code>{a.folder}</code>
        </Copyable>
      </p>
      <p>In that folder it can:</p>
      <ul className="list-disc pl-5">
        {a.permissions.map((p) => (
          <li key={p}>{p}</li>
        ))}
      </ul>
      {a.local && <p className="rounded-md bg-code px-3 py-2">This app runs on this computer. Allow it only if you started it yourself.</p>}
      <p className="text-muted">The app keeps access for 30 days. You can disconnect it at any time under Settings.</p>
      <form method="post" action="/oauth/authorize" className="flex items-center gap-4">
        {hidden.map(([name, value]) => (
          <input key={name} type="hidden" name={name} value={value} />
        ))}
        <button type="submit" name="decision" value="allow">
          Allow
        </button>
        <TextButton type="submit" name="decision" value="deny">
          Cancel
        </TextButton>
      </form>
    </Card>
  )
}
