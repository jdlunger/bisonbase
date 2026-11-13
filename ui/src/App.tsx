import { useEffect, type ReactNode } from 'react'
import { toLogin, useApi, type Me, type Session } from './api.ts'
import { ErrorPage, Flash, Header, Loading, type Section } from './components.tsx'
import { appTree, decodePath, OWN_TREE, userTree } from './format.ts'
import { Admin } from './pages/Admin.tsx'
import { Apps } from './pages/Apps.tsx'
import { Authorize } from './pages/Authorize.tsx'
import { Files } from './pages/Files.tsx'
import { Login, Recover, Signup } from './pages/Account.tsx'
import { Settings } from './pages/Settings.tsx'
import { SystemDb } from './pages/Db.tsx'
import { navigate, useHref } from './router.tsx'

interface Route {
  section: Section
  /** Pages for logged-in users; `admin`: for admins only. */
  auth?: 'user' | 'admin'
  render: (me: Me) => ReactNode
}

function route(path: string, session: Session): Route | null {
  const q = new URLSearchParams(location.search)
  switch (path) {
    case '/login':
      return { section: '', render: () => <Login signupOpen={session.signup_open} /> }
    case '/signup':
      return { section: '', render: () => <Signup invite={q.get('invite')} /> }
    case '/recover':
      return { section: '', render: () => <Recover token={q.get('token') ?? ''} /> }
    case '/settings':
      return { section: 'settings', auth: 'user', render: () => <Settings /> }
    case '/admin':
      return { section: 'admin', auth: 'admin', render: (me) => <Admin me={me} /> }
    case '/apps':
      return { section: 'apps', auth: 'user', render: (me) => <Apps me={me} /> }
    case '/admin/db':
      return { section: 'admin', auth: 'admin', render: () => <SystemDb /> }
    case '/oauth/authorize':
      return { section: '', auth: 'user', render: () => <Authorize /> }
  }
  if (path === '/files' || path.startsWith('/files/')) {
    const p = decodePath(path.slice('/files'.length))
    return { section: 'files', auth: 'user', render: () => <Files tree={OWN_TREE} path={p} /> }
  }
  const m = /^\/admin\/users\/([^/]+)\/files(\/.*)?$/.exec(path)
  if (m) {
    const p = decodePath(m[2] ?? '')
    return {
      section: 'admin',
      auth: 'admin',
      render: (me) => (m[1] === me.id ? <Redirect to={`/files/${m[2]?.slice(1) ?? ''}`} /> : <Files tree={userTree(m[1])} path={p} />),
    }
  }
  const a = /^\/apps\/([^/]+)\/files(\/.*)?$/.exec(path)
  if (a) {
    const p = decodePath(a[2] ?? '')
    return { section: 'apps', auth: 'user', render: () => <Files tree={appTree(a[1])} path={p} /> }
  }
  return null
}

function ToLogin() {
  useEffect(toLogin, [])
  return null
}

function Redirect({ to }: { to: string }) {
  useEffect(() => navigate(to, { replace: true }), [to])
  return null
}

export function App() {
  const href = useHref()
  const session = useApi<Session>('/ui/session')
  const path = location.pathname.replace(/\/+$/, '') || '/'

  useEffect(() => {
    if (path === '/' && session.data) navigate(session.data.user ? '/files' : '/login', { replace: true })
  }, [path, session.data])

  if (!session.data) {
    return (
      <>
        <Header user={null} section="" />
        <main className="mx-auto max-w-300 p-4">
          <Loading error={session.error} />
        </main>
      </>
    )
  }
  const me = session.data.user
  const r = route(path, session.data)
  let page: ReactNode
  if (path === '/') page = null
  else if (!r) page = <ErrorPage status={404} message="There is no page here." />
  else if (r.auth && !me) page = <ToLogin />
  else if (r.auth === 'admin' && !me?.is_admin) page = <ErrorPage status={403} message="admins only" />
  else page = r.render(me!)

  return (
    <>
      <Header user={me} section={r?.section ?? ''} />
      <main className="mx-auto max-w-300 p-4" key={href.split('?')[0]}>
        <Flash />
        {page}
      </main>
    </>
  )
}
