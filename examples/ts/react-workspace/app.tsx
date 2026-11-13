// A small shared workspace on the bisonbase client library: tasks, a calendar and notes, each
// private or shared with everyone else who uses the app. See data.ts for how it's stored.

import { createRoot } from 'react-dom/client'
import { AuthElement, useAuth } from 'bisonbase/react'
import { MeContext, members, useLoadMe, useMe, usePrefs } from './data.ts'
import { Calendar } from './calendar.tsx'
import { Notes } from './notes.tsx'
import { Tasks } from './tasks.tsx'
import { Card } from './ui.tsx'
import '../style.css'

const TABS = { tasks: 'Tasks', calendar: 'Calendar', notes: 'Notes' } as const
type Tab = keyof typeof TABS

function App() {
  const auth = useAuth()
  const me = useLoadMe()
  return (
    <MeContext value={me}>
      <main className="mx-auto max-w-6xl">
        <header className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2">
          <h1 className="text-2xl font-bold">Workspace</h1>
          {auth.status === 'signed-in' && <Tabs />}
          <div className="ml-auto flex items-center gap-3 text-sm">
            {me && <span id="me" className="text-muted">{me.user.username}{me.owner && ' (owner)'}</span>}
            <AuthElement className="flex items-center gap-2.5 [&_.bb-auth-error]:text-danger [&_.bb-auth-label]:hidden" />
          </div>
        </header>
        {auth.status === 'signed-in' ? <Body /> : <Welcome />}
      </main>
    </MeContext>
  )
}

function Tabs() {
  const [prefs, setPrefs] = usePrefs()
  return (
    <nav id="tabs" className="flex gap-1">
      {Object.entries(TABS).map(([tab, label]) => (
        <button key={tab} aria-current={prefs.tab === tab ? 'page' : undefined}
          className={prefs.tab === tab ? '' : 'bg-transparent text-fg hover:bg-line/50'}
          onClick={() => void setPrefs({ tab })}>
          {label}
        </button>
      ))}
    </nav>
  )
}

function Body() {
  // The open tab is kept in the user's own database, so it follows them between devices.
  const [prefs] = usePrefs()
  const tab: Tab = prefs.tab in TABS ? (prefs.tab as Tab) : 'tasks'
  return (
    <>
      {tab === 'tasks' && <Tasks />}
      {tab === 'calendar' && <Calendar />}
      {tab === 'notes' && <Notes />}
      <Members />
    </>
  )
}

function Members() {
  const me = useMe()
  const rows = members.useSelect({ orderBy: 'joined' })
  if (!me) return null
  return (
    <p id="members" className="mt-4 text-sm text-muted">
      In this workspace: {rows.map((m) => m.username + (m._owner === me.user.id ? ' (you)' : '')).join(', ')}
    </p>
  )
}

function Welcome() {
  return (
    <Card className="mx-auto max-w-140">
      <h2 className="mb-2 text-lg font-semibold">Tasks, a calendar and notes, for you and your team</h2>
      <p className="mb-2">Keep anything to yourself, or share it with everyone who uses the workspace: they can read it,
        comment on it and answer shared events, and only you can change it.</p>
      <p className="text-muted">Sign in with your bisonbase account to start.</p>
    </Card>
  )
}

createRoot(document.querySelector('#root')!).render(<App />)
