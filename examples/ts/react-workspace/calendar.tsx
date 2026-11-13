// Calendar: a month of private and shared events, with tasks on their due dates. Everyone
// can answer a shared event's invitation; each answer is a row its user owns.

import { useEffect, useState } from 'react'
import {
  add, events, isoDate, newUid, rsvps, setShared, shortDate, tableOf, tasks, time, useItems, useMe, usePrefs,
  type CalEvent,
} from './data.ts'
import { Badge, Card, Comments, ShareSwitch, Sharing, useOwns } from './ui.tsx'

const DAY = 86_400_000
const startOfDay = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate())
const addDays = (d: Date, n: number) => new Date(d.getFullYear(), d.getMonth(), d.getDate() + n)

export function Calendar() {
  const [prefs, setPrefs] = usePrefs()
  const [month, setMonth] = useState(() => new Date(new Date().getFullYear(), new Date().getMonth(), 1))
  const [selected, setSelected] = useState(() => isoDate(new Date()))
  const next = new Date(month.getFullYear(), month.getMonth() + 1, 1)

  // The grid: whole weeks covering the month.
  const weekStart = prefs.week_starts_monday ? 1 : 0
  const first = addDays(month, -((month.getDay() - weekStart + 7) % 7))
  const days = Array.from({ length: Math.ceil(Math.round((next.getTime() - first.getTime()) / DAY) / 7) * 7 }, (_, i) => addDays(first, i))
  const gridEnd = addDays(days[days.length - 1], 1)

  // Only the events that overlap the grid, and the tasks due in it, come from the server.
  const { rows: evs } = useItems(events, { where: { start: { $lt: gridEnd.getTime() }, end: { $gt: first.getTime() } }, orderBy: 'start' })
  const { rows: due } = useItems(tasks, { where: { due: { $gte: isoDate(first), $lt: isoDate(gridEnd) }, done: false } })
  const onDay = (d: Date) => {
    const from = d.getTime()
    const to = addDays(d, 1).getTime()
    return evs.filter((e) => e.start < to && e.end > from).sort((a, b) => +b.all_day - +a.all_day || a.start - b.start)
  }

  const names = Array.from({ length: 7 }, (_, i) => addDays(first, i).toLocaleDateString([], { weekday: 'short' }))
  const sel = new Date(`${selected}T00:00`)

  return (
    <div className="grid gap-4 md:grid-cols-[1fr_20rem]">
      <Card>
        <div className="mb-3 flex items-center gap-2">
          <button className="bg-transparent px-2 text-fg" aria-label="Previous month" onClick={() => setMonth(new Date(month.getFullYear(), month.getMonth() - 1, 1))}>‹</button>
          <h2 id="month" className="flex-1 text-center font-semibold">{month.toLocaleDateString([], { month: 'long', year: 'numeric' })}</h2>
          <button className="bg-transparent px-2 text-fg" aria-label="Next month" onClick={() => setMonth(next)}>›</button>
        </div>
        <div className="grid grid-cols-7 text-center text-xs text-muted">
          {names.map((n) => <div key={n} className="pb-1">{n}</div>)}
        </div>
        <div id="grid" className="grid grid-cols-7 gap-px overflow-hidden rounded-md border border-line bg-line">
          {days.map((d) => {
            const iso = isoDate(d)
            const list = onDay(d)
            const tasksDue = due.filter((t) => t.due === iso)
            return (
              <button key={iso} data-date={iso}
                className={`flex min-h-16 flex-col items-stretch gap-0.5 rounded-none p-1 text-left text-xs text-fg sm:min-h-20 ${iso === selected ? 'bg-accent/10' : 'bg-card'} ${d.getMonth() === month.getMonth() ? '' : 'opacity-50'}`}
                onClick={() => setSelected(iso)}>
                <span className={`self-end rounded-full px-1.5 ${iso === isoDate(new Date()) ? 'bg-accent text-white' : ''}`}>{d.getDate()}</span>
                {list.slice(0, 3).map((e) => (
                  <span key={e.uid} className={`truncate rounded px-1 ${e.shared ? 'bg-accent/15 text-accent' : 'bg-line'}`}>{e.title}</span>
                ))}
                {list.length > 3 && <span className="text-muted">+{list.length - 3} more</span>}
                {tasksDue.length > 0 && <span className="truncate text-muted">☐ {tasksDue.length === 1 ? tasksDue[0].title : `${tasksDue.length} tasks`}</span>}
              </button>
            )
          })}
        </div>
        <label className="mt-3 flex items-center gap-1.5 text-sm text-muted">
          <input type="checkbox" checked={prefs.week_starts_monday} onChange={(e) => void setPrefs({ week_starts_monday: e.target.checked })} />
          Weeks start on Monday
        </label>
      </Card>
      <div className="space-y-4">
        <Card>
          <h3 id="day" className="mb-2 font-semibold">{sel.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' })}</h3>
          <ul id="events" className="mb-3 space-y-2">
            {onDay(sel).map((e) => <EventItem key={e.uid} event={e} />)}
            {due.filter((t) => t.due === selected).map((t) => (
              <li key={t.uid} className="text-sm text-muted">☐ {t.title} <span className="text-xs">(due)</span></li>
            ))}
            {onDay(sel).length === 0 && <li className="empty text-sm text-muted">Nothing planned.</li>}
          </ul>
          <NewEvent date={selected} />
        </Card>
        <Upcoming />
      </div>
    </div>
  )
}

function NewEvent({ date }: { date: string }) {
  const [title, setTitle] = useState('')
  const [allDay, setAllDay] = useState(false)
  const [from, setFrom] = useState('09:00')
  const [to, setTo] = useState('10:00')
  const [location, setLocation] = useState('')
  const [shared, setSharedNew] = useState(false)
  return (
    <form
      id="new-event"
      className="space-y-2 border-t border-line pt-3 text-sm"
      onSubmit={(e) => {
        e.preventDefault()
        const day = new Date(`${date}T00:00`)
        const start = allDay ? day.getTime() : new Date(`${date}T${from}`).getTime()
        let end = allDay ? addDays(day, 1).getTime() : new Date(`${date}T${to}`).getTime()
        if (end <= start) end = start + 3_600_000
        void add(events, shared, { uid: newUid(), title: title.trim(), start, end, all_day: allDay, location: location.trim() || null })
        setTitle('')
        setLocation('')
      }}
    >
      <input className="w-full" placeholder="New event" required autoComplete="off" value={title} onChange={(e) => setTitle(e.target.value)} />
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-1.5"><input type="checkbox" checked={allDay} onChange={(e) => setAllDay(e.target.checked)} /> All day</label>
        {!allDay && (
          <>
            <input type="time" value={from} onChange={(e) => setFrom(e.target.value)} aria-label="From" />
            <span className="text-muted">to</span>
            <input type="time" value={to} onChange={(e) => setTo(e.target.value)} aria-label="To" />
          </>
        )}
      </div>
      <input className="w-full" placeholder="Location (optional)" value={location} onChange={(e) => setLocation(e.target.value)} />
      <div className="flex items-center justify-between gap-2">
        <ShareSwitch shared={shared} onChange={setSharedNew} />
        <button>Add event</button>
      </div>
    </form>
  )
}

function EventItem({ event }: { event: CalEvent }) {
  const owns = useOwns(event)
  const [open, setOpen] = useState(false)
  return (
    <li className="event rounded-md border border-line p-2 text-sm" data-uid={event.uid}>
      <button className="flex w-full items-center gap-2 bg-transparent p-0 text-left text-fg" onClick={() => setOpen(!open)}>
        <span className="w-16 shrink-0 text-xs text-muted">{event.all_day ? 'All day' : time(event.start)}</span>
        <span className="title flex-1 font-medium">{event.title}</span>
        <Sharing item={event} />
      </button>
      {open && (
        <div className="mt-2 space-y-2">
          <p className="when text-muted">
            {event.all_day ? 'All day' : `${time(event.start)} – ${time(event.end)}`}
            {event.location && ` · ${event.location}`}
          </p>
          {event.shared && <Rsvp event={event} />}
          {owns && (
            <div className="flex items-center gap-2">
              <ShareSwitch shared={event.shared} onChange={(s) => void setShared(events, event, s)} />
              <button className="ml-auto bg-transparent px-1.5 text-danger" onClick={() => void tableOf(events, event).delete(event.id)}>Delete</button>
            </div>
          )}
          {event.shared && <Comments item={`event:${event.uid}`} />}
        </div>
      )}
    </li>
  )
}

const ANSWERS = [['yes', 'Going'], ['maybe', 'Maybe'], ['no', 'Not going']] as const

/** Everyone's answers to a shared event, and buttons for the user's own. */
function Rsvp({ event }: { event: CalEvent }) {
  const me = useMe()
  const answers = rsvps.useSelect({ where: { event: event.uid } })
  const mine = answers.find((a) => a._owner === me?.user.id)
  const answer = async (value: string) => {
    // `where` only ever matches the user's own rows, so this changes their answer, if they've given one.
    if ((await rsvps.update({ event: event.uid }, { answer: value })) === 0) await rsvps.insert({ event: event.uid, answer: value })
  }
  return (
    <div className="rsvp space-y-1.5">
      <div className="flex gap-1.5">
        {ANSWERS.map(([value, label]) => (
          <button key={value} className={`px-2 py-0.5 text-xs ${mine?.answer === value ? '' : 'bg-line/60 text-fg'}`} onClick={() => void answer(value)}>{label}</button>
        ))}
      </div>
      {answers.length > 0 && (
        <p className="text-xs text-muted">
          {ANSWERS.map(([value, label]) => {
            const who = answers.filter((a) => a.answer === value).map((a) => me?.names.get(a._owner) ?? 'someone')
            return who.length ? <span key={value} className="mr-2">{label}: {who.join(', ')}.</span> : null
          })}
        </p>
      )}
    </div>
  )
}

/** The next few events, private or shared. */
function Upcoming() {
  // The query changes with `now`, so round it: a new query a minute, not one a render.
  const [now, setNow] = useState(() => Math.floor(Date.now() / 60_000) * 60_000)
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 60_000) * 60_000), 60_000)
    return () => clearInterval(t)
  }, [])
  const { rows } = useItems(events, { where: { end: { $gt: now } }, orderBy: 'start', limit: 5 })
  const next = [...rows].sort((a, b) => a.start - b.start).slice(0, 5)
  return (
    <Card>
      <h3 className="mb-2 font-semibold">Upcoming</h3>
      <ul id="upcoming" className="space-y-1 text-sm">
        {next.map((e) => (
          <li key={e.uid} className="flex gap-2">
            <span className="w-20 shrink-0 text-muted">{startOfDay(new Date(e.start)).getTime() === startOfDay(new Date()).getTime() ? 'Today' : shortDate(e.start)}</span>
            <span className="flex-1 truncate">{e.title}</span>
            {e.shared && <Badge tone="accent">Shared</Badge>}
          </li>
        ))}
        {next.length === 0 && <li className="text-muted">No upcoming events.</li>}
      </ul>
    </Card>
  )
}
