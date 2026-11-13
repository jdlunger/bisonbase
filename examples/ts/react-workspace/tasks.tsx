// Tasks: private to-dos and shared ones, with priorities, due dates, tags and estimates.

import { useState } from 'react'
import { add, newUid, setShared, shortDate, tableOf, tasks, today, useItems, usePrefs, type Task } from './data.ts'
import { Badge, Card, Comments, ShareSwitch, Sharing, useOwns } from './ui.tsx'

const PRIORITY: Record<number, string> = { 1: 'High', 2: 'Normal', 3: 'Low' }
type Show = 'all' | 'mine' | 'shared'

export function Tasks() {
  const [prefs, setPrefs] = usePrefs()
  const [show, setShow] = useState<Show>('all')
  const [tag, setTag] = useState<string | null>(null)
  // The server leaves out done tasks when they're hidden. The rows come from two tables, so
  // they're sorted and filtered further here.
  const { rows, loading, error } = useItems(tasks, prefs.show_done ? {} : { where: { done: false } })
  const list = rows
    .filter((t) => show === 'all' || (show === 'shared') === t.shared)
    .filter((t) => !tag || tagsOf(t).includes(tag))
    .sort((a, b) => +a.done - +b.done || a.priority - b.priority || (a.due ?? '9').localeCompare(b.due ?? '9'))
  const open = list.filter((t) => !t.done)
  const hours = open.reduce((sum, t) => sum + (t.estimate ?? 0), 0)
  const allTags = [...new Set(rows.flatMap(tagsOf))].sort()

  return (
    <Card>
      <NewTask />
      <div className="mb-2 flex flex-wrap items-center gap-2 text-sm">
        {(['all', 'mine', 'shared'] as const).map((s) => (
          <button key={s} className={`py-0.5 ${show === s ? '' : 'bg-transparent text-fg'}`} onClick={() => setShow(s)}>
            {s === 'all' ? 'All' : s === 'mine' ? 'Private' : 'Shared'}
          </button>
        ))}
        {allTags.map((t) => (
          <button key={t} className={`rounded-full px-2 py-0 text-xs ${tag === t ? '' : 'bg-line/60 text-muted'}`} onClick={() => setTag(tag === t ? null : t)}>
            #{t}
          </button>
        ))}
        <label className="ml-auto flex items-center gap-1.5 text-muted">
          <input type="checkbox" checked={prefs.show_done} onChange={(e) => void setPrefs({ show_done: e.target.checked })} />
          Show done
        </label>
      </div>
      {error && <p className="text-danger">{error.message}</p>}
      <ul id="tasks" className="divide-y divide-line">
        {list.map((t) => <TaskItem key={t.uid} task={t} />)}
        {!loading && list.length === 0 && <li className="empty py-3 text-center text-muted">Nothing to do.</li>}
      </ul>
      <p className="mt-3 text-sm text-muted">
        {open.length} open {open.length === 1 ? 'task' : 'tasks'}
        {hours > 0 && `, about ${+hours.toFixed(1)} h`}
      </p>
    </Card>
  )
}

const tagsOf = (t: Task) => (Array.isArray(t.tags) ? t.tags.filter((x): x is string => typeof x === 'string') : [])

function NewTask() {
  const [title, setTitle] = useState('')
  const [priority, setPriority] = useState(2)
  const [due, setDue] = useState('')
  const [shared, setSharedNew] = useState(false)
  return (
    <form
      id="new-task"
      className="mb-3 flex flex-wrap gap-2"
      onSubmit={(e) => {
        e.preventDefault()
        if (!title.trim()) return
        void add(tasks, shared, { uid: newUid(), title: title.trim(), priority, due: due || null })
        setTitle('')
        setDue('')
      }}
    >
      <input className="min-w-40 flex-1" placeholder="New task" autoComplete="off" required value={title} onChange={(e) => setTitle(e.target.value)} />
      <select className="rounded-md border border-line bg-card px-2" value={priority} onChange={(e) => setPriority(+e.target.value)} aria-label="Priority">
        {[1, 2, 3].map((p) => <option key={p} value={p}>{PRIORITY[p]}</option>)}
      </select>
      <input type="date" value={due} onChange={(e) => setDue(e.target.value)} aria-label="Due" />
      <ShareSwitch shared={shared} onChange={setSharedNew} />
      <button>Add</button>
    </form>
  )
}

function TaskItem({ task }: { task: Task }) {
  const owns = useOwns(task)
  const [open, setOpen] = useState(false)
  const table = tableOf(tasks, task)
  const overdue = !task.done && task.due && task.due < today()
  return (
    <li className="py-2" data-uid={task.uid}>
      <div className="flex items-center gap-2.5 px-1">
        <input type="checkbox" className="size-4.5" checked={task.done} disabled={!owns} title={owns ? '' : 'Only its owner can check it off'}
          onChange={() => table.update(task.id, { done: !task.done })} />
        <button className={`title flex-1 bg-transparent p-0 text-left text-fg ${task.done ? 'text-muted line-through' : ''}`} onClick={() => setOpen(!open)}>
          {task.title}
        </button>
        {task.priority === 1 && <Badge tone="danger">High</Badge>}
        {task.priority === 3 && <Badge>Low</Badge>}
        {task.due && <Badge tone={overdue ? 'danger' : 'muted'}>{task.due === today() ? 'Today' : shortDate(task.due)}</Badge>}
        <Sharing item={task} />
      </div>
      {open && <TaskDetails task={task} owns={owns} />}
    </li>
  )
}

function TaskDetails({ task, owns }: { task: Task; owns: boolean }) {
  const table = tableOf(tasks, task)
  const [details, setDetails] = useState(task.details)
  const [tags, setTags] = useState(tagsOf(task).join(', '))
  const [estimate, setEstimate] = useState(task.estimate?.toString() ?? '')
  const save = () =>
    table.update(task.id, {
      details,
      tags: tags.split(',').map((t) => t.trim().replace(/^#/, '')).filter(Boolean),
      estimate: estimate.trim() === '' ? null : Number(estimate),
    })
  return (
    <div className="details mt-2 ml-7 space-y-2 text-sm">
      <textarea className="w-full rounded-md border border-line bg-card px-2.5 py-1.5" rows={3} placeholder="Details" readOnly={!owns}
        value={details} onChange={(e) => setDetails(e.target.value)} onBlur={() => owns && void save()} />
      <div className="flex flex-wrap items-center gap-2">
        <input className="min-w-0 flex-1" placeholder="Tags, comma separated" readOnly={!owns} value={tags}
          onChange={(e) => setTags(e.target.value)} onBlur={() => owns && void save()} />
        <input className="w-24" type="number" min="0" step="0.25" placeholder="Hours" readOnly={!owns} value={estimate}
          onChange={(e) => setEstimate(e.target.value)} onBlur={() => owns && void save()} />
        <select className="rounded-md border border-line bg-card px-2 py-1" disabled={!owns} value={task.priority}
          onChange={(e) => void table.update(task.id, { priority: +e.target.value })} aria-label="Priority">
          {[1, 2, 3].map((p) => <option key={p} value={p}>{PRIORITY[p]}</option>)}
        </select>
        <input type="date" disabled={!owns} value={task.due ?? ''} onChange={(e) => void table.update(task.id, { due: e.target.value || null })} aria-label="Due" />
      </div>
      {owns && (
        <div className="flex items-center gap-2">
          <ShareSwitch shared={task.shared} onChange={(s) => void setShared(tasks, task, s)} />
          <button className="ml-auto bg-transparent px-1.5 text-danger" onClick={() => void table.delete(task.id)}>Delete</button>
        </div>
      )}
      {task.shared && <Comments item={`task:${task.uid}`} />}
    </div>
  )
}
