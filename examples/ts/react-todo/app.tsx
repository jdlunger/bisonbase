// Todo list in React, on the bisonbase client library: a typed table, live queries and
// sign-in, with no SQL in the app.

import { useState } from 'react'
import { createRoot } from 'react-dom/client'
import { BisonBase, type RowOf } from 'bisonbase'
import { AuthElement, useAuth } from 'bisonbase/react'
import '../style.css'

declare const BISONBASE_URL: string // filled in by server.ts

// The app's id never changes. By default BisonBase looks for the server at /bb on the page's
// origin; here it's on port 8080.
const bb = new BisonBase('f1487da1-14ff-4998-a2c4-90b6353fe8c3', 'React Todo', { url: BISONBASE_URL })

// One database in the app's own storage, shared by everyone who uses it. Each row belongs to the
// user who added it, and users only see their own (the table is private). The first time an
// admin signs in, the app is registered and the table created (or given new columns later).
// For a separate database in each user's own account instead, use bb.createUserDb('todos').
const todos = bb.createAppDb('todos').createTable('todos', {
  content: 'text',
  done: ['boolean', false],
})
type Todo = RowOf<typeof todos>

function App() {
  const auth = useAuth()
  // Kept up to date: reloaded whenever the table changes, from this tab or anywhere else.
  const items = todos.useSelect({ orderBy: ['done', 'id'] })
  const left = items.filter((t) => !t.done).length

  return (
    <main className="mx-auto max-w-140">
      <h1 className="mb-4 text-2xl font-bold">Todo</h1>
      <div className="rounded-xl border border-line bg-card p-4">
        <p className="mb-3 text-sm"><AuthElement className="flex items-center gap-2.5 [&_.bb-auth-error]:text-danger" /></p>
        {auth.status === 'signed-in' && (
          <>
            <NewTodo />
            <ul id="items" className="divide-y divide-line">
              {items.map((t) => <Item key={t.id} todo={t} />)}
              {items.length === 0 && <li className="empty py-2 text-center text-muted">Nothing to do.</li>}
            </ul>
            <div className="mt-3 flex items-center justify-between text-sm">
              <span className="text-muted">{left} {left === 1 ? 'item' : 'items'} left</span>
              {left < items.length && (
                <button className="bg-transparent p-0 text-accent" onClick={() => todos.delete({ done: true })}>Clear completed</button>
              )}
            </div>
          </>
        )}
      </div>
    </main>
  )
}

function NewTodo() {
  const [content, setContent] = useState('')
  return (
    <form
      id="add"
      className="mb-3 flex gap-2"
      onSubmit={(e) => {
        e.preventDefault()
        if (content.trim()) void todos.insert({ content: content.trim() })
        setContent('')
      }}
    >
      <input className="min-w-0 flex-1" placeholder="What needs doing?" autoComplete="off" required
        value={content} onChange={(e) => setContent(e.target.value)} />
      <button>Add</button>
    </form>
  )
}

function Item({ todo }: { todo: Todo }) {
  return (
    <li className="flex items-center gap-2.5 px-1 py-2">
      <input type="checkbox" className="size-4.5" checked={todo.done} onChange={() => todos.update(todo.id, { done: !todo.done })} />
      <span className={`flex-1 ${todo.done ? 'text-muted line-through' : ''}`}>{todo.content}</span>
      <button className="bg-transparent px-1.5 py-0 text-danger" title="Delete" onClick={() => todos.delete(todo.id)}>✕</button>
    </li>
  )
}

createRoot(document.querySelector('#root')!).render(<App />)
