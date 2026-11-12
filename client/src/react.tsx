// React bindings. Importing this module makes `table.useSelect()` work.

import { useSyncExternalStore } from 'react'
import { BisonBase, setHooks, type AuthState, type LiveQuery, type QueryState } from './client.ts'

setHooks({
  useQuery<R>(query: LiveQuery<R>): QueryState<R> {
    return useSyncExternalStore(query.subscribe, query.getSnapshot, query.getSnapshot)
  },
})

function instance(bb?: BisonBase): BisonBase {
  const found = bb ?? BisonBase.instance
  if (!found) throw new Error('Create a BisonBase before rendering components that use it')
  return found
}

/** Whether the user is signed in; re-renders when that changes. */
export function useAuth(bb?: BisonBase): AuthState {
  const b = instance(bb)
  return useSyncExternalStore(
    (listener) => b.onAuthChange(listener),
    () => b.auth,
    () => b.auth,
  )
}

export interface AuthElementProps {
  /** Default: the BisonBase created last. */
  bb?: BisonBase
  className?: string
}

/** A sign-in button, or a sign-out button once signed in. Unstyled; target `.bb-auth`. */
export function AuthElement({ bb, className }: AuthElementProps) {
  const b = instance(bb)
  const auth = useAuth(b)
  const cls = className ? `bb-auth ${className}` : 'bb-auth'
  if (auth.status === 'pending') return <span className={cls} data-status="pending">Signing in…</span>
  if (auth.status === 'signed-in') {
    return (
      <span className={cls} data-status="signed-in">
        <span className="bb-auth-label">Signed in</span>{' '}
        <button type="button" onClick={() => void b.signOut()}>Sign out</button>
      </span>
    )
  }
  return (
    <span className={cls} data-status="signed-out">
      <button type="button" onClick={() => void b.signIn()}>Sign in</button>
      {auth.error && <span className="bb-auth-error" role="alert"> {auth.error}</span>}
    </span>
  )
}

export { BisonBase }
