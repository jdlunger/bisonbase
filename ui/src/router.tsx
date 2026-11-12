// A small client-side router: the current URL as state, and links that change it without
// reloading the page.

import { useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent } from 'react'

const listeners = new Set<() => void>()
const notify = () => listeners.forEach((f) => f())
window.addEventListener('popstate', notify)

function subscribe(f: () => void) {
  listeners.add(f)
  return () => listeners.delete(f)
}

/** The current URL's path and query, re-rendering when it changes. */
export function useHref(): string {
  return useSyncExternalStore(subscribe, () => location.pathname + location.search)
}

export function navigate(to: string, opts: { replace?: boolean } = {}) {
  if (to === location.pathname + location.search && !opts.replace) return
  if (opts.replace) history.replaceState(null, '', to)
  else history.pushState(null, '', to)
  window.scrollTo(0, 0)
  notify()
}

/** A link that navigates within the app (plain clicks only; modified clicks open as usual). */
export function Link({ href, onClick, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) {
  const click = (e: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(e)
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    if (rest.target || rest.download != null) return
    e.preventDefault()
    navigate(href)
  }
  return <a href={href} onClick={click} {...rest} />
}
