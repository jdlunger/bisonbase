import { type AnchorHTMLAttributes, useSyncExternalStore } from "react";

// A minimal client-side router: the server (and Vite) serve index.html for every non-API path.

const listeners = new Set<() => void>();
const subscribe = (fn: () => void) => {
  listeners.add(fn);
  window.addEventListener("popstate", fn);
  return () => {
    listeners.delete(fn);
    window.removeEventListener("popstate", fn);
  };
};

export const usePath = () => useSyncExternalStore(subscribe, () => location.pathname);

export function navigate(to: string) {
  if (to === location.pathname + location.search) return;
  history.pushState(null, "", to);
  window.scrollTo(0, 0);
  listeners.forEach((fn) => fn());
}

/** A user's page: the root of their space. */
export const idPath = (pubkey: string) => `/bb/${pubkey}/`;

/** The page for one record: /bb/<owner><path>, each path segment URL-encoded. */
export const recordPath = (owner: string, path: string) => `/bb/${owner}${path.split("/").map(encodeURIComponent).join("/")}`;

/** An <a> that navigates within the SPA on a plain left click. */
export function Link({ href, onClick, ...rest }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string }) {
  return (
    <a
      href={href}
      onClick={(e) => {
        onClick?.(e);
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        navigate(href);
      }}
      {...rest}
    />
  );
}
