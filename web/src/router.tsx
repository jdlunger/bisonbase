import { type AnchorHTMLAttributes, useSyncExternalStore } from "react";

// A minimal client-side router: Vite (and the node, by redirecting there) serve index.html for every non-API path.

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

// Routes: /u/<ID> a user's page, /r/<hash> a record (and its edits), /claim a node's claim link, and any
// other path the records at or under that path.

/** A user's page. */
export const idPath = (pubkey: string) => `/u/${pubkey}`;

/** The page for one record, by its chain's hash (base58). */
export const recordPath = (hash: string) => `/r/${hash}`;

/** The page for a path ("/" for everything), each segment URL-encoded. */
export const pathPath = (path: string) => path.split("/").map(encodeURIComponent).join("/") || "/";

export type Route =
  | { page: "user"; pubkey: string }
  | { page: "record"; hash: string }
  | { page: "claim" }
  | { page: "path"; path: string };

export function useRoute(): Route {
  const p = usePath();
  let m;
  if ((m = p.match(/^\/u\/([^/]+)\/?$/))) return { page: "user", pubkey: decodeURIComponent(m[1]) };
  if ((m = p.match(/^\/r\/([^/]+)\/?$/))) return { page: "record", hash: decodeURIComponent(m[1]) };
  if (p === "/claim") return { page: "claim" };
  return { page: "path", path: p.replace(/\/+$/, "").split("/").map(decodeURIComponent).join("/") || "/" };
}

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
